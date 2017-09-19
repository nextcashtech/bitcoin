/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "node.hpp"

#include "arcmist/base/log.hpp"
#include "info.hpp"
#include "message.hpp"
#include "block.hpp"
#include "chain.hpp"

#define BITCOIN_NODE_LOG_NAME "Node"


namespace BitCoin
{
    unsigned int Node::mNextID = 256;

    Node::Node(ArcMist::Network::Connection *pConnection, Chain *pChain, bool pIncoming, bool pIsSeed) : mID(mNextID++),
      mConnectionMutex("Node Connection"), mBlockRequestMutex("Node Block Request")
    {
        mIncoming = pIncoming;
        mConnected = false;
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        mVersionData = NULL;
        mID = mNextID++;
        mLastHeaderRequest = 0;
        mLastBlockRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;
        mBlocksRequestedCount = 0;
        mBlocksReceivedCount = 0;
        mLastBlockReceiveTime = 0;
        mMessagesReceived = 0;
        mConnectedTime = getTime();
        mStop = false;
        mStopped = false;
        mIsSeed = pIsSeed;
        mThread = NULL;
        mSocketID = -1;

        mChain = pChain;

        ArcMist::Buffer name;
        name.writeFormatted("Node [%d]", mID);
        mName = name.readString(name.length());

        // Verify connection
        mConnectionMutex.lock();
        mConnection = pConnection;
        mSocketID = pConnection->socket();
        mAddress = *mConnection;
        if(!mConnection->isOpen())
        {
            mConnectionMutex.unlock();
            mStopped = true;
            if(!mIsSeed)
                Info::instance().addPeerFail(mAddress);
            return;
        }
        mConnected = true;
        mConnectionMutex.unlock();
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Connected %s : %d (socket %d)",
          mConnection->ipv6Address(), mConnection->port(), mSocketID);

        // Start thread
        mThread = new ArcMist::Thread(mName, run, this);
        ArcMist::Thread::sleep(500); // Give the thread a chance to initialize
    }

    Node::~Node()
    {
        if(mConnected)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Disconnecting (socket %d)", mSocketID);

        stop();
        if(mThread != NULL)
            delete mThread;
        mConnectionMutex.lock();
        if(mConnection != NULL)
            delete mConnection;
        mConnectionMutex.unlock();
        if(mVersionData != NULL)
            delete mVersionData;
    }

    bool Node::isOpen()
    {
        mConnectionMutex.lock();
        bool result = mConnection != NULL && mConnection->isOpen();
        mConnectionMutex.unlock();
        return result;
    }

    void Node::close()
    {
        mConnectionMutex.lock();
        if(mConnection != NULL)
            mConnection->close();
        mConnectionMutex.unlock();
    }

    void Node::stop()
    {
        if(mThread == NULL)
            return;
        mStop = true;
        while(!mStopped)
            ArcMist::Thread::sleep(100);
    }

    void Node::collectStatistics(Statistics &pCollection)
    {
        mConnectionMutex.lock();
        mStatistics.bytesReceived += mConnection->bytesReceived();
        mStatistics.bytesSent += mConnection->bytesSent();
        mConnection->resetByteCounts();
        mConnectionMutex.unlock();
        pCollection += mStatistics;
        mStatistics.clear();
    }

    bool Node::notResponding() const
    {
        // Requested blocks not received within 2 minutes of request
        return (mLastBlockRequest != 0 && getTime() - mLastBlockRequest > 120 && mLastBlockRequest > mLastBlockReceiveTime);
    }

    bool Node::versionSupported(int32_t pVersion)
    {
        // TODO Check version protocol
        return true;
    }

    bool Node::sendMessage(Message::Data *pData)
    {
        if(!isOpen())
            return false;

        ArcMist::Buffer send;
        Message::writeFull(pData, &send);
        mConnectionMutex.lock();
        bool success = mConnection->send(&send);
        mConnectionMutex.unlock();
        if(success)
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName, "Sent <%s>", Message::nameFor(pData->type));
        else
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Failed to send <%s>", Message::nameFor(pData->type));
            close(); // Disconnect
        }
        return success;
    }

    bool Node::requestHeaders(Chain &pChain, const Hash &pStartingHash)
    {
        if(!isOpen())
            return false;

        Message::GetHeadersData getHeadersData;
        if(!pStartingHash.isEmpty())
        {
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Requesting block headers starting from (%d) : %s",
              pChain.height(pStartingHash), pStartingHash.hex().text());
            getHeadersData.blockHeaderHashes.push_back(pStartingHash);
        }
        else
            ArcMist::Log::add(ArcMist::Log::INFO, mName, "Requesting block headers starting from genesis block");
        bool success = sendMessage(&getHeadersData);
        if(success)
        {
            mHeaderRequested = pStartingHash;
            mLastHeaderRequest = getTime();
        }
        return success;
    }

    bool Node::requestBlocks(Chain &pChain, unsigned int pCount, bool pReduceOnly)
    {
        if(!isOpen())
            return false;

        Hash startHash = pChain.nextBlockNeeded(pReduceOnly);

        if(waitingForBlocks() || startHash.isEmpty())
            return false;

        mBlockRequestMutex.lock();
        mBlocksRequested.clear();

        Hash nextBlockHash = startHash;
        Message::GetDataData getDataData;
        unsigned int sentCount = 0;
        while(true)
        {
            getDataData.inventory.push_back(new Message::InventoryHash(Message::InventoryHash::BLOCK, nextBlockHash));
            mBlocksRequested.push_back(new Hash(nextBlockHash));
            pChain.markBlockRequested(nextBlockHash, mID);
            ++sentCount;
            if(sentCount < pCount)
            {
                nextBlockHash = pChain.nextBlockNeeded(pReduceOnly);
                if(nextBlockHash.isEmpty())
                    break;
            }
            else
                break;
        }

        bool success = sendMessage(&getDataData);
        if(success)
        {
            mBlocksRequestedCount += sentCount;
            mLastBlockRequest = getTime();
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Requested %d blocks starting at (%d) : %s",
              sentCount, pChain.height(startHash), startHash.hex().text());
        }
        else
        {
            for(HashList::iterator hash=mBlocksRequested.begin();hash!=mBlocksRequested.end();++hash)
                pChain.markBlockNotRequested(**hash);
            mBlocksRequested.clear();
        }

        mBlockRequestMutex.unlock();
        return success;
    }

    bool Node::sendBlock(Block &pBlock)
    {
        if(!isOpen())
            return false;

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Sending block : %s", pBlock.hash.hex().text());
        Message::BlockData blockData;
        blockData.block = &pBlock;
        bool success = sendMessage(&blockData);
        if(success)
            ++mStatistics.blocksSent;
        return success;
    }

    bool Node::sendVersion(Chain &pChain)
    {
        if(!isOpen())
            return false;

        Info &info = Info::instance();
        // Apparently if relay is off most of main net won't send blocks or headers
        Message::VersionData versionMessage(mConnection->ipv6Bytes(), mConnection->port(), info.ip,
          info.port, info.fullMode, pChain.blockHeight(), true); //chain.isInSync());
        bool success = sendMessage(&versionMessage);
        mVersionSent = true;
        return success;
    }

    bool Node::sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason)
    {
        if(!isOpen())
            return false;

        Message::RejectData rejectMessage(pCommand, pCode, pReason, NULL);
        return sendMessage(&rejectMessage);
    }

    void Node::run()
    {
        Node *node = (Node *)ArcMist::Thread::getParameter();
        if(node == NULL)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_NODE_LOG_NAME, "Thread parameter is null. Stopping");
            return;
        }

        ArcMist::String name = node->mName;

        if(node->mStop)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, name, "Node stopped before thread started");
            node->mStopped = true;
            return;
        }

        node->sendVersion(*node->mChain);

        while(!node->mStop)
        {
            node->process(*node->mChain);

            if(node->mStop)
                break;

            ArcMist::Thread::sleep(500);
        }

        node->mStopped = true;
    }

    void Node::process(Chain &pChain)
    {
        mConnectionMutex.lock();
        if(mConnection == NULL)
        {
            mConnectionMutex.unlock();
            return;
        }

        if(!mConnection->isOpen() || !mConnection->receive(&mReceiveBuffer))
        {
            mConnectionMutex.unlock();
            return;
        }
        mConnectionMutex.unlock();

        // Check for a complete message
        Message::Data *message = Message::readFull(&mReceiveBuffer);
        bool dontDeleteMessage = false;

        if(message == NULL)
        {
            uint64_t time = getTime();

            if(mMessagesReceived == 0 && time - mConnectedTime > 60)
            {
                ArcMist::Log::add(ArcMist::Log::WARNING, mName, "No valid messages within 60 seconds of connecting");
                close();
                if(!mIsSeed)
                    Info::instance().addPeerFail(mAddress);
                return;
            }

            if(time - mLastReceiveTime > 1200 && // 20 minutes
              time - mLastPingTime > 30)
            {
                Message::PingData pingData;
                sendMessage(&pingData);
                mLastPingTime = getTime();
            }

            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName, "Received <%s>", Message::nameFor(message->type));
        mLastReceiveTime = getTime();

        if(mMessagesReceived < 2 && message->type != Message::VERSION && message->type != Message::VERACK &&
          message->type != Message::REJECT)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, mName, "First 2 messages not a version and verack : <%s>",
              Message::nameFor(message->type));
            close();
            if(!mIsSeed)
                Info::instance().addPeerFail(mAddress);
            delete message;
            return;
        }

        ++mMessagesReceived;

        switch(message->type)
        {
            case Message::VERSION:
            {
                if(mVersionData != NULL)
                {
                    sendReject(Message::nameFor(message->type), Message::RejectData::DUPLICATE, "");
                    break;
                }

                mVersionData = (Message::VersionData *)message;
                dontDeleteMessage = true;
                if(mVersionData->relay)
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Version : %s (%d), %d blocks, relay on",
                      mVersionData->userAgent.text(), mVersionData->version, mVersionData->startBlockHeight);
                else
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Version : %s (%d), %d blocks, relay off",
                      mVersionData->userAgent.text(), mVersionData->version, mVersionData->startBlockHeight);

                if(!versionSupported(mVersionData->version))
                    sendReject(Message::nameFor(message->type), Message::RejectData::PROTOCOL, "");

                //TODO Reject recent sent version nonces

                // Send version acknowledge
                Message::Data versionAcknowledgeMessage(Message::VERACK);
                sendMessage(&versionAcknowledgeMessage);
                mVersionAcknowledgeSent = true;

                if(mIsSeed)
                {
                    // Request addresses from the seed
                    Message::Data getAddresses(Message::GET_ADDRESSES);
                    sendMessage(&getAddresses);
                }

                // Update peer
                if(mVersionData->relay && mVersionAcknowledged)
                {
                    if(mAddress.port == 0)
                        mAddress.port = mVersionData->transmittingPort;
                    if(!mIsSeed)
                        Info::instance().updatePeer(mAddress, mVersionData->userAgent, mVersionData->transmittingServices);
                }

                // Send "send headers" message
                //Message::Data sendHeadersData(Message::SEND_HEADERS);
                //sendMessage(&sendHeadersData);

                break;
            }
            case Message::VERACK:
                mVersionAcknowledged = true;

                // Update peer
                if(mVersionData != NULL && mVersionData->relay)
                {
                    if(mAddress.port == 0)
                        mAddress.port = mVersionData->transmittingPort;
                    if(!mIsSeed)
                        Info::instance().updatePeer(mAddress, mVersionData->userAgent, mVersionData->transmittingServices);
                }
                break;

            case Message::PING:
            {
                Message::PongData pongData(((Message::PingData *)message)->nonce);
                sendMessage(&pongData);
                break;
            }
            case Message::PONG:
                if(mPingNonce != ((Message::PongData *)message)->nonce)
                    ArcMist::Log::add(ArcMist::Log::INFO, mName, "Pong nonce doesn't match sent Ping");
                break;

            case Message::REJECT:
            {
                Message::RejectData *rejectData = (Message::RejectData *)message;
                if(rejectData->command == "version")
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Closing for version reject [%02x] - %s",
                      rejectData->code, rejectData->reason.text());
                    close();
                }
                else
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, mName, "Reject %s [%02x] - %s",
                      rejectData->command.text(), rejectData->code, rejectData->reason.text());

                // TODO Determine if closing node is necessary
                break;
            }
            case Message::GET_ADDRESSES:
            {
                // Send known peer addresses
                Message::AddressesData addressData;
                std::vector<Peer *> peers;

                // Get list of peers
                Info::instance().randomizePeers(peers, 1);

                unsigned int count = peers.size();
                if(count > 1000) // Maximum of 1000
                    count = 1000;

                // Add peers to message
                addressData.addresses.resize(count);
                std::vector<Peer *>::iterator peer = peers.begin();
                for(std::vector<Peer>::iterator toSend=addressData.addresses.begin();toSend!=addressData.addresses.end();++toSend)
                    *toSend = (**peer++);

                sendMessage(&addressData);
                break;
            }
            case Message::ADDRESSES:
            {
                Message::AddressesData *addressesData = (Message::AddressesData *)message;

                Info &info = Info::instance();
                for(unsigned int i=0;i<addressesData->addresses.size();i++)
                for(std::vector<Peer>::iterator peer=addressesData->addresses.begin();peer!=addressesData->addresses.end();++peer)
                    info.updatePeer(peer->address, NULL, peer->services);

                // Disconnect from seed node because it has done its job
                close();
                break;
            }
            case Message::ALERT:
                //TODO Determine if anything needs to be done for alerts
                break;

            case Message::FEE_FILTER:
                mMinimumFeeRate = ((Message::FeeFilterData *)message)->minimumFeeRate;
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Fee minimum rate set to %d", mMinimumFeeRate);
                break;

            case Message::FILTER_ADD:
                // TODO Implement FILTER_ADD
                break;

            case Message::FILTER_CLEAR:
                // TODO Implement FILTER_CLEAR
                break;

            case Message::FILTER_LOAD:
                // TODO Implement FILTER_LOAD
                break;

            case Message::SEND_HEADERS:
                mSendHeaders = true;
                break;

            case Message::GET_BLOCKS:
            {
                Message::GetBlocksData *getBlocksData = (Message::GetBlocksData *)message;

                // Send Inventory of block headers
                Message::InventoryData inventoryData;
                HashList hashes;

                // Find appropriate hashes
                for(std::vector<Hash>::iterator i=getBlocksData->blockHeaderHashes.begin();i!=getBlocksData->blockHeaderHashes.end();++i)
                    if(pChain.getBlockHashes(hashes, *i, 500))
                        break;

                if(hashes.size() == 0)
                {
                    // No matching starting hashes found. Start from genesis
                    Hash emptyHash;
                    pChain.getBlockHashes(hashes, emptyHash, 500);
                }

                unsigned int count = hashes.size();
                if(count > 500) // Maximum of 500
                    count = 500;

                // Add inventory to message
                bool dontStop = getBlocksData->stopHeaderHash.isZero();
                inventoryData.inventory.resize(count);
                unsigned int actualCount = 0;
                Message::Inventory::iterator item=inventoryData.inventory.begin();
                for(HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
                {
                    *item = new Message::InventoryHash(Message::InventoryHash::BLOCK, **hash);
                    actualCount++;
                    if(!dontStop && **hash == getBlocksData->stopHeaderHash)
                        break;
                    ++item;
                }
                inventoryData.inventory.resize(actualCount);

                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Sending %d block hashes", actualCount);
                sendMessage(&inventoryData);
                break;
            }
            case Message::BLOCK:
            {
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName,
                  "Received block %s", ((Message::BlockData *)message)->block->hash.hex().text());
                ++mStatistics.blocksReceived;
                mBlockRequestMutex.lock();
                for(HashList::iterator hash=mBlocksRequested.begin();hash!=mBlocksRequested.end();++hash)
                    if(**hash == ((Message::BlockData *)message)->block->hash)
                    {
                        delete *hash;
                        mBlocksRequested.erase(hash);
                        break;
                    }
                mBlockRequestMutex.unlock();
                if(pChain.addPendingBlock(((Message::BlockData *)message)->block))
                {
                    mLastBlockReceiveTime = getTime();
                    ++mBlocksReceivedCount;
                    ((Message::BlockData *)message)->block = NULL; // Memory has been handed off
                    if(!mIsSeed && mVersionData != NULL)
                        Info::instance().updatePeer(mAddress, mVersionData->userAgent, mVersionData->transmittingServices);
                }
                break;
            }
            case Message::GET_DATA:
            {
                Message::GetDataData *getDataData = (Message::GetDataData *)message;
                Message::NotFoundData notFoundData;
                Block block;
                bool fail = false;

                for(Message::Inventory::iterator item=getDataData->inventory.begin();item!=getDataData->inventory.end();++item)
                {
                    switch((*item)->type)
                    {
                    case Message::InventoryHash::BLOCK:
                    {
                        if(pChain.getBlock((*item)->hash, block))
                        {
                            if(!sendBlock(block))
                                fail = true;
                        }
                        else
                            notFoundData.inventory.push_back(new Message::InventoryHash(**item));
                        break;
                    }
                    case Message::InventoryHash::TRANSACTION:
                        //TODO Implement GET_DATA transactions (TRANSACTION)
                        // For mempool and relay set
                        break;
                    case Message::InventoryHash::FILTERED_BLOCK:
                        //TODO Implement GET_DATA filtered blocks (MERKLE_BLOCK)
                        break;
                    case Message::InventoryHash::UNKNOWN:
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Unknown inventory item type %d",
                          (*item)->type);
                        break;
                    }

                    if(fail)
                        break;
                }

                if(notFoundData.inventory.size() > 0)
                    sendMessage(&notFoundData);
                break;
            }
            case Message::GET_HEADERS:
            {
                Message::GetHeadersData *getHeadersData = (Message::GetHeadersData *)message;
                BlockList blockList;

                for(std::vector<Hash>::iterator hash=getHeadersData->blockHeaderHashes.begin();hash!=getHeadersData->blockHeaderHashes.end();++hash)
                    if(pChain.getBlockHeaders(blockList, *hash, getHeadersData->stopHeaderHash, 2000))
                        break; // match found

                if(blockList.size() > 0)
                {
                    Message::HeadersData headersData;
                    // Load up the message
                    for(BlockList::iterator block=blockList.begin();block!=blockList.end();++block)
                    {
                        headersData.headers.push_back(*block);
                        if((*block)->hash == getHeadersData->stopHeaderHash)
                            break;
                    }

                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                      "Sending %d block headers", headersData.headers.size());
                    if(sendMessage(&headersData))
                        mStatistics.headersSent += headersData.headers.size();
                }
                break;
            }
            case Message::HEADERS:
            {
                Message::HeadersData *headersData = (Message::HeadersData *)message;
                unsigned int addedCount = 0;

                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                  "Received %d block headers", headersData->headers.size());
                mHeaderRequested.clear();
                mLastHeaderRequest = 0;
                mStatistics.headersReceived += headersData->headers.size();

                for(std::vector<Block *>::iterator header=headersData->headers.begin();header!=headersData->headers.end();)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName, "Header : %s", (*header)->hash.hex().text());

                    if(pChain.addPendingHeader(*header))
                    {
                        // memory will be deleted by block chain after it is processed so remove it from this list
                        header = headersData->headers.erase(header);
                        addedCount++;
                    }
                    else
                        ++header;
                }

                if(addedCount > 0 && !mIsSeed && mVersionData != NULL)
                    Info::instance().updatePeer(mAddress, mVersionData->userAgent, mVersionData->transmittingServices);

                ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Added %d pending headers", addedCount);

                break;
            }
            case Message::INVENTORY:
            {
                Message::InventoryData *inventoryData = (Message::InventoryData *)message;
                unsigned int blockCount = 0;

                for(Message::Inventory::iterator item=inventoryData->inventory.begin();item!=inventoryData->inventory.end();++item)
                {
                    if((*item)->type == Message::InventoryHash::BLOCK)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Block Inventory : %s",
                          (*item)->hash.hex().text());

                        blockCount++;
                    }
                    else if((*item)->type == Message::InventoryHash::TRANSACTION)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName,
                          "Transaction Inventory : %s", (*item)->hash.hex().text());
                        //TODO Transaction inventory messages
                    }
                }

                if(blockCount > 1)
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                      "Received %d block inventory", blockCount);
                break;
            }
            case Message::MEM_POOL:
                // TODO Implement MEM_POOL
                break;

            case Message::MERKLE_BLOCK:
                // TODO Implement MERKLE_BLOCK
                break;

            case Message::NOT_FOUND:
            {
                Message::NotFoundData *notFoundData = (Message::NotFoundData *)message;
                for(Message::Inventory::iterator item=notFoundData->inventory.begin();item!=notFoundData->inventory.end();++item)
                {
                    switch((*item)->type)
                    {
                    case Message::InventoryHash::BLOCK:
                    {
                        mBlockRequestMutex.lock();
                        for(HashList::iterator hash=mBlocksRequested.begin();hash!=mBlocksRequested.end();++hash)
                            if(**hash == (*item)->hash)
                            {
                                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                                  "Block hash returned not found : %s", (*hash)->hex().text());
                                delete *hash;
                                mBlocksRequested.erase(hash);
                                pChain.markBlockNotRequested((*item)->hash);
                                break;
                            }
                        if(mBlocksRequested.size() == 0)
                            mLastBlockRequest = 0;
                        mBlockRequestMutex.unlock();
                        break;
                    }
                    case Message::InventoryHash::TRANSACTION:
                        //TODO Implement Transaction not found
                        break;
                    case Message::InventoryHash::FILTERED_BLOCK:
                        //TODO Implement filtered blocks not found
                        break;
                    case Message::InventoryHash::UNKNOWN:
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                          "Unknown not found inventory item type %d", (*item)->type);
                        break;
                    }
                }
                break;
            }
            case Message::TRANSACTION:
                // TODO Implement TRANSACTION
                break;

            case Message::UNKNOWN:
                break;
        }

        if(!dontDeleteMessage)
            delete message;
    }
}
