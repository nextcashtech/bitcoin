/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "node.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/crypto/digest.hpp"
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
        mIsIncoming = pIncoming;
        mConnected = false;
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mMinimumFeeRate = 0;
        mVersionData = NULL;
        mID = mNextID++;
        mHeaderRequestTime = 0;
        mBlockRequestTime = 0;
        mLastReceiveTime = getTime();
        mLastPingNonce = 0;
        mLastPingTime = 0;
        mPingRoundTripTime = 0xffffffff;
        mMessagesReceived = 0;
        mConnectedTime = getTime();
        mStop = false;
        mStopped = false;
        mIsSeed = pIsSeed;
        mSendBlocksCompact = false;
        mThread = NULL;
        mSocketID = -1;

        mChain = pChain;

        if(mIsIncoming)
            mName.writeFormatted("Node i[%d]", mID);
        else
            mName.writeFormatted("Node o[%d]", mID);

        // Verify connection
        mConnectionMutex.lock();
        mConnection = pConnection;
        mSocketID = pConnection->socket();
        if(!mIsIncoming)
            mAddress = *mConnection;
        if(!mConnection->isOpen())
        {
            mConnectionMutex.unlock();
            mStopped = true;
            if(!mIsSeed && !mIsIncoming)
                Info::instance().addPeerFail(mAddress);
            return;
        }
        mConnected = true;
        mConnectionMutex.unlock();
        if(mIsIncoming)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Incoming Connection %s : %d (socket %d)",
              mConnection->ipv6Address(), mConnection->port(), mSocketID);
        else
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Outgoing Connection %s : %d (socket %d)",
              mConnection->ipv6Address(), mConnection->port(), mSocketID);

        // Start thread
        mThread = new ArcMist::Thread(mName, run, this);
        ArcMist::Thread::sleep(500); // Give the thread a chance to initialize
    }

    Node::~Node()
    {
        if(mConnected)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Disconnecting (socket %d)", mSocketID);
        if(!mMessageInterpreter.pendingBlockHash.isEmpty())
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
              "Dropping block in progress %d bytes (%d secs) : %s", mReceiveBuffer.length(),
              mMessageInterpreter.pendingBlockUpdateTime - mMessageInterpreter.pendingBlockStartTime,
              mMessageInterpreter.pendingBlockHash.hex().text());

        requestStop();
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
        requestStop();
    }

    void Node::releaseBlockRequests()
    {
        mBlockRequestMutex.lock();
        mBlocksRequested.clear();
        mBlockRequestMutex.unlock();
        mChain->releaseBlocksForNode(mID);
    }

    void Node::requestStop()
    {
        releaseBlockRequests();
        if(mThread == NULL)
            return;
        mStop = true;
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

    void Node::check(Chain &pChain)
    {
        if(!isOpen())
            return;

        if(mIsSeed && getTime() - mConnectedTime > 60)
        {
            ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Seed connected for too long");
            close();
            return;
        }

        if(!mIsIncoming && mPingRoundTripTime == 0xffffffff && getTime() - mConnectedTime > 60)
        {
            ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. No pong within 60 seconds of connection");
            close();
            return;
        }

        if(!mIsIncoming && !pChain.isInSync())
        {
            uint32_t time = getTime();

            if(mBlocksRequested.size() > 0 && time - mBlockRequestTime > 30)
            {
                if(mMessageInterpreter.pendingBlockUpdateTime == 0) // Haven't started receiving blocks 30 seconds after requesting
                {
                    ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. No block for 30 seconds");
                    Info::instance().addPeerFail(mAddress);
                    close();
                    return;
                }

                if(time - mMessageInterpreter.pendingBlockUpdateTime > 30) // Haven't received more of the block in the last 30 seconds
                {
                    ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. No update on block for 30 seconds");
                    Info::instance().addPeerFail(mAddress);
                    close();
                    return;
                }

                if(time - mMessageInterpreter.pendingBlockStartTime > 120) // Haven't finished block within 120 seconds from starting
                {
                    ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Block not finished within 120 seconds");
                    Info::instance().addPeerFail(mAddress);
                    close();
                    return;
                }
            }

            if(!mHeaderRequested.isEmpty() && time - mHeaderRequestTime > 60)
            {
                ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Not providing headers");
                Info::instance().addPeerFail(mAddress);
                close();
                return;
            }

            if(mLastReceiveTime != 0 && time - mLastReceiveTime > 1200)
            {
                ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Not responding");
                Info::instance().addPeerFail(mAddress);
                close();
                return;
            }
        }
    }

    bool Node::sendMessage(Message::Data *pData)
    {
        if(!isOpen())
            return false;

        ArcMist::Buffer send;
        mMessageInterpreter.write(pData, &send);
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
        if(!isOpen() || mIsIncoming || waitingForRequests())
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
            mHeaderRequestTime = getTime();
        }
        return success;
    }

    bool Node::requestBlocks(Chain &pChain, unsigned int pCount, bool pReduceOnly)
    {
        if(!isOpen() || mIsIncoming || waitingForRequests())
            return false;

        // Request list of blocks from the chain
        HashList hashes;
        if(!pChain.getBlocksNeeded(hashes, pCount, pReduceOnly, mID))
            return false;

        // Put block hashes into block request message
        Message::GetDataData getDataData;
        for(HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
            getDataData.inventory.push_back(new Message::InventoryHash(Message::InventoryHash::BLOCK, **hash));

        bool success = sendMessage(&getDataData);
        if(success)
        {
            mBlockRequestMutex.lock();
            mBlocksRequested.clear();
            for(HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
                mBlocksRequested.push_back(new Hash(**hash));
            mBlockRequestTime = getTime();
            mBlockRequestMutex.unlock();
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Requested %d blocks starting at (%d) : %s",
              hashes.size(), pChain.height(*hashes.front()), hashes.front()->hex().text());
        }
        else
        {
            // Clear requested blocks
            mBlockRequestMutex.lock();
            mBlocksRequested.clear();
            mBlockRequestMutex.unlock();
            pChain.releaseBlocksForNode(mID);
        }

        return success;
    }

    bool Node::requestPeers()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, mName, "Sending peer request");
        Message::Data getAddresses(Message::GET_ADDRESSES);
        return sendMessage(&getAddresses);
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

    bool Node::announceBlock(const Hash &pHash, Chain &pChain)
    {
        //TODO if(mSendBlocksCompact)
        // {
            // //TODO  Send CompactBlockData
            // //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
            // //  "Announcing block with compact : %s", pHash.hex().text());
            // return false;
        // }
        // else

        if(mSendHeaders)
        {
            // Send the header
            Message::HeadersData headersData;
            headersData.headers.push_back(new Block());

            if(!pChain.getHeader(pHash, *headersData.headers.front()))
                return false;

            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
              "Announcing block with header : %s", pHash.hex().text());

            bool success = sendMessage(&headersData);
            if(success)
                mStatistics.headersSent += headersData.headers.size();
            return success;
        }
        else
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
              "Announcing block : %s", pHash.hex().text());
            Message::InventoryData inventoryData;
            inventoryData.inventory.push_back(new Message::InventoryHash(Message::InventoryHash::BLOCK, pHash));
            return sendMessage(&inventoryData);
        }
    }

    bool Node::announceTransaction(const Hash &pHash)
    {
        if(mVersionData == NULL || !mVersionData->relay)
            return true;

        Message::InventoryData inventoryData;
        inventoryData.inventory.push_back(new Message::InventoryHash(Message::InventoryHash::TRANSACTION, pHash));
        return sendMessage(&inventoryData);
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

    bool Node::sendPing()
    {
        Message::PingData pingData;
        bool success = sendMessage(&pingData);
        mLastPingNonce = pingData.nonce;
        mLastPingTime = getTime();
        return success;
    }

    bool Node::sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason)
    {
        if(!isOpen())
            return false;

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "Sending reject : %s", pReason);
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

        // Ping every 20 minutes
        if(!mIsIncoming && mVersionData != NULL && mVersionAcknowledged && getTime() - mLastPingTime > 1200)
            sendPing();

        // Check for a complete message
        Message::Data *message = mMessageInterpreter.read(&mReceiveBuffer, mName);
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

            if(time - mLastReceiveTime > 600) // 10 minutes
                sendPing();

            if(!mMessageInterpreter.pendingBlockHash.isEmpty() && mMessageInterpreter.pendingBlockUpdateTime != 0)
                pChain.updateBlockProgress(mMessageInterpreter.pendingBlockHash, mID, mMessageInterpreter.pendingBlockUpdateTime);

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

                std::memcpy(mAddress.ip, mVersionData->transmittingIPv6, 16);
                mAddress.port = mVersionData->transmittingPort;
                mMessageInterpreter.version = mVersionData->version;

                // Require full node bit for outgoing nodes
                if(!mIsIncoming && !mIsSeed && !(mVersionData->transmittingServices & Message::VersionData::FULL_NODE_BIT))
                {
                    sendReject(Message::nameFor(message->type), Message::RejectData::PROTOCOL,
                      "Full node bit required in protocol version");
                    close();
                }
                else if(!mIsIncoming && !mIsSeed && !pChain.isInSync() && (mVersionData->startBlockHeight < 0 ||
                  (unsigned int)mVersionData->startBlockHeight < pChain.blockHeight()))
                {
                    ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Low block height");
                    Info::instance().addPeerFail(mAddress);
                    close();
                }
                else
                {
                    if(mVersionData->relay && mVersionAcknowledged && !mIsSeed) // Update peer
                        Info::instance().updatePeer(mAddress, mVersionData->userAgent, mVersionData->transmittingServices);

                    // Send version acknowledge
                    Message::Data versionAcknowledgeMessage(Message::VERACK);
                    sendMessage(&versionAcknowledgeMessage);
                    mVersionAcknowledgeSent = true;

                    if(mIsSeed)
                        requestPeers(); // Request addresses from the seed
                }

                break;
            }
            case Message::VERACK:
                mVersionAcknowledged = true;

                // Update peer
                if(mVersionData != NULL && mVersionData->relay && !mIsSeed)
                    Info::instance().updatePeer(mAddress, mVersionData->userAgent, mVersionData->transmittingServices);
                break;

            case Message::PING:
            {
                Message::PongData pongData(((Message::PingData *)message)->nonce);
                sendMessage(&pongData);
                break;
            }
            case Message::PONG:
                if(((Message::PongData *)message)->nonce != 0 && mLastPingNonce != ((Message::PongData *)message)->nonce)
                    ArcMist::Log::add(ArcMist::Log::VERBOSE, mName, "Pong nonce doesn't match sent Ping");
                else
                {
                    mPingRoundTripTime = getTime() - mLastPingTime;
                    mLastPingNonce = 0;
                }
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
                if(count == 0)
                {
                    ArcMist::Log::add(ArcMist::Log::VERBOSE, mName, "No peer addresses available to send");
                    break;
                }

                // Add peers to message
                addressData.addresses.resize(count);
                std::vector<Peer *>::iterator peer = peers.begin();
                for(std::vector<Message::Address>::iterator toSend=addressData.addresses.begin();toSend!=addressData.addresses.end();++toSend)
                    *toSend = **peer++;

                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Sending %d peer addresses",
                  addressData.addresses.size());
                sendMessage(&addressData);
                break;
            }
            case Message::ADDRESSES:
            {
                Message::AddressesData *addressesData = (Message::AddressesData *)message;
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Received %d peer addresses",
                  addressesData->addresses.size());
                IPAddress ip;

                Info &info = Info::instance();
                for(std::vector<Message::Address>::iterator address=addressesData->addresses.begin();address!=addressesData->addresses.end();++address)
                {
                    ip.set(address->ip, address->port);
                    info.updatePeer(ip, NULL, address->services);
                }

                if(mIsSeed)
                {
                    ArcMist::Log::add(ArcMist::Log::VERBOSE, mName, "Closing seed because it gave addresses");
                    close(); // Disconnect from seed node because it has done its job
                }
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
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                  "Received block (height %d) (%d bytes) : %s", pChain.height(((Message::BlockData *)message)->block->hash),
                  ((Message::BlockData *)message)->block->size(), ((Message::BlockData *)message)->block->hash.hex().text());
                ++mStatistics.blocksReceived;

                // Remove from blocks requested
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
                            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Sending block at height %d : %s",
                              pChain.height((*item)->hash), (*item)->hash.hex().text());
                            if(!sendBlock(block))
                                fail = true;
                        }
                        else
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Block not found : %s",
                              (*item)->hash.hex().text());
                            notFoundData.inventory.push_back(new Message::InventoryHash(**item));
                        }
                        break;
                    }
                    case Message::InventoryHash::TRANSACTION:
                        //TODO Implement GET_DATA transactions (TRANSACTION)
                        // For mempool and relay set
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Requested Transaction (Not implemented) : %s",
                          (*item)->hash.hex().text());
                        break;
                    case Message::InventoryHash::FILTERED_BLOCK:
                        //TODO Implement GET_DATA filtered blocks (MERKLE_BLOCK)
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Requested Merkle Block (Not implemented) : %s",
                          (*item)->hash.hex().text());
                        break;
                    case Message::InventoryHash::COMPACT_BLOCK:
                        //TODO Implement GET_DATA compact blocks (COMPACT_BLOCK)
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Requested Compact Block (Not implemented) : %s",
                          (*item)->hash.hex().text());
                        break;
                    case Message::InventoryHash::UNKNOWN:
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Unknown request inventory type %02x",
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
                Message::HeadersData headersData;

                for(std::vector<Hash>::iterator hash=getHeadersData->blockHeaderHashes.begin();hash!=getHeadersData->blockHeaderHashes.end();++hash)
                    if(pChain.getBlockHeaders(headersData.headers, *hash, getHeadersData->stopHeaderHash, 2000))
                        break; // match found

                if(headersData.headers.size() > 0)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                      "Sending %d block headers starting at height %d : %s", headersData.headers.size(),
                      pChain.height(headersData.headers.front()->hash), headersData.headers.front()->hash.hex().text());
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
                mHeaderRequestTime = 0;
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
                    switch((*item)->type)
                    {
                    case Message::InventoryHash::BLOCK:
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Block Inventory : %s",
                          (*item)->hash.hex().text());
                        blockCount++;
                        break;
                    case Message::InventoryHash::TRANSACTION:
                        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName,
                          "Transaction Inventory : %s", (*item)->hash.hex().text());
                        //TODO Transaction inventory messages
                        break;
                    case Message::InventoryHash::FILTERED_BLOCK:
                        break;
                    case Message::InventoryHash::COMPACT_BLOCK:
                        break;
                    default:
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, mName,
                          "Unknown Transaction Inventory Type : %02x", (*item)->type);
                        break;
                    }
                }

                if(blockCount > 1)
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                      "Received %d block inventory", blockCount);
                break;
            }
            case Message::MEM_POOL:
                // TODO Implement MEM_POOL
                // Send Inventory message with all transactions in the mempool
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
                        bool wasRequested = false;
                        mBlockRequestMutex.lock();
                        for(HashList::iterator hash=mBlocksRequested.begin();hash!=mBlocksRequested.end();++hash)
                            if(**hash == (*item)->hash)
                            {
                                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                                  "Block hash returned not found : %s", (*hash)->hex().text());
                                wasRequested = true;
                                break;
                            }
                        mBlockRequestMutex.unlock();

                        if(wasRequested)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                              "Dropping. Blocks not found");
                            close();
                        }
                        break;
                    }
                    case Message::InventoryHash::TRANSACTION:
                        //TODO Implement Transaction not found
                        break;
                    case Message::InventoryHash::FILTERED_BLOCK:
                        //TODO Implement filtered blocks not found
                        break;
                    case Message::InventoryHash::COMPACT_BLOCK:
                        //TODO Implement compact blocks not found
                        break;
                    case Message::InventoryHash::UNKNOWN:
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                          "Unknown \"not found\" inventory item type %d", (*item)->type);
                        break;
                    }
                }
                break;
            }
            case Message::TRANSACTION:
                // TODO Implement TRANSACTION
                break;
            case Message::SEND_COMPACT:
            {
                Message::SendCompactData *sendCompactData = (Message::SendCompactData *)message;

                if(sendCompactData->encoding == 1)
                {
                    if(sendCompactData->sendCompact == 1)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Send Compact Activated");
                        mSendBlocksCompact = true;
                    }
                    else if(sendCompactData->sendCompact == 0)
                        mSendBlocksCompact = false;
                }
                else
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                      "Unknown Send Compact encoding %08x%08x", sendCompactData->encoding >> 32,
                      sendCompactData->encoding & 0xffffffff);
                }
                break;
            }
            case Message::COMPACT_BLOCK:
            {
                //TODO Message::CompactBlockData *compactBlockData = (Message::CompactBlockData *)message;
                break;
            }
            case Message::GET_BLOCK_TRANSACTIONS:
            {
                //TODO Message::GetBlockTransactionsData *getBlockTransactionsData = (Message::GetBlockTransactionsData *)message;
                break;
            }
            case Message::BLOCK_TRANSACTIONS:
            {
                //TODO Message::BlockTransactionsData *blockTransactionsData = (Message::BlockTransactionsData *)message;
                break;
            }

            case Message::UNKNOWN:
                break;
        }

        if(!dontDeleteMessage)
            delete message;
    }
}
