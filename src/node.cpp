#include "node.hpp"

#include "arcmist/base/log.hpp"
#include "info.hpp"
#include "message.hpp"
#include "events.hpp"

#define BITCOIN_NODE_LOG_NAME "Node"


namespace BitCoin
{
    unsigned int Node::mNextID = 256;

    Node::Node(IPAddress &pAddress) : mBlockHeaderHashMutex("Node Block Header Hash")
    {
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mLastTime = 0;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        mVersionData = 0;
        mID = mNextID++;
        mAddress = pAddress;
        mReceiveBuffer.setInputEndian(ArcMist::Endian::LITTLE);
        mReceiveBuffer.setOutputEndian(ArcMist::Endian::LITTLE);

        if(!mConnection.open(AF_INET6, pAddress.ip, pAddress.port))
        {
            Info::instance().addPeerFail(pAddress);
            return;
        }

        sendVersion();
    }

    Node::Node(const char *pIP, const char *pPort) : mBlockHeaderHashMutex("Node Block Header Hash")
    {
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mLastTime = 0;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        mVersionData = 0;
        mID = mNextID++;

        if(!mConnection.open(pIP, pPort))
        {
            mAddress = mConnection;
            Info::instance().addPeerFail(mAddress);
            return;
        }

        mAddress = mConnection;
        sendVersion();
    }

    Node::Node(unsigned int pFamily, const uint8_t *pIP, uint16_t pPort) : mBlockHeaderHashMutex("Node Block Header Hash")
    {
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mLastTime = 0;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        mVersionData = 0;
        mID = mNextID++;

        if(!mConnection.open(pFamily, pIP, pPort))
        {
            mAddress = mConnection;
            Info::instance().addPeerFail(mAddress);
            return;
        }

        mAddress = mConnection;
        sendVersion();
    }

    void Node::clear()
    {
        mConnection.close();
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mLastTime = 0;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        if(mVersionData != 0)
            delete mVersionData;
        mVersionData = 0;
    }

    void Node::addBlockHeaderHash(Hash &pHash)
    {
        mBlockHeaderHashMutex.lock();
        for(std::list<Hash>::iterator i=mBlockHeaderHashes.begin();i!=mBlockHeaderHashes.end();++i)
            if(*i == pHash)
            {
                mBlockHeaderHashMutex.unlock();
                return;
            }

        mBlockHeaderHashes.push_back(pHash);
        mBlockHeaderHashMutex.unlock();
    }

    void Node::requestBlock(Hash &pHash)
    {
        Message::GetDataData getDataData;
        getDataData.inventory.push_back(Message::InventoryHash(Message::InventoryHash::BLOCK, pHash));
        sendMessage(&getDataData);
        Events::instance().post(Event::BLOCK_REQUESTED);
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Requested block : %s", mID, pHash.hex().text());
    }

    bool Node::versionSupported(int32_t pVersion)
    {
        // TODO Check version protocol
        return true;
    }

    void Node::sendMessage(Message::Data *pData)
    {
        ArcMist::Buffer send;
        Message::writeFull(pData, &send);
        mConnection.send(&send);
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Sent <%s>", mID, Message::nameFor(pData->type));
    }

    void Node::sendVersion()
    {
        Info &info = Info::instance();
        Message::VersionData versionMessage(mConnection.ipv6Bytes(), mConnection.port(), info.ip, info.port,
          info.fullMode, BlockChain::instance().blockCount(), info.fullMode);
        sendMessage(&versionMessage);
        mVersionSent = true;
    }

    void Node::sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason)
    {
        Message::RejectData rejectMessage(pCommand, pCode, pReason, NULL);
        sendMessage(&rejectMessage);
    }

    void Node::process()
    {
        if(!mConnection.isOpen() || !mConnection.receive(&mReceiveBuffer))
            return;

        // Check for a complete message
        Message::Data *message = Message::readFull(&mReceiveBuffer);
        bool dontDeleteMessage = false;

        if(message == NULL)
        {
            // Check type of pending message
            Message::Type pendingType = Message::pendingType(&mReceiveBuffer);
            if(pendingType == Message::BLOCK)
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "Started receiving block");
                Events::instance().post(Event::BLOCK_RECEIVE_PARTIAL);
            }

            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Received <%s>", mID, Message::nameFor(message->type));
        mLastTime = getTime();

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
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Version : %s (%d), %d blocks, relay on",
                      mID, mVersionData->userAgent.text(), mVersionData->version, mVersionData->startBlockHeight);
                else
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Version : %s (%d), %d blocks, relay off",
                      mID, mVersionData->userAgent.text(), mVersionData->version, mVersionData->startBlockHeight);

                if(!versionSupported(mVersionData->version))
                    sendReject(Message::nameFor(message->type), Message::RejectData::PROTOCOL, "");

                //TODO Reject recent sent version nonces

                // Send version acknowledge
                Message::Data versionAcknowledgeMessage(Message::VERACK);
                sendMessage(&versionAcknowledgeMessage);
                mVersionAcknowledgeSent = true;

                // Update peer
                if(mVersionData->relay && mVersionAcknowledged)
                {
                    mAddress.updateTime();
                    mAddress.services = mVersionData->transmittingServices;
                    if(mAddress.port == 0)
                        mAddress.port = mVersionData->transmittingPort;
                    Info::instance().updatePeer(mAddress, mVersionData->userAgent);
                }

                // Ask for block inventory
                if(mVersionData->relay)
                {
                    // Send "send headers" message
                    Message::Data sendHeadersData(Message::SEND_HEADERS);
                    sendMessage(&sendHeadersData);

                    // Send get blocks
                    Message::GetBlocksData getBlocksData;

                    // Request to stop on highest block
                    getBlocksData.stopHeaderHash.setSize(32);
                    getBlocksData.stopHeaderHash.zeroize();

                    //TODO Add some recent header hashes to the Get Blocks message
                    //BlockChain &blockChain = BlockChain::instance();
                    //if(!blockChain.lastBlockHeaderHash().isEmpty())
                    //{
                    //    getBlocksData.blockHeaderHashes.
                    //}

                    sendMessage(&getBlocksData);
                }

                break;
            }
            case Message::VERACK:
                mVersionAcknowledged = true;

                // Update peer
                if(mVersionData != NULL && mVersionData->relay)
                {
                    mAddress.updateTime();
                    mAddress.services = mVersionData->transmittingServices;
                    if(mAddress.port == 0)
                        mAddress.port = mVersionData->transmittingPort;
                    Info::instance().updatePeer(mAddress, mVersionData->userAgent);
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
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Pong nonce doesn't match sent Ping", mID);
                break;

            case Message::REJECT:
            {
                Message::RejectData *rejectData = (Message::RejectData *)message;
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_NODE_LOG_NAME, "[%d] Reject %s [%02x] - %s", mID,
                  rejectData->command, rejectData->code, rejectData->reason);

                // TODO Determine if closing node is necessary
                break;
            }
            case Message::GET_ADDRESSES:
            {
                // Send known peer addresses
                Message::AddressesData addressData;
                std::vector<Peer *> peers;

                // Get list of peers
                Info::instance().randomizePeers(peers);

                unsigned int count = peers.size();
                if(count > 100) // Maximum of 100
                    count = 100;

                // Add peers to message
                addressData.addresses.resize(count);
                for(unsigned int i=0;i<count;i++)
                    addressData.addresses[i] = peers[i]->address;

                sendMessage(&addressData);
                break;
            }
            case Message::ADDRESSES:
            {
                Message::AddressesData *addressesData = (Message::AddressesData *)message;

                Info &info = Info::instance();
                for(unsigned int i=0;i<addressesData->addresses.size();i++)
                    info.updatePeer(addressesData->addresses[i], NULL);

                break;
            }
            case Message::ALERT:
                //TODO Determine if anything needs to be done for alerts
                break;

            case Message::FEE_FILTER:
                mMinimumFeeRate = ((Message::FeeFilterData *)message)->minimumFeeRate;
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_NODE_LOG_NAME, "[%d] Fee minimum rate set to %d", mID,
                  mMinimumFeeRate);
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
                BlockChain &blockChain = BlockChain::instance();

                // Find appropriate hashes
                for(std::vector<Hash>::iterator i=getBlocksData->blockHeaderHashes.begin();i!=getBlocksData->blockHeaderHashes.end();++i)
                {
                    blockChain.getBlockHashes(hashes, *i, 200);
                    if(hashes.size() > 0)
                        break;
                }

                if(hashes.size() == 0)
                {
                    // No matching starting hashes found. Start from genesis
                    Hash emptyHash;
                    blockChain.getBlockHashes(hashes, emptyHash, 200);
                }

                unsigned int count = hashes.size();
                if(count > 200) // Maximum of 200
                    count = 200;

                // Add inventory to message
                bool dontStop = getBlocksData->stopHeaderHash.isZero();
                inventoryData.inventory.resize(count);
                unsigned int finalCount = 0;
                for(unsigned int i=0;i<count;i++)
                {
                    finalCount++;
                    inventoryData.inventory[i].type = Message::InventoryHash::BLOCK;
                    inventoryData.inventory[i].hash = *hashes[i];
                    if(dontStop || *hashes[i] == getBlocksData->stopHeaderHash)
                        break;
                }
                inventoryData.inventory.resize(finalCount);

                sendMessage(&inventoryData);
                break;
            }
            case Message::BLOCK:
            {
                Events::instance().post(Event::BLOCK_RECEIVE_FINISHED);
                if(BlockChain::instance().addPendingBlock(((Message::BlockData *)message)->block))
                    ((Message::BlockData *)message)->block = NULL; // Memory has been handed off
                break;
            }
            case Message::GET_DATA:
                // TODO Implement GET_DATA
                break;

            case Message::GET_HEADERS:
                // TODO Implement GET_HEADERS
                break;

            case Message::HEADERS:
            {
                Message::HeadersData *headersData = (Message::HeadersData *)message;
                BlockChain &blockChain = BlockChain::instance();
                std::vector<Block *> blockHeadersToRemove;

                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                  "[%d] Headers message with %d block headers", mID, headersData->headers.size());

                for(std::vector<Block *>::iterator i=headersData->headers.begin();i!=headersData->headers.end();++i)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                      "[%d] Header : %s", mID, (*i)->hash.hex().text());
                    if(blockChain.addPendingBlockHeader(*i))
                        blockHeadersToRemove.push_back(*i);
                }

                // Remove any block pointers added to block chain so they won't be deleted with this data
                for(std::vector<Block *>::iterator i=blockHeadersToRemove.begin();i!=blockHeadersToRemove.end();++i)
                    headersData->headers.erase(i);

                break;
            }
            case Message::INVENTORY:
            {
                Message::InventoryData *inventoryData = (Message::InventoryData *)message;
                BlockChain &blockChain = BlockChain::instance();
                Hash startBlockHash, stopBlockHash;

                for(std::vector<Message::InventoryHash>::iterator i=inventoryData->inventory.begin();i!=inventoryData->inventory.end();++i)
                {
                    if((*i).type == Message::InventoryHash::BLOCK)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                          "[%d] Inventory block header hash : %s", mID, (*i).hash.hex().text());
                        addBlockHeaderHash((*i).hash);
                        if(blockChain.lastBlockHash().isEmpty())
                            startBlockHash = (*i).hash;
                        else if(!startBlockHash.isEmpty())
                            stopBlockHash = (*i).hash;
                        else if((*i).hash == blockChain.lastBlockHash())
                            startBlockHash = (*i).hash;
                    }
                    else if((*i).type == Message::InventoryHash::TRANSACTION)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                          "[%d] Inventory transaction hash : %s", mID, (*i).hash.hex().text());
                        // TODO Transaction inventory messages
                    }
                }

                if(!startBlockHash.isEmpty())
                {
                    if(stopBlockHash.isEmpty())
                        stopBlockHash = startBlockHash;

                    // Request block headers
                    Message::GetHeadersData getHeadersData;
                    getHeadersData.blockHeaderHashes.push_back(startBlockHash);
                    getHeadersData.stopHeaderHash = stopBlockHash;
                    sendMessage(&getHeadersData);
                }

                break;
            }
            case Message::MEM_POOL:
                // TODO Implement MEM_POOL
                break;

            case Message::MERKLE_BLOCK:
                // TODO Implement MERKLE_BLOCK
                break;

            case Message::NOT_FOUND:
                // TODO Implement NOT_FOUND
                break;

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
