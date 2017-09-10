#include "node.hpp"

#include "arcmist/base/log.hpp"
#include "info.hpp"
#include "message.hpp"
#include "events.hpp"
#include "block.hpp"
#include "chain.hpp"

#define BITCOIN_NODE_LOG_NAME "Node"


namespace BitCoin
{
    unsigned int Node::mNextID = 256;

    Node::Node(IPAddress &pAddress) : mBlockHashMutex("Node Block Header Hash"), mBlockRequestMutex("Node Block Request")
    {
        mConnected = false;
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        mVersionData = NULL;
        mID = mNextID++;
        mAddress = pAddress;
        mReceiveBuffer.setInputEndian(ArcMist::Endian::LITTLE);
        mReceiveBuffer.setOutputEndian(ArcMist::Endian::LITTLE);
        mLastHeaderRequest = 0;
        mLastBlockRequest = 0;
        mBlockHashCount = 0;
        mInventoryHeight = 0;
        mLastBlockHashRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;

        mConnection = new ArcMist::Network::Connection(AF_INET6, pAddress.ip, pAddress.port, 5);
        if(!mConnection->isOpen())
        {
            Info::instance().addPeerFail(pAddress);
            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Connected", mID);
        mConnected = true;

        sendVersion();
    }

    Node::Node(const char *pIP, const char *pPort) :
      mBlockHashMutex("Node Block Header Hash"), mBlockRequestMutex("Node Block Request")
    {
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
        mBlockHashCount = 0;
        mInventoryHeight = 0;
        mLastBlockHashRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;

        mConnection = new ArcMist::Network::Connection(pIP, pPort, 5);
        mAddress = *mConnection;
        if(!mConnection->isOpen())
        {
            Info::instance().addPeerFail(mAddress);
            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Connected", mID);
        mConnected = true;

        sendVersion();
    }

    Node::Node(unsigned int pFamily, const uint8_t *pIP, uint16_t pPort) :
      mBlockHashMutex("Node Block Header Hash"), mBlockRequestMutex("Node Block Request")
    {
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
        mBlockHashCount = 0;
        mInventoryHeight = 0;
        mLastBlockHashRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;

        mConnection = new ArcMist::Network::Connection(pFamily, pIP, pPort, 5);
        mAddress = *mConnection;
        if(!mConnection->isOpen())
        {
            Info::instance().addPeerFail(mAddress);
            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Connected", mID);
        mConnected = true;

        sendVersion();
    }

    Node::Node(ArcMist::Network::Connection *pConnection) :
      mBlockHashMutex("Node Block Header Hash"), mBlockRequestMutex("Node Block Request")
    {
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
        mBlockHashCount = 0;
        mInventoryHeight = 0;
        mLastBlockHashRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;

        mConnection = pConnection;
        mAddress = *mConnection;
        if(!mConnection->isOpen())
        {
            Info::instance().addPeerFail(mAddress);
            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Connected", mID);
        mConnected = true;

        sendVersion();
    }

    Node::~Node()
    {
        if(mConnected)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Disconnecting", mID);
        clearInventory();
        if(mConnection != NULL)
            delete mConnection;
        if(mVersionData != NULL)
            delete mVersionData;
    }

    void Node::clear()
    {
        if(mConnection != NULL)
        {
            delete mConnection;
            mConnection = NULL;
        }
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        if(mVersionData != NULL)
            delete mVersionData;
        mVersionData = NULL;
        mLastHeaderRequest = 0;
        mLastBlockRequest = 0;
        mLastBlockHashRequest = 0;
        mBlockHashCount = 0;
        mInventoryHeight = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;

        mHeaderRequested.clear();
        mBlocksRequested.clear();

        clearInventory();
    }

    bool Node::shouldRequestInventory()
    {
        mBlockHashMutex.lock();
        uint64_t time = getTime();
        bool result = (mBlockHashCount == 0 && time - mLastBlockHashRequest > 60) ||
          Chain::instance().blockHeight() > mInventoryHeight + 200;
        mBlockHashMutex.unlock();
        return result;
    }

    bool Node::hasInventory()
    {
        mBlockHashMutex.lock();
        bool result = mBlockHashCount != 0 && Chain::instance().blockHeight() + 200 > mInventoryHeight;
        mBlockHashMutex.unlock();
        return result;
    }

    bool Node::hasBlock(const Hash &pHash)
    {
        mBlockHashMutex.lock();
        std::list<Hash *> &hashes = mBlockHashes[pHash.lookup()];
        for(std::list<Hash *>::iterator hash=hashes.begin();hash!=hashes.end();++hash)
            if(**hash == pHash)
            {
                mBlockHashMutex.unlock();
                return true;
            }
        mBlockHashMutex.unlock();
        return false;
    }

    void Node::clearInventory()
    {
        mBlockHashMutex.lock();
        std::list<Hash *> *set = mBlockHashes;
        for(unsigned int i=0;i<0x10000;i++)
        {
            for(std::list<Hash *>::iterator hash=set->begin();hash!=set->end();++hash)
                delete *hash;
            set->clear();
            set++;
        }
        mBlockHashCount = 0;
        mBlockHashMutex.unlock();
    }

    void Node::addBlockHash(Hash &pHash)
    {
        mBlockHashMutex.lock();
        unsigned int lookup = pHash.lookup();
        std::list<Hash *> &hashes = mBlockHashes[lookup];
        for(std::list<Hash *>::iterator hash=hashes.begin();hash!=hashes.end();++hash)
            if(**hash == pHash)
            {
                mBlockHashMutex.unlock();
                return; // Already added
            }

        mBlockHashCount++;
        hashes.push_back(new Hash(pHash));
        mBlockHashMutex.unlock();
    }

    void Node::removeBlockHash(Hash &pHash)
    {
        mBlockHashMutex.lock();
        std::list<Hash *> &hashes = mBlockHashes[pHash.lookup()];
        for(std::list<Hash *>::iterator hash=hashes.begin();hash!=hashes.end();++hash)
            if(**hash == pHash)
            {
                delete *hash;
                hashes.erase(hash);
                mBlockHashCount--;
                mBlockHashMutex.unlock();
                break;
            }
        mBlockHashMutex.unlock();
    }

    bool Node::versionSupported(int32_t pVersion)
    {
        // TODO Check version protocol
        return true;
    }

    bool Node::sendMessage(Message::Data *pData)
    {
        if(mConnection == NULL)
            return false;

        ArcMist::Buffer send;
        Message::writeFull(pData, &send);
        bool success = mConnection->send(&send);
        if(success)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
              "[%d] Sent <%s>", mID, Message::nameFor(pData->type));
        else
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
              "[%d] Failed to send <%s>", mID, Message::nameFor(pData->type));
            mLastReceiveTime = 0; // Tell daemon to disconnect
        }
        return success;
    }

    bool Node::requestInventory()
    {
        if(getTime() - mLastBlockHashRequest < 120) // Recently requested
            return false;

        Chain &chain = Chain::instance();
        if(mBlockHashCount != 0 && !chain.isInSync() && chain.blockHeight() < mInventoryHeight + 200)
            return false;

        HashList hashList;

        clearInventory();
        mInventoryHeight = chain.blockHeight();

        chain.getReverseBlockHashes(hashList, 32);
        if(hashList.size() == 0)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME,
              "[%d] Requesting block hashes starting from genesis", mID);
        else
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME,
              "[%d] Requesting block hashes starting from %s", mID, hashList.front()->hex().text());

        Message::GetBlocksData getBlocksData;
        for(HashList::iterator hash=hashList.begin();hash!=hashList.end();++hash)
            getBlocksData.blockHeaderHashes.push_back(**hash);
        bool success = sendMessage(&getBlocksData);
        if(success)
            mLastBlockHashRequest = getTime();
        return success;
    }

    bool Node::requestHeaders(const Hash &pStartingHash)
    {
        if(!pStartingHash.isEmpty())
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME,
              "[%d] Requesting block headers starting from %s", mID, pStartingHash.hex().text());
        else if(hasBlock(pStartingHash))
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME,
              "[%d] Requesting block headers starting from genesis block", mID);
        else
            return false;

        Message::GetHeadersData getHeadersData;
        if(!pStartingHash.isEmpty())
            getHeadersData.blockHeaderHashes.push_back(pStartingHash);
        bool success = sendMessage(&getHeadersData);
        if(success)
        {
            mHeaderRequested = pStartingHash;
            mLastHeaderRequest = getTime();
        }
        return success;
    }

    bool Node::requestBlocks(unsigned int pCount, bool pReduceOnly)
    {
        Chain &chain = Chain::instance();
        Hash startHash = chain.nextBlockNeeded(pReduceOnly);

        if(waitingForBlock() || startHash.isEmpty() || !hasBlock(startHash))
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
            Chain::instance().markBlockRequested(nextBlockHash);
            sentCount++;
            if(sentCount < pCount)
            {
                nextBlockHash = chain.nextBlockNeeded(pReduceOnly);
                if(!hasBlock(nextBlockHash))
                    break;
            }
            else
                break;
        }

        bool success = sendMessage(&getDataData);
        if(success)
        {
            mLastBlockRequest = getTime();
            Events::instance().post(Event::BLOCK_REQUESTED);
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
              "[%d] Requested %d blocks starting at : %s", mID, sentCount, startHash.hex().text());
        }
        else
        {
            for(HashList::iterator hash=mBlocksRequested.begin();hash!=mBlocksRequested.end();++hash)
                Chain::instance().markBlockNotRequested(**hash);
            mBlocksRequested.clear();
        }

        mBlockRequestMutex.unlock();
        return success;
    }

    bool Node::sendBlock(Block &pBlock)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Sending block : %s",
          mID, pBlock.hash.hex().text());
        Message::BlockData blockData;
        blockData.block = &pBlock;
        return sendMessage(&blockData);
    }

    bool Node::sendVersion()
    {
        if(mConnection == NULL)
            return false;

        Chain &chain = Chain::instance();
        Info &info = Info::instance();
        // Apparently if relay is off most of main net won't send blocks or headers
        Message::VersionData versionMessage(mConnection->ipv6Bytes(), mConnection->port(), info.ip, info.port,
          info.fullMode, chain.blockHeight(), true); //chain.isInSync());
        bool success = sendMessage(&versionMessage);
        mVersionSent = true;
        return success;
    }

    bool Node::sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason)
    {
        Message::RejectData rejectMessage(pCommand, pCode, pReason, NULL);
        return sendMessage(&rejectMessage);
    }

    void Node::process()
    {
        if(mConnection == NULL)
            return;

        if(!mConnection->isOpen() || !mConnection->receive(&mReceiveBuffer))
            return;

        // Check for a complete message
        Message::Data *message = Message::readFull(&mReceiveBuffer);
        bool dontDeleteMessage = false;

        if(message == NULL)
        {
            uint64_t time = getTime();
            if(time - mLastReceiveTime > 1200 && // 20 minutes
              time - mLastPingTime > 30)
            {
                Message::PingData pingData;
                sendMessage(&pingData);
                mLastPingTime = getTime();
            }
            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME, "[%d] Received <%s>",
          mID, Message::nameFor(message->type));
        mLastReceiveTime = getTime();

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

                // Send "send headers" message
                Message::Data sendHeadersData(Message::SEND_HEADERS);
                sendMessage(&sendHeadersData);

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
                Info::instance().randomizePeers(peers, 1);

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
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Fee minimum rate set to %d", mID,
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
                Chain &chain = Chain::instance();

                // Find appropriate hashes
                for(std::vector<Hash>::iterator i=getBlocksData->blockHeaderHashes.begin();i!=getBlocksData->blockHeaderHashes.end();++i)
                    if(chain.getBlockHashes(hashes, *i, 500))
                        break;

                if(hashes.size() == 0)
                {
                    // No matching starting hashes found. Start from genesis
                    Hash emptyHash;
                    chain.getBlockHashes(hashes, emptyHash, 500);
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

                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                  "[%d] Sending %d block hashes", mID, actualCount);
                sendMessage(&inventoryData);
                break;
            }
            case Message::BLOCK:
            {
                Events::instance().post(Event::BLOCK_RECEIVE_FINISHED);
                mBlockRequestMutex.lock();
                for(HashList::iterator hash=mBlocksRequested.begin();hash!=mBlocksRequested.end();++hash)
                    if(**hash == ((Message::BlockData *)message)->block->hash)
                    {
                        delete *hash;
                        mBlocksRequested.erase(hash);
                        break;
                    }
                if(mBlocksRequested.size() == 0)
                    mLastBlockRequest = 0;
                mBlockRequestMutex.unlock();
                if(Chain::instance().addPendingBlock(((Message::BlockData *)message)->block))
                {
                    ((Message::BlockData *)message)->block = NULL; // Memory has been handed off
                    Info::instance().updatePeer(mAddress, mVersionData->userAgent);
                }
                break;
            }
            case Message::GET_DATA:
            {
                Message::GetDataData *getDataData = (Message::GetDataData *)message;
                Message::NotFoundData notFoundData;
                Chain &chain = Chain::instance();
                Block block;
                bool fail = false;

                for(Message::Inventory::iterator item=getDataData->inventory.begin();item!=getDataData->inventory.end();++item)
                {
                    switch((*item)->type)
                    {
                    case Message::InventoryHash::BLOCK:
                    {
                        if(chain.getBlock((*item)->hash, block))
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
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                          "[%d] Unknown inventory item type %d", mID, (*item)->type);
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
                Chain &chain = Chain::instance();
                BlockList blockList;

                for(std::vector<Hash>::iterator hash=getHeadersData->blockHeaderHashes.begin();hash!=getHeadersData->blockHeaderHashes.end();++hash)
                    if(chain.getBlockHeaders(blockList, *hash, getHeadersData->stopHeaderHash, 2000))
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

                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                      "[%d] Sending %d block headers", mID, headersData.headers.size());
                    sendMessage(&headersData);
                }
                break;
            }
            case Message::HEADERS:
            {
                Message::HeadersData *headersData = (Message::HeadersData *)message;
                Chain &chain = Chain::instance();
                unsigned int addedCount = 0;

                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                  "[%d] Received %d block headers", mID, headersData->headers.size());
                mHeaderRequested.clear();
                mLastHeaderRequest = 0;

                for(std::vector<Block *>::iterator header=headersData->headers.begin();header!=headersData->headers.end();)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME,
                      "[%d] Header : %s", mID, (*header)->hash.hex().text());

                    if(chain.addPendingHeader(*header))
                    {
                        // memory will be deleted by block chain after it is processed so remove it from this list
                        header = headersData->headers.erase(header);
                        addedCount++;
                    }
                    else
                        ++header;
                }

                if(addedCount > 0)
                    Info::instance().updatePeer(mAddress, mVersionData->userAgent);

                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME,
                  "[%d] Added %d pending headers", mID, addedCount);

                break;
            }
            case Message::INVENTORY:
            {
                Message::InventoryData *inventoryData = (Message::InventoryData *)message;
                for(Message::Inventory::iterator item=inventoryData->inventory.begin();item!=inventoryData->inventory.end();++item)
                {
                    if((*item)->type == Message::InventoryHash::BLOCK)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME,
                          "[%d] Inventory block hash : %s", mID, (*item)->hash.hex().text());

                        addBlockHash((*item)->hash);
                    }
                    else if((*item)->type == Message::InventoryHash::TRANSACTION)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME,
                          "[%d] Inventory transaction hash : %s", mID, (*item)->hash.hex().text());
                        //TODO Transaction inventory messages
                    }
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
                                delete *hash;
                                mBlocksRequested.erase(hash);
                                Chain::instance().markBlockNotRequested((*item)->hash);
                                removeBlockHash((*item)->hash);
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
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                          "[%d] Unknown not found inventory item type %d", mID, (*item)->type);
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
