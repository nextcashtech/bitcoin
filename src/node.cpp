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

    Node::Node(IPAddress &pAddress) : mBlockHashMutex("Node Block Header Hash")
    {
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
        mLastBlockHashRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;

        if(!mConnection.open(AF_INET6, pAddress.ip, pAddress.port))
        {
            Info::instance().addPeerFail(pAddress);
            return;
        }

        sendVersion();
    }

    Node::Node(const char *pIP, const char *pPort) : mBlockHashMutex("Node Block Header Hash")
    {
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
        mLastBlockHashRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;

        if(!mConnection.open(pIP, pPort))
        {
            mAddress = mConnection;
            Info::instance().addPeerFail(mAddress);
            return;
        }

        mAddress = mConnection;
        sendVersion();
    }

    Node::Node(unsigned int pFamily, const uint8_t *pIP, uint16_t pPort) : mBlockHashMutex("Node Block Header Hash")
    {
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
        mLastBlockHashRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;

        if(!mConnection.open(pFamily, pIP, pPort))
        {
            mAddress = mConnection;
            Info::instance().addPeerFail(mAddress);
            return;
        }

        mAddress = mConnection;
        sendVersion();
    }

    Node::~Node()
    {
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Disconnecting", mID);
        mConnection.close();
        if(mVersionData != NULL)
            delete mVersionData;
    }

    void Node::clear()
    {
        mConnection.close();
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
        mLastReceiveTime = getTime();
        mLastPingTime = 0;

        mHeaderRequested.clear();
        mBlockRequested.clear();

        clearInventory();
    }

    bool Node::shouldRequestInventory()
    {
        mBlockHashMutex.lock();
        uint64_t time = getTime();
        bool result = (mBlockHashCount == 0 && time - mLastBlockHashRequest > 300) ||
          time - mLastBlockHashRequest > 21600;
        mBlockHashMutex.unlock();
        return result;
    }

    bool Node::hasInventory()
    {
        mBlockHashMutex.lock();
        bool result = mBlockHashCount != 0;
        mBlockHashMutex.unlock();
        return result;
    }

    bool Node::hasBlock(const Hash &pHash)
    {
        mBlockHashMutex.lock();
        std::list<Hash> &hashes = mBlockHashes[pHash.lookup()];
        for(std::list<Hash>::iterator i=hashes.begin();i!=hashes.end();++i)
            if(*i == pHash)
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
        std::list<Hash> *set = mBlockHashes;
        for(unsigned int i=0;i<0xffff;i++)
        {
            set->clear();
            set++;
        }
        mBlockHashCount = 0;
        mBlockHashMutex.unlock();
    }

    void Node::addBlockHash(Hash &pHash)
    {
        mBlockHashMutex.lock();
        std::list<Hash> &hashes = mBlockHashes[pHash.lookup()];
        for(std::list<Hash>::iterator hash=hashes.begin();hash!=hashes.end();++hash)
            if(*hash == pHash)
            {
                mBlockHashMutex.unlock();
                return; // Already added
            }

        mBlockHashCount++;
        hashes.push_back(pHash);
        mBlockHashMutex.unlock();
    }

    void Node::removeBlockHash(Hash &pHash)
    {
        mBlockHashMutex.lock();
        std::list<Hash> &hashes = mBlockHashes[pHash.lookup()];
        for(std::list<Hash>::iterator hash=hashes.begin();hash!=hashes.end();++hash)
            if(*hash == pHash)
            {
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
        ArcMist::Buffer send;
        Message::writeFull(pData, &send);
        bool success = mConnection.send(&send);
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
        Chain &chain = Chain::instance();
        HashList hashList;

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
        else
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME,
              "[%d] Requesting block headers starting from genesis block", mID);
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

    bool Node::requestBlock(const Hash &pHash)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Requesting block : %s", mID, pHash.hex().text());
        Message::GetDataData getDataData;
        getDataData.inventory.push_back(Message::InventoryHash(Message::InventoryHash::BLOCK, pHash));
        bool success = sendMessage(&getDataData);
        if(success)
        {
            mBlockRequested = pHash;
            mLastBlockRequest = getTime();
            Events::instance().post(Event::BLOCK_REQUESTED);
            Chain::instance().markBlockRequested(pHash);
        }
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
        Chain &chain = Chain::instance();
        Info &info = Info::instance();
        Message::VersionData versionMessage(mConnection.ipv6Bytes(), mConnection.port(), info.ip, info.port,
          info.fullMode, chain.blockHeight(), chain.chainIsCurrent());
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
        if(!mConnection.isOpen() || !mConnection.receive(&mReceiveBuffer))
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

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Received <%s>", mID, Message::nameFor(message->type));
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

                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                  "[%d] Sending %d block hashes", mID, finalCount);
                sendMessage(&inventoryData);
                break;
            }
            case Message::BLOCK:
            {
                Events::instance().post(Event::BLOCK_RECEIVE_FINISHED);
                if(mBlockRequested == ((Message::BlockData *)message)->block->hash)
                {
                    mBlockRequested.clear();
                    mLastBlockRequest = 0;
                }
                if(Chain::instance().addPendingBlock(((Message::BlockData *)message)->block))
                    ((Message::BlockData *)message)->block = NULL; // Memory has been handed off
                break;
            }
            case Message::GET_DATA:
            {
                Message::GetDataData *getDataData = (Message::GetDataData *)message;
                Message::NotFoundData notFoundData;
                Chain &chain = Chain::instance();
                Block block;
                bool fail = false;

                for(std::vector<Message::InventoryHash>::iterator item=getDataData->inventory.begin();item!=getDataData->inventory.end();++item)
                {
                    switch(item->type)
                    {
                    case Message::InventoryHash::BLOCK:
                    {
                        if(chain.getBlock(item->hash, block))
                        {
                            if(!sendBlock(block))
                                fail = true;
                        }
                        else
                            notFoundData.inventory.push_back(*item);
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
                          "[%d] Unknown inventory item type %d", mID, item->type);
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

                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME,
                  "[%d] Added %d pending headers", mID, addedCount);

                break;
            }
            case Message::INVENTORY:
            {
                Message::InventoryData *inventoryData = (Message::InventoryData *)message;
                for(std::vector<Message::InventoryHash>::iterator i=inventoryData->inventory.begin();i!=inventoryData->inventory.end();++i)
                {
                    if((*i).type == Message::InventoryHash::BLOCK)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME,
                          "[%d] Inventory block hash : %s", mID, (*i).hash.hex().text());

                        addBlockHash((*i).hash);
                    }
                    else if((*i).type == Message::InventoryHash::TRANSACTION)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME,
                          "[%d] Inventory transaction hash : %s", mID, (*i).hash.hex().text());
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
                for(std::vector<Message::InventoryHash>::iterator item=notFoundData->inventory.begin();item!=notFoundData->inventory.end();++item)
                {
                    switch(item->type)
                    {
                    case Message::InventoryHash::BLOCK:
                    {
                        if(item->hash == mBlockRequested)
                        {
                            Chain::instance().markBlockNotRequested(item->hash);
                            removeBlockHash(item->hash);
                            mBlockRequested.clear();
                            mLastBlockRequest = 0;
                        }
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
                          "[%d] Unknown not found inventory item type %d", mID, item->type);
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
