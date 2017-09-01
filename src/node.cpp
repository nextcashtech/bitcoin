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
        mLastTime = 0;
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
        mLastTime = 0;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        mVersionData = NULL;
        mID = mNextID++;
        mLastHeaderRequest = 0;
        mLastBlockRequest = 0;
        mBlockHashCount = 0;

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
        mLastTime = 0;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        mVersionData = NULL;
        mID = mNextID++;
        mLastHeaderRequest = 0;
        mLastBlockRequest = 0;
        mBlockHashCount = 0;

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
        mLastTime = 0;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        if(mVersionData != NULL)
            delete mVersionData;
        mVersionData = NULL;
        mLastHeaderRequest = 0;
        mLastBlockRequest = 0;
        mHeaderRequested.clear();
        mBlockRequested.clear();

        clearBlockHashes();
    }

    bool Node::hasBlocks()
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

    void Node::clearBlockHashes()
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

    void Node::addBlockHeaderHash(Hash &pHash)
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

    void Node::requestBlockHashes()
    {
        Chain &chain = Chain::instance();
        HashList hashList;

        chain.getReverseBlockHashes(hashList, 32);
        if(hashList.size() == 0)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Requesting block hashes starting from genesis", mID);
        else
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Requesting block hashes starting from %s", mID, hashList.front()->hex().text());

        Message::GetBlocksData getBlocksData;
        for(HashList::iterator hash=hashList.begin();hash!=hashList.end();++hash)
            getBlocksData.blockHeaderHashes.push_back(**hash);
        sendMessage(&getBlocksData);
    }

    void Node::requestHeaders(const Hash &pStartingHash)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Requesting block headers starting from %s", mID, pStartingHash.hex().text());
        Message::GetHeadersData getHeadersData;
        getHeadersData.blockHeaderHashes.push_back(pStartingHash);
        sendMessage(&getHeadersData);
        mHeaderRequested = pStartingHash;
        mLastHeaderRequest = getTime();
    }

    void Node::requestBlock(const Hash &pHash)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Requesting block : %s", mID, pHash.hex().text());
        Message::GetDataData getDataData;
        getDataData.inventory.push_back(Message::InventoryHash(Message::InventoryHash::BLOCK, pHash));
        sendMessage(&getDataData);
        mBlockRequested = pHash;
        mLastBlockRequest = getTime();
        Events::instance().post(Event::BLOCK_REQUESTED);
    }

    void Node::sendVersion()
    {
        Chain &chain = Chain::instance();
        Info &info = Info::instance();
        Message::VersionData versionMessage(mConnection.ipv6Bytes(), mConnection.port(), info.ip, info.port,
          info.fullMode, chain.blockCount(), chain.chainIsCurrent());
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
                    if(chain.blockInChain(*i))
                    {
                        chain.getBlockHashes(hashes, *i, 1000);
                        break;
                    }

                if(hashes.size() == 0)
                {
                    // No matching starting hashes found. Start from genesis
                    Hash emptyHash;
                    chain.getBlockHashes(hashes, emptyHash, 1000);
                }

                unsigned int count = hashes.size();
                if(count > 1000) // Maximum of 1000
                    count = 1000;

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
                // TODO Implement GET_DATA
                break;

            case Message::GET_HEADERS:
                // TODO Implement GET_HEADERS
                break;

            case Message::HEADERS:
            {
                Message::HeadersData *headersData = (Message::HeadersData *)message;
                Chain &chain = Chain::instance();

                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                  "[%d] Headers message with %d block headers", mID, headersData->headers.size());
                mHeaderRequested.clear();
                mLastHeaderRequest = 0;

                for(std::vector<Block *>::iterator header=headersData->headers.begin();header!=headersData->headers.end();)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME,
                      "[%d] Header : %s", mID, (*header)->hash.hex().text());

                    if(chain.addPendingBlockHeader(*header))
                    {
                        // memory will be deleted by block chain after it is processed so remove it from this list
                        header = headersData->headers.erase(header);
                    }
                    else
                        ++header;
                }

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

                        addBlockHeaderHash((*i).hash);
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
