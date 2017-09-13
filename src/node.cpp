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

    Node::Node(IPAddress &pAddress, Chain &pChain) :
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
        mAddress = pAddress;
        mReceiveBuffer.setInputEndian(ArcMist::Endian::LITTLE);
        mReceiveBuffer.setOutputEndian(ArcMist::Endian::LITTLE);
        mLastHeaderRequest = 0;
        mLastBlockRequest = 0;
        mBlockHashCount = 0;
        mInventoryHeight = 0;
        mLastInventoryRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;
        mBlocksRequestedCount = 0;
        mBlocksReceivedCount = 0;
        mLastBlockReceiveTime = 0;
        mMessagesReceived = 0;
        mConnectedTime = getTime();

        mConnection = new ArcMist::Network::Connection(AF_INET6, pAddress.ip, pAddress.port, 5);
        if(!mConnection->isOpen())
        {
            Info::instance().addPeerFail(pAddress);
            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Connected", mID);
        mConnected = true;

        sendVersion(pChain);
    }

    Node::Node(const char *pIP, const char *pPort, Chain &pChain) :
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
        mLastInventoryRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;
        mBlocksRequestedCount = 0;
        mBlocksReceivedCount = 0;
        mLastBlockReceiveTime = 0;
        mMessagesReceived = 0;
        mConnectedTime = getTime();

        mConnection = new ArcMist::Network::Connection(pIP, pPort, 5);
        mAddress = *mConnection;
        if(!mConnection->isOpen())
        {
            Info::instance().addPeerFail(mAddress);
            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Connected", mID);
        mConnected = true;

        sendVersion(pChain);
    }

    Node::Node(unsigned int pFamily, const uint8_t *pIP, uint16_t pPort, Chain &pChain) :
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
        mLastInventoryRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;
        mBlocksRequestedCount = 0;
        mBlocksReceivedCount = 0;
        mLastBlockReceiveTime = 0;
        mMessagesReceived = 0;
        mConnectedTime = getTime();

        mConnection = new ArcMist::Network::Connection(pFamily, pIP, pPort, 5);
        mAddress = *mConnection;
        if(!mConnection->isOpen())
        {
            Info::instance().addPeerFail(mAddress);
            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Connected", mID);
        mConnected = true;

        sendVersion(pChain);
    }

    Node::Node(ArcMist::Network::Connection *pConnection, Chain &pChain) :
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
        mLastInventoryRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;
        mBlocksRequestedCount = 0;
        mBlocksReceivedCount = 0;
        mLastBlockReceiveTime = 0;
        mMessagesReceived = 0;
        mConnectedTime = getTime();

        mConnection = pConnection;
        mAddress = *mConnection;
        if(!mConnection->isOpen())
        {
            Info::instance().addPeerFail(mAddress);
            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME, "[%d] Connected", mID);
        mConnected = true;

        sendVersion(pChain);
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
        mLastInventoryRequest = 0;
        mLastReceiveTime = getTime();
        mLastPingTime = 0;
        mBlocksRequestedCount = 0;
        mBlocksReceivedCount = 0;

        mHeaderRequested.clear();
        mBlocksRequested.clear();

        clearInventory();
    }

    void Node::collectStatistics(Statistics &pCollection)
    {
        mStatistics.bytesReceived += mConnection->bytesReceived();
        mStatistics.bytesSent += mConnection->bytesSent();
        mConnection->resetByteCounts();
        pCollection += mStatistics;
        mStatistics.clear();
    }

    bool Node::notResponding() const
    {
        uint32_t time = getTime();
        // Requested inventory not received within 2 minutes of request
        return (mLastInventoryRequest != 0 && mBlockHashCount == 0 && time - mLastInventoryRequest > 120) ||
        // Requested blocks not received within 5 minutes of request
          (mLastBlockRequest != 0 && time - mLastBlockRequest > 300 && mLastBlockRequest > mLastBlockReceiveTime);
    }

    // Update inventory height for any hashes that we didn't know the height of at the time we received them
    void Node::refreshInventoryHeight(Chain &pChain)
    {
        mBlockHashMutex.lock();
        unsigned int previousInventoryHeight = mInventoryHeight;
        std::list<BlockHashInfo *> *set = mBlockHashes;
        for(unsigned int i=0;i<0x10000;i++)
        {
            for(std::list<BlockHashInfo *>::iterator hash=set->begin();hash!=set->end();++hash)
            {
                if((*hash)->height == 0xffffffff)
                    (*hash)->height = pChain.height((*hash)->hash);
                if((*hash)->height != 0xffffffff && (*hash)->height > mInventoryHeight)
                {
                    mHighestInventoryHash = (*hash)->hash;
                    mInventoryHeight = (*hash)->height;
                }
            }
            set++;
        }
        if(previousInventoryHeight != mInventoryHeight)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
              "[%d] Inventory height changed from %d to %d", mID, previousInventoryHeight, mInventoryHeight);
        mBlockHashMutex.unlock();
    }

    bool Node::hasInventory()
    {
        mBlockHashMutex.lock();
        bool result = mInventoryHeight > 0;
        mBlockHashMutex.unlock();
        return result;
    }

    bool Node::hasBlock(const Hash &pHash)
    {
        if(pHash.isEmpty())
            return false;

        mBlockHashMutex.lock();
        std::list<BlockHashInfo *> &hashes = mBlockHashes[pHash.lookup()];
        for(std::list<BlockHashInfo *>::iterator hash=hashes.begin();hash!=hashes.end();++hash)
            if((*hash)->hash == pHash)
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
        std::list<BlockHashInfo *> *set = mBlockHashes;
        for(unsigned int i=0;i<0x10000;i++)
        {
            for(std::list<BlockHashInfo *>::iterator hash=set->begin();hash!=set->end();++hash)
                delete *hash;
            set->clear();
            set++;
        }
        mBlockHashCount = 0;
        mHighestInventoryHash.clear();
        mInventoryHeight = 0;
        mBlockHashMutex.unlock();
    }

    void Node::addBlockHash(Chain &pChain, Hash &pHash)
    {
        mBlockHashMutex.lock();
        unsigned int lookup = pHash.lookup();
        std::list<BlockHashInfo *> &hashes = mBlockHashes[lookup];
        for(std::list<BlockHashInfo *>::iterator hash=hashes.begin();hash!=hashes.end();++hash)
            if((*hash)->hash == pHash)
            {
                if((*hash)->height == 0xffffffff)
                    (*hash)->height = pChain.height((*hash)->hash);
                mBlockHashMutex.unlock();
                return; // Already added
            }

        mBlockHashCount++;
        unsigned int height = pChain.height(pHash);
        if(height != 0xffffffff && height > mInventoryHeight)
        {
            mHighestInventoryHash = pHash;
            mInventoryHeight = height;
        }
        hashes.push_back(new BlockHashInfo(pHash, height));
        mBlockHashMutex.unlock();
    }

    void Node::removeBlockHash(Hash &pHash)
    {
        mBlockHashMutex.lock();
        std::list<BlockHashInfo *> &hashes = mBlockHashes[pHash.lookup()];
        for(std::list<BlockHashInfo *>::iterator hash=hashes.begin();hash!=hashes.end();++hash)
            if((*hash)->hash == pHash)
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
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME,
              "[%d] Sent <%s>", mID, Message::nameFor(pData->type));
        else
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
              "[%d] Failed to send <%s>", mID, Message::nameFor(pData->type));
            mConnection->close(); // Disconnect
        }
        return success;
    }

    bool Node::requestInventory(Chain &pChain)
    {
        if(mLastInventoryRequest != 0 && getTime() - mLastInventoryRequest < 180) // Recently requested
            return false;

        if(mLastInventoryRequest != 0 && mBlockHashCount == 0)
        {
            // No response from previous inventory request
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_NODE_LOG_NAME,
              "[%d] Did not send inventory. Dropping", mID);
            if(mConnection != NULL)
                mConnection->close();
            return false;
        }

        refreshInventoryHeight(pChain);
        unsigned int pendingHeight = pChain.pendingBlockHeight();
        if(mInventoryHeight == pendingHeight)
            return false;

        // Add latest block
        Message::GetBlocksData getBlocksData;
        if(mInventoryHeight > pChain.blockHeight())
            getBlocksData.blockHeaderHashes.push_back(mHighestInventoryHash);
        else if(pChain.blockHeight() > 1)
        {
            // Request second to last so that they will return me the last so I have something to line up on
            Hash secondToLastHash;
            pChain.getBlockHash(pChain.blockHeight() - 1, secondToLastHash);
            getBlocksData.blockHeaderHashes.push_back(secondToLastHash);
        }

        // Add some older blocks to help with matching
        if(mInventoryHeight == 0)
        {
            HashList hashList;
            pChain.getReverseBlockHashes(hashList, 10);
            for(HashList::iterator hash=hashList.begin();hash!=hashList.end();++hash)
                getBlocksData.blockHeaderHashes.push_back(**hash);
        }

        if(getBlocksData.blockHeaderHashes.size() == 0)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME,
              "[%d] Requesting block hashes after genesis", mID);
        else
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME,
              "[%d] Requesting block hashes after (%d) : %s", mID,
              pChain.height(getBlocksData.blockHeaderHashes.front()),
              getBlocksData.blockHeaderHashes.front().hex().text());

        bool success = sendMessage(&getBlocksData);
        if(success)
            mLastInventoryRequest = getTime();
        return success;
    }

    bool Node::requestHeaders(Chain &pChain, const Hash &pStartingHash)
    {
        if(!pStartingHash.isEmpty())
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME,
              "[%d] Requesting block headers starting from (%d) : %s", mID, pChain.height(pStartingHash),
              pStartingHash.hex().text());
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

    bool Node::requestBlocks(Chain &pChain, unsigned int pCount, bool pReduceOnly)
    {
        Hash startHash = pChain.nextBlockNeeded(pReduceOnly);

        if(waitingForBlocks() || startHash.isEmpty() || !hasBlock(startHash))
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
                if(nextBlockHash.isEmpty() || !hasBlock(nextBlockHash))
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
            Events::instance().post(Event::BLOCK_REQUESTED);
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
              "[%d] Requested %d blocks starting at (%d) : %s", mID, sentCount,
              pChain.height(startHash), startHash.hex().text());
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
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Sending block : %s",
          mID, pBlock.hash.hex().text());
        Message::BlockData blockData;
        blockData.block = &pBlock;
        bool success = sendMessage(&blockData);
        if(success)
            ++mStatistics.blocksSent;
        return success;
    }

    bool Node::sendVersion(Chain &pChain)
    {
        if(mConnection == NULL)
            return false;

        Info &info = Info::instance();
        // Apparently if relay is off most of main net won't send blocks or headers
        Message::VersionData versionMessage(mConnection->ipv6Bytes(), mConnection->port(), info.ip, info.port,
          info.fullMode, pChain.blockHeight(), true); //chain.isInSync());
        bool success = sendMessage(&versionMessage);
        mVersionSent = true;
        return success;
    }

    bool Node::sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason)
    {
        Message::RejectData rejectMessage(pCommand, pCode, pReason, NULL);
        return sendMessage(&rejectMessage);
    }

    void Node::process(Chain &pChain)
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

            if(mMessagesReceived == 0 && time - mConnectedTime > 60)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_NODE_LOG_NAME,
                  "[%d] No valid messages within 60 seconds of connecting", mID);
                mConnection->close();
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

        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME, "[%d] Received <%s>",
          mID, Message::nameFor(message->type));
        mLastReceiveTime = getTime();

        if(mMessagesReceived == 0 && message->type != Message::VERSION && message->type != Message::VERACK)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_NODE_LOG_NAME,
              "[%d] First message not a version or verack message : <%s>",
              mID, Message::nameFor(message->type));
            mConnection->close();
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
                    if(mAddress.port == 0)
                        mAddress.port = mVersionData->transmittingPort;
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
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "[%d] Pong nonce doesn't match sent Ping", mID);
                break;

            case Message::REJECT:
            {
                Message::RejectData *rejectData = (Message::RejectData *)message;
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_NODE_LOG_NAME, "[%d] Reject %s [%02x] - %s", mID,
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
                if(count > 100) // Maximum of 100
                    count = 100;

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

                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                  "[%d] Sending %d block hashes", mID, actualCount);
                sendMessage(&inventoryData);
                break;
            }
            case Message::BLOCK:
            {
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME,
                  "[%d] Received block %s", mID, ((Message::BlockData *)message)->block->hash.hex().text());
                Events::instance().post(Event::BLOCK_RECEIVE_FINISHED);
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

                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                      "[%d] Sending %d block headers", mID, headersData.headers.size());
                    if(sendMessage(&headersData))
                        mStatistics.headersSent += headersData.headers.size();
                }
                break;
            }
            case Message::HEADERS:
            {
                Message::HeadersData *headersData = (Message::HeadersData *)message;
                unsigned int addedCount = 0;

                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                  "[%d] Received %d block headers", mID, headersData->headers.size());
                mHeaderRequested.clear();
                mLastHeaderRequest = 0;
                mStatistics.headersReceived += headersData->headers.size();

                for(std::vector<Block *>::iterator header=headersData->headers.begin();header!=headersData->headers.end();)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME,
                      "[%d] Header : %s", mID, (*header)->hash.hex().text());

                    if(pChain.addPendingHeader(*header))
                    {
                        // memory will be deleted by block chain after it is processed so remove it from this list
                        header = headersData->headers.erase(header);
                        addedCount++;
                    }
                    else
                        ++header;
                }

                if(addedCount > 0)
                    Info::instance().updatePeer(mAddress, mVersionData->userAgent, mVersionData->transmittingServices);

                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME,
                  "[%d] Added %d pending headers", mID, addedCount);

                break;
            }
            case Message::INVENTORY:
            {
                Message::InventoryData *inventoryData = (Message::InventoryData *)message;
                unsigned int blockHashCount = 0;
                unsigned int previousInventoryHeight = mInventoryHeight;
                for(Message::Inventory::iterator item=inventoryData->inventory.begin();item!=inventoryData->inventory.end();++item)
                {
                    if((*item)->type == Message::InventoryHash::BLOCK)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME,
                          "[%d] Inventory block hash : %s", mID, (*item)->hash.hex().text());

                        addBlockHash(pChain, (*item)->hash);
                        blockHashCount++;
                    }
                    else if((*item)->type == Message::InventoryHash::TRANSACTION)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_NODE_LOG_NAME,
                          "[%d] Inventory transaction hash : %s", mID, (*item)->hash.hex().text());
                        //TODO Transaction inventory messages
                    }
                }
                if(blockHashCount > 0)
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                      "[%d] Received %d block hashes", mID, blockHashCount);
                if(previousInventoryHeight != mInventoryHeight)
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                      "[%d] Inventory height changed from %d to %d", mID, previousInventoryHeight, mInventoryHeight);
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
                                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_NODE_LOG_NAME,
                                  "[%d] Block hash returned not found : %s", mID, (*hash)->hex().text());
                                delete *hash;
                                mBlocksRequested.erase(hash);
                                pChain.markBlockNotRequested((*item)->hash);
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
