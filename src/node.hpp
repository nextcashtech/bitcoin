#ifndef BITCOIN_NODE_HPP
#define BITCOIN_NODE_HPP

#include "arcmist/base/mutex.hpp"
#include "arcmist/io/buffer.hpp"
#include "arcmist/io/network.hpp"
#include "base.hpp"
#include "message.hpp"
#include "chain.hpp"

#include <cstdint>
#include <list>


namespace BitCoin
{
    class BlockHashInfo
    {
    public:
        BlockHashInfo(const Hash &pHash, unsigned int pHeight)
        {
            hash = pHash;
            height = pHeight;
        }

        Hash hash;
        unsigned int height;

    private:
        BlockHashInfo(BlockInfo &pCopy);
        BlockHashInfo &operator = (BlockInfo &pRight);
    };

    class Node
    {
    public:

        Node(const char *pIP, const char *pPort, Chain &pChain);
        Node(unsigned int pFamily, const uint8_t *pIP, uint16_t pPort, Chain &pChain);
        Node(IPAddress &pAddress, Chain &pChain);
        Node(ArcMist::Network::Connection *pConnection, Chain &pChain);
        ~Node();

        unsigned int id() { return mID; }
        bool isOpen() { return mConnection != NULL && mConnection->isOpen(); }
        void close() { if(mConnection != NULL) mConnection->close(); }

        void process(Chain &pChain);
        void clear();

        // Time that the node connected
        uint32_t connectedTime() { return mConnectedTime; }
        // Last time a message was received from this peer
        uint32_t lastReceiveTime() { return mLastReceiveTime; }

        // True if the node is not responding to block hash/header/full requests
        bool notResponding() const;

        bool hasInventory(); // Block inventories have been received
        uint32_t lastInventoryRequest() const { return mLastInventoryRequest; }
        void clearInventory(); // Clear block inventory information
        bool requestInventory(Chain &pChain); // Request an inventory of block hashes
        bool hasBlock(const Hash &pHash); // Block inventory received for specified hash

        bool requestHeaders(Chain &pChain, const Hash &pStartingHash);
        bool waitingForHeaders() { return !mHeaderRequested.isEmpty() && getTime() - mLastHeaderRequest < 300; }

        bool requestBlocks(Chain &pChain, unsigned int pCount, bool pReduceOnly);
        bool waitingForBlocks() { return mBlocksRequested.size() > 0; }

        uint32_t lastBlockRequestTime() { return mLastBlockRequest; }
        uint32_t lastBlockReceiveTime() { return mLastBlockReceiveTime; }
        unsigned int blocksRequestedCount() const { return mBlocksRequestedCount; }
        unsigned int blocksReceivedCount() const { return mBlocksReceivedCount; }

        const IPAddress &address() { return mAddress; }

        // Add statistics to collection and clear them
        void collectStatistics(Statistics &pCollection);

    private:

        bool versionSupported(int32_t pVersion);

        bool sendMessage(Message::Data *pData);
        bool sendVersion(Chain &pChain);
        bool sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason);
        bool sendBlock(Block &pBlock);

        unsigned int mID;
        IPAddress mAddress;
        ArcMist::Network::Connection *mConnection;
        ArcMist::Buffer mReceiveBuffer;
        Statistics mStatistics;

        Message::VersionData *mVersionData;
        bool mVersionSent, mVersionAcknowledged, mVersionAcknowledgeSent, mSendHeaders;
        uint32_t mLastReceiveTime;
        uint32_t mLastPingTime;
        uint64_t mPingNonce;
        uint64_t mMinimumFeeRate;

        // List of pending block headers this node is known to have
        ArcMist::Mutex mBlockHashMutex;
        void addBlockHash(Chain &pChain, Hash &pHash);
        void removeBlockHash(Hash &pHash);
        void refreshInventoryHeight(Chain &pChain);
        std::list<BlockHashInfo *> mBlockHashes[0x10000];
        unsigned int mBlockHashCount, mInventoryHeight;
        Hash mHighestInventoryHash;
        uint32_t mLastInventoryRequest;

        Hash mHeaderRequested;
        uint32_t mLastHeaderRequest;

        ArcMist::Mutex mBlockRequestMutex;
        HashList mBlocksRequested;
        uint32_t mLastBlockRequest;
        uint32_t mLastBlockReceiveTime;
        unsigned int mBlocksRequestedCount;
        unsigned int mBlocksReceivedCount;

        bool mConnected;
        uint32_t mConnectedTime;
        unsigned int mMessagesReceived;

        static unsigned int mNextID;

    };
}

#endif
