#ifndef BITCOIN_NODE_HPP
#define BITCOIN_NODE_HPP

#include "arcmist/base/mutex.hpp"
#include "arcmist/io/buffer.hpp"
#include "arcmist/io/network.hpp"
#include "base.hpp"
#include "message.hpp"

#include <cstdint>
#include <list>


namespace BitCoin
{
    class Node
    {
    public:

        Node(const char *pIP, const char *pPort);
        Node(unsigned int pFamily, const uint8_t *pIP, uint16_t pPort);
        Node(IPAddress &pAddress);
        Node(ArcMist::Network::Connection *pConnection);
        ~Node();

        unsigned int id() { return mID; }
        bool isOpen() { return mConnection != NULL && mConnection->isOpen(); }

        void process();
        void clear();

        // Last time a message was received from this peer
        uint32_t lastReceiveTime() { return mLastReceiveTime; }

        // True if the node is not responding to block hash/header/full requests
        bool notResponding() const;

        bool hasInventory(); // Block inventories have been received
        bool shouldRequestInventory(); // Returns true if node has no block hashes and hasn't requested any recently
        void clearInventory(); // Clear block inventory information
        bool requestInventory(); // Request an inventory of blocks
        bool hasBlock(const Hash &pHash); // Block inventory received for specified hash

        bool requestHeaders(const Hash &pStartingHash);
        bool waitingForHeaders() { return !mHeaderRequested.isEmpty() && getTime() - mLastHeaderRequest < 300; }

        bool requestBlocks(unsigned int pCount, bool pReduceOnly);
        bool waitingForBlocks() { return mBlocksRequested.size() != 0; }

        uint32_t lastBlockRequestTime() { return mLastBlockRequest; }
        uint32_t lastBlockReceiveTime() { return mLastBlockReceiveTime; }
        unsigned int blocksRequestedCount() const { return mBlocksRequestedCount; }
        unsigned int blocksReceivedCount() const { return mBlocksReceivedCount; }

        const IPAddress &address() { return mAddress; }

        // Network tracking
        uint64_t bytesReceived() const { if(mConnection == NULL) return 0; return mConnection->bytesReceived(); }
        uint64_t bytesSent() const { if(mConnection == NULL) return 0; return mConnection->bytesSent(); }
        void resetNetworkByteCounts() { if(mConnection != NULL) mConnection->resetByteCounts(); }

    private:

        bool versionSupported(int32_t pVersion);

        bool sendMessage(Message::Data *pData);
        bool sendVersion();
        bool sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason);
        bool sendBlock(Block &pBlock);

        unsigned int mID;
        IPAddress mAddress;
        ArcMist::Network::Connection *mConnection;
        ArcMist::Buffer mReceiveBuffer;

        Message::VersionData *mVersionData;
        bool mVersionSent, mVersionAcknowledged, mVersionAcknowledgeSent, mSendHeaders;
        uint32_t mLastReceiveTime;
        uint32_t mLastPingTime;
        uint64_t mPingNonce;
        uint64_t mMinimumFeeRate;

        // List of pending block headers this node is known to have
        ArcMist::Mutex mBlockHashMutex;
        void addBlockHash(Hash &pHash);
        void removeBlockHash(Hash &pHash);
        std::list<Hash *> mBlockHashes[0x10000];
        unsigned int mBlockHashCount, mInventoryHeight;
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

        static unsigned int mNextID;

    };
}

#endif
