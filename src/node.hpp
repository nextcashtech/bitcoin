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

        bool hasInventory(); // Block inventories have been received
        bool shouldRequestInventory(); // Returns true if node has no block hashes and hasn't requested any recently
        void clearInventory(); // Clear block inventory information
        bool requestInventory(); // Request an inventory of blocks
        bool hasBlock(const Hash &pHash); // Block inventory received for specified hash

        bool requestHeaders(const Hash &pStartingHash);
        bool waitingForHeaders() { return !mHeaderRequested.isEmpty() && getTime() - mLastHeaderRequest < 300; }

        bool requestBlocks(unsigned int pCount, bool pReduceOnly);
        bool waitingForBlock() { return mBlocksRequested.size() != 0 && getTime() - mLastBlockRequest < 300; }

        uint64_t lastReceiveTime() { return mLastReceiveTime; }

        const IPAddress &address() { return mAddress; }

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
        uint64_t mLastReceiveTime;
        uint64_t mLastPingTime;
        uint64_t mPingNonce;
        uint64_t mMinimumFeeRate;

        // List of pending block headers this node is known to have
        ArcMist::Mutex mBlockHashMutex;
        void addBlockHash(Hash &pHash);
        void removeBlockHash(Hash &pHash);
        std::list<Hash *> mBlockHashes[0x10000];
        unsigned int mBlockHashCount, mInventoryHeight;
        uint64_t mLastBlockHashRequest;

        Hash mHeaderRequested;
        uint64_t mLastHeaderRequest;

        ArcMist::Mutex mBlockRequestMutex;
        HashList mBlocksRequested;
        uint64_t mLastBlockRequest;

        static unsigned int mNextID;

    };
}

#endif
