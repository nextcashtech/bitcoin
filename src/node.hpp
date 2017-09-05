#ifndef BITCOIN_NODE_HPP
#define BITCOIN_NODE_HPP

#include "arcmist/base/mutex.hpp"
#include "arcmist/io/buffer.hpp"
#include "arcmist/io/network.hpp"
#include "base.hpp"
#include "message.hpp"

#include <cstdint>


namespace BitCoin
{
    class Node
    {
    public:

        Node(const char *pIP, const char *pPort);
        Node(unsigned int pFamily, const uint8_t *pIP, uint16_t pPort);
        Node(IPAddress &pAddress);
        ~Node();

        unsigned int id() { return mID; }
        bool isOpen() { return mConnection.isOpen(); }

        void process();
        void clear();

        bool hasBlocks(); // Block inventories have been received
        bool shouldRequestBlocks(); // Returns true if node has no block hashes and hasn't requested any recently
        bool hasBlock(const Hash &pHash); // Block inventory received for specified hash
        void clearBlockHashes(); // Clear block inventory information
        bool requestBlockHashes(); // Request an inventory of blocks

        bool requestHeaders(const Hash &pStartingHash);
        bool waitingForHeaders() { return !mHeaderRequested.isEmpty() && getTime() - mLastHeaderRequest < 300; }

        bool requestBlock(const Hash &pHash);
        bool waitingForBlock() { return !mBlockRequested.isEmpty() && getTime() - mLastBlockRequest < 300; }

        uint64_t lastReceiveTime() { return mLastReceiveTime; }

    private:

        bool versionSupported(int32_t pVersion);

        bool sendMessage(Message::Data *pData);
        bool sendVersion();
        bool sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason);

        unsigned int mID;
        IPAddress mAddress;
        ArcMist::Connection mConnection;
        ArcMist::Buffer mReceiveBuffer;

        Message::VersionData *mVersionData;
        bool mVersionSent, mVersionAcknowledged, mVersionAcknowledgeSent, mSendHeaders;
        uint64_t mLastReceiveTime;
        uint64_t mLastPingTime;
        uint64_t mPingNonce;
        uint64_t mMinimumFeeRate;

        // List of pending block headers this node is known to have
        ArcMist::Mutex mBlockHashMutex;
        void addBlockHeaderHash(Hash &pHash);
        std::list<Hash> mBlockHashes[0xffff];
        unsigned int mBlockHashCount;
        uint64_t mLastBlockHashRequest;

        Hash mHeaderRequested;
        uint64_t mLastHeaderRequest;
        Hash mBlockRequested;
        uint64_t mLastBlockRequest;

        static unsigned int mNextID;

    };
}

#endif
