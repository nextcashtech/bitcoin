/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_NODE_HPP
#define BITCOIN_NODE_HPP

#include "arcmist/base/mutex.hpp"
#include "arcmist/base/thread.hpp"
#include "arcmist/base/hash.hpp"
#include "arcmist/io/buffer.hpp"
#include "arcmist/io/network.hpp"
#include "base.hpp"
#include "message.hpp"
#include "chain.hpp"
#include "bloom_filter.hpp"
#include "monitor.hpp"

#include <cstdint>
#include <list>


namespace BitCoin
{
    class Node
    {
    public:

        Node(ArcMist::Network::Connection *pConnection, Chain *pChain, bool pIncoming,
          bool pIsSeed, uint64_t pServices, Monitor &pMonitor);
        ~Node();

        static void run();

        unsigned int id() { return mID; }
        bool isOpen();
        void close();

        void process();

        void requestStop();

        const char *name() { return mName.text(); }
        bool isIncoming() const { return mIsIncoming; }
        bool isSeed() const { return mIsSeed; }
        // Versions exchanged and initial ping completed
        bool isReady() const { return mPingRoundTripTime != -1; }
        uint32_t pingTime() const { return mPingRoundTripTime; }
        void setPingCutoff(uint32_t pPingCutoff) { mPingCutoff = pPingCutoff; }
        unsigned int blocksDownloadedCount() const { return mBlockDownloadCount; }
        unsigned int blocksDownloadedSize() const { return mBlockDownloadSize; }
        unsigned int blocksDownloadedTime() const { return mBlockDownloadTime; }
        double blockDownloadBytesPerSecond() const;

        // Time that the node connected
        uint32_t connectedTime() { return mConnectedTime; }
        // Last time a message was received from this peer
        uint32_t lastReceiveTime() { return mLastReceiveTime; }

        unsigned int blockHeight() { if(mVersionData == NULL) return 0; else return mVersionData->startBlockHeight; }

        bool waitingForRequests() { return mBlocksRequested.size() > 0 || !mHeaderRequested.isEmpty(); }
        bool requestHeaders();
        bool requestBlocks(ArcMist::HashList &pList);
        bool requestTransactions(ArcMist::HashList &pList);
        unsigned int blocksRequestedCount() { return mBlocksRequested.size(); }
        void releaseBlockRequests();

        const ArcMist::Hash &lastHeader() const { return mLastHeader; }

        void setMonitor(Monitor &pMonitor);

        bool hasTransaction(const ArcMist::Hash &pHash);

        bool requestPeers();

        // Send notification of a new block on the chain
        bool announceBlock(Block *pBlock);

        // Send notification of a new transaction in the mempool
        //TODO Make this send periodically with a list. Filter list to remove transaction inventory received from node
        bool announceTransaction(Transaction *pTransaction);

        const IPAddress &address() { return mAddress; }
        const uint8_t *ipv6Bytes() const { return mConnection->ipv6Bytes(); }
        bool wasRejected() const { return mRejected; }

        // Add statistics to collection and clear them
        void collectStatistics(Statistics &pCollection);

    private:

        int mSocketID;

        Message::Interpreter mMessageInterpreter;

        // Check if node should be closed
        void check();

        unsigned int mActiveMerkleRequests;
        bool requestMerkleBlock(ArcMist::Hash &pHash);

        bool sendMessage(Message::Data *pData);
        bool sendVersion();
        bool sendPing();
        bool sendFeeFilter();
        bool sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason);
        bool sendRejectWithHash(const char *pCommand, Message::RejectData::Code pCode, const char *pReason,
          const ArcMist::Hash &pHash);
        bool sendBlock(Block &pBlock);
        bool sendBloomFilter();
        bool sendMerkleBlock(const ArcMist::Hash &pBlockHash);

        unsigned int mID;
        ArcMist::String mName;
        ArcMist::Thread *mThread;
        IPAddress mAddress;
        Chain *mChain;
        Monitor *mMonitor;
        ArcMist::Mutex mConnectionMutex;
        ArcMist::Network::Connection *mConnection;
        ArcMist::Buffer mReceiveBuffer;
        Statistics mStatistics;
        bool mStop, mStopped;
        bool mIsIncoming, mIsSeed;
        bool mSendBlocksCompact;
        bool mRejected;

        Message::VersionData *mVersionData;
        bool mVersionSent, mVersionAcknowledged, mVersionAcknowledgeSent, mSendHeaders;
        int32_t mLastReceiveTime;
        int32_t mLastCheckTime;
        int32_t mLastPingTime;
        int32_t mPingRoundTripTime;
        int32_t mPingCutoff;
        int32_t mLastBlackListCheck;
        int32_t mLastMerkleCheck;
        int32_t mLastMerkleRequest;

        BloomFilter mFilter; // Bloom filter received from peer
        uint64_t mMinimumFeeRate;
        uint64_t mLastPingNonce;
        unsigned int mBloomFilterID; // ID of bloom filter last sent to peer

        unsigned int mBlockDownloadCount;
        unsigned int mBlockDownloadSize;
        unsigned int mBlockDownloadTime;

        ArcMist::Hash mHeaderRequested, mLastBlockAnnounced, mLastHeaderRequested, mLastHeader;
        uint32_t mHeaderRequestTime;

        ArcMist::Mutex mBlockRequestMutex;
        ArcMist::HashList mBlocksRequested;
        int32_t mBlockRequestTime, mBlockReceiveTime;

        ArcMist::Mutex mAnnounceMutex;
        ArcMist::HashList mAnnounceBlocks, mAnnounceTransactions;

        void addAnnouncedBlock(const ArcMist::Hash &pHash);
        bool addAnnouncedTransaction(const ArcMist::Hash &pHash);

        bool mConnected;
        int32_t mConnectedTime;
        unsigned int mMessagesReceived;
        unsigned int mPingCount;

        uint64_t mServices;

        static unsigned int mNextID;

        Node(const Node &pCopy);
        const Node &operator = (const Node &pRight);

    };
}

#endif
