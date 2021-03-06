/**************************************************************************
 * Copyright 2017 NextCash, LLC                                           *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_NODE_HPP
#define BITCOIN_NODE_HPP

#include "mutex.hpp"
#include "thread.hpp"
#include "log.hpp"
#include "hash.hpp"
#include "buffer.hpp"
#include "network.hpp"
#include "base.hpp"
#include "message.hpp"
#include "chain.hpp"
#include "bloom_filter.hpp"
#include "monitor.hpp"

#include <cstdint>
#include <list>

#define BITCOIN_NODE_LOG_NAME "Node"


namespace BitCoin
{
    class Daemon;

    class Node
    {
    public:

        enum ConnectionType
        {
            NONE         = 0x00, // Plain outgoing connection.
            SEED         = 0x01, // Seed node (only for retrieving peers).
            INCOMING     = 0x02, // Connection initiated by peer.
            GOOD         = 0x04, // Peer already has good rating.
            SCAN         = 0x08, // Connection for validating a peer exists.
        };

        static const uint32_t NOT_OUTGOING = SEED | INCOMING | SCAN;

        Node(NextCash::Network::Connection *pConnection, uint32_t pConnectionType,
          uint64_t pServices, Daemon *pDaemon, bool *pStopFlag, bool pAnnounceCompact);

        Node(NextCash::Network::IPAddress &pIPAddress, uint32_t pConnectionType,
             uint64_t pServices, Daemon *pDaemon, bool pAnnounceCompact);
        ~Node();

        static void run(void *pParameter);
        void runInThread();

        unsigned int id() { return mID; }
        bool isOpen();
        void close();

        void process();

        void requestStop();

        const char *name() { return mName.text(); }

        // Connection initiated by peer.
        bool isIncoming() const { return mConnectionType & INCOMING; }

        // Connection only for requesting peers.
        bool isSeed() const { return mConnectionType & SEED; }

        // Connection made with good rated peer.
        bool isGood() const { return mConnectionType & GOOD; }

        // Connection only for validating peer.
        bool isScan() const { return mConnectionType & SCAN; }

        // Connection for requesting network data.
        bool isOutgoing() const { return !(mConnectionType & NOT_OUTGOING); }

        bool isInitialized() const { return mIsInitialized; }
        bool isStopped() const { return mStopped; }
        // Versions exchanged and initial ping completed
        bool isReady() const { return mPingRoundTripTime != 0xffffffffffffffff; }
        Milliseconds pingTimeMilliseconds() const { return mPingRoundTripTime; }
        void setPingCutoff(uint32_t pPingCutoff) { mPingCutoff = pPingCutoff; }

        // Time that the node connected
        Time connectedTime() { return mConnectedTime; }
        // Last time a message was received from this peer
        Time lastReceiveTime() { return mLastReceiveTime; }

        unsigned int blockHeight()
        {
            if(mReceivedVersionData == NULL)
                return 0;
            else
                return (unsigned int)mReceivedVersionData->startBlockHeight;
        }

        // Header requests
        bool requestHeaders();
        bool waitingForHeaderRequests();
        const NextCash::Hash &lastHeaderHash() const { return mLastHeaderHash; }

        // Block requests
        bool requestBlocks(NextCash::HashList &pList, bool pForceFull = false);
        bool waitingForBlockRequests();
        unsigned int blocksRequestedCount() { return (unsigned int)mBlocksRequested.size(); }
        unsigned int blocksDownloadedCount() const { return mBlockDownloadCount; }
        unsigned int blocksDownloadedSize() const { return mBlockDownloadSize; }
        unsigned int blocksDownloadedTime() const { return mBlockDownloadTime; }
        double blockDownloadBytesPerSecond() const;

        bool requestTransactions(NextCash::HashList &pList, bool pReMark);

        bool requestPeers();

        // Send notification of a new block on the chain
        void announceBlock(BlockReference &pBlock);

        // Send notification of a new transaction in the mempool
        void addTransactionAnnouncements(TransactionList &pTransactions);
        bool finalizeAnnouncments();

        // Used to send transactions created by this wallet
        bool sendTransaction(TransactionReference &pTransaction);

        bool compactBlocksEnabled() const { return mSendCompactBlocksVersion != 0L; }
        bool announceBlocksCompact() const { return mAnnounceBlocksCompact; }

        bool isNewlyReady()
        {
            if(!mWasReady && isReady())
            {
                mWasReady = true;
                return true;
            }

            return false;
        }

        const NextCash::Network::IPAddress &ip() { return mAddress; }
        bool wasRejected() const { return mRejected; }

        // Add statistics to collection and clear them
        void collectStatistics(Statistics &pCollection);

    private:

        bool initialize();

        Message::Interpreter mMessageInterpreter;

        // Check if node should be closed
        //   Returns false if closed.
        bool check();

        bool failedStartBytes();

        bool processMessage();

        // Send all initial messages to prepare the node for communication
        void prepare();

        // Release anything (i.e requests) associated with this node
        void release();

        enum FillResult
        {
            FILL_COMPLETE,   // Block is now complete.
            FILL_INCOMPLETE, // Request sent for missing data.
            FILL_FAILED,     // Failed. New request required.
            FILL_ABANDONED   // Fill abandoned because another node has taken over.
        };

        // Attempt to fill block from compact block.
        FillResult fillCompactBlock(Message::CompactBlockData *pCompactBlock,
          bool pRequestTransactions);

        // Adds transactions to the compact block.
        // Returns true if any transactions were added.
        bool addTransactionsToCompactBlock(Message::CompactBlockData *pCompactBlock,
          Message::CompactTransData *pTransData);

        unsigned int mActiveMerkleRequests;
        bool requestMerkleBlock(NextCash::Hash &pHash);

        bool sendMessage(Message::Data *pData);
        bool sendVersion();
        bool sendPing();
        bool sendFeeFilter();
        bool sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason);
        bool sendRejectWithHash(const char *pCommand, Message::RejectData::Code pCode, const char *pReason,
          const NextCash::Hash &pHash);
        bool sendBlock(BlockReference &pBlock);
        bool sendBloomFilter();
        bool sendMerkleBlock(BlockReference &pBlock);

        unsigned int mID;
        NextCash::String mName;
#ifndef SINGLE_THREAD
        NextCash::Thread *mThread;
#endif
        NextCash::Network::IPAddress mAddress;
        Daemon *mDaemon;
        Chain *mChain;
        Monitor *mMonitor;
        NextCash::Mutex mConnectionMutex;
        NextCash::Network::Connection *mConnection;
        NextCash::Buffer mReceiveBuffer;
        NextCash::Mutex mStatisticsLock;
        Statistics mStatistics;
        bool mStarted, mIsInitialized, mStopRequested, mStopped;
        uint32_t mConnectionType;
        ChainID mChainID;
        bool mIsGood;
        bool mAnnounceBlocksCompact, mRequestAnnounceCompact;
        uint64_t mSendCompactBlocksVersion;
        bool mSendCompactSent;
        bool mRejected;
        bool mWasReady;
        bool mReleased;
        bool mMemPoolRequested;
        Time mMemPoolRequestedTime;
        bool mMemPoolReceived;
        bool mProcessingCompactTransactions;
        bool *mStopFlag;
        std::vector<Message::Data *> mMessagesToSend;
        NextCash::Mutex mMessagesToSendLock;

        Message::VersionData *mSentVersionData, *mReceivedVersionData;
        bool mVersionSent, mVersionAcknowledged, mVersionAcknowledgeSent, mSendHeaders, mPrepared,
          mPeersRequested;
        Time mLastReceiveTime;
        Time mLastCheckTime;
        Milliseconds mLastPingTime;
        Milliseconds mPingRoundTripTime;
        uint32_t mPingCutoff;
        Time mLastBlackListCheck;
        Time mLastMerkleCheck, mLastMerkleRequest, mLastMerkleReceive;
        Message::InventoryData *mInventoryData;
        std::vector<Message::CompactBlockData *> mIncomingCompactBlocks, mOutgoingCompactBlocks;

        BloomFilter mFilter; // Bloom filter received from peer
        uint64_t mMinimumFeeRate;
        uint64_t mLastPingNonce;
        unsigned int mBloomFilterID; // ID of bloom filter last sent to peer

        unsigned int mBlockDownloadCount;
        unsigned int mBlockDownloadSize;
        unsigned int mBlockDownloadTime;

        NextCash::Hash mHeaderRequested, mLastBlockAnnounced, mLastHeaderRequested,
          mLastHeaderHash;
        Time mHeaderRequestTime;

        NextCash::Mutex mBlockRequestMutex;
        NextCash::HashList mBlocksRequested;
        NextCash::HashSet mTransactionsRequested;
        Time mBlockRequestTime, mLastBlockReceiveTime;

        bool updateBlockRequest(const NextCash::Hash &pHash, Message::Data *pMessage,
          bool pComplete);

        NextCash::Mutex mAnnounceMutex;
        NextCash::HashList mAnnounceBlocks; // Blocks announced by peer.
        NextCash::HashList mSentTransactions; // Transactions sent to peer.
        NextCash::HashSet mAnnounceTransactions; // Transactions annoucned by peer.

        void addAnnouncedBlock(const NextCash::Hash &pHash);
        bool addAnnouncedTransaction(const NextCash::Hash &pHash);

        NextCash::Mutex mAnnounceBlockMutex;
        std::vector<BlockReference> mBlocksToAnnounce;

        // Process new blocks and send block announcements.
        void processBlocksToAnnounce();

        Time mLastExpireTime;
        void expire();

        // Transaction hashes that were already requested, but not received, when announced.
        // This ensures if one node fails to send a requested transaction, that another can still
        //   request it.
        NextCash::HashList mSavedTransactions;
        Time mLastSavedCheckTime;
        bool checkSaved();

        bool mConnected;
        Time mConnectedTime;
        unsigned int mMessagesReceived;
        unsigned int mOldTransactionCount;
        unsigned int mPingCount;

        uint64_t mServices;

        static unsigned int mNextID;

        Node(const Node &pCopy);
        const Node &operator = (const Node &pRight);

    };
}

#endif
