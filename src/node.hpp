/**************************************************************************
 * Copyright 2017 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_NODE_HPP
#define BITCOIN_NODE_HPP

#include "nextcash/base/mutex.hpp"
#include "nextcash/base/thread.hpp"
#include "nextcash/base/hash.hpp"
#include "nextcash/io/buffer.hpp"
#include "nextcash/io/network.hpp"
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

        Node(NextCash::Network::Connection *pConnection, Chain *pChain, bool pIncoming,
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
        bool requestBlocks(NextCash::HashList &pList);
        bool requestTransactions(NextCash::HashList &pList);
        unsigned int blocksRequestedCount() { return mBlocksRequested.size(); }
        void releaseBlockRequests();

        const NextCash::Hash &lastHeader() const { return mLastHeader; }

        void setMonitor(Monitor &pMonitor);

        bool hasTransaction(const NextCash::Hash &pHash);

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
        bool requestMerkleBlock(NextCash::Hash &pHash);

        bool sendMessage(Message::Data *pData);
        bool sendVersion();
        bool sendPing();
        bool sendFeeFilter();
        bool sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason);
        bool sendRejectWithHash(const char *pCommand, Message::RejectData::Code pCode, const char *pReason,
          const NextCash::Hash &pHash);
        bool sendBlock(Block &pBlock);
        bool sendBloomFilter();
        bool sendMerkleBlock(const NextCash::Hash &pBlockHash);

        unsigned int mID;
        NextCash::String mName;
        NextCash::Thread *mThread;
        IPAddress mAddress;
        Chain *mChain;
        Monitor *mMonitor;
        NextCash::Mutex mConnectionMutex;
        NextCash::Network::Connection *mConnection;
        NextCash::Buffer mReceiveBuffer;
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

        NextCash::Hash mHeaderRequested, mLastBlockAnnounced, mLastHeaderRequested, mLastHeader;
        uint32_t mHeaderRequestTime;

        NextCash::Mutex mBlockRequestMutex;
        NextCash::HashList mBlocksRequested;
        int32_t mBlockRequestTime, mBlockReceiveTime;

        NextCash::Mutex mAnnounceMutex;
        NextCash::HashList mAnnounceBlocks, mAnnounceTransactions;

        void addAnnouncedBlock(const NextCash::Hash &pHash);
        bool addAnnouncedTransaction(const NextCash::Hash &pHash);

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
