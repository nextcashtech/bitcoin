/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_DAEMON_HPP
#define BITCOIN_DAEMON_HPP

#include "stream.hpp"
#include "thread.hpp"
#include "mutex.hpp"
#include "hash.hpp"
#include "base.hpp"
#include "info.hpp"
#include "node.hpp"
#include "requests.hpp"
#include "key.hpp"
#include "monitor.hpp"
#include "seeds.hpp"

#include <cstdint>
#include <vector>
#include <list>


namespace BitCoin
{
    class IPAddress;

    class Daemon
    {
    public:

        Daemon();

        ~Daemon();

        class IPBytes
        {
        public:

            IPBytes() { std::memset(bytes, 0, INET6_ADDRLEN); }
            IPBytes(const IPBytes &pCopy) { std::memcpy(bytes, pCopy.bytes, INET6_ADDRLEN); }
            IPBytes(const uint8_t *pIP) { std::memcpy(bytes, pIP, INET6_ADDRLEN); }
            bool operator == (const IPBytes &pRight) const { return std::memcmp(bytes, pRight.bytes, INET6_ADDRLEN) == 0; }
            bool operator == (const uint8_t *pIP) const { return std::memcmp(bytes, pIP, INET6_ADDRLEN) == 0; }
            const IPBytes &operator = (const IPBytes &pRight) { std::memcpy(bytes, pRight.bytes, INET6_ADDRLEN); return *this; }
            const IPBytes &operator = (const uint8_t *pIP) { std::memcpy(bytes, pIP, INET6_ADDRLEN); return *this; }

            uint8_t bytes[INET6_ADDRLEN];
        };

        // Threads
        static void runConnections(void *pParameter);

        static void runRequests(void *pParameter);

        static void runManage(void *pParameter);

        static void runProcess(void *pParameter);

        static void runScan(void *pParameter);

        void run(bool pInDaemonMode = true);

        void manage();

        void process();

        void handleConnections();

        void handleRequests();

        void scan(std::list<IPBytes> &pRecentIPs);

        bool loadWallets();

        bool loadChain();

        bool start(bool pInDaemonMode);

        bool walletsAreLoaded() { return mWalletsLoaded; }

        bool chainIsLoaded() { return mChainLoaded; }

        bool isRunning() { return mRunning; }

        bool isStopping() { return mStopping || mStopRequested; }

        static const int FINISH_ON_REQUEST = 0x00;
        static const int FINISH_ON_SYNC = 0x01;

        // Set criteria for daemon stopping on its own
        int finishMode() { return mFinishMode; }

        void setFinishMode(int pMode);

        void setFinishTime(Time pTime); // Set time to stop daemon (zero clears)
        void requestStop()
        {
            mStopRequested = true;
            mChain.requestStop();
        }

        // Signals
        static void handleSigTermChild(int pValue);

        static void handleSigTerm(int pValue);

        static void handleSigInt(int pValue);

        static void handleSigPipe(int pValue);

        unsigned int peerCount();

        Chain *chain() { return &mChain; }

        Monitor *monitor() { return &mMonitor; }

        KeyStore *keyStore() { return &mKeyStore; }

        // Send a P2PKH or P2SH payment to the specified public key hash.
        //
        // pAmount is in satoshis.
        // pFeeRate is satoshis/byte.
        // pSendAll sends entire key balance when true.
        //
        // Result:
        //   1 : Undefined failure
        //   2 : Insuffecient Funds
        //   3 : Invalid Public Key Hash
        //   4 : No change address
        //   5 : Signing Issue
        //   6 : Amount below dust
        int sendStandardPayment(unsigned int pKeyOffset, AddressType pHashType,
          NextCash::Hash pHash, uint64_t pAmount, double pFeeRate, bool pUsePending, bool pSendAll,
          bool pTransmit, TransactionReference &pTransaction);

        int sendSpecifiedOutputsPayment(unsigned int pKeyOffset, std::vector<Output> pOutputs,
          double pFeeRate, bool pUsePending, bool pTransmit, TransactionReference &pTransaction);

        bool loadMonitor();
        bool saveMonitor();

        void registerConnection(uint32_t pConnectionType)
        {
            mLastConnectionActive = getTime();
            if(pConnectionType & Node::INCOMING)
                ++mStatistics.incomingConnections;
            else if(!(pConnectionType & Node::SEED))
            {
                ++mConnectionsSinceLastRecruit;
                ++mStatistics.outgoingConnections;
            }
        }

        bool loadKeyStore(const uint8_t *pPassword = (const uint8_t *)"NextCash",
                          unsigned int pPasswordLength = 8);
        bool saveKeyStore(const uint8_t *pPassword = (const uint8_t *)"NextCash",
                          unsigned int pPasswordLength = 8);
        void resetKeysSynchronized();

        // Drop all nodes
        void resetNodes();

        enum Status { INACTIVE, LOADING_WALLETS, LOADING_CHAIN, FINDING_PEERS, CONNECTING_TO_PEERS,
          SYNCHRONIZING, SYNCHRONIZED, FINDING_TRANSACTIONS };
        Status status();

        static const int GOOD_RATING = 20;
        static const int FALLBACK_GOOD_RATING = 5;
        static const int OKAY_RATING = 1;
        static const int USABLE_RATING = -4;

    protected:

        static const int MAX_BLOCK_REQUEST = 16;

        Chain mChain;
        Info &mInfo;

        void stop();
        bool mRunning, mStopping, mStopRequested, mLoadingWallets, mWalletsLoaded, mLoadingChain,
          mChainLoaded, mQueryingSeed, mConnecting;
        bool mKeysSynchronized;
        int mFinishMode;

#ifndef SINGLE_THREAD
        // Threads
        NextCash::Thread *mConnectionThread;
        NextCash::Thread *mRequestsThread;
        NextCash::Thread *mManagerThread;
        NextCash::Thread *mProcessThread;
        NextCash::Thread *mScanThread;
#endif

        // Timers
        Time mLastHeaderRequestTime;
        Time mLastConnectionActive;
        Time mLastDataSaveTime;
        Time mLastMonitorProcess;
        Time mLastCleanTime, mLastRequestCleanTime;
        Time mFinishTime;
        Time mLastMemPoolProcessTime;

        NextCash::Hash mLastHeaderHash;
        NextCash::Network::Listener *mNodeListener;
        NextCash::Network::Listener *mRequestsListener = NULL;

        // Signals
        void (*previousSigTermChildHandler)(int);
        void (*previousSigTermHandler)(int);
        void (*previousSigIntHandler)(int);
        void (*previousSigPipeHandler)(int);

        // Query peers from a seed
        // Returns true if connection attempted.
        bool querySeeds();
        const Seed *getRandomSeed();

        bool mSeedsRandomized;
        ChainID mRandomSeedsChainID;
        std::vector<const Seed *> mRandomSeeds;
        unsigned int mConnectionsSinceLastRecruit;

        // Nodes
        NextCash::ReadersLock mNodeLock;
        std::vector<Node *> mNodes;
        unsigned int mNodeCount, mIncomingNodes, mOutgoingNodes;
        unsigned int mMaxIncoming;

        unsigned int mGoodNodeMax;
        unsigned int mOutgoingNodeMax;

        unsigned int maxOutgoingNodes()
        {
            if(!mInfo.initialBlockDownloadIsComplete())
                return mOutgoingNodeMax * 2;

            if(mInfo.spvMode)
            {
                unsigned int monitorHeight = mMonitor.height();
                if(monitorHeight > 0 && monitorHeight < mChain.headerHeight() &&
                  mChain.headerHeight() - monitorHeight > 5000)
                    return mOutgoingNodeMax * 2;
            }
            else if(mChain.headerHeight() > 1000 &&
              mChain.blockHeight() < mChain.headerHeight() - 1000)
                return mOutgoingNodeMax * 2;

            return mOutgoingNodeMax;
        }

        std::vector<IPBytes> mRejectedIPs;
        std::list<IPBytes> mRecentIPs;

        void addRejectedIP(const uint8_t *pIP);
        bool isRejectedIP(const uint8_t *pIP);

        bool addNode(NextCash::Network::IPAddress &pIPAddress, uint32_t pType, uint64_t pServices,
          bool pAnnounceCompact);
        bool addNode(NextCash::Network::Connection *pConnection, uint32_t pType,
          uint64_t pServices, bool pAnnounceCompact);
        unsigned int recruitPeers();
        void cleanNodes();

        void checkSync();
        void sendBlockRequests();
        void sendHeaderRequest();
        void sendTransactionRequests();
        void improvePing();
        void improveSpeed();

        // Announce verified blocks and transactions
        void announce();

        KeyStore mKeyStore;
        Monitor mMonitor;

        NextCash::Mutex mTransmitMutex;
        TransactionList mTransactionsToTransmit;
        bool mTransmittedTransToLastNode;

        // Transmit any created transactions
        void transmitTransactions();

        // Request Channels
        NextCash::ReadersLock mRequestsLock;
        std::vector<RequestChannel *> mRequestChannels;
        bool addRequestChannel(NextCash::Network::Connection *pConnection);
        void cleanRequestChannels();

        Statistics mStatistics;
        void collectStatistics();
        void saveStatistics();
        void printStatistics();
    };
}

#endif
