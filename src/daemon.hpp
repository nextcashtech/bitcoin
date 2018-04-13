/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                       *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
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

#include <cstdint>
#include <vector>


namespace BitCoin
{
    class IPAddress;

    class Daemon
    {
    public:

        Daemon();
        ~Daemon();

        // Threads
        static void runConnections();
        static void runRequests();
        static void runManage();
        static void runProcesses();

        void run(bool pInDaemonMode = true);
        void manage();
        void process();
        void handleConnections();
        void handleRequests();

        bool load();
        bool start(bool pInDaemonMode);

        bool isLoaded() { return mLoaded; }
        bool isRunning() { return mRunning; }
        bool isStopping() { return mStopping; }

        static const int FINISH_ON_REQUEST = 0x00;
        static const int FINISH_ON_SYNC    = 0x01;

        // Set criteria for daemon stopping on its own
        void setFinishMode(int pMode) { mFinishMode = pMode; }
        void requestStop() { mStopRequested = true; mChain.requestStop(); }

        // Signals
        static void handleSigTermChild(int pValue);
        static void handleSigTerm(int pValue);
        static void handleSigInt(int pValue);
        static void handleSigPipe(int pValue);

        unsigned int peerCount();
        Chain *chain() { return &mChain; }
        Monitor *monitor() { return &mMonitor; }
        KeyStore *keyStore() { return &mKeyStore; }

        bool loadMonitor();
        bool saveMonitor();

        bool loadKeyStore();
        bool saveKeyStore();

        enum Status { INACTIVE, LOADING, FINDING_PEERS, CONNECTING_TO_PEERS, SYNCHRONIZING,
          SYNCHRONIZED, FINDING_TRANSACTIONS };
        Status status();

    protected:

        static const int MAX_BLOCK_REQUEST = 8;

        Chain mChain;
        Info &mInfo;

        void stop();
        bool mRunning, mStopping, mStopRequested, mLoading, mLoaded, mQueryingSeed;
        int mFinishMode;

#ifndef SINGLE_THREAD
        // Threads
        NextCash::Thread *mConnectionThread;
        NextCash::Thread *mRequestsThread;
        NextCash::Thread *mManagerThread;
        NextCash::Thread *mProcessThread;
#endif

        // Timers
        int32_t mLastHeaderRequestTime;
        int32_t mLastConnectionActive;
        int32_t mLastOutputsPurgeTime;
        int32_t mLastAddressPurgeTime;
        int32_t mLastMemPoolCheckPending;
        int32_t mLastMonitorProcess;
        int32_t mLastFillNodesTime;
        int32_t mLastCleanTime;

        NextCash::Hash mLastBlockHash;
        NextCash::Network::Listener *mNodeListener;
        NextCash::Network::Listener *mRequestsListener = NULL;

        // Signals
        void (*previousSigTermChildHandler)(int);
        void (*previousSigTermHandler)(int);
        void (*previousSigIntHandler)(int);
        void (*previousSigPipeHandler)(int);

        // Query peers from a seed
        // Returns number of peers actually connected
        unsigned int querySeed(const char *pName);

        // Nodes
        NextCash::ReadersLock mNodeLock;
        std::vector<Node *> mNodes;
        unsigned int mNodeCount, mIncomingNodes, mOutgoingNodes;
        unsigned int mMaxIncoming;

        unsigned int outgoingConnectionCountTarget() const { return 8; }

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

        std::vector<IPBytes> mRejectedIPs;

        void addRejectedIP(const uint8_t *pIP);

        bool addNode(NextCash::Network::Connection *pConnection, bool pIncoming, bool pIsSeed, uint64_t pServices);
        unsigned int recruitPeers(unsigned int pCount);
        void cleanNodes();

        void checkSync();
        void sendRequests();
        void sendHeaderRequest();
        void sendPeerRequest();
        void sendTransactionRequests();
        unsigned int mLastPeerCount;
        void improvePing();
        void improveSpeed();

        // Announce verified blocks and transactions
        void announce();

        KeyStore mKeyStore;
        Monitor mMonitor;

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
