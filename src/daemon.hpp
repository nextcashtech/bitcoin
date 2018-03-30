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

        static Daemon &instance();
        static void destroy();

        // Threads
        static void handleConnections();
        static void handleRequests();
        static void manage();
        static void process();

        void run(bool pInDaemonMode = true);

        bool load();
        bool start(bool pInDaemonMode);
        bool isRunning() { return mRunning; }
        bool stopping() { return mStopping; }

        static const int FINISH_ON_REQUEST = 0;
        static const int FINISH_ON_SYNC = 1;

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

        enum Status { INACTIVE, LOADING, FINDING_PEERS, CONNECTING_TO_PEERS, SYNCHRONIZING, SYNCHRONIZED };
        bool isLoaded() { return mLoaded; }
        Status status();

    protected:

        static const int MAX_BLOCK_REQUEST = 8;

        Daemon();
        ~Daemon();

        Chain mChain;
        Info &mInfo;

        void stop();
        bool mRunning, mStopping, mStopRequested, mLoading, mLoaded, mQueryingSeed;
        int mFinishMode;

        // Threads
        NextCash::Thread *mConnectionThread;
        NextCash::Thread *mRequestsThread;
        NextCash::Thread *mManagerThread;
        NextCash::Thread *mProcessThread;

        // Timers
        uint32_t mLastHeaderRequestTime;

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

        Node *nodeWithInventory();
        Node *nodeWithBlock(const NextCash::Hash &pHash);
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
        bool loadKeyStore();
        bool saveKeyStore();

        Monitor mMonitor;
        bool loadMonitor();
        bool saveMonitor();

        // Request Channels
        NextCash::ReadersLock mRequestsLock;
        std::vector<RequestChannel *> mRequestChannels;
        bool addRequestChannel(NextCash::Network::Connection *pConnection);
        void cleanRequestChannels();

        Statistics mStatistics;
        void collectStatistics();
        void saveStatistics();
        void printStatistics();

        static Daemon *sInstance;
    };
}

#endif
