#ifndef BITCOIN_DAEMON_HPP
#define BITCOIN_DAEMON_HPP

#include "arcmist/io/stream.hpp"
#include "arcmist/base/thread.hpp"
#include "arcmist/base/mutex.hpp"
#include "base.hpp"
#include "node.hpp"

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
        static void processConnections();
        static void processNodes();
        static void processManager();

        void run(ArcMist::String &pSeed, bool pInDaemonMode = true);

        bool start(bool pInDaemonMode);
        bool isRunning() { return mRunning; }
        bool stopping() { return mStopping; }

        void requestStop() { mStopRequested = true; }

        // Signals
        static void handleSigTermChild(int pValue);
        static void handleSigTerm(int pValue);
        static void handleSigInt(int pValue);
        static void handleSigPipe(int pValue);

    protected:

        Daemon();
        ~Daemon();

        Chain mChain;
        UnspentPool mUnspentPool;
        
        void stop();
        bool mRunning, mStopping, mStopRequested;

        // Threads
        ArcMist::Thread *mConnectionThread;
        ArcMist::Thread *mNodeThread;
        ArcMist::Thread *mManagerThread;

        // Timers
        uint32_t mLastNodeAdd;
        uint32_t mLastRequestCheck;
        uint32_t mLastHeaderRequest;
        uint32_t mLastInfoSave;
        uint32_t mLastUnspentSave;
        uint32_t mLastClean;
        uint32_t mStatReport;
        unsigned int mMaxPendingSize; // Maximum pending memory usage

        // Signals
        void (*previousSigTermChildHandler)(int);
        void (*previousSigTermHandler)(int);
        void (*previousSigIntHandler)(int);
        void (*previousSigPipeHandler)(int);

        void printStats();

        ArcMist::String mSeed;
        // Query peers from a seed
        // Returns number of peers actually connected
        unsigned int querySeed(const char *pName);

        // Nodes
        ArcMist::Mutex mNodeMutex;
        std::vector<Node *> mNodes;
        unsigned int mNodeCount;

        bool addNode(IPAddress &pAddress);
        bool addNode(const char *pIPAddress, const char *pPort);
        bool addNode(ArcMist::Network::Connection *pConnection);
        unsigned int pickNodes(unsigned int pCount);
        void cleanNodes();

        Node *nodeWithInventory();
        Node *nodeWithBlock(const Hash &pHash);
        void processRequests();

        void collectNetworkTracking();
        uint64_t mBytesReceived;
        uint64_t mBytesSent;

        static Daemon *sInstance;
    };
}

#endif
