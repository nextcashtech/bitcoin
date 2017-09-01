#ifndef BITCOIN_DAEMON_HPP
#define BITCOIN_DAEMON_HPP

#include "arcmist/io/stream.hpp"
#include "arcmist/io/network.hpp"
#include "arcmist/base/thread.hpp"
#include "arcmist/base/mutex.hpp"
#include "base.hpp"
#include "node.hpp"

#include <cstdint>
#include <cstring>
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
        void stop();

        bool stopping() { return mStopping; }
        
        static void handleSigTermChild(int pValue);
        static void handleSigTerm(int pValue);
        static void handleSigInt(int pValue);

    protected:

        Daemon();
        ~Daemon();

        ArcMist::Thread *mConnectionThread;
        ArcMist::Thread *mNodeThread;
        ArcMist::Thread *mManagerThread;
        ArcMist::Mutex mNodeMutex;
        std::vector<Node *> mNodes;
        uint64_t mLastNodeAdd;
        bool mRunning, mStopping;

        void (*previousSigTermChildHandler)(int);
        void (*previousSigTermHandler)(int);
        void (*previousSigIntHandler)(int);
        
        Node *nodeWithBlock(Hash &pBlockHeaderHash);

        // Query peers from a seed
        // Returns number of peers actually connected
        ArcMist::String mSeed;
        unsigned int querySeed(const char *pName);

        // Randomly choose peers and open nodes on them until specified count is reached.
        // Returns number of peers actually connected
        bool addNode(IPAddress &pAddress);
        bool addNode(const char *pIPAddress, const char *pPort);
        unsigned int pickNodes(unsigned int pCount);
        void cleanNodes();

        static Daemon *sInstance;
    };
}

#endif
