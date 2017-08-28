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
        static void processNodes();

        void run(ArcMist::String &pSeed);

        void start();
        bool isRunning() { return mNodeThread != NULL; }
        void stop();

        bool addNode(IPAddress &pAddress);
        bool addNode(const char *pIPAddress, const char *pPort);

        // Query peers from a seed
        // Returns number of peers actually connected
        unsigned int querySeed(const char *pName);

        // Randomly choose peers and open nodes on them until specified count is reached.
        // Returns number of peers actually connected
        unsigned int pickNodes(unsigned int pCount);

        bool stopping() { return mStopping; }
        
        static void handleSigTermChild(int pValue);
        static void handleSigTerm(int pValue);
        static void handleSigInt(int pValue);

    protected:

        Daemon();
        ~Daemon();

        ArcMist::Thread *mNodeThread;
        ArcMist::Mutex mNodeMutex;
        std::vector<Node *> mNodes;
        bool mStopping;

        void (*previousSigTermChildHandler)(int);
        void (*previousSigTermHandler)(int);
        void (*previousSigIntHandler)(int);

        void cleanNodes();

        static Daemon *sInstance;
    };
}

#endif
