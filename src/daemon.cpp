#include "daemon.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/io/network.hpp"
#include "info.hpp"
#include "block.hpp"
#include "events.hpp"
#include "block.hpp"
#include "chain.hpp"

#include <csignal>
#include <algorithm>

#define BITCOIN_DAEMON_LOG_NAME "BitCoin Daemon"


namespace BitCoin
{
    Daemon *Daemon::sInstance = 0;

    Daemon &Daemon::instance()
    {
        if(!sInstance)
        {
            sInstance = new Daemon;
            std::atexit(destroy);
        }

        return *Daemon::sInstance;
    }

    void Daemon::destroy()
    {
        delete Daemon::sInstance;
        Daemon::sInstance = 0;
    }

    Daemon::Daemon() : mNodeMutex("Nodes")
    {
        mRunning = false;
        mStopping = false;
        mStopRequested = false;
        mConnectionThread = NULL;
        mNodeThread = NULL;
        mManagerThread = NULL;
        previousSigTermChildHandler = NULL;
        previousSigTermHandler= NULL;
        previousSigIntHandler = NULL;
        previousSigPipeHandler = NULL;
        mLastNodeAdd = 0;
        mLastRequestCheck = 0;
        mLastInfoSave = 0;
        mLastUnspentSave = 0;
        mLastClean = 0;
        mLastHeaderRequest = 0;
        mNodeCount = 0;
        mStatReport = 0;
        mMaxPendingSize = 104857600; // 100 MiB
        mBytesReceived = 0;
        mBytesSent = 0;
    }

    Daemon::~Daemon()
    {
        if(isRunning())
            stop();
    }

    void Daemon::handleSigTermChild(int pValue)
    {
        //ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Child process terminated");
    }

    void Daemon::handleSigTerm(int pValue)
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Terminate signal received. Stopping.");
        instance().requestStop();
    }

    void Daemon::handleSigInt(int pValue)
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Interrupt signal received. Stopping.");
        instance().requestStop();
    }

    void Daemon::handleSigPipe(int pValue)
    {
        // Happens when writing to a network connection that is closed
        //ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Pipe signal received.");
    }

    void Daemon::run(ArcMist::String &pSeed, bool pInDaemonMode)
    {
        if(!start(pInDaemonMode))
            return;

        mSeed = pSeed;

        while(isRunning())
        {
            if(mStopRequested)
                stop();
            else
                ArcMist::Thread::sleep(100);
        }
    }

    bool Daemon::start(bool pInDaemonMode)
    {
        if(isRunning())
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_DAEMON_LOG_NAME, "Already running. Start aborted.");
            return false;
        }

        if(mStopping)
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_DAEMON_LOG_NAME, "Still stopping. Start aborted.");
            return false;
        }

        mRunning = true;

        // Set signal handlers
        if(pInDaemonMode)
            previousSigTermHandler = signal(SIGTERM, handleSigTerm);
        previousSigTermChildHandler = signal(SIGCHLD, handleSigTermChild);
        previousSigIntHandler = signal(SIGINT, handleSigInt);
        previousSigPipeHandler = signal(SIGPIPE, handleSigPipe);

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Starting %s on %s", BITCOIN_USER_AGENT, networkName());

        Info::instance(); // Load data
        mLastInfoSave = getTime();

        if(!mUnspentPool.load())
            return false;

        if(!mChain.load(mUnspentPool, false))
            return false;

        if(!mChain.updateUnspent(mUnspentPool))
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Unspent height %d doesn't match chain height %d", mUnspentPool.blockHeight(),
              mChain.blockHeight());
            return false;
        }
        mLastUnspentSave = getTime();

        mConnectionThread = new ArcMist::Thread("Connection", processConnections);
        if(mConnectionThread == NULL)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create connection thread");
            return false;
        }

        mNodeThread = new ArcMist::Thread("Node", processNodes);
        if(mNodeThread == NULL)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create node thread");
            return false;
        }

        mLastClean = getTime();
        mStatReport = getTime();
        mManagerThread = new ArcMist::Thread("Manager", processManager);
        if(mManagerThread == NULL)
        {
            mStopping = true;
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create manager thread");
            return false;
        }

        return true;
    }

    void Daemon::stop()
    {
        if(!isRunning())
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_DAEMON_LOG_NAME, "Not running. Stop aborted.");
            return;
        }

        if(mStopping)
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_DAEMON_LOG_NAME, "Still stopping. Stop aborted.");
            return;
        }

        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Stopping");
        mStopping = true;

        // Set signal handlers back to original
        if(previousSigTermChildHandler != NULL)
            signal(SIGCHLD, previousSigTermChildHandler);
        if(previousSigTermHandler != NULL)
            signal(SIGTERM, previousSigTermHandler);
        if(previousSigIntHandler != NULL)
            signal(SIGINT, previousSigIntHandler);
        if(previousSigPipeHandler != NULL)
            signal(SIGPIPE, previousSigPipeHandler);

        previousSigTermChildHandler = NULL;
        previousSigTermHandler= NULL;
        previousSigIntHandler = NULL;

        // Wait for connections to finish
        if(mConnectionThread != NULL)
            delete mConnectionThread;
        mConnectionThread = NULL;

        // Wait for manager to finish
        if(mManagerThread != NULL)
            delete mManagerThread;
        mManagerThread = NULL;

        // Wait for nodes to finish
        if(mNodeThread != NULL)
            delete mNodeThread;
        mNodeThread = NULL;

        // Delete nodes
        mNodeMutex.lock();
        std::vector<Node *> tempNodes = mNodes;
        mNodes.clear();
        mNodeMutex.unlock();
        for(unsigned int i=0;i<tempNodes.size();i++)
            delete tempNodes[i];

        mUnspentPool.save();
        Info::destroy();

        mRunning = false;
        mStopping = false;
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Stopped");
    }

    void Daemon::collectNetworkTracking()
    {
        mNodeMutex.lock();
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
        {
            mBytesReceived += (*node)->bytesReceived();
            mBytesSent += (*node)->bytesSent();
            (*node)->resetNetworkByteCounts();
        }
        mNodeMutex.unlock();
    }

    void Daemon::processRequests()
    {
        mChain.prioritizePending();

        mNodeMutex.lock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        std::random_shuffle(nodes.begin(), nodes.end()); // Sort Randomly

        int pendingCount = mChain.pendingCount();
        bool reduceOnly = mChain.pendingSize() > mMaxPendingSize;
        Hash nextBlock = mChain.nextBlockNeeded(reduceOnly);
        uint64_t time = getTime();

        if(reduceOnly)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_DAEMON_LOG_NAME,
              "Max pending block memory usage : %d", mChain.pendingSize());
        }

        // Loop through nodes
        unsigned int availableToRequestBlocks = 0;
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
        {
            if(!(*node)->hasInventory(mChain))
                (*node)->requestInventory(mChain);
            else if(pendingCount < 1000 && time - mLastHeaderRequest > 60)
            {
                if((*node)->requestHeaders(mChain.lastPendingBlockHash()))
                    mLastHeaderRequest = getTime();
            }
            else if(!(*node)->waitingForBlocks())
                ++availableToRequestBlocks;
        }

        // Request blocks
        int blocksToRequest = mChain.pendingCount() - mChain.pendingBlockCount();
        if(blocksToRequest > 0 && availableToRequestBlocks > 0)
        {
            for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end()&&blocksToRequest>0;++node)
                if((*node)->hasInventory(mChain) && !(*node)->waitingForBlocks() && (*node)->requestBlocks(mChain, 50, reduceOnly))
                    blocksToRequest -= 50;
        }

        mNodeMutex.unlock();
    }

    void Daemon::printStats()
    {
        unsigned int count = 0;
        unsigned int downloading = 0;
        unsigned int inventory = 0;
        mNodeMutex.lock();
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
        {
            count++;
            if((*node)->hasInventory(mChain))
                inventory++;
            if((*node)->waitingForBlocks())
                downloading++;
        }
        mNodeMutex.unlock();

        collectNetworkTracking();

        unsigned int blocks = mChain.pendingBlockCount();
        unsigned int totalPending = mChain.pendingCount();

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Block Chain : %d blocks, %d UTXOs", mChain.blockHeight(), mUnspentPool.count());
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Pending : %d blocks, %d headers (%d bytes)", blocks, totalPending - blocks, mChain.pendingSize());
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Nodes : %d (%d have inventory) (%d downloading)", count, inventory, downloading);
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Network : %d bytes received, %d bytes sent", mBytesReceived, mBytesSent);
    }

    void Daemon::processManager()
    {
        Daemon &daemon = Daemon::instance();
        Info &info = Info::instance();
        uint64_t time;

        while(!daemon.mStopping)
        {
            time = getTime();

            if(time - daemon.mLastRequestCheck > 10)
            {
                daemon.mLastRequestCheck = time;
                daemon.processRequests();
            }

            if(daemon.mStopping)
                break;

            daemon.mChain.process(daemon.mUnspentPool);

            if(daemon.mStopping)
                break;

            if(time - daemon.mStatReport > 60)
            {
                daemon.mStatReport = time;
                daemon.printStats();
            }

            if(daemon.mStopping)
                break;

            if(time - daemon.mLastInfoSave > 300)
            {
                daemon.mLastInfoSave = time;
                info.save();
            }

            if(daemon.mStopping)
                break;

            if(time - daemon.mLastUnspentSave > 300)
            {
                daemon.mLastUnspentSave = time;
                daemon.mUnspentPool.save();
            }

            if(daemon.mStopping)
                break;

            ArcMist::Thread::sleep(1000);

            if(daemon.mStopping)
                break;
        }
    }

    void Daemon::processNodes()
    {
        Daemon &daemon = Daemon::instance();
        std::vector<Node *> nodes;

        while(!daemon.mStopping)
        {
            daemon.mNodeMutex.lock();
            for(std::vector<Node *>::iterator node=daemon.mNodes.begin();node!=daemon.mNodes.end();++node)
            {
                if(daemon.mStopping)
                    break;

                if((*node)->isOpen())
                    (*node)->process(daemon.mChain);
            }
            daemon.mNodeMutex.unlock();

            if(daemon.mStopping)
                break;

            ArcMist::Thread::sleep(200); // 5hz
            if(daemon.mStopping)
                break;
        }
    }

    bool Daemon::addNode(const char *pIPAddress, const char *pPort)
    {
        if(!isRunning())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "You must start BitCoin before adding a node");
            return false;
        }

        Node *node = new Node(pIPAddress, pPort, mChain);
        if(node->isOpen())
        {
            mNodeMutex.lock();
            mNodes.push_back(node);
            mNodeCount++;
            mNodeMutex.unlock();
            return true;
        }
        else
        {
            delete node;
            return false;
        }
    }

    bool Daemon::addNode(IPAddress &pAddress)
    {
        if(!isRunning())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "You must start BitCoin before adding a node");
            return false;
        }

        Node *node = new Node(pAddress, mChain);
        if(node->isOpen())
        {
            mNodeMutex.lock();
            mNodes.push_back(node);
            mNodeCount++;
            mNodeMutex.unlock();
            return true;
        }
        else
        {
            delete node;
            return false;
        }
    }

    unsigned int Daemon::querySeed(const char *pName)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Querying seed %s", pName);
        ArcMist::Network::IPList ipList;
        ArcMist::Network::list(pName, ipList);
        unsigned int result = 0;

        if(ipList.size() == 0)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "No nodes found from seed");
            return 0;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Found %d nodes from %s", ipList.size(), pName);

        for(ArcMist::Network::IPList::iterator ip=ipList.begin();ip!=ipList.end() && !mStopping;++ip)
            if(addNode(*ip, networkPortString()))
                result++;

        return result;
    }

    unsigned int Daemon::pickNodes(unsigned int pCount)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Picking %d peers", pCount);
        Info &info = Info::instance();
        std::vector<Peer *> peers;
        unsigned int count = 0;
        bool found;

        // Try peers with good ratings first
        info.randomizePeers(peers, 1);
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Found %d peers with good ratings", peers.size());
        for(std::vector<Peer *>::iterator peer=peers.begin();peer!=peers.end();++peer)
        {
            // Skip nodes already connected
            found = false;
            mNodeMutex.lock();
            for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
                if((*node)->address() == (*peer)->address)
                {
                    found = true;
                    break;
                }
            mNodeMutex.unlock();
            if(found)
                continue;

            if(addNode((*peer)->address))
                count++;

            if(mStopping || count >= pCount / 2) // Limit good to half
                break;
        }

        info.randomizePeers(peers, 0);
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Found %d peers", peers.size());
        for(std::vector<Peer *>::iterator peer=peers.begin();peer!=peers.end();++peer)
        {
            // Skip nodes already connected
            found = false;
            mNodeMutex.lock();
            for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
                if((*node)->address() == (*peer)->address)
                {
                    found = true;
                    break;
                }
            mNodeMutex.unlock();
            if(found)
                continue;

            if(addNode((*peer)->address))
                count++;

            if(mStopping || count >= pCount)
                break;
        }

        return count;
    }

    bool Daemon::addNode(ArcMist::Network::Connection *pConnection)
    {
        if(!isRunning())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "You must start BitCoin before adding a node");
            return false;
        }

        Node *node = new Node(pConnection, mChain);
        if(node->isOpen())
        {
            mNodeMutex.lock();
            mNodes.push_back(node);
            mNodeCount++;
            mNodeMutex.unlock();
            return true;
        }
        else
        {
            delete node;
            return false;
        }
    }

    void Daemon::cleanNodes()
    {
        uint64_t time = getTime();
        mNodeMutex.lock();
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();)
        {
            if(!(*node)->isOpen())
            {
                delete *node;
                node = mNodes.erase(node);
                mNodeCount--;
            }
            else if((*node)->lastReceiveTime() != 0 && time - (*node)->lastReceiveTime() > 1800) // 30 minutes
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Dropping node [%d] because it is not responding", (*node)->id());
                delete *node;
                node = mNodes.erase(node);
                mNodeCount--;
            }
            else if((*node)->notResponding())
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Dropping node [%d] because it is not responding to requests", (*node)->id());
                Info::instance().addPeerFail((*node)->address());
                delete *node;
                node = mNodes.erase(node);
                mNodeCount--;
            }
            else
                ++node;
        }
        mNodeMutex.unlock();
    }

    void Daemon::processConnections()
    {
        Daemon &daemon = Daemon::instance();
        Info &info = Info::instance();
        ArcMist::Network::Listener listener(AF_INET6, networkPort(), 5, 1);
        ArcMist::Network::Connection *newConnection;
        uint64_t time;

        if(!listener.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create listener");
            daemon.requestStop();
            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Listening for connections on port %d", listener.port());

        while(!daemon.mStopping)
        {
            newConnection = listener.accept();
            if(newConnection != NULL)
            {
                if(daemon.mNodeCount < info.maxConnections)
                {
                    ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                      "Adding node from incoming connection");
                    if(!daemon.addNode(newConnection)) // Add node for this connection
                    {
                        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                          "Add node for incoming connection failed");
                    }
                }
                else
                {
                    ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                      "Dropping incoming connection because of connection limit");
                    delete newConnection; // Drop this connection
                }
            }

            if(daemon.mStopping)
                break;

            time = getTime();

            if(daemon.mSeed)
            {
                daemon.querySeed(daemon.mSeed);
                daemon.mSeed.clear();
            }

            if(daemon.mStopping)
                break;

            if(daemon.mNodes.size() < info.maxConnections && time - daemon.mLastNodeAdd > 60)
            {
                daemon.mLastNodeAdd = time;
                if(info.maxConnections > daemon.mNodes.size())
                    daemon.pickNodes(info.maxConnections - daemon.mNodes.size());
            }

            if(daemon.mStopping)
                break;

            if(time - daemon.mLastClean > 10)
            {
                daemon.mLastClean = time;
                daemon.cleanNodes();
            }

            if(daemon.mStopping)
                break;

            ArcMist::Thread::sleep(500); // 5hz
            if(daemon.mStopping)
                break;
        }
    }
}
