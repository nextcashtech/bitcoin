#include "daemon.hpp"

#include "arcmist/base/log.hpp"
#include "info.hpp"
#include "block.hpp"
#include "events.hpp"
#include "block.hpp"
#include "chain.hpp"

#include <unistd.h>
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
        mMaxConcurrentDownloads = 32;
        mNodeCount = 0;
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
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Pipe signal received.");
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

        if(!Chain::instance().loadBlocks(false))
            return false;

        if(!UnspentPool::instance().load())
            return false;
        mLastUnspentSave = getTime();
        
        if(UnspentPool::instance().blockHeight() != Chain::instance().blockHeight())
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Unspent height (%d) doesn't match chain height (%d)", UnspentPool::instance().blockHeight(),
              Chain::instance().blockHeight());
            return false;
        }

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

        UnspentPool::instance().save();

        Chain::destroy();
        UnspentPool::destroy();
        Info::destroy();

        mRunning = false;
        mStopping = false;
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Stopped");
    }

    void Daemon::getRandomizedNodeList(std::vector<Node *> &pList)
    {
        mNodeMutex.lock();
        pList = mNodes;
        mNodeMutex.unlock();

        // Sort Randomly
        std::random_shuffle(pList.begin(), pList.end());
    }

    Node *Daemon::nodeWithBlock(const Hash &pBlockHeaderHash)
    {
        std::vector<Node *> nodeList;
        getRandomizedNodeList(nodeList);
        for(std::vector<Node *>::iterator node=nodeList.begin();node!=nodeList.end();++node)
            if(!(*node)->waitingForBlock() && (*node)->hasBlock(pBlockHeaderHash))
                return *node;
        return NULL;
    }

    Node *Daemon::nodeWithInventory()
    {
        std::vector<Node *> nodeList;
        getRandomizedNodeList(nodeList);
        for(std::vector<Node *>::iterator node=nodeList.begin();node!=nodeList.end();++node)
            if((*node)->hasInventory())
                return *node;
        return NULL;
    }

    unsigned int Daemon::nodesWaitingForHeaders()
    {
        unsigned int result = 0;
        mNodeMutex.lock();
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
            if((*node)->waitingForHeaders())
                result++;
        mNodeMutex.unlock();
        return result;
    }
    
    void Daemon::cleanNodes()
    {
        uint64_t time = getTime();
        std::vector<Node *> toDelete;
        mNodeMutex.lock();
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
            if(time - (*node)->lastReceiveTime() > 1800) // 30 minutes
            {
                toDelete.push_back(*node);
                node = mNodes.erase(node);
                mNodeCount--;
            }
        mNodeMutex.unlock();

        for(std::vector<Node *>::iterator node=toDelete.begin();node!=toDelete.end();++node)
            delete *node;
    }

    void Daemon::requestInventories()
    {
        // Loop through nodes requesting blocks
        unsigned int hasInventory = 0;
        std::vector<Node *> nodeList;
        getRandomizedNodeList(nodeList);
        for(std::vector<Node *>::iterator node=nodeList.begin();node!=nodeList.end();++node)
        {
            if((*node)->hasInventory())
                hasInventory++;
            else if((*node)->shouldRequestInventory())
                (*node)->requestInventory();
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "%d/%d Nodes have block inventory", hasInventory, mNodeCount);
    }

    void Daemon::requestBlocks()
    {
        Chain &chain = Chain::instance();
        Hash nextBlockHash = chain.nextBlockNeeded();
        if(nextBlockHash.isEmpty())
            return;

        // Loop through nodes requesting blocks
        unsigned int downloading = 0;
        std::vector<Node *> nodeList;
        getRandomizedNodeList(nodeList);
        for(std::vector<Node *>::iterator node=nodeList.begin();node!=nodeList.end();++node)
        {
            if((*node)->waitingForBlock())
                downloading++;
            else if((*node)->hasBlock(nextBlockHash) && (*node)->requestBlock(nextBlockHash))
            {
                downloading++;
                nextBlockHash = chain.nextBlockNeeded();
                if(nextBlockHash.isEmpty())
                    return;
            }
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "%d/%d Nodes are downloading blocks", downloading, mNodeCount);
    }

    void Daemon::processManager()
    {
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Manager thread started");

        Daemon &daemon = Daemon::instance();
        Chain &chain = Chain::instance();
        UnspentPool &unspentPool = UnspentPool::instance();
        Info &info = Info::instance();
        uint64_t time;
        unsigned int pendingCount, nodesWaitingForHeaders;

        while(!daemon.mStopping)
        {
            time = getTime();

            if(time - daemon.mLastRequestCheck > 10)
            {
                daemon.mLastRequestCheck = time;
                daemon.requestInventories();

                pendingCount = chain.pendingCount();
                if(pendingCount < 100)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                      "%d Pending block/headers. Attempting to get more.", pendingCount);

                    // Check for header request
                    nodesWaitingForHeaders = daemon.nodesWaitingForHeaders();
                    if(nodesWaitingForHeaders < 4)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                          "%d/%d Nodes waiting for headers", nodesWaitingForHeaders, daemon.mNodeCount);

                        if(chain.blockHeight() <= 1)
                        {
                            Node *node = daemon.nodeWithInventory();
                            if(node != NULL)
                                node->requestHeaders(chain.lastPendingBlockHash());
                        }
                        else
                        {
                            Node *node = daemon.nodeWithBlock(chain.lastPendingBlockHash());
                            if(node != NULL)
                                node->requestHeaders(chain.lastPendingBlockHash());
                            else
                                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                                  "No nodes with last block : %s", chain.lastPendingBlockHash().hex().text());
                        }
                    }
                }

                if(pendingCount > 0)
                    daemon.requestBlocks();
            }

            if(daemon.mStopping)
                break;

            chain.process();

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
                unspentPool.save();
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

            ArcMist::Thread::sleep(1000);
        }

        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Manager thread finished");
    }

    void Daemon::processNodes()
    {
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Nodes thread started");

        Daemon &daemon = Daemon::instance();
        std::vector<Node *> nodes, liveNodes, deadNodes;

        while(!daemon.mStopping)
        {
            daemon.mNodeMutex.lock();
            nodes = daemon.mNodes;
            daemon.mNodeMutex.unlock();
            liveNodes.clear();
            deadNodes.clear();

            for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
            {
                if(daemon.mStopping)
                    break;

                if((*node)->isOpen())
                {
                    liveNodes.push_back(*node); // Add nodes to keep
                    (*node)->process();
                }
                else
                    deadNodes.push_back(*node);
            }

            if(daemon.mStopping)
                break;

            // Clean nodes
            daemon.mNodeMutex.lock();
            daemon.mNodes = liveNodes; // Copy live nodes back to main list
            daemon.mNodeMutex.unlock();
            for(unsigned int i=0;i<deadNodes.size();i++)
                delete deadNodes[i];

            if(daemon.mStopping)
                break;
            ArcMist::Thread::sleep(200); // 5hz
        }

        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Nodes thread finished");
    }

    bool Daemon::addNode(const char *pIPAddress, const char *pPort)
    {
        if(!isRunning())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "You must start BitCoin before adding a node");
            return false;
        }

        Node *node = new Node(pIPAddress, pPort);
        if(node->isOpen())
        {
            mNodeMutex.lock();
            mNodes.push_back(node);
            mNodeCount++;
            mNodeMutex.unlock();
            return true;
        }
        else
            return false;
    }

    bool Daemon::addNode(IPAddress &pAddress)
    {
        if(!isRunning())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "You must start BitCoin before adding a node");
            return false;
        }

        Node *node = new Node(pAddress);
        if(node->isOpen())
        {
            mNodeMutex.lock();
            mNodes.push_back(node);
            mNodeCount++;
            mNodeMutex.unlock();
            return true;
        }
        else
            return false;
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

        for(unsigned int i=0;i<ipList.size() && !mStopping;i++)
            if(addNode(ipList[i], networkPortString()))
                result++;

        return result;
    }

    unsigned int Daemon::pickNodes(unsigned int pCount)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Picking %d peers", pCount);
        Info &info = Info::instance();
        std::vector<Peer *> peers;
        unsigned int count = 0;

        info.randomizePeers(peers);
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Found %d peers", peers.size());
        for(std::vector<Peer *>::iterator peer=peers.begin();peer!=peers.end();++peer)
        {
            //TODO Ensure only one connection is made to an address. Check that this peer doesn't already have a node.
            if(addNode((*peer)->address))
                count++;

            if(mStopping || count >= pCount)
                break;
        }

        return count;
    }

    void Daemon::processConnections()
    {
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Connections thread started");

        Daemon &daemon = Daemon::instance();
        Info &info = Info::instance();
        unsigned int count;
        uint64_t time;

        while(!daemon.mStopping)
        {
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
                count = info.maxConnections - daemon.mNodes.size();
                if(count > 10)
                    count = 10; // Don't attempt more than 10 at a time
                daemon.pickNodes(count);
            }

            if(daemon.mStopping)
                break;

            ArcMist::Thread::sleep(200); // 5hz
        }

        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Connections thread finished");
    }
}
