#include "daemon.hpp"

#include "arcmist/base/log.hpp"
#include "info.hpp"

#include <unistd.h>
#include <csignal>

#define BITCOIN_DAEMON_LOG_NAME "BitCoin Daemon"


namespace BitCoin
{
    static Network sNetwork = TESTNET;

    Network network() { return sNetwork; }
    void setNetwork(Network pNetwork) { sNetwork = pNetwork; }

    const char *networkStartString()
    {
        switch(sNetwork)
        {
            case MAINNET:
                return "f9beb4d9";
            case TESTNET:
                return "0b110907";
        }

        return "";
    }

    const char *networkPortString()
    {
        switch(sNetwork)
        {
            case MAINNET:
                return "8333";
            case TESTNET:
                return "18333";
        }

        return "";
    }

    uint16_t networkPort()
    {
        switch(sNetwork)
        {
            case MAINNET:
                return 8333;
            case TESTNET:
                return 18333;
        }

        return 0;
    }

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

    Daemon::Daemon() : mNodeMutex("Daemon")
    {
        mStopping = false;
        mNodeThread = NULL;
    }

    Daemon::~Daemon()
    {
        if(isRunning())
            stop();
    }

    void Daemon::handleSigTermChild(int pValue)
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Terminate child signal received. Stopping.");
        instance().stop();
    }

    void Daemon::handleSigTerm(int pValue)
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Terminate signal received. Stopping.");
        instance().stop();
    }

    void Daemon::handleSigInt(int pValue)
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Interrupt signal received. Stopping.");
        instance().stop();
    }

    void Daemon::run(ArcMist::String &pSeed)
    {
        start();
        
        if(pSeed)
            querySeed(pSeed);
        else
            pickNodes(Info::instance().maxConnections);

        unsigned int sinceSave = 0;

        while(isRunning())
        {
            usleep(100000);
            sinceSave++;
            
            if(sinceSave > 6000)
            {
                sinceSave = 0;
                Info::instance().save();
            }
        }
    }

    void Daemon::start()
    {
        if(isRunning())
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_DAEMON_LOG_NAME, "Already running. Start aborted.");
            return;
        }

        if(mStopping)
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_DAEMON_LOG_NAME, "Still stopping. Start aborted.");
            return;
        }

        // Set signal handlers
        previousSigTermChildHandler = signal(SIGCHLD, handleSigTermChild);
        previousSigTermHandler = signal(SIGTERM, handleSigTerm);
        previousSigIntHandler = signal(SIGINT, handleSigInt);

        switch(network())
        {
            case MAINNET:
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Starting BitCoin Daemon for Main Net");
                break;
            case TESTNET:
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Starting BitCoin Daemon for Test Net");
                break;
            default:
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Starting BitCoin Daemon for Unknown Net");
                break;
        }

        mNodeThread = new ArcMist::Thread("Node", processNodes);

        if(mNodeThread == NULL)
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create node thread");
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

        // Set signal handlers back to original
        signal(SIGCHLD, previousSigTermChildHandler);
        signal(SIGTERM, previousSigTermHandler);
        signal(SIGINT, previousSigIntHandler);

        mStopping = true;

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

        Info::destroy();

        mStopping = false;
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

        for(unsigned int i=0;i<ipList.size();i++)
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
        for(std::vector<Peer *>::iterator i=peers.begin();i!=peers.end();++i)
        {
            if(addNode((*i)->address))
                count++;

            if(count >= pCount)
                break;
        }

        return count;
    }

    void Daemon::processNodes()
    {
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Nodes thread started");

        Daemon &daemon = Daemon::instance();
        std::vector<Node *> nodes, liveNodes, deadNodes;
        Node *node;

        while(!daemon.mStopping)
        {
            daemon.mNodeMutex.lock();
            nodes = daemon.mNodes;
            daemon.mNodeMutex.unlock();
            liveNodes.clear();
            deadNodes.clear();

            for(unsigned int i=0;i<nodes.size();i++)
            {
                if(daemon.mStopping)
                    break;

                node = nodes[i];
                if(node->isOpen())
                {
                    liveNodes.push_back(node); // Add nodes to keep
                    node->process();
                }
                else
                    deadNodes.push_back(node);
            }

            if(daemon.mStopping)
                break;

            // Clean nodes
            daemon.mNodeMutex.lock();
            daemon.mNodes = liveNodes; // Copy live nodes back to main list
            daemon.mNodeMutex.unlock();
            for(unsigned int i=0;i<deadNodes.size();i++)
                delete deadNodes[i];

            usleep(50000); // 5hz
        }

        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Nodes thread finished");
    }
}
