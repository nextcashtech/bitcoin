/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "daemon.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/io/network.hpp"
#include "info.hpp"
#include "block.hpp"
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

    Daemon::Daemon() : mInfo(Info::instance()), mNodeLock("Nodes")
    {
        mLastInfoSave = getTime();
        mRunning = false;
        mStopping = false;
        mStopRequested = false;
        mConnectionThread = NULL;
        mManagerThread = NULL;
        mProcessThread = NULL;
        previousSigTermChildHandler = NULL;
        previousSigTermHandler= NULL;
        previousSigIntHandler = NULL;
        previousSigPipeHandler = NULL;
        mLastNodeAdd = 0;
        mLastRequestCheck = 0;
        mLastTransactionOutputsSave = 0;
        mLastClean = 0;
        mLastHeaderRequest = 0;
        mNodeCount = 0;
        mIncomingNodes = 0;
        mOutgoingNodes = 0;
        mStatReport = 0;
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
                ArcMist::Thread::sleep(1000);
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

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Starting %s on %s", BITCOIN_USER_AGENT, networkName());

        if(!mPool.load())
            return false;

        if(!mChain.load(mPool, false))
            return false;

        mChain.loadPending();

        if(!mChain.updateTransactionOutputs(mPool))
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Unspent transaction outputs height %d doesn't match chain height %d", mPool.blockHeight(),
              mChain.blockHeight());
            return false;
        }
        mLastTransactionOutputsSave = getTime();

        mConnectionThread = new ArcMist::Thread("Connection", handleConnections);
        if(mConnectionThread == NULL)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create connection thread");
            return false;
        }

        mLastClean = getTime();
        mStatReport = getTime();
        mManagerThread = new ArcMist::Thread("Manager", manage);
        if(mManagerThread == NULL)
        {
            mStopping = true;
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create manage thread");
            return false;
        }

        mProcessThread = new ArcMist::Thread("Process", process);
        if(mProcessThread == NULL)
        {
            mStopping = true;
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create process thread");
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

        // Tell the chain to stop processing
        mChain.requestStop();

        // Wait for connections to finish
        if(mConnectionThread != NULL)
            delete mConnectionThread;
        mConnectionThread = NULL;

        // Delete nodes
        mNodeLock.writeLock("Destroy");
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
            delete *node;
        mNodes.clear();
        mNodeLock.writeUnlock();

        // Wait for process thread to finish
        if(mProcessThread != NULL)
            delete mProcessThread;
        mProcessThread = NULL;

        // Wait for manager to finish
        if(mManagerThread != NULL)
            delete mManagerThread;
        mManagerThread = NULL;

        saveStatistics();
        mChain.savePending();
        mPool.save();
        Info::destroy();

        mRunning = false;
        mStopping = false;
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Stopped");
    }

    void Daemon::collectStatistics()
    {
        mNodeLock.readLock();
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
            (*node)->collectStatistics(mStatistics);
        mNodeLock.readUnlock();
    }

    void Daemon::saveStatistics()
    {
        collectStatistics();

        ArcMist::String filePathName = Info::instance().path();
        filePathName.pathAppend("statistics");
        ArcMist::FileOutputStream file(filePathName, false, true);
        if(!file.isValid())
        {
            // Clear anyway so it doesn't try to save every manager loop
            mStatistics.clear();
            return;
        }
        mStatistics.write(&file);
        mStatistics.clear();
    }

    void Daemon::printStatistics()
    {
        unsigned int downloading = 0;
        mNodeLock.readLock();
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
            if((*node)->waitingForBlocks())
                downloading++;
        mNodeLock.readUnlock();

        collectStatistics();

        unsigned int pendingBlocks = mChain.pendingBlockCount();
        unsigned int pendingCount = mChain.pendingCount();
        unsigned int pendingSize = mChain.pendingSize();

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Block Chain : %d blocks, %d UTXOs", mChain.blockHeight(), mPool.count());
        if(pendingSize > mInfo.pendingSizeThreshold || pendingBlocks > mInfo.pendingBlocksThreshold)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Pending (above threshold) : %d blocks, %d headers (%d bytes)", pendingBlocks,
              pendingCount - pendingBlocks, pendingSize);
        else
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Pending : %d blocks, %d headers (%d bytes)", pendingBlocks, pendingCount - pendingBlocks, pendingSize);
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Nodes : %d/%d outgoing/incoming (%d downloading)", mOutgoingNodes, mIncomingNodes, downloading);
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Network : %d bytes received, %d bytes sent", mStatistics.bytesReceived, mStatistics.bytesSent);
    }

    void Daemon::sendRequests()
    {
        mChain.prioritizePending();

        unsigned int pendingCount = mChain.pendingCount();
        unsigned int pendingBlockCount = mChain.pendingBlockCount();
        unsigned int pendingSize = mChain.pendingSize();
        bool reduceOnly = pendingSize > mInfo.pendingSizeThreshold || pendingBlockCount > mInfo.pendingBlocksThreshold;
        Hash nextBlock = mChain.nextBlockNeeded(reduceOnly);
        unsigned int availableToRequestBlocks = 0;

        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        std::random_shuffle(nodes.begin(), nodes.end()); // Sort Randomly
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
        {
            if(!mChain.isInSync() && getTime() - mLastHeaderRequest > 60 && pendingCount < 4000 &&
              (*node)->requestHeaders(mChain, mChain.lastPendingBlockHash()))
                mLastHeaderRequest = getTime();

            if(!(*node)->waitingForBlocks() && (*node)->blockHeight() > mChain.blockHeight())
                ++availableToRequestBlocks;
        }

        // Request blocks
        if(pendingCount > pendingBlockCount && availableToRequestBlocks > 0)
        {
            int blocksToRequest = pendingCount - pendingBlockCount;
            for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end()&&blocksToRequest>0;++node)
                if(!(*node)->waitingForBlocks() && (*node)->blockHeight() > mChain.blockHeight()
                  && (*node)->requestBlocks(mChain, 16, reduceOnly))
                    blocksToRequest -= 16;
        }

        mNodeLock.readUnlock();
    }

    void Daemon::manage()
    {
        Daemon &daemon = Daemon::instance();

        while(!daemon.mStopping)
        {
            if(getTime() - daemon.mStatReport > 60)
            {
                daemon.mStatReport = getTime();
                daemon.printStatistics();
            }

            if(daemon.mStopping)
                break;

            if(getTime() - daemon.mLastRequestCheck > 10)
            {
                daemon.mLastRequestCheck = getTime();
                daemon.sendRequests();
            }

            if(daemon.mStopping)
                break;

            if(getTime() - daemon.mLastInfoSave > 600)
            {
                daemon.mLastInfoSave = getTime();
                daemon.mInfo.save();
            }

            if(daemon.mStopping)
                break;

            if(getTime() - daemon.mStatistics.startTime > 3600)
                daemon.saveStatistics();

            if(daemon.mStopping)
                break;

            ArcMist::Thread::sleep(500);
        }
    }

    void Daemon::process()
    {
        Daemon &daemon = Daemon::instance();

        while(!daemon.mStopping)
        {
            daemon.mChain.process(daemon.mPool);

            if(daemon.mStopping)
                break;

            if(getTime() - daemon.mLastTransactionOutputsSave > 1200)
            {
                daemon.mLastTransactionOutputsSave = getTime();
                daemon.mPool.save();
            }

            if(daemon.mStopping)
                break;

            ArcMist::Thread::sleep(500);
        }
    }

    bool Daemon::addNode(ArcMist::Network::Connection *pConnection, bool pIncoming, bool pIsSeed)
    {
        Node *node;
        try
        {
            node = new Node(pConnection, &mChain, pIncoming, pIsSeed);
        }
        catch(std::bad_alloc &pBadAlloc)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Bad allocation while allocating new node : %s", pBadAlloc.what());
            delete pConnection;
            return false;
        }
        catch(...)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Bad allocation while allocating new node : unknown");
            delete pConnection;
            return false;
        }

        mNodeLock.writeLock("Add Node");
        mNodes.push_back(node);
        mNodeCount++;
        if(pIncoming)
            ++mIncomingNodes;
        else
            ++mOutgoingNodes;
        mNodeLock.writeUnlock();
        return true;
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
        ArcMist::Network::Connection *connection;
        for(ArcMist::Network::IPList::iterator ip=ipList.begin();ip!=ipList.end() && !mStopping;++ip)
        {
            connection = new ArcMist::Network::Connection(*ip, networkPortString(), 5);
            if(!connection->isOpen())
                delete connection;
            else if(addNode(connection, false, true))
            {
                ++mStatistics.outgoingConnections;
                result++;
            }
        }

        return result;
    }

    unsigned int Daemon::pickNodes(unsigned int pCount)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Picking %d peers", pCount);
        std::vector<Peer *> peers;
        unsigned int count = 0;
        bool found;

        // Try peers with good ratings first
        mInfo.randomizePeers(peers, 1);
        ArcMist::Network::Connection *connection;
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Found %d peers with good ratings", peers.size());
        for(std::vector<Peer *>::iterator peer=peers.begin();peer!=peers.end();++peer)
        {
            // Skip nodes already connected
            found = false;
            mNodeLock.readLock();
            for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
                if((*node)->address() == (*peer)->address)
                {
                    found = true;
                    break;
                }
            mNodeLock.readUnlock();
            if(found)
                continue;

            connection = new ArcMist::Network::Connection(AF_INET6, (*peer)->address.ip, (*peer)->address.port, 5);
            if(!connection->isOpen())
                delete connection;
            else if(addNode(connection, false))
            {
                ++mStatistics.outgoingConnections;
                count++;
            }

            if(mStopping || count >= pCount / 2) // Limit good to half
                break;
        }

        peers.clear();
        mInfo.randomizePeers(peers, 0);
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Found %d peers", peers.size());
        for(std::vector<Peer *>::iterator peer=peers.begin();peer!=peers.end();++peer)
        {
            // Skip nodes already connected
            found = false;
            mNodeLock.readLock();
            for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
                if((*node)->address() == (*peer)->address)
                {
                    found = true;
                    break;
                }
            mNodeLock.readUnlock();
            if(found)
                continue;

            connection = new ArcMist::Network::Connection(AF_INET6, (*peer)->address.ip, (*peer)->address.port, 5);
            if(!connection->isOpen())
                delete connection;
            else if(addNode(connection, false))
            {
                ++mStatistics.outgoingConnections;
                count++;
            }

            if(mStopping || count >= pCount)
                break;
        }

        return count;
    }

    void Daemon::cleanNodes()
    {
        uint64_t time = getTime();

        mNodeLock.readLock();

        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        std::random_shuffle(nodes.begin(), nodes.end()); // Sort Randomly
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
            if((*node)->isOpen())
            {
                if((*node)->lastReceiveTime() != 0 && time - (*node)->lastReceiveTime() > 1800) // 30 minutes
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                      "Dropping node [%d] because it is not responding", (*node)->id());
                    (*node)->close();
                }
                else if((*node)->notResponding())
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                      "Dropping node [%d] because it is not responding to requests", (*node)->id());
                    mInfo.addPeerFail((*node)->address());
                    (*node)->close();
                }
            }

        mNodeLock.readUnlock();

        // Drop all disconnected nodes
        std::vector<Node *> toDelete;
        mNodeLock.writeLock("Clean Nodes");
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();)
            if(!(*node)->isOpen())
            {
                toDelete.push_back(*node);
                node = mNodes.erase(node);
                --mNodeCount;
                if((*node)->isIncoming())
                    --mIncomingNodes;
                else
                    --mOutgoingNodes;
            }
            else
                ++node;
        mNodeLock.writeUnlock();

        for(std::vector<Node *>::iterator node=toDelete.begin();node!=toDelete.end();++node)
        {
            (*node)->collectStatistics(mStatistics);
            mChain.releaseBlocksForNode((*node)->id());
            delete *node;
        }
    }

    void Daemon::handleConnections()
    {
        Daemon &daemon = Daemon::instance();
        ArcMist::Network::Listener listener(AF_INET6, networkPort(), 5, 1);
        ArcMist::Network::Connection *newConnection;
        unsigned int maxOutgoing, maxIncoming;

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
            if(daemon.mChain.isInSync())
                maxOutgoing = 8;
            else
                maxOutgoing = daemon.mInfo.maxConnections / 2;
            maxIncoming = daemon.mInfo.maxConnections - maxOutgoing;

            if(getTime() - daemon.mLastClean > 10)
            {
                daemon.mLastClean = getTime();
                daemon.cleanNodes();
            }

            while(!daemon.mStopping && (newConnection = listener.accept()) != NULL)
            {
                ++daemon.mStatistics.incomingConnections;
                if(daemon.mIncomingNodes < maxIncoming)
                {
                    ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                      "Adding node from incoming connection");
                    daemon.addNode(newConnection, true);
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

            if(daemon.mSeed)
            {
                daemon.querySeed(daemon.mSeed);
                daemon.mSeed.clear();
            }

            if(daemon.mStopping)
                break;

            if(daemon.mOutgoingNodes < maxOutgoing && getTime() - daemon.mLastNodeAdd > 60)
            {
                daemon.pickNodes(maxOutgoing - daemon.mOutgoingNodes);
                daemon.mLastNodeAdd = getTime();
            }

            if(daemon.mStopping)
                break;

            ArcMist::Thread::sleep(500);
        }
    }
}
