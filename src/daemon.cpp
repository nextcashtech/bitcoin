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
        mLastHeaderRequestTime = 0;
        mNodeCount = 0;
        mIncomingNodes = 0;
        mOutgoingNodes = 0;
        mLastPeerCount = 0;
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

        if(!mChain.load(false))
            return false;

        mConnectionThread = new ArcMist::Thread("Connection", handleConnections);
        if(mConnectionThread == NULL)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create connection thread");
            return false;
        }

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

        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping connection thread");
        // Wait for connections to finish
        if(mConnectionThread != NULL)
            delete mConnectionThread;
        mConnectionThread = NULL;

        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping nodes");
        mNodeLock.readLock();
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
            (*node)->requestStop();
        mNodeLock.readUnlock();

        // Delete nodes
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Deleting nodes");
        mNodeLock.writeLock("Destroy");
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
            delete *node;
        mNodes.clear();
        mNodeLock.writeUnlock();

        // Tell the chain to stop processing
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping chain");
        mChain.requestStop();

        // Wait for process thread to finish
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping process thread");
        if(mProcessThread != NULL)
            delete mProcessThread;
        mProcessThread = NULL;

        // Wait for manager to finish
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping manager thread");
        if(mManagerThread != NULL)
            delete mManagerThread;
        mManagerThread = NULL;

        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Saving data");
        saveStatistics();
        mChain.save();
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
        unsigned int blocksRequestedCount = 0;
        mNodeLock.readLock();
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
        {
            blocksRequestedCount += (*node)->blocksRequestedCount();
            if((*node)->waitingForRequests())
                downloading++;
        }
        mNodeLock.readUnlock();

        collectStatistics();

        unsigned int pendingBlocks = mChain.pendingBlockCount();
        unsigned int pendingCount = mChain.pendingCount();
        unsigned int pendingSize = mChain.pendingSize();

        ArcMist::String statStartTime;
        statStartTime.writeFormattedTime(mStatistics.startTime);

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Block Chain : %d blocks, %d TXOs", mChain.blockHeight(), mChain.outputCount());
        if(pendingSize > mInfo.pendingSizeThreshold || pendingBlocks > mInfo.pendingBlocksThreshold)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Pending (above threshold) : %d/%d blocks/headers (%d bytes) (%d requested)", pendingBlocks,
              pendingCount - pendingBlocks, pendingSize, blocksRequestedCount);
        else
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Pending : %d/%d blocks/headers (%d bytes) (%d requested)", pendingBlocks, pendingCount - pendingBlocks,
              pendingSize, blocksRequestedCount);
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Nodes : %d/%d outgoing/incoming (%d downloading)", mOutgoingNodes, mIncomingNodes, downloading);
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Network : %d/%d bytes received/sent (since %s)", mStatistics.bytesReceived, mStatistics.bytesSent,
          statStartTime.text());
    }

    void Daemon::sendRequests()
    {
        unsigned int pendingCount = mChain.pendingCount();
        unsigned int pendingBlockCount = mChain.pendingBlockCount();
        unsigned int pendingSize = mChain.pendingSize();
        bool reduceOnly = pendingSize >= mInfo.pendingSizeThreshold || pendingBlockCount >= mInfo.pendingBlocksThreshold;
        unsigned int availableToRequestBlocks = 0;
        unsigned int blocksRequestedCount = 0;

        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        std::random_shuffle(nodes.begin(), nodes.end()); // Sort Randomly
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
        {
            if((*node)->isIncoming() || !(*node)->isReady())
                continue;

            blocksRequestedCount += (*node)->blocksRequestedCount();

            if((*node)->waitingForRequests())
                continue;

            if(!mChain.isInSync() && getTime() - mLastHeaderRequestTime > 60 &&
              pendingCount < mInfo.pendingBlocksThreshold * 4 &&
              (*node)->requestHeaders(mChain, mChain.lastPendingBlockHash()))
                mLastHeaderRequestTime = getTime();
            else
                ++availableToRequestBlocks;
        }

        // Request blocks
        if(availableToRequestBlocks == 0)
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              "No nodes available for block requests");

        if(pendingCount > pendingBlockCount && availableToRequestBlocks > 0)
        {
            int blocksToRequest;
            if(reduceOnly)
                blocksToRequest = mChain.highestFullPendingHeight() - mChain.blockHeight() - pendingBlockCount;
            else
                blocksToRequest = mInfo.pendingBlocksThreshold + MAX_BLOCK_REQUEST - pendingBlockCount - blocksRequestedCount;
            for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end()&&blocksToRequest>0;++node)
                if((*node)->requestBlocks(mChain, MAX_BLOCK_REQUEST, reduceOnly))
                    blocksToRequest -= MAX_BLOCK_REQUEST;
        }

        mNodeLock.readUnlock();
    }

    void Daemon::sendPeerRequest()
    {
        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        std::random_shuffle(nodes.begin(), nodes.end()); // Sort Randomly
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
            if(!(*node)->isIncoming() && (*node)->requestPeers())
                break;
        mNodeLock.readUnlock();
    }

    void Daemon::improvePing(int pDropFactor)
    {
        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes

        // Remove incoming and seed nodes
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();)
            if(!(*node)->isReady() || (*node)->isIncoming() || (*node)->isSeed())
                node = nodes.erase(node);
            else
                ++node;

        // Sort slowest ping to fastest ping
        Node *highestNode;
        std::vector<Node *> sortedNodes;
        while(nodes.size() > 0)
        {
            highestNode = NULL;
            for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
                if(highestNode == NULL || highestNode->pingTime() < (*node)->pingTime())
                    highestNode = *node;

            sortedNodes.push_back(highestNode);

            // Remove highestNode
            for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
                if(*node == highestNode)
                {
                    nodes.erase(node);
                    break;
                }
        }

        // Drop slowest
        int dropCount = sortedNodes.size() / pDropFactor;
        for(std::vector<Node *>::iterator node=sortedNodes.begin();node!=sortedNodes.end();++node)
        {
            if(dropCount-- > 0)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s - %ds ping (dropping)", (*node)->name(), (*node)->pingTime());
                (*node)->close();
            }
            else
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s - %ds ping", (*node)->name(), (*node)->pingTime());
        }

        mNodeLock.readUnlock();
    }

    void Daemon::manage()
    {
        Daemon &daemon = Daemon::instance();
        uint32_t startTime = getTime();
        uint32_t lastStatReportTime = startTime;
        uint32_t lastRequestCheckTime = startTime;
        uint32_t lastInfoSaveTime = startTime;
        uint32_t lastPeerRequestTime = 0;
        uint32_t lastPingImprovement = startTime;
        uint32_t time;

        while(!daemon.mStopping)
        {
            time = getTime();
            if(getTime() - lastStatReportTime > 60)
            {
                lastStatReportTime = getTime();
                daemon.printStatistics();
            }

            if(daemon.mStopping)
                break;

            time = getTime();
            if(time - lastRequestCheckTime > 10)
            {
                lastRequestCheckTime = time;
                daemon.sendRequests();
            }

            if(daemon.mStopping)
                break;

            time = getTime();
            if(time - lastInfoSaveTime > 600)
            {
                lastInfoSaveTime = time;
                daemon.mInfo.save();
            }

            if(daemon.mStopping)
                break;

            time = getTime();
            if(time - daemon.mStatistics.startTime > 3600)
                daemon.saveStatistics();

            if(daemon.mStopping)
                break;

            time = getTime();
            if(daemon.mLastPeerCount < 1000 && time - lastPeerRequestTime > 60)
            {
                lastPeerRequestTime = time;
                daemon.sendPeerRequest();
            }

            if(daemon.mStopping)
                break;

            // Every 5 minutes for the first hour, then hourly after that
            time = getTime();
            if(time - startTime < 3600 && time - lastPingImprovement > 300)
            {
                lastPingImprovement = time;
                daemon.improvePing(2);
            }
            else if(time - lastPingImprovement > 3600)
            {
                lastPingImprovement = time;
                daemon.improvePing(4);
            }

            if(daemon.mStopping)
                break;

            ArcMist::Thread::sleep(500);
        }
    }

    void Daemon::process()
    {
        Daemon &daemon = Daemon::instance();
        uint32_t lastOutputsSaveTime = getTime();

        while(!daemon.mStopping)
        {
            daemon.mChain.process();

            if(daemon.mStopping)
                break;

            if(getTime() - lastOutputsSaveTime > 1200)
            {
                lastOutputsSaveTime = getTime();
                daemon.mChain.saveOutputs();
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
        {
            ++mStatistics.incomingConnections;
            ++mIncomingNodes;
        }
        else
        {
            ++mStatistics.outgoingConnections;
            ++mOutgoingNodes;
        }
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
                result++;
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
        mInfo.randomizePeers(peers, 2);
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
                count++;

            if(mStopping || count >= pCount / 2) // Limit good to half
                break;
        }

        peers.clear();
        mInfo.randomizePeers(peers, 0);
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Found %d peers", peers.size());
        mLastPeerCount = peers.size();
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
                count++;

            if(mStopping || count >= pCount)
                break;
        }

        return count;
    }

    void Daemon::cleanNodes()
    {
        mNodeLock.readLock();
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
            (*node)->check(mChain);
        mNodeLock.readUnlock();

        // Drop all closed nodes
        std::vector<Node *> toDelete;
        mNodeLock.writeLock("Clean Nodes");
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();)
            if(!(*node)->isOpen())
            {
                --mNodeCount;
                if((*node)->isIncoming())
                    --mIncomingNodes;
                else
                    --mOutgoingNodes;
                toDelete.push_back(*node);
                node = mNodes.erase(node);
            }
            else
                ++node;
        mNodeLock.writeUnlock();

        for(std::vector<Node *>::iterator node=toDelete.begin();node!=toDelete.end();++node)
        {
            (*node)->collectStatistics(mStatistics);
            delete *node;
        }
    }

    void Daemon::handleConnections()
    {
        Daemon &daemon = Daemon::instance();
        ArcMist::Network::Listener *listener = NULL;
        ArcMist::Network::Connection *newConnection;
        unsigned int maxOutgoing, maxIncoming;
        uint32_t lastFillNodesTime = 0;
        uint32_t lastCleanTime = getTime();

        while(!daemon.mStopping)
        {
            if(daemon.mChain.isInSync())
                maxOutgoing = 8;
            else
                maxOutgoing = daemon.mInfo.maxConnections / 2;
            if(maxOutgoing > daemon.mInfo.pendingBlocksThreshold / MAX_BLOCK_REQUEST)
                maxOutgoing = daemon.mInfo.pendingBlocksThreshold / MAX_BLOCK_REQUEST;
            maxIncoming = daemon.mInfo.maxConnections - maxOutgoing;

            if(getTime() - lastCleanTime > 10)
            {
                lastCleanTime = getTime();
                daemon.cleanNodes();
            }

            if(listener == NULL)
            {
                if(daemon.mIncomingNodes < maxIncoming)
                {
                    listener = new ArcMist::Network::Listener(AF_INET6, networkPort(), 5, 1);
                    if(listener->isValid())
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                          "Started listening for connections on port %d", listener->port());
                    }
                    else
                    {
                        ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create listener");
                        daemon.requestStop();
                        break;
                    }
                }
            }
            else
            {
                while(!daemon.mStopping && (newConnection = listener->accept()) != NULL)
                {
                    daemon.addNode(newConnection, true);

                    if(daemon.mIncomingNodes >= maxIncoming)
                    {
                        delete listener;
                        listener = NULL;
                        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                          "Stopped listening for incoming connections because of connection limit");
                        break;
                    }
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

            if(daemon.mOutgoingNodes < maxOutgoing && getTime() - lastFillNodesTime > 60)
            {
                daemon.pickNodes(maxOutgoing - daemon.mOutgoingNodes);
                lastFillNodesTime = getTime();
            }

            if(daemon.mStopping)
                break;

            ArcMist::Thread::sleep(500);
        }

        if(listener != NULL)
            delete listener;
    }
}
