/**************************************************************************
 * Copyright 2017-2018 ArcMist, LLC                                       *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "daemon.hpp"

#ifdef PROFILER_ON
#include "arcmist/dev/profiler.hpp"
#endif

#include "arcmist/base/log.hpp"
#include "arcmist/io/network.hpp"
#include "info.hpp"
#include "block.hpp"
#include "block.hpp"
#include "chain.hpp"

#include <csignal>
#include <algorithm>

#define BITCOIN_DAEMON_LOG_NAME "Daemon"


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

    Daemon::Daemon() : mInfo(Info::instance()), mNodeLock("Nodes"), mRequestsLock("Requests")
    {
        mRunning = false;
        mStopping = false;
        mStopRequested = false;
        mLoaded = false;
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
          "Starting %s on %s in %s", BITCOIN_USER_AGENT, networkName(), Info::instance().path().text());

        mManagerThread = new ArcMist::Thread("Manager", manage);
        if(mManagerThread == NULL)
        {
            requestStop();
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create manage thread");
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

        // Stop nodes
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

        // Stop request channels
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping request channels");
        mRequestsLock.readLock();
        for(std::vector<RequestChannel *>::iterator requestChannel=mRequestChannels.begin();requestChannel!=mRequestChannels.end();++requestChannel)
            (*requestChannel)->requestStop();
        mRequestsLock.readUnlock();

        // Delete request channels
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Deleting request channels");
        mRequestsLock.writeLock("Destroy");
        for(std::vector<RequestChannel *>::iterator requestChannel=mRequestChannels.begin();requestChannel!=mRequestChannels.end();++requestChannel)
            delete *requestChannel;
        mRequestChannels.clear();
        mRequestsLock.writeUnlock();

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

#ifdef PROFILER_ON
        ArcMist::String profilerTime;
        profilerTime.writeFormattedTime(getTime(), "%Y%m%d.%H%M");
        ArcMist::String profilerFileName = "profiler.";
        profilerFileName += profilerTime;
        profilerFileName += ".txt";
        ArcMist::FileOutputStream profilerFile(profilerFileName, true);
        ArcMist::ProfilerManager::write(&profilerFile);
#endif

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
        unsigned int blocksRequestedCount = 0;
        if(!mChain.isInSync())
        {
            mNodeLock.readLock();
            for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
            {
                blocksRequestedCount += (*node)->blocksRequestedCount();
            }
            mNodeLock.readUnlock();
        }

        collectStatistics();

        ArcMist::String timeText;

        timeText.writeFormattedTime(mChain.blockStats().time(mChain.height()));
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Block Chain : %d blocks (last %s)", mChain.height(), timeText.text());
        const Branch *branch;
        for(unsigned int i=0;i<mChain.branchCount();++i)
        {
            branch = mChain.branchAt(i);
            if(branch == NULL)
                break;

            if(branch->pendingBlocks.size() > 0)
                timeText.writeFormattedTime(branch->pendingBlocks.back()->block->time);

            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Block Chain Branch %d : %d blocks (last %s)", i + 1, branch->height + branch->pendingBlocks.size() - 1, timeText.text());
        }
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Outputs : %d trans (%d KiB cached)", mChain.outputs().size(),
          mChain.outputs().cacheDataSize() / 1024);
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Mem Pool : %d/%d trans/pending (%d KiB)", mChain.memPool().count(),
          mChain.memPool().pendingCount(), mChain.memPool().size() / 1024);
        if(!mChain.isInSync())
        {
            unsigned int pendingBlocks = mChain.pendingBlockCount();
            unsigned int pendingCount = mChain.pendingCount();
            unsigned int pendingSize = mChain.pendingSize();
            if(pendingSize > mInfo.pendingSizeThreshold || pendingBlocks > mInfo.pendingBlocksThreshold)
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Pending (above threshold) : %d/%d blocks/headers (%d KiB) (%d requested)", pendingBlocks,
                  pendingCount - pendingBlocks, pendingSize / 1024, blocksRequestedCount);
            else
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Pending : %d/%d blocks/headers (%d KiB) (%d requested)", pendingBlocks, pendingCount - pendingBlocks,
                  pendingSize / 1024, blocksRequestedCount);
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Nodes : %d/%d outgoing/incoming", mOutgoingNodes, mIncomingNodes);

        timeText.writeFormattedTime(mStatistics.startTime);
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Network : %d/%d KiB received/sent (since %s)", mStatistics.bytesReceived / 1024, mStatistics.bytesSent / 1024,
          timeText.text());
    }

    void sortOutgoingNodesByPing(std::vector<Node *> &pNodes)
    {
        std::vector<Node *> nodes = pNodes;
        pNodes.clear();

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

            pNodes.push_back(highestNode);

            // Remove highestNode
            for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
                if(*node == highestNode)
                {
                    nodes.erase(node);
                    break;
                }
        }
    }

    bool higherSpeedThan(Node *pLeft, Node *pRight)
    {
        if(pLeft->blockDownloadBytesPerSecond() == 0.0 && pRight->blockDownloadBytesPerSecond() == 0.0)
            return pLeft->pingTime() < pRight->pingTime();

        if(pLeft->blockDownloadBytesPerSecond() == 0.0)
            return false;
        if(pRight->blockDownloadBytesPerSecond() == 0.0)
            return true;
        return pLeft->blockDownloadBytesPerSecond() > pRight->blockDownloadBytesPerSecond();
    }

    void sortOutgoingNodesBySpeed(std::vector<Node *> &pNodes)
    {
        std::vector<Node *> nodes = pNodes;
        pNodes.clear();

        // Remove incoming and seed nodes
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();)
            if(!(*node)->isReady() || (*node)->isIncoming() || (*node)->isSeed())
                node = nodes.erase(node);
            else
                ++node;

        // Sort highest speed first
        Node *highestNode;
        std::vector<Node *> sortedNodes;
        while(nodes.size() > 0)
        {
            highestNode = NULL;
            for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
                if(highestNode == NULL || higherSpeedThan(*node, highestNode))
                    highestNode = *node;

            pNodes.push_back(highestNode);

            // Remove highestNode
            for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
                if(*node == highestNode)
                {
                    nodes.erase(node);
                    break;
                }
        }
    }

    class NodeRequests
    {
    public:
        Node *node;
        ArcMist::HashList list;
    };

    void Daemon::sendRequests()
    {
        unsigned int pendingCount = mChain.pendingCount();

        if(!mChain.isInSync() && getTime() - mLastHeaderRequestTime > 60 &&
          pendingCount < mInfo.pendingBlocksThreshold * 8)
            sendHeaderRequest();

        unsigned int pendingBlockCount = mChain.pendingBlockCount();
        unsigned int pendingSize = mChain.pendingSize();
        bool reduceOnly = pendingSize >= mInfo.pendingSizeThreshold || pendingBlockCount >= mInfo.pendingBlocksThreshold;
        unsigned int blocksRequestedCount = 0;

        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        std::vector<Node *> requestNodes;
        sortOutgoingNodesBySpeed(nodes);

        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
        {
            blocksRequestedCount += (*node)->blocksRequestedCount();
            if(!(*node)->waitingForRequests())
                requestNodes.push_back(*node);
        }

        // Request blocks
        if(requestNodes.size() == 0)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              "No nodes available for block requests");
            mNodeLock.readUnlock();
            return;
        }

        int blocksToRequestCount;
        // Don't make large block set requests without large enough request node counts
        //   Otherwise the block staggering can be very low and slow down the download stream
        if(reduceOnly || requestNodes.size() < 4)
            blocksToRequestCount = requestNodes.size();
        else
        {
            blocksToRequestCount = mInfo.pendingBlocksThreshold - pendingBlockCount - blocksRequestedCount;
            if(blocksToRequestCount > (int)requestNodes.size() * MAX_BLOCK_REQUEST)
                blocksToRequestCount = (int)requestNodes.size() * MAX_BLOCK_REQUEST;
        }
        if(blocksToRequestCount <= 0)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              "No blocks need requested");
            mNodeLock.readUnlock();
            return;
        }

        ArcMist::HashList blocksToRequest;
        mChain.getBlocksNeeded(blocksToRequest, blocksToRequestCount, reduceOnly);

        if(blocksToRequest.size() == 0)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              "No blocks to request");
            mNodeLock.readUnlock();
            return;
        }

        // Divided these up (staggered) between available nodes
        NodeRequests *nodeRequests = new NodeRequests[requestNodes.size()];
        NodeRequests *nodeRequest = nodeRequests;
        unsigned int i;

        // Assign nodes
        nodeRequest = nodeRequests;
        for(std::vector<Node *>::iterator node=requestNodes.begin();node!=requestNodes.end();++node)
        {
            nodeRequest->node = *node;
            ++nodeRequest;
        }

        // Stagger out block requests
        unsigned int requestNodeOffset = 0;
        for(ArcMist::HashList::iterator hash=blocksToRequest.begin();hash!=blocksToRequest.end();++hash)
        {
            nodeRequests[requestNodeOffset].list.push_back(*hash);
            if(++requestNodeOffset >= requestNodes.size())
                requestNodeOffset = 0;
        }

        // Send requests to nodes
        nodeRequest = nodeRequests;
        for(i=0;i<requestNodes.size();++i)
        {
            nodeRequest->node->requestBlocks(nodeRequest->list);
            ++nodeRequest;
        }

        delete[] nodeRequests;
        mNodeLock.readUnlock();
    }

    void randomizeOutgoing(std::vector<Node *> &pNodeList)
    {
        for(std::vector<Node *>::iterator node=pNodeList.begin();node!=pNodeList.end();)
            if((*node)->isIncoming() || !(*node)->isReady() || (*node)->waitingForRequests())
                node = pNodeList.erase(node);
            else
                ++node;
        std::random_shuffle(pNodeList.begin(), pNodeList.end()); // Sort Randomly
    }

    void Daemon::sendTransactionRequests()
    {
        ArcMist::HashList transactionsToRequest;

        mChain.memPool().getNeeded(transactionsToRequest);

        if(transactionsToRequest.size() == 0)
            return;

        mNodeLock.readLock();

        if(mNodes.size() == 0)
        {
            mNodeLock.readUnlock();
            return;
        }

        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        randomizeOutgoing(nodes);

        NodeRequests *nodeRequests = new NodeRequests[nodes.size()];
        NodeRequests *nodeRequest = nodeRequests;
        unsigned int i;

        // Assign nodes
        nodeRequest = nodeRequests;
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
        {
            nodeRequest->node = *node;
            ++nodeRequest;
        }

        // Try to find nodes that have the transactions
        bool found;
        for(ArcMist::HashList::iterator hash=transactionsToRequest.begin();hash!=transactionsToRequest.end();++hash)
        {
            found = false;
            nodeRequest = nodeRequests;
            for(i=0;i<nodes.size();++i)
            {
                if(nodeRequest->node->hasTransaction(*hash))
                {
                    nodeRequest->list.push_back(*hash);
                    found = true;
                }
                ++nodeRequest;
            }

            if(!found) // Add to first node
                nodeRequests->list.push_back(*hash);
        }

        // Send requests to nodes
        nodeRequest = nodeRequests;
        for(i=0;i<nodes.size();++i)
        {
            nodeRequest->node->requestTransactions(nodeRequest->list);
            ++nodeRequest;
        }

        delete[] nodeRequests;
        mNodeLock.readUnlock();
    }

    void Daemon::sendHeaderRequest()
    {
        if(getTime() - mLastHeaderRequestTime < 20)
            return;

        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        randomizeOutgoing(nodes);
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
            if((*node)->requestHeaders())
            {
                mLastHeaderRequestTime = getTime();
                break;
            }
        mNodeLock.readUnlock();
    }

    void Daemon::sendPeerRequest()
    {
        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        randomizeOutgoing(nodes);
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
            if((*node)->requestPeers())
                break;
        mNodeLock.readUnlock();
    }

    void Daemon::improvePing()
    {
        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        sortOutgoingNodesByPing(nodes);

        if(nodes.size() < MAX_OUTGOING_CONNECTION_COUNT / 2)
        {
            mNodeLock.readUnlock();
            return;
        }

        // Calculate average
        double average = 0.0;
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
            average += (double)(*node)->pingTime();
        average /= (double)nodes.size();

        // Calculate variance
        double variance = 0.0;
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
            // Sum the squared difference from the mean
            variance += ArcMist::Math::square((double)(*node)->pingTime() - average);
        // Average the sum
        variance /= (double)nodes.size();

        // Square root to get standard deviation
        double standardDeviation = ArcMist::Math::squareRoot(variance);

        uint32_t cutoff;
        if(average > 60)
            cutoff = (int)(average + (standardDeviation * 0.5));
        else
            cutoff = (int)(average + standardDeviation);
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Node ping : average %ds, cutoff %ds", (int)average, cutoff);

        // Regularly drop some nodes to increase diversity
        int churnDrop = 0;
        if(nodes.size() == MAX_OUTGOING_CONNECTION_COUNT)
            churnDrop = nodes.size() / 8;

        // Drop slowest
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
        {
            if((*node)->blockDownloadBytesPerSecond() > cutoff)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s - %d KiB/s, %ds ping (dropping because of ping)", (*node)->name(),
                  (int)(*node)->blockDownloadBytesPerSecond() / 1024, (*node)->pingTime());
                (*node)->close();
            }
            else if(churnDrop > 0)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s - %d KiB/s, %ds ping (dropping for churn)", (*node)->name(),
                  (int)(*node)->blockDownloadBytesPerSecond() / 1024, (*node)->pingTime());
                (*node)->close();
            }
            else
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s - %d KiB/s, %ds ping", (*node)->name(),
                  (int)(*node)->blockDownloadBytesPerSecond() / 1024, (*node)->pingTime());
            --churnDrop;
        }

        mNodeLock.readUnlock();
    }

    void Daemon::improveSpeed()
    {
        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes

        if(nodes.size() < MAX_OUTGOING_CONNECTION_COUNT / 2)
        {
            mNodeLock.readUnlock();
            return;
        }

        // Remove nodes that aren't outgoing or aren't ready
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();)
            if((*node)->isIncoming() || (*node)->isSeed() || !(*node)->isReady())
                node = nodes.erase(node);
            else
                ++node;

        if(nodes.size() < MAX_OUTGOING_CONNECTION_COUNT / 2)
        {
            mNodeLock.readUnlock();
            return;
        }

        // Calculate average
        double averageSpeed = 0.0;
        double averagePing = 0.0;
        int nodesWithSpeed = 0;
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
        {
            if((*node)->blockDownloadBytesPerSecond() != 0.0)
            {
                averageSpeed += (*node)->blockDownloadBytesPerSecond();
                ++nodesWithSpeed;
            }
            averagePing += (double)(*node)->pingTime();
        }
        if(nodesWithSpeed > 0)
            averageSpeed /= (double)nodesWithSpeed;
        averagePing /= (double)nodes.size();

        // Calculate variance
        double speedVariance = 0.0;
        double pingVariance = 0.0;
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
        {
            // Sum the squared difference from the mean
            if((*node)->blockDownloadBytesPerSecond() != 0.0)
                speedVariance += ArcMist::Math::square((*node)->blockDownloadBytesPerSecond() - averageSpeed);
            pingVariance += ArcMist::Math::square((double)(*node)->pingTime() - averagePing);
        }

        // Average the sum
        speedVariance /= (double)nodesWithSpeed;
        pingVariance /= (double)nodes.size();

        // Square root to get standard deviation
        double speedStandardDeviation = ArcMist::Math::squareRoot(speedVariance);
        double pingStandardDeviation = ArcMist::Math::squareRoot(pingVariance);

        // Score based on deviation from average of ping and speed
        std::vector<double> scores;
        double score;
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
        {
            if((*node)->blockDownloadBytesPerSecond() != 0.0 && speedStandardDeviation > 0.01)
                score = ((*node)->blockDownloadBytesPerSecond() - averageSpeed) / speedStandardDeviation;
            else
                score = 0.0;
            if(pingStandardDeviation > 0.01)
                score += ((averagePing - (*node)->pingTime()) / pingStandardDeviation) / 2.0;
            scores.push_back(score);
        }

        // Calculate average score
        double averageScore = 0.0;
        std::vector<double>::iterator nodeScore;
        for(nodeScore=scores.begin();nodeScore!=scores.end();++nodeScore)
            averageScore += *nodeScore;
        averageScore /= (double)scores.size();

        // Calculate score variance
        double scoreVariance = 0.0;
        for(nodeScore=scores.begin();nodeScore!=scores.end();++nodeScore)
            scoreVariance += ArcMist::Math::square(*nodeScore - averageScore);
        scoreVariance /= (double)scores.size();

        // Square root to get standard deviation
        double scoreStandardDeviation = ArcMist::Math::squareRoot(scoreVariance);

        // Sort by score
        std::vector<Node *> sortedNodes;
        std::vector<double> sortedScores;
        Node *lowestNode;
        double lowestScore;
        while(nodes.size() > 0)
        {
            lowestNode = NULL;
            nodeScore = scores.begin();
            for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
            {
                if(lowestNode == NULL || *nodeScore < lowestScore)
                {
                    lowestNode = *node;
                    lowestScore = *nodeScore;
                }
                ++nodeScore;
            }

            sortedNodes.push_back(lowestNode);
            sortedScores.push_back(lowestScore);

            // Remove highest
            nodeScore = scores.begin();
            for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
            {
                if(*node == lowestNode)
                {
                    nodes.erase(node);
                    scores.erase(nodeScore);
                    break;
                }
                ++nodeScore;
            }
        }

        double dropScore = averageScore - (scoreStandardDeviation * 1.25);
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Node Performance Summary : average speed %d KiB/s, average ping %ds, drop score %d",
          (int)averageSpeed / 1024, (int)averagePing, (int)(100.0 * dropScore));

        // Always drop some nodes so nodes with lower pings can still be found
        int churnDrop = 0;
        if(sortedScores.size() == MAX_OUTGOING_CONNECTION_COUNT)
            churnDrop = sortedScores.size() / 8;

        // Drop slowest
        nodeScore = sortedScores.begin();
        for(std::vector<Node *>::iterator node=sortedNodes.begin();node!=sortedNodes.end();++node)
        {
            if(*nodeScore < dropScore)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s (score %d) - %d KiB/s, %ds ping (dropping because of score)", (*node)->name(),
                  (int)(100.0 * *nodeScore), (int)(*node)->blockDownloadBytesPerSecond() / 1024, (*node)->pingTime());
                (*node)->close();
            }
            else if(churnDrop > 0)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s (score %d) - %d KiB/s, %ds ping (dropping for churn)", (*node)->name(),
                  (int)(100.0 * *nodeScore), (int)(*node)->blockDownloadBytesPerSecond() / 1024, (*node)->pingTime());
                (*node)->close();
            }
            else
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s (score %d) - %d KiB/s, %ds ping", (*node)->name(),
                  (int)(100.0 * *nodeScore), (int)(*node)->blockDownloadBytesPerSecond() / 1024, (*node)->pingTime());

            --churnDrop;
            ++nodeScore;
        }

        mNodeLock.readUnlock();
    }

    void Daemon::announce()
    {
        Block *block = mChain.blockToAnnounce();
        if(block != NULL)
        {
            // Announce to all nodes
            mNodeLock.readLock();
            for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
                (*node)->announceBlock(block);
            mNodeLock.readUnlock();
            delete block;
        }

        ArcMist::HashList transactionList;
        Transaction *transaction;
        mChain.memPool().getToAnnounce(transactionList);
        if(transactionList.size() > 0)
        {
            mNodeLock.readLock();
            for(ArcMist::HashList::iterator hash=transactionList.begin();hash!=transactionList.end();++hash)
            {
                transaction = mChain.memPool().get(*hash);
                if(transaction != NULL)
                {
                    // Announce to all nodes
                    for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
                        (*node)->announceTransaction(transaction);
                }
            }
            mNodeLock.readUnlock();
        }
    }

    void Daemon::manage()
    {
        Daemon &daemon = Daemon::instance();

        if(!daemon.mChain.load())
        {
            if(daemon.mStopRequested || daemon.mStopping)
                return;
            daemon.requestStop();
            return;
        }

        daemon.mLoaded = true;

        if(daemon.mStopping)
            return;

        daemon.mConnectionThread = new ArcMist::Thread("Connection", handleConnections);
        if(daemon.mConnectionThread == NULL)
        {
            daemon.requestStop();
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create connection thread");
            return;
        }

        if(daemon.mStopping)
            return;

        daemon.mProcessThread = new ArcMist::Thread("Process", process);
        if(daemon.mProcessThread == NULL)
        {
            daemon.requestStop();
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create process thread");
            return;
        }

        uint32_t startTime = getTime();
        uint32_t lastStatReportTime = startTime;
        uint32_t lastRequestCheckTime = startTime;
        uint32_t lastInfoSaveTime = startTime;
        uint32_t lastPeerRequestTime = 0;
        uint32_t lastImprovement = startTime;
        uint32_t lastTransactionRequest = startTime;
        uint32_t time;
#ifdef PROFILER_ON
        uint32_t lastProfilerWrite = startTime;
        ArcMist::String profilerTime;
        ArcMist::String profilerFileName;
        ArcMist::FileOutputStream *profilerFile;
#endif

        while(!daemon.mStopping)
        {
            time = getTime();
            if(getTime() - lastStatReportTime > 180)
            {
                lastStatReportTime = getTime();
                daemon.printStatistics();
            }

            if(daemon.mStopping)
                break;

            if(!daemon.mChain.isInSync())
            {
                // Wait 30 seconds so hopefully a bunch of nodes are ready to request at the same time to improve staggering
                time = getTime();
                if(time - lastRequestCheckTime > 30 ||
                  (daemon.mChain.pendingBlockCount() == 0 && time - lastRequestCheckTime > 10))
                {
                    lastRequestCheckTime = time;
                    daemon.sendRequests();
                }

                if(daemon.mStopping)
                    break;
            }
            else
            {
                if(daemon.mChain.headersNeeded())
                    daemon.sendHeaderRequest();
                if(daemon.mChain.blocksNeeded())
                    daemon.sendRequests();
                time = getTime();
                if(time - lastTransactionRequest > 20)
                {
                    lastTransactionRequest = time;
                    daemon.sendTransactionRequests();
                }
            }

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
            if(daemon.mLastPeerCount > 0 && daemon.mLastPeerCount < 2000 && time - lastPeerRequestTime > 60)
            {
                lastPeerRequestTime = time;
                daemon.sendPeerRequest();
            }

            if(daemon.mStopping)
                break;

            time = getTime();
            if(time - lastImprovement > 300) // Every 5 minutes
            {
                lastImprovement = time;
                daemon.improveSpeed();
            }

            if(daemon.mStopping)
                break;

#ifdef PROFILER_ON
            time = getTime();
            if(time - lastProfilerWrite > 3600)
            {
                profilerTime.writeFormattedTime(time, "%Y%m%d.%H%M");
                profilerFileName.writeFormatted("profiler.%s.txt", profilerTime.text());
                profilerFile = new ArcMist::FileOutputStream(profilerFileName, true);
                ArcMist::ProfilerManager::write(profilerFile);
                delete profilerFile;
                ArcMist::ProfilerManager::reset();
                lastProfilerWrite = time;
            }
#endif

            ArcMist::Thread::sleep(2000);
        }
    }

    void Daemon::process()
    {
        Daemon &daemon = Daemon::instance();
        uint32_t lastOutputsPurgeTime = getTime();
        uint32_t lastAddressPurgeTime = getTime();
        uint32_t lastMemPoolCheckPending = getTime();

        while(!daemon.mStopping)
        {
            daemon.mChain.process();

            if(daemon.mStopping)
                break;

            if(daemon.mChain.isInSync())
                daemon.announce();

            if(daemon.mStopping)
                break;

            if(getTime() - lastMemPoolCheckPending > 20)
            {
                daemon.mChain.memPool().checkPendingTransactions(daemon.mChain.outputs(),
                  daemon.mChain.blockStats(), daemon.mChain.forks(), daemon.mInfo.minFee);
                lastMemPoolCheckPending = getTime();
            }

            if(daemon.mStopping)
                break;

            daemon.mChain.memPool().process(daemon.mInfo.memPoolThreshold);

            if(daemon.mStopping)
                break;

            if((getTime() - lastOutputsPurgeTime > 30 && daemon.mChain.outputs().needsPurge()) ||
              getTime() - lastOutputsPurgeTime > 3600)
            {
                if(!daemon.mChain.outputs().save())
                    daemon.requestStop();
                lastOutputsPurgeTime = getTime();
            }

            if(daemon.mStopping)
                break;

            if((getTime() - lastAddressPurgeTime > 30 && daemon.mChain.addresses().needsPurge()) ||
              getTime() - lastAddressPurgeTime > 3600)
            {
                if(!daemon.mChain.addresses().save())
                    daemon.requestStop();
                lastAddressPurgeTime = getTime();
            }

            if(daemon.mStopping)
                break;

            ArcMist::Thread::sleep(100);
        }
    }

    void Daemon::addRejectedIP(const uint8_t *pIP)
    {
        IPBytes ip = pIP;
        mRejectedIPs.push_back(ip);

        while(mRejectedIPs.size() > 1000)
            mRejectedIPs.erase(mRejectedIPs.begin());
    }

    bool Daemon::addNode(ArcMist::Network::Connection *pConnection, bool pIncoming, bool pIsSeed)
    {
        // Check if IP is on reject list
        for(std::vector<IPBytes>::iterator ip=mRejectedIPs.begin();ip!=mRejectedIPs.end();++ip)
            if(*ip == pConnection->ipv6Bytes())
            {
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_DAEMON_LOG_NAME,
                  "Rejecting connection from IP %s", pConnection->ipv6Address());
                delete pConnection;
                return false;
            }

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

        mNodeLock.writeLock("Add");
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

    unsigned int Daemon::recruitPeers(unsigned int pCount)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Recruiting %d peers", pCount);
        std::vector<Peer *> peers;
        unsigned int count = 0;
        bool found;
        uint64_t servicesMask = Message::VersionData::FULL_NODE_BIT;

        if(mChain.forks().cashActive())
            servicesMask |= Message::VersionData::CASH_NODE_BIT;

        // Try peers with good ratings first
        mInfo.getRandomizedPeers(peers, 5, servicesMask);
        ArcMist::Network::Connection *connection;
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
          "Found %d good peers", peers.size());
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
        mInfo.getRandomizedPeers(peers, -5, servicesMask);
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
          "Found %d usable peers", peers.size());
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
        // Check for black listed nodes
        std::vector<unsigned int> blackListedNodeIDs = mChain.blackListedNodeIDs();

        // Drop all closed nodes
        std::vector<Node *> toDelete;
        bool dropped;
        mNodeLock.writeLock("Clean");
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();)
            if(!(*node)->isOpen())
            {
                if((*node)->wasRejected())
                    addRejectedIP((*node)->ipv6Bytes());
                --mNodeCount;
                if((*node)->isIncoming())
                    --mIncomingNodes;
                else
                    --mOutgoingNodes;
                toDelete.push_back(*node);
                node = mNodes.erase(node);
            }
            else
            {
                dropped = false;
                for(std::vector<unsigned int>::iterator nodeID=blackListedNodeIDs.begin();nodeID!=blackListedNodeIDs.end();++nodeID)
                    if(*nodeID == (*node)->id())
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                          "%s Dropping. Black listed", (*node)->name());
                        dropped = true;
                        addRejectedIP((*node)->ipv6Bytes());
                        (*node)->close();
                        --mNodeCount;
                        if((*node)->isIncoming())
                            --mIncomingNodes;
                        else
                            --mOutgoingNodes;
                        toDelete.push_back(*node);
                        node = mNodes.erase(node);
                        break;
                    }

                if(!dropped)
                    ++node;
            }
        mNodeLock.writeUnlock();

        for(std::vector<Node *>::iterator node=toDelete.begin();node!=toDelete.end();++node)
        {
            (*node)->collectStatistics(mStatistics);
            delete *node;
        }
    }

    bool Daemon::addRequestChannel(ArcMist::Network::Connection *pConnection)
    {
        mRequestsLock.writeLock("Add");
        mRequestChannels.push_back(new RequestChannel(pConnection, &mChain));
        mRequestsLock.writeUnlock();
        return true;
    }

    void Daemon::cleanRequestChannels()
    {
        // Drop all closed nodes
        std::vector<RequestChannel *> toDelete;
        mRequestsLock.writeLock("Clean");
        for(std::vector<RequestChannel *>::iterator requestChannel=mRequestChannels.begin();requestChannel!=mRequestChannels.end();)
            if((*requestChannel)->isStopped())
            {
                toDelete.push_back(*requestChannel);
                requestChannel = mRequestChannels.erase(requestChannel);
            }
            else
                ++requestChannel;
        mRequestsLock.writeUnlock();

        for(std::vector<RequestChannel *>::iterator requestChannel=toDelete.begin();requestChannel!=toDelete.end();++requestChannel)
            delete *requestChannel;
    }

    void Daemon::handleConnections()
    {
        Daemon &daemon = Daemon::instance();
        ArcMist::Network::Listener *nodeListener = NULL, *requestsListener = NULL;
        ArcMist::Network::Connection *newConnection;
        uint32_t lastFillNodesTime = 0;
        uint32_t lastCleanTime = getTime();

        if(MAX_OUTGOING_CONNECTION_COUNT >= daemon.mInfo.maxConnections)
            daemon.mMaxIncoming = 0;
        else
            daemon.mMaxIncoming = daemon.mInfo.maxConnections - MAX_OUTGOING_CONNECTION_COUNT;

        while(!daemon.mStopping)
        {
            if(daemon.mSeed)
            {
                daemon.querySeed(daemon.mSeed);
                daemon.mSeed.clear();
            }

            if(daemon.mStopping)
                break;

            if(daemon.mOutgoingNodes < MAX_OUTGOING_CONNECTION_COUNT && getTime() - lastFillNodesTime > 30)
            {
                daemon.recruitPeers(MAX_OUTGOING_CONNECTION_COUNT - daemon.mOutgoingNodes);
                lastFillNodesTime = getTime();
            }

            if(daemon.mStopping)
                break;

            if(getTime() - lastCleanTime > 10)
            {
                lastCleanTime = getTime();
                daemon.cleanNodes();
                daemon.cleanRequestChannels();
            }

            if(nodeListener == NULL)
            {
                if(daemon.mIncomingNodes < daemon.mMaxIncoming)
                {
                    nodeListener = new ArcMist::Network::Listener(AF_INET6, networkPort(), 5, 1);
                    if(nodeListener->isValid())
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                          "Started listening for incoming connections on port %d", nodeListener->port());
                    }
                    else
                    {
                        ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create incoming listener");
                        daemon.requestStop();
                        break;
                    }
                }
            }
            else
            {
                while(!daemon.mStopping && (newConnection = nodeListener->accept()) != NULL)
                    if(daemon.addNode(newConnection, true) && daemon.mIncomingNodes >= daemon.mMaxIncoming)
                    {
                        delete nodeListener;
                        nodeListener = NULL;
                        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                          "Stopped listening for incoming connections because of connection limit");
                        break;
                    }
            }

            if(daemon.mStopping)
                break;

            if(requestsListener == NULL)
            {
                if(daemon.mRequestChannels.size() < 8)
                {
                    requestsListener = new ArcMist::Network::Listener(AF_INET6, 8666, 5, 1);
                    if(requestsListener->isValid())
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                          "Started listening for request connections on port %d", requestsListener->port());
                    }
                    else
                    {
                        ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create requests listener");
                        daemon.requestStop();
                        break;
                    }
                }
            }
            else
            {
                while(!daemon.mStopping && (newConnection = requestsListener->accept()) != NULL)
                    if(daemon.addRequestChannel(newConnection) && daemon.mRequestChannels.size() >= 8)
                    {
                        delete requestsListener;
                        requestsListener = NULL;
                        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                          "Stopped listening for request connections because of connection limit");
                        break;
                    }
            }

            if(daemon.mStopping)
                break;

            ArcMist::Thread::sleep(200);
        }

        if(nodeListener != NULL)
            delete nodeListener;

        if(requestsListener != NULL)
            delete requestsListener;
    }
}
