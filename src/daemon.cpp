/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                       *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "daemon.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#endif

#include "log.hpp"
#include "network.hpp"
#include "info.hpp"
#include "block.hpp"
#include "chain.hpp"

#include <csignal>
#include <algorithm>

#define BITCOIN_DAEMON_LOG_NAME "Daemon"


namespace BitCoin
{
    Daemon::Daemon() : mInfo(Info::instance()), mNodeLock("Nodes"), mRequestsLock("Requests")
    {
        mRunning = false;
        mStopping = false;
        mStopRequested = false;
        mLoading = false;
        mLoaded = false;
        mQueryingSeed = false;
#ifndef SINGLE_THREAD
        mConnectionThread = NULL;
        mRequestsThread = NULL;
        mManagerThread = NULL;
        mProcessThread = NULL;
#endif
        previousSigTermChildHandler = NULL;
        previousSigTermHandler= NULL;
        previousSigIntHandler = NULL;
        previousSigPipeHandler = NULL;
        mLastHeaderRequestTime = 0;
        mLastConnectionActive = 0;
        mNodeCount = 0;
        mIncomingNodes = 0;
        mOutgoingNodes = 0;
        mLastPeerCount = 0;
        mLastOutputsPurgeTime = getTime();
        mLastAddressPurgeTime = getTime();
        mLastMemPoolCheckPending = getTime();
        mLastMonitorProcess = getTime();
        mLastFillNodesTime = 0;
        mLastCleanTime = getTime();
        mNodeListener = NULL;
        mLastCleanTime = getTime();
        mRequestsListener = NULL;

        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Creating daemon object");
    }

    Daemon::~Daemon()
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Destroying daemon object");

        if(isRunning() && !mStopping)
            requestStop();

        while(isRunning())
            NextCash::Thread::sleep(100);
    }

    unsigned int Daemon::peerCount()
    {
        mNodeLock.readLock();
        unsigned int result = mNodes.size();
        mNodeLock.readUnlock();
        return result;
    }

    Daemon::Status Daemon::status()
    {
        if(mLoading)
            return LOADING;

        if(!mRunning)
            return INACTIVE;

        if(mQueryingSeed)
            return FINDING_PEERS;

        if(peerCount() < outgoingConnectionCountTarget() / 2)
            return CONNECTING_TO_PEERS;

        if(mChain.isInSync())
        {
            int monitorHeight = mMonitor.height();
            if(monitorHeight > 0 && monitorHeight < mChain.height())
                return FINDING_TRANSACTIONS;
            else
                return SYNCHRONIZED;
        }
        else
            return SYNCHRONIZING;
    }

    static Daemon *sSignalInstance = NULL;

    void Daemon::handleSigTermChild(int pValue)
    {
        //NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Child process terminated");
    }

    void Daemon::handleSigTerm(int pValue)
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Terminate signal received. Stopping.");
        if(sSignalInstance != NULL)
            sSignalInstance->requestStop();
    }

    void Daemon::handleSigInt(int pValue)
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Interrupt signal received. Stopping.");
        if(sSignalInstance != NULL)
            sSignalInstance->requestStop();
    }

    void Daemon::handleSigPipe(int pValue)
    {
        // Happens when writing to a network connection that is closed
        //NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Pipe signal received.");
    }

    bool Daemon::load()
    {
        if(mLoaded || mLoading)
            return true;

        mLoading = true;

        if(!loadKeyStore())
        {
            mLoading = false;
            return false;
        }

        if(!loadMonitor())
        {
            mLoading = false;
            return false;
        }

        if(!mChain.load())
        {
            mLoading = false;
            return false;
        }

        mChain.setMonitor(mMonitor);

        mLoading = false;
        mLoaded = true;
        return true;
    }

    bool Daemon::start(bool pInDaemonMode)
    {
        if(isRunning())
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME, "Already running. Start aborted.");
            return false;
        }

        if(mStopping)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME, "Still stopping. Start aborted.");
            return false;
        }

        mRunning = true;
        mLastConnectionActive = getTime();

        // Set signal handlers
        sSignalInstance = this;
        if(pInDaemonMode)
            previousSigTermHandler = signal(SIGTERM, handleSigTerm);
        previousSigTermChildHandler = signal(SIGCHLD, handleSigTermChild);
        previousSigIntHandler = signal(SIGINT, handleSigInt);
        previousSigPipeHandler = signal(SIGPIPE, handleSigPipe);

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Starting %s on %s in %s", BITCOIN_USER_AGENT, networkName(), Info::instance().path().text());

#ifdef SINGLE_THREAD
        if(mInfo.spvMode)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Running in SPV mode (Single Thread)");
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Running in Full/Bloom mode (Single Thread)");
#else
        if(mInfo.spvMode)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Running in SPV mode (Multi Threaded)");
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Running in Full/Bloom mode (Multi Threaded)");
#endif

#ifndef SINGLE_THREAD
        mManagerThread = new NextCash::Thread("Manager", runManage, this);
        if(mManagerThread == NULL)
        {
            requestStop();
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "Failed to create manage thread");
            return false;
        }
#endif

        return true;
    }

    void Daemon::stop()
    {
        if(!isRunning())
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME, "Not running. Stop aborted.");
            return;
        }

        if(mStopping)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME, "Still stopping. Stop aborted.");
            return;
        }

        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Stopping");
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

#ifndef SINGLE_THREAD
        // Wait for connections to finish
        if(mConnectionThread != NULL)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping connection thread");
            delete mConnectionThread;
            mConnectionThread = NULL;
        }
#endif

        // Stop nodes
        mNodeLock.readLock();
        if(mNodes.size() > 0)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping nodes");
            for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
                (*node)->requestStop();
        }
        mNodeLock.readUnlock();

        // Delete nodes
        mNodeLock.writeLock("Destroy");
        if(mNodes.size() > 0)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Deleting nodes");
            for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
                delete *node;
            mNodes.clear();
            mOutgoingNodes = 0;
            mIncomingNodes = 0;
            mNodeCount = 0;
        }
        mNodeLock.writeUnlock();

        // Stop request channels
        mRequestsLock.readLock();
        if(mRequestChannels.size() > 0)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping request channels");
            for(std::vector<RequestChannel *>::iterator requestChannel=mRequestChannels.begin();requestChannel!=mRequestChannels.end();++requestChannel)
                (*requestChannel)->requestStop();
        }
        mRequestsLock.readUnlock();

        // Delete request channels
        mRequestsLock.writeLock("Destroy");
        if(mRequestChannels.size() > 0)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Deleting request channels");
            for(std::vector<RequestChannel *>::iterator requestChannel=mRequestChannels.begin();requestChannel!=mRequestChannels.end();++requestChannel)
                delete *requestChannel;
            mRequestChannels.clear();
        }
        mRequestsLock.writeUnlock();

#ifndef SINGLE_THREAD
        // Wait for requests to finish
        if(mRequestsThread != NULL)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping requests thread");
            delete mRequestsThread;
            mRequestsThread = NULL;
        }
#endif

        // Tell the chain to stop processing
        NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping chain");
        mChain.requestStop();

#ifndef SINGLE_THREAD
        // Wait for process thread to finish
        if(mProcessThread != NULL)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping process thread");
            delete mProcessThread;
            mProcessThread = NULL;
        }

        // Wait for manager to finish
        if(mManagerThread != NULL)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Stopping manager thread");
            delete mManagerThread;
            mManagerThread = NULL;
        }
#endif

        NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Saving data");
        saveStatistics();
        saveMonitor();
        saveKeyStore();
        mChain.save();
        mChain.clearInSync();

#ifdef PROFILER_ON
        NextCash::String profilerTime;
        profilerTime.writeFormattedTime(getTime(), "%Y%m%d.%H%M");
        NextCash::String profilerFileName = "profiler.";
        profilerFileName += profilerTime;
        profilerFileName += ".txt";
        NextCash::FileOutputStream profilerFile(profilerFileName, true);
        NextCash::ProfilerManager::write(&profilerFile);
#endif

        mRunning = false;
        mStopping = false;
        mStopRequested = false;
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Stopped");
    }

    void Daemon::run(bool pInDaemonMode)
    {
        if(!start(pInDaemonMode))
            return;

#ifdef SINGLE_THREAD
        manage();
#else
        while(isRunning())
        {
            if(mStopRequested)
                stop();
            else
                NextCash::Thread::sleep(1000);
        }
#endif
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

        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend("statistics");
        NextCash::FileOutputStream file(filePathName, false, true);
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

        NextCash::String timeText;

        timeText.writeFormattedTime(mChain.blockStats().time(mChain.height()));
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Block Chain : %d blocks (last %s)", mChain.height(), timeText.text());

        const Branch *branch;
        for(unsigned int i=0;i<mChain.branchCount();++i)
        {
            branch = mChain.branchAt(i);
            if(branch == NULL)
                break;

            if(branch->pendingBlocks.size() > 0)
                timeText.writeFormattedTime(branch->pendingBlocks.back()->block->time);

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Block Chain Branch %d : %d blocks (last %s)", i + 1, branch->height + branch->pendingBlocks.size() - 1, timeText.text());
        }

        if(mInfo.spvMode)
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Nodes : %d outgoing", mOutgoingNodes);
        else
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Outputs : %d trans (%d KiB cached)", mChain.outputs().size(),
              mChain.outputs().cacheDataSize() / 1024);
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Mem Pool : %d/%d trans/pending (%d KiB)", mChain.memPool().count(),
              mChain.memPool().pendingCount(), mChain.memPool().size() / 1024);

            if(!mChain.isInSync())
            {
                unsigned int pendingBlocks = mChain.pendingBlockCount();
                unsigned int pendingCount = mChain.pendingCount();
                unsigned int pendingSize = mChain.pendingSize();
                if(pendingSize > mInfo.pendingSizeThreshold || pendingBlocks > mInfo.pendingBlocksThreshold)
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                      "Pending (above threshold) : %d/%d blocks/headers (%d KiB) (%d requested)", pendingBlocks,
                      pendingCount - pendingBlocks, pendingSize / 1024, blocksRequestedCount);
                else
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                      "Pending : %d/%d blocks/headers (%d KiB) (%d requested)", pendingBlocks, pendingCount - pendingBlocks,
                      pendingSize / 1024, blocksRequestedCount);
            }

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Nodes : %d/%d outgoing/incoming", mOutgoingNodes, mIncomingNodes);
        }

        timeText.writeFormattedTime(mStatistics.startTime);
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Network : %d/%d KiB received/sent (since %s)", mStatistics.bytesReceived / 1024, mStatistics.bytesSent / 1024,
          timeText.text());
    }

    bool Daemon::loadMonitor()
    {
        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend("monitor");
        NextCash::FileInputStream file(filePathName);
        if(file.isValid())
        {
            if(!mMonitor.read(&file))
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
                  "Monitor failed to load");
                return false;
            }
            else
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Monitor loaded with %d addresses and %d transactions", mMonitor.size(),
                  mMonitor.transactionCount());
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Monitor file not found to load");

        // filePathName = Info::instance().path();
        // filePathName.pathAppend("address_text");
        // NextCash::FileInputStream textFile(filePathName);
        // if(textFile.isValid() && !mMonitor.loadAddresses(&textFile))
            // return false;

        mMonitor.setKeyStore(&mKeyStore);
        return true;
    }

    bool Daemon::saveMonitor()
    {
        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend("monitor");
        NextCash::FileOutputStream file(filePathName, true);
        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Monitor file failed to open");
            return false;
        }
        mMonitor.write(&file);
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Monitor saved with %d addresses and %d transactions", mMonitor.size(),
          mMonitor.transactionCount());
        return true;
    }

    bool Daemon::loadKeyStore()
    {
        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend("keystore");
        NextCash::FileInputStream file(filePathName);
        if(file.isValid())
        {
            if(!mKeyStore.read(&file))
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
                  "Key store failed to load");
                return false;
            }
            else
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Key store loaded with %d keys", mKeyStore.size());
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Key store file not found to load");

        filePathName = Info::instance().path();
        filePathName.pathAppend("key_text");
        NextCash::FileInputStream textFile(filePathName);
        return !textFile.isValid() || mKeyStore.loadKeys(&textFile);
    }

    bool Daemon::saveKeyStore()
    {
        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend("keystore");
        NextCash::FileOutputStream file(filePathName, true);
        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Key store file failed to open");
            return false;
        }
        mKeyStore.write(&file);
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Key store saved with %d keys", mKeyStore.size());
        return true;
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
        NextCash::HashList list;
    };

    void Daemon::sendRequests()
    {
        if(mInfo.spvMode)
        {
            sendHeaderRequest();
            return;
        }

        unsigned int pendingCount = mChain.pendingCount();

        if(!mChain.isInSync() && pendingCount < mInfo.pendingBlocksThreshold * 8)
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
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
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
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              "No blocks need requested");
            mNodeLock.readUnlock();
            return;
        }

        NextCash::HashList blocksToRequest;
        mChain.getBlocksNeeded(blocksToRequest, blocksToRequestCount, reduceOnly);

        if(blocksToRequest.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
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
        for(NextCash::HashList::iterator hash=blocksToRequest.begin();hash!=blocksToRequest.end();++hash)
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
        NextCash::HashList transactionsToRequest;

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

        if(nodes.size() == 0)
        {
            mNodeLock.readUnlock();
            return;
        }

        NodeRequests *nodeRequests = new NodeRequests[nodes.size()];
        NodeRequests *nodeRequest;
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
        for(NextCash::HashList::iterator hash=transactionsToRequest.begin();hash!=transactionsToRequest.end();++hash)
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
        if(getTime() - mLastHeaderRequestTime < 10)
            return;

        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        randomizeOutgoing(nodes);
        bool sent = false;

        if(nodes.size() == 0)
        {
            mNodeLock.readUnlock();
            return;
        }

        // Check for node with empty last header
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
            if((*node)->lastHeader().isEmpty() && (*node)->requestHeaders())
            {
                sent = true;
                mLastHeaderRequestTime = getTime();
                break;
            }

        if(!sent)
        {
            for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
                if((*node)->requestHeaders())
                {
                    mLastHeaderRequestTime = getTime();
                    break;
                }
        }

        mNodeLock.readUnlock();
    }

    void Daemon::checkSync()
    {
        mNodeLock.readLock();
        unsigned int count = 0;
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
            if(!(*node)->isIncoming())
            {
                // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                  // "Node [%d] last header : %s", (*node)->id(), (*node)->lastHeader().hex().text());
                if((*node)->lastHeader() == mChain.lastBlockHash())
                    ++count;
            }
        mNodeLock.readUnlock();

        if(count >= 4)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              "Chain is in sync. %d nodes have matching latest header : %s", count, mChain.lastBlockHash().hex().text());
            mChain.setInSync();
        }
        // else
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              // "Chain latest header : %s", mChain.lastBlockHash().hex().text());
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

        if(nodes.size() < outgoingConnectionCountTarget() / 2)
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
            variance += NextCash::Math::square((double)(*node)->pingTime() - average);
        // Average the sum
        variance /= (double)nodes.size();

        // Square root to get standard deviation
        double standardDeviation = NextCash::Math::squareRoot(variance);

        uint32_t cutoff;
        if(average > 60)
            cutoff = (int)(average + (standardDeviation * 0.5));
        else
            cutoff = (int)(average + standardDeviation);
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Node ping : average %ds, cutoff %ds", (int)average, cutoff);

        // Regularly drop some nodes to increase diversity
        int churnDrop = 0;
        if(nodes.size() >= outgoingConnectionCountTarget())
            churnDrop = nodes.size() / 8;

        // Drop slowest
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
        {
            if((*node)->blockDownloadBytesPerSecond() > cutoff)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s - %d KiB/s, %ds ping (dropping because of ping)", (*node)->name(),
                  (int)(*node)->blockDownloadBytesPerSecond() / 1024, (*node)->pingTime());
                (*node)->close();
            }
            else if(churnDrop > 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s - %d KiB/s, %ds ping (dropping for churn)", (*node)->name(),
                  (int)(*node)->blockDownloadBytesPerSecond() / 1024, (*node)->pingTime());
                (*node)->close();
            }
            else
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
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

        if(nodes.size() < outgoingConnectionCountTarget() / 2)
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

        if(nodes.size() < outgoingConnectionCountTarget() / 2)
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
                speedVariance += NextCash::Math::square((*node)->blockDownloadBytesPerSecond() - averageSpeed);
            pingVariance += NextCash::Math::square((double)(*node)->pingTime() - averagePing);
        }

        // Average the sum
        speedVariance /= (double)nodesWithSpeed;
        pingVariance /= (double)nodes.size();

        // Square root to get standard deviation
        double speedStandardDeviation = NextCash::Math::squareRoot(speedVariance);
        double pingStandardDeviation = NextCash::Math::squareRoot(pingVariance);

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
            scoreVariance += NextCash::Math::square(*nodeScore - averageScore);
        scoreVariance /= (double)scores.size();

        // Square root to get standard deviation
        double scoreStandardDeviation = NextCash::Math::squareRoot(scoreVariance);

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
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Node Performance Summary : average speed %d KiB/s, average ping %ds, drop score %d",
          (int)averageSpeed / 1024, (int)averagePing, (int)(100.0 * dropScore));

        // Always drop some nodes so nodes with lower pings can still be found
        int churnDrop = 0;
        if(sortedScores.size() >= outgoingConnectionCountTarget())
            churnDrop = sortedScores.size() / 8;

        // Drop slowest
        nodeScore = sortedScores.begin();
        for(std::vector<Node *>::iterator node=sortedNodes.begin();node!=sortedNodes.end();++node)
        {
            if(*nodeScore < dropScore)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s (score %d) - %d KiB/s, %ds ping (dropping because of score)", (*node)->name(),
                  (int)(100.0 * *nodeScore), (int)(*node)->blockDownloadBytesPerSecond() / 1024, (*node)->pingTime());
                (*node)->close();
            }
            else if(churnDrop > 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s (score %d) - %d KiB/s, %ds ping (dropping for churn)", (*node)->name(),
                  (int)(100.0 * *nodeScore), (int)(*node)->blockDownloadBytesPerSecond() / 1024, (*node)->pingTime());
                (*node)->close();
            }
            else
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
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

        NextCash::HashList transactionList;
        Transaction *transaction;
        mChain.memPool().getToAnnounce(transactionList);
        if(transactionList.size() > 0)
        {
            mNodeLock.readLock();
            for(NextCash::HashList::iterator hash=transactionList.begin();hash!=transactionList.end();++hash)
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

    void Daemon::runManage()
    {
        ((Daemon *)NextCash::Thread::getParameter())->manage();
    }

    void Daemon::manage()
    {
        try
        {
            load();
        }
        catch(std::bad_alloc pException)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME,
              "Bad allocation while loading : %s", pException.what());
            return;
        }
        catch(std::exception pException)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME,
              "Exception while loading : %s", pException.what());
            return;
        }

        // If another thread started loading first, then wait for it to finish.
        while(mLoading)
            NextCash::Thread::sleep(100);

        if(mStopping || !mLoaded)
            return;

#ifndef SINGLE_THREAD
        mConnectionThread = new NextCash::Thread("Connection", runConnections, this);
        if(mConnectionThread == NULL)
        {
            requestStop();
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Failed to create connection thread");
            return;
        }

        if(mStopping)
            return;

        if(!mInfo.spvMode)
        {
            mRequestsThread = new NextCash::Thread("Requests", runRequests, this);
            if(mRequestsThread == NULL)
            {
                requestStop();
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
                  "Failed to create requests thread");
                return;
            }

            if(mStopping)
                return;
        }

        mProcessThread = new NextCash::Thread("Process", runProcesses, this);
        if(mProcessThread == NULL)
        {
            requestStop();
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Failed to create process thread");
            return;
        }
#endif

        int32_t startTime = getTime();
        int32_t lastStatReportTime = startTime;
        int32_t lastRequestCheckTime = startTime;
        int32_t lastInfoSaveTime = startTime;
        int32_t lastPeerRequestTime = 0;
        int32_t lastImprovement = startTime;
        int32_t lastTransactionRequest = startTime;
        int32_t time;
#ifdef PROFILER_ON
        uint32_t lastProfilerWrite = startTime;
        NextCash::String profilerTime;
        NextCash::String profilerFileName;
        NextCash::FileOutputStream *profilerFile;
#endif

        while(!mStopping)
        {
            if(mFinishMode == FINISH_ON_SYNC && mChain.isInSync() &&
              (int)mMonitor.height() == mChain.height())
            {
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Stopping because of finish on sync");
                requestStop();
                break;
            }

            if(mStopping)
                break;

            time = getTime();
            if(time - lastStatReportTime > 180)
            {
                lastStatReportTime = getTime();
                printStatistics();
            }

            if(mStopping)
                break;

            if(mFinishMode != FINISH_ON_REQUEST &&
              peerCount() == 0 && time - mLastConnectionActive > 60)
            {
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Stopping because of lack of network connectivity");
                requestStop();
                break;
            }

            if(!mChain.isInSync())
            {
                // Wait 30 seconds so hopefully a bunch of nodes are ready to request at the same
                //   time to improve staggering
                time = getTime();
                if(time - lastRequestCheckTime > 30 ||
                  (mChain.pendingBlockCount() == 0 && time - lastRequestCheckTime > 10))
                {
                    lastRequestCheckTime = time;
                    checkSync();
                    sendRequests();
                }

                if(mStopping)
                    break;
            }
            else
            {
                if(mChain.headersNeeded())
                    sendHeaderRequest();
                if(mChain.blocksNeeded())
                    sendRequests();
                if(!mInfo.spvMode)
                {
                    time = getTime();
                    if(time - lastTransactionRequest > 20)
                    {
                        lastTransactionRequest = time;
                        sendTransactionRequests();
                    }
                }
            }

            time = getTime();
#ifdef ANDROID
            if(time - lastInfoSaveTime > 180)
#else
            if(time - lastInfoSaveTime > 600)
#endif
            {
                lastInfoSaveTime = time;
                mInfo.save();
                saveMonitor();
                mChain.blockStats().save();
                mChain.forks().save();
            }

            if(mStopping)
                break;

#ifdef LOW_MEM
            if(mChain.blockStats().cacheSize() > 10000)
            {
                mChain.blockStats().save();
                mChain.forks().save();
            }
#endif

            if(mStopping)
                break;

            time = getTime();
            if(time - mStatistics.startTime > 3600)
                saveStatistics();

            if(mStopping)
                break;

            time = getTime();
            if(mLastPeerCount > 0 && mLastPeerCount < 10000 &&
              time - lastPeerRequestTime > 60)
            {
                lastPeerRequestTime = time;
                sendPeerRequest();
            }

            if(mStopping)
                break;

            time = getTime();
            if(time - lastImprovement > 300) // Every 5 minutes
            {
                lastImprovement = time;
                improveSpeed();
            }

            if(mStopping)
                break;

#ifdef SINGLE_THREAD
            // Process nodes
            mNodeLock.readLock();
            for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();++node)
                (*node)->process();
            mNodeLock.readUnlock();
            if(mStopping)
                break;

            process();
            if(mStopping)
                break;

            handleConnections();
            if(mStopping)
                break;

            if(!mInfo.spvMode)
            {
                handleRequests();
                if(mStopping)
                    break;
            }

            if(mStopRequested)
            {
                stop();
                break;
            }
            else
                NextCash::Thread::sleep(200);
#else
            NextCash::Thread::sleep(2000);
#endif

#ifdef PROFILER_ON
            time = getTime();
            if(time - lastProfilerWrite > 3600)
            {
                profilerTime.writeFormattedTime(time, "%Y%m%d.%H%M");
                profilerFileName.writeFormatted("profiler.%s.txt", profilerTime.text());
                profilerFile = new NextCash::FileOutputStream(profilerFileName, true);
                NextCash::ProfilerManager::write(profilerFile);
                delete profilerFile;
                NextCash::ProfilerManager::reset();
                lastProfilerWrite = time;
            }
#endif
        }
    }

    void Daemon::runProcesses()
    {
        Daemon *daemon = (Daemon *)NextCash::Thread::getParameter();
        daemon->mLastBlockHash = daemon->mChain.lastBlockHash();

        while(!daemon->mStopping)
        {
            daemon->process();
            NextCash::Thread::sleep(100);
        }
    }

    void Daemon::process()
    {
        mChain.process();

        if(mStopping)
            return;

        if(mInfo.spvMode)
        {
            if(mLastBlockHash != mChain.lastBlockHash() ||
              getTime() - mLastMonitorProcess > 2)
            {
                mMonitor.process(mChain);
                mLastMonitorProcess = getTime();
                mLastBlockHash = mChain.lastBlockHash();
            }

            if(mStopping)
                return;
        }
        else
        {
            if(mChain.isInSync())
                announce();

            if(mStopping)
                return;

            if(getTime() - mLastMemPoolCheckPending > 20)
            {
                mChain.memPool().checkPendingTransactions(mChain.outputs(),
                  mChain.blockStats(), mChain.forks(), mInfo.minFee);
                mLastMemPoolCheckPending = getTime();
            }

            if(mStopping)
                return;

            mChain.memPool().process(mInfo.memPoolThreshold);

            if(mStopping)
                return;

            if((getTime() - mLastOutputsPurgeTime > 30 && mChain.outputs().needsPurge()) ||
              getTime() - mLastOutputsPurgeTime > 3600)
            {
                if(!mChain.outputs().save())
                    requestStop();
                mLastOutputsPurgeTime = getTime();
            }

            if(mStopping)
                return;

            if((getTime() - mLastAddressPurgeTime > 30 && mChain.addresses().needsPurge()) ||
              getTime() - mLastAddressPurgeTime > 3600)
            {
                if(!mChain.addresses().save())
                    requestStop();
                mLastAddressPurgeTime = getTime();
            }

            if(mStopping)
                return;
        }
    }

    void Daemon::addRejectedIP(const uint8_t *pIP)
    {
        IPBytes ip = pIP;
        mRejectedIPs.push_back(ip);

        while(mRejectedIPs.size() > 1000)
            mRejectedIPs.erase(mRejectedIPs.begin());
    }

    bool Daemon::addNode(NextCash::Network::Connection *pConnection, bool pIncoming, bool pIsSeed, uint64_t pServices)
    {
        mLastConnectionActive = getTime();

        // Check if IP is on reject list
        for(std::vector<IPBytes>::iterator ip=mRejectedIPs.begin();ip!=mRejectedIPs.end();++ip)
            if(*ip == pConnection->ipv6Bytes())
            {
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_DAEMON_LOG_NAME,
                  "Rejecting connection from IP %s", pConnection->ipv6Address());
                delete pConnection;
                return false;
            }

        Node *node;
        try
        {
            node = new Node(pConnection, &mChain, pIncoming, pIsSeed, pServices, mMonitor);
        }
        catch(std::bad_alloc &pBadAlloc)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Bad allocation while allocating new node : %s", pBadAlloc.what());
            delete pConnection;
            return false;
        }
        catch(...)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Bad allocation while allocating new node : unknown");
            delete pConnection;
            return false;
        }

        mNodeLock.writeLock("Add");
        mNodes.push_back(node);
        ++mNodeCount;
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

    static const char *SEEDS[] =
            { "seed.bitcoinabc.org",
              "seed-abc.bitcoinforks.org",
              "btccash-seeder.bitcoinunlimited.info",
              "seed.bitprim.org",
              "seed.deadalnix.me",
              "seeder.criptolayer.net"
            };
    static const int SEED_COUNT = 6;

    unsigned int Daemon::querySeed(const char *pName)
    {
        mQueryingSeed = true;

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Querying seed %s", pName);
        NextCash::Network::IPList ipList;
        NextCash::Network::list(pName, ipList);
        unsigned int result = 0;
#ifdef SINGLE_THREAD
        int32_t lastNodeProcess = getTime();
#endif

        if(ipList.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME, "No nodes found from seed");
            mQueryingSeed = false;
            return 0;
        }

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Found %d nodes from %s", ipList.size(), pName);
        NextCash::Network::Connection *connection;
        unsigned int seedConnections;
        for(NextCash::Network::IPList::iterator ip=ipList.begin();ip!=ipList.end() && !mStopping;++ip)
        {
            seedConnections = 0;
            mNodeLock.readLock();
            for (std::vector<Node *>::iterator node = mNodes.begin();
                 node != mNodes.end() && !mStopRequested; ++node)
                if ((*node)->isSeed())
                    ++seedConnections;
            mNodeLock.readUnlock();

            if(seedConnections < 16)
            {
                connection = new NextCash::Network::Connection(*ip, networkPortString(), 5);
                if (!connection->isOpen())
                    delete connection;
                else if (addNode(connection, false, true, 0))
                    result++;
            }
            else
            {
                NextCash::Thread::sleep(500);
#ifdef SINGLE_THREAD
                if(getTime() - lastNodeProcess > 5)
                {
                    // Process nodes so they don't wait a long time
                    mNodeLock.readLock();
                    for (std::vector<Node *>::iterator node = mNodes.begin();
                         node != mNodes.end() && !mStopRequested; ++node)
                        (*node)->process();
                    mNodeLock.readUnlock();
                    lastNodeProcess = getTime();
                }
#endif
            }
        }

        mQueryingSeed = false;
        return result;
    }

    unsigned int Daemon::recruitPeers(unsigned int pCount)
    {
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Recruiting %d peers", pCount);
        std::vector<Peer *> peers;
        unsigned int count = 0;
        bool found;
        uint64_t servicesMask = Message::VersionData::FULL_NODE_BIT;
#ifdef SINGLE_THREAD
        int32_t lastNodeProcess = getTime();
#endif

        if(mChain.forks().cashActive())
            servicesMask |= Message::VersionData::CASH_NODE_BIT;

        if(mInfo.spvMode)
            servicesMask |= Message::VersionData::BLOOM_NODE_BIT;

        // Try peers with good ratings first
        mInfo.getRandomizedPeers(peers, 5, servicesMask);
        NextCash::Network::Connection *connection;
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
          "Found %d good peers", peers.size());
        for(std::vector<Peer *>::iterator peer=peers.begin();peer!=peers.end()&&!mStopRequested;++peer)
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

            connection = new NextCash::Network::Connection(AF_INET6, (*peer)->address.ip, (*peer)->address.port, 5);
            if(!connection->isOpen())
                delete connection;
            else if(addNode(connection, false, false, (*peer)->services))
            {
                ++count;
#ifdef SINGLE_THREAD
                break;
#endif
            }

            if(mStopping || count >= pCount / 2) // Limit good to half
                break;

#ifdef SINGLE_THREAD
            if(getTime() - lastNodeProcess > 5)
            {
                // Process nodes so they don't wait a long time
                mNodeLock.readLock();
                for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end()&&!mStopRequested;++node)
                    (*node)->process();
                mNodeLock.readUnlock();
                lastNodeProcess = getTime();
            }
#endif
        }

        peers.clear();
        mInfo.getRandomizedPeers(peers, -5, servicesMask);
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
          "Found %d usable peers", peers.size());
        unsigned int usableCount = 0;
        mLastPeerCount = peers.size();
        for(std::vector<Peer *>::iterator peer=peers.begin();peer!=peers.end();++peer)
        {
            // Skip nodes already connected
            found = false;
            mNodeLock.readLock();
            for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end()&&!mStopRequested;++node)
                if((*node)->address() == (*peer)->address)
                {
                    found = true;
                    break;
                }
            mNodeLock.readUnlock();
            if(found)
                continue;

            connection = new NextCash::Network::Connection(AF_INET6, (*peer)->address.ip, (*peer)->address.port, 5);
            if(!connection->isOpen())
                delete connection;
            else if(addNode(connection, false, false, 0))
            {
                ++count;
#ifdef SINGLE_THREAD
                break;
#endif
                ++usableCount;
            }

            if(mStopping || count >= pCount)
                break;

#ifdef SINGLE_THREAD
            if(getTime() - lastNodeProcess > 5)
            {
                // Process nodes so they don't wait a long time
                mNodeLock.readLock();
                for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end()&&!mStopRequested;++node)
                    (*node)->process();
                mNodeLock.readUnlock();
                lastNodeProcess = getTime();
            }
#endif
        }

        if(count == 0)
        {
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Choosing random seed");
            querySeed(SEEDS[NextCash::Math::randomInt(SEED_COUNT)]);
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
                mLastConnectionActive = getTime();
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
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
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

    bool Daemon::addRequestChannel(NextCash::Network::Connection *pConnection)
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

    void Daemon::runConnections()
    {
        Daemon *daemon = (Daemon *)NextCash::Thread::getParameter();

        if (daemon->outgoingConnectionCountTarget() >= daemon->mInfo.maxConnections)
            daemon->mMaxIncoming = 0;
        else
            daemon->mMaxIncoming =
              daemon->mInfo.maxConnections - daemon->outgoingConnectionCountTarget();

        while(!daemon->mStopping)
        {
            daemon->handleConnections();
            NextCash::Thread::sleep(500);
        }

        if(daemon->mNodeListener != NULL)
            delete daemon->mNodeListener;
    }

    void Daemon::handleConnections()
    {
        NextCash::Network::Connection *newConnection;

        if(mOutgoingNodes < outgoingConnectionCountTarget() && getTime() - mLastFillNodesTime > 30)
        {
            recruitPeers(outgoingConnectionCountTarget() - mOutgoingNodes);
            mLastFillNodesTime = getTime();
        }

        if(mStopping)
            return;

        if(getTime() - mLastCleanTime > 10)
        {
            mLastCleanTime = getTime();
            cleanNodes();
        }

        if(mStopping)
            return;

        if(!mInfo.spvMode)
        {
            if(mNodeListener == NULL)
            {
                if(mIncomingNodes < mMaxIncoming)
                {
                    mNodeListener = new NextCash::Network::Listener(AF_INET6, networkPort(), 5, 1);
                    if(mNodeListener->isValid())
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                          "Started listening for incoming connections on port %d", mNodeListener->port());
                    }
                    else
                    {
                        NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
                          "Failed to create incoming listener");
                        requestStop();
                        return;
                    }
                }
            }
            else
            {
                while(!mStopping && (newConnection = mNodeListener->accept()) != NULL)
                    if(addNode(newConnection, true, false, 0) && mIncomingNodes >= mMaxIncoming)
                    {
                        delete mNodeListener;
                        mNodeListener = NULL;
                        NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                          "Stopped listening for incoming connections because of connection limit");
                        break;
                    }
            }
        }
    }

    void Daemon::runRequests()
    {
        Daemon *daemon = (Daemon *)NextCash::Thread::getParameter();

        while(!daemon->mStopping)
        {
            daemon->handleRequests();
            NextCash::Thread::sleep(200);
        }

        if(daemon->mRequestsListener != NULL)
            delete daemon->mRequestsListener;
    }

    void Daemon::handleRequests()
    {
        NextCash::Network::Connection *newConnection;

        if(getTime() - mLastCleanTime > 10)
        {
            mLastCleanTime = getTime();
            cleanRequestChannels();
        }

        if(mStopping)
            return;

        if(mRequestsListener == NULL)
        {
            if(mRequestChannels.size() < 8)
            {
                mRequestsListener = new NextCash::Network::Listener(AF_INET6, 8666, 5, 1);
                if(mRequestsListener->isValid())
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                      "Started listening for request connections on port %d",
                      mRequestsListener->port());
                }
                else
                {
                    NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
                      "Failed to create requests listener");
                    requestStop();
                    return;
                }
            }
        }
        else
        {
            while(!mStopping && (newConnection = mRequestsListener->accept()) != NULL)
                if(addRequestChannel(newConnection) && mRequestChannels.size() >= 8)
                {
                    delete mRequestsListener;
                    mRequestsListener = NULL;
                    NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                      "Stopped listening for request connections because of connection limit");
                    break;
                }
        }
    }
}
