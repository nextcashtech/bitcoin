/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "daemon.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#include "profiler_setup.hpp"
#endif

#include "log.hpp"
#include "network.hpp"
#include "info.hpp"
#include "header.hpp"
#include "block.hpp"
#include "chain.hpp"
#include "interpreter.hpp"

#include <csignal>
#include <algorithm>

#define BITCOIN_DAEMON_LOG_NAME "Daemon"
#define RECENT_IP_COUNT 500


namespace BitCoin
{
    Daemon::Daemon() : mInfo(Info::instance()), mNodeLock("Nodes"), mTransmitMutex("Transmit"),
      mRequestsLock("Requests")
    {
        mRunning = false;
        mStopping = false;
        mStopRequested = false;
        mLoadingWallets = false;
        mWalletsLoaded = false;
        mLoadingChain = false;
        mChainLoaded = false;
        mQueryingSeed = false;
        mConnecting = false;
#ifndef SINGLE_THREAD
        mConnectionThread = NULL;
        mRequestsThread = NULL;
        mManagerThread = NULL;
        mProcessThread = NULL;
        mScanThread = NULL;
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
        mLastDataSaveTime = getTime();
        mLastMonitorProcess = getTime();
        mLastCleanTime = getTime();
        mNodeListener = NULL;
        mLastRequestCleanTime = getTime();
        mLastMemPoolProcessTime = getTime();
        mRequestsListener = NULL;
        mGoodNodeMax = 5;
        mOutgoingNodeMax = 8;
        mSeedsRandomized = false;
        mConnectionsSinceLastRecruit = 0;
        mFinishMode = FINISH_ON_REQUEST;
        mFinishTime = 0;
        mKeysSynchronized = true;
        mTransmittedTransToLastNode = false;

        NextCash::Log::add(NextCash::Log::DEBUG, BITCOIN_DAEMON_LOG_NAME,
          "Creating daemon object");
    }

    Daemon::~Daemon()
    {
        NextCash::Log::add(NextCash::Log::DEBUG, BITCOIN_DAEMON_LOG_NAME,
          "Destroying daemon object");

        if(isRunning() && !mStopping)
            requestStop();

        while(isRunning())
            NextCash::Thread::sleep(100);

        mTransmitMutex.lock();
    }

    void Daemon::transmitTransactions()
    {
        // Check if transactions have confirmed
        mTransmitMutex.lock();
        for(TransactionList::iterator trans = mTransactionsToTransmit.begin();
          trans != mTransactionsToTransmit.end();)
        {
            if(mMonitor.isConfirmed((*trans)->hash()))
                trans = mTransactionsToTransmit.erase(trans);
            else
                ++trans;
        }

        if(mTransactionsToTransmit.size() == 0)
        {
            mTransmitMutex.unlock();
            return;
        }

        mNodeLock.readLock();
        for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
            if((*node)->isNewlyReady())
            {
                if(!mTransmittedTransToLastNode)
                    for(TransactionList::iterator trans = mTransactionsToTransmit.begin();
                      trans != mTransactionsToTransmit.end(); ++trans)
                        (*node)->sendTransaction(*trans);
                mTransmittedTransToLastNode = !mTransmittedTransToLastNode;
            }
        mNodeLock.readUnlock();
        mTransmitMutex.unlock();
    }

    unsigned int Daemon::peerCount()
    {
        mNodeLock.readLock();
        unsigned int result = 0;
        for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
            if((*node)->isOutgoing() && (*node)->isReady())
                ++result;
        mNodeLock.readUnlock();
        return result;
    }

    Daemon::Status Daemon::status()
    {
        if(mLoadingWallets)
            return LOADING_WALLETS;

        if(mLoadingChain)
            return LOADING_CHAIN;

        if(!mRunning)
            return INACTIVE;

        if(mQueryingSeed)
            return FINDING_PEERS;

        if(mConnecting && peerCount() < maxOutgoingNodes() / 2)
            return CONNECTING_TO_PEERS;

        if(mChain.isInSync())
        {
            unsigned int monitorHeight = mMonitor.height();
            if(monitorHeight > 0 && monitorHeight < mChain.headerHeight())
                return FINDING_TRANSACTIONS;
            else
                return SYNCHRONIZED;
        }
        else
            return SYNCHRONIZING;
    }

    void Daemon::setFinishMode(int pMode)
    {
        if(pMode != mFinishMode)
        {
            if(pMode == FINISH_ON_REQUEST)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Finish mode set to on request");
            else
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Finish mode set to on sync");
        }
        mFinishMode = pMode;
    }

    void Daemon::setFinishTime(Time pTime)
    {
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Finish time set to %d", pTime);
        mFinishTime = pTime;
    }

    static Daemon *sSignalInstance = NULL;

    void Daemon::handleSigTermChild(int pValue)
    {
        //NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Child process terminated");
    }

    void Daemon::handleSigTerm(int pValue)
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Terminate signal received. Stopping.");
        if(sSignalInstance != NULL)
            sSignalInstance->requestStop();
    }

    void Daemon::handleSigInt(int pValue)
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Interrupt signal received. Stopping.");
        if(sSignalInstance != NULL)
            sSignalInstance->requestStop();
    }

    void Daemon::handleSigPipe(int pValue)
    {
        // Happens when writing to a network connection that is closed
        //NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
        // "Pipe signal received.");
    }

    bool Daemon::loadWallets()
    {
        if(mWalletsLoaded || mLoadingWallets)
            return true;

        mLoadingWallets = true;

        if(!mInfo.load())
        {
            mLoadingWallets = false;
            return false;
        }

        if(!loadKeyStore())
        {
            mLoadingWallets = false;
            return false;
        }

        if(!loadMonitor())
        {
            mLoadingWallets = false;
            return false;
        }

        mLoadingWallets = false;
        mWalletsLoaded = true;
        return true;
    }

    bool Daemon::loadChain()
    {
        if(mChainLoaded || mLoadingChain)
            return true;

        mLoadingChain = true;

        if(!mChain.load())
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME,
              "Failed to load chain.");
            mLoadingChain = false;
            return false;
        }

        if(mChain.headerHeight() < mMonitor.height())
            mMonitor.revertToHeight(mChain.headerHeight());

        mChain.setMonitor(mMonitor);

        mLastDataSaveTime = getTime();
        mLoadingChain = false;
        mChainLoaded = true;
        return true;

    }

    bool Daemon::start(bool pInDaemonMode)
    {
        if(mRunning)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME,
              "Already running. Start aborted.");
            return false;
        }

        if(mStopping)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME,
              "Still stopping. Start aborted.");
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
          "Starting %s on %s in %s", BITCOIN_USER_AGENT, networkName(),
          mInfo.path().text());

#ifdef TEST
        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME, "Running in TEST mode.");
#endif

#ifdef SINGLE_THREAD
        if(mInfo.spvMode)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Running in SPV mode (Single Thread)");
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME, "Running in Full/Bloom mode (Single Thread)");
#else
        if(mInfo.spvMode)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Running in SPV mode (Multi Threaded)");
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Running in Full/Bloom mode (Multi Threaded)");
#endif

#ifndef SINGLE_THREAD
        mManagerThread = new NextCash::Thread("Manager", runManage, this);
        if(mManagerThread == NULL)
        {
            requestStop();
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Failed to create manage thread");
            return false;
        }
#endif

        return true;
    }

    void Daemon::stop()
    {
        if(!isRunning())
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME,
              "Not running. Stop aborted.");
            return;
        }

        if(mStopping)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME,
              "Still stopping. Stop aborted.");
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
            for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
                (*node)->requestStop();
        }
        mNodeLock.readUnlock();

        // Delete nodes
        mNodeLock.writeLock("Destroy");
        if(mNodes.size() > 0)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Deleting nodes");
            for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
            {
                (*node)->collectStatistics(mStatistics);
                delete *node;
            }
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
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              "Stopping process thread");
            delete mProcessThread;
            mProcessThread = NULL;
        }

        // Wait for manager to finish
        if(mManagerThread != NULL)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              "Stopping manager thread");
            delete mManagerThread;
            mManagerThread = NULL;
        }

        // Wait for scan thread to finish
        if(mScanThread != NULL)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              "Stopping scan thread");
            delete mScanThread;
            mScanThread = NULL;
        }
#endif

        NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME, "Saving data");
        saveStatistics();
        saveMonitor();
        saveKeyStore();
        mChain.save(true);
        mChain.clearInSync();
        Header::clean();
        Block::clean();
        mInfo.save();

#ifdef PROFILER_ON
        NextCash::printProfilerDataToLog(NextCash::Log::VERBOSE);
        NextCash::resetProfilers();
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
        for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
            (*node)->collectStatistics(mStatistics);
        mNodeLock.readUnlock();
    }

    void Daemon::saveStatistics()
    {
        collectStatistics();

        NextCash::String filePathName = mInfo.path();
        filePathName.pathAppend("statistics");
        NextCash::FileOutputStream statisticsFile(filePathName, false, true);
        if(!statisticsFile.isValid())
        {
            // Clear anyway so it doesn't try to save every manager loop
            mStatistics.clear();
            return;
        }
        mStatistics.write(&statisticsFile);
        mStatistics.clear();
    }

    void Daemon::printStatistics()
    {
        unsigned int blocksRequestedCount = 0;
        unsigned int outgoingCount = 0;
        mNodeLock.readLock();
        for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
        {
            if((*node)->isOutgoing() && (*node)->isReady())
                ++outgoingCount;
            blocksRequestedCount += (*node)->blocksRequestedCount();
            (*node)->collectStatistics(mStatistics);
        }
        mNodeLock.readUnlock();

        NextCash::String timeText;

        timeText.writeFormattedTime(mChain.time(mChain.headerHeight()));
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Block Chain : %d/%d blocks/headers (last %s)", mChain.blockHeight(),
          mChain.headerHeight(), timeText.text());

        const Branch *branch;
        for(unsigned int i = 0; i < mChain.branchCount(); ++i)
        {
            branch = mChain.branchAt(i);
            if(branch == NULL)
                break;

            if(branch->pendingBlocks.size() > 0)
                timeText.writeFormattedTime(branch->pendingBlocks.back()->block->header.time);

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Block Chain Branch %d : height %d (%d blocks) (last %s)", i + 1,
              branch->height, branch->pendingBlocks.size(), timeText.text());
        }

        if(mInfo.spvMode)
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Nodes : %d outgoing", outgoingCount);
        else
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Outputs : %d trans (%d K, %d KB cached)", mChain.outputs().size(),
              mChain.outputs().cacheSize() / 1000, mChain.outputs().cacheDataSize() / 1000);
#ifndef DISABLE_ADDRESSES
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Addresses : %d addrs (%d KB cached)", mChain.addresses().size(),
              mChain.addresses().cacheDataSize() / 1000);
#endif
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Mem Pool : %d/%d trans/pending (%d/%d KB)", mChain.memPool().count(),
              mChain.memPool().pendingCount(), mChain.memPool().size() / 1000,
              mChain.memPool().pendingSize() / 1000);

            if(!mChain.isInSync())
            {
                unsigned int pendingBlocks = mChain.pendingBlockCount();
                unsigned int pendingCount = mChain.pendingCount();
                unsigned int pendingSize = mChain.pendingSize();
                if(pendingSize > mInfo.pendingSize || pendingBlocks > mInfo.pendingBlocks)
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                      "Pending (above threshold) : %d/%d blocks/headers (%d KB) (%d requested)",
                      pendingBlocks, pendingCount - pendingBlocks, pendingSize / 1000,
                      blocksRequestedCount);
                else
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                      "Pending : %d/%d blocks/headers (%d KB) (%d requested)", pendingBlocks,
                      pendingCount - pendingBlocks, pendingSize / 1000, blocksRequestedCount);
            }

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Nodes : %d/%d outgoing/incoming", outgoingCount, mIncomingNodes);
        }

        timeText.writeFormattedTime(mStatistics.startTime);
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Network : %d/%d KB received/sent (since %s)", mStatistics.bytesReceived / 1000,
          mStatistics.bytesSent / 1000, timeText.text());
    }

    bool Daemon::loadMonitor()
    {
        NextCash::String filePathName = mInfo.path();
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
        {
            mMonitor.markLoaded();
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Monitor file not found to load");
        }

        // filePathName = mInfo.path();
        // filePathName.pathAppend("address_text");
        // NextCash::FileInputStream textFile(filePathName);
        // if(textFile.isValid() && !mMonitor.loadAddresses(&textFile))
            // return false;

        mMonitor.setKeyStore(&mKeyStore);
        return true;
    }

    bool Daemon::saveMonitor()
    {
        NextCash::String tempFilePathName = mInfo.path();
        tempFilePathName.pathAppend("monitor.temp");
        NextCash::FileOutputStream file(tempFilePathName, true);
        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Monitor file failed to open");
            return false;
        }
        mMonitor.sortTransactions(&mChain);
        mMonitor.write(&file);
        file.close();

        NextCash::String realFilePathName = mInfo.path();
        realFilePathName.pathAppend("monitor");
        NextCash::renameFile(tempFilePathName, realFilePathName);

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Monitor saved with %d addresses and %d transactions", mMonitor.size(),
          mMonitor.transactionCount());
        return true;
    }

    bool Daemon::loadKeyStore(const uint8_t *pPassword, unsigned int pPasswordLength)
    {
        NextCash::String filePathName = mInfo.path();
        filePathName.pathAppend("keystore");
        NextCash::FileInputStream publicFile(filePathName);
        if(publicFile.isValid())
        {
            if(!mKeyStore.read(&publicFile))
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
        {
            mKeyStore.markLoaded();
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Key store public file not found to load");
        }

        mKeysSynchronized = mKeyStore.allAreSynchronized();

#ifndef ANDROID
        filePathName = mInfo.path();
        filePathName.pathAppend("key_text");
        NextCash::FileInputStream textFile(filePathName);

        if(!textFile.isValid())
            return true;

        filePathName = mInfo.path();
        filePathName.pathAppend(".private_keystore");
        NextCash::FileInputStream privateFile(filePathName);
        if(privateFile.isValid())
        {
            if(!mKeyStore.readPrivate(&privateFile, pPassword, pPasswordLength))
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
                  "Key store failed to load private");
                return false;
            }
            else
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Key store loaded private keys");
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Key store private file not found to load");

        unsigned int previousSize = mKeyStore.size();
        if(!mKeyStore.loadKeys(&textFile))
        {
            mKeyStore.unloadPrivate();
            return false;
        }

        privateFile.close();
        publicFile.close();

        if(previousSize != mKeyStore.size())
            saveKeyStore();

        mKeyStore.unloadPrivate();
#endif
        return true;
    }

    bool Daemon::saveKeyStore(const uint8_t *pPassword, unsigned int pPasswordLength)
    {
        NextCash::String tempFilePathName = mInfo.path();
        tempFilePathName.pathAppend("keystore.temp");
        NextCash::FileOutputStream publicFile(tempFilePathName, true);
        if(!publicFile.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Key store file failed to open");
            return false;
        }
        mKeyStore.write(&publicFile);
        publicFile.close();

        NextCash::String realFilePathName = mInfo.path();
        realFilePathName.pathAppend("keystore");
        NextCash::renameFile(tempFilePathName, realFilePathName);

#ifndef ANDROID
        if(mKeyStore.isPrivateLoaded())
        {
            tempFilePathName = mInfo.path();
            tempFilePathName.pathAppend(".private_keystore.temp");
            NextCash::FileOutputStream privateFile(tempFilePathName, true);
            mKeyStore.writePrivate(&privateFile, pPassword, pPasswordLength);

            privateFile.close();

            NextCash::String realFilePathName = mInfo.path();
            realFilePathName.pathAppend(".private_keystore");
            NextCash::renameFile(tempFilePathName, realFilePathName);
        }
#endif

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Key store saved with %d keys", mKeyStore.size());
        return true;
    }

    void Daemon::resetKeysSynchronized()
    {
        mKeysSynchronized = mKeyStore.allAreSynchronized();
    }

    int estimatedStandardFee(int pInputCount, int pOutputCount, double pFeeRate)
    {
        // P2PKH/P2SH input size
        //   Previous Transaction ID = 32 bytes
        //   Previous Transaction Output Index = 4 bytes
        //   Signature push to stack = 75
        //       push size = 1 byte
        //       signature up to = 73 bytes
        //       signature hash type = 1 byte
        //   Public key push to stack = 34
        //       push size = 1 byte
        //       public key size = 33 bytes
        int inputSize = 32 + 4 + 75 + 34;

        // P2PKH/P2SH output size
        //   amount = 8 bytes
        //   push size = 1 byte
        //   Script (24 bytes) OP_DUP OP_HASH160 <PUB KEY/SCRIPT HASH (20 bytes)> OP_EQUALVERIFY
        //     OP_CHECKSIG
        int outputSize = 8 + 25;

        return (int)((double)((inputSize * pInputCount) + (pOutputCount * outputSize)) * pFeeRate);
    }

    int Daemon::sendStandardPayment(unsigned int pKeyOffset, AddressType pHashType,
      NextCash::Hash pHash, uint64_t pAmount, double pFeeRate, bool pUsePending, bool pSendAll,
      bool pTransmit, TransactionReference &pTransaction)
    {
        if(pAmount < Transaction::DUST)
        {
            pTransaction.clear();
            return 6; // Below dust
        }

        if(pHash.size() != 20) // Required for P2PKH and P2SH
        {
            pTransaction.clear();
            return 3; // Invalid Hash
        }

        Key *fullKey = mKeyStore.fullKey(pKeyOffset);
        std::vector<BitCoin::Key *> *chainKeys = mKeyStore.chainKeys(pKeyOffset);
        if(fullKey == NULL || chainKeys == NULL)
        {
            pTransaction.clear();
            return 1;
        }

        // Get UTXOs from monitor
        std::vector<Outpoint> unspentOutputs;
        if(!mMonitor.getUnspentOutputs(chainKeys->begin(), chainKeys->end(), unspentOutputs,
          &mChain, pUsePending))
        {
            pTransaction.clear();
            return 1;
        }

        // Create transaction
        pTransaction = new Transaction();
        uint64_t inputAmount = 0;
        uint64_t sendAmount = pAmount;

        for(std::vector<Outpoint>::iterator output = unspentOutputs.begin();
          output != unspentOutputs.end() && (pSendAll || inputAmount <= sendAmount +
          estimatedStandardFee((unsigned int)pTransaction->inputs.size(), pSendAll ? 1 : 2,
          pFeeRate)); ++output)
        {
            pTransaction->addInput(output->transactionID, output->index);
            pTransaction->inputs.back().outpoint.output = new Output(*output->output);
            inputAmount += output->output->amount;
        }

        if(pSendAll)
            sendAmount = inputAmount;
        else if(inputAmount < sendAmount +
          estimatedStandardFee((unsigned int)pTransaction->inputs.size(), pSendAll ? 1 : 2,
          pFeeRate))
        {
            pTransaction.clear();
            return 2; // Insufficient funds
        }

        // Add payment output
        if(pHashType == MAIN_PUB_KEY_HASH)
            pTransaction->addP2PKHOutput(pHash, sendAmount);
        else if(pHashType == MAIN_SCRIPT_HASH)
            pTransaction->addP2SHOutput(pHash, sendAmount);
        else
        {
            pTransaction.clear();
            return 3; // Insufficient funds
        }

        bool sendingChange = !pSendAll && inputAmount - sendAmount -
          estimatedStandardFee((unsigned int)pTransaction->inputs.size(), 2, pFeeRate) >
          Transaction::DUST * 2;
        int changeOutputOffset = -1;
        if(sendingChange)
        {
            // Add change output
            Key *changeChainKey = mKeyStore.chainKey(pKeyOffset, 1);
            if(changeChainKey == NULL)
            {
                pTransaction.clear();
                return 4; // No change address
            }

            mKeyStore.synchronize(pKeyOffset);

            pTransaction->addP2PKHOutput(changeChainKey->getNextUnused()->hash(),
              inputAmount - sendAmount -
              estimatedStandardFee((unsigned int)pTransaction->inputs.size(), 2, pFeeRate));
            changeOutputOffset = (int)pTransaction->outputs.size() - 1;
        }

        // Sign inputs and adjust fee
        if(pSendAll)
            sendAmount = 0xffffffffffffffffL;
        Signature::HashType hashType =
          static_cast<Signature::HashType>(Signature::ALL | Signature::FORKID);
        int result = pTransaction->sign(inputAmount, pFeeRate, sendAmount,
          changeOutputOffset, fullKey, hashType, mChain.forks());
        if(result != 0)
        {
            pTransaction.clear();
            return result;
        }

        // Check Fee
        uint64_t calculatedFee = inputAmount - pTransaction->outputAmount();
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
          "Created %d byte transaction with fee of %d sat (%0.2f sat/byte)",
          pTransaction->size(), calculatedFee, (float)calculatedFee / (float)pTransaction->size());

        // TODO Transaction verification

        // Add to monitor
        mMonitor.addTransactionAnnouncement(pTransaction->hash(), 0);
        mMonitor.addTransaction(mChain, pTransaction);

        pTransaction->print(mChain.forks(), NextCash::Log::INFO);

        if(pTransmit)
        {
            mTransmittedTransToLastNode = false;

            // Transmit to every other currently "ready" node.
            mNodeLock.readLock();
            for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
                if((*node)->isReady())
                {
                    if(!mTransmittedTransToLastNode)
                        (*node)->sendTransaction(pTransaction);
                    mTransmittedTransToLastNode = !mTransmittedTransToLastNode;
                }
            mNodeLock.readUnlock();

            // Save to transmit to other nodes.
            mTransmitMutex.lock();
            mTransactionsToTransmit.push_back(pTransaction);
            mTransmitMutex.unlock();
        }

        return 0;
    }

    int Daemon::sendSpecifiedOutputsPayment(unsigned int pKeyOffset, std::vector<Output> pOutputs,
      double pFeeRate, bool pUsePending, bool pTransmit, TransactionReference &pTransaction)
    {
        if(pOutputs.size() == 0)
        {
            pTransaction.clear();
            return 7; // Invalid outputs
        }

        uint64_t sendAmount = 0;
        for(std::vector<Output>::iterator output = pOutputs.begin(); output != pOutputs.end();
          ++output)
        {
            if(output->amount < Transaction::DUST)
            {
                pTransaction.clear();
                return 6; // Below dust
            }
            if(output->script.length() == 0)
            {
                pTransaction.clear();
                return 7; // Invalid outputs
            }
            sendAmount += output->amount;
        }

        Key *fullKey = mKeyStore.fullKey(pKeyOffset);
        std::vector<BitCoin::Key *> *chainKeys = mKeyStore.chainKeys(pKeyOffset);
        if(fullKey == NULL || chainKeys == NULL)
        {
            pTransaction.clear();
            return 1;
        }

        // Get UTXOs from monitor
        std::vector<Outpoint> unspentOutputs;
        if(!mMonitor.getUnspentOutputs(chainKeys->begin(), chainKeys->end(), unspentOutputs,
          &mChain, pUsePending))
        {
            pTransaction.clear();
            return 1;
        }

        // Create transaction
        pTransaction = new Transaction();
        uint64_t inputAmount = 0;

        for(std::vector<Outpoint>::iterator output = unspentOutputs.begin();
          output != unspentOutputs.end() && (inputAmount <= sendAmount +
          estimatedStandardFee((unsigned int)pTransaction->inputs.size(), pOutputs.size() + 1,
          pFeeRate)); ++output)
        {
            pTransaction->addInput(output->transactionID, output->index);
            pTransaction->inputs.back().outpoint.output = new Output(*output->output);
            inputAmount += output->output->amount;
        }

        if(inputAmount < sendAmount +
          estimatedStandardFee((unsigned int)pTransaction->inputs.size(), 2, pFeeRate))
        {
            pTransaction.clear();
            return 2; // Insufficient funds
        }

        // Add payment outputs
        for(std::vector<Output>::iterator output = pOutputs.begin(); output != pOutputs.end();
          ++output)
            pTransaction->addOutput(*output);

        bool sendingChange = inputAmount - sendAmount -
          estimatedStandardFee((unsigned int)pTransaction->inputs.size(), pOutputs.size() + 1,
          pFeeRate) > Transaction::DUST * 2;
        int changeOutputOffset = -1;
        if(sendingChange)
        {
            // Add change output
            Key *changeChainKey = mKeyStore.chainKey(pKeyOffset, 1);
            if(changeChainKey == NULL)
            {
                pTransaction.clear();
                return 4; // No change address
            }

            mKeyStore.synchronize(pKeyOffset);

            pTransaction->addP2PKHOutput(changeChainKey->getNextUnused()->hash(),
              inputAmount - sendAmount -
              estimatedStandardFee((unsigned int)pTransaction->inputs.size(), pOutputs.size() + 1,
              pFeeRate));
            changeOutputOffset = (int)pTransaction->outputs.size() - 1;
        }

        // Sign inputs and adjust fee
        Signature::HashType hashType =
          static_cast<Signature::HashType>(Signature::ALL | Signature::FORKID);
        int result = pTransaction->sign(inputAmount, pFeeRate, sendAmount,
          changeOutputOffset, fullKey, hashType, mChain.forks());
        if(result != 0)
        {
            pTransaction.clear();
            return result;
        }

        // Check Fee
        uint64_t calculatedFee = inputAmount - pTransaction->outputAmount();
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
          "Created %d byte transaction with fee of %d sat (%0.2f sat/byte) : %s",
          pTransaction->size(), calculatedFee, (float)calculatedFee / (float)pTransaction->size(),
          pTransaction->hash().hex().text());

        // TODO Transaction verification

        // Add to monitor
        mMonitor.addTransactionAnnouncement(pTransaction->hash(), 0);
        mMonitor.addTransaction(mChain, pTransaction);

        pTransaction->print(mChain.forks(), NextCash::Log::INFO);

        if(pTransmit)
        {
            mTransmittedTransToLastNode = false;

            // Transmit to every other currently "ready" node.
            mNodeLock.readLock();
            for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
                if((*node)->isReady())
                {
                    if(!mTransmittedTransToLastNode)
                        (*node)->sendTransaction(pTransaction);
                    mTransmittedTransToLastNode = !mTransmittedTransToLastNode;
                }
            mNodeLock.readUnlock();

            // Save to transmit to other nodes.
            mTransmitMutex.lock();
            mTransactionsToTransmit.push_back(pTransaction);
            mTransmitMutex.unlock();
        }

        return 0;
    }

    void sortOutgoingNodesByPing(std::vector<Node *> &pNodes)
    {
        std::vector<Node *> nodes = pNodes;
        pNodes.clear();

        // Remove incoming and seed nodes
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();)
            if(!(*node)->isReady() || !(*node)->isOutgoing())
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
                if(highestNode == NULL ||
                  highestNode->pingTimeMilliseconds() < (*node)->pingTimeMilliseconds())
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
            return pLeft->pingTimeMilliseconds() < pRight->pingTimeMilliseconds();

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
            if(!(*node)->isReady() || !(*node)->isOutgoing())
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

    void Daemon::sendBlockRequests()
    {
        if(mInfo.spvMode)
            return;

        unsigned int pendingBlockCount = mChain.pendingBlockCount();
        unsigned int pendingSize = mChain.pendingSize();
        bool reduceOnly = pendingSize >= mInfo.pendingSize ||
          pendingBlockCount >= mInfo.pendingBlocks;
        unsigned int blocksRequestedCount = 0;

        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        std::vector<Node *> requestNodes;
        sortOutgoingNodesBySpeed(nodes);

        for(std::vector<Node *>::iterator node = nodes.begin(); node != nodes.end(); ++node)
        {
            blocksRequestedCount += (*node)->blocksRequestedCount();
            if((*node)->isReady() && !(*node)->waitingForBlockRequests() &&
              !(*node)->waitingForHeaderRequests())
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
            blocksToRequestCount = mInfo.pendingBlocks - pendingBlockCount -
              blocksRequestedCount;
            if(blocksToRequestCount > (int)requestNodes.size() * MAX_BLOCK_REQUEST)
                blocksToRequestCount = (int)requestNodes.size() * MAX_BLOCK_REQUEST;
        }

        if(blocksToRequestCount <= 0)
        {
            mNodeLock.readUnlock();
            return;
        }

        NextCash::HashList blocksToRequest;
        mChain.getBlocksNeeded(blocksToRequest, blocksToRequestCount, reduceOnly);

        if(blocksToRequest.size() == 0)
        {
            mNodeLock.readUnlock();
            return;
        }

        if(blocksToRequest.size() == 1)
        {
            if(mChain.isInSync() && mChain.lastHeaderHash() == blocksToRequest.front())
            {
                unsigned int compactsAvailable = 0;
                for(std::vector<Node *>::iterator node = requestNodes.begin();
                  node != requestNodes.end(); ++node)
                    if((*node)->compactBlocksEnabled())
                    {
                        ++compactsAvailable;
                        if((*node)->requestBlocks(blocksToRequest))
                        {
                            mNodeLock.readUnlock();
                            return;
                        }
                    }

                if(compactsAvailable == 0)
                    NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                      "No nodes with compact blocks enabled to request block from");
                else
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                      "None of the %d compact block nodes had the block to request",
                      compactsAvailable);
            }

            for(std::vector<Node *>::iterator node = requestNodes.begin();
              node != requestNodes.end(); ++node)
                if((*node)->requestBlocks(blocksToRequest))
                {
                    mNodeLock.readUnlock();
                    return;
                }

            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              "No nodes had the block to request");
            mNodeLock.readUnlock();
            return;
        }

        // Divided these up (staggered) between available nodes
        NodeRequests *nodeRequests = new NodeRequests[requestNodes.size()];
        NodeRequests *nodeRequest = nodeRequests;
        unsigned int i;

        // Assign nodes
        for(std::vector<Node *>::iterator node = requestNodes.begin(); node != requestNodes.end();
          ++node)
        {
            nodeRequest->node = *node;
            ++nodeRequest;
        }

        // Stagger out block requests
        unsigned int requestNodeOffset = 0;
        for(NextCash::HashList::iterator hash = blocksToRequest.begin();
          hash != blocksToRequest.end(); ++hash)
        {
            nodeRequests[requestNodeOffset].list.push_back(*hash);
            if(++requestNodeOffset >= requestNodes.size())
                requestNodeOffset = 0;
        }

        // Send requests to nodes
        nodeRequest = nodeRequests;
        for(i = 0;i < requestNodes.size(); ++i)
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
            if(!(*node)->isOutgoing() || !(*node)->isReady())
                node = pNodeList.erase(node);
            else
                ++node;
        std::random_shuffle(pNodeList.begin(), pNodeList.end()); // Sort Randomly
    }

    void Daemon::sendHeaderRequest()
    {
        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        randomizeOutgoing(nodes);
        bool sent = false;

        if(nodes.size() == 0)
        {
            mNodeLock.readUnlock();
            return;
        }

        // Check for node with empty last header. They haven't given headers yet.
        for(std::vector<Node *>::iterator node = nodes.begin(); node != nodes.end(); ++node)
            if((*node)->lastHeaderHash().isEmpty() && (*node)->requestHeaders())
            {
                sent = true;
                mLastHeaderRequestTime = getTime();
                mNodeLock.readUnlock();
                return;
            }

        if(!sent)
            for(std::vector<Node *>::iterator node = nodes.begin(); node != nodes.end(); ++node)
                if((*node)->requestHeaders())
                {
                    mLastHeaderRequestTime = getTime();
                    mNodeLock.readUnlock();
                    return;
                }

        mNodeLock.readUnlock();
    }

    void Daemon::sendTransactionRequests()
    {
        // Node: See not on getNeededHashes
        // NextCash::HashList transactionHashes;
        // mChain.memPool().getNeededHashes(transactionHashes);

        // if(transactionHashes.size() == 0)
            // return;

        // mNodeLock.readLock();
        // std::vector<Node *> nodes = mNodes; // Copy list of nodes
        // randomizeOutgoing(nodes);

        // if(nodes.size() == 0)
        // {
            // mNodeLock.readUnlock();
            // return;
        // }

        // if(transactionHashes.size() < 5000)
        // {
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              // "Re-requesting %d transactions from %s", transactionHashes.size(),
              // nodes.front()->name());
            // nodes.front()->requestTransactions(transactionHashes, true);
        // }
        // else
        // {
            // NextCash::HashList transactionSubList;
            // NextCash::HashList::iterator next = transactionHashes.begin();

            // for(std::vector<Node *>::iterator node = nodes.begin(); node != nodes.end(); ++node)
            // {
                // transactionSubList.clear();
                // while(next != transactionHashes.end() && transactionSubList.size() < 5000)
                    // transactionSubList.push_back(*next++);

                // if(transactionSubList.size() == 0)
                    // break;

                // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                  // "Re-requesting %d transactions from %s", transactionSubList.size(), (*node)->name());
                // (*node)->requestTransactions(transactionSubList, true);

                // if(next == transactionHashes.end())
                    // break;
            // }
        // }

        // mNodeLock.readUnlock();
    }

    void Daemon::checkSync()
    {
        // Latest header older than 3 hours.
        if(mChain.headerHeight() == 0 || getTime() - mChain.time(mChain.headerHeight()) > 10800)
            return;

        mNodeLock.readLock();
        unsigned int count = 0;
        for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
            if((*node)->isOutgoing() && (*node)->isReady() &&
              (*node)->lastHeaderHash() == mChain.lastHeaderHash())
                ++count;
        mNodeLock.readUnlock();

        if(count >= 3 && (mInfo.spvMode || mChain.blockHeight() == mChain.headerHeight()))
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
              "Chain is in sync. %d nodes have matching latest header : %s", count,
              mChain.lastHeaderHash().hex().text());
            mChain.setInSync();
        }
    }

    void Daemon::improvePing()
    {
        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes
        sortOutgoingNodesByPing(nodes);

        if(nodes.size() < maxOutgoingNodes())
        {
            mNodeLock.readUnlock();
            return;
        }

        // Calculate average
        double average = 0.0;
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
            average += (double)(*node)->pingTimeMilliseconds();
        average /= (double)nodes.size();

        // Calculate variance
        double variance = 0.0;
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
            // Sum the squared difference from the mean
            variance += NextCash::Math::square((double)(*node)->pingTimeMilliseconds() - average);
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
          "Node ping : average %d ms, cutoff %d ms", (int)average, cutoff);

        // Regularly drop some nodes to increase diversity
        int churnDrop = 0;
        if(nodes.size() >= maxOutgoingNodes())
            churnDrop = nodes.size() / 8;

        // Drop slowest
        for(std::vector<Node *>::iterator node=nodes.begin();node!=nodes.end();++node)
        {
            if((*node)->blockDownloadBytesPerSecond() > cutoff)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s - %d KB/s, %d ms ping (dropping because of ping)",
                  (*node)->name(), (int)(*node)->blockDownloadBytesPerSecond() / 1000,
                  (*node)->pingTimeMilliseconds());
                (*node)->close();
            }
            else if(churnDrop > 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s - %d KB/s, %d ms ping (dropping for churn)", (*node)->name(),
                  (int)(*node)->blockDownloadBytesPerSecond() / 1000, (*node)->pingTimeMilliseconds());
                (*node)->close();
            }
            else
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s - %d KB/s, %d ms ping", (*node)->name(),
                  (int)(*node)->blockDownloadBytesPerSecond() / 1000, (*node)->pingTimeMilliseconds());
            --churnDrop;
        }

        mNodeLock.readUnlock();
    }

    void Daemon::improveSpeed()
    {
        mNodeLock.readLock();
        std::vector<Node *> nodes = mNodes; // Copy list of nodes

        if(nodes.size() < maxOutgoingNodes() / 2)
        {
            mNodeLock.readUnlock();
            return;
        }

        // Remove nodes that aren't outgoing or aren't ready
        for(std::vector<Node *>::iterator node = nodes.begin(); node != nodes.end();)
            if(!(*node)->isOutgoing() || !(*node)->isReady())
                node = nodes.erase(node);
            else
                ++node;

        if(nodes.size() < maxOutgoingNodes() / 2)
        {
            mNodeLock.readUnlock();
            return;
        }

        // Calculate average
        double averageSpeed = 0.0;
        double averagePing = 0.0;
        int nodesWithSpeed = 0;
        for(std::vector<Node *>::iterator node = nodes.begin(); node != nodes.end(); ++node)
        {
            if((*node)->blockDownloadBytesPerSecond() != 0.0)
            {
                averageSpeed += (*node)->blockDownloadBytesPerSecond();
                ++nodesWithSpeed;
            }
            averagePing += (double)(*node)->pingTimeMilliseconds();
        }
        if(nodesWithSpeed > 0)
            averageSpeed /= (double)nodesWithSpeed;
        averagePing /= (double)nodes.size();

        // Calculate variance
        double speedVariance = 0.0;
        double pingVariance = 0.0;
        for(std::vector<Node *>::iterator node = nodes.begin(); node != nodes.end(); ++node)
        {
            // Sum the squared difference from the mean
            if((*node)->blockDownloadBytesPerSecond() != 0.0)
                speedVariance += NextCash::Math::square((*node)->blockDownloadBytesPerSecond() - averageSpeed);
            pingVariance += NextCash::Math::square((double)(*node)->pingTimeMilliseconds() - averagePing);
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
        for(std::vector<Node *>::iterator node = nodes.begin(); node != nodes.end(); ++node)
        {
            if((*node)->blockDownloadBytesPerSecond() != 0.0 && speedStandardDeviation > 0.01)
                score = ((*node)->blockDownloadBytesPerSecond() - averageSpeed) /
                  speedStandardDeviation;
            else if(nodesWithSpeed > 0) // If no speed available, assume slightly below average.
                score = (averageSpeed * -0.1) / speedStandardDeviation;
            else
                score = 0.0;
            if(pingStandardDeviation > 0.01)
                score += ((averagePing - (*node)->pingTimeMilliseconds()) /
                  pingStandardDeviation) / 2.0;
            scores.push_back(score);
        }

        // Calculate average score
        double averageScore = 0.0;
        std::vector<double>::iterator nodeScore;
        for(nodeScore = scores.begin(); nodeScore != scores.end(); ++nodeScore)
            averageScore += *nodeScore;
        averageScore /= (double)scores.size();

        // Calculate score variance
        double scoreVariance = 0.0;
        for(nodeScore = scores.begin(); nodeScore != scores.end(); ++nodeScore)
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
            for(std::vector<Node *>::iterator node = nodes.begin(); node != nodes.end(); ++node)
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
            for(std::vector<Node *>::iterator node = nodes.begin(); node != nodes.end(); ++node)
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

        double dropScore = averageScore - (scoreStandardDeviation * 1.5);
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Node Performance Summary : average speed %d KB/s, average ping %d ms, drop score %d",
          (int)averageSpeed / 1000, (int)averagePing, (int)(100.0 * dropScore));

        // Always drop some nodes so nodes with lower pings can still be found
        int churnDrop = 0;
        if(sortedScores.size() >= maxOutgoingNodes())
            churnDrop = sortedScores.size() / 8;

        // Drop slowest
        nodeScore = sortedScores.begin();
        for(std::vector<Node *>::iterator node=sortedNodes.begin();node!=sortedNodes.end();++node)
        {
            if(*nodeScore < dropScore)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s (score %d) - %d KB/s, %d ms ping (dropping because of score)",
                  (*node)->name(),
                  (int)(100.0 * *nodeScore), (int)(*node)->blockDownloadBytesPerSecond() / 1000,
                  (*node)->pingTimeMilliseconds());
                (*node)->close();
            }
            else if(churnDrop > 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s (score %d) - %d KB/s, %d ms ping (dropping for churn)",
                  (*node)->name(),
                  (int)(100.0 * *nodeScore), (int)(*node)->blockDownloadBytesPerSecond() / 1000,
                  (*node)->pingTimeMilliseconds());
                (*node)->close();
            }
            else
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                  "Sorted Nodes : %s (score %d) - %d KB/s, %d ms ping", (*node)->name(),
                  (int)(100.0 * *nodeScore), (int)(*node)->blockDownloadBytesPerSecond() / 1000,
                  (*node)->pingTimeMilliseconds());

            --churnDrop;
            ++nodeScore;
        }

        mNodeLock.readUnlock();
    }

    void Daemon::announce()
    {
        BlockReference block = mChain.blockToAnnounce();
        if(block)
        {
            // Announce to all nodes
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Announcing block : %s", block->header.hash().hex().text());
            mNodeLock.readLock();
            for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
                (*node)->announceBlock(block);
            mNodeLock.readUnlock();
        }

        TransactionList transactionList;
        mChain.memPool().getToAnnounce(transactionList, 0);
        if(transactionList.size() == 0)
            return;
        NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_DAEMON_LOG_NAME,
          "Announcing %d transactions", transactionList.size());

        mNodeLock.readLock();
        for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
            (*node)->addTransactionAnnouncements(transactionList);

        for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
            (*node)->finalizeAnnouncments();
        mNodeLock.readUnlock();
    }

    void Daemon::runManage(void *pParameter)
    {
        Daemon *daemon = (Daemon *)pParameter;
        if(daemon == NULL)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Manage thread failed to get daemon");
            return;
        }
        daemon->manage();
    }

    void Daemon::manage()
    {
        try
        {
            if(!loadWallets())
                requestStop();

            if(!loadChain())
                requestStop();
        }
        catch(std::bad_alloc pException)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME,
              "Bad allocation while loading : %s", pException.what());
            requestStop();
            return;
        }
        catch(std::exception pException)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME,
              "Exception while loading : %s", pException.what());
            requestStop();
            return;
        }

        // If another thread started loading first, then wait for it to finish.
        while((mLoadingWallets || mLoadingChain) && !mStopping)
            NextCash::Thread::sleep(100);

        if(mStopping || !mWalletsLoaded || !mChainLoaded)
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

        mProcessThread = new NextCash::Thread("Process", runProcess, this);
        if(mProcessThread == NULL)
        {
            requestStop();
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Failed to create process thread");
            return;
        }

        std::vector<Peer *> peers;
        uint64_t servicesMask = Message::VersionData::FULL_NODE_BIT;
        if(mInfo.spvMode)
            servicesMask |= Message::VersionData::BLOOM_NODE_BIT;
        mInfo.getRandomizedPeers(peers, Daemon::OKAY_RATING, servicesMask, CHAIN_UNKNOWN);

        if(peers.size() > 250)
        {
            mScanThread = NULL;
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Not starting scan thread because there are already %d okay peers.", peers.size());
        }
        else
        {
            mScanThread = new NextCash::Thread("Scan", runScan, this);
            if(mScanThread == NULL)
            {
                requestStop();
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
                  "Failed to create scan thread");
                return;
            }
        }
#endif

        Time startTime = getTime();
        Time lastStatReportTime = startTime;
        Time lastSyncCheck = startTime;
        Time lastRequestCheckTime = startTime;
        Time lastInfoSaveTime = startTime;
        Time lastImprovement = startTime;
        Time lastTransactionRequest = startTime;
        Time lastTransactionTransmit = startTime;
        Time time;
#ifdef PROFILER_ON
        Time lastProfilerWrite = startTime;
#endif

        while(!mStopping)
        {
            time = getTime();
            if(!mKeysSynchronized && mChain.isInSync() &&
              mMonitor.height() == mChain.headerHeight())
            {
                mKeyStore.setAllSynchronized();
                mKeysSynchronized = mKeyStore.allAreSynchronized();
                mMonitor.incrementChange();
            }

            if(mFinishMode == FINISH_ON_SYNC && mChain.isInSync() &&
              (mKeyStore.size() == 0 || mMonitor.height() == mChain.headerHeight()) &&
              (mFinishTime == 0 || mFinishTime <= time))
            {
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Stopping because of finish on sync");
                requestStop();
                break;
            }

            if(mStopping)
                break;

            if(time - lastStatReportTime > 180)
            {
                lastStatReportTime = getTime();
                printStatistics();
            }

            if(mStopping)
                break;

#ifdef ANDROID
            if(mFinishMode != FINISH_ON_REQUEST &&
              peerCount() == 0 && time - mLastConnectionActive > 60)
            {
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Stopping because of lack of network connectivity");
                requestStop();
                break;
            }
#endif

            time = getTime();
            if(time - lastTransactionTransmit > 10)
            {
                lastTransactionTransmit = getTime();
                transmitTransactions();
            }

            if(mStopping)
                break;

            if(mChain.headersNeeded())
                sendHeaderRequest();

            if(!mChain.isInSync())
            {
                time = getTime();
                if(mChain.blocksNeeded() || time - lastRequestCheckTime > 30 ||
                  (mChain.pendingBlockCount() == 0 && time - lastRequestCheckTime > 10))
                {
                    lastRequestCheckTime = time;
                    sendBlockRequests();
                }

                if(time - lastSyncCheck > 10)
                {
                    checkSync();
                    lastSyncCheck = time;
                }

                if(mStopping)
                    break;
            }
            else
            {
                if(mChain.blocksNeeded())
                    sendBlockRequests();
                if(getTime() - lastTransactionRequest > 2)
                {
                    sendTransactionRequests();
                    lastTransactionRequest = getTime();
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
                mChain.forks().save();
            }

            if(mStopping)
                break;

            time = getTime();
            if(time - mStatistics.startTime > 3600)
                saveStatistics();

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
            for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
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
            NextCash::Thread::sleep(1000);
#endif

#ifdef PROFILER_ON
            time = getTime();
            if(time - lastProfilerWrite > 3600)
            {
                NextCash::printProfilerDataToLog(NextCash::Log::VERBOSE);
                NextCash::resetProfilers();
                lastProfilerWrite = time;
            }
#endif
        }
    }

    void Daemon::runProcess(void *pParameter)
    {
        Daemon *daemon = (Daemon *)pParameter;
        if(daemon == NULL)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Process thread failed to get daemon");
            return;
        }
        while(!daemon->mStopping)
        {
            daemon->process();
            NextCash::Thread::sleep(100);
        }
    }

    void Daemon::process()
    {
        unsigned int count = 0;
        while(mChain.process() && ++count < 50);

        if(mStopping)
            return;

        if(mInfo.spvMode)
        {
            if(mLastHeaderHash != mChain.lastHeaderHash() || getTime() - mLastMonitorProcess > 2)
            {
                mMonitor.process(mChain, false);
                mLastMonitorProcess = getTime();
                mLastHeaderHash = mChain.lastHeaderHash();
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

            if(getTime() - mLastMemPoolProcessTime > 30)
            {
                mChain.memPool().process();
                mLastMemPoolProcessTime = getTime();
            }

            if(mStopping)
                return;

            Time time = getTime();
            if((time - mLastDataSaveTime > 30 && mChain.saveDataNeeded()) ||
              time - mLastDataSaveTime > 3600)
            {
                mChain.saveData(false);
                mLastDataSaveTime = getTime();
            }

            if(mStopping)
                return;
        }
    }

    void Daemon::runScan(void *pParameter)
    {
        Daemon *daemon = (Daemon *)pParameter;
        if(daemon == NULL)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Scan thread failed to get daemon");
            return;
        }
        std::list<IPBytes> recentIPs;
        while(!daemon->mStopping)
            daemon->scan(recentIPs);
    }

    class ScanThreadData
    {
    public:

        ScanThreadData(Daemon *pDaemon, std::list<Daemon::IPBytes> *pRecentIPs) :
          mutex("ScanThreadData"), recentIPLock("ScanRecentIP"), info(Info::instance())
        {
            daemon = pDaemon;
            recentIPs = pRecentIPs;
            uint64_t servicesMask = Message::VersionData::FULL_NODE_BIT;
            if(info.spvMode)
                servicesMask |= Message::VersionData::BLOOM_NODE_BIT;
            info.getRandomizedPeers(peers, Daemon::USABLE_RATING, servicesMask, CHAIN_UNKNOWN,
              Daemon::OKAY_RATING - 1);
            nextPeer = peers.begin();
            stop = false;
            done = false;
        }
        ~ScanThreadData()
        {
        }

        NextCash::Mutex mutex, recentIPLock;
        Info &info;
        Daemon *daemon;
        std::vector<Peer *> peers;
        std::vector<Peer *>::iterator nextPeer;
        std::list<Daemon::IPBytes> *recentIPs;
        bool stop, done;

        Peer *getNext()
        {
            Peer *result = NULL;
            mutex.lock();
            if(nextPeer == peers.end())
                done = true;
            else
            {
                result = *nextPeer;
                ++nextPeer;
            }
            mutex.unlock();
            return result;
        }

    };

    void scanThreadRun(void *pParameter)
    {
        ScanThreadData *data = (ScanThreadData *)pParameter;
        if(data == NULL)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_DAEMON_LOG_NAME,
              "Scan thread parameter is null. Stopping");
            return;
        }

        Peer *peer;
        NextCash::Network::Connection *connection;
        Node *scanNode;
        bool found;
        while(!data->stop)
        {
            peer = data->getNext();
            if(peer == NULL)
                break;

            data->recentIPLock.lock();
            found = false;
            for(std::list<Daemon::IPBytes>::iterator recent = data->recentIPs->begin();
              recent != data->recentIPs->end(); ++recent)
                if(*recent == peer->address.ipv6Bytes())
                {
                    found = true;
                    break;
                }
            if(!found)
            {
                data->recentIPs->emplace_back(peer->address.ipv6Bytes());
                while(data->recentIPs->size() > RECENT_IP_COUNT)
                    data->recentIPs->pop_front();
            }
            data->recentIPLock.unlock();

            NextCash::Thread::sleep(100);

            if(found)
                continue;

            try
            {
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_DAEMON_LOG_NAME,
                  "Scanning : %s", peer->address.text().text());
                connection = new NextCash::Network::Connection(peer->address, 5);
            }
            catch(std::bad_alloc &pBadAlloc)
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
                  "Bad allocation while allocating new scan connection : %s",
                  pBadAlloc.what());
                continue;
            }
            catch(...)
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
                  "Bad allocation while allocating new scan connection : unknown");
                continue;
            }

            NextCash::Thread::sleep(100);

            if(!connection->isOpen())
            {
                data->info.addPeerFail(peer->address, 1, 1);
                delete connection;
            }
            else
            {
                try
                {
                    scanNode = new Node(connection, Node::SCAN, peer->services, data->daemon,
                      &data->stop, false);
                }
                catch(std::bad_alloc &pBadAlloc)
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
                      "Bad allocation while allocating new scan node : %s", pBadAlloc.what());
                    delete connection;
                    continue;
                }
                catch(...)
                {
                    NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
                      "Bad allocation while allocating new scan node : unknown");
                    delete connection;
                    continue;
                }

                delete scanNode;
            }

            NextCash::Thread::sleep(100);
        }
    }

    void Daemon::scan(std::list<IPBytes> &pRecentIPs)
    {
        if(mStopping)
            return;

        // Sleep for 2 seconds to let regular connections happen first.
        for(unsigned int i = 0; i < 2; ++i)
        {
            NextCash::Thread::sleep(1000);
            if(mStopping)
                return;
        }

        // Connect to a random zero score node to check for connectivity.
        ScanThreadData threadData(this, &pRecentIPs);
        if(threadData.peers.size() < 10)
            return;

        // Start threads
        unsigned int threadCount = mInfo.threadCount;
        NextCash::Thread *threads[threadCount];
        NextCash::String threadName;
        for(unsigned int i = 0; i < threadCount; ++i)
        {
            threadName.writeFormatted("Scan %d", i);
            threads[i] = new NextCash::Thread(threadName, scanThreadRun, &threadData);
        }

        NextCash::Thread::sleep(1);

        while(!mStopping && !threadData.done)
            NextCash::Thread::sleep(200);

        // Delete threads
        NextCash::Log::add(NextCash::Log::DEBUG, BITCOIN_DAEMON_LOG_NAME, "Deleting scan threads");
        threadData.stop = true;
        for(unsigned int i = 0; i < threadCount; ++i)
            delete threads[i];
    }

    bool Daemon::addNode(NextCash::Network::Connection *pConnection, uint32_t pType,
      uint64_t pServices, bool pAnnounceCompact)
    {
        mLastConnectionActive = getTime();

        // Check if IP is on reject list
        if(isRejectedIP(pConnection->ip().ipv6Bytes()))
        {
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_DAEMON_LOG_NAME,
                  "Rejecting connection from IP %s", pConnection->ip().text().text());
                delete pConnection;
                return false;
        }

        Node *node;
        try
        {
            node = new Node(pConnection, pType, pServices, this, NULL, pAnnounceCompact);
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
        if(pType & Node::INCOMING)
        {
            ++mStatistics.incomingConnections;
            ++mIncomingNodes;
        }
        else if(!(pType & Node::SEED))
        {
            ++mStatistics.outgoingConnections;
            ++mOutgoingNodes;
        }
        mNodeLock.writeUnlock();
        return true;
    }

    bool Daemon::addNode(NextCash::Network::IPAddress &pIPAddress, uint32_t pType,
      uint64_t pServices, bool pAnnounceCompact)
    {
        Node *node;
        try
        {
            node = new Node(pIPAddress, pType, pServices, this, pAnnounceCompact);
        }
        catch(std::bad_alloc &pBadAlloc)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Bad allocation while allocating new node : %s", pBadAlloc.what());
            return false;
        }
        catch(...)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Bad allocation while allocating new node : unknown");
            return false;
        }

        mNodeLock.writeLock("Add");
        mNodes.push_back(node);
        ++mNodeCount;
        if(!(pType & Node::SEED))
            ++mOutgoingNodes;
        mNodeLock.writeUnlock();
        return true;
    }

    const Seed *Daemon::getRandomSeed()
    {
        if(!mSeedsRandomized || mRandomSeedsChainID != mInfo.chainID)
        {
            mRandomSeeds.clear();
            unsigned int seedCount;
            const Seed *seed;
            switch(mInfo.chainID)
            {
            case CHAIN_ABC:
                seed = SEEDS_ABC;
                seedCount = sizeof(SEEDS_ABC) / sizeof(*SEEDS_ABC);
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Loading %d ABC seeds", seedCount);
                for(unsigned int i = 0; i < seedCount; ++i, ++seed)
                    mRandomSeeds.push_back(seed);
                break;
            case CHAIN_SV:
                seed = SEEDS_SV;
                seedCount = sizeof(SEEDS_SV) / sizeof(*SEEDS_SV);
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                  "Loading %d SV seeds", seedCount);
                for(unsigned int i = 0; i < seedCount; ++i, ++seed)
                    mRandomSeeds.push_back(seed);
                break;
            default:
                return NULL;
            }

            std::random_shuffle(mRandomSeeds.begin(), mRandomSeeds.end());
            mSeedsRandomized = true;
            mRandomSeedsChainID = mInfo.chainID;
        }

        if(mRandomSeeds.size() > 0)
        {
            const Seed *result = mRandomSeeds.back();
            mRandomSeeds.pop_back();
            return result;
        }
        else
            return NULL;
    }

    bool Daemon::querySeeds()
    {
        NextCash::Network::IPAddress ip;
        unsigned int seedConnections = 0;
        const Seed *seed;
        bool result = false;

        mNodeLock.readLock();
        for(std::vector<Node *>::iterator node = mNodes.begin();
          node != mNodes.end() && !mStopping; ++node)
            if((*node)->isSeed())
                ++seedConnections;
        mNodeLock.readUnlock();

        mQueryingSeed = true;
        while(seedConnections < 16)
        {
            seed = getRandomSeed();
            if(seed == NULL)
                break;

            ip.set(NextCash::Network::IPAddress::IPV6, seed->ip, seed->port);

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Connecting to seed %s", ip.text().text());
            if(addNode(ip, Node::SEED, 0, false))
            {
                ++seedConnections;
                result = true;
            }
            else
                break;
        }
        mQueryingSeed = false;
        return result;
    }

    unsigned int Daemon::recruitPeers()
    {
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
          "Recruiting %s peers", chainName(mInfo.chainID));
        std::vector<Peer *> peers;
        unsigned int newCount = 0;
        bool found;
        uint64_t servicesMask = 0;// = Message::VersionData::FULL_NODE_BIT;
        unsigned int connectionsSinceLast = mConnectionsSinceLastRecruit;
#ifdef SINGLE_THREAD
        Time lastNodeProcess = getTime();
#endif

        mConnectionsSinceLastRecruit = 0;
        mConnecting = true;

        mNodeLock.readLock();
        unsigned int goodCount = 0;
        unsigned int allCount = 0;
        unsigned int compactCount = 0;
        for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
        {
            if((*node)->isOutgoing())
            {
                if((*node)->isGood())
                    ++goodCount;
                ++allCount;
            }
            if((*node)->announceBlocksCompact())
                ++compactCount;
        }
        mNodeLock.readUnlock();

        if(mInfo.spvMode)
            servicesMask |= Message::VersionData::BLOOM_NODE_BIT;

        if(!mStopping && goodCount < mGoodNodeMax)
        {
            // Try peers with good ratings first
            mInfo.getRandomizedPeers(peers, GOOD_RATING, servicesMask, mInfo.chainID);
            if(peers.size() < 50)
                mInfo.getRandomizedPeers(peers, FALLBACK_GOOD_RATING, servicesMask, mInfo.chainID);
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Found %d good peers", peers.size());
            for(std::vector<Peer *>::iterator peer = peers.begin(); peer != peers.end() &&
              !mStopping && goodCount < mGoodNodeMax; ++peer)
            {
                // Skip nodes already connected
                found = false;
                mNodeLock.readLock();
                for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end() &&
                  !mStopping; ++node)
                    if((*node)->ip() == (*peer)->address)
                    {
                        found = true;
                        break;
                    }
                if(found)
                {
                    mNodeLock.readUnlock();
                    continue;
                }

                for(std::list<IPBytes>::iterator recent = mRecentIPs.begin();
                  recent != mRecentIPs.end(); ++recent)
                    if(*recent == (*peer)->address.ipv6Bytes())
                    {
                        found = true;
                        break;
                    }
                if(found)
                {
                    mNodeLock.readUnlock();
                    continue;
                }

                mRecentIPs.emplace_back((*peer)->address.ipv6Bytes());
                while(mRecentIPs.size() > RECENT_IP_COUNT)
                    mRecentIPs.erase(mRecentIPs.begin());

                mNodeLock.readUnlock();

                if(addNode((*peer)->address, Node::GOOD, (*peer)->services, compactCount < 3))
                {
                    if(compactCount < 3)
                        ++compactCount;
                    ++goodCount;
                    ++allCount;
                    ++newCount;
#ifdef SINGLE_THREAD
                    break;
#endif
                }

                if(mStopping)
                    break;

#ifdef SINGLE_THREAD
                if(getTime() - lastNodeProcess > 5)
                {
                    // Process nodes so they don't wait a long time
                    mNodeLock.readLock();
                    for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end() &&
                      !mStopRequested; ++node)
                        (*node)->process();
                    mNodeLock.readUnlock();
                    lastNodeProcess = getTime();
                }
#endif
            }
        }

        if(!mStopping && allCount < maxOutgoingNodes() - 2)
        {
            // Try peers with okay ratings
            peers.clear();
            mInfo.getRandomizedPeers(peers, OKAY_RATING, servicesMask, mInfo.chainID);
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Found %d okay peers", peers.size());
            Time startTime = getTime();
            for(std::vector<Peer *>::iterator peer = peers.begin(); peer != peers.end() &&
              !mStopping && allCount < maxOutgoingNodes() - 3; ++peer)
            {
                // Skip nodes already connected
                found = false;
                mNodeLock.readLock();
                for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end() &&
                  !mStopping; ++node)
                    if((*node)->ip() == (*peer)->address)
                    {
                        found = true;
                        break;
                    }
                if(found)
                {
                    mNodeLock.readUnlock();
                    continue;
                }

                for(std::list<IPBytes>::iterator recent = mRecentIPs.begin();
                  recent != mRecentIPs.end(); ++recent)
                    if(*recent == (*peer)->address.ipv6Bytes())
                    {
                        found = true;
                        break;
                    }
                if(found)
                {
                    mNodeLock.readUnlock();
                    continue;
                }

                mNodeLock.readUnlock();

                mRecentIPs.emplace_back((*peer)->address.ipv6Bytes());
                while(mRecentIPs.size() > RECENT_IP_COUNT)
                    mRecentIPs.erase(mRecentIPs.begin());

                if(addNode((*peer)->address, Node::NONE, (*peer)->services, compactCount < 3))
                {
                    if(compactCount < 3)
                        ++compactCount;
                    ++allCount;
                    ++newCount;
#ifdef SINGLE_THREAD
                    break;
#endif
                }

                // Max 30 seconds connecting to usable peers
                if(mStopping || getTime() - startTime > 30)
                    break;

#ifdef SINGLE_THREAD
                if(getTime() - lastNodeProcess > 5)
                {
                    // Process nodes so they don't wait a long time
                    mNodeLock.readLock();
                    for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end() &&
                      !mStopRequested; ++node)
                        (*node)->process();
                    mNodeLock.readUnlock();
                    lastNodeProcess = getTime();
                }
#endif
            }
        }

        if(!mStopping && allCount < maxOutgoingNodes() && mInfo.chainID != CHAIN_UNKNOWN)
        {
            // Try peers on matching chain with no ratings
            peers.clear();
            mInfo.getRandomizedPeers(peers, USABLE_RATING, servicesMask, mInfo.chainID);
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Found %d usable chain peers", peers.size());
            Time startTime = getTime();
            for(std::vector<Peer *>::iterator peer = peers.begin(); peer != peers.end() &&
              !mStopping && allCount < maxOutgoingNodes(); ++peer)
            {
                // Skip nodes already connected
                found = false;
                mNodeLock.readLock();
                for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end() &&
                  !mStopping; ++node)
                    if((*node)->ip() == (*peer)->address)
                    {
                        found = true;
                        break;
                    }
                if(found)
                {
                    mNodeLock.readUnlock();
                    continue;
                }

                for(std::list<IPBytes>::iterator recent = mRecentIPs.begin();
                  recent != mRecentIPs.end(); ++recent)
                    if(*recent == (*peer)->address.ipv6Bytes())
                    {
                        found = true;
                        break;
                    }
                if(found)
                {
                    mNodeLock.readUnlock();
                    continue;
                }

                mNodeLock.readUnlock();

                mRecentIPs.emplace_back((*peer)->address.ipv6Bytes());
                while(mRecentIPs.size() > RECENT_IP_COUNT)
                    mRecentIPs.pop_front();

                if(addNode((*peer)->address, Node::NONE, 0, compactCount < 3))
                {
                    if(compactCount < 3)
                        ++compactCount;
                    ++allCount;
                    ++newCount;
#ifdef SINGLE_THREAD
                    break;
#endif
                }

                // Max 30 seconds connecting to usable peers
                if(mStopping || getTime() - startTime > 30)
                    break;

#ifdef SINGLE_THREAD
                if(getTime() - lastNodeProcess > 5)
                {
                    // Process nodes so they don't wait a long time
                    mNodeLock.readLock();
                    for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end() &&
                      !mStopRequested; ++node)
                        (*node)->process();
                    mNodeLock.readUnlock();
                    lastNodeProcess = getTime();
                }
#endif
            }
        }

        if(!mStopping && allCount < maxOutgoingNodes())
        {
            // Try peers with no ratings
            peers.clear();
            mInfo.getRandomizedPeers(peers, USABLE_RATING, servicesMask, CHAIN_UNKNOWN);
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
              "Found %d usable peers", peers.size());
            Time startTime = getTime();
            for(std::vector<Peer *>::iterator peer = peers.begin(); peer != peers.end() &&
              !mStopping && allCount < maxOutgoingNodes(); ++peer)
            {
                // Skip nodes already connected
                found = false;
                mNodeLock.readLock();
                for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end() &&
                  !mStopping; ++node)
                    if((*node)->ip() == (*peer)->address)
                    {
                        found = true;
                        break;
                    }
                if(found)
                {
                    mNodeLock.readUnlock();
                    continue;
                }

                for(std::list<IPBytes>::iterator recent = mRecentIPs.begin();
                  recent != mRecentIPs.end(); ++recent)
                    if(*recent == (*peer)->address.ipv6Bytes())
                    {
                        found = true;
                        break;
                    }
                if(found)
                {
                    mNodeLock.readUnlock();
                    continue;
                }

                mNodeLock.readUnlock();

                mRecentIPs.emplace_back((*peer)->address.ipv6Bytes());
                while(mRecentIPs.size() > RECENT_IP_COUNT)
                    mRecentIPs.pop_front();

                if(addNode((*peer)->address, Node::NONE, 0, compactCount < 3))
                {
                    if(compactCount < 3)
                        ++compactCount;
                    ++allCount;
                    ++newCount;
#ifdef SINGLE_THREAD
                    break;
#endif
                }

                // Max 30 seconds connecting to usable peers
                if(mStopping || getTime() - startTime > 30)
                    break;

#ifdef SINGLE_THREAD
                if(getTime() - lastNodeProcess > 5)
                {
                    // Process nodes so they don't wait a long time
                    mNodeLock.readLock();
                    for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end() &&
                      !mStopRequested; ++node)
                        (*node)->process();
                    mNodeLock.readUnlock();
                    lastNodeProcess = getTime();
                }
#endif
            }
        }

        if(!mStopping && connectionsSinceLast == 0 && peers.size() < 20000)
            querySeeds();

        mConnecting = false;
        return newCount;
    }

    void Daemon::cleanNodes()
    {
        // Check for black listed nodes
        std::vector<unsigned int> blackListedNodeIDs = mChain.invalidNodeIDs();

        // Drop all closed nodes
        std::vector<Node *> toDelete;
        bool dropped;
        mNodeLock.writeLock("Clean");
        for(std::vector<Node *>::iterator node=mNodes.begin();node!=mNodes.end();)
            if((*node)->isStopped())
            {
                mLastConnectionActive = getTime();
                if((*node)->wasRejected())
                    addRejectedIP((*node)->ip().ipv6Bytes());
                --mNodeCount;
                if((*node)->isIncoming())
                    --mIncomingNodes;
                else if(!(*node)->isSeed())
                    --mOutgoingNodes;
                toDelete.push_back(*node);
                node = mNodes.erase(node);
            }
            else
            {
                dropped = false;
                for(std::vector<unsigned int>::iterator nodeID = blackListedNodeIDs.begin();
                  nodeID != blackListedNodeIDs.end(); ++nodeID)
                    if(*nodeID == (*node)->id())
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_DAEMON_LOG_NAME,
                          "%s Dropping. Black listed", (*node)->name());
                        dropped = true;
                        addRejectedIP((*node)->ip().ipv6Bytes());
                        (*node)->close();
                        --mNodeCount;
                        if((*node)->isIncoming())
                            --mIncomingNodes;
                        else if(!(*node)->isSeed())
                            --mOutgoingNodes;
                        toDelete.push_back(*node);
                        node = mNodes.erase(node);
                        break;
                    }

                if(!dropped)
                    ++node;
            }
        mNodeLock.writeUnlock();

        for(std::vector<Node *>::iterator node = toDelete.begin(); node != toDelete.end(); ++node)
        {
            (*node)->collectStatistics(mStatistics);
            delete *node;
        }
    }

    void Daemon::resetNodes()
    {
        mNodeLock.readLock();
        for(std::vector<Node *>::iterator node = mNodes.begin(); node != mNodes.end(); ++node)
            (*node)->close();
        mNodeLock.readUnlock();
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
        for(std::vector<RequestChannel *>::iterator requestChannel = mRequestChannels.begin();
          requestChannel != mRequestChannels.end();)
            if((*requestChannel)->isStopped())
            {
                toDelete.push_back(*requestChannel);
                requestChannel = mRequestChannels.erase(requestChannel);
            }
            else
                ++requestChannel;
        mRequestsLock.writeUnlock();

        for(std::vector<RequestChannel *>::iterator requestChannel = toDelete.begin();
          requestChannel != toDelete.end(); ++requestChannel)
            delete *requestChannel;
    }

    void Daemon::runConnections(void *pParameter)
    {
        Daemon *daemon = (Daemon *)pParameter;
        if(daemon == NULL)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Connection thread failed to get daemon");
            return;
        }

        if (daemon->mOutgoingNodeMax >= daemon->mInfo.maxConnections)
            daemon->mMaxIncoming = 0;
        else
            daemon->mMaxIncoming =
              daemon->mInfo.maxConnections - daemon->mOutgoingNodeMax;

        while(!daemon->mStopping)
        {
            daemon->handleConnections();
            NextCash::Thread::sleep(500);
        }

        if(daemon->mNodeListener != NULL)
            delete daemon->mNodeListener;
    }

    void Daemon::addRejectedIP(const uint8_t *pIP)
    {
        mRejectedIPs.emplace_back(pIP);
        while(mRejectedIPs.size() > RECENT_IP_COUNT)
            mRejectedIPs.erase(mRejectedIPs.begin());
    }

    bool Daemon::isRejectedIP(const uint8_t *pIPv6Bytes)
    {
        for(std::vector<IPBytes>::iterator ip = mRejectedIPs.begin();
          ip != mRejectedIPs.end(); ++ip)
            if(*ip == pIPv6Bytes)
                return true;
        return false;
    }

    void Daemon::handleConnections()
    {
        NextCash::Network::Connection *newConnection;

        if(getTime() - mLastCleanTime > 10)
        {
            mLastCleanTime = getTime();
            cleanNodes();
        }

        if(mStopping)
            return;

        if(mOutgoingNodes < maxOutgoingNodes())
            recruitPeers();

        if(mStopping)
            return;

        if(!mInfo.spvMode)
        {
            if(mNodeListener == NULL)
            {
                if(mIncomingNodes < mMaxIncoming && mChain.isInSync())
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
                {
                    if(isRejectedIP(newConnection->ip().ipv6Bytes()))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                          BITCOIN_DAEMON_LOG_NAME, "Rejecting IP : %s",
                          newConnection->ip().text().text());
                        delete newConnection;
                    }
                    else if(newConnection->isOpen())
                    {
                        if(addNode(newConnection, Node::INCOMING, 0, false) &&
                          mIncomingNodes >= mMaxIncoming)
                        {
                            delete mNodeListener;
                            mNodeListener = NULL;
                            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_DAEMON_LOG_NAME,
                              "Stopped listening for incoming connections because of connection limit");
                            break;
                        }
                    }
                    else
                        delete newConnection;
                }
            }
        }
    }

    void Daemon::runRequests(void *pParameter)
    {
        Daemon *daemon = (Daemon *)pParameter;
        if(daemon == NULL)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_DAEMON_LOG_NAME,
              "Request thread failed to get daemon");
            return;
        }

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

        if(getTime() - mLastRequestCleanTime > 10)
        {
            mLastRequestCleanTime = getTime();
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
