/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "mem_pool.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#include "profiler_setup.hpp"
#endif

#include "log.hpp"
#include "chain.hpp"

#define BITCOIN_MEM_POOL_LOG_NAME "MemPool"


namespace BitCoin
{
    MemPool::MemPool(Chain *pChain) : mInfo(Info::instance()),
      mRequestedHashesLock("RequestedHashes"), mLock("MemPool"), mPipeLineLock("PipeLine")
    {
        mChain = pChain;
        mSize = 0;
        mPendingSize = 0;
        mStopping = false;
        mPipeLineThreadCount = mInfo.threadCount;
        mPipeLineThreads = new NextCash::Thread*[mInfo.threadCount];
        NextCash::String threadName;
        for(unsigned int i = 0; i < mPipeLineThreadCount; ++i)
        {
            threadName.writeFormatted("MemPool %d", i);
            mPipeLineThreads[i] = new NextCash::Thread(threadName, processPipeLine, this);
        }
    }

    MemPool::~MemPool()
    {
        mLock.writeLock("Destroy");
    }

    void MemPool::stop()
    {
        if(mStopping) // Already stopping
            return;
        mStopping = true;
        for(unsigned int i = 0; i < mPipeLineThreadCount; ++i)
            delete mPipeLineThreads[i];
        delete[] mPipeLineThreads;
        mPipeLineThreads = NULL;
    }

    bool MemPool::addRequested(const NextCash::Hash &pHash, unsigned int pNodeID, bool pMissing,
      bool pRetry)
    {
        bool result = false;
        Time time = getTime();
        RequestedHash *requestedHash;

        mRequestedHashesLock.lock();

        requestedHash = (RequestedHash *)mRequestedHashes.get(pHash);
        if(requestedHash == NULL)
        {
            mRequestedHashes.insert(new RequestedHash(pHash, pNodeID, time, pMissing));
            result = true;
        }
        else
        {
            if(pRetry && requestedHash->requestAttempts > 2)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Requested transaction failed %d times : %s",
                  requestedHash->requestAttempts, requestedHash->getHash().hex().text());
                mRequestedHashes.remove(pHash);
            }
            else if(requestedHash->nodeID != pNodeID &&
              (requestedHash->time == 0 || time - requestedHash->time > 4))
            {
                requestedHash->nodeID = pNodeID;
                requestedHash->time = time;
                ++requestedHash->requestAttempts;
                requestedHash->missing = pMissing;
                result = true;
            }
        }

        mRequestedHashesLock.unlock();
        return result;
    }

    void MemPool::removeRequested(const NextCash::Hash &pHash)
    {
        mRequestedHashesLock.lock();
        mRequestedHashes.remove(pHash);
        mRequestedHashesLock.unlock();
    }

    void MemPool::markTransactions(NextCash::HashList &pList, unsigned int pNodeID)
    {
        RequestedHash *requestedHash;
        Time time = getTime();

        mRequestedHashesLock.lock();
        for(NextCash::HashList::iterator hash = pList.begin(); hash != pList.end(); ++hash)
        {
            requestedHash = (RequestedHash *)mRequestedHashes.get(*hash);
            if(requestedHash != NULL)
            {
                requestedHash->nodeID = pNodeID;
                requestedHash->time = time;
                ++requestedHash->requestAttempts;
                requestedHash->missing = false;
            }
        }
        mRequestedHashesLock.unlock();
    }

    void MemPool::release(unsigned int pNodeID)
    {
        mRequestedHashesLock.lock();
        for(NextCash::HashSet::Iterator hash = mRequestedHashes.begin();
          hash != mRequestedHashes.end(); ++hash)
            if(((RequestedHash *)*hash)->nodeID == pNodeID)
                ((RequestedHash *)*hash)->time = 0;
        mRequestedHashesLock.unlock();
    }

    bool MemPool::release(const NextCash::Hash &pHash, unsigned int pNodeID)
    {
        bool result = false;
        mRequestedHashesLock.lock();
        RequestedHash *requestedHash = (RequestedHash *)mRequestedHashes.get(pHash);
        if(requestedHash != NULL && requestedHash->nodeID == pNodeID)
        {
            result = requestedHash->missing;
            requestedHash->time = 0;
        }
        mRequestedHashesLock.unlock();
        return result;
    }

    TransactionReference MemPool::getPipeLineTransaction()
    {
        TransactionReference result;
        mLock.writeLock("Get PipeLine");
        mPipeLineLock.lock();
        if(mPipeLineQueue.size() > 0)
        {
            result = mPipeLineTransactions.getAndRemove(mPipeLineQueue.front());
            mPipeLineQueue.pop_front();
            if(result)
                mValidatingTransactions.insertSorted(result->hash());
        }
        mPipeLineLock.unlock();
        mLock.writeUnlock();
        return result;
    }

    void MemPool::processPipeLine(void *pParameter)
    {
        MemPool *memPool = (MemPool *)pParameter;
        if(memPool == NULL)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
              "Process mempool thread parameter is null. Stopping");
            return;
        }

        TransactionReference transaction;
        while(!memPool->mStopping)
        {
            transaction = memPool->getPipeLineTransaction();
            if(!transaction)
            {
                if(memPool->mStopping)
                    break;
                NextCash::Thread::sleep(200);
                continue;
            }

            memPool->addInternal(transaction);
        }
    }

    MemPool::HashStatus MemPool::hashStatus(const NextCash::Hash &pHash, unsigned int pNodeID,
      bool pRetry)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_STATUS_ID, PROFILER_MEMPOOL_STATUS_NAME), true);
#endif

        mLock.readLock();

        HashStatusTime *status = (HashStatusTime *)mHashStatuses.get(pHash);
        if(status != NULL)
        {
            HashStatus result = status->status;
            mLock.readUnlock();
            return result;
        }

        if(haveTransaction(pHash))
        {
            mLock.readUnlock();
            return HASH_ALREADY_HAVE;
        }

        mPipeLineLock.lock();
        bool isProcessing = mPipeLineTransactions.contains(pHash);
        mPipeLineLock.unlock();
        if(isProcessing)
        {
            mLock.readUnlock();
            return HASH_PROCESSING;
        }

        if(!addRequested(pHash, pNodeID, false, pRetry))
        {
            mLock.readUnlock();
            return HASH_REQUESTED;
        }

        mLock.readUnlock();
        return HASH_NEED;
    }

    void MemPool::addHashStatus(const NextCash::Hash &pHash, HashStatus pStatus)
    {
        HashStatusTime *newHashStatusTime = new HashStatusTime(pHash, pStatus);
        if(!mHashStatuses.insert(newHashStatusTime))
            delete newHashStatusTime;
    }

    void MemPool::getToAnnounce(TransactionList &pList, unsigned int pNodeID)
    {
        TransactionReference transaction;
        pList.clear();

        mLock.writeLock("Get Announce");

        for(NextCash::HashList::iterator hash = mToAnnounce.begin(); hash != mToAnnounce.end();
          ++hash)
        {
            transaction = mTransactions.get(*hash);
            if(transaction)
                pList.push_back(transaction);
        }

        mToAnnounce.clear();

        mLock.writeUnlock();
    }

    void MemPool::getFullList(NextCash::HashList &pList, const BloomFilter &pFilter)
    {
        pList.clear();

        mLock.readLock();

        if(pFilter.isEmpty())
            pList.reserve(mTransactions.size());

        for(TransactionSet::Iterator trans = mTransactions.begin(); trans != mTransactions.end();
          ++trans)
            if(pFilter.isEmpty() || pFilter.contains(*trans))
                pList.push_back((*trans)->getHash());

        mLock.readUnlock();
    }

    bool MemPool::haveTransaction(const NextCash::Hash &pHash)
    {
        return mTransactions.contains(pHash) || mPendingTransactions.contains(pHash) ||
          mValidatingTransactions.containsSorted(pHash);
    }

    bool MemPool::check(TransactionReference &pTransaction)
    {
        NextCash::Hash emptyBlockHash;
        NextCash::Mutex spentAgeLock("Spent Age");
        std::vector<unsigned int> spentAges;
        NextCash::Timer checkDupTime, outputLookupTime, signatureTime;

        pTransaction->check(mChain, emptyBlockHash, Chain::INVALID_HEIGHT, false,
          mChain->forks().requiredBlockVersion(Chain::INVALID_HEIGHT), spentAgeLock, spentAges,
          checkDupTime, outputLookupTime, signatureTime);

        if(pTransaction->isValid() && !pTransaction->outpointsFound())
        {
            if(mChain->outputs().exists(pTransaction->hash()))
            {
#ifdef PROFILER_ON
                NextCash::Profiler &profilerMB = NextCash::getProfiler(PROFILER_SET,
                  PROFILER_MEMPOOL_ADD_DUP_B_ID, PROFILER_MEMPOOL_ADD_DUP_B_NAME);
                profilerMB.addHits(pTransaction->size());
#endif
                return false;
            }
        }

        return true;
    }

    bool MemPool::checkPendingTransaction(TransactionReference &pTransaction, unsigned int pDepth)
    {
        // if(pDepth > 0)
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              // "Checking child %d pending transaction. (%d bytes) : %s", pDepth,
              // pTransaction->size(), pTransaction->hash().hex().text());
        // else
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              // "Checking pending transaction. (%d bytes) : %s", pTransaction->size(),
              // pTransaction->hash().hex().text());

        bool inserted;
        NextCash::String timeString;

        if(!check(pTransaction))
        {
            mLock.writeLock("Existing");
            mValidatingTransactions.removeSorted(pTransaction->hash());
            mLock.writeUnlock();

            // Transaction not standard
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Existing transaction. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash().hex().text());
        }
        else if(!pTransaction->isValid())
        {
            mLock.writeLock("Invalid Pending");
            mValidatingTransactions.removeSorted(pTransaction->hash());
            mLock.writeUnlock();

            if(pTransaction->feeIsValid())
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Removed pending transaction (%d bytes) (%llu fee rate) : %s",
                  pTransaction->size(), pTransaction->feeRate(),
                  pTransaction->hash().hex().text());
            else
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Removed pending transaction (%d bytes) : %s", pTransaction->size(),
                  pTransaction->hash().hex().text());
            pTransaction->print(mChain->forks(), NextCash::Log::VERBOSE);
        }
        else if(!pTransaction->outpointsFound())
        {
            // Not ready yet.
            if(getTime() - pTransaction->time() > 60)
            {
                // Expire
                mLock.writeLock("Expire Pending");
                mValidatingTransactions.removeSorted(pTransaction->hash());
                mLock.writeUnlock();

                timeString.writeFormattedTime(pTransaction->time());
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring pending transaction (time %d) %s (%d bytes) : %s",
                  pTransaction->time(), timeString.text(), pTransaction->size(),
                  pTransaction->hash().hex().text());
            }
            else
            {
                // Add back into pending.
                mLock.writeLock("Readd Pending");
                inserted = mPendingTransactions.insert(pTransaction);
                if(inserted)
                    mPendingSize += pTransaction->size();
                mValidatingTransactions.removeSorted(pTransaction->hash());
                mLock.writeUnlock();

                if(!inserted)
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
                      "Failed to re-add pending transaction. (%d bytes) (%llu fee rate) : %s",
                      pTransaction->size(), pTransaction->feeRate(), pTransaction->hash().hex().text());
                }
            }
        }
        else if(!pTransaction->isStandard())
        {
            mLock.writeLock("Non Standard Pending");
            addHashStatus(pTransaction->hash(), HASH_NON_STANDARD);
            mValidatingTransactions.removeSorted(pTransaction->hash());
            mLock.writeUnlock();

            // Transaction not standard
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Nonstandard transaction. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash().hex().text());
            pTransaction->print(mChain->forks(), NextCash::Log::VERBOSE);
        }
        else if(pTransaction->isStandardVerified())
        {
            NextCash::Hash hash = pTransaction->hash();
            mLock.writeLock("Verify Pending");
            mValidatingTransactions.removeSorted(pTransaction->hash());

            // Double check outpoints and then insert.
            // They could have been spent since they were checked without a full lock.
            inserted = !outpointExists(pTransaction) && insert(pTransaction, true);

            mLock.writeUnlock();

            if(inserted)
            {
                if(pDepth > 0)
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                      "Added child %d pending transaction. (%d bytes) (%llu fee rate) : %s",
                      pDepth, pTransaction->size(), pTransaction->feeRate(),
                      pTransaction->hash().hex().text());
                else
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                      "Added pending transaction. (%d bytes) (%llu fee rate) : %s",
                      pTransaction->size(), pTransaction->feeRate(), pTransaction->hash().hex().text());

                checkPendingForNewTransaction(hash, pDepth + 1);
            }
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
                  "Failed to add pending transaction. (%d bytes) (%llu fee rate) : %s",
                  pTransaction->size(), pTransaction->feeRate(), pTransaction->hash().hex().text());
            }

            return true;
        }
        else
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Unknown pending transaction state (%d bytes) (%llu fee rate) : %s",
              pTransaction->size(), pTransaction->feeRate(), pTransaction->hash().hex().text());
            mLock.writeLock("Unknown Pending");
            mValidatingTransactions.removeSorted(pTransaction->hash());
            mLock.writeUnlock();
        }

        return false;
    }

    void MemPool::checkPendingForNewTransaction(const NextCash::Hash &pHash, unsigned int pDepth)
    {
        if(pDepth > 100)
            return;

        NextCash::HashList pendingToCheck;

        // Find any pending child transactions of the new transaction.
        mLock.readLock();
        for(TransactionSet::Iterator trans = mPendingTransactions.begin();
          trans != mPendingTransactions.end(); ++trans)
            for(std::vector<Input>::iterator input = (*trans)->inputs.begin();
              input != (*trans)->inputs.end(); ++input)
                if(input->outpoint.transactionID == pHash)
                {
                    pendingToCheck.push_back((*trans)->getHash());
                    break;
                }
        mLock.readUnlock();

        TransactionReference transaction;
        for(NextCash::HashList::iterator hash = pendingToCheck.begin();
          hash != pendingToCheck.end(); ++hash)
        {
            mLock.writeLock("Get Pending Child");
            transaction = mPendingTransactions.getAndRemove(*hash);
            if(transaction)
            {
                mPendingSize -= transaction->size();
                if(!mValidatingTransactions.insertSorted(transaction->hash()))
                {
                    // Already being validated.
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
                      "Already validating pending child transaction (%d bytes) : %s",
                      transaction->size(), transaction->hash().hex().text());
                }
            }
            mLock.writeUnlock();

            if(transaction)
                checkPendingTransaction(transaction, pDepth);
        }
    }

    void MemPool::removePendingForNewTransaction(const NextCash::Hash &pHash, unsigned int pDepth)
    {
        if(pDepth > 100)
            return;

        NextCash::HashList pendingRemoved;

        // Find any pending child transactions of the new transaction.
        mLock.readLock();
        bool removed;
        for(TransactionSet::Iterator trans = mPendingTransactions.begin();
          trans != mPendingTransactions.end();)
        {
            removed = false;
            for(std::vector<Input>::iterator input = (*trans)->inputs.begin();
              input != (*trans)->inputs.end(); ++input)
                if(input->outpoint.transactionID == pHash)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                      "Removing descendant of rejected transaction (%d bytes) : %s",
                      (*trans)->size(), (*trans)->getHash().hex().text());
                    pendingRemoved.push_back((*trans)->getHash());
                    addHashStatus((*trans)->getHash(), HASH_REJECTED_ANCESTOR);
                    mPendingSize -= (*trans)->size();
                    trans = mPendingTransactions.erase(trans);
                    removed = true;
                    break;
                }
            if(!removed)
                ++trans;
        }
        mLock.readUnlock();

        for(NextCash::HashList::iterator hash = pendingRemoved.begin();
          hash != pendingRemoved.end(); ++hash)
            removePendingForNewTransaction(*hash, pDepth + 1);
    }

    bool MemPool::add(TransactionReference &pTransaction)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_ADD_ID, PROFILER_MEMPOOL_ADD_NAME), true);
#endif
        NextCash::Timer timer(true);

        mLock.writeLock("Add Check");

        removeRequested(pTransaction->hash());

        // Check known status.
        if(mHashStatuses.contains(pTransaction->hash()))
        {
            mLock.writeUnlock();
            return false;
        }

        // Check that the transaction isn't already in the mempool.
        if(haveTransaction(pTransaction->hash()))
        {
            mLock.writeUnlock();
#ifdef PROFILER_ON
            NextCash::Profiler &profilerMB = NextCash::getProfiler(PROFILER_SET,
              PROFILER_MEMPOOL_ADD_DUP_B_ID, PROFILER_MEMPOOL_ADD_DUP_B_NAME);
            profilerMB.addHits(pTransaction->size());
#endif
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Already have transaction (%d bytes) : %s",
              pTransaction->size(), pTransaction->hash().hex().text());
            return false;
        }

        // Add to pipeline.
        bool result;
        mPipeLineLock.lock();
        if(mPipeLineTransactions.insert(pTransaction))
        {
            mPipeLineQueue.push_back(pTransaction->hash());
            result = true;
        }
        else
            result = false;
        mPipeLineLock.unlock();
        mLock.writeUnlock();
        return result;
    }

    void MemPool::addInternal(TransactionReference &pTransaction)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_ADD_INTERNAL_ID, PROFILER_MEMPOOL_ADD_INTERNAL_NAME), true);

        NextCash::Profiler &profilerMB = NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_ADD_INTERNAL_B_ID, PROFILER_MEMPOOL_ADD_INTERNAL_B_NAME);
        profilerMB.addHits(pTransaction->size());
#endif
        NextCash::Timer timer(true);
        unsigned int startHeight = mChain->blockHeight();

        // Do this outside the lock because it is time consuming.
        if(!check(pTransaction))
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Existing transaction. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash().hex().text());

            mLock.writeLock("Existing");
            mValidatingTransactions.removeSorted(pTransaction->hash());
            mLock.writeUnlock();
            return;
        }
        else if(!pTransaction->isValid())
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Invalid transaction. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash().hex().text());

            mLock.writeLock("AddInvalid");
            addHashStatus(pTransaction->hash(), HASH_INVALID);
            mValidatingTransactions.removeSorted(pTransaction->hash());
            mLock.writeUnlock();
            removePendingForNewTransaction(pTransaction->hash(), 1);
            return;
        }

        if(pTransaction->outpointsFound())
        {
            if(!pTransaction->isStandard())
            {
                // Transaction not standard
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Transaction is not standard %02x. (%d bytes) : %s", pTransaction->status(),
                  pTransaction->size(), pTransaction->hash().hex().text());
                pTransaction->print(mChain->forks(), NextCash::Log::VERBOSE);

                mLock.writeLock("AddNonStd");
                addHashStatus(pTransaction->hash(), HASH_NON_STANDARD);
                mValidatingTransactions.removeSorted(pTransaction->hash());
                mLock.writeUnlock();
                removePendingForNewTransaction(pTransaction->hash(), 1);
                return;
            }

            uint64_t feeRate = (uint64_t)pTransaction->feeRate();
            if(mInfo.minFee > 0 && feeRate < mInfo.minFee)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Fee rate below minimum %llu < %llu (%lld fee) (%d bytes) : %s",
                  feeRate, mInfo.minFee, pTransaction->fee(), pTransaction->size(),
                  pTransaction->hash().hex().text());

                mLock.writeLock("AddLow");
                addHashStatus(pTransaction->hash(), HASH_LOW_FEE);
                mValidatingTransactions.removeSorted(pTransaction->hash());
                mLock.writeUnlock();
                removePendingForNewTransaction(pTransaction->hash(), 1);
                return;
            }
            else if(mSize + pTransaction->size() > mInfo.memPoolLowFeeSize &&
              feeRate < mInfo.lowFee)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Fee rate too low for size (%d MB) %llu < %llu (%lld fee) (%d bytes) : %s",
                  mSize / 1000000, feeRate, mInfo.lowFee, pTransaction->fee(),
                  pTransaction->size(), pTransaction->hash().hex().text());

                mLock.writeLock("AddLow");
                addHashStatus(pTransaction->hash(), HASH_LOW_FEE);
                mValidatingTransactions.removeSorted(pTransaction->hash());
                mLock.writeUnlock();
                removePendingForNewTransaction(pTransaction->hash(), 1);
                return;
            }
        }

        mLock.writeLock("Add");

        mValidatingTransactions.removeSorted(pTransaction->hash());

        if(outpointExists(pTransaction))
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction has double spend : %s", pTransaction->hash().hex().text());
            addHashStatus(pTransaction->hash(), HASH_DOUBLE_SPEND);
            mLock.writeUnlock();
            removePendingForNewTransaction(pTransaction->hash(), 1);
            return;
        }

        if(startHeight == mChain->blockHeight() ? !pTransaction->outpointsFound() :
          !pTransaction->checkOutpoints(mChain, true))
        {
            // Put in pending to wait for outpoint transactions
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction requires unseen output. Adding to pending. (%d bytes) : %s",
              pTransaction->size(), pTransaction->hash().hex().text());
            mPendingTransactions.insert(pTransaction);
            mPendingSize += pTransaction->size();
            mLock.writeUnlock();
            return;
        }

        if(pTransaction->isStandardVerified())
        {
            NextCash::Hash hash = pTransaction->hash();
            timer.stop();
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Added transaction (%d bytes) (%llu fee rate) (%llu us) : %s", pTransaction->size(),
              pTransaction->feeRate(), timer.microseconds(), pTransaction->hash().hex().text());
            bool inserted = insert(pTransaction, true);
            mLock.writeUnlock();
            if(inserted)
                checkPendingForNewTransaction(hash, 1);
            return;
        }

        mLock.writeUnlock();
        return;
    }

    unsigned int MemPool::pull(TransactionList &pTransactions)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_PULL_ID, PROFILER_MEMPOOL_PULL_NAME), true);
#endif
        mLock.writeLock("Pull");

        TransactionReference matchingTransaction;
        unsigned int result = 0;

        for(TransactionList::iterator trans = pTransactions.begin(); trans != pTransactions.end();
          ++trans)
            if((*trans)->inMemPool())
                ++result;
            else
            {
                matchingTransaction = mTransactions.get((*trans)->hash());
                if(!matchingTransaction)
                    matchingTransaction = mPendingTransactions.get((*trans)->hash());

                if(matchingTransaction)
                {
                    ++result;
                    *trans = matchingTransaction; // Replace with transaction from mempool.
                }
            }

        // Intenionally leave locked while block processes.
        mLock.writeUnlock(); // TODO Make function to convert write lock to read lock.
        mLock.readLock();
        return result;
    }

    void MemPool::revert(TransactionList &pTransactions, bool pFollowingPull)
    {
        // Should already be locked while block was processing.
        if(pFollowingPull)
            mLock.readUnlock();

        // Transactions are not removed from the mempool until finalize, so we probably don't need
        //   to do anything here.
    }

    void MemPool::finalize(TransactionList &pTransactions)
    {
        mLock.readUnlock();
        mLock.writeLock("Finalize");
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_FINALIZE_ID, PROFILER_MEMPOOL_FINALIZE_NAME), true);
#endif

        bool spentFound;
        unsigned int index;
        unsigned int removedCount = 0;
        uint64_t removedSize = 0L;
        TransactionReference matchingTransaction;
        for(TransactionList::iterator trans = pTransactions.begin(); trans != pTransactions.end();
          ++trans)
        {
            if((*trans)->inMemPool())
            {
                matchingTransaction = mTransactions.getAndRemove((*trans)->hash());
                if(matchingTransaction)
                {
                    ++removedCount;
                    removedSize += matchingTransaction->size();
                    removeInternal(matchingTransaction);
                }
                else
                {
                    matchingTransaction = mPendingTransactions.getAndRemove((*trans)->hash());
                    if(matchingTransaction)
                    {
                        ++removedCount;
                        removedSize += matchingTransaction->size();
                        mPendingSize -= matchingTransaction->size();
                    }
                }
            }
            else if(outpointExists(*trans))
            {
                // Find transaction and remove.
                for(TransactionSet::Iterator poolTrans = mTransactions.begin();
                  poolTrans != mTransactions.end(); ++poolTrans)
                {
                    spentFound = false;
                    index = 0;
                    for(std::vector<Input>::iterator poolInput = (*poolTrans)->inputs.begin();
                      poolInput != (*poolTrans)->inputs.end() && !spentFound; ++poolInput, ++index)
                        for(std::vector<Input>::iterator input = (*trans)->inputs.begin();
                          input != (*trans)->inputs.end() && !spentFound; ++input, ++index)
                            if(input->outpoint.transactionID == poolInput->outpoint.transactionID &&
                              input->outpoint.index == poolInput->outpoint.index)
                            {
                                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                                  "Removing double spend from mempool : %s",
                                  (*poolTrans)->getHash().hex().text());
                                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                                  "Double spent index %d : %s", index,
                                  input->outpoint.transactionID.hex().text());
                                spentFound = true;
                            }

                    if(spentFound)
                    {
                        ++removedCount;
                        removedSize += (*poolTrans)->size();
                        removeInternal(*poolTrans);
                        poolTrans = mTransactions.erase(poolTrans);
                        break;
                    }
                }
            }
        }

        mOutpoints.shrink();
        mTransactions.shrink();
        mPendingTransactions.shrink();

        mHashStatuses.shrink();

        mLock.writeUnlock();

        mRequestedHashesLock.lock();
        mRequestedHashes.shrink();
        mRequestedHashesLock.unlock();

        int percent = 0;
        if(removedSize > 0)
            percent = (int)(((float)removedSize /
              (float)(removedSize + mSize + mPendingSize)) * 100.0f);
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
          "Reduced by %d trans, %d KB, %d%% to %d trans, %d KB", removedCount,
          removedSize / 1000, percent, mTransactions.size() + mPendingTransactions.size(),
          (mSize + mPendingSize) / 1000);
    }

    bool MemPool::insert(TransactionReference &pTransaction, bool pAnnounce)
    {
        if(mTransactions.insert(pTransaction))
        {
            pTransaction->setInMemPool();
            mSize += pTransaction->size();

            if(pAnnounce)
                mToAnnounce.push_back(pTransaction->hash());

            // Add outpoints
            for(std::vector<Input>::iterator input = pTransaction->inputs.begin();
              input != pTransaction->inputs.end(); ++input)
                mOutpoints.insert(new OutpointHash(input->outpoint));
            return true;
        }
        else
            return false;
    }

    void MemPool::getOutpointHash(const Outpoint &pOutpoint, NextCash::Hash &pHash)
    {
        NextCash::Digest digest(NextCash::Digest::SHA256);
        pOutpoint.transactionID.write(&digest);
        digest.writeUnsignedInt(pOutpoint.index);
        digest.getResult(&pHash);
    }

    void MemPool::removeInternal(TransactionReference &pTransaction)
    {
        // Remove outpoints
        NextCash::Hash hash(32);
        for(std::vector<Input>::iterator input = pTransaction->inputs.begin();
          input != pTransaction->inputs.end(); ++input)
        {
            getOutpointHash(input->outpoint, hash);
            mOutpoints.remove(hash);
        }

        pTransaction->clearInMemPool();
        mSize -= pTransaction->size();
    }

    bool MemPool::outpointExists(TransactionReference &pTransaction)
    {
        NextCash::Hash hash(32);
        for(std::vector<Input>::iterator input = pTransaction->inputs.begin();
          input != pTransaction->inputs.end(); ++input)
        {
            getOutpointHash(input->outpoint, hash);
            if(mOutpoints.contains(hash))
                return true;
        }
        return false;
    }

    bool MemPool::outputExists(const NextCash::Hash &pTransactionID, unsigned int pIndex)
    {
        TransactionReference transaction = mTransactions.get(pTransactionID);
        if(transaction)
            return pIndex < transaction->outputs.size();
        else
            return false;
    }

    TransactionReference MemPool::getTransaction(const NextCash::Hash &pHash)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_GET_TRANS_ID, PROFILER_MEMPOOL_GET_TRANS_NAME), true);
#endif
        mLock.readLock();
        TransactionReference result = mTransactions.get(pHash);
        mLock.readUnlock();
        return result;
    }

    void MemPool::calculateShortIDs(Message::CompactBlockData *pCompactBlock,
      NextCash::SortedSet &pShortIDs)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_GET_COMPACT_TRANS_CALC_ID,
          PROFILER_MEMPOOL_GET_COMPACT_TRANS_CALC_NAME), true);
#endif
        mLock.readLock();

        pShortIDs.clear();
        pShortIDs.reserve(mTransactions.size() + mPendingTransactions.size());

        for(TransactionSet::Iterator trans = mTransactions.begin(); trans != mTransactions.end();
          ++trans)
            pShortIDs.insert(new ShortIDHash((*trans)->getHash(),
              pCompactBlock->calculateShortID((*trans)->getHash())));

        for(TransactionSet::Iterator trans = mPendingTransactions.begin();
          trans != mPendingTransactions.end(); ++trans)
            pShortIDs.insert(new ShortIDHash((*trans)->getHash(),
              pCompactBlock->calculateShortID((*trans)->getHash())));

        mLock.readUnlock();
    }

    bool MemPool::getOutput(const NextCash::Hash &pHash, uint32_t pIndex, Output &pOutput,
      bool pIsLocked)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_GET_OUTPUT_ID, PROFILER_MEMPOOL_GET_OUTPUT_NAME), true);
#endif
        bool result = false;
        if(!pIsLocked)
            mLock.readLock();
        TransactionReference transaction = mTransactions.get(pHash);
        if(transaction && transaction->outputs.size() > pIndex)
        {
            pOutput = transaction->outputs.at(pIndex);
            result = true;
        }
        if(!pIsLocked)
            mLock.readUnlock();
        return result;
    }

    bool MemPool::isSpent(TransactionReference &pTransaction)
    {
        for(TransactionSet::Iterator trans = mTransactions.begin(); trans != mTransactions.end();
          ++trans)
            for(std::vector<Input>::iterator input = (*trans)->inputs.begin();
              input != (*trans)->inputs.end(); ++input)
                if(input->outpoint.transactionID == pTransaction->hash())
                    return true;
        return false;
    }

    void MemPool::drop()
    {
        if(mSize < mInfo.memPoolLowFeeSize)
            return;

        uint64_t minFee = mInfo.minFee;
        if(mSize > mInfo.memPoolLowFeeSize)
            minFee = mInfo.lowFee;

        mLock.writeLock("Drop");
        TransactionSet::Iterator lowestFeeTransaction = mTransactions.end();
        uint64_t lowestFeeRate;
        uint64_t feeRate;

        while(true)
        {
            for(TransactionSet::Iterator trans = mTransactions.begin();
              trans != mTransactions.end(); ++trans)
                if(!isSpent(*trans)) // Don't remove an ancestor
                {
                    feeRate = (*trans)->feeRate();
                    if(lowestFeeTransaction == mTransactions.end())
                    {
                        lowestFeeRate = feeRate;
                        lowestFeeTransaction = trans;
                    }
                    else if(feeRate < lowestFeeRate || (feeRate == lowestFeeRate &&
                      (*trans)->time() < (*lowestFeeTransaction)->time()))
                    {
                        lowestFeeRate = feeRate;
                        lowestFeeTransaction = trans;
                    }
                }

            if(lowestFeeTransaction == mTransactions.end() ||
              (lowestFeeRate >= minFee && mSize < mInfo.memPoolSize))
                break;

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
              "Dropping transaction (%llu fee rate) (%d bytes) : %s", lowestFeeRate,
              (*lowestFeeTransaction)->size(),
              (*lowestFeeTransaction)->getHash().hex().text());
            removeInternal(*lowestFeeTransaction);
            mTransactions.erase(lowestFeeTransaction);
        }
        mLock.writeUnlock();
    }

    void MemPool::expire()
    {
        Time expireTime = getTime() - (60 * 60 * 24); // 24 hours
        NextCash::String timeString;

        mLock.writeLock("Expire");
        for(TransactionSet::Iterator trans = mTransactions.begin(); trans != mTransactions.end();)
        {
            if((*trans)->time() < expireTime)
            {
                timeString.writeFormattedTime((*trans)->time());
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring transaction (time %d) %s (%d bytes) : %s", (*trans)->time(),
                  timeString.text(), (*trans)->size(), (*trans)->getHash().hex().text());
                removeInternal(*trans);
                trans = mTransactions.erase(trans);
            }
            else
                ++trans;
        }

        expireTime = getTime() - (60 * 5); // 5 minutes
        for(TransactionSet::Iterator trans = mPendingTransactions.begin();
          trans != mPendingTransactions.end();)
        {
            if((*trans)->time() < expireTime)
            {
                timeString.writeFormattedTime((*trans)->time());
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring pending transaction (time %d) %s (%d bytes) : %s", (*trans)->time(),
                  timeString.text(), (*trans)->size(), (*trans)->getHash().hex().text());
                mPendingSize -= (*trans)->size();
                trans = mPendingTransactions.erase(trans);
            }
            else
                ++trans;
        }

        // Expire requested hashes
        expireTime = getTime() - 60; // 1 minute
        unsigned int count = 0;
        mRequestedHashesLock.lock();
        for(NextCash::HashSet::Iterator hash = mRequestedHashes.begin();
          hash != mRequestedHashes.end();)
        {
            if(((RequestedHash *)*hash)->time < expireTime)
            {
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring requested hash : %s", (*hash)->getHash().hex().text());
                hash = mRequestedHashes.eraseDelete(hash);
                ++count;
            }
            else
                ++hash;
        }
        mRequestedHashesLock.unlock();

        if(count > 0)
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Expired %d requested hashes", count);

        // Expire hash statuses
        expireTime = getTime() - (60 * 60); // 1 hour
        count = 0;
        for(NextCash::HashSet::Iterator hash = mHashStatuses.begin();
          hash != mHashStatuses.end();)
        {
            if(((HashStatusTime *)*hash)->time < expireTime)
            {
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring hash status : %s", (*hash)->getHash().hex().text());
                hash = mHashStatuses.eraseDelete(hash);
                ++count;
            }
            else
                ++hash;
        }

        if(count > 0)
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Expired %d hash statuses", count);

        mLock.writeUnlock();
    }

    void MemPool::process()
    {
        drop();
        expire();
    }

    void MemPool::getRequestData(MemPool::RequestData &pData)
    {
        pData.clear();

        mLock.readLock();

        pData.count = mTransactions.size();
        pData.size = mSize;
        pData.pendingCount = mPendingTransactions.size();
        pData.pendingSize = mPendingSize;

        uint64_t feeRate;

        for(TransactionSet::Iterator trans = mTransactions.begin(); trans != mTransactions.end();
          ++trans)
        {
            feeRate = (*trans)->feeRate();
            pData.totalFee += (uint64_t)(*trans)->fee();

            if(feeRate == 0)
                pData.zero += (*trans)->size();
            else if(feeRate < 1000)
                pData.low += (*trans)->size();
            else if(feeRate < 2000)
                pData.one += (*trans)->size();
            else if(feeRate < 5000)
                pData.two += (*trans)->size();
            else if(feeRate < 10000)
                pData.five += (*trans)->size();
            else
            {
                pData.remainingSize += (*trans)->size();
                pData.remainingFee += (*trans)->fee();
            }
        }

        mLock.readUnlock();
    }
}
