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
#endif

#include "log.hpp"
#include "chain.hpp"

#define BITCOIN_MEM_POOL_LOG_NAME "MemPool"


namespace BitCoin
{
    MemPool::MemPool() : mInfo(Info::instance()), mRequestedHashesLock("RequestedHashes"),
      mLock("MemPool"), mNodeLock("MemPool Nodes")
    {
        mSize = 0;
        mPendingSize = 0;
    }

    MemPool::~MemPool()
    {
        mLock.writeLock("Destroy");
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

    // void MemPool::getNeededHashes(NextCash::HashList &pList)
    // {
        // pList.clear();
        // Time time = getTime();
        // mRequestedHashesLock.lock();
        // for(NextCash::HashSet::Iterator hash = mRequestedHashes.begin();
          // hash != mRequestedHashes.end();)
        // {
            // if(((RequestedHash *)*hash)->nodeID == 0 || time - ((RequestedHash *)*hash)->time > 4)
            // {
                // if(((RequestedHash *)*hash)->requestAttempts > 2)
                // {
                    // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                      // "Requested transaction failed %d times : %s",
                      // ((RequestedHash *)*hash)->requestAttempts, (*hash)->getHash().hex().text());
                    // hash = mRequestedHashes.erase(hash);
                // }
                // else
                // {
                    // pList.emplace_back((*hash)->getHash());
                    // ++hash;
                // }
            // }
            // else
                // ++hash;
        // }
        // mRequestedHashesLock.unlock();
    // }

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

    MemPool::HashStatus MemPool::hashStatus(Chain *pChain, const NextCash::Hash &pHash,
      unsigned int pNodeID, bool pRetry)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_STATUS_ID, PROFILER_MEMPOOL_STATUS_NAME), true);
#endif

        mLock.readLock();

        if(mInvalidHashes.contains(pHash))
        {
            mLock.readUnlock();
            return HASH_INVALID;
        }

        if(mLowFeeHashes.contains(pHash))
        {
            mLock.readUnlock();
            return HASH_LOW_FEE;
        }

        if(mNonStandardHashes.contains(pHash))
        {
            mLock.readUnlock();
            return HASH_NON_STANDARD;
        }

        if(mDoubleSpendHashes.contains(pHash))
        {
            mLock.readUnlock();
            return HASH_DOUBLE_SPEND;
        }

        if(mRejectedAncestorHashes.contains(pHash))
        {
            mLock.readUnlock();
            return HASH_REJECTED_ANCESTOR;
        }

        if(haveTransaction(pHash))
        {
            mLock.readUnlock();
            return HASH_ALREADY_HAVE;
        }

        if(!addRequested(pHash, pNodeID, false, pRetry))
        {
            mLock.readUnlock();
            return HASH_REQUESTED;
        }

        mLock.readUnlock();
        return HASH_NEED;
    }

    void MemPool::addInvalidHash(const NextCash::Hash &pHash)
    {
        HashTime *newHashTime = new HashTime(pHash);
        if(!mInvalidHashes.insert(newHashTime))
            delete newHashTime;
    }

    void MemPool::addLowFeeHash(const NextCash::Hash &pHash)
    {
        HashTime *newHashTime = new HashTime(pHash);
        if(!mLowFeeHashes.insert(newHashTime))
            delete newHashTime;
    }

    void MemPool::addNonStandardHash(const NextCash::Hash &pHash)
    {
        HashTime *newHashTime = new HashTime(pHash);
        if(!mNonStandardHashes.insert(newHashTime))
            delete newHashTime;
    }

    void MemPool::addDoubleSpendHash(const NextCash::Hash &pHash)
    {
        HashTime *newHashTime = new HashTime(pHash);
        if(!mDoubleSpendHashes.insert(newHashTime))
            delete newHashTime;
    }

    void MemPool::addRejectedAncestorHash(const NextCash::Hash &pHash)
    {
        HashTime *newHashTime = new HashTime(pHash);
        if(!mRejectedAncestorHashes.insert(newHashTime))
            delete newHashTime;
    }

    void MemPool::getToAnnounce(TransactionList &pList, unsigned int pNodeID)
    {
        Transaction *transaction;
        pList.clear();

        mLock.writeLock("Get Announce");
        mNodeLock.lock();

        for(NextCash::HashList::iterator hash = mToAnnounce.begin(); hash != mToAnnounce.end();
          ++hash)
        {
            transaction = (Transaction *)mTransactions.get(*hash);
            if(transaction != NULL)
            {
                mNodeLocks.insert(new HashNodeID(*hash, pNodeID), true);
                pList.push_back(transaction);
            }
        }

        mToAnnounce.clear();

        mNodeLock.unlock();
        mLock.writeUnlock();
    }

    void MemPool::freeTransactions(TransactionList &pList, unsigned int pNodeID)
    {
        mNodeLock.lock();
        NextCash::HashSet::Iterator lock;
        bool found;
        for(TransactionList::iterator trans = pList.begin(); trans != pList.end(); ++trans)
        {
            found = false;
            for(lock = mNodeLocks.find((*trans)->hash); lock != mNodeLocks.end() &&
              (*lock)->getHash() == (*trans)->hash; ++lock)
            {
                if(((HashNodeID *)*lock)->nodeID == pNodeID)
                {
                    found = true;
                    mNodeLocks.eraseDelete(lock);
                    break;
                }
            }

            if(found && !mNodeLocks.contains((*trans)->hash)) // No locks left on this transaction.
                mNodeLockedTransactions.removeAll((*trans)->hash);
        }
        mNodeLock.unlock();
    }

    void MemPool::getFullList(NextCash::HashList &pList, const BloomFilter &pFilter)
    {
        pList.clear();

        mLock.readLock();

        if(pFilter.isEmpty())
            pList.reserve(mTransactions.size());

        for(NextCash::HashSet::Iterator trans = mTransactions.begin();
          trans != mTransactions.end(); ++trans)
            if(pFilter.isEmpty() || pFilter.contains(*((Transaction *)*trans)))
                pList.push_back((*trans)->getHash());

        mLock.readUnlock();
    }

    bool MemPool::haveTransaction(const NextCash::Hash &pHash)
    {
        return mTransactions.contains(pHash) ||
          mPendingTransactions.contains(pHash) ||
          mValidatingTransactions.containsSorted(pHash);
    }

    bool MemPool::check(Transaction *pTransaction, Chain *pChain, unsigned int pNodeID,
      NextCash::HashList &pUnseenOutpoints, bool pPending)
    {
        NextCash::Hash emptyBlockHash;
        NextCash::Mutex spentAgeLock("Spent Age");
        std::vector<unsigned int> spentAges;
        NextCash::Timer checkDupTime, outputLookupTime, signatureTime;

        pUnseenOutpoints.clear();

        pTransaction->check(pChain, emptyBlockHash, Chain::INVALID_HEIGHT, false,
          pChain->forks().requiredBlockVersion(Chain::INVALID_HEIGHT), spentAgeLock, spentAges,
          checkDupTime, outputLookupTime, signatureTime);

        if(pTransaction->isValid() && !pTransaction->outpointsFound())
        {
            if(pChain->outputs().exists(pTransaction->hash))
            {
#ifdef PROFILER_ON
                NextCash::Profiler &profilerMB = NextCash::getProfiler(PROFILER_SET,
                  PROFILER_MEMPOOL_ADD_DUP_B_ID, PROFILER_MEMPOOL_ADD_DUP_B_NAME);
                profilerMB.addHits(pTransaction->size());
#endif
                return false;
            }
            else if(pNodeID != 0)
            {
                Output output;
                bool have;
                for(std::vector<Input>::iterator input = pTransaction->inputs.begin();
                  input != pTransaction->inputs.end(); ++ input)
                {
                    mLock.readLock();
                    have = haveTransaction(input->outpoint.transactionID);
                    mLock.readUnlock();
                    if(!have && !pChain->outputs().isUnspent(input->outpoint.transactionID,
                      input->outpoint.index) &&
                      !pChain->memPool().getOutput(input->outpoint.transactionID,
                      input->outpoint.index, output, false) &&
                      addRequested(input->outpoint.transactionID, pNodeID, true, false))
                        pUnseenOutpoints.push_back(input->outpoint.transactionID);
                }
            }
        }

        return true;
    }

    bool MemPool::checkPendingTransaction(Chain *pChain, Transaction *pTransaction,
      unsigned int pDepth)
    {
        // if(pDepth > 0)
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              // "Checking child %d pending transaction. (%d bytes) : %s", pDepth,
              // pTransaction->size(), pTransaction->hash.hex().text());
        // else
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              // "Checking pending transaction. (%d bytes) : %s", pTransaction->size(),
              // pTransaction->hash.hex().text());

        bool inserted;
        NextCash::HashList unseen;
        NextCash::String timeString;

        if(!check(pTransaction, pChain, 0, unseen, true))
        {
            mLock.writeLock("Existing");
            mValidatingTransactions.removeSorted(pTransaction->hash);
            mLock.writeUnlock();

            // Transaction not standard
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Existing transaction. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash.hex().text());
            delete pTransaction;
        }
        else if(!pTransaction->isValid())
        {
            mLock.writeLock("Invalid Pending");
            mValidatingTransactions.removeSorted(pTransaction->hash);
            mLock.writeUnlock();

            if(pTransaction->feeIsValid())
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Removed pending transaction (%d bytes) (%llu fee rate) : %s",
                  pTransaction->size(), pTransaction->feeRate(),
                  pTransaction->hash.hex().text());
            else
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Removed pending transaction (%d bytes) : %s", pTransaction->size(),
                  pTransaction->hash.hex().text());
            pTransaction->print(pChain->forks(), NextCash::Log::VERBOSE);
            delete pTransaction;
        }
        else if(!pTransaction->outpointsFound())
        {
            // Not ready yet.
            if(getTime() - pTransaction->time() > 60)
            {
                // Expire
                mLock.writeLock("Expire Pending");
                mValidatingTransactions.removeSorted(pTransaction->hash);
                mLock.writeUnlock();

                timeString.writeFormattedTime(pTransaction->time());
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring pending transaction (time %d) %s (%d bytes) : %s",
                  pTransaction->time(), timeString.text(), pTransaction->size(),
                  pTransaction->hash.hex().text());

                delete pTransaction;
            }
            else
            {
                // Add back into pending.
                mLock.writeLock("Readd Pending");
                inserted = mPendingTransactions.insert(pTransaction);
                if(inserted)
                    mPendingSize += pTransaction->size();
                mValidatingTransactions.removeSorted(pTransaction->hash);
                mLock.writeUnlock();

                if(!inserted)
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
                      "Failed to re-add pending transaction. (%d bytes) (%llu fee rate) : %s",
                      pTransaction->size(), pTransaction->feeRate(), pTransaction->hash.hex().text());
                    delete pTransaction;
                }
            }
        }
        else if(!pTransaction->isStandard())
        {
            mLock.writeLock("Non Standard Pending");
            addNonStandardHash(pTransaction->hash);
            mValidatingTransactions.removeSorted(pTransaction->hash);
            mLock.writeUnlock();

            // Transaction not standard
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Nonstandard transaction. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash.hex().text());
            pTransaction->print(pChain->forks(), NextCash::Log::VERBOSE);
            delete pTransaction;
        }
        else if(pTransaction->isStandardVerified())
        {
            NextCash::Hash hash = pTransaction->hash;
            mLock.writeLock("Verify Pending");
            mValidatingTransactions.removeSorted(pTransaction->hash);

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
                      pTransaction->hash.hex().text());
                else
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                      "Added pending transaction. (%d bytes) (%llu fee rate) : %s",
                      pTransaction->size(), pTransaction->feeRate(), pTransaction->hash.hex().text());

                checkPendingForNewTransaction(pChain, hash, pDepth + 1);
            }
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
                  "Failed to add pending transaction. (%d bytes) (%llu fee rate) : %s",
                  pTransaction->size(), pTransaction->feeRate(), pTransaction->hash.hex().text());
                delete pTransaction;
            }

            return true;
        }
        else
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Unknown pending transaction state (%d bytes) (%llu fee rate) : %s",
              pTransaction->size(), pTransaction->feeRate(), pTransaction->hash.hex().text());
            mLock.writeLock("Unknown Pending");
            mValidatingTransactions.removeSorted(pTransaction->hash);
            mLock.writeUnlock();
            delete pTransaction;
        }

        return false;
    }

    void MemPool::checkPendingForNewTransaction(Chain *pChain, const NextCash::Hash &pHash,
      unsigned int pDepth)
    {
        if(pDepth > 100)
            return;

        NextCash::HashList pendingToCheck;

        // Find any pending child transactions of the new transaction.
        mLock.readLock();
        for(NextCash::HashSet::Iterator trans = mPendingTransactions.begin();
          trans != mPendingTransactions.end(); ++trans)
            for(std::vector<Input>::iterator input = ((Transaction *)*trans)->inputs.begin();
              input != ((Transaction *)*trans)->inputs.end(); ++input)
                if(input->outpoint.transactionID == pHash)
                {
                    pendingToCheck.push_back(((Transaction *)*trans)->hash);
                    break;
                }
        mLock.readUnlock();

        Transaction *transaction;
        for(NextCash::HashList::iterator hash = pendingToCheck.begin();
          hash != pendingToCheck.end(); ++hash)
        {
            mLock.writeLock("Get Pending Child");
            transaction = (Transaction *)mPendingTransactions.getAndRemove(*hash);
            if(transaction != NULL)
            {
                mPendingSize -= transaction->size();
                if(!mValidatingTransactions.insertSorted(transaction->hash))
                {
                    // Already being validated.
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
                      "Already validating pending child transaction (%d bytes) : %s",
                      transaction->size(), transaction->hash.hex().text());
                    delete transaction;
                    transaction = NULL;
                }
            }
            mLock.writeUnlock();

            if(transaction != NULL)
                checkPendingTransaction(pChain, transaction, pDepth);
        }
    }

    void MemPool::removePendingForNewTransaction(Chain *pChain, const NextCash::Hash &pHash,
      unsigned int pDepth)
    {
        if(pDepth > 100)
            return;

        NextCash::HashList pendingRemoved;

        // Find any pending child transactions of the new transaction.
        mLock.readLock();
        bool removed;
        for(NextCash::HashSet::Iterator trans = mPendingTransactions.begin();
          trans != mPendingTransactions.end();)
        {
            removed = false;
            for(std::vector<Input>::iterator input = ((Transaction *)*trans)->inputs.begin();
              input != ((Transaction *)*trans)->inputs.end(); ++input)
                if(input->outpoint.transactionID == pHash)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                      "Removing descendant of rejected transaction (%d bytes) : %s",
                      ((Transaction *)*trans)->size(), ((Transaction *)*trans)->hash.hex().text());
                    pendingRemoved.push_back(((Transaction *)*trans)->hash);
                    addRejectedAncestorHash(((Transaction *)*trans)->hash);
                    mPendingSize -= ((Transaction *)*trans)->size();
                    trans = mPendingTransactions.eraseDelete(trans);
                    removed = true;
                    break;
                }
            if(!removed)
                ++trans;
        }
        mLock.readUnlock();

        for(NextCash::HashList::iterator hash = pendingRemoved.begin();
          hash != pendingRemoved.end(); ++hash)
            removePendingForNewTransaction(pChain, *hash, pDepth + 1);
    }

    MemPool::AddStatus MemPool::add(Transaction *pTransaction, Chain *pChain, unsigned int pNodeID,
      NextCash::HashList &pUnseenOutpoints)
    {
        NextCash::Timer timer(true);

        mLock.writeLock("Add Check");

        // Check that the transaction isn't already in the mempool
        if(haveTransaction(pTransaction->hash))
        {
            mLock.writeUnlock();
#ifdef PROFILER_ON
            NextCash::Profiler &profilerMB = NextCash::getProfiler(PROFILER_SET,
              PROFILER_MEMPOOL_ADD_DUP_B_ID, PROFILER_MEMPOOL_ADD_DUP_B_NAME);
            profilerMB.addHits(pTransaction->size());
#endif
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Already have transaction (%d bytes) : %s",
              pTransaction->size(), pTransaction->hash.hex().text());
            return ALREADY_HAVE;
        }

        removeRequested(pTransaction->hash);
        mValidatingTransactions.insertSorted(pTransaction->hash);

        mLock.writeUnlock();

#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_ADD_ID, PROFILER_MEMPOOL_ADD_NAME), true);

        NextCash::Profiler &profilerMB = NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_ADD_B_ID, PROFILER_MEMPOOL_ADD_B_NAME);
        profilerMB.addHits(pTransaction->size());
#endif

        unsigned int startHeight = pChain->blockHeight();

        // Do this outside the lock because it is time consuming.
        if(!check(pTransaction, pChain, pNodeID, pUnseenOutpoints, false))
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Existing transaction. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash.hex().text());

            mLock.writeLock("Existing");
            mValidatingTransactions.removeSorted(pTransaction->hash);
            mLock.writeUnlock();
            return IN_CHAIN;
        }
        else if(!pTransaction->isValid())
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Invalid transaction. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash.hex().text());

            mLock.writeLock("AddInvalid");
            addInvalidHash(pTransaction->hash);
            mValidatingTransactions.removeSorted(pTransaction->hash);
            mLock.writeUnlock();
            removePendingForNewTransaction(pChain, pTransaction->hash, 1);
            return INVALID;
        }

        if(pTransaction->outpointsFound())
        {
            if(!pTransaction->isStandard())
            {
                // Transaction not standard
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Transaction is not standard %02x. (%d bytes) : %s", pTransaction->status(),
                  pTransaction->size(), pTransaction->hash.hex().text());
                pTransaction->print(pChain->forks(), NextCash::Log::VERBOSE);

                mLock.writeLock("AddNonStd");
                addNonStandardHash(pTransaction->hash);
                mValidatingTransactions.removeSorted(pTransaction->hash);
                mLock.writeUnlock();
                removePendingForNewTransaction(pChain, pTransaction->hash, 1);
                return NON_STANDARD;
            }

            uint64_t feeRate = (uint64_t)pTransaction->feeRate();
            if(mInfo.minFee > 0 && feeRate < mInfo.minFee)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Fee rate below minimum %llu < %llu (%lld fee) (%d bytes) : %s",
                  feeRate, mInfo.minFee, pTransaction->fee(), pTransaction->size(),
                  pTransaction->hash.hex().text());

                mLock.writeLock("AddLow");
                addLowFeeHash(pTransaction->hash);
                mValidatingTransactions.removeSorted(pTransaction->hash);
                mLock.writeUnlock();
                removePendingForNewTransaction(pChain, pTransaction->hash, 1);
                return LOW_FEE;
            }
            else if(mSize + pTransaction->size() > mInfo.memPoolLowFeeSize &&
              feeRate < mInfo.lowFee)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Fee rate too low for size (%d MB) %llu < %llu (%lld fee) (%d bytes) : %s",
                  mSize / 1000000, feeRate, mInfo.lowFee, pTransaction->fee(),
                  pTransaction->size(), pTransaction->hash.hex().text());

                mLock.writeLock("AddLow");
                addLowFeeHash(pTransaction->hash);
                mValidatingTransactions.removeSorted(pTransaction->hash);
                mLock.writeUnlock();
                removePendingForNewTransaction(pChain, pTransaction->hash, 1);
                return LOW_FEE;
            }
        }

        mLock.writeLock("Add");

        mValidatingTransactions.removeSorted(pTransaction->hash);

        if(outpointExists(pTransaction))
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction has double spend : %s", pTransaction->hash.hex().text());
            addDoubleSpendHash(pTransaction->hash);
            mLock.writeUnlock();
            removePendingForNewTransaction(pChain, pTransaction->hash, 1);
            return DOUBLE_SPEND;
        }

        if(startHeight == pChain->blockHeight() ? !pTransaction->outpointsFound() :
          !pTransaction->checkOutpoints(pChain, true))
        {
            // Put in pending to wait for outpoint transactions
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction requires unseen output. Adding to pending. (%d bytes) : %s",
              pTransaction->size(), pTransaction->hash.hex().text());
            mPendingTransactions.insert(pTransaction);
            mPendingSize += pTransaction->size();
            mLock.writeUnlock();
            return UNSEEN_OUTPOINTS;
        }

        if(pTransaction->isStandardVerified())
        {
            NextCash::Hash hash = pTransaction->hash;
            timer.stop();
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Added transaction (%d bytes) (%llu fee rate) (%llu us) : %s", pTransaction->size(),
              pTransaction->feeRate(), timer.microseconds(), pTransaction->hash.hex().text());
            bool inserted = insert(pTransaction, true);
            mLock.writeUnlock();

            if(inserted)
            {
                checkPendingForNewTransaction(pChain, hash, 1);
                return ADDED;
            }
            else
                return ALREADY_HAVE;
        }

        mLock.writeUnlock();
        return INVALID;
    }

    unsigned int MemPool::pull(std::vector<Transaction *> &pTransactions)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_PULL_ID, PROFILER_MEMPOOL_PULL_NAME), true);
#endif
        mLock.writeLock("Pull");

        Transaction *matchingTransaction;
        unsigned int result = 0;

        for(std::vector<Transaction *>::iterator transaction = pTransactions.begin();
          transaction != pTransactions.end(); ++transaction)
        {
            matchingTransaction = (Transaction *)mTransactions.get((*transaction)->hash);
            if(matchingTransaction == NULL)
                matchingTransaction =
                  (Transaction *)mPendingTransactions.get((*transaction)->hash);

            if(matchingTransaction != NULL)
            {
                ++result;
                if(matchingTransaction != *transaction)
                    (*transaction)->pullPrecomputed(*matchingTransaction);
            }
        }

        // Intenionally leave locked while block processes.
        mLock.writeUnlock(); // TODO Make function to convert write lock to read lock.
        mLock.readLock();
        return result;
    }

    void MemPool::revert(const std::vector<Transaction *> &pTransactions, bool pFollowingPull)
    {
        // Should already be locked while block was processing.
        if(pFollowingPull)
            mLock.readUnlock();
        // mLock.writeLock("Revert");

        // unsigned int previousSize = mSize;
        // unsigned int previousCount = mTransactions.size() + mPendingTransactions.size();
        // Transaction *newTransaction;

        // for(std::vector<Transaction *>::const_iterator transaction = pTransactions.begin() + 1;
          // transaction != pTransactions.end(); ++transaction)
        // {
            // // TODO Only accept valid transactions.
            // newTransaction = new Transaction(**transaction);
            // if(!insert(newTransaction, false))
                // delete newTransaction;
        // }

        // if((mTransactions.size() + mPendingTransactions.size()) == previousCount)
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              // "Not increased reverting block. %d trans, %d KB",
              // mTransactions.size() + mPendingTransactions.size(), mSize / 1000);
        // else
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              // "Increased reverting block by %d trans, %d KB, %d%% to %d trans, %d KB",
              // (mTransactions.size() + mPendingTransactions.size()) - previousCount,
              // (mSize - previousSize) / 1000, (int)(((float)(mSize - previousSize) /
              // (float)mSize) * 100.0f), mTransactions.size() + mPendingTransactions.size(),
              // mSize / 1000);

        // mLock.writeUnlock();
    }

    void MemPool::finalize(std::vector<Transaction *> &pTransactions)
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
        Transaction *matchingTransaction;
        for(std::vector<Transaction *>::iterator trans = pTransactions.begin();
          trans != pTransactions.end(); ++trans)
        {
            if((*trans)->wasInMemPool())
            {
                matchingTransaction = (Transaction *)mTransactions.getAndRemove((*trans)->hash);
                if(matchingTransaction != NULL)
                {
                    ++removedCount;
                    removedSize += matchingTransaction->size();
                    removeInternal(matchingTransaction);
                }
                else
                {
                    matchingTransaction =
                      (Transaction *)mPendingTransactions.getAndRemove((*trans)->hash);
                    if(matchingTransaction != NULL)
                    {
                        ++removedCount;
                        removedSize += matchingTransaction->size();
                        mPendingSize -= matchingTransaction->size();
                        delete matchingTransaction;
                    }
                }
            }
            else if(outpointExists(*trans))
            {
                // Find transaction and remove.
                for(NextCash::HashSet::Iterator poolTrans = mTransactions.begin();
                  poolTrans != mTransactions.end(); ++poolTrans)
                {
                    spentFound = false;
                    index = 0;
                    for(std::vector<Input>::iterator poolInput =
                      ((Transaction *)*poolTrans)->inputs.begin();
                      poolInput != ((Transaction *)*poolTrans)->inputs.end() && !spentFound; ++poolInput, ++index)
                        for(std::vector<Input>::iterator input = (*trans)->inputs.begin();
                          input != (*trans)->inputs.end() && !spentFound; ++input, ++index)
                            if(input->outpoint.transactionID == poolInput->outpoint.transactionID &&
                              input->outpoint.index == poolInput->outpoint.index)
                            {
                                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                                  "Removing double spend from mempool : %s",
                                  ((Transaction *)*poolTrans)->hash.hex().text());
                                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                                  "Double spent index %d : %s", index,
                                  input->outpoint.transactionID.hex().text());
                                spentFound = true;
                            }

                    if(spentFound)
                    {
                        ++removedCount;
                        removedSize += ((Transaction *)*poolTrans)->size();
                        removeInternal((Transaction *)*poolTrans);
                        poolTrans = mTransactions.eraseNoDelete(poolTrans);
                        break;
                    }
                }
            }
        }

        mOutpoints.shrink();
        mTransactions.shrink();
        mPendingTransactions.shrink();

        mInvalidHashes.shrink();
        mLowFeeHashes.shrink();
        mNonStandardHashes.shrink();
        mDoubleSpendHashes.shrink();
        mRejectedAncestorHashes.shrink();

        mLock.writeUnlock();

        mRequestedHashesLock.lock();
        mRequestedHashes.shrink();
        mRequestedHashesLock.unlock();

        mNodeLock.lock();
        mNodeLocks.shrink();
        mNodeLockedTransactions.shrink();
        mNodeLock.unlock();

        int percent = 0;
        if(removedSize > 0)
            percent = (int)(((float)removedSize /
              (float)(removedSize + mSize + mPendingSize)) * 100.0f);
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
          "Reduced by %d trans, %d KB, %d%% to %d trans, %d KB", removedCount,
          removedSize / 1000, percent, mTransactions.size() + mPendingTransactions.size(),
          (mSize + mPendingSize) / 1000);
    }

    bool MemPool::insert(Transaction *pTransaction, bool pAnnounce)
    {
        if(mTransactions.insert(pTransaction))
        {
            mSize += pTransaction->size();

            if(pAnnounce)
                mToAnnounce.push_back(pTransaction->hash);

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

    void MemPool::removeInternal(Transaction *pTransaction)
    {
        // Remove outpoints
        NextCash::Hash hash(32);
        for(std::vector<Input>::iterator input = pTransaction->inputs.begin();
          input != pTransaction->inputs.end(); ++input)
        {
            getOutpointHash(input->outpoint, hash);
            mOutpoints.remove(hash);
        }

        mSize -= pTransaction->size();

        // Don't delete if locked by a node.
        mNodeLock.lock();
        bool locked = mNodeLocks.contains(pTransaction->hash);
        if(locked) // Save to delete when lock is released.
            mNodeLockedTransactions.insert(pTransaction, true);
        mNodeLock.unlock();
        if(!locked)
            delete pTransaction;
    }

    bool MemPool::outpointExists(Transaction *pTransaction)
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
        Transaction *transaction = (Transaction *)mTransactions.get(pTransactionID);
        if(transaction == NULL)
            return false;
        else
            return pIndex < transaction->outputs.size();
    }

    Transaction *MemPool::getTransactionCopy(const NextCash::Hash &pHash)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_GET_TRANS_COPY_ID, PROFILER_MEMPOOL_GET_TRANS_COPY_NAME), true);
#endif
        mLock.readLock();
        Transaction *result = (Transaction *)mTransactions.get(pHash);
        if(result == NULL)
            result = (Transaction *)mPendingTransactions.get(pHash);
        if(result != NULL)
            result = new Transaction(*result); // Make copy
        mLock.readUnlock();
        return result;
    }

    Transaction *MemPool::getTransaction(const NextCash::Hash &pHash, unsigned int pNodeID)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_GET_TRANS_ID, PROFILER_MEMPOOL_GET_TRANS_NAME), true);
#endif
        mLock.readLock();
        Transaction *result = (Transaction *)mTransactions.get(pHash);
        mNodeLock.lock();
        if(result != NULL)
            mNodeLocks.insert(new HashNodeID(pHash, pNodeID), true);
        mNodeLock.unlock();
        mLock.readUnlock();
        return result;
    }

    void MemPool::freeTransaction(const NextCash::Hash &pHash, unsigned int pNodeID)
    {
        mNodeLock.lock();
        NextCash::HashSet::Iterator lock;
        bool found = false;
        for(lock = mNodeLocks.find(pHash); lock != mNodeLocks.end() && (*lock)->getHash() == pHash;
          ++lock)
            if(((HashNodeID *)*lock)->nodeID == pNodeID)
            {
                found = true;
                mNodeLocks.eraseDelete(lock);
                break;
            }
        if(found && !mNodeLocks.contains(pHash))
            mNodeLockedTransactions.removeAll(pHash);
        mNodeLock.unlock();
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

        for(NextCash::HashSet::Iterator trans = mTransactions.begin();
          trans != mTransactions.end(); ++trans)
            pShortIDs.insert(new ShortIDHash((*trans)->getHash(),
              pCompactBlock->calculateShortID((*trans)->getHash())));

        for(NextCash::HashSet::Iterator trans = mPendingTransactions.begin();
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
        Transaction *transaction = (Transaction *)mTransactions.get(pHash);
        if(transaction != NULL && transaction->outputs.size() > pIndex)
        {
            pOutput = transaction->outputs.at(pIndex);
            result = true;
        }
        if(!pIsLocked)
            mLock.readUnlock();
        return result;
    }

    bool MemPool::isSpent(Transaction *pTransaction)
    {
        for(NextCash::HashSet::Iterator trans = mTransactions.begin();
          trans != mTransactions.end(); ++trans)
            for(std::vector<Input>::iterator input = ((Transaction *)(*trans))->inputs.begin();
              input != ((Transaction *)(*trans))->inputs.end(); ++input)
                if(input->outpoint.transactionID == pTransaction->hash)
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
        NextCash::HashSet::Iterator lowestFeeTransaction = mTransactions.end();
        uint64_t lowestFeeRate;
        uint64_t feeRate;

        while(true)
        {
            for(NextCash::HashSet::Iterator trans = mTransactions.begin();
              trans != mTransactions.end(); ++trans)
                if(!isSpent((Transaction *)*trans)) // Don't remove an ancestor
                {
                    feeRate = ((Transaction *)*trans)->feeRate();
                    if(lowestFeeTransaction == mTransactions.end())
                    {
                        lowestFeeRate = feeRate;
                        lowestFeeTransaction = trans;
                    }
                    else if(feeRate < lowestFeeRate || (feeRate == lowestFeeRate &&
                      ((Transaction *)*trans)->time() <
                      ((Transaction *)*lowestFeeTransaction)->time()))
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
              ((Transaction *)*lowestFeeTransaction)->size(),
              ((Transaction *)*lowestFeeTransaction)->hash.hex().text());
            removeInternal((Transaction *)*lowestFeeTransaction);
            mTransactions.eraseNoDelete(lowestFeeTransaction);
        }
        mLock.writeUnlock();
    }

    void MemPool::expire()
    {
        Time expireTime = getTime() - (60 * 60 * 24); // 24 hours
        NextCash::String timeString;

        mLock.writeLock("Expire");
        for(NextCash::HashSet::Iterator trans = mTransactions.begin();
          trans != mTransactions.end();)
        {
            if(((Transaction *)*trans)->time() < expireTime)
            {
                timeString.writeFormattedTime(((Transaction *)*trans)->time());
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring transaction (time %d) %s (%d bytes) : %s",
                  ((Transaction *)*trans)->time(), timeString.text(),
                  ((Transaction *)*trans)->size(), ((Transaction *)*trans)->hash.hex().text());
                removeInternal((Transaction *)*trans);
                trans = mTransactions.eraseNoDelete(trans);
            }
            else
                ++trans;
        }

        expireTime = getTime() - (60 * 5); // 5 minutes
        for(NextCash::HashSet::Iterator trans = mPendingTransactions.begin();
          trans != mPendingTransactions.end();)
        {
            if(((Transaction *)*trans)->time() < expireTime)
            {
                timeString.writeFormattedTime(((Transaction *)*trans)->time());
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring pending transaction (time %d) %s (%d bytes) : %s",
                  ((Transaction *)*trans)->time(), timeString.text(),
                  ((Transaction *)*trans)->size(), ((Transaction *)*trans)->hash.hex().text());
                mPendingSize -= ((Transaction *)*trans)->size();
                trans = mPendingTransactions.eraseDelete(trans);
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

        // Expire invalid hashes
        expireTime = getTime() - (60 * 60); // 1 hour
        count = 0;
        for(NextCash::HashSet::Iterator hash = mInvalidHashes.begin();
          hash != mInvalidHashes.end();)
        {
            if(((HashTime *)*hash)->time < expireTime)
            {
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring invalid hash : %s", (*hash)->getHash().hex().text());
                hash = mInvalidHashes.eraseDelete(hash);
                ++count;
            }
            else
                ++hash;
        }

        if(count > 0)
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Expired %d invalid hashes", count);

        // Expire low fee hashes
        count = 0;
        for(NextCash::HashSet::Iterator hash = mLowFeeHashes.begin(); hash != mLowFeeHashes.end();)
        {
            if(((HashTime *)*hash)->time < expireTime)
            {
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring low fee hash : %s", (*hash)->getHash().hex().text());
                hash = mLowFeeHashes.eraseDelete(hash);
                ++count;
            }
            else
                ++hash;
        }

        if(count > 0)
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Expired %d low fee hashes", count);

        // Expire non-standard hashes
        count = 0;
        for(NextCash::HashSet::Iterator hash = mNonStandardHashes.begin();
          hash != mNonStandardHashes.end();)
        {
            if(((HashTime *)*hash)->time < expireTime)
            {
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring non-standard hash : %s", (*hash)->getHash().hex().text());
                hash = mNonStandardHashes.eraseDelete(hash);
                ++count;
            }
            else
                ++hash;
        }

        if(count > 0)
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Expired %d non-standard hashes", count);

        // Expire double spend hashes
        count = 0;
        for(NextCash::HashSet::Iterator hash = mDoubleSpendHashes.begin();
          hash != mDoubleSpendHashes.end();)
        {
            if(((HashTime *)*hash)->time < expireTime)
            {
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring double spend hash : %s", (*hash)->getHash().hex().text());
                hash = mDoubleSpendHashes.eraseDelete(hash);
                ++count;
            }
            else
                ++hash;
        }

        if(count > 0)
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Expired %d double spend hashes", count);

        // Expire rejected ancestor hashes
        count = 0;
        for(NextCash::HashSet::Iterator hash = mRejectedAncestorHashes.begin();
          hash != mRejectedAncestorHashes.end();)
        {
            if(((HashTime *)*hash)->time < expireTime)
            {
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring rejected ancestor hash : %s", (*hash)->getHash().hex().text());
                hash = mRejectedAncestorHashes.eraseDelete(hash);
                ++count;
            }
            else
                ++hash;
        }

        if(count > 0)
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Expired %d rejected ancestor hashes", count);

        mLock.writeUnlock();
    }

    void MemPool::process(Chain *pChain)
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

        for(NextCash::HashSet::Iterator trans = mTransactions.begin();
          trans != mTransactions.end(); ++trans)
        {
            feeRate = ((Transaction *)*trans)->feeRate();
            pData.totalFee += (uint64_t)((Transaction *)*trans)->fee();

            if(feeRate == 0)
                pData.zero += ((Transaction *)*trans)->size();
            else if(feeRate < 1200)
                pData.one += ((Transaction *)*trans)->size();
            else if(feeRate < 2200)
                pData.two += ((Transaction *)*trans)->size();
            else if(feeRate < 5200)
                pData.five += ((Transaction *)*trans)->size();
            else if(feeRate < 10200)
                pData.ten += ((Transaction *)*trans)->size();
            else
            {
                pData.remainingSize += ((Transaction *)*trans)->size();
                pData.remainingFee += ((Transaction *)*trans)->fee();
            }
        }

        mLock.readUnlock();
    }
}
