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
    MemPool::MemPool() : mLock("MemPool"), mNodeLock("MemPool Nodes")
    {
        mSize = 0;
    }

    MemPool::~MemPool()
    {
        mLock.writeLock("Destroy");
    }

    MemPool::HashStatus MemPool::hashStatus(Chain *pChain, const NextCash::Hash &pHash)
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

        if(mTransactions.getSorted(pHash) != NULL ||
          mPendingTransactions.getSorted(pHash) != NULL ||
          mValidatingTransactions.containsSorted(pHash))
        {
            mLock.readUnlock();
            return HASH_ALREADY_HAVE;
        }

        if(pChain->outputs().exists(pHash, false))
        {
            mLock.readUnlock();
            return HASH_ALREADY_HAVE;
        }

        mLock.readUnlock();
        return HASH_NEED;
    }

    void MemPool::addInvalidHash(const NextCash::Hash &pHash)
    {
        mInvalidHashes.push_back(pHash);
        while(mInvalidHashes.size() > 1024)
            mInvalidHashes.erase(mInvalidHashes.begin());
    }

    void MemPool::addLowFeeHash(const NextCash::Hash &pHash)
    {
        mLowFeeHashes.push_back(pHash);
        while(mLowFeeHashes.size() > 1024)
            mLowFeeHashes.erase(mLowFeeHashes.begin());
    }

    void MemPool::addNonStandardHash(const NextCash::Hash &pHash)
    {
        mNonStandardHashes.push_back(pHash);
        while(mNonStandardHashes.size() > 1024)
            mNonStandardHashes.erase(mNonStandardHashes.begin());
    }

    void MemPool::getToAnnounce(NextCash::HashList &pList)
    {
        pList.clear();
        mLock.readLock();
        for(NextCash::HashList::iterator hash = mToAnnounce.begin(); hash != mToAnnounce.end();
          ++hash)
            pList.push_back(*hash);
        mToAnnounce.clear();
        mLock.readUnlock();
    }

    void MemPool::getFullList(NextCash::HashList &pList, const BloomFilter &pFilter)
    {
        pList.clear();
        mLock.readLock();
        if(pFilter.isEmpty())
            pList.reserve(mTransactions.size());
        for(TransactionList::iterator trans = mTransactions.begin(); trans != mTransactions.end();
          ++trans)
            if(pFilter.isEmpty() || pFilter.contains(**trans))
                pList.push_back((*trans)->hash);
        mLock.readUnlock();
    }

    void MemPool::check(Transaction *pTransaction, uint64_t pMinFeeRate, Chain *pChain)
    {
        NextCash::Hash emptyBlockHash;
        NextCash::Mutex spentAgeLock("Spent Age");
        std::vector<unsigned int> spentAges;
        NextCash::Timer checkDupTime, outputLookupTime, signatureTime;

        pTransaction->check(pChain, emptyBlockHash, Chain::INVALID_HEIGHT, false,
          pChain->forks().requiredBlockVersion(Chain::INVALID_HEIGHT), spentAgeLock, spentAges,
          checkDupTime, outputLookupTime, signatureTime);
    }

    void MemPool::checkPending(Chain *pChain, uint64_t pMinFeeRate)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_PENDING_ID, PROFILER_MEMPOOL_PENDING_NAME), true);
#endif
        unsigned int offset = 0;
        Transaction *transaction;
        bool inserted;

        while(true)
        {
            // Temporarily remove from pending.
            mLock.writeLock("Check Pending");
            transaction = mPendingTransactions.getAndRemoveAt(offset);
            if(transaction != NULL)
            {
                mSize -= transaction->size();
                mValidatingTransactions.insertSorted(transaction->hash);
            }
            mLock.writeUnlock();

            if(transaction == NULL)
                break;

            check(transaction, pMinFeeRate, pChain);

            if(!transaction->isValid())
            {
                mLock.writeLock("Invalid Pending");
                mValidatingTransactions.remove(transaction->hash);
                mLock.writeUnlock();

                if(transaction->feeIsValid())
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                      "Removed pending transaction (%d bytes) (%llu fee rate) : %s",
                      transaction->size(), transaction->feeRate(),
                      transaction->hash.hex().text());
                else
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                      "Removed pending transaction (%d bytes) : %s", transaction->size(),
                      transaction->hash.hex().text());
                transaction->print(pChain->forks(), NextCash::Log::VERBOSE);
                delete transaction;
            }
            else if(!transaction->outpointsFound())
            {
                // Not ready yet. Add back into pending.
                mLock.writeLock("Readd Pending");
                inserted = mPendingTransactions.insertSorted(transaction);
                if(inserted)
                    mSize += transaction->size();
                mValidatingTransactions.remove(transaction->hash);
                mLock.writeUnlock();

                if(!inserted)
                    delete transaction;
            }
            else if(!transaction->isStandard())
            {
                mLock.writeLock("Non Standard Pending");
                addNonStandardHash(transaction->hash);
                mValidatingTransactions.remove(transaction->hash);
                mLock.writeUnlock();

                // Transaction not standard
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Nonstandard transaction. (%d bytes) : %s", transaction->size(),
                  transaction->hash.hex().text());
                transaction->print(pChain->forks(), NextCash::Log::VERBOSE);
                delete transaction;
            }
            else if(transaction->isStandardVerified())
            {
                mLock.writeLock("Verify Pending");
                mValidatingTransactions.remove(transaction->hash);

                // Double check outpoints and then insert.
                // They could have been spent since they were checked without a full lock.
                inserted = checkOutpoints(transaction, pChain) && insert(transaction, true);

                mLock.writeUnlock();

                if(inserted)
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                      "Added pending transaction. (%d bytes) (%llu fee rate) : %s",
                      transaction->size(), transaction->feeRate(), transaction->hash.hex().text());
                else
                    delete transaction;
            }
            else
            {
                mLock.writeLock("Unknown Pending");
                mValidatingTransactions.remove(transaction->hash);
                mLock.writeUnlock();
                delete transaction;
            }

            ++offset;
        }
    }

    MemPool::AddStatus MemPool::add(Transaction *pTransaction, uint64_t pMinFeeRate, Chain *pChain)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_ADD_ID, PROFILER_MEMPOOL_ADD_NAME), true);
#endif
        if(pChain->outputs().exists(pTransaction->hash))
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction already confirmed : %s", pTransaction->hash.hex().text());
            return ALREADY_HAVE;
        }

        mLock.writeLock("Add");

        // Check that the transaction isn't already in the mempool
        if(mTransactions.getSorted(pTransaction->hash) != NULL ||
          mPendingTransactions.getSorted(pTransaction->hash) != NULL ||
          mValidatingTransactions.containsSorted(pTransaction->hash))
        {
            mLock.writeUnlock();
            return ALREADY_HAVE;
        }

        mValidatingTransactions.insertSorted(pTransaction->hash);

        mLock.writeUnlock();

        // Do this outside the lock because it is time consuming.
        check(pTransaction, pMinFeeRate, pChain);

        if(!pTransaction->isValid())
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Failed to check transaction. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash.hex().text());

            mLock.writeLock("Add");
            addInvalidHash(pTransaction->hash);
            mValidatingTransactions.remove(pTransaction->hash);
            mLock.writeUnlock();
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

                mLock.writeLock("Add");
                addNonStandardHash(pTransaction->hash);
                mValidatingTransactions.remove(pTransaction->hash);
                mLock.writeUnlock();
                return NON_STANDARD;
            }

            if(pTransaction->feeRate() < pMinFeeRate)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Fee rate below minimum %llu < %llu (%lld fee) (%d bytes) : %s",
                  pTransaction->feeRate(), pMinFeeRate, pTransaction->fee(), pTransaction->size(),
                  pTransaction->hash.hex().text());

                mLock.writeLock("Add");
                addLowFeeHash(pTransaction->hash);
                mValidatingTransactions.remove(pTransaction->hash);
                mLock.writeUnlock();
                return LOW_FEE;
            }
        }

        mLock.writeLock("Add");

        mValidatingTransactions.remove(pTransaction->hash);

        if(outpointExists(pTransaction))
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction has double spend from mempool : %s", pTransaction->hash.hex().text());
            mLock.writeUnlock();
            return DOUBLE_SPEND;
        }

        // Double check outpoints.
        // They could have been spent since they were checked without a full lock.
        if(!checkOutpoints(pTransaction, pChain))
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction has double spend : %s", pTransaction->hash.hex().text());
            mLock.writeUnlock();
            return DOUBLE_SPEND;
        }

        if(!pTransaction->outpointsFound())
        {
            // Put in pending to wait for outpoint transactions
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction requires unseen output. Adding to pending. (%d bytes) : %s",
              pTransaction->size(), pTransaction->hash.hex().text());
            mPendingTransactions.insertSorted(pTransaction);
            mSize += pTransaction->size();
            mLock.writeUnlock();
            return UNSEEN_OUTPOINTS;
        }

        if(pTransaction->isStandardVerified())
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Added transaction (%d bytes) (%llu fee rate) : %s", pTransaction->size(),
              pTransaction->feeRate(), pTransaction->hash.hex().text());
            insert(pTransaction, true);
            mLock.writeUnlock();
            return ADDED;
        }

        mLock.writeUnlock();
        return INVALID;
    }

    bool MemPool::checkOutpoints(Transaction *pTransaction, Chain *pChain)
    {
        Transaction *outpointTransaction;
        for(std::vector<Input>::iterator input = pTransaction->inputs.begin();
          input != pTransaction->inputs.end(); ++input)
        {
            if(pChain->outputs().isUnspent(input->outpoint.transactionID, input->outpoint.index))
                continue;

            outpointTransaction = mTransactions.getSorted(input->outpoint.transactionID);
            if(outpointTransaction == NULL ||
              outpointTransaction->outputs.size() <= input->outpoint.index)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
                  "Attempted double spend on index %d : %s", input->outpoint.index,
                  input->outpoint.transactionID.hex().text());
                return false;
            }
        }

        return true;
    }

    void MemPool::pull(std::vector<Transaction *> &pTransactions)
    {
        mLock.writeLock("Remove");

        Transaction *matchingTransaction;
        unsigned int previousSize = mSize;
        unsigned int previousCount = mTransactions.size() + mPendingTransactions.size();

        for(std::vector<Transaction *>::const_iterator transaction = pTransactions.begin();
          transaction != pTransactions.end(); ++transaction)
        {
            matchingTransaction = mTransactions.getAndRemoveSorted((*transaction)->hash);
            if(matchingTransaction == NULL)
                matchingTransaction =
                  mPendingTransactions.getAndRemoveSorted((*transaction)->hash);

            if(matchingTransaction != NULL)
            {
                (*transaction)->pullPrecomputed(*matchingTransaction);
                mSize -= matchingTransaction->size();
                if(!addIfLockedByNode(matchingTransaction))
                    delete matchingTransaction;
            }
        }

        if((mTransactions.size() + mPendingTransactions.size()) == previousCount)
        {
            if(Info::instance().initialBlockDownloadIsComplete())
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Mem pool not reduced. %d trans, %d KB",
                  mTransactions.size() + mPendingTransactions.size(), mSize / 1000);
        }
        else
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Mem pool reduced by %d trans, %d KB, %d%% to %d trans, %d KB",
              previousCount - (mTransactions.size() + mPendingTransactions.size()),
              (previousSize - mSize) / 1000, (int)(((float)(previousSize - mSize) /
              (float)previousSize) * 100.0f), mTransactions.size() + mPendingTransactions.size(),
              mSize / 1000);

        mLock.writeUnlock();
    }

    void MemPool::revert(const std::vector<Transaction *> &pTransactions)
    {
        mLock.writeLock("Revert");

        unsigned int previousSize = mSize;
        unsigned int previousCount = mTransactions.size() + mPendingTransactions.size();
        Transaction *newTransaction;

        for(std::vector<Transaction *>::const_iterator transaction = pTransactions.begin() + 1;
          transaction != pTransactions.end(); ++transaction)
        {
            newTransaction = new Transaction(**transaction);
            if(!insert(newTransaction, false))
                delete newTransaction;
        }

        if((mTransactions.size() + mPendingTransactions.size()) == previousCount)
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Mem pool not increased reverting block. %d trans, %d KB",
              mTransactions.size() + mPendingTransactions.size(), mSize / 1000);
        else
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Mem pool increased reverting block by %d trans, %d KB, %d%% to %d trans, %d KB",
              (mTransactions.size() + mPendingTransactions.size()) - previousCount,
              (mSize - previousSize) / 1000, (int)(((float)(mSize - previousSize) /
              (float)mSize) * 100.0f), mTransactions.size() + mPendingTransactions.size(),
              mSize / 1000);

        mLock.writeUnlock();
    }

    bool MemPool::insert(Transaction *pTransaction, bool pAnnounce)
    {
        if(pAnnounce)
            mToAnnounce.push_back(pTransaction->hash);

        if(mTransactions.insertSorted(pTransaction))
        {
            mSize += pTransaction->size();
            return true;
        }
        else
            return false;
    }

    bool MemPool::remove(const NextCash::Hash &pHash)
    {
        Transaction *toRemove = mTransactions.getAndRemoveSorted(pHash);
        if(toRemove != NULL)
        {
            mSize -= toRemove->size();
            if(!addIfLockedByNode(toRemove))
                delete toRemove;
            return true;
        }

        toRemove = mPendingTransactions.getAndRemoveSorted(pHash);
        if(toRemove != NULL)
        {
            mSize -= toRemove->size();
            if(!addIfLockedByNode(toRemove))
                delete toRemove;
            return true;
        }

        return false;
    }

    bool MemPool::outpointExists(Transaction *pTransaction)
    {
        // TODO Implement hash lookup instead of brute force search.
        for(TransactionList::iterator trans = mTransactions.begin(); trans != mTransactions.end();
          ++trans)
            for(std::vector<Input>::iterator input = (*trans)->inputs.begin();
              input != (*trans)->inputs.end(); ++input)
                for(std::vector<Input>::iterator otherInput = pTransaction->inputs.begin();
                  otherInput != pTransaction->inputs.end(); ++otherInput)
                    if(input->outpoint == otherInput->outpoint)
                        return true;
        return false;
    }

    Transaction *MemPool::getTransaction(const NextCash::Hash &pHash, unsigned int pNodeID)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_GET_TRANS_ID, PROFILER_MEMPOOL_GET_TRANS_NAME), true);
#endif
        mLock.readLock();
        Transaction *result = mTransactions.getSorted(pHash);
        mNodeLock.lock();
        if(result != NULL)
            mNodeLocks.insert(pHash, pNodeID);
        mNodeLock.unlock();
        mLock.readUnlock();
        return result;
    }

    void MemPool::releaseTransaction(const NextCash::Hash &pHash, unsigned int pNodeID)
    {
        mNodeLock.lock();
        NextCash::HashContainerList<unsigned int>::Iterator lock;
        for(lock = mNodeLocks.get(pHash); lock != mNodeLocks.end() && lock.hash() == pHash; ++lock)
        {
            if(*lock == pNodeID)
            {
                mNodeLockedTransactions.removeSorted(pHash);
                mNodeLocks.erase(lock);
                break;
            }
        }
        mNodeLock.unlock();
    }

    bool MemPool::getOutput(const NextCash::Hash &pHash, uint32_t pIndex, Output &pOutput)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_MEMPOOL_GET_OUTPUT_ID, PROFILER_MEMPOOL_GET_OUTPUT_NAME), true);
#endif
        bool result = false;
        mLock.readLock();
        Transaction *transaction = mTransactions.getSorted(pHash);
        if(transaction != NULL && transaction->outputs.size() > pIndex)
        {
            pOutput = transaction->outputs.at(pIndex);
            result = true;
        }
        mLock.readUnlock();
        return result;
    }

    void MemPool::drop()
    {
        std::vector<Transaction *>::iterator toRemove = mTransactions.begin();
        uint64_t feeRate = (*toRemove)->feeRate();
        uint64_t newFeeRate;
        for(std::vector<Transaction *>::iterator transaction = toRemove + 1;
          transaction != mTransactions.end(); ++transaction)
        {
            newFeeRate = (*transaction)->feeRate();
            if(newFeeRate < feeRate || (newFeeRate == feeRate &&
              (*transaction)->time() < (*toRemove)->time()))
            {
                feeRate = newFeeRate;
                toRemove = transaction;
            }
        }

        if(toRemove != mTransactions.end())
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
              "Dropping transaction (%llu fee rate) (%d bytes) : %s", feeRate,
              (*toRemove)->size(), (*toRemove)->hash.hex().text());
            mSize -= (*toRemove)->size();
            if(!addIfLockedByNode(*toRemove))
                delete *toRemove;
            mTransactions.erase(toRemove);
        }
    }

    void MemPool::expirePending()
    {
        Time expireTime = getTime() - 60;
        NextCash::String timeString;

        for(std::vector<Transaction *>::iterator transaction = mPendingTransactions.begin();
          transaction != mPendingTransactions.end();)
        {
            if((*transaction)->time() < expireTime)
            {
                timeString.writeFormattedTime((*transaction)->time());
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring pending transaction (time %d) %s (%d bytes) : %s", (*transaction)->time(),
                  timeString.text(), (*transaction)->size(), (*transaction)->hash.hex().text());
                mSize -= (*transaction)->size();
                if(!addIfLockedByNode(*transaction))
                    delete *transaction;
                transaction = mPendingTransactions.erase(transaction);
            }
            else
                ++transaction;
        }
    }

    void MemPool::expire()
    {
        Time expireTime = getTime() - (60 * 60 * 24); // 24 hours
        NextCash::String timeString;

        for(TransactionList::iterator transaction = mTransactions.begin();
          transaction != mTransactions.end();)
        {
            if((*transaction)->time() < expireTime)
            {
                timeString.writeFormattedTime((*transaction)->time());
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring transaction (time %d) %s (%d bytes) : %s", (*transaction)->time(),
                  timeString.text(), (*transaction)->size(), (*transaction)->hash.hex().text());
                mSize -= (*transaction)->size();
                if(!addIfLockedByNode(*transaction))
                    delete *transaction;
                transaction = mTransactions.erase(transaction);
            }
            else
                ++transaction;
        }
    }

    void MemPool::process(unsigned int pMemPoolThreshold)
    {
        mLock.writeLock("Process");
        while(mTransactions.size() > 0 && mSize > pMemPoolThreshold)
            drop();

        expirePending();
        expire();
        mLock.writeUnlock();
    }
}
