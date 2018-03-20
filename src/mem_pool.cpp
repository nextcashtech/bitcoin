/**************************************************************************
 * Copyright 2017 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "mem_pool.hpp"

#include "nextcash/base/log.hpp"

#define BITCOIN_MEM_POOL_LOG_NAME "MemPool"


namespace BitCoin
{
    MemPool::MemPool() : mLock("Mem Pool")
    {
        mSize = 0;
    }

    MemPool::~MemPool()
    {
        mLock.writeLock("Destroy");
        for(std::list<PendingTransactionData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            delete *pending;
        mLock.writeUnlock();
    }

    void MemPool::addBlacklisted(const NextCash::Hash &pHash)
    {
        mBlackListed.push_back(pHash);
        while(mBlackListed.size() > 1024)
            mBlackListed.erase(mBlackListed.begin());
    }

    bool MemPool::isBlackListed(const NextCash::Hash &pHash)
    {
        bool result = false;
        mLock.readLock();
        result = mBlackListed.contains(pHash);
        mLock.readUnlock();
        return result;
    }

    bool MemPool::isBlackListedInternal(const NextCash::Hash &pHash)
    {
        return mBlackListed.contains(pHash);
    }

    MemPool::HashStatus MemPool::addPending(const NextCash::Hash &pHash, TransactionOutputPool &pOutputs, unsigned int pNodeID)
    {
        mLock.writeLock("Add Pending");

        if(pOutputs.find(pHash, 0) != NULL)
        {
            mLock.writeUnlock();
            return ALREADY_HAVE; // Already in UTXO set
        }

        HashStatus result = addPendingInternal(pHash, pNodeID);
        mLock.writeUnlock();
        return result;
    }

    MemPool::HashStatus MemPool::addPendingInternal(const NextCash::Hash &pHash, unsigned int pNodeID)
    {
        if(isBlackListedInternal(pHash))
            return BLACK_LISTED;

        if(getInternal(pHash) != NULL)
            return ALREADY_HAVE;

        for(std::list<PendingTransactionData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if((*pending)->hash == pHash)
            {
                if((*pending)->requestingNode == 0 || getTime() - (*pending)->requestedTime > 2)
                {
                    (*pending)->requestingNode = pNodeID;
                    (*pending)->requestedTime = getTime();
                    return NEED;
                }
                else
                    return ALREADY_HAVE;
            }

        mPending.push_back(new PendingTransactionData(pHash, pNodeID, getTime()));
        return NEED;
    }

    void MemPool::markForNode(NextCash::HashList &pList, unsigned int pNodeID)
    {
        NextCash::HashList remaining = pList;
        mLock.writeLock("Mark");

        // Mark all existing
        for(std::list<PendingTransactionData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if(remaining.contains((*pending)->hash))
            {
                (*pending)->requestingNode = pNodeID;
                (*pending)->requestedTime = getTime();
                for(NextCash::HashList::iterator hash=remaining.begin();hash!=remaining.end();++hash)
                    if(*hash == (*pending)->hash)
                    {
                        remaining.erase(hash);
                        break;
                    }
            }

        // Add any remaining as new pending
        for(NextCash::HashList::iterator hash=remaining.begin();hash!=remaining.end();++hash)
            mPending.push_back(new PendingTransactionData(*hash, pNodeID, getTime()));

        mLock.writeUnlock();
    }

    void MemPool::releaseForNode(unsigned int pNodeID)
    {
        mLock.readLock();
        for(std::list<PendingTransactionData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if((*pending)->requestingNode == pNodeID)
                (*pending)->requestingNode = 0;
        mLock.readUnlock();
    }

    void MemPool::getNeeded(NextCash::HashList &pList)
    {
        mLock.readLock();
        uint32_t time = getTime();
        for(std::list<PendingTransactionData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if((*pending)->requestingNode == 0 || time - (*pending)->requestedTime > 2)
                pList.push_back((*pending)->hash);
        mLock.readUnlock();
    }

    void MemPool::getToAnnounce(NextCash::HashList &pList)
    {
        pList.clear();
        mLock.readLock();
        for(NextCash::HashList::iterator hash=mToAnnounce.begin();hash!=mToAnnounce.end();++hash)
            pList.push_back(*hash);
        mToAnnounce.clear();
        mLock.readUnlock();
    }

    void MemPool::getFullList(NextCash::HashList &pList, const BloomFilter &pFilter)
    {
        pList.clear();
        mLock.readLock();
        for(TransactionList::iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            if(pFilter.isEmpty() || pFilter.contains(**trans))
                pList.push_back((*trans)->hash);
        mLock.readUnlock();
    }

    bool MemPool::outpointExists(Transaction *pTransaction)
    {
        for(TransactionList::iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            for(std::vector<Input *>::iterator input=(*trans)->inputs.begin();input!=(*trans)->inputs.end();++input)
                for(std::vector<Input *>::iterator otherInput=pTransaction->inputs.begin();otherInput!=pTransaction->inputs.end();++otherInput)
                    if((*input)->outpoint == (*otherInput)->outpoint)
                        return true;
        return false;
    }

    bool MemPool::check(Transaction *pTransaction, TransactionOutputPool &pOutputs, const BlockStats &pBlockStats,
      const Forks &pForks, uint64_t pMinFeeRate)
    {
        NextCash::HashList outpointsNeeded;
        if(!pTransaction->check(pOutputs, mTransactions, outpointsNeeded,
          pForks.requiredVersion(), pBlockStats, pForks))
        {
            addBlacklisted(pTransaction->hash);
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Failed to check transaction. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash.hex().text());
            return false;
        }

        if(!(pTransaction->status() & Transaction::IS_VALID))
            return false;
        else if(!(pTransaction->status() & Transaction::STANDARD_VERIFIED))
        {
            // Transaction not standard or has invalid signatures
            addBlacklisted(pTransaction->hash);
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction is not standard %02x. (%d bytes) : %s", pTransaction->status(), pTransaction->size(),
              pTransaction->hash.hex().text());
            pTransaction->print(NextCash::Log::VERBOSE);
            return false;
        }
        else if(!(pTransaction->status() & Transaction::OUTPOINTS_FOUND))
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction requires unseen output. Adding to pending. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash.hex().text());

            for(NextCash::HashList::iterator outpoint=outpointsNeeded.begin();outpoint!=outpointsNeeded.end();++outpoint)
                addPendingInternal(*outpoint, 0);

            return pTransaction->status();
        }

        if(pTransaction->feeRate() < pMinFeeRate)
        {
            addBlacklisted(pTransaction->hash);
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Fee rate below minimum %llu < %llu (%lld fee) (%d bytes) : %s", pTransaction->feeRate(), pMinFeeRate,
              pTransaction->fee(), pTransaction->size(), pTransaction->hash.hex().text());
            return false;
        }

        return pTransaction->status();
    }

    void MemPool::checkPendingTransactions(TransactionOutputPool &pOutputs,
      const BlockStats &pBlockStats, const Forks &pForks, uint64_t pMinFeeRate)
    {
        mLock.writeLock("Check Pending");
        for(TransactionList::iterator transaction=mPendingTransactions.begin();transaction!=mPendingTransactions.end();)
        {
            if(!check(*transaction, pOutputs, pBlockStats, pForks, pMinFeeRate))
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Failed to check pending transaction. Removing. (%d bytes) (%llu fee rate) : %s", (*transaction)->size(),
                  (*transaction)->feeRate(), (*transaction)->hash.hex().text());
                mSize -= (*transaction)->size();
                transaction = mPendingTransactions.erase(transaction);
            }
            else if(((*transaction)->status() & Transaction::STANDARD_VERIFIED) == Transaction::STANDARD_VERIFIED)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Verified pending transaction. (%d bytes) (%llu fee rate) : %s", (*transaction)->size(),
                  (*transaction)->feeRate(), (*transaction)->hash.hex().text());
                if(insert(*transaction, true))
                {
                    mSize -= (*transaction)->size();
                    transaction = mPendingTransactions.erase(transaction);
                }
                else
                    ++transaction;
            }
            else
                ++transaction;
        }
        mLock.writeUnlock();
    }

    MemPool::AddStatus MemPool::add(Transaction *pTransaction, TransactionOutputPool &pOutputs,
      const BlockStats &pBlockStats, const Forks &pForks, uint64_t pMinFeeRate)
    {
        mLock.writeLock("Add");

        // Check the transaction isn't already in the list
        if(get(pTransaction->hash, true) != NULL)
        {
            mLock.writeUnlock();
            return NOT_NEEDED;
        }

        if(pOutputs.find(pTransaction->hash, 0) != NULL)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction already confirmed : %s", pTransaction->hash.hex().text());
            mLock.writeUnlock();
            return NOT_NEEDED;
        }

        for(TransactionList::iterator transaction=mPendingTransactions.begin();transaction!=mPendingTransactions.end();++transaction)
            if((*transaction)->hash == pTransaction->hash)
            {
                mLock.writeUnlock();
                return NOT_NEEDED;
            }

        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
          // "Attempting to add transaction. (%d bytes) : %s", pTransaction->size(),
          // pTransaction->hash.hex().text());

        //TODO Move this outside of write lock
        if(!check(pTransaction, pOutputs, pBlockStats, pForks, pMinFeeRate))
        {
            mLock.writeUnlock();
            if(pTransaction->feeRate() < pMinFeeRate)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
                  "Transaction has low fee (%d bytes) (%llu fee rate) : %s", pTransaction->size(), pTransaction->feeRate(),
                  pTransaction->hash.hex().text());
                return LOW_FEE;
            }
            else if((pTransaction->status() & Transaction::STANDARD_VERIFIED) == Transaction::STANDARD_VERIFIED &&
              pTransaction->status() & Transaction::OUTPOINTS_SPENT)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
                  "Transaction has double spend : %s", pTransaction->hash.hex().text());
                return DOUBLE_SPEND;
            }
            else
                return NON_STANDARD;
        }
        else if(!(pTransaction->status() & Transaction::OUTPOINTS_FOUND))
        {
            // Put in pending to wait for outpoint transactions
            mPendingTransactions.insertSorted(pTransaction);
            mSize += pTransaction->size();
            mLock.writeUnlock();
            return UNSEEN_OUTPOINTS;
        }

        if(outpointExists(pTransaction))
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction has double spend from mempool : %s", pTransaction->hash.hex().text());
            addBlacklisted(pTransaction->hash);
            mLock.writeUnlock();
            return DOUBLE_SPEND;
        }

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
          "Adding transaction (%d bytes) (%llu fee rate) : %s", pTransaction->size(), pTransaction->feeRate(),
          pTransaction->hash.hex().text());

        insert(pTransaction, true);

        mLock.writeUnlock();
        return ADDED;
    }

    void MemPool::remove(const std::vector<Transaction *> &pTransactions)
    {
        mLock.writeLock("Remove");
        unsigned int previousSize = mSize;
        unsigned int previousCount = mTransactions.size() + mPendingTransactions.size();
        for(std::vector<Transaction *>::const_iterator transaction=pTransactions.begin();transaction!=pTransactions.end();++transaction)
            remove((*transaction)->hash);
        if((mTransactions.size() + mPendingTransactions.size()) == previousCount)
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Mem pool not reduced. %d trans, %d KiB", mTransactions.size() + mPendingTransactions.size(),
              mSize / 1024);
        else
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Mem pool reduced by %d trans, %d KiB, %d%% to %d trans, %d KiB",
              previousCount - (mTransactions.size() + mPendingTransactions.size()), (previousSize - mSize) / 1024,
              (int)(((float)(previousSize - mSize) / (float)previousSize) * 100.0f), mTransactions.size() + mPendingTransactions.size(),
              mSize / 1024);
        mLock.writeUnlock();
    }

    void MemPool::revert(const std::vector<Transaction *> &pTransactions)
    {
        mLock.writeLock("Revert");
        unsigned int previousSize = mSize;
        unsigned int previousCount = mTransactions.size() + mPendingTransactions.size();
        Transaction *newTransaction;
        for(std::vector<Transaction *>::const_iterator transaction=pTransactions.begin()+1;transaction!=pTransactions.end();++transaction)
        {
            newTransaction = new Transaction(**transaction);
            if(!insert(newTransaction, false))
                delete newTransaction;
        }
        if((mTransactions.size() + mPendingTransactions.size()) == previousCount)
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Mem pool not increased reverting block. %d trans, %d KiB", mTransactions.size() + mPendingTransactions.size(),
              mSize / 1024);
        else
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Mem pool increased reverting block by %d trans, %d KiB, %d%% to %d trans, %d KiB",
              (mTransactions.size() + mPendingTransactions.size()) - previousCount, (mSize - previousSize) / 1024,
              (int)(((float)(mSize - previousSize) / (float)mSize) * 100.0f), mTransactions.size() + mPendingTransactions.size(),
              mSize / 1024);
        mLock.writeUnlock();
    }

    bool MemPool::insert(Transaction *pTransaction, bool pAnnounce)
    {
        if(pAnnounce)
            mToAnnounce.push_back(pTransaction->hash);

        // Remove from pending
        for(std::list<PendingTransactionData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if((*pending)->hash == pTransaction->hash)
            {
                delete *pending;
                mPending.erase(pending);
                break;
            }

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
        // Remove from pending
        for(std::list<PendingTransactionData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if((*pending)->hash == pHash)
            {
                delete *pending;
                mPending.erase(pending);
                return true;
            }

        Transaction *toRemove = mPendingTransactions.getSorted(pHash);
        if(toRemove != NULL)
        {
            mSize -= toRemove->size();
            mPendingTransactions.removeSorted(pHash);
            return true;
        }

        toRemove = mTransactions.getSorted(pHash);
        if(toRemove != NULL)
        {
            mSize -= toRemove->size();
            mTransactions.removeSorted(pHash);
            return true;
        }

        return false;
    }

    Transaction *MemPool::get(const NextCash::Hash &pHash, bool pLocked)
    {
        if(!pLocked)
            mLock.readLock();
        Transaction *result = getInternal(pHash);
        if(!pLocked)
            mLock.readUnlock();
        return result;
    }

    Transaction *MemPool::getInternal(const NextCash::Hash &pHash)
    {
        return mTransactions.getSorted(pHash);
    }

    void MemPool::drop()
    {
        std::vector<Transaction *>::iterator toRemove = mTransactions.begin();
        uint64_t feeRate = (*toRemove)->feeRate();
        uint64_t newFeeRate;
        for(std::vector<Transaction *>::iterator transaction=toRemove+1;transaction!=mTransactions.end();++transaction)
        {
            newFeeRate = (*transaction)->feeRate();
            if(newFeeRate < feeRate || (newFeeRate == feeRate && (*transaction)->time() < (*toRemove)->time()))
            {
                feeRate = newFeeRate;
                toRemove = transaction;
            }
        }

        if(toRemove != mTransactions.end())
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
              "Dropping transaction with fee rate %llu (%d bytes) : %s", feeRate, (*toRemove)->size(),
              (*toRemove)->hash.hex().text());
            mSize -= (*toRemove)->size();
            delete *toRemove;
            mTransactions.erase(toRemove);
        }
    }

    void MemPool::expirePending()
    {
        int32_t expireTime = getTime() - 60;
        NextCash::String timeString;

        for(std::list<PendingTransactionData *>::iterator pending=mPending.begin();pending!=mPending.end();)
        {
            if((*pending)->firstTime < expireTime)
            {
                delete *pending;
                pending = mPending.erase(pending);
            }
            else
                ++pending;
        }

        for(std::vector<Transaction *>::iterator transaction=mPendingTransactions.begin();transaction!=mPendingTransactions.end();)
        {
            if((*transaction)->time() < expireTime)
            {
                timeString.writeFormattedTime((*transaction)->time());
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring pending transaction (time %d) %s : %s", (*transaction)->time(), timeString.text(),
                  (*transaction)->hash.hex().text());
                transaction = mPendingTransactions.erase(transaction);
            }
            else
                ++transaction;
        }
    }

    void MemPool::expire()
    {
        int32_t expireTime = getTime() - (60 * 60 * 24);
        NextCash::String timeString;

        for(TransactionList::iterator transaction=mTransactions.begin();transaction!=mTransactions.end();)
        {
            if((*transaction)->time() < expireTime)
            {
                timeString.writeFormattedTime((*transaction)->time());
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring transaction (time %d) %s : %s", (*transaction)->time(), timeString.text(),
                  (*transaction)->hash.hex().text());
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
