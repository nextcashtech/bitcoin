/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "mem_pool.hpp"

#include "arcmist/base/log.hpp"

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

    void MemPool::addBlacklisted(const ArcMist::Hash &pHash)
    {
        mBlackListed.push_back(pHash);
        while(mBlackListed.size() > 1024)
            mBlackListed.erase(mBlackListed.begin());
    }

    bool MemPool::isBlackListed(const ArcMist::Hash &pHash)
    {
        bool result = false;
        mLock.readLock();
        result = mBlackListed.contains(pHash);
        mLock.readUnlock();
        return result;
    }

    bool MemPool::isBlackListedInternal(const ArcMist::Hash &pHash)
    {
        return mBlackListed.contains(pHash);
    }

    MemPool::HashStatus MemPool::addPending(const ArcMist::Hash &pHash, unsigned int pNodeID)
    {
        mLock.writeLock("Add Pending");
        HashStatus result = addPendingInternal(pHash, pNodeID);
        mLock.writeUnlock();
        return result;
    }

    MemPool::HashStatus MemPool::addPendingInternal(const ArcMist::Hash &pHash, unsigned int pNodeID)
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

    void MemPool::markForNode(ArcMist::HashList &pList, unsigned int pNodeID)
    {
        ArcMist::HashList remaining = pList;
        mLock.writeLock("Mark");

        // Mark all existing
        for(std::list<PendingTransactionData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if(remaining.contains((*pending)->hash))
            {
                (*pending)->requestingNode = pNodeID;
                (*pending)->requestedTime = getTime();
                for(ArcMist::HashList::iterator hash=remaining.begin();hash!=remaining.end();++hash)
                    if(*hash == (*pending)->hash)
                    {
                        remaining.erase(hash);
                        break;
                    }
            }

        // Add any remaining as new pending
        for(ArcMist::HashList::iterator hash=remaining.begin();hash!=remaining.end();++hash)
            mPending.push_back(new PendingTransactionData(*hash, pNodeID, getTime()));

        mLock.writeUnlock();
    }

    void MemPool::releaseForNode(unsigned int pNodeID)
    {
        mLock.writeLock("Release");
        for(std::list<PendingTransactionData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if((*pending)->requestingNode == pNodeID)
                (*pending)->requestingNode = 0;
        mLock.writeUnlock();
    }

    void MemPool::getNeeded(ArcMist::HashList &pList)
    {
        mLock.writeLock("Get Needed");
        uint32_t time = getTime();
        for(std::list<PendingTransactionData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if((*pending)->requestingNode == 0 || time - (*pending)->requestedTime > 2)
                pList.push_back((*pending)->hash);
        mLock.writeUnlock();
    }

    void MemPool::getToAnnounce(ArcMist::HashList &pList)
    {
        pList.clear();
        mLock.writeLock("Get Announce");
        for(ArcMist::HashList::iterator hash=mToAnnounce.begin();hash!=mToAnnounce.end();++hash)
            pList.push_back(*hash);
        mToAnnounce.clear();
        mLock.writeUnlock();
    }

    bool MemPool::check(Transaction *pTransaction, TransactionOutputPool &pOutputs, const BlockStats &pBlockStats,
      const Forks &pForks, uint64_t pMinFeeRate)
    {
        ArcMist::HashList outpointsNeeded;
        if(!pTransaction->check(pOutputs, mTransactions, outpointsNeeded,
          pForks.requiredVersion(), pBlockStats, pForks))
        {
            addBlacklisted(pTransaction->hash);
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Failed to check transaction. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash.hex().text());
            return false;
        }

        if(!(pTransaction->status() & Transaction::IS_VALID))
        {
            addBlacklisted(pTransaction->hash);
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction is not valid %02x. (%d bytes) : %s", pTransaction->status(), pTransaction->size(),
              pTransaction->hash.hex().text());
            return false;
        }
        else if(!(pTransaction->status() & Transaction::STANDARD_VERIFIED))
        {
            // Transaction not standard or has invalid signatures
            addBlacklisted(pTransaction->hash);
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction is not standard %02x. (%d bytes) : %s", pTransaction->status(), pTransaction->size(),
              pTransaction->hash.hex().text());
            pTransaction->print(ArcMist::Log::VERBOSE);
            return false;
        }
        else if(!(pTransaction->status() & Transaction::OUTPOINTS_FOUND))
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Transaction requires unseen output. Adding to pending. (%d bytes) : %s", pTransaction->size(),
              pTransaction->hash.hex().text());

            for(ArcMist::HashList::iterator outpoint=outpointsNeeded.begin();outpoint!=outpointsNeeded.end();++outpoint)
                addPendingInternal(*outpoint, 0);
            return pTransaction->status();
        }

        if(pTransaction->feeRate() < pMinFeeRate)
        {
            addBlacklisted(pTransaction->hash);
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
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
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
                  "Failed to check pending transaction. Removing. (%d bytes) (%llu fee rate) : %s", (*transaction)->size(),
                  (*transaction)->feeRate(), (*transaction)->hash.hex().text());
                mSize -= (*transaction)->size();
                transaction = mPendingTransactions.erase(transaction);
            }
            else if(((*transaction)->status() & Transaction::STANDARD_VERIFIED) == Transaction::STANDARD_VERIFIED)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
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

    bool MemPool::add(Transaction *pTransaction, TransactionOutputPool &pOutputs, const BlockStats &pBlockStats,
      const Forks &pForks, uint64_t pMinFeeRate)
    {
        // Check the transaction isn't already in the list
        if(get(pTransaction->hash) != NULL)
            return false;

        mLock.readLock();
        for(TransactionList::iterator transaction=mPendingTransactions.begin();transaction!=mPendingTransactions.end();++transaction)
            if((*transaction)->hash == pTransaction->hash)
            {
                mLock.readUnlock();
                return false;
            }
        mLock.readUnlock();

        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
          // "Attempting to add transaction. (%d bytes) : %s", pTransaction->size(),
          // pTransaction->hash.hex().text());

        mLock.writeLock("Verify Insert");
        //TODO Move this outside of write lock
        if(!check(pTransaction, pOutputs, pBlockStats, pForks, pMinFeeRate))
        {
            mLock.writeUnlock();
            return false;
        }
        else if(!(pTransaction->status() & Transaction::OUTPOINTS_FOUND))
        {
            // Put in pending to wait for outpoint transactions
            mPendingTransactions.insertSorted(pTransaction);
            mSize += pTransaction->size();
            mLock.writeUnlock();
            return true;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
          "Adding transaction (%d bytes) (%llu fee rate) : %s", pTransaction->size(), pTransaction->feeRate(),
          pTransaction->hash.hex().text());

        insert(pTransaction, true);

        mLock.writeUnlock();
        return true;
    }

    void MemPool::remove(const std::vector<Transaction *> &pTransactions)
    {
        mLock.writeLock("Remove");
        unsigned int previousSize = mSize;
        unsigned int previousCount = mTransactions.size() + mPendingTransactions.size();
        for(std::vector<Transaction *>::const_iterator transaction=pTransactions.begin();transaction!=pTransactions.end();++transaction)
            remove((*transaction)->hash);
        if((mTransactions.size() + mPendingTransactions.size()) == previousCount)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Mem pool not reduced. %d trans, %d KiB", mTransactions.size() + mPendingTransactions.size(),
              mSize / 1024);
        else
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
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
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
              "Mem pool not increased reverting block. %d trans, %d KiB", mTransactions.size() + mPendingTransactions.size(),
              mSize / 1024);
        else
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MEM_POOL_LOG_NAME,
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

    bool MemPool::remove(const ArcMist::Hash &pHash)
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

    Transaction *MemPool::get(const ArcMist::Hash &pHash)
    {
        mLock.readLock();
        Transaction *result = getInternal(pHash);
        mLock.readUnlock();
        return result;
    }

    Transaction *MemPool::getInternal(const ArcMist::Hash &pHash)
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
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
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
        ArcMist::String timeString;

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
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_MEM_POOL_LOG_NAME,
                  "Expiring pending transaction (time %d) %s : %s", (*transaction)->time(), timeString.text(),
                  (*transaction)->hash.hex().text());
                transaction = mPendingTransactions.erase(transaction);
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
        mLock.writeUnlock();
    }
}
