/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_MEM_POOL_HPP
#define BITCOIN_MEM_POOL_HPP

#include "mutex.hpp"
#include "hash.hpp"
#include "base.hpp"
#include "transaction.hpp"
#include "outputs.hpp"
#include "bloom_filter.hpp"

#include <vector>


namespace BitCoin
{
    class Chain;

    class PendingTransactionData
    {
    public:

        PendingTransactionData(const NextCash::Hash &pHash, unsigned int pNodeID, Time pTime)
        {
            hash = pHash;
            requestedTime = pTime;
            requestingNode = pNodeID;
            firstTime = getTime();
        }

        NextCash::Hash hash;
        Time requestedTime;
        unsigned int requestingNode;
        Time firstTime;

    private:
        PendingTransactionData(PendingTransactionData &pCopy);
        PendingTransactionData &operator = (PendingTransactionData &pRight);
    };

    class MemPool
    {
    public:

        MemPool();
        ~MemPool();

        enum HashStatus { HASH_NEED, HASH_ALREADY_HAVE, HASH_INVALID, HASH_LOW_FEE, HASH_NON_STANDARD };
        HashStatus hashStatus(Chain *pChain, const NextCash::Hash &pHash);

        // Add transaction to mem pool. Returns false if it was already in the mem pool or is
        //   invalid
        enum AddStatus { ADDED, ALREADY_HAVE, NON_STANDARD, DOUBLE_SPEND, LOW_FEE,
          UNSEEN_OUTPOINTS, INVALID };
        AddStatus add(Transaction *pTransaction, uint64_t pMinFeeRate, Chain *pChain);

        // Pull transactions that have been added to a block from the mempool.
        // Locks mempool while the block is being processed.
        unsigned int pull(std::vector<Transaction *> &pTransactions);

        // Add transactions back in to mempool for a block that is being reverted.
        // Unlocks the mempool since block is no longer processing.
        void revert(const std::vector<Transaction *> &pTransactions);

        // Remove any transactions whose inputs were spent by the block.
        // Unlocks the mempool since the block is finished processing.
        void finalize(Chain *pChain);

        Transaction *getTransaction(const NextCash::Hash &pHash, unsigned int pNodeID);
        void releaseTransaction(const NextCash::Hash &pHash, unsigned int pNodeID);

        bool getOutput(const NextCash::Hash &pHash, uint32_t pIndex, Output &pOutput);

        void process(unsigned int pMemPoolThreshold);

        // Get transaction hashes that should be announced
        void getToAnnounce(NextCash::HashList &pList);
        void getFullList(NextCash::HashList &pList, const BloomFilter &pFilter);

        void checkPending(Chain *pChain, uint64_t pMinFeeRate);

        NextCash::stream_size size() const { return mSize; }
        unsigned int count() const { return mTransactions.size(); }
        unsigned int pendingCount() const { return mPendingTransactions.size(); }

    private:

        bool insert(Transaction *pTransaction, bool pAnnounce);
        bool remove(const NextCash::Hash &pHash);

        // Drop the oldest/lowest fee rate transaction
        void drop();

        // Drop pending transactions older than 60 seconds
        void expirePending();

        // Drop verified transactions older than 24 hours
        void expire();

        void addInvalidHash(const NextCash::Hash &pHash);
        void addLowFeeHash(const NextCash::Hash &pHash);
        void addNonStandardHash(const NextCash::Hash &pHash);

        // Checks transaction validity.
        void check(Transaction *pTransaction, uint64_t pMinFeeRate, Chain *pChain);

        // Return true if any of the transactions outpoints are shared with any transaction in the
        //   mempool
        bool outpointExists(Transaction *pTransaction);

        // Return true if this identifies an output in the mempool.
        bool outputExists(const NextCash::Hash &pTransactionID, unsigned int pIndex);

        NextCash::ReadersLock mLock;
        NextCash::stream_size mSize; // Size in bytes of all transactions in mempool

        // Hashes for transactions currently being validated.
        NextCash::HashList mValidatingTransactions;

        TransactionList mTransactions; // Verified transactions.
        TransactionList mPendingTransactions; // Transactions waiting for unseen outpoints.

        // Transactions that failed to verify.
        NextCash::HashList mInvalidHashes, mLowFeeHashes, mNonStandardHashes;

        NextCash::HashList mToAnnounce; // Transactions that need to be announced to peers.

        // Hold removed transactions here, while a node is sending it, until the node releases it
        //   and it can be deleted.
        NextCash::Mutex mNodeLock;
        NextCash::HashContainerList<unsigned int> mNodeLocks;
        TransactionList mNodeLockedTransactions;

        bool addIfLockedByNode(Transaction *pTransaction)
        {
            mNodeLock.lock();
            bool result = mNodeLocks.get(pTransaction->hash) != mNodeLocks.end();
            if(result)
                mNodeLockedTransactions.insertSorted(pTransaction);
            mNodeLock.unlock();
            return result;
        }

    };
}

#endif
