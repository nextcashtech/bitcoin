/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_MEM_POOL_HPP
#define BITCOIN_MEM_POOL_HPP

#include "arcmist/base/mutex.hpp"
#include "base.hpp"
#include "transaction.hpp"
#include "outputs.hpp"

#include <vector>


namespace BitCoin
{
    class PendingTransactionData
    {
    public:

        PendingTransactionData(const Hash &pHash, unsigned int pNodeID, int32_t pTime)
        {
            hash = pHash;
            requestedTime = pTime;
            requestingNode = pNodeID;
            firstTime = getTime();
        }

        Hash hash;
        int32_t requestedTime;
        unsigned int requestingNode;
        int32_t firstTime;

    private:
        PendingTransactionData(PendingTransactionData &pCopy);
        PendingTransactionData &operator = (PendingTransactionData &pRight);
    };

    class MemPool
    {
    public:

        MemPool();
        ~MemPool();

        enum HashStatus { ALREADY_HAVE, NEED, BLACK_LISTED };
        // Add to transaction hashes that need downloaded and verified. Returns hash status. Zero means already added.
        HashStatus addPending(const Hash &pHash, unsigned int pNodeID);

        // Add transaction to mem pool. Returns false if it was already in the mem pool or is invalid
        bool add(Transaction *pTransaction, TransactionOutputPool &pOutputs, const BlockStats &pBlockStats,
          const Forks &pForks, uint64_t pMinFeeRate);

        // Remove transactions that have been added to a block
        void remove(const std::vector<Transaction *> &pTransactions);

        // Add transactions back in for a block that is being reverted
        void revert(const std::vector<Transaction *> &pTransactions);

        Transaction *get(const Hash &pHash);

        void process(unsigned int pMemPoolThreshold);

        void markForNode(HashList &pList, unsigned int pNodeID);
        void releaseForNode(unsigned int pNodeID);

        void getNeeded(HashList &pList);

        // Get transaction hashes that should be announced
        void getToAnnounce(HashList &pList);

        void checkPendingTransactions(TransactionOutputPool &pOutputs,
          const BlockStats &pBlockStats, const Forks &pForks, uint64_t pMinFeeRate);

        bool isBlackListed(const Hash &pHash);

        unsigned int size() const { return mSize; }
        unsigned int count() const { return mTransactions.size(); }
        unsigned int pendingCount() const { return mPendingTransactions.size(); }

    private:

        bool insert(Transaction *pTransaction, bool pAnnounce);
        bool remove(const Hash &pHash);

        // Drop the oldest/lowest fee rate transaction
        void drop();

        // Drop pending transactions older than 10 minutes
        void expirePending();

        void addBlacklisted(const Hash &pHash);
        bool isBlackListedInternal(const Hash &pHash);

        HashStatus addPendingInternal(const Hash &pHash, unsigned int pNodeID);

        Transaction *getInternal(const Hash &pHash);

        // Verifies that a transaction is valid
        bool check(Transaction *pTransaction, TransactionOutputPool &pOutputs,
          const BlockStats &pBlockStats, const Forks &pForks, uint64_t pMinFeeRate);

        ArcMist::ReadersLock mLock;
        unsigned int mSize; // Size in bytes of all transactions in mempool
        TransactionList mTransactions; // Verified transactions
        TransactionList mPendingTransactions; // Transactions waiting for unseen outpoints
        HashList mBlackListed; // Transactions that failed to verify
        HashList mToAnnounce; // Transactions that need to be announced to peers
        std::list<PendingTransactionData *> mPending; // IDs for transactions not received yet

    };
}

#endif
