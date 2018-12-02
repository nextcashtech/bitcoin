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
#include "hash_set.hpp"
#include "sorted_set.hpp"
#include "base.hpp"
#include "message.hpp"
#include "transaction.hpp"
#include "outputs.hpp"
#include "bloom_filter.hpp"
#include "info.hpp"

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

    class ShortIDHash : public NextCash::SortedObject
    {
    public:

        ShortIDHash()
        {
            shortID = 0;
        }
        ShortIDHash(uint64_t pShortID)
        {
            shortID = pShortID;
        }
        ShortIDHash(const NextCash::Hash &pHash, uint64_t pShortID) : hash(pHash)
        {
            shortID = pShortID;
        }
        ShortIDHash(const ShortIDHash &pCopy) : hash(pCopy.hash)
        {
            shortID = pCopy.shortID;
        }
        ~ShortIDHash() {}

        int compare(SortedObject *pRight)
        {
            if(shortID < ((ShortIDHash *)pRight)->shortID)
                return -1;
            else if(shortID > ((ShortIDHash *)pRight)->shortID)
                return 1;
            else
                return 0;
        }

        NextCash::Hash hash;
        uint64_t shortID;

    };

    class MemPool
    {
    public:

        MemPool();
        ~MemPool();

        enum HashStatus { HASH_NEED, HASH_REQUESTED, HASH_ALREADY_HAVE, HASH_INVALID, HASH_LOW_FEE,
          HASH_NON_STANDARD, HASH_DOUBLE_SPEND, HASH_REJECTED_ANCESTOR };
        HashStatus hashStatus(Chain *pChain, const NextCash::Hash &pHash, unsigned int pNodeID,
          bool pRetry);

        // Return requested hashes that need to be requested again.
        // Note: This doesn't seem to make sense. If a node announces a transaction that we don't
        //   have, we request it.
        //   Replaced by nodes saving hashes for transactions already requested when they were
        //     announced. Then check to make sure they were received.
        // void getNeededHashes(NextCash::HashList &pList);

        // Mark transactions as requested by specified node.
        void markTransactions(NextCash::HashList &pList, unsigned int pNodeID);

        // Release any requested hashes for this node.
        void release(unsigned int pNodeID);

        // Release the requested hash.
        // Returns true if it was a missing outpoint given by this node.
        bool release(const NextCash::Hash &pHash, unsigned int pNodeID);

        // Add transaction to mem pool. Returns false if it was already in the mem pool or is
        //   invalid
        enum AddStatus { ADDED, ALREADY_HAVE, NON_STANDARD, DOUBLE_SPEND, LOW_FEE,
          UNSEEN_OUTPOINTS, IN_CHAIN, INVALID };
        AddStatus add(Transaction *pTransaction, Chain *pChain,
          unsigned int pNodeID, NextCash::HashList &pUnseenOutpoints);

        // Pull transactions that have been added to a block from the mempool.
        // Locks mempool while the block is being processed.
        unsigned int pull(std::vector<Transaction *> &pTransactions);

        // Add transactions back in to mempool for a block that is being reverted.
        // Unlocks the mempool since block is no longer processing.
        void revert(const std::vector<Transaction *> &pTransactions, bool pFollowingPull);

        // Remove any transactions whose inputs were spent by the block.
        // Unlocks the mempool since the block is finished processing.
        void finalize(std::vector<Transaction *> &pTransactions);

        // Calculate short IDs for all transaction hashes.
        void calculateShortIDs(Message::CompactBlockData *pCompactBlock,
          NextCash::SortedSet &pShortIDs);

        // Get a copy of a transaction. Receiver is responsible for delete.
        Transaction *getTransactionCopy(const NextCash::Hash &pHash);

        // Get the transaction.
        Transaction *getTransaction(const NextCash::Hash &pHash, unsigned int pNodeID);

        // Confirm no longer using transaction from getTransaction.
        void freeTransaction(const NextCash::Hash &pHash, unsigned int pNodeID);

        bool getOutput(const NextCash::Hash &pHash, uint32_t pIndex, Output &pOutput,
          bool pIsLocked);

        void process(Chain *pChain);

        // Get transaction hashes that should be announced.
        void getToAnnounce(TransactionList &pList, unsigned int pNodeID);
        void freeTransactions(TransactionList &pList, unsigned int pNodeID);

        // Full mempool requests.
        void getFullList(NextCash::HashList &pList, const BloomFilter &pFilter);

        NextCash::stream_size size() const { return mSize; }
        NextCash::stream_size pendingSize() const { return mPendingSize; }
        unsigned int count() const { return mTransactions.size(); }
        unsigned int pendingCount() const { return mPendingTransactions.size(); }

        // Request support
        class RequestData
        {
        public:

            unsigned int count; // Number of transactions
            NextCash::stream_size size; // Size in bytes
            uint64_t totalFee; // Total of fees
            NextCash::stream_size zero; // Zero fee
            NextCash::stream_size low;  // >0  <1 sat/B
            NextCash::stream_size one;  // >=1 <2 sat/B
            NextCash::stream_size two;  // >=2 <5 sat/B
            NextCash::stream_size five; // >=5 <10 sat/B
            NextCash::stream_size remainingSize; // Total size of remaining transactions
            uint64_t remainingFee; // Total fee of remaining transactions
            unsigned int pendingCount; // Number of pending transactions
            NextCash::stream_size pendingSize; // Pending size in bytes

            void clear()
            {
                count    = 0;
                size     = 0UL;
                totalFee = 0UL;
                zero     = 0UL;
                low      = 0UL;
                one      = 0UL;
                two      = 0UL;
                five     = 0UL;
                remainingSize = 0UL;
                remainingFee  = 0UL;
                pendingCount  = 0;
                pendingSize   = 0UL;
            }

        };

        void getRequestData(RequestData &pData);

    private:

        Info &mInfo;

        bool insert(Transaction *pTransaction, bool pAnnounce);

        // Returns true if the transaction is locked by a node.
        void removeInternal(Transaction *pTransaction);

        // Drop all the oldest/lowest fee rate transactions.
        void drop();

        // Drop verified transactions older than 24 hours
        // Drop pending transactions older than 5 minutes.
        void expire();

        class RequestedHash : public NextCash::HashObject
        {
        public:

            NextCash::Hash hash;
            unsigned int nodeID;
            Time time;
            unsigned int requestAttempts;
            bool missing; // Requested because of missing outpoint in given transaction.

            RequestedHash(const NextCash::Hash &pHash, unsigned int pNodeID, Time pTime, bool pMissing = false)
            {
                hash = pHash;
                nodeID = pNodeID;
                time = pTime;
                requestAttempts = 1;
                missing = pMissing;
            }

            RequestedHash(const RequestedHash &pCopy)
            {
                hash = pCopy.hash;
                nodeID = pCopy.nodeID;
                time = pCopy.time;
                requestAttempts = pCopy.requestAttempts;
                missing = pCopy.missing;
            }

            ~RequestedHash() {}

            const RequestedHash &operator = (const RequestedHash &pRight)
            {
                hash = pRight.hash;
                nodeID = pRight.nodeID;
                time = pRight.time;
                requestAttempts = pRight.requestAttempts;
                missing = pRight.missing;
                return *this;
            }

            const NextCash::Hash &getHash() { return hash; }
        };

        NextCash::Mutex mRequestedHashesLock;
        NextCash::HashSet mRequestedHashes;

        // Adds hash to requested list with the node ID.
        // Returns false if the hash is already in the list.
        bool addRequested(const NextCash::Hash &pHash, unsigned int pNodeID, bool pMissing,
          bool pRetry);

        // Remove hash from requested list.
        void removeRequested(const NextCash::Hash &pHash);

        bool haveTransaction(const NextCash::Hash &pHash);

        // Checks transaction validity.
        bool check(Transaction *pTransaction, Chain *pChain, unsigned int pNodeID,
          NextCash::HashList &pUnseenOutpoints, bool pPending);

        bool checkPendingTransaction(Chain *pChain, Transaction *pTransaction,
          unsigned int pDepth);

        // Check for child transactions of this transaction in pending.
        void checkPendingForNewTransaction(Chain *pChain, const NextCash::Hash &pHash,
          unsigned int pDepth);

        // Remove any child transactions of this transaction from pending.
        void removePendingForNewTransaction(Chain *pChain, const NextCash::Hash &pHash,
          unsigned int pDepth);

        class OutpointHash : public NextCash::HashObject
        {
        public:

            OutpointHash(Outpoint &pOutpoint) : outpoint(pOutpoint) { calculateHash(); }
            ~OutpointHash() {}

            Outpoint outpoint;

            const NextCash::Hash &getHash() { return mHash; }

        private:

            NextCash::Hash mHash;

            void calculateHash()
            {
                NextCash::Digest digest(NextCash::Digest::SHA256);
                outpoint.transactionID.write(&digest);
                digest.writeUnsignedInt(outpoint.index);
                digest.getResult(&mHash);
            }

        };

        static void getOutpointHash(const Outpoint &pOutpoint, NextCash::Hash &pHash);

        NextCash::HashSet mOutpoints;

        // Return true if any of the transactions outpoints are shared with any transaction in the
        //   mempool
        bool outpointExists(Transaction *pTransaction);

        // Return true if this identifies an output in the mempool.
        bool outputExists(const NextCash::Hash &pTransactionID, unsigned int pIndex);

        // Returns true if this transaction's outputs are spent by any transaction in the mempool.
        bool isSpent(Transaction *pTransaction);

        NextCash::ReadersLock mLock;
        NextCash::stream_size mSize; // Size in bytes of all transactions in mempool
        NextCash::stream_size mPendingSize; // Size in bytes of all transactions pending validation

        // Hashes for transactions currently being validated.
        NextCash::HashList mValidatingTransactions;

        NextCash::HashSet mTransactions; // Verified transactions.
        NextCash::HashSet mPendingTransactions; // Transactions waiting for unseen outpoints.

        // Object used to save hashes with times in a HashSet.
        class HashStatusTime : public NextCash::HashObject
        {
        public:

            HashStatusTime(const NextCash::Hash &pHash, HashStatus pStatus) : mHash(pHash)
            {
                time = getTime();
                status = pStatus;
            }
            HashStatusTime(HashStatusTime &pCopy) : mHash(pCopy.mHash)
            {
                time = pCopy.time;
                status = pCopy.status;
            }
            ~HashStatusTime() {}

            Time time;
            HashStatus status;

            const NextCash::Hash &getHash() { return mHash; }

        private:

            NextCash::Hash mHash;

        };

        // Transaction hashes that failed to verify, had a low fee, are non-standard, or ...
        NextCash::HashSet mHashStatuses;

        void addHashStatus(const NextCash::Hash &pHash, HashStatus pStatus);

        NextCash::HashList mToAnnounce; // Transactions that need to be announced to peers.

        class HashNodeID : public NextCash::HashObject
        {
        public:

            HashNodeID(const NextCash::Hash &pHash, unsigned int pNodeID) : mHash(pHash)
              { nodeID = pNodeID; }
            ~HashNodeID() {}

            unsigned int nodeID;

            const NextCash::Hash &getHash() { return mHash; }

        private:

            NextCash::Hash mHash;

        };

        // Hold removed transactions here, while a node is sending it, until the node releases it
        //   and it can be deleted.
        NextCash::Mutex mNodeLock;
        NextCash::HashSet mNodeLocks;
        NextCash::HashSet mNodeLockedTransactions;
    };
}

#endif
