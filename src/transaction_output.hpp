/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_TRANSACTION_OUTPUT_HPP
#define BITCOIN_TRANSACTION_OUTPUT_HPP

#include "arcmist/base/mutex.hpp"
#include "arcmist/base/log.hpp"
#include "arcmist/io/buffer.hpp"
#include "base.hpp"

#include <list>
#include <stdlib.h>


namespace BitCoin
{
    // Transaction output (TXO)
    class TransactionOutput
    {
    public:

        TransactionOutput() : transactionID(32) { amount = 0; index = 0xffffffff; }
        TransactionOutput(TransactionOutput &pValue);
        TransactionOutput &operator = (TransactionOutput &pRight);

        uint64_t amount; // Quantity of Satoshis
        ArcMist::Buffer script; // Public key script needed to spend
        Hash transactionID; // Hash of transaction that created this unspent
        uint32_t index; // Index of output in transaction that created this unspent
        Hash hash; // Hash of public key or redeem script used in this unspent script
        unsigned int height; // Height of block that contained this transaction output

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        bool operator == (const TransactionOutput &pRight) const
        {
            return transactionID == pRight.transactionID && index == pRight.index;
        }

        // Print human readable to log
        void print(ArcMist::Log::Level pLevel = ArcMist::Log::VERBOSE);

    };

    // Hash table of subset of unspent transaction outputs
    class TransactionOutputSet
    {
    public:

        static constexpr const char *START_STRING = "AMUNSP01";

        TransactionOutputSet() {}
        ~TransactionOutputSet();

        unsigned int size() const { return mPool.size(); }

        TransactionOutput *find(const Hash &pTransactionID, uint32_t pIndex);

        void add(TransactionOutput *pTransactionOutput);
        void remove(TransactionOutput *pTransactionOutput);

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        void clear();

        // This will remove items from pOther as it finds matches
        // Returns true if they match
        bool compare(TransactionOutputSet &pOther, const char *pName, const char *pOtherName);

    private:

        std::list<TransactionOutput *> mPool;

    };

    // Container for all unspent transaction outputs
    class TransactionOutputPool
    {
    public:

        TransactionOutputPool();
        ~TransactionOutputPool();

        bool isValid() const { return mValid; }

        // Activate/deactivate test mode. When on "outpoint" transactions will be pulled from the spent pool
        void setTestMode(bool pOn) { mTest = pOn; }

        // Find an unspent transaction output
        TransactionOutput *findUnspent(const Hash &pTransactionID, uint32_t pIndex);

        // Add a new transaction output
        void add(TransactionOutput *pTransactionOutput);

        // Remove an unspent transaction output (use pointer returned from find())
        void spend(TransactionOutput *pTransactionOutput);
        bool spend(const Hash &pTransactionID, uint32_t pIndex)
        {
            TransactionOutput *unspent = findUnspent(pTransactionID, pIndex);
            if(unspent == NULL)
                return false;
            spend(unspent);
            return true;
        }

        // Find a spent transaction output
        TransactionOutput *findSpent(const Hash &pTransactionID, uint32_t pIndex);

        // Commit pending adds and spends
        bool commit(unsigned int pBlockID);
        // Remove pending adds and spends
        void revert();

        // Height of last block
        unsigned int blockHeight() { return mBlockHeight - 1; }

        // Number of unspent transaction outputs
        unsigned int count()
        {
            mMutex.lock();
            unsigned int result = mTransactionOutputCount + mPendingAdd.size() - mPendingSpend.size();
            mMutex.unlock();
            return result;
        }

        // Reverse all of the changes made by the most recent block
        //TODO void reverseLastBlock();

        // Load from/Save to file system
        bool load();
        bool save();

        // This will remove items from pOther as it finds matches
        // Returns true if they match
        bool compare(TransactionOutputPool &pOther, const char *pName, const char *pOtherName);

    private:

        TransactionOutputPool(const TransactionOutputPool &pCopy);
        const TransactionOutputPool &operator = (const TransactionOutputPool &pRight);

        ArcMist::Mutex mMutex;
        TransactionOutputSet mUnspent[0x10000];
        std::list<TransactionOutput *> mPendingAdd, mPendingSpend;
        TransactionOutputSet mSpent[0x10000];
        std::list<TransactionOutput *> mSpentToDelete;
        bool mModified;
        bool mValid;
        unsigned int mTransactionOutputCount;
        unsigned int mBlockHeight;
        bool mTest;

    };
}

#endif
