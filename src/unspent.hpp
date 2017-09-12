#ifndef BITCOIN_UNSPENT_HPP
#define BITCOIN_UNSPENT_HPP

#include "arcmist/base/mutex.hpp"
#include "arcmist/base/log.hpp"
#include "arcmist/io/buffer.hpp"
#include "base.hpp"

#include <list>
#include <stdlib.h>


namespace BitCoin
{
    // Unspent transaction output (UTXO)
    class Unspent
    {
    public:

        Unspent() : transactionID(32) { amount = 0; index = 0xffffffff; }
        Unspent(Unspent &pValue);
        Unspent &operator = (Unspent &pRight);

        uint64_t amount; // Quantity of Satoshis
        ArcMist::Buffer script; // Public key script needed to spend
        Hash transactionID; // Hash of transaction that created this unspent
        uint32_t index; // Index of output in transaction that created this unspent
        Hash hash; // Hash of public key or redeem script used in this unspent script
        unsigned int height;

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        bool operator == (const Unspent &pRight) const
        {
            return transactionID == pRight.transactionID && index == pRight.index;
        }

        // Print human readable to log
        void print(ArcMist::Log::Level pLevel = ArcMist::Log::VERBOSE);

    };

    // Hash table of subset of unspent transaction outputs
    class UnspentSet
    {
    public:

        static constexpr const char *START_STRING = "AMUNSP01";

        UnspentSet() {}
        ~UnspentSet();

        unsigned int size() const { return mPool.size(); }

        Unspent *find(const Hash &pTransactionID, uint32_t pIndex);

        void add(Unspent *pUnspent);
        void remove(Unspent *pUnspent);

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        void clear();

        // This will remove items from pOther as it finds matches
        // Returns true if they match
        bool compare(UnspentSet &pOther, const char *pName, const char *pOtherName);

    private:

        std::list<Unspent *> mPool;

    };

    // Container for all unspent transaction outputs
    class UnspentPool
    {
    public:

        UnspentPool();
        ~UnspentPool();

        bool isValid() const { return mValid; }

        // Find an existing unspent transaction output
        Unspent *find(const Hash &pTransactionID, uint32_t pIndex);

        // Add a new unspent transaction output
        void add(Unspent &pUnspent);

        // Remove an unspent transaction output (use pointer returned from find())
        void spend(Unspent *pUnspent);
        bool spend(const Hash &pTransactionID, uint32_t pIndex)
        {
            Unspent *unspent = find(pTransactionID, pIndex);
            if(unspent == NULL)
                return false;
            spend(unspent);
            return true;
        }

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
            unsigned int result = mUnspentCount + mPendingAdd.size() - mPendingSpend.size();
            mMutex.unlock();
            return result;
        }

        // Reverse all of the changes made by the most recent block
        //TODO void reverseLastBlock();

        // Load from file system
        bool load();

        // Save to file system
        bool save();

        void clear();

        // This will remove items from pOther as it finds matches
        // Returns true if they match
        bool compare(UnspentPool &pOther, const char *pName, const char *pOtherName);

    private:

        const UnspentPool &operator = (const UnspentPool &pRight);

        ArcMist::Mutex mMutex;
        UnspentSet mSets[0x10000];
        std::list<Unspent *> mPendingAdd, mPendingSpend;
        bool mModified;
        bool mValid;
        unsigned int mUnspentCount;
        unsigned int mBlockHeight;

    };
}

#endif
