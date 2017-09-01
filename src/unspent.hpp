#ifndef BITCOIN_UNSPENT_HPP
#define BITCOIN_UNSPENT_HPP

#include "arcmist/base/mutex.hpp"
#include "arcmist/io/buffer.hpp"
#include "base.hpp"

#include <list>


namespace BitCoin
{
    // Unspent transaction UTXO
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

    };

    // Hash table of subset of unspent transactions
    class UnspentSet
    {
    public:

        static constexpr const char *START_STRING = "AMUNSP01";

        UnspentSet() {}
        ~UnspentSet();

        Unspent *find(const Hash &pTransactionID, uint32_t pIndex);

        void add(Unspent *pUnspent);
        void remove(Unspent *pUnspent);

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        void clear();

    private:

        std::list<Unspent *> mPool;

    };

    // Container for all unspent transactions
    class UnspentPool
    {
    public:

        static UnspentPool &instance();
        static void destroy();

        bool isValid() const { return mValid; }

        // Find an existing unspent transaction
        Unspent *find(const Hash &pTransactionID, uint32_t pIndex);

        // Add a new unspent transaction
        void add(Unspent &pUnspent);

        // Remove an unspent transaction (use pointer returned from find())
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
        unsigned int blockHeight() { return mNextBlockHeight - 1; }

        // Number of unspent transactions
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

        // Clear all unspent transactions
        void reset();

    private:

        UnspentPool();
        ~UnspentPool();
        const UnspentPool &operator = (const UnspentPool &pRight);

        void clear()
        {
            mMutex.lock();
            mValid = true;
            mNextBlockHeight = 0;

            for(std::list<Unspent *>::iterator iter=mPendingAdd.begin();iter!=mPendingAdd.end();++iter)
                delete *iter;
            mPendingAdd.clear();
            mPendingSpend.clear();

            for(unsigned int i=0;i<0xffff;i++)
                mSets[i].clear();
            mMutex.unlock();
        }

        ArcMist::Mutex mMutex;
        UnspentSet mSets[0xffff];
        std::list<Unspent *> mPendingAdd, mPendingSpend;
        bool mModified;
        bool mValid;
        unsigned int mUnspentCount;
        unsigned int mNextBlockHeight;

        static UnspentPool *sInstance;

    };
}

#endif
