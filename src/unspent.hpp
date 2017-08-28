#ifndef BITCOIN_UNSPENT_HPP
#define BITCOIN_UNSPENT_HPP

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

        uint64_t amount; // Quantity of Satoshis
        ArcMist::Buffer script; // Public key script needed to spend
        Hash transactionID; // Hash of transaction that created this unspent
        uint32_t index; // Index of output in transaction that created this unspent
        Hash hash; // Hash of public key or redeem script used in this unspent script

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

    private:

        std::list<Unspent *> mPool;

    };

    // Container for all unspent transactions
    class UnspentPool
    {
    public:

        static UnspentPool &instance();
        static void destroy();

        ~UnspentPool();

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
        void commit(unsigned int pBlockID);
        // Remove and pending adds and spends
        void revert();

        // ID of last block
        unsigned int lastBlock() { return mLastBlockID; }
        // Reverse all of the changes made by the most recent block
        void reverseLastBlock();

        // Save to file system
        bool save();

    private:

        UnspentPool();

        UnspentSet mSets[0xffff];
        std::list<Unspent *> mPendingAdd, mPendingSpend;
        bool mModified;
        bool mValid;

        unsigned int mLastBlockID;

        static UnspentPool *sInstance;

    };
}

#endif
