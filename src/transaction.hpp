#ifndef BITCOIN_TRANSACTION_HPP
#define BITCOIN_TRANSACTION_HPP

#include "arcmist/io/stream.hpp"
#include "arcmist/io/buffer.hpp"
#include "base.hpp"
#include "key.hpp"
#include "unspent.hpp"

#include <vector>


namespace BitCoin
{
    // Link to transaction and output that funded the input
    class Outpoint
    {
    public:

        Outpoint() : transactionID(32) { index = 0xffffffff; }
        Outpoint(const Outpoint &pCopy) : transactionID(pCopy.transactionID)
        {
            index = pCopy.index;
        }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        Hash transactionID; // Double SHA256 of signed transaction that paid the input of this transaction.
        uint32_t index;

    };

    class Input
    {
    public:

        Input() { sequence = 0xffffffff; }
        Input(const Input &pCopy) : outpoint(pCopy.outpoint), script(pCopy.script)
        {
            sequence = pCopy.sequence;
        }
        virtual ~Input() {}

        // Outpoint (32 trans id + 4 index), + 4 sequence, + script length size + script length
        unsigned int size() { return 40 + compactIntegerSize(script.length()) + script.length(); }

        virtual void write(ArcMist::OutputStream *pStream);
        virtual bool read(ArcMist::InputStream *pStream);

        Outpoint outpoint;
        ArcMist::Buffer script;
        uint32_t sequence;

    };

    class Output
    {
    public:

        Output() {}
        Output(const Output &pCopy) : script(pCopy.script)
        {
            amount = pCopy.amount;
        }

        // 8 amount + script length size + script length
        unsigned int size() { return 8 + compactIntegerSize(script.length()) + script.length(); }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        int64_t amount; // Number of Satoshis spent (documentation says this should be signed)
        ArcMist::Buffer script;

    };

    class Transaction
    {
    public:

        Transaction() { version = 1; mFee = 0; lockTime = 0xffffffff; }
        Transaction(const Transaction &pCopy);
        ~Transaction();

        void write(ArcMist::OutputStream *pStream);

        // pCalculateHash will calculate the hash of the block data while it reads it
        bool read(ArcMist::InputStream *pStream, bool pCalculateHash = true);

        // P2PKH only
        bool addP2PKHInput(Unspent *pUnspent, PrivateKey &pPrivateKey, PublicKey &pPublicKey);
        bool addP2PKHOutput(Hash pPublicKeyHash, uint64_t pAmount);
        
        // P2SH only
        bool addP2SHInput(Unspent *pUnspent, ArcMist::Buffer &pRedeemScript);
        
        void clear();

        // Hash
        Hash hash;

        // Data
        uint32_t version;
        std::vector<Input *> inputs;
        std::vector<Output *> outputs;
        uint32_t lockTime;

        unsigned int size();
        uint64_t feeRate();

        uint64_t fee() const { return mFee; }

        void calculateHash();
        bool process(UnspentPool &pUnspentPool, uint64_t pBlockHeight, bool pCoinBase);

        // Run unit tests
        static bool test();

    private:

        int64_t mFee;
        std::vector<Unspent *> mUnspents;

    };
}

#endif
