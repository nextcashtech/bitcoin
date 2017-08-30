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

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        Hash transactionID; // Double SHA256 of signed transaction that paid the input of this transaction.
        uint32_t index;

    };

    class Input
    {
    public:

        Input() { sequence = 0xffffffff; }
        virtual ~Input() {}

        // Outpoint (32 trans id + 4 index), + 4 sequence, + script length size + script length
        unsigned int size() { return 40 + compactIntegerSize(script.length()) + script.length(); }

        virtual void write(ArcMist::OutputStream *pStream);
        virtual bool read(ArcMist::InputStream *pStream);

        unsigned int blockHeight() { return 0; } //TODO signatureScript.blockHeight(); }

        Outpoint outpoint;
        ArcMist::Buffer script;
        uint32_t sequence;

    };

    /*class CoinBaseInput : public Input
    {
    public:

        void write(ArcMist::OutputStream *pStream) const;
        bool read(ArcMist::InputStream *pStream);

        Hash256 hash;
        uint32_t index; // always 0xffffffff, because there is no previous outpoint
        uint64_t blockHeight;

    };*/

    class Output
    {
    public:

        Output() {}

        // 8 amount + script length size + script length
        unsigned int size() { return 8 + compactIntegerSize(script.length()) + script.length(); }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        uint64_t amount; // Number of Satoshis spent (documentation says this should be signed)
        ArcMist::Buffer script;

    };

    class Transaction
    {
    public:

        Transaction() { version = 1; mFee = 0; lockTime = 0xffffffff; }
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

        unsigned int blockHeight()
        {
            if(inputs.size() > 0)
                return inputs[0]->blockHeight();
            return 0;
        }

        // Hash
        Hash hash;

        // Data
        uint32_t version;
        std::vector<Input *> inputs;
        std::vector<Output *> outputs;
        uint32_t lockTime;

        Hash &id() { return mID; }
        unsigned int size();
        uint64_t feeRate();

        void calculateHash();
        bool process(UnspentPool &pUnspentPool, bool pTest);

        // Run unit tests
        static bool test();

    private:

        Hash mID;
        uint64_t mFee;
        std::vector<Unspent *> mUnspents;

    };
    
    
}

#endif
