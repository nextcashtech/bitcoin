/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_TRANSACTION_HPP
#define BITCOIN_TRANSACTION_HPP

#include "arcmist/base/log.hpp"
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
        Outpoint &operator = (const Outpoint &pRight)
        {
            transactionID = pRight.transactionID;
            index = pRight.index;
            return *this;
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
        Input &operator = (const Input &pRight)
        {
            outpoint = pRight.outpoint;
            script = pRight.script;
            sequence = pRight.sequence;
            return *this;
        }

        // Outpoint (32 trans id + 4 index), + 4 sequence, + script length size + script length
        unsigned int size() { return 40 + compactIntegerSize(script.length()) + script.length(); }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        // Print human readable version to log
        void print(ArcMist::Log::Level pLevel = ArcMist::Log::DEBUG);

        bool writeSignatureData(ArcMist::OutputStream *pStream, ArcMist::Buffer *pSubScript, bool pZeroSequence);

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
        Output &operator = (Output &pRight)
        {
            amount = pRight.amount;
            script = pRight.script;
            return *this;
        }

        // 8 amount + script length size + script length
        unsigned int size() { return 8 + compactIntegerSize(script.length()) + script.length(); }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        // Print human readable version to log
        void print(ArcMist::Log::Level pLevel = ArcMist::Log::DEBUG);

        int64_t amount; // Number of Satoshis spent (documentation says this should be signed)
        ArcMist::Buffer script;

    };

    class Transaction
    {
    public:

        Transaction() { version = 1; mFee = 0; lockTime = 0xffffffff; mSize = 0; }
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

        // Print human readable version to log
        void print(ArcMist::Log::Level pLevel = ArcMist::Log::DEBUG);

        // Hash
        Hash hash;

        // Data
        uint32_t version;
        std::vector<Input *> inputs;
        std::vector<Output *> outputs;
        uint32_t lockTime;

        unsigned int size() const { return mSize; }
        unsigned int calculatedSize();
        uint64_t feeRate();

        uint64_t fee() const { return mFee; }

        void calculateHash();
        bool process(UnspentPool &pUnspentPool, uint64_t pBlockHeight, bool pCoinBase,
          int32_t pBlockVersion, int32_t pBlockVersionFlags);

        bool writeSignatureData(ArcMist::OutputStream *pStream, unsigned int pInputOffset,
          ArcMist::Buffer &pOutputScript, Signature::HashType pHashType);

        // Run unit tests
        static bool test();

    private:

        int64_t mFee;
        unsigned int mSize;
        std::vector<Unspent *> mUnspents;

        Transaction(const Transaction &pCopy);
        Transaction &operator = (const Transaction &pRight);

    };
}

#endif
