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
#include "forks.hpp"
#include "key.hpp"
#include "outputs.hpp"

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

    private:

        Outpoint(const Outpoint &pCopy);
        Outpoint &operator = (const Outpoint &pRight);

    };

    class Input
    {
    public:

        static const uint32_t SEQUENCE_DISABLE       = 1 << 31;
        static const uint32_t SEQUENCE_TYPE          = 1 << 22; // Determines time or block height
        static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

        Input() { sequence = 0xffffffff; }

        // Outpoint (32 trans id + 4 index), + 4 sequence, + script length size + script length
        unsigned int size() { return 40 + compactIntegerSize(script.length()) + script.length(); }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        // BIP-0068 Relative time lock sequence
        bool sequenceDisabled() const { return SEQUENCE_DISABLE & sequence; }

        // Print human readable version to log
        void print(ArcMist::Log::Level pLevel = ArcMist::Log::VERBOSE);

        bool writeSignatureData(ArcMist::OutputStream *pStream, ArcMist::Buffer *pSubScript, bool pZeroSequence);

        Outpoint outpoint;
        ArcMist::Buffer script;
        // BIP-0068 Minimum time/blocks since outpoint creation before this transaction is valid
        uint32_t sequence;

    private:

        Input(const Input &pCopy);
        Input &operator = (const Input &pRight);

    };

    class Transaction
    {
    public:

        // Value below which lock times are considered block heights instead of timestamps
        static const uint32_t LOCKTIME_THRESHOLD = 500000000;

        Transaction()
        {
            version = 2; // BIP-0068
            mFee = 0;
            lockTime = 0xffffffff;
            mSize = 0;
        }
        ~Transaction();

        void write(ArcMist::OutputStream *pStream, bool pBlockFile = false);

        // pCalculateHash will calculate the hash of the transaction data while it reads it
        bool read(ArcMist::InputStream *pStream, bool pCalculateHash = true, bool pBlockFile = false);

        void clear();

        // Print human readable version to log
        void print(ArcMist::Log::Level pLevel = ArcMist::Log::VERBOSE);

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

        bool process(TransactionOutputPool &pOutputs, const std::vector<Transaction *> &pBlockTransactions,
          uint64_t pBlockHeight, bool pCoinBase, int32_t pBlockVersion, const BlockStats &pBlockStats,
          const Forks &pForks, std::vector<unsigned int> &pSpentAges);

        bool updateOutputs(TransactionOutputPool &pOutputs, const std::vector<Transaction *> &pBlockTransactions,
          uint64_t pBlockHeight, std::vector<unsigned int> &pSpentAges);

        bool writeSignatureData(ArcMist::OutputStream *pStream, unsigned int pInputOffset,
          int64_t pOutputAmount, ArcMist::Buffer &pOutputScript, Signature::HashType pHashType, const Forks &pForks);

        // P2PKH only
        bool addP2PKHInput(const Hash &pTransactionID, unsigned int pIndex, Output &pOutput, PrivateKey &pPrivateKey,
          PublicKey &pPublicKey, const Forks &pForks);
        bool addP2PKHOutput(Hash pPublicKeyHash, uint64_t pAmount);

        // P2SH only
        bool addP2SHInput(const Hash &pTransactionID, unsigned int pIndex, Output &pOutput, ArcMist::Buffer &pRedeemScript);

        // Run unit tests
        static bool test();

    private:

        int64_t mFee;
        unsigned int mSize;

        Transaction(const Transaction &pCopy);
        Transaction &operator = (const Transaction &pRight);

    };
}

#endif
