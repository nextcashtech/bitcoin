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
#include "arcmist/base/hash.hpp"
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

        Outpoint() : transactionID(32) { index = 0xffffffff; output = NULL; signatureStatus = 0; }
        Outpoint(const ArcMist::Hash &pTransactionID, uint32_t pIndex)
        {
            transactionID = pTransactionID;
            index = pIndex;
            output = NULL;
            signatureStatus = 0;
        }
        Outpoint(const Outpoint &pCopy)
        {
            index = pCopy.index;
            if(pCopy.output == NULL)
                output = NULL;
            else
                output = new Output(*pCopy.output);
            signatureStatus = pCopy.signatureStatus;
        }
        ~Outpoint() { if(output != NULL) delete output; }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        static bool skip(ArcMist::InputStream *pInputStream, ArcMist::OutputStream *pOutputStream = NULL);

        ArcMist::Hash transactionID; // Double SHA256 of signed transaction that paid the input of this transaction.
        uint32_t index;

        // Verification data
        Output *output;

        static const uint8_t CHECKED  = 0x01;
        static const uint8_t VERIFIED = 0x02;
        uint8_t signatureStatus;

    private:
        Outpoint &operator = (const Outpoint &pRight);
    };

    class Input
    {
    public:

        static const uint32_t SEQUENCE_DISABLE       = 1 << 31;
        static const uint32_t SEQUENCE_TYPE          = 1 << 22; // Determines time or block height
        static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

        Input() { sequence = 0xffffffff; }
        Input(const Input &pCopy) : outpoint(pCopy.outpoint), script(pCopy.script)
        {
            sequence = pCopy.sequence;
        }

        // Outpoint (32 trans id + 4 index), + 4 sequence, + script length size + script length
        unsigned int size() { return 40 + compactIntegerSize(script.length()) + script.length(); }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        // Skip over input in stream (The input stream's read offset must be at the beginning of an input)
        static bool skip(ArcMist::InputStream *pInputStream, ArcMist::OutputStream *pOutputStream = NULL);

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
        Input &operator = (const Input &pRight);
    };

    class Transaction;

    class TransactionList : public std::vector<Transaction *>
    {
    public:

        ~TransactionList();

        Transaction *getSorted(const ArcMist::Hash &pHash);
        bool insertSorted(Transaction *pTransaction);
        bool removeSorted(const ArcMist::Hash &pHash);

        void clear();
        void clearNoDelete();

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
            mTime = getTime();
            mStatus = 0;
        }
        Transaction(const Transaction &pCopy);
        ~Transaction();

        void write(ArcMist::OutputStream *pStream, bool pBlockFile = false);

        // pCalculateHash will calculate the hash of the transaction data while it reads it
        bool read(ArcMist::InputStream *pStream, bool pCalculateHash = true, bool pBlockFile = false);

        // Skip over transaction in stream (The input stream's read offset must be at the beginning of a transaction)
        static bool skip(ArcMist::InputStream *pStream);

        // Read the script of the output at the specified offset (The input stream's read offset must be at the beginning of a transaction)
        static bool readOutput(ArcMist::InputStream *pStream, unsigned int pOutputIndex,
          ArcMist::Hash &pTransactionID, Output &pOutput, bool pBlockFile = false);

        void clear();
        void clearCache();

        // Print human readable version to log
        void print(ArcMist::Log::Level pLevel = ArcMist::Log::VERBOSE);

        // Hash
        ArcMist::Hash hash;

        // Data
        uint32_t version;
        std::vector<Input *> inputs;
        std::vector<Output *> outputs;
        uint32_t lockTime;

        unsigned int size() const { return mSize; }
        int32_t time() const { return mTime; }
        int64_t fee() const { return mFee; }
        uint64_t feeRate(); // Satoshis per KB

        /***********************************************************************************************
         * Transaction verification
         ***********************************************************************************************/
        // Flags set by calling validate
        static const uint8_t WAS_CHECKED     = 0x01; // Validate has been run at least once
        static const uint8_t IS_VALID        = 0x02; // Basic format validity
        static const uint8_t IS_STANDARD     = 0x04; // Is a "standard" transaction
        static const uint8_t OUTPOINTS_FOUND = 0x08; // Has valid outpoints
        static const uint8_t SIGS_VERIFIED   = 0x10; // Has valid signatures

        // Flag checking operations
        uint8_t status() const { return mStatus; }
        bool wasChecked() const { return mStatus & WAS_CHECKED; }
        bool isValid() const { return mStatus & IS_VALID; }
        bool isStandard() const { return mStatus & IS_STANDARD; }
        bool hasOutpoints() const { return mStatus & OUTPOINTS_FOUND; }
        bool isVerfied() const { return mStatus & SIGS_VERIFIED; }

        // Flag masks
        static const uint8_t STANDARD_VERIFIED = IS_STANDARD | SIGS_VERIFIED;
        bool isStandardVerified() const { return (mStatus & STANDARD_VERIFIED) == STANDARD_VERIFIED; }

        unsigned int calculatedSize();

        void calculateHash();

        bool process(TransactionOutputPool &pOutputs, const std::vector<Transaction *> &pBlockTransactions,
          uint64_t pBlockHeight, bool pCoinBase, int32_t pBlockVersion, const BlockStats &pBlockStats,
          const Forks &pForks, std::vector<unsigned int> &pSpentAges);

        // Check validity and return status
        bool check(TransactionOutputPool &pOutputs, TransactionList &pMemPoolTransactions,
          ArcMist::HashList &pOutpointsNeeded, int32_t pBlockVersion, const BlockStats &pBlockStats, const Forks &pForks);

        // Check that none of the outpoints are spent and return status
        uint8_t checkOutpoints(TransactionOutputPool &pOutputs, TransactionList &pMemPoolTransactions);

        bool updateOutputs(TransactionOutputPool &pOutputs, const std::vector<Transaction *> &pBlockTransactions,
          uint64_t pBlockHeight, std::vector<unsigned int> &pSpentAges);

        bool getSignatureHash(ArcMist::Hash &pHash, unsigned int pInputOffset, ArcMist::Buffer &pOutputScript,
          int64_t pOutputAmount, Signature::HashType pHashType);

        /***********************************************************************************************
         * Transaction building
         *
         * Steps to building a transaction
         * 1. Call addInput to add all inputs to be spent.
         * 2. Call addXXXOutput to add all the outputs to be created.
         * 3. Call signXXXInput to sign each input and pass in the output being spent.
         ***********************************************************************************************/
        bool addInput(const ArcMist::Hash &pTransactionID, unsigned int pIndex, uint32_t pSequence = 0xffffffff);
        bool addCoinbaseInput(int pBlockHeight);

        // P2PKH Pay to Public Key Hash
        bool signP2PKHInput(Output &pOutput, unsigned int pInputOffset, const PrivateKey &pPrivateKey,
          const PublicKey &pPublicKey, Signature::HashType pType);
        bool addP2PKHOutput(const ArcMist::Hash &pPublicKeyHash, uint64_t pAmount);

        // P2PK Pay to Public Key (not as secure as P2PKH)
        bool signP2PKInput(Output &pOutput, unsigned int pInputOffset, const PrivateKey &pPrivateKey,
          const PublicKey &pPublicKey, Signature::HashType pType);
        bool addP2PKOutput(const PublicKey &pPublicKey, uint64_t pAmount);

        // P2SH Pay to Script Hash
        bool authorizeP2SHInput(Output &pOutput, unsigned int pInputOffset, ArcMist::Buffer &pRedeemScript);
        bool addP2SHOutput(const ArcMist::Hash &pScriptHash, uint64_t pAmount);

        // MultiSig
        bool addMultiSigInputSignature(Output &pOutput, unsigned int pInputOffset, const PrivateKey &pPrivateKey,
          const PublicKey &pPublicKey, Signature::HashType pHashType, const Forks &pForks, bool &pSignatureAdded,
          bool &pTransactionComplete);
        bool addMultiSigOutput(unsigned int pRequiredSignatureCount, std::vector<PublicKey *> pPublicKeys,
          uint64_t pAmount);

        static Transaction *createCoinbaseTransaction(int pBlockHeight, int64_t pFees, const ArcMist::Hash &pPublicKeyHash);

        // Run unit tests
        static bool test();

    private:

        int32_t mTime;
        int64_t mFee;
        unsigned int mSize;
        uint8_t mStatus;

        ArcMist::Hash mOutpointHash, mSequenceHash, mOutputHash;

        bool writeSignatureData(ArcMist::OutputStream *pStream, unsigned int pInputOffset,
          ArcMist::Buffer &pOutputScript, int64_t pOutputAmount, Signature::HashType pHashType);

        Transaction &operator = (const Transaction &pRight);

    };
}

#endif
