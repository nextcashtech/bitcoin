/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_TRANSACTION_HPP
#define BITCOIN_TRANSACTION_HPP

#include "log.hpp"
#include "digest.hpp"
#include "hash.hpp"
#include "hash_set.hpp"
#include "stream.hpp"
#include "buffer.hpp"
#include "reference_counter.hpp"
#include "base.hpp"
#include "forks.hpp"
#include "key.hpp"
#include "output.hpp"
#include "timer.hpp"

#include <vector>


namespace BitCoin
{
    // Link to transaction and output that funded the input
    class Outpoint
    {
    public:

        Outpoint() : transactionID(TRANSACTION_HASH_SIZE)
        {
            index = 0xffffffff;
            output = NULL;
            confirmations = 0xffffffff;
        }
        Outpoint(const NextCash::Hash &pTransactionID, uint32_t pIndex) : transactionID(pTransactionID)
        {
            index = pIndex;
            output = NULL;
            confirmations = 0xffffffff;
        }
        Outpoint(const Outpoint &pCopy) : transactionID(pCopy.transactionID)
        {
            index = pCopy.index;
            if(pCopy.output == NULL)
                output = NULL;
            else
                output = new Output(*pCopy.output);
            confirmations = pCopy.confirmations;
        }
        ~Outpoint() { if(output != NULL) delete output; }

        Outpoint &operator = (const Outpoint &pRight)
        {
            transactionID = pRight.transactionID;
            index = pRight.index;
            if(output != NULL)
                delete output;
            if(pRight.output == NULL)
                output = NULL;
            else
                output = new Output(*pRight.output);
            confirmations = pRight.confirmations;
            return *this;
        }

        void write(NextCash::OutputStream *pStream);
        bool read(NextCash::InputStream *pStream);

        static bool skip(NextCash::InputStream *pInputStream, NextCash::OutputStream *pOutputStream = NULL);

        bool operator == (const Outpoint &pRight)
        {
            return transactionID == pRight.transactionID && index == pRight.index;
        }

        NextCash::Hash transactionID; // Double SHA256 of signed transaction that paid the input of this transaction.
        uint32_t index;

        Output *output;

        uint32_t confirmations; // 0xffffffff means not specified

    };

    class Input
    {
    public:

        static const uint32_t SEQUENCE_NONE          = 0xffffffff;
        static const uint32_t SEQUENCE_DISABLE       = 1 << 31;
        static const uint32_t SEQUENCE_TYPE          = 1 << 22; // Determines time or block height
        static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

        Input() { sequence = SEQUENCE_NONE; signatureStatus = 0; }
        Input(const Input &pCopy) : outpoint(pCopy.outpoint), script(pCopy.script)
        {
            sequence = pCopy.sequence;
            signatureStatus = pCopy.signatureStatus;
        }
        Input &operator = (const Input &pRight)
        {
            outpoint = pRight.outpoint;
            script = pRight.script;
            sequence = pRight.sequence;
            signatureStatus = pRight.signatureStatus;
            return *this;
        }

        // Outpoint (32 trans id + 4 index), + 4 sequence, + script length size + script length
        unsigned int size()
        {
            return TRANSACTION_HASH_SIZE + 8 + compactIntegerSize(script.length()) +
              script.length();
        }

        void write(NextCash::OutputStream *pStream);
        bool read(NextCash::InputStream *pStream);

        // Skip over input in stream (The input stream's read offset must be at the beginning of
        //   an input)
        static bool skip(NextCash::InputStream *pInputStream,
          NextCash::OutputStream *pOutputStream = NULL);

        // BIP-0068 Relative time lock sequence
        bool sequenceDisabled() const { return SEQUENCE_DISABLE & sequence; }

        // Print human readable version to log
        void print(const Forks &pForks, NextCash::Log::Level pLevel = NextCash::Log::VERBOSE);

        bool writeSignatureData(NextCash::OutputStream *pStream, NextCash::Buffer *pSubScript,
          bool pZeroSequence);

        Outpoint outpoint;
        NextCash::Buffer script;
        // BIP-0068 Minimum time/blocks since outpoint creation before this transaction is valid
        uint32_t sequence;

        static const uint8_t CHECKED  = 0x01;
        static const uint8_t VERIFIED = 0x02;
        uint8_t signatureStatus;
    };

    class Transaction
    {
    public:

        static const int64_t DUST = 546;
        static const int64_t INVALID_FEE = 0xffffffffffffffff;

        // Value below which lock times are considered block heights instead of timestamps
        static const uint32_t LOCKTIME_THRESHOLD = 500000000;

        Transaction()
        {
            version = 2;
            lockTime = 0;

            mFee = INVALID_FEE;
            mSize = 0;
            mTime = getTime();
            mStatus = 0;
        }
        Transaction(const Transaction &pCopy);

        Transaction &operator = (const Transaction &pRight);

        const NextCash::Hash &getHash() { return hash(); }
        bool valueEquals(const NextCash::SortedObject *pRight) const
          { return this == (const Transaction *)pRight; }
        bool valueEquals(Transaction &pRight) { return this == &pRight; }
        int compare(Transaction &pRight) { return hash().compare(pRight.hash()); }

        void write(NextCash::OutputStream *pStream);

        // pCalculateHash will calculate the hash of the transaction data while it reads it
        bool read(NextCash::InputStream *pStream);

        // Skip over transaction in stream (The input stream's read offset must be at the beginning
        //   of a transaction)
        static bool skip(NextCash::InputStream *pStream);

        // Read the script of the output at the specified offset (The input stream's read offset
        //   must be at the beginning of a transaction)
        static bool readOutput(NextCash::InputStream *pStream, unsigned int pOutputIndex,
          NextCash::Hash &pTransactionID, Output &pOutput);

        void clear();
        void clearCache();

        // Print human readable version to log
        void print(const Forks &pForks, NextCash::Log::Level pLevel = NextCash::Log::VERBOSE);

        // Data
        uint32_t version;
        std::vector<Input> inputs;
        std::vector<Output> outputs;
        uint32_t lockTime; // Time/Block height at or after which a transaction can be confirmed.

        const NextCash::Hash &hash() { if(mHash.isEmpty()) calculateHash(); return mHash; }
        unsigned int size() const { return mSize; }
        Time time() const { return mTime; }
        bool feeIsValid() const { return mFee != INVALID_FEE; }
        int64_t fee() const { return mFee; }
        uint64_t feeRate(); // Satoshis per KB

        uint64_t outputAmount()
        {
            uint64_t result = 0;
            for(std::vector<Output>::iterator output = outputs.begin(); output != outputs.end();
              ++output)
                result += output->amount;
            return result;
        }

        /***********************************************************************************************
         * Transaction verification
         ***********************************************************************************************/
        // Flags set by calling validate
        static const uint8_t WAS_CHECKED     = 0x01; // Validate has been run at least once
        static const uint8_t IS_VALID        = 0x02; // Basic format validity
        static const uint8_t IS_STANDARD     = 0x04; // Is a "standard" transaction
        static const uint8_t OUTPOINTS_FOUND = 0x08; // Has valid outpoints
        static const uint8_t SIGS_VERIFIED   = 0x10; // Has valid signatures
#ifdef TRANS_ID_DUP_CHECK
        static const uint8_t DUP_CHECKED     = 0x20; // Duplicate ID has been checked for
#endif
        static const uint8_t IN_MEMPOOL      = 0x40; // Was in the mempool during block validation

        // Flag checking operations
        uint8_t status() const { return mStatus; }
        bool wasChecked() const { return mStatus & WAS_CHECKED; }
        bool isValid() const { return mStatus & IS_VALID; }
        bool isStandard() const { return mStatus & IS_STANDARD; }
        bool outpointsFound() const { return mStatus & OUTPOINTS_FOUND; }

        // Flag masks
        static const uint8_t VERIFIED_MASK = IS_VALID | SIGS_VERIFIED | OUTPOINTS_FOUND;
        bool isVerified() const
          { return (mStatus & VERIFIED_MASK) == VERIFIED_MASK; }
        static const uint8_t STANDARD_VERIFIED_MASK = VERIFIED_MASK | IS_STANDARD;
        bool isStandardVerified() const
          { return (mStatus & STANDARD_VERIFIED_MASK) == STANDARD_VERIFIED_MASK; }

        void calculateSize();
        void calculateHash();
        void setTime(Time pValue) { mTime = pValue; }

        // Signs the inputs and adjusts the output amounts to set the fee.
        //
        // Parameters
        //   pInputAmount is total amount in satoshis included in inputs.
        //   pFeeRate is the rate in satoshis/byte at which to set the fee.
        //   pSendAmount of 0xffffffffffffffffL means send all to last output.
        //   pChangeOutputOffset < 0 means there is no change output and remaining balance
        //     (below dust) should be added to fee.
        // Returns
        //   1 if general failure
        //   5 if signature failure
        int sign(uint64_t pInputAmount, double pFeeRate, uint64_t pSendAmount,
          int pChangeOutputOffset, Key *pKey, Signature::HashType pHashType, const Forks &pForks);

        class CheckStats
        {
        public:

            CheckStats() { outputPulls = 0; }

            void operator += (const CheckStats &pRight)
            {
                spentAges.reserve(spentAges.size() + pRight.spentAges.size());
                for(std::vector<unsigned int>::const_iterator iter = pRight.spentAges.begin();
                  iter != pRight.spentAges.end(); ++iter)
                    spentAges.emplace_back(*iter);
                outputPulls += pRight.outputPulls;
                outputsTimer += pRight.outputsTimer;
                scriptTimer += pRight.scriptTimer;
            }

            std::vector<unsigned int> spentAges;
            unsigned int outputPulls;
            NextCash::Timer outputsTimer, scriptTimer;

        };

        // Check validity
        void check(Chain *pChain, const NextCash::Hash &pBlockHash, unsigned int pHeight, bool pCoinBase,
          int32_t pBlockVersion, CheckStats &pStats);

        // Re-check that outpoints are unspent.
        bool checkOutpoints(Chain *pChain, bool pMemPoolIsLocked);

        bool updateOutputs(Chain *pChain, uint64_t pHeight, bool pCoinBase, CheckStats &pStats);

        void getSignatureHash(const Forks &pForks, unsigned int pHeight,
          NextCash::Hash &pHash, unsigned int pInputOffset, NextCash::Buffer &pOutputScript,
          int64_t pOutputAmount, uint8_t pHashType);

        /***********************************************************************************************
         * Transaction building
         *
         * Steps to building a transaction
         * 1. Call addInput to add all inputs to be spent.
         * 2. Call addXXXOutput to add all the outputs to be created.
         * 3. Call signXXXInput to sign each input and pass in the output being spent.
         ***********************************************************************************************/
        bool addInput(const NextCash::Hash &pTransactionID, unsigned int pIndex,
          uint32_t pSequence = Input::SEQUENCE_NONE);
        bool addCoinbaseInput(int pHeight);

        bool addOutput(NextCash::Buffer pOutputScript, uint64_t pAmount);
        bool addOutput(const Output &pOutput);

        // P2PKH Pay to Public Key Hash
        bool signP2PKHInput(const Forks &pForks, Output &pOutput, unsigned int pInputOffset,
          const Key &pPrivateKey, Signature::HashType pHashType);
        bool addP2PKHOutput(const NextCash::Hash &pPublicKeyHash, uint64_t pAmount);

        // P2PK Pay to Public Key (not as secure as P2PKH)
        bool signP2PKInput(const Forks &pForks, Output &pOutput, unsigned int pInputOffset,
          const Key &pPrivateKey, const Key &pPublicKey, Signature::HashType pHashType);
        bool addP2PKOutput(const Key &pPublicKey, uint64_t pAmount);

        // P2SH Pay to Script Hash
        bool authorizeP2SHInput(Output &pOutput, unsigned int pInputOffset, NextCash::Buffer &pRedeemScript);
        bool addP2SHOutput(const NextCash::Hash &pScriptHash, uint64_t pAmount);

        // MultiSig
        bool addMultiSigInputSignature(Output &pOutput, unsigned int pInputOffset,
          const Key &pPrivateKey, const Key &pPublicKey, Signature::HashType pHashType,
          const Forks &pForks, bool &pSignatureAdded, bool &pTransactionComplete);
        bool addMultiSigOutput(unsigned int pRequiredSignatureCount, std::vector<Key *> pPublicKeys,
          uint64_t pAmount);

        static Transaction *createCoinbaseTransaction(int pHeight, int64_t pFees,
          const NextCash::Hash &pPublicKeyHash);

        // Run unit tests
        static bool test();

        void setInMemPool() { mStatus |= IN_MEMPOOL; }
        void clearInMemPool() { if(mStatus & IN_MEMPOOL) mStatus ^= IN_MEMPOOL; }
        bool inMemPool() const { return mStatus & IN_MEMPOOL; }

    private:

        NextCash::Hash mHash;
        Time mTime;
        int64_t mFee;
        NextCash::stream_size mSize;
        uint8_t mStatus;

        NextCash::Hash mOutpointHash, mSequenceHash, mOutputHash;

        bool writeSignatureData(const Forks &pForks, unsigned int pHeight,
          NextCash::OutputStream *pStream, unsigned int pInputOffset,
          NextCash::Buffer &pOutputScript, int64_t pOutputAmount, uint8_t pHashType);

    };

    typedef NextCash::ReferenceCounter<Transaction> TransactionReference;

    class TransactionList : public std::vector<TransactionReference>
    {
    public:

        TransactionReference getSorted(const NextCash::Hash &pHash);
        bool insertSorted(TransactionReference pTransaction);
        bool removeSorted(const NextCash::Hash &pHash);

        TransactionReference getAndRemoveSorted(const NextCash::Hash &pHash);
        TransactionReference getAndRemoveAt(unsigned int pOffset);

        typedef std::vector<TransactionReference>::iterator iterator;
        typedef std::vector<TransactionReference>::const_iterator const_iterator;
        typedef std::vector<TransactionReference>::reverse_iterator reverse_iterator;
        typedef std::vector<TransactionReference>::const_reverse_iterator const_reverse_iterator;

    };
}

#endif
