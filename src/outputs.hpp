/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_OUTPUTS_HPP
#define BITCOIN_OUTPUTS_HPP

#include "arcmist/base/mutex.hpp"
#include "arcmist/base/log.hpp"
#include "arcmist/io/buffer.hpp"
#include "base.hpp"

#include <list>
#include <stdlib.h>

#define BITCOIN_OUTPUTS_LOG_NAME "BitCoin Outputs"


namespace BitCoin
{
    class Transaction; // Get around circular reference

    class Output
    {
    public:

        Output() { blockFileOffset = 0; }

        Output &operator = (const Output &pRight);

        // 8 amount + script length size + script length
        unsigned int size() { return 8 + compactIntegerSize(script.length()) + script.length(); }

        void write(ArcMist::OutputStream *pStream, bool pBlockFile = false);
        bool read(ArcMist::InputStream *pStream, bool pBlockFile = false);

        // Print human readable version to log
        void print(ArcMist::Log::Level pLevel = ArcMist::Log::VERBOSE);

        int64_t amount; // Number of Satoshis spent (documentation says this should be signed)
        ArcMist::Buffer script;

        unsigned int blockFileOffset;

    private:

        Output(const Output &pCopy);

    };

    // Reference to transaction output with information to get it quickly
    // This needs to be really optimized because it use used many millions of times
    class OutputReference
    {
    public:

        // Size of data written to file
        static const unsigned int SIZE = 8;
        static const unsigned int MEMORY_SIZE = SIZE + 4; // index per output in transaction reference

        // Mark as spent (only called from TransactionOutputPool::spend so it can track spent outputs)
        void spendInternal(unsigned int pBlockHeight) { spentBlockHeight = pBlockHeight; }

        // Update block file offset
        void commit(const Output &pOutput) { blockFileOffset = pOutput.blockFileOffset; }

        unsigned int spentBlockHeight;
        unsigned int blockFileOffset;
    };

    // Reference to a transaction's outputs with information to get them quickly
    class TransactionReference
    {
    public:

        // Size of data written to file (not counting outputs)
        //   32 byte hash, 4 byte block height, 4 byte output count
        static const unsigned int SIZE = 40;
        // 8 byte file offset, 4 byte hash size, 8 byte hash data pointer, 8 byte output data pointer,
        //   8 byte output index data pointer
        static const unsigned int MEMORY_SIZE = SIZE + 8 + 4 + 8 + 8 + 8;

        // These are used to allow reading from the file without allocating data.
        //   So when allocation is done it can exclude the spent outputs
        static const unsigned int STATIC_OUTPUTS_COUNT = 32;
        static OutputReference sOutputs[STATIC_OUTPUTS_COUNT];
        static const ArcMist::stream_size NOT_WRITTEN = 0xffffffffffffffff;

        TransactionReference() : id(32)
        {
            blockHeight  = 0;
            fileOffset   = NOT_WRITTEN;
            mOutputCount = 0;
            mOutputs     = NULL;
            mOutputIndices = NULL;
        }
        TransactionReference(const Hash &pID, unsigned int pBlockHeight, unsigned int pOutputCount) : id(pID)
        {
            blockHeight = pBlockHeight;
            fileOffset  = NOT_WRITTEN;
            mOutputCount = 0;
            mOutputs = NULL;
            mOutputIndices = NULL;
            if(pOutputCount > 0)
            {
                allocateOutputs(pOutputCount);

                // Set indices
                unsigned int *index = mOutputIndices;
                for(unsigned int i=0;i<mOutputCount;++i,++index)
                    *index = i;

                // Initialize outputs
                std::memset(mOutputs, 0, OutputReference::SIZE * mOutputCount);
            }
        }
        ~TransactionReference()
        {
            if(mOutputs != NULL)
            {
                delete[] mOutputs;
                delete[] mOutputIndices;
            }
        }

        // Writes all outputs
        // Note: Not portable. Dependent on system endian
        void write(ArcMist::OutputStream *pStream);

        void writeAll(ArcMist::OutputStream *pStream);

        // Reads only unspent outputs
        // Note: Not portable. Dependent on system endian
        bool readUnspent(ArcMist::InputStream *pStream);

        bool readAll(ArcMist::InputStream *pStream, unsigned int &pTransactionCount, unsigned int &pOutputCount,
          unsigned int &pSpentTransactionCount, unsigned int &pSpentOutputCount);

        bool hasUnspentOutputs() const { return mOutputCount > 0 && spentOutputCount() < mOutputCount; }
        unsigned int outputCount() const { return mOutputCount; }
        unsigned int spentOutputCount() const;

        OutputReference *outputAt(unsigned int pIndex);
        void allocateOutputs(unsigned int pCount)
        {
            // Allocate the number of outputs needed
            if(mOutputCount != pCount)
            {
                if(mOutputs != NULL)
                {
                    delete[] mOutputs;
                    delete[] mOutputIndices;
                }
                mOutputCount = pCount;
                if(mOutputCount == 0)
                {
                    mOutputs = NULL;
                    mOutputIndices = NULL;
                }
                else
                {
                    mOutputs = new OutputReference[mOutputCount];
                    mOutputIndices = new unsigned int[mOutputCount];
                }
            }
        }
        void clearOutputs()
        {
            if(mOutputs != NULL)
            {
                delete[] mOutputs;
                delete[] mOutputIndices;
            }
            mOutputCount = 0;
            mOutputs = NULL;
            mOutputIndices = NULL;
        }

        // Write spent block heights to the file
        void writeSpent(ArcMist::OutputStream *pStream, bool pWrote, unsigned int &pOutputCount,
          unsigned int &pSpentOutputCount);

        // Remove the outputs that are spent
        void removeSpent(unsigned int &pOutputCount, unsigned int &pSpentOutputCount);

        // Update block file offsets in outputs
        void commit(std::vector<Output *> &pOutputs);

        // Unmark any outputs spent at specified block height
        void revert(unsigned int pBlockHeight, unsigned int &pSpentOutputCount);

        unsigned int size() const { return SIZE + (mOutputCount * OutputReference::SIZE); }

        void print(ArcMist::Log::Level pLevel = ArcMist::Log::Level::VERBOSE);

        Hash id; // Transaction Hash
        unsigned int blockHeight; // Block height of transaction
        ArcMist::stream_size fileOffset; // Offset of this data in transaction reference file

    private:

        unsigned int mOutputCount;
        OutputReference *mOutputs;
        unsigned int *mOutputIndices;

        TransactionReference(const TransactionReference &pCopy);
        const TransactionReference &operator = (const TransactionReference &pRight);
    };

    // Set of transaction outputs
    class TransactionOutputSet
    {
    public:

        static constexpr const char *START_STRING = "AMTX";

        ~TransactionOutputSet();

        // Find an unspent transaction output
        TransactionReference *findUnspent(const Hash &pTransactionID, uint32_t pIndex);

        // Returns true if there is currently a transaction with this ID with unspent outputs
        TransactionReference *find(const Hash &pTransactionID);

        // Update spent transactions or add new transactions to the file
        void writeUpdate(ArcMist::OutputStream *pStream, unsigned int &pTransactionCount, unsigned int &pOutputCount,
          unsigned int &pSpentTransactionCount, unsigned int &pSpentOutputCount);

        // Write all data to stream
        void writeAll(ArcMist::OutputStream *pStream);

        // Add a new transaction's outputs
        bool add(TransactionReference *pReference, unsigned int &pTransactionCount, unsigned int &pOutputCount);

        // Add block file offsets to "pending" outputs for a block
        void commit(const Hash &pTransactionID, std::vector<Output *> &pOutputs, unsigned int pBlockHeight);

        // Remove pending adds and spends (Note: Only reverts changes not written to the file yet)
        void revert(unsigned int pBlockHeight, unsigned int &pTransactionCount, unsigned int &pOutputCount,
          unsigned int &pSpentTransactionCount, unsigned int &pSpentOutputCount);

        void clear();

    private:
        std::list<TransactionReference *> mReferences;
    };

    // Container for all unspent transaction outputs
    class TransactionOutputPool
    {
    public:

        static const unsigned int SET_COUNT = 0x10000;
        static const unsigned int BIP0030_HASH_COUNT = 2;
        static const unsigned int BIP0030_HEIGHTS[BIP0030_HASH_COUNT];
        static const Hash BIP0030_HASHES[BIP0030_HASH_COUNT];

        TransactionOutputPool();

        bool isValid() const { return mValid; }

        // Find an unspent transaction output
        TransactionReference *findUnspent(const Hash &pTransactionID, uint32_t pIndex);

        // Add all the outputs from a block (pending since they have no block file IDs or offsets yet)
        // Returns false if one of the transaction IDs is currently unspent BIP-0030
        bool add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight, const Hash &pBlockHash);

        // Find a spent transaction output
        TransactionReference *findSpent(const Hash &pTransactionID, uint32_t pIndex);


        // Mark an output as spent
        void spend(TransactionReference *pReference, unsigned int pIndex, unsigned int pBlockHeight);

        // Add block file IDs and offsets to the outputs for a block (call after writing the block to the block file)
        bool commit(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);

        // Remove pending adds and spends
        void revert(unsigned int pBlockHeight);

        // Height of last block
        int blockHeight() const { return mNextBlockHeight - 1; }
        unsigned int transactionCount() const { return mTransactionCount; }
        unsigned int spentTransactionCount() const { return mSpentTransactionCount; }
        unsigned int outputCount() const { return mOutputCount; }
        unsigned int spentOutputCount() const { return mSpentOutputCount; }
        unsigned int unspentOutputCount() const { return mOutputCount - mSpentOutputCount; }
        unsigned int size() const
        {
            return (mTransactionCount * TransactionReference::MEMORY_SIZE) +
              (mOutputCount * OutputReference::MEMORY_SIZE);
        }
        unsigned int spentSize() const
        {
            return (mSpentTransactionCount * TransactionReference::MEMORY_SIZE) +
              (mSpentOutputCount * OutputReference::MEMORY_SIZE);
        }

        // Load from/Save to file system
        bool load(bool &pStop);
        bool save();

    private:

        TransactionOutputPool(const TransactionOutputPool &pCopy);
        const TransactionOutputPool &operator = (const TransactionOutputPool &pRight);

        ArcMist::Mutex mMutex;
        TransactionOutputSet mReferences[SET_COUNT];
        bool mModified;
        bool mValid;
        unsigned int mTransactionCount, mOutputCount, mSpentTransactionCount, mSpentOutputCount;
        unsigned int mNextBlockHeight;

    };
}

#endif
