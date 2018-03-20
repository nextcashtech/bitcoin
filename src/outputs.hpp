/**************************************************************************
 * Copyright 2017 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_OUTPUTS_HPP
#define BITCOIN_OUTPUTS_HPP

#include "nextcash/base/mutex.hpp"
#include "nextcash/base/hash.hpp"
#include "nextcash/base/hash_data_set.hpp"
#include "nextcash/base/log.hpp"
#include "nextcash/io/buffer.hpp"
#include "nextcash/io/file_stream.hpp"
#include "base.hpp"

#include <vector>
#include <stdlib.h>

#define BITCOIN_OUTPUTS_LOG_NAME "Output"


namespace BitCoin
{
    class Transaction; // Get around circular reference

    class Output
    {
    public:

        Output() { blockFileOffset = 0; }
        Output(const Output &pCopy) : script(pCopy.script)
        {
            amount = pCopy.amount;
            blockFileOffset = pCopy.blockFileOffset;
        }

        Output &operator = (const Output &pRight);

        // 8 amount + script length size + script length
        unsigned int size() { return 8 + compactIntegerSize(script.length()) + script.length(); }

        void write(NextCash::OutputStream *pStream, bool pBlockFile = false);
        bool read(NextCash::InputStream *pStream, bool pBlockFile = false);

        // Skip over output in stream (The input stream's read offset must be at the beginning of an output)
        static bool skip(NextCash::InputStream *pInputStream, NextCash::OutputStream *pOutputStream = NULL);

        // Print human readable version to log
        void print(NextCash::Log::Level pLevel = NextCash::Log::VERBOSE);

        int64_t amount; // Number of Satoshis spent (documentation says this should be signed)
        NextCash::Buffer script;

        // Collected when reading/writing and used for output references
        unsigned int blockFileOffset;

    };

    // Reference to transaction output with information to get it quickly
    // This needs to be really optimized because it use used many millions of times
    class OutputReference
    {
    public:

        // Size of data written to file
        static const unsigned int SIZE = 8;

        // Mark as spent (only called from TransactionOutputPool::spend so it can track spent outputs)
        void spendInternal(unsigned int pBlockHeight) { spentBlockHeight = pBlockHeight; }

        // Update block file offset
        bool commit(const Output &pOutput)
        {
            if(blockFileOffset != pOutput.blockFileOffset)
            {
                blockFileOffset = pOutput.blockFileOffset;
                return true;
            }
            return false;
        }

        unsigned int spentBlockHeight;
        unsigned int blockFileOffset;
    };

    // Reference to a transaction's outputs with information to get them quickly
    class TransactionReference : public NextCash::HashData
    {
    public:

        TransactionReference()
        {
            blockHeight  = 0;
            mOutputCount = 0;
            mOutputs     = NULL;
        }
        TransactionReference(unsigned int pBlockHeight, unsigned int pOutputCount)
        {
            blockHeight  = pBlockHeight;
            mOutputCount = 0;
            mOutputs     = NULL;
            if(pOutputCount > 0)
            {
                allocateOutputs(pOutputCount);
                std::memset(mOutputs, 0, sizeof(OutputReference) * mOutputCount); // Initialize outputs
            }
        }
        ~TransactionReference()
        {
            if(mOutputs != NULL)
                delete[] mOutputs;
        }

        // Returns the size(bytes) in memory of the object
        uint64_t size()
        {
            return 20 + // Block height 4 + Output count 4 + Output pointer 8
              (mOutputCount * OutputReference::SIZE);
        }

        // Evaluates the relative age of two objects.
        // Used to determine which objects to drop from cache
        // Negative means this object is older than pRight.
        // Zero means both objects are the same age.
        // Positive means this object is newer than pRight.
        int compareAge(NextCash::HashData *pRight)
        {
            // Spent transactions are "older" than unspent transactions
            bool spent = !hasUnspentOutputs();
            bool rightSpent = ((TransactionReference *)pRight)->hasUnspentOutputs();

            if(spent != rightSpent)
            {
                if(spent)
                    return -1;
                else
                    return 1;
            }

            // If both transactions are spent or both unspent then use block height
            if(blockHeight < ((TransactionReference *)pRight)->blockHeight)
                return -1;
            if(blockHeight > ((TransactionReference *)pRight)->blockHeight)
                return 1;
            return 0;
        }

        // Returns true if the value of this object matches the value pRight references
        bool valuesMatch(const HashData *pRight) const
        {
            // Since more than one transaction with the same hash will never be in the same block
            return blockHeight == blockHeight;
        }

        // Reads object data from a stream
        bool read(NextCash::InputStream *pStream);

        // Writes object data to a stream
        bool write(NextCash::OutputStream *pStream);

        bool hasUnspentOutput(unsigned int pIndex) const
          { return mOutputCount > pIndex && mOutputs[pIndex].spentBlockHeight == 0; }
        bool hasUnspentOutputs() const { return mOutputCount > 0 && spentOutputCount() < mOutputCount; }

        // The highest block that spent this block. Returns MAX_BLOCK_HEIGHT if all outputs are not spent yet
        unsigned int spentBlockHeight() const;
        unsigned int outputCount() const { return mOutputCount; }
        unsigned int spentOutputCount() const;

        void spendInternal(unsigned int pIndex, unsigned int pBlockHeight);

        bool wasModifiedInOrAfterBlock(unsigned int pBlockHeight) const;

        OutputReference *outputAt(unsigned int pIndex)
        {
            if(mOutputs != NULL && pIndex < mOutputCount)
                return mOutputs + pIndex;
            return NULL;
        }

        bool allocateOutputs(unsigned int pCount);
        void clearOutputs();

        // Update block file offsets in outputs
        void commit(std::vector<Output *> &pOutputs);

        // Unmark any outputs spent above a specified block height
        bool revert(const NextCash::Hash &pHash, unsigned int pBlockHeight);

        void print(NextCash::Log::Level pLevel = NextCash::Log::Level::VERBOSE);

        unsigned int blockHeight; // Block height of transaction

    private:

        // Max check values for validation
        static const unsigned int MAX_OUTPUT_COUNT = 0x0000ffff;
        static const unsigned int MAX_BLOCK_HEIGHT = 0x00ffffff;

        unsigned int mOutputCount;
        OutputReference *mOutputs;

        TransactionReference(const TransactionReference &pCopy);
        const TransactionReference &operator = (const TransactionReference &pRight);

    };

    // Container for all unspent transaction outputs
    class TransactionOutputPool : public NextCash::HashDataSet<TransactionReference, 32, 1024, 1024>
    {
    public:

        unsigned int subSetOffset(const NextCash::Hash &pLookupValue)
        {
            return pLookupValue.lookup16() >> 6;
        }

        static const unsigned int BIP0030_HASH_COUNT = 2;
        static const unsigned int BIP0030_HEIGHTS[BIP0030_HASH_COUNT];
        static const NextCash::Hash BIP0030_HASHES[BIP0030_HASH_COUNT];

        TransactionOutputPool() { mNextBlockHeight = 0; mSavedBlockHeight = 0; }
        ~TransactionOutputPool() {}

        // Find an unspent transaction output
        TransactionReference *findUnspent(const NextCash::Hash &pTransactionID, uint32_t pIndex);

        // Find a transaction output. Return unspent if found, otherwise return spent.
        TransactionReference *find(const NextCash::Hash &pTransactionID, uint32_t pIndex);

        // BIP-0030 Check if this block's transactions match any existing unspent transaction IDs
        //   This is expensive since it is a negative lookup and has to search a file for every transaction.
        //   Positive lookups can be limited extremely by cacheing transactions from recent (a few thousand) blocks
        bool checkDuplicates(const std::vector<Transaction *> &pBlockTransactions,
          unsigned int pBlockHeight, const NextCash::Hash &pBlockHash);

        // Add all the outputs from a block (pending since they have no block file IDs or offsets yet)
        // Returns false if one of the transaction IDs is currently unspent BIP-0030
        bool add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);

        // Mark an output as spent
        void spend(TransactionReference *pReference, unsigned int pIndex, unsigned int pBlockHeight);

        // Add block file IDs and offsets to the outputs for a block (call after writing the block to the block file)
        bool commit(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);

        // Revert transactions in a block.
        bool revert(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);

        // Height of last block
        int height() const { return mNextBlockHeight - 1; }
        unsigned int transactionCount() const;

        bool needsPurge() { return cacheDataSize() > (NextCash::stream_size)((double)targetCacheDataSize() * 1.5); }

        bool load(const char *pFilePath, uint64_t pCacheDataTargetSize);
        bool save();

    private:

        TransactionOutputPool(const TransactionOutputPool &pCopy);
        const TransactionOutputPool &operator = (const TransactionOutputPool &pRight);

        unsigned int mNextBlockHeight;
        unsigned int mSavedBlockHeight;

        std::vector<TransactionReference *> mToCommit;
        NextCash::HashList mToCommitHashes;

    };
}

#endif
