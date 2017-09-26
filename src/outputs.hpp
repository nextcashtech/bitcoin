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
    class TransactionOutputReference
    {
    public:

        static const unsigned int SIZE = 12;
        static const unsigned int FILE_SIZE = 8;

        TransactionOutputReference()
        {
            index            = 0;
            blockFileOffset  = 0;
            spentBlockHeight = 0;
        }
        TransactionOutputReference(const TransactionOutputReference &pCopy)
        {
            index            = pCopy.index;
            blockFileOffset  = pCopy.blockFileOffset;
            spentBlockHeight = pCopy.spentBlockHeight;
        }
        ~TransactionOutputReference() {}

        const TransactionOutputReference &operator = (const TransactionOutputReference &pRight)
        {
            index            = pRight.index;
            blockFileOffset  = pRight.blockFileOffset;
            spentBlockHeight = pRight.spentBlockHeight;
            return *this;
        }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        // Mark as spent (only called from TransactionOutputPool::spend so it can track spent outputs)
        void spendInternal(unsigned int pBlockHeight) { spentBlockHeight = pBlockHeight; }

        // Update block file offset
        void commit(const Output &pOutput) { blockFileOffset = pOutput.blockFileOffset; }

        // Write the spent block height to the file
        void writeSpentHeight(ArcMist::OutputStream *pStream);

        void print(ArcMist::Log::Level pLevel = ArcMist::Log::Level::VERBOSE);

        unsigned int index; // Not written to file
        unsigned int blockFileOffset;
        unsigned int spentBlockHeight;
    };

    // Reference to a transaction's outputs with information to get them quickly
    class TransactionReference
    {
    public:

        static const unsigned int SIZE = 40;

        TransactionReference() : id(32)
        {
            blockHeight  = 0;
            fileOffset   = 0xffffffff;
            mOutputCount = 0;
            mOutputs     = NULL;
        }
        TransactionReference(const Hash &pID, unsigned int pBlockHeight, unsigned int pOutputCount) : id(pID)
        {
            blockHeight = pBlockHeight;
            fileOffset  = 0xffffffff;
            mOutputCount = pOutputCount;
            if(pOutputCount == 0)
                mOutputs = NULL;
            else
            {
                mOutputs = new TransactionOutputReference[mOutputCount];
                TransactionOutputReference *output=mOutputs;
                for(unsigned int index=0;index<mOutputCount;++output)
                    output->index = index++;
            }
        }
        ~TransactionReference()
        {
            if(mOutputs != NULL)
                delete[] mOutputs;
        }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream, unsigned int &pOutputCount, unsigned int &pSpentOutputCount);

        unsigned int outputCount() const { return mOutputCount; }
        unsigned int spentOutputCount() const;

        TransactionOutputReference *outputAt(unsigned int pIndex);

        // Write spent block heights to the file
        void writeSpent(ArcMist::OutputStream *pStream, bool pWrote, unsigned int &pOutputCount,
          unsigned int &pSpentOutputCount);

        // Remove the outputs that are spent
        void removeSpent(unsigned int &pOutputCount, unsigned int &pSpentOutputCount);

        // Update block file offsets in outputs
        void commit(std::vector<Output *> &pOutputs);

        // Unmark any outputs spent at specified block height
        void revert(unsigned int pBlockHeight, unsigned int &pSpentOutputCount);

        unsigned int size() const { return SIZE + (mOutputCount * TransactionOutputReference::SIZE); }

        void print(ArcMist::Log::Level pLevel = ArcMist::Log::Level::VERBOSE);

        Hash id; // Transaction Hash
        unsigned int blockHeight; // Block height of transaction
        unsigned int fileOffset; // Offset of this data in transaction reference set file

    private:

        unsigned int mOutputCount;
        TransactionOutputReference *mOutputs;

        TransactionReference(const TransactionReference &pCopy);
        const TransactionReference &operator = (const TransactionReference &pRight);
    };

    // Set of transaction outputs
    class TransactionOutputSet
    {
    public:

        static constexpr const char *START_STRING = "AMTX";

        ~TransactionOutputSet();

        //unsigned int count() const { return mReferences.size(); }

        TransactionReference *findUnspent(const Hash &pTransactionID, uint32_t pIndex);

        // Parse file if not in pending spent
        TransactionReference *findSpent(const Hash &pTransactionID, uint32_t pIndex);

        void write(ArcMist::OutputStream *pStream, unsigned int &pTransactionCount, unsigned int &pOutputCount,
          unsigned int &pSpentTransactionCount, unsigned int &pSpentOutputCount);
        bool read(ArcMist::InputStream *pStream, unsigned int &pTransactionCount, unsigned int &pOutputCount,
          unsigned int &pSpentTransactionCount, unsigned int &pSpentOutputCount);

        // Add a new transaction's outputs
        void add(TransactionReference *pReference, unsigned int &pTransactionCount, unsigned int &pOutputCount);

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

        TransactionOutputPool();

        bool isValid() const { return mValid; }

        // Find an unspent transaction output
        TransactionReference *findUnspent(const Hash &pTransactionID, uint32_t pIndex);

        // Add all the outputs from a block (pending since they have no block file IDs or offsets yet)
        void add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);

        // Find a spent transaction output
        TransactionReference *findSpent(const Hash &pTransactionID, uint32_t pIndex);

        // Mark an output as spent
        void spend(TransactionReference *pReference, unsigned int pIndex, unsigned int pBlockHeight)
        {
            pReference->outputAt(pIndex)->spendInternal(pBlockHeight);
            ++mSpentOutputCount;
            if(pReference->outputCount() == pReference->spentOutputCount())
                ++mSpentTransactionCount;
        }

        // Add block file IDs and offsets to the outputs for a block (call after writing the block to the block file)
        bool commit(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);

        // Remove pending adds and spends
        void revert(unsigned int pBlockHeight);

        // Height of last block
        unsigned int blockHeight() const { return mNextBlockHeight - 1; }
        unsigned int transactionCount() const { return mTransactionCount; }
        unsigned int spentTransactionCount() const { return mSpentTransactionCount; }
        unsigned int outputCount() const { return mOutputCount; }
        unsigned int spentOutputCount() const { return mSpentOutputCount; }
        unsigned int size() const
        {
            return (mTransactionCount * TransactionReference::SIZE) +
              (mOutputCount * TransactionOutputReference::SIZE);
        }
        unsigned int spentSize() const
        {
            return (mSpentTransactionCount * TransactionReference::SIZE) +
              (mSpentOutputCount * TransactionOutputReference::SIZE);
        }

        // Load from/Save to file system
        bool load(bool &pStop);
        bool save();

    private:

        TransactionOutputPool(const TransactionOutputPool &pCopy);
        const TransactionOutputPool &operator = (const TransactionOutputPool &pRight);

        ArcMist::Mutex mMutex;
        TransactionOutputSet mReferences[0x10000];
        bool mModified;
        bool mValid;
        unsigned int mTransactionCount, mOutputCount, mSpentTransactionCount, mSpentOutputCount;
        unsigned int mNextBlockHeight;

    };
}

#endif
