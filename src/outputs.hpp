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

    class TransactionOutputReference
    {
    public:

        TransactionOutputReference()
        {
            index            = 0;
            blockFileOffset  = 0;
            spentBlockHeight = 0;
        }

        void spend(unsigned int pBlockHeight) { spentBlockHeight = pBlockHeight; }
        void update(const Output &pOutput) { blockFileOffset = pOutput.blockFileOffset; }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        // Update the spent block height in the file
        void writeSpentHeight(ArcMist::OutputStream *pStream);

        void print(ArcMist::Log::Level pLevel = ArcMist::Log::Level::VERBOSE);

        unsigned int index;
        unsigned int blockFileOffset;
        unsigned int spentBlockHeight;
    };

    class TransactionReference
    {
    public:

        TransactionReference() : id(32)
        {
            blockHeight = 0;
            fileOffset  = 0xffffffff;
        }
        TransactionReference(const Hash &pID, unsigned int pBlockHeight, unsigned int pOutputCount)
          : id(pID), mOutputs(pOutputCount)
        {
            blockHeight = pBlockHeight;
            fileOffset  = 0xffffffff;
            unsigned int index = 0;
            for(std::vector<TransactionOutputReference>::iterator output=mOutputs.begin();output!=mOutputs.end();++output)
                output->index = index++;
        }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        TransactionOutputReference *output(unsigned int pIndex);

        void writeSpent(ArcMist::OutputStream *pStream, bool pWrote);
        void removeSpent();

        // Update block file offsets in outputs
        void update(std::vector<Output *> &pOutputs);

        void revert(unsigned int pBlockHeight);

        unsigned int outputCount() const { return mOutputs.size(); }

        void print(ArcMist::Log::Level pLevel = ArcMist::Log::Level::VERBOSE);

        Hash id; // Transaction Hash
        unsigned int blockHeight; // Block height of transaction
        unsigned int fileOffset; // Offset of this data in transaction reference set file

    private:
        std::vector<TransactionOutputReference> mOutputs;
    };

    // Hash table of subset of unspent transaction outputs
    class TransactionOutputSet
    {
    public:

        static constexpr const char *START_STRING = "AMTX";

        ~TransactionOutputSet();

        unsigned int size() const { return mReferences.size(); }

        TransactionReference *findUnspent(const Hash &pTransactionID, uint32_t pIndex);

        // Parse file if not in pending spent
        TransactionReference *findSpent(const Hash &pTransactionID, uint32_t pIndex);

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        void add(TransactionReference *pReference);

        // Add block file IDs and offsets to "pending" outputs for a block
        void commit(const Hash &pTransactionID, std::vector<Output *> &pOutputs, unsigned int pBlockHeight);

        // Remove pending adds and spends (Note: Only reverts changes not written yet)
        unsigned int revert(unsigned int pBlockHeight);

        unsigned int count() const;

        void clear();

    private:

        std::list<TransactionReference *> mReferences;

    };

    // Container for all unspent transaction outputs
    class TransactionOutputPool
    {
    public:

        TransactionOutputPool();
        ~TransactionOutputPool();

        bool isValid() const { return mValid; }

        // Find an unspent transaction output
        TransactionReference *findUnspent(const Hash &pTransactionID, uint32_t pIndex);

        // Add all the outputs from a block (pending since they have no block file IDs or offsets yet)
        void add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);

        // Find a spent transaction output
        TransactionReference *findSpent(const Hash &pTransactionID, uint32_t pIndex);

        // Add block file IDs and offsets to the outputs for a block (call after writing the block to the block file)
        bool commit(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);
        // Remove pending adds and spends
        void revert(unsigned int pBlockHeight);

        // Height of last block
        unsigned int blockHeight() const { return mNextBlockHeight - 1; }

        // Number of transaction outputs spent and unspent currently in memory
        unsigned int count() const { return mCount; }

        // Reverse all of the changes made by the most recent block
        //TODO void reverseLastBlock();

        // Load from/Save to file system
        bool load();
        bool save();

        // This will remove items from pOther as it finds matches
        // Returns true if they match
        //bool compare(TransactionOutputPool &pOther, const char *pName, const char *pOtherName);

    private:

        TransactionOutputPool(const TransactionOutputPool &pCopy);
        const TransactionOutputPool &operator = (const TransactionOutputPool &pRight);

        ArcMist::Mutex mMutex;
        TransactionOutputSet mReferences[0x10000];
        bool mModified;
        bool mValid;
        unsigned int mCount;
        unsigned int mNextBlockHeight;

    };
}

#endif
