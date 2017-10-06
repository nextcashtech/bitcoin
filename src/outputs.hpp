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
#include "arcmist/io/file_stream.hpp"
#include "base.hpp"

#include <vector>
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
        //   32 byte hash, 4 byte block height, 4 byte output count, 8 byte file offset
        static const unsigned int SIZE = 48;
        // 4 byte hash size, 8 byte hash data pointer, 8 byte output data pointer,
        //   8 byte output index data pointer
        static const unsigned int MEMORY_SIZE = SIZE + 4 + 8 + 8 + 8;
        static const ArcMist::stream_size NOT_WRITTEN = 0xffffffffffffffff;

        TransactionReference() : id(32)
        {
            blockHeight      = 0;
            outputFileOffset = NOT_WRITTEN;
            mOutputCount     = 0;
            mOutputs         = NULL;
            toDelete         = false;
        }
        TransactionReference(const Hash &pID, unsigned int pBlockHeight, unsigned int pOutputCount) : id(pID)
        {
            blockHeight      = pBlockHeight;
            outputFileOffset = NOT_WRITTEN;
            mOutputCount     = 0;
            mOutputs         = NULL;
            toDelete         = false;
            if(pOutputCount > 0)
            {
                allocateOutputs(pOutputCount);
                std::memset(mOutputs, 0, OutputReference::SIZE * mOutputCount); // Initialize outputs
            }
        }
        ~TransactionReference()
        {
            if(mOutputs != NULL)
                delete[] mOutputs;
        }

        // Read only header data. Used for resorting header file
        bool readHeaderOnly(ArcMist::InputStream *pHeaderStream);

        // Read the hash, then if the hash matches read the rest
        bool readMatchingID(const Hash &pHash, ArcMist::InputStream *pHeaderStream,
          ArcMist::InputStream *pOutputStream);

        bool readOld(ArcMist::InputStream *pStream);

        bool read(ArcMist::InputStream *pHeaderStream, ArcMist::InputStream *pOutputStream);
        bool write(ArcMist::OutputStream *pHeaderStream, ArcMist::OutputStream *pOutputStream, bool pRewriteOutputs);

        bool operator == (const TransactionReference &pRight) const
        {
            return id == pRight.id && blockHeight == pRight.blockHeight;
        }
        bool operator < (const TransactionReference &pRight) const
        {
            int compareID = id.compare(pRight.id);
            return compareID < 0 || (compareID == 0 && blockHeight < pRight.blockHeight);
        }
        bool operator > (const TransactionReference &pRight) const
        {
            int compareID = id.compare(pRight.id);
            return compareID > 0 || (compareID == 0 && blockHeight > pRight.blockHeight);
        }
        int compare(const TransactionReference &pRight) const
        {
            int compareID = id.compare(pRight.id);
            if(compareID == 0)
            {
                if(blockHeight < pRight.blockHeight)
                    return -1;
                else if(blockHeight > pRight.blockHeight)
                    return 1;
                else
                    return 0;
            }
            return compareID;
        }

        bool hasUnspentOutputs() const { return mOutputCount > 0 && spentOutputCount() < mOutputCount; }
        unsigned int outputCount() const { return mOutputCount; }
        unsigned int spentOutputCount() const;

        bool wasModifiedInOrAfterBlock(unsigned int pBlockHeight) const;

        OutputReference *outputAt(unsigned int pIndex)
        {
            if(mOutputs != NULL && pIndex < mOutputCount)
                return mOutputs + pIndex;
            return NULL;
        }
        void allocateOutputs(unsigned int pCount)
        {
            // Allocate the number of outputs needed
            if(mOutputCount != pCount)
            {
                if(mOutputs != NULL)
                    delete[] mOutputs;
                mOutputCount = pCount;
                if(mOutputCount == 0)
                    mOutputs = NULL;
                else
                    mOutputs = new OutputReference[mOutputCount];
            }
        }
        void clearOutputs()
        {
            if(mOutputs != NULL)
                delete[] mOutputs;
            mOutputCount = 0;
            mOutputs = NULL;
        }

        // Update block file offsets in outputs
        void commit(std::vector<Output *> &pOutputs);

        // Unmark any outputs spent at specified block height
        bool revert(unsigned int pBlockHeight);

        void print(ArcMist::Log::Level pLevel = ArcMist::Log::Level::VERBOSE);

        Hash id; // Transaction Hash
        unsigned int blockHeight; // Block height of transaction
        ArcMist::stream_size outputFileOffset; // Offset of the output data in the output file

        bool toDelete;

    private:

        unsigned int mOutputCount;
        OutputReference *mOutputs;

        TransactionReference(const TransactionReference &pCopy);
        const TransactionReference &operator = (const TransactionReference &pRight);

    };

    class TransactionReferenceList : public std::vector<TransactionReference *>
    {
    public:

        ~TransactionReferenceList()
        {
            for(iterator item=begin();item!=end();++item)
                delete *item;
        }

        void clear()
        {
            for(iterator item=begin();item!=end();++item)
                delete *item;
            std::vector<TransactionReference *>::clear();
        }

        // Clear the list without deleting the items within it
        void clearNoDelete() { std::vector<TransactionReference *>::clear(); }

        // Insert an item into a sorted list and retain sorting
        void insertSorted(TransactionReference *pItem);

        // Returns true if the list is properly sorted
        bool checkSort();

        // Merge two sorted lists. pRight is empty after this call
        void mergeSorted(TransactionReferenceList &pRight);

        // Remove transaction references created below a specified block height
        void dropBlocks(unsigned int pBlockHeight, unsigned int &pTransactionCount,
          unsigned int &pOutputCount);

        // Return an iterator to the first matching item in the list
        iterator firstMatching(const Hash &pHash);

        void print(unsigned int pID);

    };

    // Set of transaction outputs
    class OutputSet
    {
    public:

        static const unsigned int SUBSET_COUNT = 0x100;

        OutputSet();
        ~OutputSet();

        void setup(unsigned int pID, const char *pFilePath);

        // Find a transaction with an unspent output at the specified index
        TransactionReference *find(const Hash &pTransactionID, uint32_t pIndex);

        // Find a transaction with any unspent outputs
        TransactionReference *find(const Hash &pTransactionID);

        // Add a new transaction
        void add(TransactionReference *pReference);

        // Add block file offsets to "pending" outputs for a block
        void commit(const Hash &pTransactionID, std::vector<Output *> &pOutputs, unsigned int pBlockHeight);

        // Remove pending adds and spends (Note: Only reverts changes not written to the file yet)
        void revert(unsigned int pBlockHeight, bool pHard = false);

        // Pull all transactions from the file created at or after the specified block height
        //   Returns count of transactions found
        unsigned int pullBlocks(unsigned int pBlockHeight);

        unsigned int transactionCount() const { return mHeaderSize / TransactionReference::SIZE; }
        unsigned int outputCount() const { return mOutputSize / OutputReference::SIZE; }
        unsigned long long size() const
        {
            return (unsigned long long)mHeaderSize - (unsigned long long)(SUBSET_COUNT * 8) +
              (unsigned long long)mOutputSize + cachedSize();
        }
        // New data added, but not yet saved
        unsigned long long cachedSize() const
        {
            return ((unsigned long long)mCachedCount * (unsigned long long)TransactionReference::SIZE) +
              ((unsigned long long)mCachedOutputCount * (unsigned long long)OutputReference::SIZE);
        }

        // pBlockHeight is the block height below which to drop transactions from memory
        bool save(unsigned int pDropBlockHeight);

        void clear();

    private:

        // Pull al transactions with matching IDs from the file and put them in pending.
        //   Returns count of transactions found
        unsigned int pull(const Hash &pTransactionID, TransactionReferenceList &pList);

        // Pull all transactions created or spent at the specified block height from the file and put them in pending.
        //   Returns count of transactions found
        unsigned int pullBlock(unsigned int pBlockHeight);

        bool transactionIsCached(const Hash &pTransactionID, unsigned int pBlockHeight);

        bool openHeaderFile()
        {
            if(mHeaderFile == NULL)
                mHeaderFile = new ArcMist::FileInputStream(mFilePathName);
            if(!mHeaderFile->isValid())
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to open header file for set %02x", mID);
            return mHeaderFile->isValid();
        }
        void closeHeaderFile()
        {
            if(mHeaderFile != NULL)
                delete mHeaderFile;
            mHeaderFile = NULL;
        }
        bool openOutputsFile()
        {
            if(mOutputsFile == NULL)
                mOutputsFile = new ArcMist::FileInputStream(mFilePathName + ".outputs");
            if(!mOutputsFile->isValid())
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to open outputs file for set %02x", mID);
            return mOutputsFile->isValid();
        }
        void closeOutputFile()
        {
            if(mOutputsFile != NULL)
                delete mOutputsFile;
            mOutputsFile = NULL;
        }

        // File is sorted transaction references with offsets to output data in output file
        // mCached contains transactions added since last "save"
        // mModified contains transactions with outputs spent/modified since last "save"
        ArcMist::ReadersLock mLock;
        unsigned int mID;
        ArcMist::String mFilePathName;
        ArcMist::FileInputStream *mHeaderFile, *mOutputsFile;
        TransactionReferenceList mCached[SUBSET_COUNT];
        unsigned int mCachedCount, mCachedOutputCount;
        ArcMist::stream_size mHeaderSize, mOutputSize;
        bool mRewriteOutputs;

    };

    // Container for all unspent transaction outputs
    class TransactionOutputPool
    {
    public:

        static const unsigned int SET_COUNT = 0x100;
        static const unsigned int BIP0030_HASH_COUNT = 2;
        static const unsigned int BIP0030_HEIGHTS[BIP0030_HASH_COUNT];
        static const Hash BIP0030_HASHES[BIP0030_HASH_COUNT];

        TransactionOutputPool();

        bool isValid() const { return mValid; }

        // Find an unspent transaction output
        TransactionReference *findUnspent(const Hash &pTransactionID, uint32_t pIndex);

        // BIP-0030 Check if this block's transactions match any existing unspent transaction IDs
        //   This is expensive since it is a negative lookup and has to search a file for every transaction.
        //   Positive lookups can be limited extremely by cacheing transactions from recent (a few thousand) blocks
        bool checkDuplicates(const std::vector<Transaction *> &pBlockTransactions,
          unsigned int pBlockHeight, const Hash &pBlockHash);

        // Add all the outputs from a block (pending since they have no block file IDs or offsets yet)
        // Returns false if one of the transaction IDs is currently unspent BIP-0030
        bool add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);

        // Find a spent transaction output
        TransactionReference *findSpent(const Hash &pTransactionID, uint32_t pIndex);

        // Mark an output as spent
        void spend(TransactionReference *pReference, unsigned int pIndex, unsigned int pBlockHeight);

        // Add block file IDs and offsets to the outputs for a block (call after writing the block to the block file)
        bool commit(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);

        // Reverts all blocks above a specified block height
        bool revert(unsigned int pBlockHeight, bool pHard = false);

        // Pull all transactions from the files created at or after the specified block height
        //   Returns count of transactions found
        unsigned int pullBlocks(unsigned int pBlockHeight);

        // Height of last block
        int blockHeight() const { return mNextBlockHeight - 1; }
        unsigned int transactionCount() const;
        unsigned int outputCount() const;
        unsigned long long size() const;
        unsigned long long cachedSize() const;

        unsigned int cacheBlockHeight() const
        {
            if(mNextBlockHeight > mCacheAge)
                return mNextBlockHeight - mCacheAge;
            else
                return 0;
        }

        // Load from/Save to file system
        bool load();
        bool purge();
        bool save();

        bool convert();

    private:

        TransactionOutputPool(const TransactionOutputPool &pCopy);
        const TransactionOutputPool &operator = (const TransactionOutputPool &pRight);

        OutputSet mSets[SET_COUNT];
        bool mModified;
        bool mValid;
        unsigned int mNextBlockHeight;
        unsigned int mSavedBlockHeight;
        unsigned int mCacheAge;

        std::vector<TransactionReference *> mToCommit;

    };
}

#endif
