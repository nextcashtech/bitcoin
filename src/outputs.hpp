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
    class TransactionReference
    {
    public:

        // Size of data written to file (not counting outputs)
        //   32 byte hash, 4 byte block height, 4 byte output count
        static const unsigned int SIZE = 40;
        // 4 byte hash size, 8 byte hash data pointer, 8 byte output data pointer,
        //   8 byte file offset, 1 byte flags
        static const unsigned int MEMORY_SIZE = SIZE + 4 + 8 + 8 + 8 + 1;

        TransactionReference() : id(32)
        {
            blockHeight  = 0;
            mOutputCount = 0;
            mOutputs     = NULL;
            mFlags       = 0;
            fileOffset   = ArcMist::INVALID_STREAM_SIZE;
        }
        TransactionReference(const Hash &pID, unsigned int pBlockHeight, unsigned int pOutputCount) : id(pID)
        {
            blockHeight  = pBlockHeight;
            mOutputCount = 0;
            mOutputs     = NULL;
            mFlags       = 0;
            fileOffset   = ArcMist::INVALID_STREAM_SIZE;
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

        // Read everything except outputs. For sorting purposes
        bool readHeader(ArcMist::InputStream *pStream);

        // Read the hash, then if the hash matches read the rest
        bool readMatchingID(const Hash &pHash, ArcMist::InputStream *pStream);

        // Read the hash, then block height and return false if the block height is equal to or above specified
        bool readAboveBlock(unsigned int pBlockHeight, ArcMist::InputStream *pStream);

        bool read(ArcMist::InputStream *pStream);
        bool write(ArcMist::OutputStream *pStream);

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

        // Unmark any outputs spent at specified block height
        bool revert(unsigned int pBlockHeight);

        void print(ArcMist::Log::Level pLevel = ArcMist::Log::Level::VERBOSE);

        bool isHeader() const { return mOutputs == NULL; }

        // Flags
        bool markedDelete() const { return mFlags & DELETE_FLAG; }
        bool isModified() const { return mFlags & MODIFIED_FLAG; }
        bool isNew() const { return mFlags & NEW_FLAG; }
        bool wasSpent() const { return mFlags & WAS_SPENT_FLAG; }

        void setDelete() { mFlags |= DELETE_FLAG; }
        void setModified() { mFlags |= MODIFIED_FLAG; }
        void setNew() { mFlags |= NEW_FLAG; }
        void setWasSpent() { mFlags |= WAS_SPENT_FLAG; }

        void clearDelete() { mFlags ^= DELETE_FLAG; }
        void clearModified() { mFlags ^= MODIFIED_FLAG; }
        void clearNew() { mFlags ^= NEW_FLAG; }
        void clearWasSpent() { mFlags ^= WAS_SPENT_FLAG; }
        void clearFlags() { mFlags = 0; }

        Hash id; // Transaction Hash
        unsigned int blockHeight; // Block height of transaction
        ArcMist::stream_size fileOffset; // Offset into file where transaction reference is written

    private:

        // Max check values for validation
        static const unsigned int MAX_OUTPUT_COUNT = 0x0000ffff;
        static const unsigned int MAX_BLOCK_HEIGHT = 0x00ffffff;

        unsigned int mOutputCount;
        OutputReference *mOutputs;

        static const uint8_t DELETE_FLAG    = 0x01; // Transaction needs completely removed
        static const uint8_t MODIFIED_FLAG  = 0x02; // Transaction has been modified since last save
        static const uint8_t NEW_FLAG       = 0x04; // Transaction has not been saved yet
        static const uint8_t WAS_SPENT_FLAG = 0x08; // Transaction was previously saved as spent and removed from unspent index
        uint8_t mFlags;

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

        // Insert an item into a sorted list and retain sorting.
        //   Return false if the item was already in the list
        bool insertSorted(TransactionReference *pItem);

        // Returns true if the list is properly sorted
        bool checkSort();

        // Merge two sorted lists. pRight is empty after this call
        void mergeSorted(TransactionReferenceList &pRight);

        // Remove transaction references matching the following criteria.
        //   Created below a specified block height
        //   All outputs spent
        //   Marked for delete
        void drop(unsigned int pBlockHeight, unsigned int &pOutputCount);

        // Return an iterator to the first matching item in the list
        iterator firstMatching(const Hash &pHash);

    };

    class IndexEntry
    {
    public:

        IndexEntry() {}

        IndexEntry(const TransactionReference *pReference)
        {
            fileOffset  = pReference->fileOffset;
            // blockHeight = pReference->blockHeight;
            // unspent     = pReference->hasUnspentOutputs();
        }

        void invalidate()
        {
            fileOffset = ArcMist::INVALID_STREAM_SIZE;
            // blockHeight = 0xffffffff;
            // unspent     = true;
        }

        const IndexEntry &operator = (const TransactionReference *pReference)
        {
            fileOffset  = pReference->fileOffset;
            // blockHeight = pReference->blockHeight;
            // unspent     = pReference->hasUnspentOutputs();
            return *this;
        }

        bool read(ArcMist::InputStream *pStream)
        {
            if(pStream->remaining() < sizeof(IndexEntry))
                return false;
            pStream->read(this, sizeof(IndexEntry));
            return true;
        }

        bool write(ArcMist::OutputStream *pStream)
        {
            pStream->write(this, sizeof(IndexEntry));
            return true;
        }

        ArcMist::stream_size fileOffset;
        // unsigned int blockHeight;
        // bool unspent;

    };

    class SampleEntry
    {
    public:
        SampleEntry() {}

        Hash hash;
        ArcMist::stream_size indexOffset;
    };

    // Set of transaction outputs
    class OutputSet
    {
    public:

        OutputSet();
        ~OutputSet();

        bool setup(unsigned int pID, const char *pFilePath, unsigned int pCacheSize = 4096);

        // Find a transaction with an unspent output at the specified index
        TransactionReference *find(const Hash &pTransactionID, uint32_t pIndex);

        // Find a transaction with any unspent outputs
        TransactionReference *find(const Hash &pTransactionID);

        // Add a new transaction
        void add(TransactionReference *pReference);

        // Add block file offsets to "pending" outputs for a block
        void commit(TransactionReference *pReference, std::vector<Output *> &pOutputs);

        // Remove pending adds and spends (Note: Only reverts changes not written to the file yet)
        void revert(unsigned int pBlockHeight, bool pHard = false);

        // Pull all transactions from the file created at or after the specified block height
        //   Returns count of transactions found
        unsigned int pullBlocks(unsigned int pBlockHeight, bool pUnspentOnly = true);
        unsigned int loadCache(unsigned int pBlockHeight);

        unsigned int transactionCount() const { return mTransactionCount; }
        unsigned int outputCount() const { return mOutputCount; }
        unsigned long long size() const
        {
            return ((unsigned long long)mTransactionCount * TransactionReference::MEMORY_SIZE) +
              ((unsigned long long)mOutputCount * OutputReference::SIZE) + cachedSize();
        }
        // New data added, but not yet saved
        unsigned long long cachedSize() const
        {
            return ((unsigned long long)mCache.size() * (unsigned long long)TransactionReference::SIZE) +
              ((unsigned long long)mCacheOutputCount * (unsigned long long)OutputReference::SIZE);
        }

        // pBlockHeight is the block height below which to drop transactions from memory
        bool save(unsigned int pDropBlockHeight);
        bool saveCache(unsigned int pBlockHeight);

        void clear();

    private:

        static const unsigned int HEADER_SIZE = 8; // Transaction count and output count
        static const unsigned int INDICE_SET_COUNT = 256; // Number of sets to break indices into when rebuilding

        // Pull all transactions with matching IDs from the file and put them in cached.
        //   Returns count of transactions found
        TransactionReference *pull(const Hash &pTransactionID, unsigned int &pItemsPulled);
        unsigned int pullLinear(const Hash &pTransactionID);

        bool transactionIsCached(const Hash &pTransactionID, unsigned int pBlockHeight);

        // Find offsets into indices that contain the specified transaction ID, based on samples
        bool findSample(const Hash &pTransactionID, ArcMist::stream_size &pBegin, ArcMist::stream_size &pEnd);

        TransactionReference *pullTransactionHeader(ArcMist::stream_size pDataOffset);
        bool loadSample(unsigned int pSampleOffset);

        // File is sorted transaction references with offsets to output data in output file
        // mCache contains transactions added since last "save"
        // mModified contains transactions with outputs spent/modified since last "save"
        ArcMist::ReadersLock mLock;
        unsigned int mID;
        ArcMist::String mFilePath;
        ArcMist::FileInputStream *mUnspentFile;
        ArcMist::FileInputStream *mDataFile;

        TransactionReferenceList mCache;
        unsigned int mTransactionCount; // Number of transactions currently indexed
        unsigned int mOutputCount; // Number of transaction outputs currently indexed
        unsigned int mCacheOutputCount; // Number of transactions outputs in cache

        // Number of samples to pull from the file for preliminary search narrowing
        static const unsigned int SAMPLE_SIZE = 1024;
        SampleEntry *mSamples;
        bool mSamplesLoaded;

        void initializeSamples();

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
        ~TransactionOutputPool() { mToCommit.clearNoDelete(); } // Will be deleted in sets

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
        unsigned int loadCache(unsigned int pBlockHeight);

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
        bool load(bool pPreCache = true);
        bool purge();
        bool save();

        bool convert();

        // Run unit tests
        static bool test();

    private:

        TransactionOutputPool(const TransactionOutputPool &pCopy);
        const TransactionOutputPool &operator = (const TransactionOutputPool &pRight);

        OutputSet mSets[SET_COUNT];
        bool mModified;
        bool mValid;
        unsigned int mNextBlockHeight;
        unsigned int mSavedBlockHeight;
        unsigned int mCacheAge;

        TransactionReferenceList mToCommit;

    };
}

#endif
