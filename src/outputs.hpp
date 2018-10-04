/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_OUTPUTS_HPP
#define BITCOIN_OUTPUTS_HPP

#include "mutex.hpp"
#include "hash.hpp"
#include "log.hpp"
#include "buffer.hpp"
#include "file_stream.hpp"
#include "base.hpp"
#include "forks.hpp"

#include <vector>
#include <stdlib.h>

#define BITCOIN_OUTPUTS_LOG_NAME "Outputs"


namespace BitCoin
{
    class Transaction; // Work around circular reference

    class Output
    {
    public:

        Output() { }
        Output(const Output &pCopy) : script(pCopy.script)
        {
            amount = pCopy.amount;
        }

        Output &operator = (const Output &pRight)
        {
            amount = pRight.amount;
            script = pRight.script;
            return *this;
        }

        // 8 amount + script length size + script length
        NextCash::stream_size size() const
          { return 8 + compactIntegerSize(script.length()) + script.length(); }

        void write(NextCash::OutputStream *pStream);
        bool read(NextCash::InputStream *pStream);

        // Skip over output in stream
        //   (The input stream's read offset must be at the beginning of an output)
        static bool skip(NextCash::InputStream *pInputStream,
          NextCash::OutputStream *pOutputStream = NULL);

        // Print human readable version to log
        void print(const Forks &pForks, const char *pLogName = BITCOIN_OUTPUTS_LOG_NAME,
          NextCash::Log::Level pLevel = NextCash::Log::VERBOSE);

        int64_t amount; // Number of Satoshis spent (documentation says this should be signed)
        NextCash::Buffer script;

    };

    // Reference to a transaction's outputs with information to get them quickly
    class TransactionReference
    {
    public:

        TransactionReference()
        {
            mFlags = 0;
            mDataOffset = NextCash::INVALID_STREAM_SIZE;
            blockHeight  = 0;
            mOutputCount = 0;
            mSpentHeights = NULL;
        }
        TransactionReference(uint32_t pBlockHeight, uint32_t pOutputCount)
        {
            mFlags = 0;
            mDataOffset = NextCash::INVALID_STREAM_SIZE;
            blockHeight  = pBlockHeight;
            mOutputCount = pOutputCount;
            if(mOutputCount > 0)
            {
                mSpentHeights = new uint32_t[mOutputCount];
                std::memset(mSpentHeights, 0, sizeof(uint32_t) * mOutputCount);
            }
            else
                mSpentHeights = NULL;
        }
        ~TransactionReference()
        {
            if(mSpentHeights != NULL)
                delete[] mSpentHeights;
        }

        // Flags
        bool markedRemove() const { return mFlags & REMOVE_FLAG; }
        bool isModified() const { return mFlags & MODIFIED_FLAG; }
        bool isNew() const { return mFlags & NEW_FLAG; }
        bool isOld() const { return mFlags & OLD_FLAG; }

        void setRemove() { mFlags |= REMOVE_FLAG; }
        void setModified() { mFlags |= MODIFIED_FLAG; }
        void setNew() { mFlags |= NEW_FLAG; }
        void setOld() { mFlags |= OLD_FLAG; }

        void clearRemove() { mFlags &= ~REMOVE_FLAG; }
        void clearModified() { mFlags &= ~MODIFIED_FLAG; }
        void clearNew() { mFlags &= ~NEW_FLAG; }
        void clearOld() { mFlags &= ~OLD_FLAG; }
        void clearFlags() { mFlags = 0; }

        bool wasWritten() const { return mDataOffset != NextCash::INVALID_STREAM_SIZE; }
        NextCash::stream_size dataOffset() const { return mDataOffset; }
        void setDataOffset(NextCash::stream_size pDataOffset) { mDataOffset = pDataOffset; }
        void clearDataOffset() { mDataOffset = NextCash::INVALID_STREAM_SIZE; }

        // Returns the size(bytes) in memory of the object
        NextCash::stream_size size() const;

        // Evaluates the relative age of two objects.
        // Used to determine which objects to drop from cache
        // Negative means this object is older than pRight.
        // Zero means both objects are the same age.
        // Positive means this object is newer than pRight.
        int compareAge(TransactionReference *pRight)
        {
            // Spent transactions are "older" than unspent transactions
            bool spent = !hasUnspent();
            bool rightSpent = ((TransactionReference *)pRight)->hasUnspent();

            if(spent != rightSpent)
            {
                if(spent)
                    return -1;
                else
                    return 1;
            }

            // If both transactions are spent or both unspent then use block height.
            if(blockHeight < ((TransactionReference *)pRight)->blockHeight)
                return -1;
            if(blockHeight > ((TransactionReference *)pRight)->blockHeight)
                return 1;
            return 0;
        }

        // Returns true if the value of this object matches the value pRight references.
        bool valuesMatch(const TransactionReference *pRight) const
        {
            // Since more than one transaction with the same hash will never be in the same block.
            return blockHeight == ((TransactionReference *)pRight)->blockHeight;
        }

        bool read(NextCash::InputStream *pStream);
        void write(NextCash::OutputStream *pStream);
        bool readData(NextCash::InputStream *pStream);
        bool readOutput(NextCash::InputStream *pStream, uint32_t pIndex, Output &pOutput);
        void writeInitialData(const NextCash::Hash &pHash, NextCash::OutputStream *pStream,
          Transaction &pTransaction);
        void writeModifiedData(NextCash::OutputStream *pStream);

        bool spendInternal(uint32_t pBlockHeight, uint32_t pIndex)
        {
            if(mOutputCount <= pIndex)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                  "Invalid output index %d/%d", pIndex, mOutputCount);
                return false;
            }

            if(mSpentHeights[pIndex] != 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                  "Output already spent at height %d", mSpentHeights[pIndex]);
                return false;
            }

            mSpentHeights[pIndex] = pBlockHeight;
            setModified();
            return true;
        }


        bool isUnspent(uint32_t pIndex) const
          { return mOutputCount > pIndex && mSpentHeights[pIndex] == 0; }
        bool hasUnspent() const
        {
            uint32_t *spentHeight = mSpentHeights;
            for(uint32_t i = 0; i < mOutputCount; ++i, ++spentHeight)
                if(*spentHeight == 0)
                    return true;
            return false;
        }

        // The highest block that spent this block. Returns MAX_BLOCK_HEIGHT if all outputs are not spent yet
        uint32_t spentBlockHeight() const;
        uint32_t outputCount() const { return mOutputCount; }
        uint32_t spentOutputCount() const;

        bool wasModifiedInOrAfterBlock(uint32_t pBlockHeight) const;

        bool allocateOutputs(uint32_t pCount);
        void clearOutputs();

        // Unmark any outputs spent above a specified block height
        bool revert(const NextCash::Hash &pHash, uint32_t pBlockHeight);
        bool revertSpend(uint32_t pIndex, uint32_t pBlockHeight)
        {
            if(mOutputCount > pIndex && mSpentHeights[pIndex] == pBlockHeight)
            {
                mSpentHeights[pIndex] = 0;
                setModified();
                return true;
            }
            else
                return false;
        }

        void print(NextCash::Log::Level pLevel = NextCash::Log::Level::VERBOSE);

        uint32_t blockHeight; // Block height of transaction

    private:

        static const uint8_t NEW_FLAG           = 0x01; // Hasn't been added to the index yet.
        static const uint8_t MODIFIED_FLAG      = 0x02; // Modified since last write.
        static const uint8_t REMOVE_FLAG        = 0x04; // Needs removed from index and cache.
        static const uint8_t OLD_FLAG           = 0x08; // Needs to be dropped from cache.

        uint8_t mFlags;

        // The offset in the data file of the hash value, followed by the specific data for the
        //   virtual read/write functions.
        NextCash::stream_size mDataOffset;

        // Max check values for validation
        static const uint32_t MAX_OUTPUT_COUNT = 0x0000ffff;
        static const uint32_t MAX_BLOCK_HEIGHT = 0x00ffffff;

        uint32_t mOutputCount;
        uint32_t *mSpentHeights;

        TransactionReference(const TransactionReference &pCopy);
        const TransactionReference &operator = (const TransactionReference &pRight);

    };

    // Container for all unspent transaction outputs
    class TransactionOutputPool
    {
    public:

        TransactionOutputPool() : mLock("OutputsLock") { mNextBlockHeight = 0; mSavedBlockHeight = 0; }
        ~TransactionOutputPool() {}

        static const uint8_t MARK_SPENT = 0x01;
        static const uint8_t REQUIRE_UNSPENT = 0x02;
        bool getOutput(const NextCash::Hash &pTransactionID, uint32_t pIndex, uint8_t pFlags,
          uint32_t pSpentBlockHeight, Output &pOutput, uint32_t &pPreviousBlockHeight);
        bool isUnspent(const NextCash::Hash &pTransactionID, uint32_t pIndex);
        bool spend(const NextCash::Hash &pTransactionID, uint32_t pIndex,
          uint32_t pSpentBlockHeight, uint32_t &pPreviousBlockHeight, bool pRequireUnspent);
        bool hasUnspent(const NextCash::Hash &pTransactionID,
          uint32_t pSpentBlockHeight = 0xffffffff);
        bool exists(const NextCash::Hash &pTransactionID);

        // BIP-0030 Check if a transaction ID exists with unspent outputs before this block height.
        //   pBlockHash is for exceptions allowed before BIP-0030 was activated.
        //   This is expensive since it is a negative lookup and has to search a file for every
        //     transaction.
        bool checkDuplicate(const NextCash::Hash &pTransactionID, unsigned int pBlockHeight,
          const NextCash::Hash &pBlockHash);

        // Add all the outputs from a block (pending since they have no block file IDs or offsets yet)
        // Returns false if one of the transaction IDs is currently unspent BIP-0030
        bool add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);

        // Revert transactions in a block.
        bool revert(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);

        // bool revertToHeight(unsigned int pBlockHeight);

        // Height of last block
        unsigned int height() const
        {
            if(mNextBlockHeight == 0)
                return 0xffffffff;
            else
                return mNextBlockHeight - 1;
        }
        unsigned int transactionCount() const;

        bool cacheNeedsTrim()
        {
            return cacheDataSize() > (mTargetCacheSize + mCacheDelta);
        }

        // Debug Only
        void markValid() { mIsValid = true; }

        bool load(const char *pFilePath, NextCash::stream_size pTargetCacheSize,
          NextCash::stream_size pCacheDelta);
        bool save(unsigned int pThreadCount, bool pAutoTrimCache = true);

        static bool test();

    private:

        TransactionOutputPool(const TransactionOutputPool &pCopy);
        const TransactionOutputPool &operator = (const TransactionOutputPool &pRight);

        unsigned int mNextBlockHeight, mSavedBlockHeight;

        static const uint32_t BIP0030_HASH_COUNT = 2;
        static const uint32_t BIP0030_HEIGHTS[BIP0030_HASH_COUNT];
        static const NextCash::Hash BIP0030_HASHES[BIP0030_HASH_COUNT];

        // Returns true if the values pointed to by both HashData pointers match
        static bool transactionsMatch(TransactionReference *&pLeft, TransactionReference *&pRight)
        {
            return pLeft->valuesMatch(pRight);
        }

        unsigned int subSetOffset(const NextCash::Hash &pTransactionID)
        {
            return pTransactionID.lookup16() >> 6;
        }

        class SampleEntry
        {
        public:
            NextCash::Hash hash;
            NextCash::stream_size offset;

            bool load(NextCash::InputStream *pIndexFile, NextCash::InputStream *pDataFile)
            {
                if(hash.isEmpty())
                {
                    pIndexFile->setReadOffset(offset);
                    NextCash::stream_size dataOffset;
                    pIndexFile->read(&dataOffset, sizeof(NextCash::stream_size));

                    pDataFile->setReadOffset(dataOffset);
                    if(!hash.read(pDataFile, TRANSACTION_HASH_SIZE))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed to read sample index hash at offset %llu", offset);
                        return false;
                    }
                }
                return true;
            }
        };

        typedef typename NextCash::HashContainerList<TransactionReference *>::Iterator
          SubSetIterator;

        class SubSet
        {
        public:

            SubSet();
            ~SubSet();

            unsigned int id() const { return mID; }

            NextCash::stream_size size() const { return mIndexSize + mNewSize; }
            NextCash::stream_size cacheSize() const { return mCache.size(); }
            static const NextCash::stream_size staticCacheItemSize =
              NextCash::Hash::memorySize(TRANSACTION_HASH_SIZE) + // Hash in cache.
              sizeof(void *); // Data pointer in cache.
            NextCash::stream_size cacheDataSize()
              { return mCacheRawDataSize + (mCache.size() * staticCacheItemSize); }

            SubSetIterator get(const NextCash::Hash &pTransactionID);

            // Inserts a new item corresponding to the lookup.
            bool insert(const NextCash::Hash &pTransactionID, TransactionReference *pReference,
              Transaction &pTransaction);

            bool getOutput(const NextCash::Hash &pTransactionID, uint32_t pIndex, uint8_t pFlags,
              uint32_t pSpentBlockHeight, Output &pOutput, uint32_t &pPreviousBlockHeight);
            bool isUnspent(const NextCash::Hash &pTransactionID, uint32_t pIndex);
            bool spend(const NextCash::Hash &pTransactionID, uint32_t pIndex,
              uint32_t pSpentBlockHeight, uint32_t &pPreviousBlockHeight, bool pRequireUnspent);
            bool hasUnspent(const NextCash::Hash &pTransactionID, uint32_t pSpentBlockHeight);
            bool exists(const NextCash::Hash &pTransactionID);

            bool checkDuplicate(const NextCash::Hash &pTransactionID, unsigned int pBlockHeight,
              const NextCash::Hash &pBlockHash);

            SubSetIterator end() { return mCache.end(); }

            // Pull all items with matching hashes from the file and put them in the cache.
            //   Returns true if any items were added to the cache.
            // If pPullMatchingFunction then only items that return true will be pulled.
            bool pull(const NextCash::Hash &pTransactionID, TransactionReference *pMatching = NULL);

            bool load(const char *pFilePath, unsigned int pID);
            bool save(NextCash::stream_size pMaxCacheDataSize, bool pAutoTrimCache);

            // Rewrite data file filling in gaps from removed data.
            bool defragment();

        private:

            bool pullHash(NextCash::InputStream *pDataFile, NextCash::stream_size pFileOffset,
              NextCash::Hash &pHash)
            {
#ifdef PROFILER_ON
                NextCash::Profiler profiler("Hash SubSet Pull Hash");
#endif
                if(!pDataFile->setReadOffset(pFileOffset))
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed to pull hash at index offset %d/%d", pFileOffset,
                      pDataFile->length());
                    return false;
                }

                if(!pHash.read(pDataFile, TRANSACTION_HASH_SIZE))
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed to pull hash at index offset %d/%d", pFileOffset,
                      pDataFile->length());
                    return false;
                }

                return true;
            }

            void loadSamples(NextCash::InputStream *pIndexFile);

            // Find offsets into indices that contain the specified hash, based on samples
            bool findSample(const NextCash::Hash &pHash, NextCash::InputStream *pIndexFile,
              NextCash::InputStream *pDataFile, NextCash::stream_size &pBegin,
              NextCash::stream_size &pEnd);

            bool loadCache();
            bool saveCache();

            // Mark items in the cache as old until it is under the specified data size.
            // Only called by trimeCache.
            void markOld(NextCash::stream_size pDataSize);

            // Remove items from cache based on "age" and data size specified.
            // Only called by save.
            bool trimCache(NextCash::stream_size pMaxCacheDataSize, bool pAutoTrimCache);

            NextCash::MutexWithConstantName mLock;
            const char *mFilePath;
            NextCash::stream_size mIndexSize, mNewSize, mCacheRawDataSize;
            unsigned int mID;
            NextCash::HashContainerList<TransactionReference *> mCache;
            SampleEntry *mSamples;

        };

        NextCash::ReadersLock mLock;
        NextCash::String mFilePath;
        SubSet mSubSets[OUTPUTS_SET_COUNT];
        NextCash::stream_size mTargetCacheSize, mCacheDelta;
        bool mIsValid;

    public:

        bool isValid() const { return mIsValid; }

        const NextCash::String &path() const { return mFilePath; }

        // Iterators only allow iteration through the end of the current sub set. They are only
        //   designed to allow iterating through matching hashes.
        class Iterator
        {
        public:

            Iterator() { mSubSet = NULL; }
            Iterator(SubSet *pSubSet, SubSetIterator &pIterator)
            {
                mSubSet = pSubSet;
                mIterator = pIterator;
            }

            TransactionReference *operator *() { return *mIterator; }
            TransactionReference *operator ->() { return *mIterator; }

            const NextCash::Hash &hash() const { return mIterator.hash(); }

            operator bool() const { return mSubSet != NULL && mIterator != mSubSet->end(); }
            bool operator !() const { return mSubSet == NULL || mIterator == mSubSet->end(); }

            bool operator ==(const Iterator &pRight) { return mIterator == pRight.mIterator; }
            bool operator !=(const Iterator &pRight) { return mIterator != pRight.mIterator; }

            Iterator &operator =(const Iterator &pRight)
            {
                mSubSet = pRight.mSubSet;
                mIterator = pRight.mIterator;
                return *this;
            }

            // Prefix increment
            Iterator &operator ++()
            {
                ++mIterator;
                return *this;
            }

            // Postfix increment
            Iterator operator ++(int)
            {
                Iterator result = *this;
                ++result;
                return result;
            }

            // Prefix decrement
            Iterator &operator --()
            {
                --mIterator;
                return *this;
            }

            // Postfix decrement
            Iterator operator --(int)
            {
                Iterator result = *this;
                --result;
                return result;
            }

        private:
            SubSet *mSubSet;
            SubSetIterator mIterator;
        };

        NextCash::stream_size size() const
        {
            NextCash::stream_size result = 0;
            const SubSet *subSet = mSubSets;
            for(unsigned int i = 0; i < OUTPUTS_SET_COUNT; ++i)
            {
                result += subSet->size();
                ++subSet;
            }
            return result;
        }

        NextCash::stream_size cacheSize() const
        {
            NextCash::stream_size result = 0;
            const SubSet *subSet = mSubSets;
            for(unsigned int i = 0; i < OUTPUTS_SET_COUNT; ++i)
            {
                result += subSet->cacheSize();
                ++subSet;
            }
            return result;
        }

        NextCash::stream_size cacheDataSize()
        {
            NextCash::stream_size result = 0;
            SubSet *subSet = mSubSets;
            for(unsigned int i = 0; i < OUTPUTS_SET_COUNT; ++i)
            {
                result += subSet->cacheDataSize();
                ++subSet;
            }
            return result;
        }

        // Set max cache data size in bytes
        NextCash::stream_size targetCacheSize() const { return mTargetCacheSize; }
        void setTargetCacheSize(NextCash::stream_size pSize) { mTargetCacheSize = pSize; }
        NextCash::stream_size cacheDelta() const { return mCacheDelta; }
        void setCacheDelta(NextCash::stream_size pSize) { mCacheDelta = pSize; }

        Iterator get(const NextCash::Hash &pTransactionID);

        // Inserts a new item corresponding to the lookup.
        // Returns false if the pReference matches an existing value under the same hash according
        //   to the TransactionReference::valuesMatch function.
        bool insert(const NextCash::Hash &pTransactionID, TransactionReference *pReference,
          Transaction &pTransaction);

        Iterator begin();
        Iterator end();

        bool load(const char *pFilePath);
        bool saveSingleThreaded(bool pAutoTrimCache);
        bool saveMultiThreaded(unsigned int pThreadCount, bool pAutoTrimCache);

        class SaveThreadData
        {
        public:

            SaveThreadData(SubSet *pFirstSubSet, NextCash::stream_size pMaxSetCacheDataSize,
              bool pAutoTrimCache) : mutex("SaveThreadData")
            {
                nextSubSet = pFirstSubSet;
                maxSetCacheDataSize = pMaxSetCacheDataSize;
                autoTrimCache = pAutoTrimCache;
                offset = 0;
                success = true;
                for(unsigned int i = 0; i < OUTPUTS_SET_COUNT; ++i)
                {
                    setComplete[i] = false;
                    setSuccess[i] = true;
                }
            }

            NextCash::Mutex mutex;
            SubSet *nextSubSet;
            NextCash::stream_size maxSetCacheDataSize;
            bool autoTrimCache;
            unsigned int offset;
            bool success;
            bool setComplete[OUTPUTS_SET_COUNT];
            bool setSuccess[OUTPUTS_SET_COUNT];

            SubSet *getNext()
            {
                mutex.lock();
                SubSet *result = nextSubSet;
                if(nextSubSet != NULL)
                {
                    if(++offset == OUTPUTS_SET_COUNT)
                        nextSubSet = NULL;
                    else
                        ++nextSubSet;
                }
                mutex.unlock();
                return result;
            }

            void markComplete(unsigned int pOffset, bool pSuccess)
            {
                setComplete[pOffset] = true;
                setSuccess[pOffset] = pSuccess;
                if(!pSuccess)
                    success = false;
            }

        };

        static void saveThreadRun(); // Thread to process save tasks

    };
}

#endif
