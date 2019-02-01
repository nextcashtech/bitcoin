/**************************************************************************
 * Copyright 2017-2019 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_OUTPUTS_HPP
#define BITCOIN_OUTPUTS_HPP

#include "mutex.hpp"
#include "hash.hpp"
#include "hash_set.hpp"
#include "sorted_set.hpp"
#include "log.hpp"
#include "buffer.hpp"
#include "file_stream.hpp"
#include "base.hpp"
#include "transaction.hpp"
#include "forks.hpp"
#include "profiler_setup.hpp"

#include <vector>
#include <stdlib.h>

#define BITCOIN_OUTPUTS_LOG_NAME "Outputs"


namespace BitCoin
{
    // Reference to a transaction's outputs with information to get them quickly
    class TransactionOutputs : public NextCash::HashObject
    {
    public:

        TransactionOutputs()
        {
            cacheFlags = 0;
            dataFlags = 0;
            mDataOffset = NextCash::INVALID_STREAM_SIZE;
            blockHeight  = 0;
            mOutputCount = 0;
            mSpentHeights = NULL;
        }
        TransactionOutputs(const NextCash::Hash &pHash) : mHash(pHash)
        {
            cacheFlags = 0;
            dataFlags = 0;
            mDataOffset = NextCash::INVALID_STREAM_SIZE;
            blockHeight  = 0;
            mOutputCount = 0;
            mSpentHeights = NULL;
        }
        TransactionOutputs(const NextCash::Hash &pHash, bool pIsCoinBase, uint32_t pBlockHeight,
          uint32_t pOutputCount) : mHash(pHash)
        {
            cacheFlags = 0;
            if(pIsCoinBase)
                dataFlags = COINBASE_DATA_FLAG;
            else
                dataFlags = 0;
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
        ~TransactionOutputs()
        {
            if(mSpentHeights != NULL)
                delete[] mSpentHeights;
        }

        void setHash(const NextCash::Hash &pHash) { mHash = pHash; }

        // Data Flags
        bool isCoinBase() const { return dataFlags & COINBASE_DATA_FLAG; }

        // Cache Flags
        bool markedRemove() const { return cacheFlags & REMOVE_CACHE_FLAG; }
        bool isModified() const { return cacheFlags & MODIFIED_CACHE_FLAG; }
        bool isNew() const { return cacheFlags & NEW_CACHE_FLAG; }
        bool isOld() const { return cacheFlags & OLD_CACHE_FLAG; }

        void setRemove() { cacheFlags |= REMOVE_CACHE_FLAG; }
        void setModified() { cacheFlags |= MODIFIED_CACHE_FLAG; }
        void setNew() { cacheFlags |= NEW_CACHE_FLAG; }
        void setOld() { cacheFlags |= OLD_CACHE_FLAG; }

        void clearRemove() { cacheFlags &= ~REMOVE_CACHE_FLAG; }
        void clearModified() { cacheFlags &= ~MODIFIED_CACHE_FLAG; }
        void clearNew() { cacheFlags &= ~NEW_CACHE_FLAG; }
        void clearOld() { cacheFlags &= ~OLD_CACHE_FLAG; }
        void clearFlags() { cacheFlags = 0; }

        bool wasWritten() const { return mDataOffset != NextCash::INVALID_STREAM_SIZE; }
        NextCash::stream_size dataOffset() const { return mDataOffset; }
        void setDataOffset(NextCash::stream_size pDataOffset) { mDataOffset = pDataOffset; }
        void clearDataOffset() { mDataOffset = NextCash::INVALID_STREAM_SIZE; }

        // Returns the size(bytes) in memory of the object
        NextCash::stream_size memorySize() const;

        // Evaluates the relative age of two objects.
        // Used to determine which objects to drop from cache
        // Negative means this object is older than pRight.
        // Zero means both objects are the same age.
        // Positive means this object is newer than pRight.
        int compareAge(TransactionOutputs *pRight)
        {
            // Spent transactions are "older" than unspent transactions
            bool spent = !hasUnspent();
            bool rightSpent = ((TransactionOutputs *)pRight)->hasUnspent();

            if(spent != rightSpent)
            {
                if(spent)
                    return -1;
                else
                    return 1;
            }

            // If both transactions are spent or both unspent then use block height.
            if(blockHeight < ((TransactionOutputs *)pRight)->blockHeight)
                return -1;
            if(blockHeight > ((TransactionOutputs *)pRight)->blockHeight)
                return 1;
            return 0;
        }

        bool read(NextCash::InputStream *pStream);
        void write(NextCash::OutputStream *pStream);
        bool readData(NextCash::InputStream *pStream);
        bool readOutput(NextCash::InputStream *pStream, uint32_t pIndex, Output &pOutput);
        void writeInitialData(const NextCash::Hash &pHash, NextCash::OutputStream *pStream,
          TransactionReference &pTransaction, unsigned int pBlockHeight);
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
        void clearSpends();

        // HashObject virtual functions
        const NextCash::Hash &getHash() { return mHash; }
        bool valueEquals(const NextCash::SortedObject *pRight) const
        {
            try
            {
                // Since more than one transaction with the same hash will never be in the same
                //   block.
                return blockHeight ==
                  dynamic_cast<const TransactionOutputs *>(pRight)->blockHeight;
            }
            catch(...)
            {
                return false;
            }
        }

        void print(NextCash::Log::Level pLevel = NextCash::Log::Level::VERBOSE);

        uint32_t blockHeight; // Block height of transaction
        uint8_t cacheFlags;
        uint8_t dataFlags;

    private:

        static const uint8_t NEW_CACHE_FLAG           = 0x01; // Hasn't been added to the index yet.
        static const uint8_t MODIFIED_CACHE_FLAG      = 0x02; // Modified since last write.
        static const uint8_t REMOVE_CACHE_FLAG        = 0x04; // Needs removed from index and cache.
        static const uint8_t OLD_CACHE_FLAG           = 0x08; // Needs to be dropped from cache.

        // This transaction is a coinbase transaction (first of block).
        static const uint8_t COINBASE_DATA_FLAG = 0x01;

        // Size in file not counting variable size data.
        // Base size :
        //   sizeof(uint8_t) dataFlags
        //   sizeof(uint32_t) height
        //   sizeof(uint32_t) output count
        static const NextCash::stream_size mBaseSize = sizeof(uint8_t) + (2 * sizeof(uint32_t));

        // Base memory size :
        //   Base size
        //   sizeof(uint32_t *) spent height pointer
        //   sizeof(NextCash::stream_size) data offset
        //   sizeof(uint8_t) cacheFlags
        static const NextCash::stream_size mBaseMemorySize = mBaseSize + sizeof(uint32_t *) +
          sizeof(NextCash::stream_size) + sizeof(uint8_t);

        // The offset in the data file of the hash value, followed by the specific data for the
        //   virtual read/write functions.
        NextCash::stream_size mDataOffset;

        // Max check values for validation
        static const uint32_t MAX_OUTPUT_COUNT = 0x0000ffff;
        static const uint32_t MAX_BLOCK_HEIGHT = 0x00ffffff;

        uint32_t mOutputCount;
        uint32_t *mSpentHeights;

        NextCash::Hash mHash;

        TransactionOutputs(const TransactionOutputs &pCopy);
        const TransactionOutputs &operator = (const TransactionOutputs &pRight);

    };

    // Container for all unspent transaction outputs
    class Outputs
    {
    public:

        Outputs() : mLock("OutputsLock") { mNextBlockHeight = 0; mSavedBlockHeight = 0; }
        ~Outputs() {}

        // Returns 0xffffffff if not found.
        unsigned int getBlockHeight(const NextCash::Hash &pTransactionID);

        static const uint8_t MARK_SPENT = 0x01;
        static const uint8_t REQUIRE_UNSPENT = 0x02;
        bool getOutput(const NextCash::Hash &pTransactionID, uint32_t pIndex, uint8_t pFlags,
          uint32_t pSpentBlockHeight, Output &pOutput, uint32_t &pPreviousBlockHeight,
          bool &pPulled);

        bool isUnspent(const NextCash::Hash &pTransactionID, uint32_t pIndex, bool &pPulled);
        bool spend(const NextCash::Hash &pTransactionID, uint32_t pIndex,
          uint32_t pSpentBlockHeight, uint32_t &pPreviousBlockHeight, bool pRequireUnspent,
          bool &pPulled);
        bool hasUnspent(const NextCash::Hash &pTransactionID,
          uint32_t pSpentBlockHeight = 0xffffffff);
        bool exists(const NextCash::Hash &pTransactionID, bool pPullIfNeeded = true);

        static const uint8_t UNSPENT_STATUS_EXISTS  = 0x01; // Transaction output found
        static const uint8_t UNSPENT_STATUS_UNSPENT = 0x02; // Transaction output is not spent
        uint8_t unspentStatus(const NextCash::Hash &pTransactionID, uint32_t pIndex);

        // BIP-0030 Check if a transaction ID exists with unspent outputs before this block height.
        //   pBlockHash is for exceptions allowed before BIP-0030 was activated.
        //   This is expensive since it is a negative lookup and has to search a file for every
        //     transaction.
        bool checkDuplicate(const NextCash::Hash &pTransactionID, unsigned int pBlockHeight,
          const NextCash::Hash &pBlockHash);

        // Add all the outputs from a block (pending since they have no block file IDs or offsets yet)
        // Returns false if one of the transaction IDs is currently unspent BIP-0030
        bool add(TransactionList &pBlockTransactions, unsigned int pBlockHeight);

        // Revert transactions in a block.
        bool revert(TransactionList &pBlockTransactions, unsigned int pBlockHeight);

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

        bool saveFull(unsigned int pThreadCount, bool pAutoTrimCache = true);
        bool saveCache();

        static bool test();

    private:

        Outputs(const Outputs &pCopy);
        const Outputs &operator = (const Outputs &pRight);

        bool saveBlockHeight();

        unsigned int mNextBlockHeight, mSavedBlockHeight;

        static const uint32_t BIP0030_HASH_COUNT = 2;
        static const uint32_t BIP0030_HEIGHTS[BIP0030_HASH_COUNT];
        static const NextCash::Hash BIP0030_HASHES[BIP0030_HASH_COUNT];

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

        typedef typename NextCash::HashSet::Iterator SubSetIterator;

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

            // Returns 0xffffffff if not found.
            unsigned int getBlockHeight(const NextCash::Hash &pTransactionID);

            SubSetIterator get(const NextCash::Hash &pTransactionID);

            // Inserts a new item corresponding to the lookup.
            bool insert(TransactionOutputs *pReference, TransactionReference &pTransaction,
              unsigned int pBlockHeight);

            bool getOutput(const NextCash::Hash &pTransactionID, uint32_t pIndex, uint8_t pFlags,
              uint32_t pSpentBlockHeight, Output &pOutput, uint32_t &pPreviousBlockHeight,
              bool &pPulled);
            bool isUnspent(const NextCash::Hash &pTransactionID, uint32_t pIndex, bool &pPulled);
            bool spend(const NextCash::Hash &pTransactionID, uint32_t pIndex,
              uint32_t pSpentBlockHeight, uint32_t &pPreviousBlockHeight, bool pRequireUnspent,
              bool &pPulled);
            bool hasUnspent(const NextCash::Hash &pTransactionID, uint32_t pSpentBlockHeight);
            bool exists(const NextCash::Hash &pTransactionID, bool pPullIfNeeded);
            uint8_t unspentStatus(const NextCash::Hash &pTransactionID, uint32_t pIndex);

            bool checkDuplicate(const NextCash::Hash &pTransactionID, unsigned int pBlockHeight,
              const NextCash::Hash &pBlockHash);

            SubSetIterator end() { return mCache.end(); }

            // Pull all items with matching hashes from the file and put them in the cache.
            //   Returns true if any items were added to the cache.
            // If pPullMatchingFunction then only items that return true will be pulled.
            bool pull(const NextCash::Hash &pTransactionID, TransactionOutputs *pMatching = NULL);

            bool load(const char *pFilePath, unsigned int pID, unsigned int &pLoadedCount);
            bool save(NextCash::stream_size pMaxCacheDataSize, bool pAutoTrimCache,
              unsigned int &pSavedCount);

            bool saveCache(unsigned int &pSavedCount);

            // Rewrite data file filling in gaps from removed data.
            bool defragment();

        private:

            bool pullHash(NextCash::InputStream *pDataFile, NextCash::stream_size pFileOffset,
              NextCash::Hash &pHash)
            {
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

            bool loadCache(unsigned int &pLoadedCount);

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
            NextCash::HashSet mCache;
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

            TransactionOutputs *operator *() { return (TransactionOutputs *)*mIterator; }
            TransactionOutputs *operator ->() { return (TransactionOutputs *)*mIterator; }

            const NextCash::Hash &hash() { return (*mIterator)->getHash(); }

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

        Iterator get(const NextCash::Hash &pTransactionID, bool pLocked = false);

        // Inserts a new item corresponding to the lookup.
        // Returns false if the pReference matches an existing value under the same hash according
        //   to the TransactionOutputs::valuesMatch function.
        bool insert(TransactionOutputs *pReference, TransactionReference &pTransaction,
          unsigned int pBlockHeight);

        Iterator begin();
        Iterator end();

        bool loadSubSets(const char *pFilePath);
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
                savedCount = 0;
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
            unsigned int savedCount;
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

            void markComplete(unsigned int pOffset, bool pSuccess, unsigned int pCount)
            {
                mutex.lock();
                savedCount += pCount;
                setComplete[pOffset] = true;
                setSuccess[pOffset] = pSuccess;
                if(!pSuccess)
                    success = false;
                mutex.unlock();
            }

        };

        static void saveThreadRun(void *pParameter); // Thread to process save tasks

    };
}

#endif
