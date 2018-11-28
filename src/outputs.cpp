/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "outputs.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#endif

#include "distributed_vector.hpp"
#include "info.hpp"
#include "interpreter.hpp"
#include "block.hpp"

#include <cstring>


namespace BitCoin
{
    void Output::write(NextCash::OutputStream *pStream)
    {
        pStream->writeLong(amount);
        writeCompactInteger(pStream, script.length());
        script.setReadOffset(0);
        pStream->writeStream(&script, script.length());
    }

    bool Output::read(NextCash::InputStream *pStream)
    {
        if(pStream->remaining() < 8)
            return false;

        amount = pStream->readLong();

        NextCash::stream_size bytes = readCompactInteger(pStream);
        if(bytes > MAX_SCRIPT_SIZE)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to read output. Script too long : %d", bytes);
            return false;
        }
        if(pStream->remaining() < bytes)
            return false;
        script.setSize(bytes);
        script.reset();
        script.writeStreamCompact(*pStream, bytes);

        return true;
    }

    bool Output::skip(NextCash::InputStream *pInputStream, NextCash::OutputStream *pOutputStream)
    {
        // Amount
        if(pInputStream->remaining() < 8)
            return false;
        if(pOutputStream == NULL)
            pInputStream->setReadOffset(pInputStream->readOffset() + 8);
        else
            pOutputStream->writeLong(pInputStream->readLong());

        // Script
        NextCash::stream_size bytes = readCompactInteger(pInputStream);
        if(pOutputStream != NULL)
            writeCompactInteger(pOutputStream, bytes);
        if(pInputStream->remaining() < bytes)
            return false;
        if(pOutputStream == NULL)
            pInputStream->setReadOffset(pInputStream->readOffset() + bytes);
        else
            pInputStream->readStream(pOutputStream, bytes);
        return true;
    }

    void Output::print(const Forks &pForks, const char *pLogName, NextCash::Log::Level pLevel)
    {
        NextCash::Log::addFormatted(pLevel, pLogName, "  Amount : %.08f",
          bitcoins(amount));
        NextCash::Log::addFormatted(pLevel, pLogName, "  Script : (%d bytes)",
          script.length());
        script.setReadOffset(0);
        ScriptInterpreter::printScript(script, pForks, pLevel);
    }

    bool TransactionReference::allocateOutputs(uint32_t pCount)
    {
        // Allocate the number of outputs needed
        if(mOutputCount != pCount)
        {
            if(mSpentHeights != NULL)
                delete[] mSpentHeights;
            mOutputCount = pCount;
            if(mOutputCount == 0)
                mSpentHeights = NULL;
            else
            {
                try
                {
                    mSpentHeights = new uint32_t[mOutputCount];
                }
                catch(std::bad_alloc &pBadAlloc)
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Bad allocation (Allocate %d Spent Heights) : %s", mOutputCount,
                      pBadAlloc.what());
                    return false;
                }
            }
        }

        return true;
    }

    void TransactionReference::clearOutputs()
    {
        if(mSpentHeights != NULL)
            delete[] mSpentHeights;
        mOutputCount = 0;
        mSpentHeights = NULL;
    }

    bool TransactionReference::read(NextCash::InputStream *pStream)
    {
        if(pStream->remaining() < 9)
            return false;

        dataFlags = pStream->readByte();
        blockHeight = pStream->readUnsignedInt();
        uint32_t newOutputCount = pStream->readUnsignedInt();
        if(newOutputCount > MAX_OUTPUT_COUNT)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
              "Output count too high : %d", newOutputCount);
            return false;
        }

        if(mSpentHeights != NULL)
        {
            if(newOutputCount != mOutputCount)
            {
                delete[] mSpentHeights;
                mOutputCount = newOutputCount;
                mSpentHeights = new uint32_t[mOutputCount];
            }
        }
        else
        {
            mOutputCount = newOutputCount;
            mSpentHeights = new uint32_t[mOutputCount];
        }

        if(pStream->remaining() < sizeof(uint32_t) * mOutputCount)
            return false;

        pStream->read(mSpentHeights, sizeof(uint32_t) * mOutputCount);
        return true;
    }

    void TransactionReference::write(NextCash::OutputStream *pStream)
    {
        pStream->writeByte(dataFlags);
        pStream->writeUnsignedInt(blockHeight);
        pStream->writeUnsignedInt(mOutputCount);
        pStream->write(mSpentHeights, sizeof(uint32_t) * mOutputCount);
    }

    bool TransactionReference::readData(NextCash::InputStream *pStream)
    {
        // Hash has already been read from the file so set the file offset to the current location
        //   minus hash size.
        mDataOffset = pStream->readOffset() - TRANSACTION_HASH_SIZE;
        if(!read(pStream))
            return false;
        clearFlags();
        return true;
    }

    bool TransactionReference::readOutput(NextCash::InputStream *pStream, uint32_t pIndex,
      Output &pOutput)
    {
        if(pIndex >= mOutputCount)
            return false;

        pStream->setReadOffset(mDataOffset + TRANSACTION_HASH_SIZE + mBaseSize +
          (sizeof(uint32_t) * mOutputCount));

        for(uint32_t i = 0; i < pIndex; i++)
            Output::skip(pStream);

        return pOutput.read(pStream);
    }

    void TransactionReference::writeInitialData(const NextCash::Hash &pHash,
      NextCash::OutputStream *pStream, Transaction &pTransaction)
    {
        if(mDataOffset == NextCash::INVALID_STREAM_SIZE)
        {
            // Not written to file yet. Append to end of file.
            pStream->setWriteOffset(pStream->length());
            mDataOffset = pStream->writeOffset();
            pHash.write(pStream);

            write(pStream);

            for(std::vector<Output>::iterator output = pTransaction.outputs.begin();
              output != pTransaction.outputs.end(); ++output)
                output->write(pStream);

            clearModified();
            setNew();
            return;
        }

        if(!isModified())
            return;

        // Only spent heights will be modified.
        pStream->setWriteOffset(mDataOffset + TRANSACTION_HASH_SIZE + mBaseSize);
        pStream->write(mSpentHeights, sizeof(uint32_t) * mOutputCount);

        clearModified();
    }

    void TransactionReference::writeModifiedData(NextCash::OutputStream *pStream)
    {
        // Only spent heights will be modified.
        pStream->setWriteOffset(mDataOffset + TRANSACTION_HASH_SIZE + mBaseSize);
        pStream->write(mSpentHeights, sizeof(uint32_t) * mOutputCount);

        clearModified();
    }

    NextCash::stream_size TransactionReference::memorySize() const
    {
        // Add spent height array size
        return mBaseMemorySize + (sizeof(uint32_t) * mOutputCount);
    }

    uint32_t TransactionReference::spentOutputCount() const
    {
        if(mSpentHeights == NULL)
            return 0;
        uint32_t result = 0;
        uint32_t *spentHeight = mSpentHeights;
        for(uint32_t i = 0; i < mOutputCount; ++i, ++spentHeight)
            if(*spentHeight != 0)
                ++result;
        return result;
    }

    bool TransactionReference::wasModifiedInOrAfterBlock(uint32_t pBlockHeight) const
    {
        if(blockHeight >= pBlockHeight)
            return true;

        if(mOutputCount == 0 || mSpentHeights == NULL)
            return false;

        uint32_t *spentHeight = mSpentHeights;
        for(uint32_t i = 0; i < mOutputCount; ++i, ++spentHeight)
            if(*spentHeight >= pBlockHeight)
                return true;

        return false;
    }

    uint32_t TransactionReference::spentBlockHeight() const
    {
        uint32_t result = 0;
        uint32_t *spentHeight = mSpentHeights;
        for(uint32_t i = 0; i < mOutputCount; ++i, ++spentHeight)
        {
            if(*spentHeight == 0)
                return MAX_BLOCK_HEIGHT;
            else if(*spentHeight > result)
                result = *spentHeight;
        }
        return result;
    }

    void TransactionReference::print(NextCash::Log::Level pLevel)
    {
        NextCash::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "Transaction Reference");
        NextCash::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Height         : %d",
          blockHeight);
        if(isCoinBase())
            NextCash::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Is CoinBase");

        uint32_t *spentHeight = mSpentHeights;
        for(uint32_t i = 0; i < mOutputCount; ++i, ++spentHeight)
        {
            if(*spentHeight == 0)
                NextCash::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    Unspent");
            else
                NextCash::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    Spent at %d",
                  *spentHeight);
        }
    }

    const uint32_t Outputs::BIP0030_HEIGHTS[BIP0030_HASH_COUNT] = { 91842, 91880 };
    const NextCash::Hash Outputs::BIP0030_HASHES[BIP0030_HASH_COUNT] =
    {
        NextCash::Hash("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"),
        NextCash::Hash("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")
    };

    bool Outputs::checkDuplicate(const NextCash::Hash &pTransactionID,
      unsigned int pBlockHeight, const NextCash::Hash &pBlockHash)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_CHECK_ID, PROFILER_OUTPUTS_CHECK_NAME), true);
#endif
        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        bool result = subSet->checkDuplicate(pTransactionID, pBlockHeight, pBlockHash);
        mLock.readUnlock();
        return result;
    }

    typename Outputs::Iterator Outputs::get(const NextCash::Hash &pTransactionID, bool pLocked)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_GET_ID, PROFILER_OUTPUTS_GET_NAME), true);
#endif
        if(!pLocked)
            mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        SubSetIterator result = subSet->get(pTransactionID);
        if(!pLocked)
            mLock.readUnlock();
        return Iterator(subSet, result);
    }

    bool Outputs::add(const std::vector<Transaction *> &pBlockTransactions,
      unsigned int pBlockHeight)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_ADD_ID, PROFILER_OUTPUTS_ADD_NAME), true);
#endif
        if(pBlockHeight != mNextBlockHeight)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't add transaction outputs for non-matching block height %d. Should be %d",
              pBlockHeight, mNextBlockHeight);
            return false;
        }

        TransactionReference *transactionReference;
        Iterator item;
        unsigned int count = 0;
        bool success = true, valid;
        for(std::vector<Transaction *>::const_iterator transaction = pBlockTransactions.begin();
          transaction != pBlockTransactions.end(); ++transaction)
        {
            // Get references set for transaction ID.
            transactionReference = new TransactionReference((*transaction)->hash, count == 0,
              pBlockHeight, (*transaction)->outputs.size());

            valid = true;
            if(!insert(transactionReference, **transaction))
            {
                // Check for matching transaction marked for removal.
                Iterator item = get((*transaction)->hash);

                valid = false;
                while(item && (*item)->getHash() == (*transaction)->hash)
                {
                    if(transactionReference->valueEquals(*item) && (*item)->markedRemove())
                    {
                        // Unmark the matching item for removal
                        NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
                          "Reversing removal of transaction output for block height %d : %s",
                          pBlockHeight, (*transaction)->hash.hex().text());
                        (*item)->clearRemove();
                        valid = true;
                        delete transactionReference;
                        transactionReference = (TransactionReference *)*item;
                        break;
                    }
                    ++item;
                }
            }

            if(valid)
                ++count;
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to insert transaction output for block height %d : %s", pBlockHeight,
                  (*transaction)->hash.hex().text());
                success = false;
                delete transactionReference;
            }
        }

        ++mNextBlockHeight;
        return success;
    }

    bool Outputs::revert(const std::vector<Transaction *> &pBlockTransactions,
      unsigned int pHeight)
    {
        if(!mIsValid)
            return false;

        mLock.writeLock("Revert");

        if(mNextBlockHeight != 0 && pHeight != mNextBlockHeight - 1)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't revert non-matching block height %d. Should be %d", pHeight,
              mNextBlockHeight - 1);
            mLock.writeUnlock();
            return false;
        }

        std::vector<Input>::const_iterator input;
        Iterator reference;
        bool success = true;
        bool found;

        // Process transactions in reverse since they can unspend previous transactions in the same
        //   block
        for(std::vector<Transaction *>::const_reverse_iterator transaction =
          pBlockTransactions.rbegin(); transaction != pBlockTransactions.rend(); ++transaction)
        {
            // Unspend inputs
            for(input = (*transaction)->inputs.begin(); input != (*transaction)->inputs.end();
              ++input)
                if(input->outpoint.index != 0xffffffff) // Coinbase input
                {
                    reference = get(input->outpoint.transactionID, true);
                    found = false;
                    while(reference && reference.hash() == input->outpoint.transactionID)
                    {
                        if(!(*reference)->markedRemove())
                        {
                            if((*reference)->revertSpend(input->outpoint.index, pHeight))
                            {
                                NextCash::Log::addFormatted(NextCash::Log::DEBUG,
                                  BITCOIN_OUTPUTS_LOG_NAME,
                                  "Reverting spend on input transaction : %s index %d",
                                  input->outpoint.transactionID.hex().text(),
                                  input->outpoint.index);
                            }

                            found = true;
                            break;
                        }

                        ++reference;
                    }

                    // if(!found)
                    // {
                        // NextCash::Log::addFormatted(NextCash::Log::WARNING,
                          // BITCOIN_OUTPUTS_LOG_NAME,
                          // "Input transaction not found to revert spend : %s index %d",
                          // input->outpoint.transactionID.hex().text(), input->outpoint.index);
                    // }
                }

            // Remove transaction
            reference = get((*transaction)->hash, true);
            found = false;
            while(reference && reference.hash() == (*transaction)->hash)
            {
                if(!((TransactionReference *)(*reference))->markedRemove())
                {
                    NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
                      "Removing transaction : %s", (*transaction)->hash.hex().text());
                    reference->setRemove();
                    found = true;
                    break;
                }

                ++reference;
            }

            if(!found)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                  "Transaction not found to remove for revert : %s",
                  (*transaction)->hash.hex().text());
            }
        }

        --mNextBlockHeight;
        mLock.writeUnlock();
        return success;
    }

    // bool Outputs::revertToHeight(unsigned int pBlockHeight)
    // {
        // mLock.writeLock("Revert");

        // if(!mIsValid)
        // {
            // NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              // "%s : can't revert invalid data set", BITCOIN_OUTPUTS_LOG_NAME);
            // mLock.writeUnlock();
            // return false;
        // }

        // for(NextCash::HashContainerList<NextCash::TransactionReference *>::Iterator item = mCache.begin();
          // item != mCache.end(); ++item)
        // {

        // }

        // SubSet *subSet = mSubSets;
        // uint32_t lastReport = getTime();
        // bool success = true;

        // for(unsigned int i = 0; i < OUTPUTS_SET_COUNT; ++i)
        // {
            // if(getTime() - lastReport >= 10)
            // {
                // NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  // "%s revert is %2d%% Complete", BITCOIN_OUTPUTS_LOG_NAME,
                  // (int)(((float)i / (float)OUTPUTS_SET_COUNT) * 100.0f));
                // lastReport = getTime();
            // }

            // ++subSet;
        // }

        // mLock.writeUnlock();
    // }

    bool Outputs::getOutput(const NextCash::Hash &pTransactionID, uint32_t pIndex,
      uint8_t pFlags, uint32_t pSpentBlockHeight, Output &pOutput, uint32_t &pPreviousBlockHeight)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_GET_OUTPUT_ID, PROFILER_OUTPUTS_GET_OUTPUT_NAME), true);
#endif
        if(!mIsValid)
            return false;

        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        bool result = subSet->getOutput(pTransactionID, pIndex, pFlags, pSpentBlockHeight,
          pOutput, pPreviousBlockHeight);
        mLock.readUnlock();
        return result;
    }

    bool Outputs::isUnspent(const NextCash::Hash &pTransactionID, uint32_t pIndex)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_IS_UNSPENT_ID, PROFILER_OUTPUTS_IS_UNSPENT_NAME), true);
#endif
        if(!mIsValid)
            return false;

        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        bool result = subSet->isUnspent(pTransactionID, pIndex);
        mLock.readUnlock();
        return result;
    }

    uint8_t Outputs::unspentStatus(const NextCash::Hash &pTransactionID, uint32_t pIndex)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_UNSPENT_STATUS_ID, PROFILER_OUTPUTS_UNSPENT_STATUS_NAME), true);
#endif
        if(!mIsValid)
            return 0;

        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        uint8_t result = subSet->unspentStatus(pTransactionID, pIndex);
        mLock.readUnlock();
        return result;
    }

    bool Outputs::spend(const NextCash::Hash &pTransactionID, uint32_t pIndex,
      uint32_t pSpentBlockHeight, uint32_t &pPreviousBlockHeight, bool pRequireUnspent)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_SPEND_ID, PROFILER_OUTPUTS_SPEND_NAME), true);
#endif
        if(!mIsValid)
            return false;

        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        bool result = subSet->spend(pTransactionID, pIndex, pSpentBlockHeight,
          pPreviousBlockHeight, pRequireUnspent);
        mLock.readUnlock();
        return result;
    }

    bool Outputs::hasUnspent(const NextCash::Hash &pTransactionID,
      uint32_t pSpentBlockHeight)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_HAS_UNSPENT_ID, PROFILER_OUTPUTS_HAS_UNSPENT_NAME), true);
#endif
        if(!mIsValid)
            return false;

        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        bool result = subSet->hasUnspent(pTransactionID, pSpentBlockHeight);
        mLock.readUnlock();
        return result;
    }

    bool Outputs::exists(const NextCash::Hash &pTransactionID, bool pPullIfNeeded)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_EXISTS_ID, PROFILER_OUTPUTS_EXISTS_NAME), true);
#endif
        if(!mIsValid)
            return false;

        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        bool result = subSet->exists(pTransactionID, pPullIfNeeded);
        mLock.readUnlock();
        return result;
    }

    bool Outputs::load(const char *pFilePath, NextCash::stream_size pTargetCacheSize,
      NextCash::stream_size pCacheDelta)
    {
        NextCash::String filePath = pFilePath;
        filePath.pathAppend("outputs");

        if(!loadSubSets(filePath))
            return false;

        NextCash::String filePathName = filePath;
        filePathName.pathAppend("height");
        if(!NextCash::fileExists(filePathName))
            mNextBlockHeight = 0;
        else
        {
            NextCash::FileInputStream file(filePathName);
            if(!file.isValid())
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to open height file to load");
                mIsValid = false;
                return false;
            }

            // Read block height
            mNextBlockHeight = file.readUnsignedInt();
        }

        if(mIsValid)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
              "Loaded outputs at height %d (%d K trans) (%d K, %d KB cached)",
              mNextBlockHeight - 1, size() / 1000, cacheSize() / 1000, cacheDataSize() / 1000);
            mSavedBlockHeight = mNextBlockHeight;

            setTargetCacheSize(pTargetCacheSize);
            setCacheDelta(pCacheDelta);
        }

        return mIsValid;
    }

    bool Outputs::saveBlockHeight()
    {
        NextCash::String filePathName = path();
        filePathName.pathAppend("height");
        NextCash::FileOutputStream file(filePathName, true);
        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to open height file to save");
            return false;
        }

        // Block Height
        file.writeUnsignedInt(mNextBlockHeight);
        file.flush();
        mSavedBlockHeight = mNextBlockHeight;
        return true;
    }

    bool Outputs::saveFull(unsigned int pThreadCount, bool pAutoTrimCache)
    {
        mLock.writeLock("Save Cache");

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Saving outputs at height %d (%d K trans) (%d K, %d KB cached)", mNextBlockHeight - 1,
          size() / 1000, cacheSize() / 1000, cacheDataSize() / 1000);

#ifdef SINGLE_THREAD
        if(!Outputs::saveSingleThreaded(pAutoTrimCache))
#else
        if(!Outputs::saveMultiThreaded(pThreadCount, pAutoTrimCache))
#endif
        {
            mLock.writeUnlock();
            return false;
        }

        if(!saveBlockHeight())
        {
            mLock.writeUnlock();
            return false;
        }

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Saved outputs at height %d (%d K trans) (%d K, %d KB cached)", mNextBlockHeight - 1,
          size() / 1000, cacheSize() / 1000, cacheDataSize() / 1000);
        mLock.writeUnlock();
        return true;
    }

    bool Outputs::saveCache()
    {
        mLock.writeLock("Save Cache");

        if(!mIsValid)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't save invalid data set");
            mLock.writeUnlock();
            return false;
        }

        SubSet *subSet = mSubSets;
        Time lastReport = getTime();
        bool success = true;
        unsigned int savedCount = 0;
        unsigned int totalSavedCount = 0;
        for(unsigned int i = 0; i < OUTPUTS_SET_COUNT; ++i)
        {
            if(getTime() - lastReport >= 10)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Save cache is %2d%% Complete", (int)(((float)i / (float)OUTPUTS_SET_COUNT) * 100.0f));
                lastReport = getTime();
            }

            if(!subSet->saveCache(savedCount))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed set %d save cache", subSet->id());
                success = false;
            }

            totalSavedCount += savedCount;
            ++subSet;
        }

        if(!saveBlockHeight())
        {
            mLock.writeUnlock();
            return false;
        }

        NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
          "Saved %d cache items", totalSavedCount);
        mLock.writeUnlock();
        return success;
    }

    bool Outputs::insert(TransactionReference *pValue, Transaction &pTransaction)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_INSERT_ID, PROFILER_OUTPUTS_INSERT_NAME), true);
#endif
        mLock.readLock();
        bool result = mSubSets[subSetOffset(pValue->getHash())].insert(pValue, pTransaction);
        mLock.readUnlock();
        return result;
    }

    bool Outputs::loadSubSets(const char *pFilePath)
    {
        mLock.writeLock("Load");

        mIsValid = true;
        mFilePath = pFilePath;
        if(!createDirectory(mFilePath))
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to create directory : %s", mFilePath.text());
            mIsValid = false;
            mLock.writeUnlock();
            return false;
        }

        SubSet *subSet = mSubSets;
        Time lastReport = getTime();
        unsigned int loadedCount;
        unsigned int totalLoadedCount = 0;
        for(unsigned int i = 0; i < OUTPUTS_SET_COUNT; ++i)
        {
            if(getTime() - lastReport >= 10)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Load is %2d%% Complete", (int)(((float)i / (float)OUTPUTS_SET_COUNT) * 100.0f));
                lastReport = getTime();
            }
            if(!subSet->load(mFilePath, i, loadedCount))
                mIsValid = false;
            totalLoadedCount += loadedCount;
            ++subSet;
        }

        mLock.writeUnlock();
        NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
          "Loaded %d cache items", totalLoadedCount);
        return mIsValid;
    }

    bool Outputs::saveSingleThreaded(bool pAutoTrimCache)
    {
        if(!mIsValid)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't save invalid data set");
            return false;
        }

        SubSet *subSet = mSubSets;
        Time lastReport = getTime();
        NextCash::stream_size maxSetCacheDataSize = 0;
        unsigned int savedCount;
        unsigned int totalSavedCount = 0;
        bool success = true;
        if(mTargetCacheSize > 0)
            maxSetCacheDataSize = mTargetCacheSize / OUTPUTS_SET_COUNT;
        for(unsigned int i = 0; i < OUTPUTS_SET_COUNT; ++i)
        {
            if(getTime() - lastReport >= 10)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Save is %2d%% Complete", (int)(((float)i / (float)OUTPUTS_SET_COUNT) * 100.0f));
                lastReport = getTime();
            }

            if(!subSet->save(maxSetCacheDataSize, pAutoTrimCache, savedCount))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed set %d save", subSet->id());
                success = false;
            }

            totalSavedCount += savedCount;
            ++subSet;
        }

        NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
          "Saved %d cache items", totalSavedCount);
        return success;
    }

    void Outputs::saveThreadRun(void *pParameter)
    {
        SaveThreadData *data = (SaveThreadData *)pParameter;
        if(data == NULL)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
              "Thread parameter is null. Stopping");
            return;
        }

        SubSet *subSet;
        unsigned int savedCount;
        while(true)
        {
            subSet = data->getNext();
            if(subSet == NULL)
            {
                NextCash::Log::add(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
                  "No more save tasks remaining");
                break;
            }

            if(subSet->save(data->maxSetCacheDataSize, data->autoTrimCache, savedCount))
                data->markComplete(subSet->id(), true, savedCount);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed save of set %d", subSet->id());
                data->markComplete(subSet->id(), false, savedCount);
            }
        }
    }

    bool Outputs::saveMultiThreaded(unsigned int pThreadCount, bool pAutoTrimCache)
    {
        if(!mIsValid)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't save invalid data set");
            return false;
        }

        NextCash::stream_size maxSetCacheDataSize = 0;
        if(mTargetCacheSize > 0)
            maxSetCacheDataSize = mTargetCacheSize / OUTPUTS_SET_COUNT;
        SaveThreadData threadData(mSubSets, maxSetCacheDataSize, pAutoTrimCache);
        NextCash::Thread *threads[pThreadCount];
        Time lastReport = getTime();
        unsigned int i;
        NextCash::String threadName;

        // Start threads
        for(i = 0; i < pThreadCount; ++i)
        {
            threadName.writeFormatted("%s Save %d", BITCOIN_OUTPUTS_LOG_NAME, i);
            threads[i] = new NextCash::Thread(threadName, saveThreadRun, &threadData);
        }

        // Monitor threads
        unsigned int completedCount;
        bool report;
        while(true)
        {
            if(threadData.offset == OUTPUTS_SET_COUNT)
            {
                report = getTime() - lastReport >= 10;
                completedCount = 0;
                for(i = 0; i < OUTPUTS_SET_COUNT; ++i)
                    if(threadData.setComplete[i])
                        ++completedCount;
                    else if(report)
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                          "Save waiting for set %d", i);

                if(report)
                    lastReport = getTime();

                if(completedCount == OUTPUTS_SET_COUNT)
                    break;
            }
            else if(getTime() - lastReport >= 10)
            {
                completedCount = 0;
                for(i = 0; i < OUTPUTS_SET_COUNT; ++i)
                    if(threadData.setComplete[i])
                        ++completedCount;

                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Save is %2d%% Complete",
                  (int)(((float)completedCount / (float)OUTPUTS_SET_COUNT) * 100.0f));

                lastReport = getTime();
            }

            NextCash::Thread::sleep(500);
        }

        // Delete threads
        NextCash::Log::add(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME, "Deleting save threads");
        for(i = 0; i < pThreadCount; ++i)
            delete threads[i];

        NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
          "Saved %d cache items", threadData.savedCount);
        return threadData.success;
    }

    Outputs::SubSet::SubSet() : mLock("OutputsSubSet")
    {
        mSamples = NULL;
        mIndexSize = 0;
        mNewSize = 0;
        mCacheRawDataSize = 0;
    }

    Outputs::SubSet::~SubSet()
    {
        if(mSamples != NULL)
            delete[] mSamples;
    }

    typename Outputs::SubSetIterator Outputs::SubSet::get(const NextCash::Hash &pTransactionID)
    {
        mLock.lock();

        SubSetIterator result = mCache.find(pTransactionID);
        if(result == mCache.end() && pull(pTransactionID))
            result = mCache.find(pTransactionID);

        mLock.unlock();
        return result;
    }

    bool Outputs::SubSet::insert(TransactionReference *pReference, Transaction &pTransaction)
    {
        mLock.lock();

        if(!mCache.insert(pReference, true))
        {
            mLock.unlock();
            return false;
        }

        pReference->clearDataOffset();

#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_WRITE_ID, PROFILER_OUTPUTS_WRITE_NAME), true);
#endif
        NextCash::String filePathName;
        filePathName.writeFormatted("%s%s%04x.data", mFilePath, NextCash::PATH_SEPARATOR, mID);
        NextCash::FileOutputStream *dataOutFile = new NextCash::FileOutputStream(filePathName);
        if(!dataOutFile->isValid())
        {
            delete dataOutFile;
            mCache.remove(pReference->getHash());
            mLock.unlock();
            return false;
        }

        pReference->writeInitialData(pReference->getHash(), dataOutFile, pTransaction);
        delete dataOutFile;

        ++mNewSize;
        mCacheRawDataSize += pReference->memorySize();

        mLock.unlock();
        return true;
    }

    bool Outputs::SubSet::getOutput(const NextCash::Hash &pTransactionID,
      uint32_t pIndex, uint8_t pFlags, uint32_t pSpentBlockHeight, Output &pOutput,
      uint32_t &pPreviousBlockHeight)
    {
        mLock.lock();

        bool result = false;
        SubSetIterator item = mCache.find(pTransactionID);
        if(item == mCache.end() && pull(pTransactionID))
            item = mCache.find(pTransactionID);

        while(item != mCache.end() && (*item)->getHash() == pTransactionID)
        {
            if(!((TransactionReference *)*item)->markedRemove())
            {
                pPreviousBlockHeight = ((TransactionReference *)*item)->blockHeight;

                if(pFlags & MARK_SPENT)
                    result =
                      ((TransactionReference *)*item)->spendInternal(pSpentBlockHeight, pIndex) ||
                      !(pFlags & REQUIRE_UNSPENT);
                else if(pFlags & REQUIRE_UNSPENT)
                    result = ((TransactionReference *)*item)->isUnspent(pIndex);

                if(result)
                {
                    NextCash::String filePathName;
                    filePathName.writeFormatted("%s%s%04x.data", mFilePath,
                      NextCash::PATH_SEPARATOR, mID);
                    NextCash::FileInputStream *dataInFile =
                      new NextCash::FileInputStream(filePathName);
                    result = dataInFile->isValid() &&
                      ((TransactionReference *)*item)->readOutput(dataInFile, pIndex, pOutput);
                    delete dataInFile;
                }

                break;
            }

            ++item;
        }

        mLock.unlock();
        return result;
    }

    bool Outputs::SubSet::isUnspent(const NextCash::Hash &pTransactionID, uint32_t pIndex)
    {
        mLock.lock();

        bool result = false;
        SubSetIterator item = mCache.find(pTransactionID);
        if(item == mCache.end() && pull(pTransactionID))
            item = mCache.find(pTransactionID);

        while(item != mCache.end() && (*item)->getHash() == pTransactionID)
        {
            if(!((TransactionReference *)*item)->markedRemove())
            {
                result = ((TransactionReference *)*item)->isUnspent(pIndex);
                break;
            }

            ++item;
        }

        mLock.unlock();
        return result;
    }

    uint8_t Outputs::SubSet::unspentStatus(const NextCash::Hash &pTransactionID, uint32_t pIndex)
    {
        mLock.lock();

        uint8_t result = 0;
        SubSetIterator item = mCache.find(pTransactionID);
        if(item == mCache.end() && pull(pTransactionID))
            item = mCache.find(pTransactionID);

        while(item != mCache.end() && (*item)->getHash() == pTransactionID)
        {
            if(!((TransactionReference *)*item)->markedRemove())
            {
                result |= UNSPENT_STATUS_EXISTS;
                if(((TransactionReference *)*item)->isUnspent(pIndex))
                    result |= UNSPENT_STATUS_UNSPENT;
                break;
            }

            ++item;
        }

        mLock.unlock();
        return result;
    }

    bool Outputs::SubSet::spend(const NextCash::Hash &pTransactionID, uint32_t pIndex,
      uint32_t pSpentBlockHeight, uint32_t &pPreviousBlockHeight, bool pRequireUnspent)
    {
        mLock.lock();

        bool result = false;
        SubSetIterator item = mCache.find(pTransactionID);
        if(item == mCache.end() && pull(pTransactionID))
            item = mCache.find(pTransactionID);

        while(item != mCache.end() && (*item)->getHash() == pTransactionID)
        {
            if(!((TransactionReference *)*item)->markedRemove())
            {
                pPreviousBlockHeight = ((TransactionReference *)*item)->blockHeight;
                result =
                  ((TransactionReference *)*item)->spendInternal(pSpentBlockHeight, pIndex) ||
                  !pRequireUnspent;
                break;
            }

            ++item;
        }

        mLock.unlock();
        return result;
    }

    bool Outputs::SubSet::hasUnspent(const NextCash::Hash &pTransactionID,
      uint32_t pSpentBlockHeight)
    {
        mLock.lock();

        bool result = false;
        SubSetIterator item = mCache.find(pTransactionID);
        while(item != mCache.end() && (*item)->getHash() == pTransactionID)
        {
            if(!((TransactionReference *)*item)->markedRemove() &&
              (pSpentBlockHeight == 0xffffffff || pSpentBlockHeight !=
              ((TransactionReference *)*item)->blockHeight))
            {
                result = ((TransactionReference *)*item)->hasUnspent();
                break;
            }

            ++item;
        }

        mLock.unlock();
        return result;
    }

    bool Outputs::SubSet::checkDuplicate(const NextCash::Hash &pTransactionID,
      unsigned int pBlockHeight, const NextCash::Hash &pBlockHash)
    {
        mLock.lock();

        // Force pull because we know there is already one in the cache since this is called during
        //   block validation after the blocks transactions have already been added to the output set.
        pull(pTransactionID);

        bool result = true;
        SubSetIterator item = mCache.find(pTransactionID);
        while(item != mCache.end() && (*item)->getHash() == pTransactionID)
        {
            if(!((TransactionReference *)*item)->markedRemove() &&
              ((TransactionReference *)*item)->blockHeight != pBlockHeight &&
              ((TransactionReference *)*item)->hasUnspent())
            {
                bool exceptionFound = false;
                for(unsigned int i = 0; i < BIP0030_HASH_COUNT; ++i)
                    if(BIP0030_HEIGHTS[i] == pBlockHeight && BIP0030_HASHES[i] == pBlockHash)
                        exceptionFound = true;
                if(exceptionFound)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                      "BIP-0030 Exception for duplicate transaction ID in block %d : %s",
                      ((TransactionReference *)*item)->blockHeight, pTransactionID.hex().text());
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                      "Matching transaction hash from block %d has unspent outputs : %s",
                      ((TransactionReference *)*item)->blockHeight, pTransactionID.hex().text());
                    result = false;
                    break;
                }
            }

            ++item;
        }

        mLock.unlock();
        return result;
    }

    bool Outputs::SubSet::exists(const NextCash::Hash &pTransactionID, bool pPullIfNeeded)
    {
        mLock.lock();

        bool result = false;
        SubSetIterator item = mCache.find(pTransactionID);
        if(item == mCache.end() && pPullIfNeeded && pull(pTransactionID))
            item = mCache.find(pTransactionID);

        while(item != mCache.end() && (*item)->getHash() == pTransactionID)
        {
            if(!((TransactionReference *)*item)->markedRemove())
            {
                result = true;
                break;
            }

            ++item;
        }

        mLock.unlock();
        return result;
    }

    bool Outputs::SubSet::pull(const NextCash::Hash &pTransactionID,
      TransactionReference *pMatching)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_PULL_ID, PROFILER_OUTPUTS_PULL_NAME), true);
#endif
        if(mIndexSize == 0)
            return false;

        int compare;
        NextCash::stream_size dataOffset;
        NextCash::Hash hash(TRANSACTION_HASH_SIZE);
        NextCash::stream_size first = 0, last = (mIndexSize - 1) * sizeof(NextCash::stream_size),
          begin, end, current;
        NextCash::String filePathName;
        filePathName.writeFormatted("%s%s%04x.index", mFilePath, NextCash::PATH_SEPARATOR, mID);
        NextCash::FileInputStream indexFile(filePathName);
        filePathName.writeFormatted("%s%s%04x.data", mFilePath, NextCash::PATH_SEPARATOR, mID);
        NextCash::FileInputStream dataFile(filePathName);

        if(!indexFile.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to open index file in pull");
            return false;
        }

        if(!dataFile.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to open index file in pull");
            return false;
        }

        if(mSamples != NULL)
        {
            if(!findSample(pTransactionID, &indexFile, &dataFile, begin, end))
                return false; // Failed

            if(begin == NextCash::INVALID_STREAM_SIZE)
                return false; // Not within subset
        }
        else // Not enough items for a full sample set
        {
            // Setup index binary search on all indices
            begin = first;
            end = last;

            // Check first item
            indexFile.setReadOffset(begin);
            indexFile.read(&dataOffset, sizeof(NextCash::stream_size));
            dataFile.setReadOffset(dataOffset);
            if(!hash.read(&dataFile))
                return false;

            compare = hash.compare(pTransactionID);
            if(compare > 0)
                return false; // Lookup is before first item
            else if(compare == 0)
                end = begin;
            else if(mIndexSize > 1)
            {
                // Check last item
                indexFile.setReadOffset(end);
                indexFile.read(&dataOffset, sizeof(NextCash::stream_size));
                dataFile.setReadOffset(dataOffset);
                if(!hash.read(&dataFile))
                    return false;

                compare = hash.compare(pTransactionID);
                if(compare < 0)
                    return false; // Lookup is after last item
                else if(compare == 0)
                    begin = end;
            }
            else
                return false; // Not within subset
        }

        if(begin == end)
            current = begin; // Lookup matches a sample
        else
        {
            // Binary search the file indices
            while(true)
            {
                // Break the set in two halves (set current to the middle)
                current = (end - begin) / 2;
                current -= current % sizeof(NextCash::stream_size);
                if(current == 0) // Begin and end are next to each other and have already been checked
                    return false;
                current += begin;

                // Read the middle item
                indexFile.setReadOffset(current);
                indexFile.read(&dataOffset, sizeof(NextCash::stream_size));
                dataFile.setReadOffset(dataOffset);
                if(!hash.read(&dataFile))
                    return false;

                // Determine which half the desired item is in
                compare = hash.compare(pTransactionID);
                if(compare < 0)
                    begin = current;
                else if(compare > 0)
                    end = current;
                else
                    break;
            }
        }

        // Match likely found
        // Loop backwards to find the first matching
        while(current > first)
        {
            current -= sizeof(NextCash::stream_size);
            indexFile.setReadOffset(current);
            indexFile.read(&dataOffset, sizeof(NextCash::stream_size));
            dataFile.setReadOffset(dataOffset);
            if(!hash.read(&dataFile))
                return false;

            if(hash != pTransactionID)
            {
                current += sizeof(NextCash::stream_size);
                break;
            }
        }

        // Read in all matching
        bool result = false;
        TransactionReference *next;
        while(current <= last)
        {
            indexFile.setReadOffset(current);
            indexFile.read(&dataOffset, sizeof(NextCash::stream_size));
            dataFile.setReadOffset(dataOffset);
            if(!hash.read(&dataFile))
                return result;

            if(hash != pTransactionID)
                break;

            next = new TransactionReference(hash);
            if(!next->readData(&dataFile))
            {
                delete next;
                break;
            }

            if((pMatching == NULL || pMatching->valueEquals(next)) && mCache.insert(next, true))
            {
                mCacheRawDataSize += next->memorySize();
                result = true;
            }
            else
                delete next;

            current += sizeof(NextCash::stream_size);
        }

        return result;
    }

    void Outputs::SubSet::loadSamples(NextCash::InputStream *pIndexFile)
    {
        NextCash::stream_size delta = mIndexSize / OUTPUTS_SAMPLE_COUNT;
        if(delta < 4)
        {
            if(mSamples != NULL)
                delete[] mSamples;
            mSamples = NULL;
            return;
        }

        if(mSamples == NULL)
            mSamples = new SampleEntry[OUTPUTS_SAMPLE_COUNT];

        // Load samples
        NextCash::stream_size offset = 0;
        SampleEntry *sample = mSamples;
        for(unsigned int i = 0; i < OUTPUTS_SAMPLE_COUNT - 1; ++i)
        {
            sample->hash.clear();
            sample->offset = offset;
            offset += (delta * sizeof(NextCash::stream_size));
            ++sample;
        }

        // Load last sample
        sample->hash.clear();
        sample->offset = pIndexFile->length() - sizeof(NextCash::stream_size);
    }

    bool Outputs::SubSet::findSample(const NextCash::Hash &pHash,
      NextCash::InputStream *pIndexFile, NextCash::InputStream *pDataFile,
      NextCash::stream_size &pBegin, NextCash::stream_size &pEnd)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_OUTPUTS_SAMPLE_ID, PROFILER_OUTPUTS_SAMPLE_NAME), true);
#endif
        // Check first entry
        SampleEntry *sample = mSamples;
        if(!sample->load(pIndexFile, pDataFile))
            return false;
        int compare = sample->hash.compare(pHash);
        if(compare > 0)
        {
            // Hash is before the first entry of subset
            pBegin = NextCash::INVALID_STREAM_SIZE;
            pEnd   = NextCash::INVALID_STREAM_SIZE;
            return true;
        }
        else if(compare == 0)
        {
            // Hash is the first entry of subset
            pBegin = sample->offset;
            pEnd   = sample->offset;
            return true;
        }
        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
          // "First : %s", mSamples[0].hash.hex().text());

        // Check last entry
        sample = mSamples + (OUTPUTS_SAMPLE_COUNT - 1);
        if(!sample->load(pIndexFile, pDataFile))
            return false;
        compare = sample->hash.compare(pHash);
        if(compare < 0)
        {
            // Hash is after the last entry of subset
            pBegin = NextCash::INVALID_STREAM_SIZE;
            pEnd   = NextCash::INVALID_STREAM_SIZE;
            return true;
        }
        else if(compare == 0)
        {
            // Hash is the after last entry of subset
            pBegin = sample->offset;
            pEnd   = sample->offset;
            return true;
        }
        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
          // "Last : %s", mSamples[OUTPUTS_SAMPLE_COUNT - 1].hash.hex().text());

        // Binary search the samples
        unsigned int sampleBegin = 0;
        unsigned int sampleEnd = OUTPUTS_SAMPLE_COUNT - 1;
        unsigned int sampleCurrent;
        bool done = false;

        while(!done)
        {
            sampleCurrent = (sampleBegin + sampleEnd) / 2;
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              // "Sample : %s", mSamples[sampleCurrent].hash.hex().text());

            if(sampleCurrent == sampleBegin || sampleCurrent == sampleEnd)
                done = true;

            sample = mSamples + sampleCurrent;
            if(!sample->load(pIndexFile, pDataFile))
                return false;

            // Determine which half the desired item is in
            compare = sample->hash.compare(pHash);
            if(compare < 0)
                sampleBegin = sampleCurrent;
            else if(compare > 0)
                sampleEnd = sampleCurrent;
            else
            {
                sampleBegin = sampleCurrent;
                sampleEnd = sampleCurrent;
                break;
            }
        }

        // Setup index binary search on sample subset of indices
        pBegin = mSamples[sampleBegin].offset;
        pEnd = mSamples[sampleEnd].offset;
        return true;
    }

    bool Outputs::SubSet::loadCache(unsigned int &pLoadedCount)
    {
        pLoadedCount = 0;

        mCache.clear();
        mCacheRawDataSize = 0UL;

        // Open cache file
        NextCash::String filePathName;
        filePathName.writeFormatted("%s%s%04x.cache", mFilePath, NextCash::PATH_SEPARATOR, mID);
        NextCash::FileInputStream *cacheFile = new NextCash::FileInputStream(filePathName);

        if(!cacheFile->isValid())
        {
            delete cacheFile;
            return true; // Assume empty file
        }

        bool success = true;
        TransactionReference *next;
        NextCash::Hash hash(TRANSACTION_HASH_SIZE);
        cacheFile->setReadOffset(0);
        while(cacheFile->remaining())
        {
            // Read data from cache file
            next = new TransactionReference();

            // Read data offset from cache file
            next->setDataOffset(cacheFile->readUnsignedLong());

            next->cacheFlags = cacheFile->readByte();

            // Read hash from cache file
            if(!hash.read(cacheFile))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to read subset cache item hash");
                delete next;
                success = false;
                break;
            }

            next->setHash(hash);

            if(!next->read(cacheFile))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to load/read subset cache item : %s", hash.hex().text());
                delete next;
                success = false;
                break;
            }

            if(!mCache.insert(next, true))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to load/insert subset cache item : %s", hash.hex().text());
                delete next;
            }
            else
            {
                ++pLoadedCount;
                if(next->isNew())
                    ++mNewSize;
                mCacheRawDataSize += next->memorySize();
            }
        }

        delete cacheFile;
        return success;
    }

    bool Outputs::SubSet::saveCache(unsigned int &pSavedCount)
    {
        pSavedCount = 0;

        // Open cache file
        NextCash::String filePathName;
        filePathName.writeFormatted("%s%s%04x.cache", mFilePath, NextCash::PATH_SEPARATOR, mID);
        NextCash::FileOutputStream *cacheFile = new NextCash::FileOutputStream(filePathName, true);

        if(!cacheFile->isValid())
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to open subset cache file %04x for writing : %s", mID, filePathName.text());
            delete cacheFile;
            return false;
        }

        for(SubSetIterator item = mCache.begin(); item != mCache.end(); ++item)
        {
            cacheFile->writeUnsignedLong(((TransactionReference *)*item)->dataOffset());
            cacheFile->writeByte(((TransactionReference *)*item)->cacheFlags);
            (*item)->getHash().write(cacheFile);
            ((TransactionReference *)*item)->write(cacheFile);
            ++pSavedCount;
        }

        if(pSavedCount != mCache.size())
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
              "Subset cache size doesn't match count %d != %d", mCache.size(), pSavedCount);

        delete cacheFile;
        return true;
    }

    // Insert sorted, oldest first
    inline void insertOldest(TransactionReference *pItem,
      std::vector<TransactionReference *> &pList, unsigned int pMaxCount)
    {
        if(pList.size() == 0)
        {
            // Add as first item
            pList.push_back(pItem);
            return;
        }

        if((*--pList.end())->compareAge(pItem) < 0)
        {
            if(pList.size() < pMaxCount)
                pList.push_back(pItem); // Add as last item
            return;
        }

        // Insert sorted
        bool inserted = false;
        for(std::vector<TransactionReference *>::iterator item = pList.begin();
          item != pList.end(); ++item)
            if(((TransactionReference *)*item)->compareAge(pItem) > 0)
            {
                inserted = true;
                pList.insert(item, pItem);
                break;
            }

        if(!inserted)
            pList.push_back(pItem);

        if(pList.size() > pMaxCount)
            pList.pop_back();
    }

    bool Outputs::SubSet::load(const char *pFilePath, unsigned int pID, unsigned int &pLoadedCount)
    {
        mLock.lock();

        NextCash::String filePathName;
        bool created = false;

        mFilePath = pFilePath;
        mID = pID;

        // Open index file
        filePathName.writeFormatted("%s%s%04x.index", mFilePath, NextCash::PATH_SEPARATOR, mID);
        if(!fileExists(filePathName))
        {
            // Create index file
            NextCash::FileOutputStream indexOutFile(filePathName, true);
            created = true;
        }
        NextCash::FileInputStream indexFile(filePathName);
        indexFile.setReadOffset(0);

        if(!indexFile.isValid())
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to open index file : %s", filePathName.text());
            mLock.unlock();
            return false;
        }

        mIndexSize = indexFile.length() / sizeof(NextCash::stream_size);
        mNewSize = 0;

        // Open data file
        if(created)
        {
            filePathName.writeFormatted("%s%s%04x.data", mFilePath,
              NextCash::PATH_SEPARATOR, mID);
            NextCash::FileOutputStream dataOutFile(filePathName, true); // Create data file
        }

        bool success = true;
        loadSamples(&indexFile);
        if(!loadCache(pLoadedCount))
            success = false;

        mLock.unlock();
        return success;
    }

    //TODO This operation is expensive. Try to find a better algorithm.
    void Outputs::SubSet::markOld(NextCash::stream_size pDataSize)
    {
        if(pDataSize == 0)
        {
            for(SubSetIterator item = mCache.begin(); item != mCache.end(); ++item)
                ((TransactionReference *)*item)->setOld();
            return;
        }

        NextCash::stream_size currentSize = cacheDataSize();
        if(currentSize <= pDataSize)
            return;

        double targetPercent = ((double)currentSize - ((double)pDataSize * 0.9)) /
          (double)currentSize;
        unsigned int targetCount = (unsigned int)((double)mCache.size() * targetPercent);
        std::vector<TransactionReference *> oldestList;
        if(targetCount == 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
              "Set %d has no items to mark old", mID);
            return;
        }

        // Build list of oldest items.
        for(SubSetIterator item = mCache.begin(); item != mCache.end(); ++item)
            insertOldest((TransactionReference *)*item, oldestList, targetCount);

        // Remove all items below age of newest item in old list.
        if(oldestList.size() == 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Set %d has mark old list is empty", mID);
            return;
        }

        unsigned int markedCount = 0;
        TransactionReference *cutoff = oldestList.back();
        NextCash::stream_size markedSize = 0;
        for(SubSetIterator item = mCache.begin(); item != mCache.end(); ++item)
        {
            if(((TransactionReference *)*item)->isOld())
            {
                ++markedCount;
                markedSize += ((TransactionReference *)*item)->memorySize() + staticCacheItemSize;
                if(currentSize - markedSize < pDataSize)
                    break;
            }
            else if(((TransactionReference *)*item)->compareAge(cutoff) < 0)
            {
                ((TransactionReference *)*item)->setOld();
                ++markedCount;
                markedSize += ((TransactionReference *)*item)->memorySize() + staticCacheItemSize;
                if(currentSize - markedSize < pDataSize)
                    break;
            }
        }

        if(currentSize - markedSize > pDataSize)
        {
            // Mark every other item as old.
            bool markThisOld = false;
            for(SubSetIterator item = mCache.begin(); item != mCache.end(); ++item)
            {
                if(markThisOld && !((TransactionReference *)*item)->isOld())
                {
                    ++markedCount;
                    ((TransactionReference *)*item)->setOld();
                    markedSize += ((TransactionReference *)*item)->memorySize() +
                      staticCacheItemSize;
                    if(currentSize - markedSize < pDataSize)
                        break;
                    markThisOld = false;
                }
                else
                    markThisOld = true;
            }
        }

        if(currentSize - markedSize > pDataSize)
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
              "Set %d failed to mark enough old. Marked %d/%d items (%d/%d)", mID, markedCount,
              mCache.size(), markedSize, currentSize);
    }

    bool Outputs::SubSet::trimCache(NextCash::stream_size pMaxCacheDataSize,
      bool pAutoTrimCache)
    {
        // Mark items as old to keep cache data size under max.
        if(pAutoTrimCache)
            markOld(pMaxCacheDataSize);

        // Remove old items from the cache.
        for(SubSetIterator item = mCache.begin(); item != mCache.end();)
        {
            if(((TransactionReference *)*item)->isOld())
            {
                mCacheRawDataSize -= ((TransactionReference *)*item)->memorySize();
                item = mCache.eraseDelete(item);
            }
            else
                ++item;
        }

        mCache.shrink();
        return true;
    }

    bool Outputs::SubSet::save(NextCash::stream_size pMaxCacheDataSize, bool pAutoTrimCache,
      unsigned int &pSavedCount)
    {
        mLock.lock();

        if(mCache.size() == 0)
        {
            mLock.unlock();
            return true;
        }

        // Open data file as an output stream
        NextCash::String filePathName;
        filePathName.writeFormatted("%s%s%04x.data", mFilePath, NextCash::PATH_SEPARATOR, mID);
        NextCash::FileOutputStream *dataOutFile = new NextCash::FileOutputStream(filePathName);
        SubSetIterator item;
        uint64_t newCount = 0;
        bool indexNeedsUpdated = false;

        // Write all cached/modified data to file.
        for(item = mCache.begin(); item != mCache.end();)
        {
            if(((TransactionReference *)*item)->markedRemove())
            {
                if(!((TransactionReference *)*item)->isNew())
                {
                    indexNeedsUpdated = true;
                    ++item;
                }
                else
                {
                    mCacheRawDataSize -= ((TransactionReference *)*item)->memorySize();
                    item = mCache.eraseDelete(item);
                }
            }
            else
            {
                if(((TransactionReference *)*item)->isModified())
                    ((TransactionReference *)*item)->writeModifiedData(dataOutFile);
                if(((TransactionReference *)*item)->isNew())
                {
                    ++newCount;
                    indexNeedsUpdated = true;
                }

                ++item;
            }
        }

        delete dataOutFile;

        if(!indexNeedsUpdated)
        {
            bool success = trimCache(pMaxCacheDataSize, pAutoTrimCache);
            if(success)
                success = saveCache(pSavedCount);

            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              // "Set %d save index not updated", mID);
            mLock.unlock();
            return success;
        }

        // Read entire index file
        filePathName.writeFormatted("%s%s%04x.index", mFilePath, NextCash::PATH_SEPARATOR,
          mID);
        NextCash::FileInputStream *indexFile = new NextCash::FileInputStream(filePathName);
        NextCash::stream_size previousSize = indexFile->length() / sizeof(NextCash::stream_size);
        NextCash::DistributedVector<NextCash::stream_size> indices(OUTPUTS_SET_COUNT);
        NextCash::DistributedVector<NextCash::Hash> hashes(OUTPUTS_SET_COUNT);
        unsigned int indicesPerSet = (previousSize / OUTPUTS_SET_COUNT) + 1;
        unsigned int readIndices = 0;
        std::vector<NextCash::stream_size> *indiceSet;
        std::vector<NextCash::Hash> *hashSet;
        unsigned int setOffset = 0;
        NextCash::stream_size reserveSize = previousSize + mCache.size();

        if(reserveSize < OUTPUTS_SET_COUNT * 32)
            reserveSize = OUTPUTS_SET_COUNT * 32;

        indices.reserve(reserveSize);
        hashes.reserve(reserveSize);
        indexFile->setReadOffset(0);
        while(indexFile->remaining())
        {
            if(previousSize - readIndices < indicesPerSet)
                indicesPerSet = previousSize - readIndices;

            // Read set of indices
            indiceSet = indices.dataSet(setOffset);
            indiceSet->resize(indicesPerSet);
            indexFile->read(indiceSet->data(), indicesPerSet * sizeof(NextCash::stream_size));

            // Allocate empty hashes
            hashSet = hashes.dataSet(setOffset);
            hashSet->resize(indicesPerSet);

            readIndices += indicesPerSet;
            ++setOffset;
        }

        delete indexFile;
        indices.refresh();
        hashes.refresh();

        // Update indices
        NextCash::DistributedVector<NextCash::Hash>::Iterator hash;
        NextCash::DistributedVector<NextCash::stream_size>::Iterator index;
        int compare;
        bool found;
        Time lastReport = getTime();
        unsigned int cacheOffset = 0, initialCacheSize = mCache.size();
        unsigned int begin, end, current;
        unsigned int readHeadersCount = 0;
        NextCash::stream_size dataOffset;
        bool success = true;

        filePathName.writeFormatted("%s%s%04x.data", mFilePath, NextCash::PATH_SEPARATOR,
          mID);
        NextCash::FileInputStream dataFile(filePathName);

        for(item = mCache.begin(); item != mCache.end() && success; ++cacheOffset)
        {
            if(getTime() - lastReport >= 10)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Set %d save index update is %2d%% Complete", mID,
                  (int)(((float)cacheOffset / (float)initialCacheSize) * 100.0f));

                lastReport = getTime();
            }

            if(((TransactionReference *)*item)->markedRemove())
            {
                // Check that it was previously added to the index and data file.
                // Otherwise it isn't in current indices and doesn't need removed.
                if(!((TransactionReference *)*item)->isNew())
                {
                    // Remove from indices.
                    // They aren't sorted by file offset so in this scenario a linear search is
                    //   required since not all hashes are read and reading them for a binary
                    //   search would presumably be more expensive since it requires reading hashes.
                    found = false;
                    dataOffset = ((TransactionReference *)*item)->dataOffset();
                    hash = hashes.begin();
                    for(index = indices.begin(); index != indices.end(); ++index, ++hash)
                        if(*index == dataOffset)
                        {
                            indices.erase(index);
                            hashes.erase(hash);
                            found = true;
                            break;
                        }

                    if(!found)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed to find index to remove for file offset %d : %s",
                          dataOffset, (*item)->getHash().hex().text());
                        success = false;
                        break;
                    }
                }

                mCacheRawDataSize -= ((TransactionReference *)*item)->memorySize();
                item = mCache.eraseDelete(item);
            }
            else if(((TransactionReference *)*item)->isNew())
            {
                // For new items perform insert sort into existing indices.
                // This costs more processor time to do the insert for every new item.
                // This saves file reads by not requiring a read of every existing indice like a
                //   merge sort would.
                if(indices.size () == 0)
                {
                    // Add as only item
                    indices.push_back(((TransactionReference *)*item)->dataOffset());
                    hashes.push_back((*item)->getHash());
                    ((TransactionReference *)*item)->clearNew();
                    ++item;
                    continue;
                }

                // Check first entry
                hash = hashes.begin();
                index = indices.begin();
                if(hash->isEmpty())
                {
                    // Fetch data
                    if(!pullHash(&dataFile, *index, *hash))
                    {
                        success = false;
                        break;
                    }
                    ++readHeadersCount;
                }

                compare = (*item)->getHash().compare(*hash);
                if(compare <= 0)
                {
                    // Insert as first
                    indices.insert(index, ((TransactionReference *)*item)->dataOffset());
                    hashes.insert(hash, (*item)->getHash());
                    ((TransactionReference *)*item)->clearNew();
                    ++item;
                    continue;
                }

                // Check last entry
                hash = hashes.end() - 1;
                index = indices.end() - 1;
                if(hash->isEmpty())
                {
                    // Fetch data
                    if(!pullHash(&dataFile, *index, *hash))
                    {
                        success = false;
                        break;
                    }
                    ++readHeadersCount;
                }

                compare = (*item)->getHash().compare(*hash);
                if(compare >= 0)
                {
                    // Add to end
                    indices.push_back(((TransactionReference *)*item)->dataOffset());
                    hashes.push_back((*item)->getHash());
                    ((TransactionReference *)*item)->clearNew();
                    ++item;
                    continue;
                }

                // Binary insert sort
                begin = 0;
                end = indices.size() - 1;
                while(true)
                {
                    // Divide data set in half
                    current = (begin + end) / 2;

                    // Pull "current" entry (if it isn't already)
                    hash = hashes.begin() + current;
                    index = indices.begin() + current;
                    if(hash->isEmpty())
                    {
                        // Fetch data
                        if(!pullHash(&dataFile, *index, *hash))
                        {
                            success = false;
                            break;
                        }
                        ++readHeadersCount;
                    }

                    compare = (*item)->getHash().compare(*hash);
                    if(current == begin || compare == 0)
                    {
                        if(compare < 0)
                        {
                            // Insert before current
                            indices.insert(index, ((TransactionReference *)*item)->dataOffset());
                            hashes.insert(hash, (*item)->getHash());
                            ((TransactionReference *)*item)->clearNew();
                            break;
                        }
                        else //if(compare >= 0)
                        {
                            // Insert after current
                            ++index;
                            ++hash;
                            indices.insert(index, ((TransactionReference *)*item)->dataOffset());
                            hashes.insert(hash, (*item)->getHash());
                            ((TransactionReference *)*item)->clearNew();
                            break;
                        }
                    }

                    if(compare > 0)
                        begin = current;
                    else //if(compare < 0)
                        end = current;
                }

                ++item;

            }
            else
                ++item;
        }

        if(success)
        {
            // Open index file as an output stream
            filePathName.writeFormatted("%s%s%04x.index", mFilePath,
              NextCash::PATH_SEPARATOR, mID);
            NextCash::FileOutputStream *indexOutFile = new NextCash::FileOutputStream(filePathName,
              true);

            // Write the new index
            for(setOffset = 0; setOffset < OUTPUTS_SET_COUNT; ++setOffset)
            {
                // Write set of indices
                indiceSet = indices.dataSet(setOffset);
                indexOutFile->write(indiceSet->data(), indiceSet->size() *
                  sizeof(NextCash::stream_size));
            }

            // Update size
            mIndexSize = indexOutFile->length() / sizeof(NextCash::stream_size);
            mNewSize = 0;

            delete indexOutFile;

            // Open index file
            filePathName.writeFormatted("%s%s%04x.index", mFilePath, NextCash::PATH_SEPARATOR,
              mID);
            NextCash::FileInputStream indexFile(filePathName);

            // Reload samples
            loadSamples(&indexFile);

            success = trimCache(pMaxCacheDataSize, pAutoTrimCache);
            if(success)
                success = saveCache(pSavedCount);
        }

        mLock.unlock();
        return success;
    }

    bool Outputs::SubSet::defragment()
    {
        // Open current index file.
        // Create new temp index file.
        // Open current data file.
        // Create new temp data file.
        // Parse through index file.
        //   Pull each associated item from the current data file and append it to the temp data
        //     file.
        //   Append new data offset to the temp index file.
        // Remove current files and replace with temp files.
        return false;
    }

    bool Outputs::test()
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "------------- Starting Outputs Tests -------------");

        bool success = true;
        NextCash::Hash hash(32);
        TransactionReference *data;
        NextCash::Digest digest(NextCash::Digest::SHA256);
        Outputs::Iterator found;
        Transaction transaction;
        bool checkSuccess;
        unsigned int markedOldCount = 0;
        unsigned int removedSize = 0;
        const unsigned int testSize = 50000;
        const unsigned int testSizeLarger = 75000;
        uint32_t dupValue, nonDupValue;
        NextCash::stream_size cacheTargetSize = 5000000;

        NextCash::removeDirectory("test_outputs");

        if(success)
        {
            Outputs testOutputs;
            TransactionReference *lowest = NULL, *highest = NULL;
            NextCash::Hash lowestHash, highestHash;

            testOutputs.load("test_outputs", 5000000UL, 5000000UL);
            testOutputs.setTargetCacheSize(cacheTargetSize);

            for(unsigned int i = 0; i < testSize; ++i)
            {
                // Calculate hash
                digest.initialize();
                digest.writeUnsignedInt(i);
                digest.writeUnsignedInt((i % 10) + 1);
                digest.getResult(&hash);

                // Create new value
                data = new TransactionReference(hash, i == 0, i, (i % 10) + 1);

                if(lowest == NULL || lowestHash > hash)
                {
                    lowestHash = hash;
                    lowest = data;
                }

                if(highest == NULL || highestHash < hash)
                {
                    highestHash = hash;
                    highest = data;
                }

                while(transaction.outputs.size() < data->outputCount())
                    transaction.outputs.emplace_back();
                while(transaction.outputs.size() > data->outputCount())
                    transaction.outputs.pop_back();

                // Add to set
                if(!testOutputs.insert(data, transaction))
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed to insert : %s", data->getHash().hex().text());
                    success = false;
                }
            }

            // Calculate hash
            digest.initialize();
            digest.writeUnsignedInt((testSize / 2) + 2);
            digest.writeUnsignedInt((((testSize / 2) + 2) % 10) + 1);
            digest.getResult(&hash);

            // Create duplicate value
            // Make sure to use a different height to prevent dup check from rejecting insert.
            data = new TransactionReference(hash, false, (testSize / 2) + 2,
              (((testSize / 2) + 2) % 10) + 1);
            dupValue = (testSize / 2) + 2;
            nonDupValue = dupValue;

            while(transaction.outputs.size() < data->outputCount())
                transaction.outputs.emplace_back();
            while(transaction.outputs.size() > data->outputCount())
                transaction.outputs.pop_back();

            // Add to set
            if(!testOutputs.insert(data, transaction))
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed not insert duplicate value");
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to not insert duplicate value : %s", data->getHash().hex().text());
                success = false;
            }

            // Make sure to use a different height to prevent dup check from rejecting insert.
            data->blockHeight = (testSize / 2) + 3;
            if(testOutputs.insert(data, transaction))
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed insert duplicate sort");
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to insert duplicate sort : %s", data->getHash().hex().text());
                success = false;
            }

            if(testOutputs.size() == testSize + 1)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed size");
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed size : %d != %d", testOutputs.size(), testSize + 1);
                success = false;
            }

            found = testOutputs.get(lowestHash);
            if(!found)
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed lowest : not found : %s", lowestHash.hex().text());
                success = false;
            }
            else if(((TransactionReference *)(*found))->blockHeight == lowest->blockHeight)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed lowest : %d - %s", ((TransactionReference *)(*found))->blockHeight,
                  found.hash().hex().text());
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed lowest : wrong entry : %d - %s",
                  ((TransactionReference *)(*found))->blockHeight, found.hash().hex().text());
                success = false;
            }

            found = testOutputs.get(highestHash);
            if(!found)
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed highest : not found : %s", highestHash.hex().text());
                success = false;
            }
            else if(((TransactionReference *)(*found))->blockHeight == highest->blockHeight)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed highest : %d - %s", ((TransactionReference *)(*found))->blockHeight,
                  found.hash().hex().text());
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed highest : wrong entry : %d - %s",
                  ((TransactionReference *)(*found))->blockHeight, found.hash().hex().text());
                success = false;
            }

            // Check duplicate values
            found = testOutputs.get(hash);
            if(!found)
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed duplicate : not found");
                success = false;
            }
            else
            {
                TransactionReference *firstData = *found;
                if(found.hash() == hash)
                {
                    if(((TransactionReference *)(*found))->blockHeight == dupValue ||
                      ((TransactionReference *)(*found))->blockHeight == nonDupValue ||
                      ((TransactionReference *)(*found))->blockHeight == data->blockHeight)
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                          "Passed duplicate first : %d - %s",
                          ((TransactionReference *)(*found))->blockHeight, found.hash().hex().text());
                    else
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed duplicate first : wrong entry : %d - %s",
                          ((TransactionReference *)(*found))->blockHeight, found.hash().hex().text());
                        success = false;
                    }
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed duplicate first : wrong hash : %s", found.hash().hex().text());
                    success = false;
                }

                ++found;
                if(!found)
                {
                    NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed duplicate second increment failed");
                    success = false;
                }
                else if(*found == firstData)
                {
                    NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed duplicate second not incremented");
                    success = false;
                }
                else
                {
                    NextCash::Log::add(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                      "Passed duplicate second incremented");

                    if(found.hash() == hash)
                    {
                        if(((TransactionReference *)(*found))->blockHeight == dupValue ||
                          ((TransactionReference *)(*found))->blockHeight == nonDupValue ||
                          ((TransactionReference *)(*found))->blockHeight == data->blockHeight)
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                              "Passed duplicate second : %d - %s",
                              ((TransactionReference *)(*found))->blockHeight, found.hash().hex().text());
                        else
                        {
                            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                              "Failed duplicate second : wrong entry : %d - %s",
                              ((TransactionReference *)(*found))->blockHeight, found.hash().hex().text());
                            success = false;
                        }
                    }
                    else
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed duplicate second : wrong hash", found.hash().hex().text());
                        success = false;
                    }
                }
            }

            if(testOutputs.size() == testSize + 1)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed pre-save size : %d", testSize + 1);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed pre-save size : %d != %d", testOutputs.size(), testSize + 1);
                success = false;
            }

            if(!testOutputs.saveFull(4))
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed multi-threaded save");
                success = false;
            }
        }

        if(success)
        {
            Outputs testOutputs;

            testOutputs.load("test_outputs", 5000000UL, 5000000UL);
            testOutputs.setTargetCacheSize(cacheTargetSize);

            if(testOutputs.size() == testSize + 1)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed load size : %d", testSize + 1);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed load size : %d != %d", testOutputs.size(), testSize + 1);
                success = false;
            }

            checkSuccess = true;
            for(unsigned int i = 0; i < testSize; ++i)
            {
                // Calculate hash
                digest.initialize();
                digest.writeUnsignedInt(i);
                digest.writeUnsignedInt((i % 10) + 1);
                digest.getResult(&hash);

                // Create new value
                data = new TransactionReference(hash, i == 0, i, (i % 10) + 1);

                found = testOutputs.get(hash);
                if(!found)
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed load : %d not found", data->blockHeight);
                    checkSuccess = false;
                    success = false;
                    return false;
                }
                else
                {
                    if(found.hash() != hash)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed load : wrong hash : %s", found.hash().hex().text());
                        checkSuccess = false;
                        success = false;
                    }
                    else if(((TransactionReference *)(*found))->blockHeight != data->blockHeight &&
                      ((TransactionReference *)(*found))->blockHeight != dupValue &&
                      ((TransactionReference *)(*found))->blockHeight != nonDupValue)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed load : wrong value : %d - %s",
                          ((TransactionReference *)(*found))->blockHeight, found.hash().hex().text());
                        checkSuccess = false;
                        success = false;
                    }
                }

                delete data;
            }

            if(checkSuccess)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed load check %d lookups", testSize);

            for(unsigned int i = testSize; i < testSizeLarger; ++i)
            {
                // Calculate hash
                digest.initialize();
                digest.writeUnsignedInt(i);
                digest.writeUnsignedInt((i % 10) + 1);
                digest.getResult(&hash);

                // Create new value
                data = new TransactionReference(hash, i == 0, i, (i % 10) + 1);

                while(transaction.outputs.size() < data->outputCount())
                    transaction.outputs.emplace_back();
                while(transaction.outputs.size() > data->outputCount())
                    transaction.outputs.pop_back();

                // Add to set
                if(!testOutputs.insert(data, transaction))
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed to insert : %s", data->getHash().hex().text());
                    success = false;
                }
            }

            checkSuccess = true;
            for(unsigned int i = testSize; i < testSizeLarger; ++i)
            {
                // Calculate hash
                digest.initialize();
                digest.writeUnsignedInt(i);
                digest.writeUnsignedInt((i % 10) + 1);
                digest.getResult(&hash);

                // Create new value
                data = new TransactionReference(hash, i == 0, i, (i % 10) + 1);

                found = testOutputs.get(hash);
                if(!found)
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed load : %d not found", data->blockHeight);
                    checkSuccess = false;
                    success = false;
                }
                else
                {
                    if(found.hash() != hash)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed load : wrong hash : %s", found.hash().hex().text());
                        checkSuccess = false;
                        success = false;
                    }
                    else if(((TransactionReference *)(*found))->blockHeight != data->blockHeight &&
                      ((TransactionReference *)(*found))->blockHeight != dupValue &&
                      ((TransactionReference *)(*found))->blockHeight != nonDupValue)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed load : wrong value : %d - %s",
                          ((TransactionReference *)(*found))->blockHeight, found.hash().hex().text());
                        checkSuccess = false;
                        success = false;
                    }
                }

                delete data;
            }

            if(checkSuccess)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed check %d lookups", testSizeLarger);

            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Original Size : %d", testOutputs.size());

            // Check removing items
            removedSize = testOutputs.size();
            for(unsigned int i = 0; i < testSizeLarger; i += (testSize / 10))
            {
                // Calculate hash
                digest.initialize();
                digest.writeUnsignedInt(i);
                digest.writeUnsignedInt((i % 10) + 1);
                digest.getResult(&hash);

                // Create new value
                data = new TransactionReference(hash, i == 0, i, (i % 10) + 1);

                // Mark to remove
                found = testOutputs.get(hash);
                if(found)
                {
                    (*found)->setRemove();
                    --removedSize;
                }
            }

            // Check marking items as old
            for(unsigned int i = 50; i < testSizeLarger; i += (testSize / 10))
            {
                // Calculate hash
                digest.initialize();
                digest.writeUnsignedInt(i);
                digest.writeUnsignedInt((i % 10) + 1);
                digest.getResult(&hash);

                // Create new value
                data = new TransactionReference(hash, i == 0, i, (i % 10) + 1);

                // Mark old
                found = testOutputs.get(hash);
                if(found && !(*found)->markedRemove())
                {
                    (*found)->setOld();
                    ++markedOldCount;
                }
            }

            // This applies the changes to the marked items.
            testOutputs.saveFull(4, false);

            if(testOutputs.size() == removedSize)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed remove size : %d", removedSize);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed remove size : %d != %d", testOutputs.size(), removedSize);
                success = false;
            }

            if(testOutputs.cacheSize() == testOutputs.size() - markedOldCount)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed old cache size : %d", testOutputs.cacheSize());
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed old cache size : %d != %d", testOutputs.cacheSize(),
                  testOutputs.size() - markedOldCount);
                success = false;
            }
        }

        if(success)
        {
            Outputs testOutputs;

            testOutputs.load("test_outputs", 5000000UL, 5000000UL);

            // Set max cache data size to 75% of current size
            uint64_t cacheMaxSize = (uint64_t)((double)testOutputs.cacheDataSize() * 0.75);
            testOutputs.setTargetCacheSize(cacheMaxSize);

            // Force cache to prune
            testOutputs.saveFull(4);

            if(testOutputs.size() == removedSize)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed prune size : %d", removedSize);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed prune size : %d != %d", testOutputs.size(), removedSize);
                success = false;
            }

            // Pruning isn't exact so allow a 10% over amount
            uint64_t bufferDataSize = (uint64_t)((double)cacheMaxSize * 1.1);

            if(testOutputs.cacheDataSize() < bufferDataSize)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed prune cache data size : %d < %d", testOutputs.cacheDataSize(),
                  bufferDataSize);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed prune cache data size : %d >= %d", testOutputs.cacheDataSize(),
                  bufferDataSize);
                success = false;
            }

            checkSuccess = true;
            for(unsigned int i=0;i<testSize;++i)
            {
                // Calculate hash
                digest.initialize();
                digest.writeUnsignedInt(i);
                digest.writeUnsignedInt((i % 10) + 1);
                digest.getResult(&hash);

                // Create new value
                data = new TransactionReference(hash, i == 0, i, (i % 10) + 1);

                found = testOutputs.get(hash);

                if(i % (testSize/10) == 0)
                {
                    if(found)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed after prune : %d not removed : %s", data->blockHeight,
                          hash.hex().text());
                        checkSuccess = false;
                        success = false;
                        break;
                    }
                }
                else
                {
                    if(!found)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed after prune : %d not found : %s", data->blockHeight,
                          hash.hex().text());
                        checkSuccess = false;
                        success = false;
                        break;
                    }
                    else
                    {
                        if(found.hash() != hash)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::ERROR,
                              BITCOIN_OUTPUTS_LOG_NAME,
                              "Failed after prune : wrong hash : %s", found.hash().hex().text());
                            checkSuccess = false;
                            success = false;
                        }
                        else if(((TransactionReference *)(*found))->blockHeight != data->blockHeight &&
                          ((TransactionReference *)(*found))->blockHeight != dupValue &&
                          ((TransactionReference *)(*found))->blockHeight != nonDupValue)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::ERROR,
                              BITCOIN_OUTPUTS_LOG_NAME, "Failed load : wrong value : %d - %s",
                              ((TransactionReference *)(*found))->blockHeight,
                              found.hash().hex().text());
                            checkSuccess = false;
                            success = false;
                        }
                        // else
                            // NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                              // "Passed load : %d - %s",
                              // ((TransactionReference *)(*found))->blockHeight, found.hash().hex().text());
                    }
                }

                delete data;
            }

            if(checkSuccess)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Passed after prune check %d lookups", testSize);
        }

        return success;
    }
}
