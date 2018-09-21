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
        script.setReadOffset(0);
        NextCash::Log::addFormatted(pLevel, pLogName, "  Script : (%d bytes)",
          script.length());
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
        if(pStream->remaining() < 8)
            return false;

        blockHeight = pStream->readUnsignedInt();
        uint32_t newOutputCount = pStream->readUnsignedInt();
        if(newOutputCount > MAX_OUTPUT_COUNT)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
              "Output Count too high : %d", newOutputCount);
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

        pStream->setReadOffset(mDataOffset + TRANSACTION_HASH_SIZE + (sizeof(uint32_t) * 2) +
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
        pStream->setWriteOffset(mDataOffset + TRANSACTION_HASH_SIZE + (sizeof(uint32_t) * 2));
        pStream->write(mSpentHeights, sizeof(uint32_t) * mOutputCount);

        clearModified();
    }

    void TransactionReference::writeModifiedData(NextCash::OutputStream *pStream)
    {
        // Only spent heights will be modified.
        pStream->setWriteOffset(mDataOffset + TRANSACTION_HASH_SIZE + (sizeof(uint32_t) * 2));
        pStream->write(mSpentHeights, sizeof(uint32_t) * mOutputCount);

        clearModified();
    }

    NextCash::stream_size TransactionReference::size() const
    {
        // Static size :
        //   sizeof(uint32_t) height
        //   sizeof(uint32_t) output count
        //   sizeof(uint32_t *) spent height pointer
        //   sizeof(NextCash::stream_size) data offset
        //   sizeof(uint8_t) flags
        static NextCash::stream_size staticSize = sizeof(uint32_t) + sizeof(uint32_t) +
          sizeof(uint32_t *) + sizeof(NextCash::stream_size) + sizeof(uint8_t);
        // Add spent height array size
        return staticSize + (sizeof(uint32_t) * mOutputCount);
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

    const uint32_t TransactionOutputPool::BIP0030_HEIGHTS[BIP0030_HASH_COUNT] =
      { 91842, 91880 };
    const NextCash::Hash TransactionOutputPool::BIP0030_HASHES[BIP0030_HASH_COUNT] =
    {
        NextCash::Hash("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"),
        NextCash::Hash("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")
    };

    bool TransactionOutputPool::checkDuplicates(const std::vector<Transaction *> &pBlockTransactions,
      unsigned int pBlockHeight, const NextCash::Hash &pBlockHash)
    {
        Iterator reference;
        for(std::vector<Transaction *>::const_iterator transaction = pBlockTransactions.begin();
          transaction != pBlockTransactions.end(); ++transaction)
        {
            if(hasUnspent((*transaction)->hash))
            {
                bool exceptionFound = false;
                for(unsigned int i=0;i<BIP0030_HASH_COUNT;++i)
                    if(BIP0030_HEIGHTS[i] == pBlockHeight && BIP0030_HASHES[i] == pBlockHash)
                        exceptionFound = true;
                if(exceptionFound)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                      "BIP-0030 Exception for duplicate transaction ID at block height %d : transaction %s",
                      ((TransactionReference *)(*reference))->blockHeight,
                      (*transaction)->hash.hex().text());
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Matching transaction output hash from block height %d has unspent outputs : %s",
                      ((TransactionReference *)(*reference))->blockHeight,
                      (*transaction)->hash.hex().text());
                    return false;
                }
            }
        }

        return true;
    }

    bool TransactionOutputPool::checkDuplicate(const Transaction &pTransaction,
      unsigned int pBlockHeight, const NextCash::Hash &pBlockHash)
    {
        // Get references set for transaction ID
        if(hasUnspent(pTransaction.hash, pBlockHeight))
        {
            bool exceptionFound = false;
            for(unsigned int i = 0; i < BIP0030_HASH_COUNT; ++i)
                if(BIP0030_HEIGHTS[i] == pBlockHeight && BIP0030_HASHES[i] == pBlockHash)
                    exceptionFound = true;
            if(exceptionFound)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "BIP-0030 Exception for duplicate transaction ID : transaction %s",
                  pTransaction.hash.hex().text());
            }
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                  "Matching transaction output hash has unspent outputs : %s",
                  pTransaction.hash.hex().text());
                return false;
            }
        }

        return true;
    }

    typename TransactionOutputPool::Iterator TransactionOutputPool::get(
      const NextCash::Hash &pTransactionID)
    {
        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        SubSetIterator result = subSet->get(pTransactionID);
        mLock.readUnlock();
        return Iterator(subSet, result);
    }

    bool TransactionOutputPool::add(const std::vector<Transaction *> &pBlockTransactions,
      unsigned int pBlockHeight)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Outputs Add Block");
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
            transactionReference = new TransactionReference(pBlockHeight,
              (*transaction)->outputs.size());

            valid = true;
            if(!insert((*transaction)->hash, transactionReference, **transaction))
            {
                // Check for matching transaction marked for removal.
                Iterator item = get((*transaction)->hash);

                valid = false;
                while(item && item.hash() == (*transaction)->hash)
                {
                    if(transactionReference->valuesMatch(*item) && (*item)->markedRemove())
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

    bool TransactionOutputPool::revert(const std::vector<Transaction *> &pBlockTransactions,
      unsigned int pHeight)
    {
        if(!mIsValid)
            return false;

        if(mNextBlockHeight != 0 && pHeight != mNextBlockHeight - 1)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't revert non-matching block height %d. Should be %d", pHeight,
              mNextBlockHeight - 1);
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
                    reference = get(input->outpoint.transactionID);
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

                    if(!found)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING,
                          BITCOIN_OUTPUTS_LOG_NAME,
                          "Input transaction not found to revert spend : %s index %d",
                          input->outpoint.transactionID.hex().text(), input->outpoint.index);
                    }
                }

            // Remove transaction
            reference = get((*transaction)->hash);
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
        return success;
    }

    // bool TransactionOutputPool::revertToHeight(unsigned int pBlockHeight)
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

    bool TransactionOutputPool::getOutput(const NextCash::Hash &pTransactionID, uint32_t pIndex,
      uint8_t pFlags, uint32_t pSpentBlockHeight, Output &pOutput, uint32_t &pPreviousBlockHeight)
    {
        if(!mIsValid)
            return false;

        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        bool result = subSet->getOutput(pTransactionID, pIndex, pFlags, pSpentBlockHeight,
          pOutput, pPreviousBlockHeight);
        mLock.readUnlock();
        return result;
    }

    bool TransactionOutputPool::isUnspent(const NextCash::Hash &pTransactionID, uint32_t pIndex)
    {
        if(!mIsValid)
            return false;

        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        bool result = subSet->isUnspent(pTransactionID, pIndex);
        mLock.readUnlock();
        return result;
    }

    bool TransactionOutputPool::spend(const NextCash::Hash &pTransactionID, uint32_t pIndex,
      uint32_t pSpentBlockHeight, uint32_t &pPreviousBlockHeight, bool pRequireUnspent)
    {
        if(!mIsValid)
            return false;

        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        bool result = subSet->spend(pTransactionID, pIndex, pSpentBlockHeight,
          pPreviousBlockHeight, pRequireUnspent);
        mLock.readUnlock();
        return result;
    }

    bool TransactionOutputPool::hasUnspent(const NextCash::Hash &pTransactionID,
      uint32_t pSpentBlockHeight)
    {
        if(!mIsValid)
            return false;

        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        bool result = subSet->hasUnspent(pTransactionID, pSpentBlockHeight);
        mLock.readUnlock();
        return result;
    }

    bool TransactionOutputPool::exists(const NextCash::Hash &pTransactionID)
    {
        if(!mIsValid)
            return false;

        mLock.readLock();
        SubSet *subSet = mSubSets + subSetOffset(pTransactionID);
        bool result = subSet->exists(pTransactionID);
        mLock.readUnlock();
        return result;
    }

    bool TransactionOutputPool::load(const char *pFilePath, NextCash::stream_size pTargetCacheSize,
      NextCash::stream_size pCacheDelta)
    {
        NextCash::String filePath = pFilePath;
        filePath.pathAppend("outputs");

        if(!TransactionOutputPool::load(filePath))
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

    bool TransactionOutputPool::save(unsigned int pThreadCount, bool pAutoTrimCache)
    {
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Saving outputs at height %d (%d K trans) (%d K, %d KB cached)", mNextBlockHeight - 1,
          size() / 1000, cacheSize() / 1000, cacheDataSize() / 1000);

#ifdef SINGLE_THREAD
        if(!TransactionOutputPool::saveSingleThreaded(pAutoTrimCache))
#else
        if(!TransactionOutputPool::saveMultiThreaded(pThreadCount, pAutoTrimCache))
#endif
            return false;

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
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Saved outputs at height %d (%d K trans) (%d K, %d KB cached)", mNextBlockHeight - 1,
          size() / 1000, cacheSize() / 1000, cacheDataSize() / 1000);
        return true;
    }

    bool TransactionOutputPool::insert(const NextCash::Hash &pTransactionID,
      TransactionReference *pValue, Transaction &pTransaction)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Hash Set Insert");
#endif
        mLock.writeLock("Insert");
        bool result = mSubSets[subSetOffset(pTransactionID)].insert(pTransactionID, pValue,
          pTransaction);
        mLock.writeUnlock();
        return result;
    }

    bool TransactionOutputPool::load(const char *pFilePath)
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
        uint32_t lastReport = getTime();
        for(unsigned int i = 0; i < OUTPUTS_SET_COUNT; ++i)
        {
            if(getTime() - lastReport >= 10)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Load is %2d%% Complete", (int)(((float)i / (float)OUTPUTS_SET_COUNT) * 100.0f));
                lastReport = getTime();
            }
            if(!subSet->load(mFilePath, i))
                mIsValid = false;
            ++subSet;
        }

        mLock.writeUnlock();
        return true;
    }

    bool TransactionOutputPool::saveSingleThreaded(bool pAutoTrimCache)
    {
        mLock.writeLock("Save");

        if(!mIsValid)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't save invalid data set");
            mLock.writeUnlock();
            return false;
        }

        SubSet *subSet = mSubSets;
        uint32_t lastReport = getTime();
        NextCash::stream_size maxSetCacheDataSize = 0;
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

            if(!subSet->save(maxSetCacheDataSize, pAutoTrimCache))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed set %d save", subSet->id());
                success = false;
            }

            ++subSet;
        }

        mLock.writeUnlock();
        return success;
    }

    void TransactionOutputPool::saveThreadRun()
    {
        SaveThreadData *data = (SaveThreadData *)NextCash::Thread::getParameter();
        if(data == NULL)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
              "Thread parameter is null. Stopping");
            return;
        }

        SubSet *subSet;
        while(true)
        {
            subSet = data->getNext();
            if(subSet == NULL)
            {
                NextCash::Log::add(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
                  "No more save tasks remaining");
                break;
            }

            if(subSet->save(data->maxSetCacheDataSize, data->autoTrimCache))
                data->markComplete(subSet->id(), true);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed save of set %d", subSet->id());
                data->markComplete(subSet->id(), false);
            }
        }
    }

    bool TransactionOutputPool::saveMultiThreaded(unsigned int pThreadCount, bool pAutoTrimCache)
    {
        mLock.writeLock("Save");

        if(!mIsValid)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't save invalid data set");
            mLock.writeUnlock();
            return false;
        }

        NextCash::stream_size maxSetCacheDataSize = 0;
        if(mTargetCacheSize > 0)
            maxSetCacheDataSize = mTargetCacheSize / OUTPUTS_SET_COUNT;
        SaveThreadData threadData(mSubSets, maxSetCacheDataSize, pAutoTrimCache);
        NextCash::Thread *threads[pThreadCount];
        int32_t lastReport = getTime();
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

        mLock.writeUnlock();
        return threadData.success;
    }

    TransactionOutputPool::SubSet::SubSet() : mLock("OutputsSubSet")
    {
        mSamples = NULL;
        mIndexSize = 0;
        mNewSize = 0;
        mCacheRawDataSize = 0;
    }

    TransactionOutputPool::SubSet::~SubSet()
    {
        for(NextCash::HashContainerList<TransactionReference *>::Iterator item = mCache.begin();
          item != mCache.end(); ++item)
            delete *item;
        if(mSamples != NULL)
            delete[] mSamples;
    }

    typename TransactionOutputPool::SubSetIterator TransactionOutputPool::SubSet::get(
      const NextCash::Hash &pTransactionID)
    {
        mLock.lock();

        SubSetIterator result = mCache.get(pTransactionID);
        if(result == mCache.end() && pull(pTransactionID))
            result = mCache.get(pTransactionID);

        mLock.unlock();
        return result;
    }

    bool TransactionOutputPool::SubSet::insert(const NextCash::Hash &pTransactionID,
      TransactionReference *pReference, Transaction &pTransaction)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Outputs SubSet Insert");
#endif
        bool result = false;
        mLock.lock();

        mCache.insert(pTransactionID, pReference);
        ++mNewSize;
        mCacheRawDataSize += pReference->size();
        pReference->clearDataOffset();
        result = true;

        if(result)
        {
            NextCash::String filePathName;
            filePathName.writeFormatted("%s%s%04x.data", mFilePath, NextCash::PATH_SEPARATOR, mID);
            NextCash::FileOutputStream *dataOutFile = new NextCash::FileOutputStream(filePathName);
            if(dataOutFile->isValid())
                pReference->writeInitialData(pTransactionID, dataOutFile, pTransaction);
            else
                result = false;
            delete dataOutFile;
        }

        mLock.unlock();
        return result;
    }

    bool TransactionOutputPool::SubSet::getOutput(const NextCash::Hash &pTransactionID,
      uint32_t pIndex, uint8_t pFlags, uint32_t pSpentBlockHeight, Output &pOutput,
      uint32_t &pPreviousBlockHeight)
    {
        mLock.lock();

        bool result = false;
        SubSetIterator item = mCache.get(pTransactionID);
        if(item == mCache.end() && pull(pTransactionID))
            item = mCache.get(pTransactionID);

        while(item != mCache.end() && item.hash() == pTransactionID)
        {
            if(!(*item)->markedRemove())
            {
                pPreviousBlockHeight = (*item)->blockHeight;

                if(pFlags & MARK_SPENT)
                    result = (*item)->spendInternal(pSpentBlockHeight, pIndex) ||
                      !(pFlags & REQUIRE_UNSPENT);
                else if(pFlags & REQUIRE_UNSPENT)
                    result = (*item)->isUnspent(pIndex);

                if(result)
                {
                    NextCash::String filePathName;
                    filePathName.writeFormatted("%s%s%04x.data", mFilePath,
                      NextCash::PATH_SEPARATOR, mID);
                    NextCash::FileInputStream *dataInFile =
                      new NextCash::FileInputStream(filePathName);
                    result = dataInFile->isValid() &&
                      (*item)->readOutput(dataInFile, pIndex, pOutput);
                    delete dataInFile;
                }

                break;
            }

            ++item;
        }

        mLock.unlock();
        return result;
    }

    bool TransactionOutputPool::SubSet::isUnspent(const NextCash::Hash &pTransactionID,
      uint32_t pIndex)
    {
        mLock.lock();

        bool result = false;
        SubSetIterator item = mCache.get(pTransactionID);
        if(item == mCache.end() && pull(pTransactionID))
            item = mCache.get(pTransactionID);

        while(item != mCache.end() && item.hash() == pTransactionID)
        {
            if(!(*item)->markedRemove())
            {
                result = (*item)->isUnspent(pIndex);
                break;
            }

            ++item;
        }

        mLock.unlock();
        return result;
    }

    bool TransactionOutputPool::SubSet::spend(const NextCash::Hash &pTransactionID,
      uint32_t pIndex, uint32_t pSpentBlockHeight, uint32_t &pPreviousBlockHeight,
      bool pRequireUnspent)
    {
        mLock.lock();

        bool result = false;
        SubSetIterator item = mCache.get(pTransactionID);
        if(item == mCache.end() && pull(pTransactionID))
            item = mCache.get(pTransactionID);

        while(item != mCache.end() && item.hash() == pTransactionID)
        {
            if(!(*item)->markedRemove())
            {
                pPreviousBlockHeight = (*item)->blockHeight;
                result = (*item)->spendInternal(pSpentBlockHeight, pIndex) || !pRequireUnspent;
                break;
            }

            ++item;
        }

        mLock.unlock();
        return result;
    }

    bool TransactionOutputPool::SubSet::hasUnspent(const NextCash::Hash &pTransactionID,
      uint32_t pSpentBlockHeight)
    {
        mLock.lock();

        bool result = false;
        SubSetIterator item = mCache.get(pTransactionID);
        if(item == mCache.end() && pull(pTransactionID))
            item = mCache.get(pTransactionID);

        while(item != mCache.end() && item.hash() == pTransactionID)
        {
            if(!(*item)->markedRemove() &&
              (pSpentBlockHeight == 0xffffffff || pSpentBlockHeight != (*item)->blockHeight))
            {
                result = (*item)->hasUnspent();
                break;
            }

            ++item;
        }

        mLock.unlock();
        return result;
    }

    bool TransactionOutputPool::SubSet::exists(const NextCash::Hash &pTransactionID)
    {
        mLock.lock();

        bool result = false;
        SubSetIterator item = mCache.get(pTransactionID);
        if(item == mCache.end() && pull(pTransactionID))
            item = mCache.get(pTransactionID);

        while(item != mCache.end() && item.hash() == pTransactionID)
        {
            if(!(*item)->markedRemove())
            {
                result = true;
                break;
            }

            ++item;
        }

        mLock.unlock();
        return result;
    }

    bool TransactionOutputPool::SubSet::pull(const NextCash::Hash &pTransactionID,
      TransactionReference *pMatching)
    {
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

            next = new TransactionReference();
            if(!next->readData(&dataFile))
            {
                delete next;
                break;
            }

            if((pMatching == NULL || pMatching->valuesMatch(next)) &&
              mCache.insertIfNotMatching(pTransactionID, next, transactionsMatch))
            {
                mCacheRawDataSize += next->size();
                result = true;
            }
            else
                delete next;

            current += sizeof(NextCash::stream_size);
        }

        return result;
    }

    void TransactionOutputPool::SubSet::loadSamples(NextCash::InputStream *pIndexFile)
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

    bool TransactionOutputPool::SubSet::findSample(const NextCash::Hash &pHash,
      NextCash::InputStream *pIndexFile, NextCash::InputStream *pDataFile,
      NextCash::stream_size &pBegin, NextCash::stream_size &pEnd)
    {
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

    bool TransactionOutputPool::SubSet::loadCache()
    {
        for(NextCash::HashContainerList<TransactionReference *>::Iterator item = mCache.begin();
          item != mCache.end(); ++item)
            delete *item;
        mCache.clear();
        mCacheRawDataSize = 0;

        // Open cache file
        NextCash::String filePathName;
        filePathName.writeFormatted("%s%s%04x.cache", mFilePath, NextCash::PATH_SEPARATOR, mID);
        NextCash::FileInputStream *cacheFile = new NextCash::FileInputStream(filePathName);

        if(!cacheFile->isValid())
        {
            delete cacheFile;
            return false;
        }

        bool success = true;
        TransactionReference *next;
        NextCash::Hash hash(TRANSACTION_HASH_SIZE);
        NextCash::stream_size dataOffset;
        cacheFile->setReadOffset(0);
        while(cacheFile->remaining())
        {
            // Read data offset from cache file
            dataOffset = cacheFile->readUnsignedLong();

            // Read hash from cache file
            if(!hash.read(cacheFile))
            {
                success = false;
                break;
            }

            // Read data from cache file
            next = new TransactionReference();
            if(!next->read(cacheFile))
            {
                delete next;
                success = false;
                break;
            }

            next->setDataOffset(dataOffset);

            mCache.insert(hash, next);
            mCacheRawDataSize += next->size();
        }

        delete cacheFile;
        return success;
    }

    bool TransactionOutputPool::SubSet::saveCache()
    {
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

        for(NextCash::HashContainerList<TransactionReference *>::Iterator item =
          mCache.begin(); item != mCache.end(); ++item)
        {
            cacheFile->writeUnsignedLong((*item)->dataOffset());
            item.hash().write(cacheFile);
            (*item)->write(cacheFile);
        }

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
            if((*item)->compareAge(pItem) > 0)
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

    bool TransactionOutputPool::SubSet::load(const char *pFilePath, unsigned int pID)
    {
        mLock.lock();

        for(NextCash::HashContainerList<TransactionReference *>::Iterator item = mCache.begin();
          item != mCache.end(); ++item)
            delete *item;
        mCache.clear();
        mCacheRawDataSize = 0;

        NextCash::String filePathName;
        bool created = false;

        mFilePath = pFilePath;
        mID = pID;

        // Open index file
        filePathName.writeFormatted("%s%s%04x.index", mFilePath, NextCash::PATH_SEPARATOR,
          mID);
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

        loadSamples(&indexFile);
        loadCache();

        mLock.unlock();
        return true;
    }

    //TODO This operation is expensive. Try to find a better algorithm.
    void TransactionOutputPool::SubSet::markOld(NextCash::stream_size pDataSize)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Outputs SubSet Mark Old");
#endif
        if(pDataSize == 0)
        {
            for(NextCash::HashContainerList<TransactionReference *>::Iterator item =
              mCache.begin(); item != mCache.end(); ++item)
                (*item)->setOld();
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
        for(NextCash::HashContainerList<TransactionReference *>::Iterator item = mCache.begin();
          item != mCache.end(); ++item)
            insertOldest(*item, oldestList, targetCount);

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
        for(NextCash::HashContainerList<TransactionReference *>::Iterator item = mCache.begin();
          item != mCache.end(); ++item)
        {
            if((*item)->isOld())
            {
                ++markedCount;
                markedSize += (*item)->size() + staticCacheItemSize;
                if(currentSize - markedSize < pDataSize)
                    break;
            }
            else if((*item)->compareAge(cutoff) < 0)
            {
                (*item)->setOld();
                ++markedCount;
                markedSize += (*item)->size() + staticCacheItemSize;
                if(currentSize - markedSize < pDataSize)
                    break;
            }
        }

        if(currentSize - markedSize > pDataSize)
        {
            // Mark every other item as old.
            bool markThisOld = false;
            for(NextCash::HashContainerList<TransactionReference *>::Iterator item =
              mCache.begin(); item != mCache.end(); ++item)
            {
                if(markThisOld && !(*item)->isOld())
                {
                    ++markedCount;
                    (*item)->setOld();
                    markedSize += (*item)->size() + staticCacheItemSize;
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

    bool TransactionOutputPool::SubSet::trimCache(NextCash::stream_size pMaxCacheDataSize,
      bool pAutoTrimCache)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Outputs SubSet Clean");
#endif

        // Mark items as old to keep cache data size under max.
        if(pAutoTrimCache)
            markOld(pMaxCacheDataSize);

        // Remove old items from the cache.
        for(NextCash::HashContainerList<TransactionReference *>::Iterator item = mCache.begin();
          item != mCache.end();)
        {
            if((*item)->isOld())
            {
                mCacheRawDataSize -= (*item)->size();
                delete *item;
                item = mCache.erase(item);
            }
            else
                ++item;
        }

        return saveCache();
    }

    bool TransactionOutputPool::SubSet::save(NextCash::stream_size pMaxCacheDataSize,
      bool pAutoTrimCache)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Outputs SubSet Save");
#endif
        mLock.lock();

        if(mCache.size() == 0)
        {
            mLock.unlock();
            return true;
        }

#ifdef PROFILER_ON
        NextCash::Profiler profilerWriteData("Outputs SubSet Save Write Data");
#endif

        // Open data file as an output stream
        NextCash::String filePathName;
        filePathName.writeFormatted("%s%s%04x.data", mFilePath, NextCash::PATH_SEPARATOR,
          mID);
        NextCash::FileOutputStream *dataOutFile = new NextCash::FileOutputStream(filePathName);
        NextCash::HashContainerList<TransactionReference *>::Iterator item;
        uint64_t newCount = 0;
        bool indexNeedsUpdated = false;

        // Write all cached/modified data to file.
        for(item = mCache.begin(); item != mCache.end();)
        {
            if((*item)->markedRemove())
            {
                if(!(*item)->isNew())
                {
                    indexNeedsUpdated = true;
                    ++item;
                }
                else
                {
                    mCacheRawDataSize -= (*item)->size();
                    delete *item;
                    item = mCache.erase(item);
                }
            }
            else
            {
                if((*item)->isModified())
                    (*item)->writeModifiedData(dataOutFile);
                if((*item)->isNew())
                {
                    ++newCount;
                    indexNeedsUpdated = true;
                }

                ++item;
            }
        }

        delete dataOutFile;
#ifdef PROFILER_ON
        profilerWriteData.stop();
#endif

        if(!indexNeedsUpdated)
        {
            trimCache(pMaxCacheDataSize, pAutoTrimCache);

            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              // "Set %d save index not updated", mID);
            mLock.unlock();
            return true;
        }

#ifdef PROFILER_ON
        NextCash::Profiler profilerReadIndex("Outputs SubSet Save Read Index");
#endif
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
#ifdef PROFILER_ON
        profilerReadIndex.stop();
#endif

#ifdef PROFILER_ON
        NextCash::Profiler profilerUpdateIndex("Outputs SubSet Save Update Index");
        NextCash::Profiler profilerIndexInsert("Outputs SubSet Save Index Insert", false);
        NextCash::Profiler profilerIndexInsertPush("Outputs SubSet Save Index Insert Push", false);
#endif
        // Update indices
        NextCash::DistributedVector<NextCash::Hash>::Iterator hash;
        NextCash::DistributedVector<NextCash::stream_size>::Iterator index;
        int compare;
        bool found;
        int32_t lastReport = getTime();
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

            if((*item)->markedRemove())
            {
                // Check that it was previously added to the index and data file.
                // Otherwise it isn't in current indices and doesn't need removed.
                if(!(*item)->isNew())
                {
                    // Remove from indices.
                    // They aren't sorted by file offset so in this scenario a linear search is
                    //   required since not all hashes are read and reading them for a binary
                    //   search would presumably be more expensive since it requires reading hashes.
                    found = false;
                    dataOffset = (*item)->dataOffset();
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
                          dataOffset, item.hash().hex().text());
                        success = false;
                        break;
                    }
                }

                mCacheRawDataSize -= (*item)->size();
                delete *item;
                item = mCache.erase(item);
            }
            else if((*item)->isNew())
            {
#ifdef PROFILER_ON
                profilerIndexInsert.start();
#endif
                // For new items perform insert sort into existing indices.
                // This costs more processor time to do the insert for every new item.
                // This saves file reads by not requiring a read of every existing indice like a
                //   merge sort would.
                if(indices.size () == 0)
                {
#ifdef PROFILER_ON
                    profilerIndexInsertPush.start();
#endif
                    // Add as only item
                    indices.push_back((*item)->dataOffset());
                    hashes.push_back(item.hash());
#ifdef PROFILER_ON
                    profilerIndexInsertPush.stop();
#endif
                    (*item)->clearNew();
#ifdef PROFILER_ON
                    profilerIndexInsert.stop();
#endif
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
#ifdef PROFILER_ON
                        profilerIndexInsert.stop();
#endif
                        break;
                    }
                    ++readHeadersCount;
                }

                compare = item.hash().compare(*hash);
                if(compare <= 0)
                {
#ifdef PROFILER_ON
                    profilerIndexInsertPush.start();
#endif
                    // Insert as first
                    indices.insert(index, (*item)->dataOffset());
                    hashes.insert(hash, item.hash());
                    (*item)->clearNew();
#ifdef PROFILER_ON
                    profilerIndexInsertPush.stop();
                    profilerIndexInsert.stop();
#endif
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
#ifdef PROFILER_ON
                        profilerIndexInsert.stop();
#endif
                        break;
                    }
                    ++readHeadersCount;
                }

                compare = item.hash().compare(*hash);
                if(compare >= 0)
                {
#ifdef PROFILER_ON
                    profilerIndexInsertPush.start();
#endif
                    // Add to end
                    indices.push_back((*item)->dataOffset());
                    hashes.push_back(item.hash());
                    (*item)->clearNew();
#ifdef PROFILER_ON
                    profilerIndexInsertPush.stop();
                    profilerIndexInsert.stop();
#endif
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

                    compare = item.hash().compare(*hash);
                    if(current == begin || compare == 0)
                    {
#ifdef PROFILER_ON
                        profilerIndexInsertPush.start();
#endif
                        if(compare < 0)
                        {
                            // Insert before current
                            indices.insert(index, (*item)->dataOffset());
                            hashes.insert(hash, item.hash());
                            (*item)->clearNew();
#ifdef PROFILER_ON
                            profilerIndexInsertPush.stop();
#endif
                            break;
                        }
                        else //if(compare >= 0)
                        {
                            // Insert after current
                            ++index;
                            ++hash;
                            indices.insert(index, (*item)->dataOffset());
                            hashes.insert(hash, item.hash());
                            (*item)->clearNew();
#ifdef PROFILER_ON
                            profilerIndexInsertPush.stop();
#endif
                            break;
                        }
                    }

                    if(compare > 0)
                        begin = current;
                    else //if(compare < 0)
                        end = current;
                }

                ++item;

#ifdef PROFILER_ON
                profilerIndexInsert.stop();
#endif
            }
            else
                ++item;
        }
#ifdef PROFILER_ON
        profilerUpdateIndex.stop();
#endif

        if(success)
        {
#ifdef PROFILER_ON
            NextCash::Profiler profilerWriteIndex("Outputs SubSet Save Write Index");
#endif
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
#ifdef PROFILER_ON
            profilerWriteIndex.stop();
#endif

            // Open index file
            filePathName.writeFormatted("%s%s%04x.index", mFilePath, NextCash::PATH_SEPARATOR,
              mID);
            NextCash::FileInputStream indexFile(filePathName);

            // Reload samples
            loadSamples(&indexFile);

            trimCache(pMaxCacheDataSize, pAutoTrimCache);
        }

        mLock.unlock();
        return true;
    }

    bool TransactionOutputPool::SubSet::defragment()
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

    bool TransactionOutputPool::test()
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "------------- Starting Outputs Tests -------------");

        bool success = true;
        NextCash::Hash hash(32);
        TransactionReference *data;
        NextCash::Digest digest(NextCash::Digest::SHA256);
        TransactionOutputPool::Iterator found;
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
            TransactionOutputPool testOutputs;
            TransactionReference *lowest = NULL, *highest = NULL;
            NextCash::Hash lowestHash, highestHash;

            testOutputs.load("test_outputs");
            testOutputs.setTargetCacheSize(cacheTargetSize);

            for(unsigned int i = 0; i < testSize; ++i)
            {
                // Create new value
                data = new TransactionReference(i, (i % 10) + 1);

                // Calculate hash
                digest.initialize();
                data->write(&digest);
                digest.getResult(&hash);

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
                testOutputs.insert(hash, data, transaction);
            }

            // Create duplicate value
            data = new TransactionReference((testSize / 2) + 2, (((testSize / 2) + 2) % 10) + 1);
            dupValue = (testSize / 2) + 2;
            nonDupValue = dupValue;

            while(transaction.outputs.size() < data->outputCount())
                transaction.outputs.emplace_back();
            while(transaction.outputs.size() > data->outputCount())
                transaction.outputs.pop_back();

            // Calculate hash
            digest.initialize();
            data->write(&digest);
            digest.getResult(&hash);

            // Add to set
            testOutputs.insert(hash, data, transaction);

            if(testOutputs.size() == testSize + 1)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Pass size");
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
                  "Pass lowest : %d - %s", ((TransactionReference *)(*found))->blockHeight,
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
                  "Pass highest : %d - %s", ((TransactionReference *)(*found))->blockHeight,
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
                          "Pass duplicate first : %d - %s",
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
                      "Failed duplicate first : wrong hash", found.hash().hex().text());
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
                      "Pass duplicate second incremented");

                    if(found.hash() == hash)
                    {
                        if(((TransactionReference *)(*found))->blockHeight == dupValue ||
                          ((TransactionReference *)(*found))->blockHeight == nonDupValue ||
                          ((TransactionReference *)(*found))->blockHeight == data->blockHeight)
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                              "Pass duplicate second : %d - %s",
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

            if(!testOutputs.save(4))
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed multi-threaded save");
                success = false;
            }
        }

        if(success)
        {
            TransactionOutputPool testOutputs;

            testOutputs.load("test_outputs");
            testOutputs.setTargetCacheSize(cacheTargetSize);

            if(testOutputs.size() == testSize + 1)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Pass load size : %d", testSize + 1);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed load size : %d != %d", testOutputs.size(), testSize + 1);
                success = false;
            }

            checkSuccess = true;
            for(unsigned int i=0;i<testSize;++i)
            {
                // Create new value
                data = new TransactionReference(i, (i % 10) + 1);

                // Calculate hash
                digest.initialize();
                data->write(&digest);
                digest.getResult(&hash);

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
                  "Pass load check %d lookups", testSize);

            for(unsigned int i=testSize;i<testSizeLarger;++i)
            {
                // Create new value
                data = new TransactionReference(i, (i % 10) + 1);

                // Calculate hash
                digest.initialize();
                data->write(&digest);
                digest.getResult(&hash);

                while(transaction.outputs.size() < data->outputCount())
                    transaction.outputs.emplace_back();
                while(transaction.outputs.size() > data->outputCount())
                    transaction.outputs.pop_back();

                // Add to set
                testOutputs.insert(hash, data, transaction);
            }

            checkSuccess = true;
            for(unsigned int i=testSize;i<testSizeLarger;++i)
            {
                // Create new value
                data = new TransactionReference(i, (i % 10) + 1);

                // Calculate hash
                digest.initialize();
                data->write(&digest);
                digest.getResult(&hash);

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
                  "Pass check %d lookups", testSizeLarger);

            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Original Size : %d", testOutputs.size());

            // Check removing items
            removedSize = testOutputs.size();
            for(unsigned int i = 0; i < testSizeLarger; i += (testSize / 10))
            {
                // Create new value
                data = new TransactionReference(i, (i % 10) + 1);

                // Calculate hash
                digest.initialize();
                data->write(&digest);
                digest.getResult(&hash);

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
                // Create new value
                data = new TransactionReference(i, (i % 10) + 1);

                // Calculate hash
                digest.initialize();
                data->write(&digest);
                digest.getResult(&hash);

                // Mark old
                found = testOutputs.get(hash);
                if(found && !(*found)->markedRemove())
                {
                    (*found)->setOld();
                    ++markedOldCount;
                }
            }

            // This applies the changes to the marked items.
            testOutputs.save(4, false);

            if(testOutputs.size() == removedSize)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Pass remove size : %d", removedSize);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed remove size : %d != %d", testOutputs.size(), removedSize);
                success = false;
            }

            if(testOutputs.cacheSize() == testOutputs.size() - markedOldCount)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Pass old cache size : %d", testOutputs.cacheSize());
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
            TransactionOutputPool testOutputs;

            testOutputs.load("test_outputs");

            // Set max cache data size to 75% of current size
            uint64_t cacheMaxSize = (uint64_t)((double)testOutputs.cacheDataSize() * 0.75);
            testOutputs.setTargetCacheSize(cacheMaxSize);

            // Force cache to prune
            testOutputs.save(4);

            if(testOutputs.size() == removedSize)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Pass prune size : %d", removedSize);
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
                  "Pass prune cache data size : %d < %d", testOutputs.cacheDataSize(),
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
                // Create new value
                data = new TransactionReference(i, (i % 10) + 1);

                // Calculate hash
                digest.initialize();
                data->write(&digest);
                digest.getResult(&hash);

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
                              // "Pass load : %d - %s",
                              // ((TransactionReference *)(*found))->blockHeight, found.hash().hex().text());
                    }
                }

                delete data;
            }

            if(checkSuccess)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Pass after prune check %d lookups", testSize);
        }

        return success;
    }
}
