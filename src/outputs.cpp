/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "outputs.hpp"

#ifdef PROFILER_ON
#include "arcmist/dev/profiler.hpp"
#endif

#include "arcmist/base/distributed_vector.hpp"
#include "info.hpp"
#include "interpreter.hpp"
#include "block.hpp"

#include <cstring>


namespace BitCoin
{
    void Output::write(ArcMist::OutputStream *pStream, bool pBlockFile)
    {
        if(pBlockFile)
            blockFileOffset = pStream->writeOffset();
        pStream->writeLong(amount);
        writeCompactInteger(pStream, script.length());
        script.setReadOffset(0);
        pStream->writeStream(&script, script.length());
    }

    bool Output::read(ArcMist::InputStream *pStream, bool pBlockFile)
    {
        if(pBlockFile)
            blockFileOffset = pStream->readOffset();

        if(pStream->remaining() < 8)
            return false;

        amount = pStream->readLong();

        uint64_t bytes = readCompactInteger(pStream);
        if(pStream->remaining() < bytes)
            return false;
        script.setSize(bytes);
        script.reset();
        script.writeStreamCompact(*pStream, bytes);

        return true;
    }

    void Output::print(ArcMist::Log::Level pLevel)
    {
        ArcMist::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "Output");
        ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Amount : %.08f", bitcoins(amount));
        script.setReadOffset(0);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Script : (%d bytes)", script.length());
        ScriptInterpreter::printScript(script, pLevel);
    }

    Output &Output::operator = (const Output &pRight)
    {
        amount = pRight.amount;
        script = pRight.script;
        return *this;
    }

    bool TransactionReference::allocateOutputs(unsigned int pCount)
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
            {
                try
                {
                    mOutputs = new OutputReference[mOutputCount];
                }
                catch(std::bad_alloc &pBadAlloc)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Bad allocation (Allocate %d Outputs) : %s", mOutputCount, pBadAlloc.what());
                    return false;
                }
            }
        }

        return true;
    }

    void TransactionReference::clearOutputs()
    {
        if(mOutputs != NULL)
            delete[] mOutputs;
        mOutputCount = 0;
        mOutputs = NULL;
    }

    bool TransactionReference::readHeader(ArcMist::InputStream *pStream)
    {
        mFlags = 0;
        if(pStream->remaining() < SIZE)
            return false;

        fileOffset = pStream->readOffset();
        if(!id.read(pStream, 32))
            return false;

        blockHeight = pStream->readUnsignedInt();
        if(blockHeight > MAX_BLOCK_HEIGHT)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Block height too high : %d", blockHeight);
            return false;
        }

        clearOutputs();
        mOutputCount = pStream->readUnsignedInt();
        if(mOutputCount > MAX_OUTPUT_COUNT)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Output Count too high : %d", mOutputCount);
            return false;
        }

        if(pStream->remaining() < OutputReference::SIZE * mOutputCount)
            return false;

        return true;
    }

    bool TransactionReference::readMatchingID(const ArcMist::Hash &pHash, ArcMist::InputStream *pStream)
    {
        mFlags = 0;
        if(pStream->remaining() < SIZE)
            return false;

        fileOffset = pStream->readOffset();
        if(!id.read(pStream) || id != pHash)
            return false;

        blockHeight = pStream->readUnsignedInt();
        if(blockHeight > MAX_BLOCK_HEIGHT)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Block height too high : %d", blockHeight);
            return false;
        }

        unsigned int outputCount = pStream->readUnsignedInt();
        if(outputCount > MAX_OUTPUT_COUNT)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Output Count too high : %d", outputCount);
            return false;
        }

        if(pStream->remaining() < OutputReference::SIZE * outputCount)
            return false;

        if(!allocateOutputs(outputCount))
            return false;
        pStream->read(mOutputs, mOutputCount * OutputReference::SIZE);
        clearFlags();
        return true;
    }

    bool TransactionReference::readAboveBlock(unsigned int pBlockHeight, ArcMist::InputStream *pStream)
    {
        mFlags = 0;
        if(pStream->remaining() < SIZE)
            return false;

        fileOffset = pStream->readOffset();

        // Check block height first
        pStream->setReadOffset(fileOffset + 32);
        blockHeight = pStream->readUnsignedInt();
        if(blockHeight < pBlockHeight)
            return false;

        // Read all data
        pStream->setReadOffset(fileOffset);
        if(!id.read(pStream))
            return false;

        blockHeight = pStream->readUnsignedInt();
        if(blockHeight > MAX_BLOCK_HEIGHT)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Block height too high : %d", blockHeight);
            return false;
        }

        unsigned int outputCount = pStream->readUnsignedInt();
        if(outputCount > MAX_OUTPUT_COUNT)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Output Count too high : %d", outputCount);
            return false;
        }

        if(pStream->remaining() < OutputReference::SIZE * outputCount)
            return false;

        if(!allocateOutputs(outputCount))
            return false;
        pStream->read(mOutputs, mOutputCount * OutputReference::SIZE);
        clearFlags();
        return true;
    }

    bool TransactionReference::read(ArcMist::InputStream *pStream)
    {
        mFlags = 0;
        fileOffset = pStream->readOffset();
        if(!id.read(pStream))
            return false;
        if(pStream->remaining() < SIZE - 32)
            return false;

        blockHeight = pStream->readUnsignedInt();
        if(blockHeight > MAX_BLOCK_HEIGHT)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Block height too high : %d", blockHeight);
            return false;
        }

        unsigned int outputCount = pStream->readUnsignedInt();
        if(outputCount > MAX_OUTPUT_COUNT)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Output Count too high : %d", outputCount);
            return false;
        }

        if(pStream->remaining() < OutputReference::SIZE * outputCount)
            return false;

        if(!allocateOutputs(outputCount))
            return false;
        pStream->read(mOutputs, mOutputCount * OutputReference::SIZE);
        clearFlags();
        return true;
    }

    bool TransactionReference::write(ArcMist::OutputStream *pStream)
    {
        if(mOutputs == NULL)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Trying to write header only transaction : %s", id.hex().text());
            return false;
        }

        // Not modified and already written to file
        if(!isModified() && fileOffset != ArcMist::INVALID_STREAM_SIZE)
            return true;

        // Not written yet, append to end of file
        if(fileOffset == ArcMist::INVALID_STREAM_SIZE)
        {
            fileOffset = pStream->length();
            setNew();
        }

        if(pStream->writeOffset() != fileOffset)
            pStream->setWriteOffset(fileOffset);

        id.write(pStream);
        pStream->writeUnsignedInt(blockHeight);
        pStream->writeUnsignedInt(mOutputCount);
        pStream->write(mOutputs, mOutputCount * OutputReference::SIZE);
        clearModified();
        return true;
    }

    unsigned int TransactionReference::spentOutputCount() const
    {
        if(mOutputs == NULL) // Header only
            return 0;
        unsigned int result = 0;
        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
            if(output->spentBlockHeight != 0)
                ++result;
        return result;
    }

    // Mark an output as spent
    void TransactionReference::spendInternal(unsigned int pIndex, unsigned int pBlockHeight)
    {
        if(mOutputs == NULL)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Trying to spend header only transaction at index %d : %s", pIndex, id.hex().text());
            return;
        }

        OutputReference *output = outputAt(pIndex);
        if(output == NULL)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Spend index %d not found", pIndex);
            return;
        }
        else if(output->spentBlockHeight != 0)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Spend index %d already spent at block height %d", pIndex, output->spentBlockHeight);
            return;
        }
        output->spendInternal(pBlockHeight);
        setModified();
    }

    bool TransactionReference::wasModifiedInOrAfterBlock(unsigned int pBlockHeight) const
    {
        if(blockHeight >= pBlockHeight)
            return true;

        if(mOutputCount == 0 || mOutputs == NULL)
            return false;

        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
            if(output->spentBlockHeight >= pBlockHeight)
                return true;

        return false;
    }

    unsigned int TransactionReference::spentBlockHeight() const
    {
        unsigned int result = 0;
        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i)
        {
            if(output->spentBlockHeight == 0)
                return MAX_BLOCK_HEIGHT;
            else if(output->spentBlockHeight > result)
                result = output->spentBlockHeight;
            ++output;
        }
        return result;
    }

    void TransactionReference::commit(std::vector<Output *> &pOutputs)
    {
        if(mOutputs == NULL)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Trying to commit header only transaction : %s", id.hex().text());
            return;
        }

        if(mOutputCount != pOutputs.size())
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Mismatched transaction outputs on commit %d != %d : %s", mOutputCount, pOutputs.size(),
              id.hex().text());
            return;
        }

        OutputReference *output = mOutputs;
        for(std::vector<Output *>::iterator fullOutput=pOutputs.begin();fullOutput!=pOutputs.end();++fullOutput,++output)
            if(output->commit(**fullOutput))
                setModified();
    }

    bool TransactionReference::revert(unsigned int pBlockHeight)
    {
        if(blockHeight > pBlockHeight)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Deleting transaction for block %d : %s", blockHeight, id.hex().text());
            // Created above this block height, so mark for delete on next save
            setDelete();
        }

        if(mOutputs == NULL)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Trying to revert header only transaction : %s", id.hex().text());
            return false;
        }

        bool result = false;
        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
            if(output->spentBlockHeight > pBlockHeight)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  "Unspending transaction output for block %d : index %d - %s",
                  output->spentBlockHeight, i, id.hex().text());
                output->spentBlockHeight = 0; // Spent at or above this block height, so "unspend"
                result = true;
                setModified();
            }
        return result;
    }

    void TransactionReference::print(ArcMist::Log::Level pLevel)
    {
        if(mOutputs == NULL)
            ArcMist::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "Transaction Reference (Header only)");
        else
            ArcMist::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "Transaction Reference");
        ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Transaction ID : %s", id.hex().text());
        ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Height         : %d", blockHeight);

        if(mOutputs == NULL)
            return;

        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
        {
            ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Output Reference %d", i);
            ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    File Offset : %d", output->blockFileOffset);
            ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    Spent       : %d", output->spentBlockHeight);
        }
    }

    bool TransactionReferenceList::insertSorted(TransactionReference *pItem)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Insert Sorted");
#endif
        if(pItem == NULL)
            return false;

        if(size() == 0)
        {
            push_back(pItem);
            return true;
        }

        int compare = back()->compare(*pItem);
        if(compare == 0)
            return false;
        else if(compare < 0)
        {
            push_back(pItem);
            return true;
        }

        compare = front()->compare(*pItem);
        if(compare == 0)
            return false;
        else if(compare > 0)
        {
            insert(begin(), pItem);
            return true;
        }

        TransactionReference **first = data();
        TransactionReference **bottom = data();
        TransactionReference **top = data() + size() - 1;
        TransactionReference **current;

        while(true)
        {
            // Break the set in two halves
            current = bottom + ((top - bottom) / 2);
            compare = pItem->compare(**current);

            if(current == bottom)
            {
                if(**current == *pItem)
                    return false;

                if(**bottom > *pItem)
                    current = bottom; // Insert before bottom
                else if(current != top && **top > *pItem)
                    current = top; // Insert before top
                else
                    current = top + 1; // Insert after top

                if(*current != NULL && **current == *pItem)
                    return false;

                break;
            }

            // Determine which half the desired item is in
            if(compare > 0)
                bottom = current;
            else if(compare < 0)
                top = current;
            else
            {
                // Item found
                // Loop backwards to find the first matching
                while(current > first)
                {
                    --current;
                    if(pItem->id != (*current)->id)
                    {
                        ++current;
                        break;
                    }
                }

                while(pItem->id == (*current)->id)
                {
                    compare = pItem->compare(**current);
                    if(compare == 0)
                        return false;
                    else if(compare < 0)
                        break;
                    ++current;
                }

                break;
            }
        }

        iterator after = begin();
        after += (current - data());
        insert(after, pItem);
        return true;
    }

    void TransactionReferenceList::mergeSorted(TransactionReferenceList &pRight)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Merge Sorted");
#endif
        TransactionReferenceList copy = *this;
        clearNoDelete();

        TransactionReferenceList::iterator left = copy.begin();
        TransactionReferenceList::iterator right = pRight.begin();
        while(left != copy.end() || right != pRight.end())
        {
            if(left == copy.end())
                push_back(*right++);
            else if(right == pRight.end())
                push_back(*left++);
            else if(**left < **right)
                push_back(*left++);
            else
                push_back(*right++);
        }

        copy.clearNoDelete();
        pRight.clearNoDelete();
    }

    TransactionReferenceList::iterator TransactionReferenceList::firstMatching(const ArcMist::Hash &pHash)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs First Matching");
#endif
        if(size() == 0 || back()->id.compare(pHash) < 0 || front()->id.compare(pHash) > 0)
            return end();

        int compare;
        TransactionReference **first = data();
        TransactionReference **bottom = data();
        TransactionReference **top = data() + size() - 1;
        TransactionReference **current;

        while(true)
        {
            // Break the set in two halves
            current = bottom + ((top - bottom) / 2);
            compare = pHash.compare((*current)->id);

            if(current == bottom)
            {
                if(pHash == (*current)->id)
                    break;
                else if(current != top && pHash == (*top)->id)
                {
                    iterator result = begin();
                    result += (top - first);
                    return result;
                }
                else
                    return end();
            }

            // Determine which half the desired item is in
            if(compare > 0)
                bottom = current;
            else if(compare < 0)
                top = current;
            else
                break;
        }

        // Item found
        // Loop backwards to find the first matching
        while(current > first)
        {
            --current;
            if(pHash != (*current)->id)
            {
                ++current;
                break;
            }
        }

        iterator result = begin();
        result += (current - first);
        return result;
    }

    void TransactionReferenceList::drop(unsigned int pBlockHeight, unsigned int &pOutputCount)
    {
        std::vector<TransactionReference *> items;
        swap(items);
        for(iterator item=items.begin();item!=items.end();++item)
            if((*item)->blockHeight < pBlockHeight || !(*item)->hasUnspentOutputs() || (*item)->markedDelete())
            {
                // Drop the item
                pOutputCount -= (*item)->outputCount();
                delete *item;
            }
            else
                push_back(*item); // Keep the item
    }

    bool TransactionReferenceList::checkSort()
    {
        TransactionReference *previous = NULL;
        for(iterator item=begin();item!=end();++item)
        {
            if(previous != NULL && *previous > **item)
            {
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Not sorted :");
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Previous : %s",
                  previous->id.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Current : %s",
                  (*item)->id.hex().text());
                return false;
            }
            previous = *item;
        }
        return true;
    }

    OutputSet::OutputSet() : mLock("Output Set")
    {
        mID = 0x100;
        mUnspentFile = NULL;
        mDataFile = NULL;
        mTransactionCount = 0;
        mOutputCount = 0;
        mCacheOutputCount = 0;
        mSamplesLoaded = false;
        mSamples = NULL;
    }

    OutputSet::~OutputSet()
    {
        if(mUnspentFile != NULL)
            delete mUnspentFile;
        if(mDataFile != NULL)
            delete mDataFile;
        if(mSamples != NULL)
            delete[] mSamples;
    }

    void OutputSet::clear()
    {
        mCache.clear();
        mCacheOutputCount = 0;
        if(mSamples != NULL)
            delete[] mSamples;
        mSamples = NULL;
        mSamplesLoaded = false;
        if(mUnspentFile != NULL)
            delete mUnspentFile;
        mUnspentFile = NULL;
        if(mDataFile != NULL)
            delete mDataFile;
        mDataFile = NULL;
    }

    bool OutputSet::setup(unsigned int pID, const char *pFilePath, unsigned int pCacheSize)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Setup");
#endif
        mLock.writeLock("Setup");

        mFilePath = pFilePath;
        ArcMist::String filePathName;
        mID = pID;
        if(mUnspentFile != NULL)
            delete mUnspentFile;
        mUnspentFile = NULL;
        if(mDataFile != NULL)
            delete mDataFile;
        mDataFile = NULL;

        bool created = false;
        filePathName.writeFormatted("%s%s%02x.unspent", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        if(!ArcMist::fileExists(filePathName))
        {
            // Create file
            ArcMist::FileOutputStream *unspentOutFile = new ArcMist::FileOutputStream(filePathName, true);
            unspentOutFile->writeUnsignedInt(0);
            mTransactionCount = 0;
            unspentOutFile->writeUnsignedInt(0);
            mOutputCount = 0;
            created = true;
            delete unspentOutFile;
        }

        mUnspentFile = new ArcMist::FileInputStream(filePathName);
        mUnspentFile->setReadOffset(0);
        if(!created)
        {
            mTransactionCount = mUnspentFile->readUnsignedInt();
            mOutputCount = mUnspentFile->readUnsignedInt();
        }

        filePathName.writeFormatted("%s%s%02x.data", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        if(created)
        {
            // Create file
            ArcMist::FileOutputStream *dataOutFile = new ArcMist::FileOutputStream(filePathName, true);
            delete dataOutFile;
        }
        mDataFile = new ArcMist::FileInputStream(filePathName);

        mCache.clear();
        mCache.reserve(pCacheSize);

        if(!mUnspentFile->isValid() || !mDataFile->isValid())
        {
            mLock.writeUnlock();
            return false;
        }

        initializeSamples();
        mLock.writeUnlock();
        return true;
    }

    unsigned int OutputSet::loadCache(unsigned int pBlockHeight)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Load Cache");
#endif
        ArcMist::String filePathName;
        filePathName.writeFormatted("%s%s%02x.cache", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        ArcMist::FileInputStream cacheFile(filePathName);

        if(!cacheFile.isValid())
            return pullBlocks(pBlockHeight) && saveCache(pBlockHeight);

        cacheFile.setReadOffset(0);
        IndexEntry index;
        unsigned int itemsAdded = 0;
        TransactionReference *nextTransaction;
        try
        {
            nextTransaction = new TransactionReference();
        }
        catch(std::bad_alloc &pBadAlloc)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Bad allocation (Load Cache) : %s", pBadAlloc.what());
            return 0;
        }
        while(cacheFile.remaining())
        {
            if(!index.read(&cacheFile))
            {
                delete nextTransaction;
                return itemsAdded;
            }
            mDataFile->setReadOffset(index.fileOffset);
            if(nextTransaction->read(mDataFile) && nextTransaction->hasUnspentOutputs() &&
              mCache.insertSorted(nextTransaction))
            {
                ++itemsAdded;
                mCacheOutputCount += nextTransaction->outputCount();
                try
                {
                    nextTransaction = new TransactionReference();
                }
                catch(std::bad_alloc &pBadAlloc)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Bad allocation (Load Cache) : %s", pBadAlloc.what());
                    return itemsAdded;
                }
            }
        }

        delete nextTransaction;
        return itemsAdded;
    }

    bool OutputSet::saveCache(unsigned int pBlockHeight)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Save Cache");
#endif
        ArcMist::String filePathName;
        filePathName.writeFormatted("%s%s%02x.cache", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        ArcMist::FileOutputStream cacheFile(filePathName, true);

        if(!cacheFile.isValid())
            return false;

        IndexEntry index;
        for(TransactionReferenceList::iterator item=mCache.begin();item!=mCache.end();++item)
            if((*item)->hasUnspentOutputs() && (*item)->blockHeight >= pBlockHeight &&
              !(*item)->markedDelete())
            {
                index = *item;
                index.write(&cacheFile);
            }

        return true;
    }

    TransactionReference *OutputSet::pullTransactionHeader(ArcMist::stream_size pDataOffset)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler indexInsertProfiler("Outputs Pull Header");
#endif
        TransactionReference *result = new TransactionReference();
        mDataFile->setReadOffset(pDataOffset);
        if(!result->readHeader(mDataFile))
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to read header at index offset %d", pDataOffset);
            delete result;
            return NULL;
        }
        return result;
    }

    bool OutputSet::save(unsigned int pDropBlockHeight, unsigned int pPurgeBlockHeight)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Save");
#endif
        mLock.writeLock("Save");

        if(mCache.size() == 0)
        {
            mLock.writeUnlock();
            return true;
        }

        if(!mDataFile->isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Data file failed in save");
            mLock.writeUnlock();
            return false;
        }

#ifdef PROFILER_ON
        ArcMist::Profiler writeDataProfiler("Outputs Save Write Data");
#endif
        // Count all added transactions
        unsigned int addedTransactionCount = 0, addedOutputCount = 0; // Needs added to unspent indices
        unsigned int removedTransactionCount = 0, removedOutputCount = 0; // Needs removed from unspent and all indices
        unsigned int spentTransactionCount = 0, spentOutputCount = 0; // Needs removed from unspent indices
        TransactionReferenceList::iterator item;
        ArcMist::String filePathName;

        // Reopen data file as an output stream
        delete mDataFile;
        mDataFile = NULL;
        filePathName.writeFormatted("%s%s%02x.data", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        ArcMist::FileOutputStream *dataOutFile = new ArcMist::FileOutputStream(filePathName);

        // Write all cached transactions to data file, update or append, so they all have file offsets
        for(item=mCache.begin();item!=mCache.end();++item)
        {
            if((*item)->markedDelete())
            {
                if((*item)->fileOffset != ArcMist::INVALID_STREAM_SIZE)
                {
                    // Needs removed from unspent and all indices
                    ++removedTransactionCount;
                    removedOutputCount += (*item)->outputCount();
                }
            }
            else if(!(*item)->hasUnspentOutputs() && (*item)->spentBlockHeight() < pPurgeBlockHeight)
            {
                (*item)->write(dataOutFile);
                if(!(*item)->isNew() && !(*item)->mightNeedIndexed())
                {
                    // Needs removed from unspent indices
                    ++spentTransactionCount;
                    spentOutputCount += (*item)->outputCount();
                }
            }
            else
            {
                (*item)->write(dataOutFile);
                if((*item)->isNew())
                {
                    // Needs added to unspent indices
                    ++addedTransactionCount;
                    addedOutputCount += (*item)->outputCount();
                }
            }
        }
        dataOutFile->flush();

        // Reopen data input file
        delete dataOutFile;
        filePathName.writeFormatted("%s%s%02x.data", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        mDataFile = new ArcMist::FileInputStream(filePathName);

#ifdef PROFILER_ON
        writeDataProfiler.stop();
#endif

#ifdef PROFILER_ON
        ArcMist::Profiler readIndexProfiler("Outputs Save Read Index");
#endif
        ArcMist::DistributedVector<IndexEntry> indices(INDICE_SET_COUNT);
        ArcMist::DistributedVector<TransactionReference *> headers(INDICE_SET_COUNT);
        ArcMist::DistributedVector<TransactionReference *>::iterator header;
        ArcMist::DistributedVector<IndexEntry>::iterator index;
        IndexEntry indexEntry;
        TransactionReference *currentTransaction = NULL;
        int compare;
        bool found;

        // Read current index data
        indices.reserve(mTransactionCount + addedTransactionCount);
        headers.reserve(mTransactionCount + addedTransactionCount);
        mUnspentFile->setReadOffset(HEADER_SIZE); // Transaction count, output count
        unsigned int indicesPerSet = (mTransactionCount / INDICE_SET_COUNT) + 1;
        unsigned int readIndices = 0;
        std::vector<IndexEntry> *indiceSet;
        std::vector<TransactionReference *> *headerSet;
        unsigned int setOffset = 0;
        while(readIndices < mTransactionCount)
        {
            if(mTransactionCount - readIndices < indicesPerSet)
                indicesPerSet = mTransactionCount - readIndices;

            // Read set of indices
            indiceSet = indices.dataSet(setOffset);
            indiceSet->resize(indicesPerSet);
            mUnspentFile->read(indiceSet->data(), indicesPerSet * sizeof(IndexEntry));

            // Zeroize header pointers
            headerSet = headers.dataSet(setOffset);
            headerSet->resize(indicesPerSet);
            std::memset(headerSet->data(), 0, indicesPerSet * sizeof(TransactionReference *));

            readIndices += indicesPerSet;
            ++setOffset;
        }

        indices.refresh();
        headers.refresh();

        // Skip rebuild of index if no items have been added or removed (only updated)
        if(addedTransactionCount == 0 && removedTransactionCount == 0 && spentTransactionCount == 0)
        {
            mLock.writeUnlock();
            return true;
        }
#ifdef PROFILER_ON
        readIndexProfiler.stop();
#endif

#ifdef PROFILER_ON
        ArcMist::Profiler updateIndexProfiler("Outputs Save Update Index");
        ArcMist::Profiler indexInsertProfiler("Outputs Save Index Insert", false);
        ArcMist::Profiler dataInsertProfiler("Outputs Save Data Insert", false);
        ArcMist::Profiler removeProfiler("Outputs Save Remove Deleted", false);
        ArcMist::Profiler removeSpentProfiler("Outputs Save Remove Spent", false);
#endif
        // Read .index file with all transaction indices
        filePathName.writeFormatted("%s%s%02x.index", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        ArcMist::DistributedVector<IndexEntry> allIndices(INDICE_SET_COUNT);
        ArcMist::FileInputStream *indexInputFile = new ArcMist::FileInputStream(filePathName);
        if(indexInputFile->isValid())
        {
            unsigned int allTransCount = indexInputFile->length() / sizeof(IndexEntry);
            allIndices.reserve(allTransCount);
            setOffset = 0;
            readIndices = 0;
            indicesPerSet = (allTransCount / INDICE_SET_COUNT) + 1;
            while(readIndices < allTransCount)
            {
                if(allTransCount - readIndices < indicesPerSet)
                    indicesPerSet = allTransCount - readIndices;

                // Read set of indices
                indiceSet = allIndices.dataSet(setOffset);
                indiceSet->resize(indicesPerSet);
                indexInputFile->read(indiceSet->data(), indicesPerSet * sizeof(IndexEntry));

                readIndices += indicesPerSet;
                ++setOffset;
            }
        }
        delete indexInputFile;

        // ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
          // "Starting index 0x%02x count %d, previous/added/spent/removed %d/%d/%d/%d", mID, indices.size(),
          // mTransactionCount, addedTransactionCount, spentTransactionCount, removedTransactionCount);

        unsigned int begin, end, current;
        unsigned int readHeadersCount = 0;//, previousIndices = indices.size();
        bool success = true;
        for(item=mCache.begin();item!=mCache.end() && success;++item)
        {
            if((*item)->markedDelete())
            {
                (*item)->clearNew();
                (*item)->clearMightNeedIndexed();

                // Check that it was previously added to the index and data file.
                // Otherwise it isn't in current indices and doesn't need removed.
                if((*item)->fileOffset != ArcMist::INVALID_STREAM_SIZE)
                {
#ifdef PROFILER_ON
                    removeProfiler.start();
#endif
                    // Remove from "all" indices (not sorted)
                    for(index=allIndices.begin();index!=allIndices.end();++index)
                        if(index->fileOffset == (*item)->fileOffset)
                        {
                            allIndices.erase(index);
                            break;
                        }

                    // Remove from unspent indices.
                    // They aren't sorted by file offset so in this scenario a linear search is
                    //   required since not all headers are read and reading them for a binary
                    //   search would presumably be more expensive.
                    found = false;
                    header = headers.begin();
                    for(index=indices.begin();index!=indices.end();++index,++header)
                        if(index->fileOffset == (*item)->fileOffset)
                        {
                            indices.erase(index);
                            headers.erase(header);
                            found = true;
                            break;
                        }
#ifdef PROFILER_ON
                    removeProfiler.stop();
#endif

                    if(!found)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed to find index to remove for file offset %d : %s", (*item)->fileOffset,
                          (*item)->id.hex().text());
                        success = false;
                        break;
                    }
                }
            }
            else if(!(*item)->hasUnspentOutputs() && (*item)->spentBlockHeight() < pPurgeBlockHeight)
            {
                // Doesn't belong in sorted indices
                if((*item)->isNew()) // Add to "all" indices (not sorted)
                {
                    allIndices.push_back(IndexEntry((*item)));
                    (*item)->clearNew();
                    (*item)->clearMightNeedIndexed();
                }
                else if(!(*item)->mightNeedIndexed())
                {
#ifdef PROFILER_ON
                    removeSpentProfiler.start();
#endif
                    // Remove from unspent indices.
                    if(indices.size () == 0)
                        break;

                    found = false;
                    if(indices.front().fileOffset == (*item)->fileOffset)
                    {
                        found = true;
                        indices.erase(indices.begin());
                        headers.erase(headers.begin());
                    }

                    if(!found && indices.back().fileOffset == (*item)->fileOffset)
                    {
                        found = true;
                        indices.erase(--indices.end());
                        headers.erase(--headers.end());
                    }

                    if(!found)
                    {
                        // Binary search for remove
                        begin = 0;
                        end = indices.size() - 1;
                        while(true)
                        {
                            // Divide data set in half
                            current = (begin + end) / 2;

                            // Check for match
                            if(indices[current].fileOffset == (*item)->fileOffset)
                            {
                                // Remove match from indices and headers
                                index = indices.begin();
                                index += current;
                                indices.erase(index);

                                header = headers.begin();
                                header += current;
                                headers.erase(header);

                                found = true;
                                break;
                            }

                            // Pull "current" entry (if it isn't already)
                            currentTransaction = headers[current];
                            if(currentTransaction == NULL)
                            {
                                // Fetch transaction data
                                currentTransaction = pullTransactionHeader(indices[current].fileOffset);
                                ++readHeadersCount;
                                if(currentTransaction == NULL)
                                {
                                    success = false;
                                    break;
                                }
                                headers[current] = currentTransaction;
                            }

                            compare = (*item)->compare(*currentTransaction);
                            if(compare == 0)
                            {
                                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                                  "Found matching transaction reference with non-matching file offset. Block height %d : %s",
                                  (*item)->blockHeight, (*item)->id.hex().text());
                                success = false;
                                break;
                            }

                            if(current == begin) // Not found
                            {
                                --spentTransactionCount;
                                spentOutputCount -= (*item)->outputCount();
                                break;
                            }

                            if(compare > 0)
                                begin = current;
                            else //if(compare < 0)
                                end = current;
                        }
                    }
#ifdef PROFILER_ON
                    removeSpentProfiler.stop();
#endif
                }
            }
            else if((*item)->isNew() || (*item)->mightNeedIndexed())
            {
#ifdef PROFILER_ON
                indexInsertProfiler.start();
#endif
                if((*item)->isNew()) // Add to "all" indices (not sorted)
                    allIndices.push_back(IndexEntry((*item)));

                // For new transactions perform insert sort into existing unspent indices.
                // This costs more processor time to do the insert for every new item.
                // This saves file reads by not requiring a read of every existing indice like a merge sort
                //   would.
                if(indices.size () == 0)
                {
                    // Add as only item
                    indices.push_back(IndexEntry((*item)));
                    headers.push_back(*item);
                    if(!(*item)->isNew())
                    {
                        ++addedTransactionCount;
                        addedOutputCount += (*item)->outputCount();
                    }
                    (*item)->clearNew();
                    (*item)->clearMightNeedIndexed();
                    continue;
                }

                // Check first entry
                currentTransaction = headers.front();
                if(currentTransaction == NULL)
                {
                    // Fetch transaction data
                    currentTransaction = pullTransactionHeader(indices.front().fileOffset);
                    ++readHeadersCount;
                    if(currentTransaction == NULL)
                    {
                        success = false;
#ifdef PROFILER_ON
                        indexInsertProfiler.stop();
#endif
                        break;
                    }
                    headers.front() = currentTransaction;
                }

                compare = (*item)->compare(*currentTransaction);
                if(compare < 0)
                {
                    // Insert as first
                    indices.insert(indices.begin(), IndexEntry((*item)));
                    (*item)->clearNew();
                    (*item)->clearMightNeedIndexed();
                    headers.insert(headers.begin(), *item);
#ifdef PROFILER_ON
                    indexInsertProfiler.stop();
#endif
                    continue;
                }

                if(compare == 0)
                {
                    // Item already indexed
                    if((*item)->isNew())
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed to insert index. Item already indexed as first item. Block height %d : %s",
                          (*item)->blockHeight, (*item)->id.hex().text());
                        success = false;
#ifdef PROFILER_ON
                        indexInsertProfiler.stop();
#endif
                        break;
                    }
                    else
                        continue;
                }

                // Check last entry
                currentTransaction = headers.back();
                if(currentTransaction == NULL)
                {
                    // Fetch transaction data
                    currentTransaction = pullTransactionHeader(indices.back().fileOffset);
                    ++readHeadersCount;
                    if(currentTransaction == NULL)
                    {
                        success = false;
#ifdef PROFILER_ON
                        indexInsertProfiler.stop();
#endif
                        break;
                    }
                    headers.back() = currentTransaction;
                }

                compare = (*item)->compare(*currentTransaction);
                if(compare > 0)
                {
                    // Add to end
                    indices.push_back(IndexEntry((*item)));
                    (*item)->clearNew();
                    (*item)->clearMightNeedIndexed();
                    headers.push_back(*item);
#ifdef PROFILER_ON
                    indexInsertProfiler.stop();
#endif
                    continue;
                }

                if(compare == 0)
                {
                    // Item already indexed
                    if((*item)->isNew())
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed to insert index. Item already indexed as last item. Block height %d : %s",
                          (*item)->blockHeight, (*item)->id.hex().text());
                        success = false;
#ifdef PROFILER_ON
                        indexInsertProfiler.stop();
#endif
                        break;
                    }
                    else
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
                    currentTransaction = headers[current];
                    if(currentTransaction == NULL)
                    {
                        // Fetch transaction data
                        currentTransaction = pullTransactionHeader(indices[current].fileOffset);
                        ++readHeadersCount;
                        if(currentTransaction == NULL)
                        {
                            success = false;
                            break;
                        }
                        headers[current] = currentTransaction;
                    }

                    compare = (*item)->compare(*currentTransaction);
                    if(compare == 0)
                    {
                        // Item already indexed
                        if((*item)->isNew())
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                              "Failed to insert previously spent index. Already indexed. Block height %d : %s",
                              (*item)->blockHeight, (*item)->id.hex().text());
                            (*item)->print(ArcMist::Log::ERROR);
                            success = false;
                        }
                        break; // Break from binary insert loop
                    }

                    if(current == begin)
                    {
                        if(!(*item)->isNew())
                        {
                            ++addedTransactionCount;
                            addedOutputCount += (*item)->outputCount();
                        }

                        if(compare > 0)
                        {
                            // Insert after current
#ifdef PROFILER_ON
                            dataInsertProfiler.start();
#endif
                            index = indices.begin();
                            index += current + 1;
                            indices.insert(index, IndexEntry((*item)));
                            (*item)->clearNew();
                            (*item)->clearMightNeedIndexed();

                            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                              // "Inserted after : %s", headers[current]->id.hex().text());

                            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                              // "Inserted index : %s", (*item)->id.hex().text());

                            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                              // "Inserted befor : %s", headers[current+1]->id.hex().text());

                            header = headers.begin();
                            header += current + 1;
                            headers.insert(header, *item);
#ifdef PROFILER_ON
                            dataInsertProfiler.stop();
#endif
                            break;
                        }
                        else //if(compare < 0)
                        {
                            // Insert before current
#ifdef PROFILER_ON
                            dataInsertProfiler.start();
#endif
                            index = indices.begin();
                            index += current;
                            indices.insert(index, IndexEntry((*item)));
                            (*item)->clearNew();
                            (*item)->clearMightNeedIndexed();

                            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                              // "Inserted after : %s", headers[current-1]->id.hex().text());

                            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                              // "Inserted index : %s", (*item)->id.hex().text());

                            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                              // "Inserted befor : %s", headers[current]->id.hex().text());

                            header = headers.begin();
                            header += current;
                            headers.insert(header, *item);
#ifdef PROFILER_ON
                            dataInsertProfiler.stop();
#endif
                            break;
                        }
                    }

                    if(compare > 0)
                        begin = current;
                    else //if(compare < 0)
                        end = current;
                }
#ifdef PROFILER_ON
                indexInsertProfiler.stop();
#endif
            }
        }

#ifdef PROFILER_ON
        ArcMist::Profiler deleteHeaderProfiler("Outputs Save Delete Header");
#endif
        // Delete any allocated headers
        for(header=headers.begin();header!=headers.end();++header)
            if(*header != NULL && (*header)->isHeader())
                delete *header;
        headers.clear();
#ifdef PROFILER_ON
        deleteHeaderProfiler.stop();
#endif

        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
          // "Read %d/%d transaction headers. Added %d transactions. Removed %d transactions",
          // readHeadersCount, previousIndices, addedTransactionCount, removedTransactionCount);

#ifdef PROFILER_ON
        updateIndexProfiler.stop();
#endif

        if(success)
        {
#ifdef PROFILER_ON
            ArcMist::Profiler writeIndexProfiler("Outputs Save Write Index");
#endif
            // Rewrite .index file with all transaction indices
            filePathName.writeFormatted("%s%s%02x.index", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
            ArcMist::FileOutputStream *indexOutputFile = new ArcMist::FileOutputStream(filePathName, true);
            for(setOffset=0;setOffset<INDICE_SET_COUNT;++setOffset)
            {
                // Write set of indices
                indiceSet = allIndices.dataSet(setOffset);
                indexOutputFile->write(indiceSet->data(), indiceSet->size() * sizeof(IndexEntry));
            }
            delete indexOutputFile;

            // Reopen .unspent index file as an output stream
            delete mUnspentFile;
            mUnspentFile = NULL;
            filePathName.writeFormatted("%s%s%02x.unspent", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
            ArcMist::FileOutputStream *unspentOutFile = new ArcMist::FileOutputStream(filePathName, true);

            // Write the new unspent index
            unspentOutFile->writeUnsignedInt(mTransactionCount + addedTransactionCount - removedTransactionCount - spentTransactionCount);
            unspentOutFile->writeUnsignedInt(mOutputCount + addedOutputCount - removedOutputCount - spentOutputCount);
            for(setOffset=0;setOffset<INDICE_SET_COUNT;++setOffset)
            {
                // Write set of indices
                indiceSet = indices.dataSet(setOffset);
                unspentOutFile->write(indiceSet->data(), indiceSet->size() * sizeof(IndexEntry));
            }

            // Reopen .unspent index file as an input stream
            delete unspentOutFile;
            filePathName.writeFormatted("%s%s%02x.unspent", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
            mUnspentFile = new ArcMist::FileInputStream(filePathName);
#ifdef PROFILER_ON
            writeIndexProfiler.stop();
#endif

#ifdef PROFILER_ON
            ArcMist::Profiler cleanProfiler("Outputs Save Cleanup");
#endif
            mCache.drop(pDropBlockHeight, mCacheOutputCount);
            saveCache(pDropBlockHeight);

            // Assert the counts still match (otherwise something went wrong)
            if(mTransactionCount + addedTransactionCount - removedTransactionCount - spentTransactionCount != indices.size())
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Output set index %02x update counts not adding up. Current index count %d, previous/added/spent/removed %d/%d/%d/%d",
                  mID, indices.size(), mTransactionCount, addedTransactionCount, spentTransactionCount, removedTransactionCount);
                success = false;
            }

            // Update counts
            mTransactionCount += addedTransactionCount;
            mTransactionCount -= removedTransactionCount;
            mTransactionCount -= spentTransactionCount;
            mOutputCount += addedOutputCount;
            mOutputCount -= removedOutputCount;
            mOutputCount -= spentOutputCount;

            // Reinitialize samples
            initializeSamples();
#ifdef PROFILER_ON
            cleanProfiler.stop();
#endif
        }

        mLock.writeUnlock();
        return success;
    }

    unsigned int OutputSet::pullBlocks(unsigned int pBlockHeight, bool pUnspentOnly)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Pull Blocks");
#endif
        if(!mDataFile->isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Data file failed in pull blocks");
            return 0;
        }

        // Read .index file with all transaction indices
        ArcMist::String filePathName;
        filePathName.writeFormatted("%s%s%02x.index", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        ArcMist::DistributedVector<IndexEntry> allIndices(INDICE_SET_COUNT);
        ArcMist::FileInputStream *indexInputFile = new ArcMist::FileInputStream(filePathName);
        IndexEntry index;
        TransactionReference *nextTransaction;
        try
        {
            nextTransaction = new TransactionReference();
        }
        catch(std::bad_alloc &pBadAlloc)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Bad allocation (Pull Blocks Initial) : %s", pBadAlloc.what());
            delete indexInputFile;
            return 0;
        }
        unsigned int itemsAdded = 0;
        while(indexInputFile->remaining())
        {
            index.read(indexInputFile);
            mDataFile->setReadOffset(index.fileOffset);
            if(nextTransaction->read(mDataFile) &&
              (nextTransaction->blockHeight >= pBlockHeight || nextTransaction->spentBlockHeight() >= pBlockHeight) &&
              (!pUnspentOnly || nextTransaction->hasUnspentOutputs()) &&
              mCache.insertSorted(nextTransaction))
            {
                nextTransaction->setMightNeedIndexed();

                ++itemsAdded;
                mCacheOutputCount += nextTransaction->outputCount();
                try
                {
                    nextTransaction = new TransactionReference();
                }
                catch(std::bad_alloc &pBadAlloc)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Bad allocation (Pull Blocks) : %s", pBadAlloc.what());
                    delete indexInputFile;
                    return itemsAdded;
                }
            }
        }

        delete indexInputFile;
        delete nextTransaction;
        return itemsAdded;
    }

    unsigned int OutputSet::pullLinear(const ArcMist::Hash &pTransactionID)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Pull Linear");
#endif
        if(mTransactionCount == 0)
            return 0;

        if(!mDataFile->isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Data file failed in pull linear");
            return 0;
        }

        // Linear search
        IndexEntry index;
        ArcMist::Hash hash(32);
        unsigned int itemsAdded;
        bool first = true;
        unsigned int offset = 0;

        mUnspentFile->setReadOffset(HEADER_SIZE);

        while(mUnspentFile->remaining())
        {
            index.read(mUnspentFile);
            mDataFile->setReadOffset(index.fileOffset);
            if(!hash.read(mDataFile))
                return 0;
            if(first)
            {
                first = false;
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  "First : %s", hash.hex().text());
            }
            if(hash == pTransactionID)
                break;
            if(hash.getByte(31) == pTransactionID.getByte(31))
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  "Linear %d : %s", offset, hash.hex().text());

            ++offset;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
          "Last : %s", hash.hex().text());

        TransactionReference *nextTransaction = new TransactionReference();

        mUnspentFile->setReadOffset(mUnspentFile->readOffset() - sizeof(IndexEntry));
        while(mUnspentFile->remaining())
        {
            index.read(mUnspentFile);
            mDataFile->setReadOffset(index.fileOffset);
            if(!nextTransaction->readMatchingID(pTransactionID, mDataFile))
                break;
            if(mCache.insertSorted(nextTransaction))
            {
                ++itemsAdded;
                mCacheOutputCount += nextTransaction->outputCount();
                nextTransaction = new TransactionReference();
            }
        }

        delete nextTransaction;
        return itemsAdded;
    }

    void OutputSet::initializeSamples()
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Initialize Samples");
#endif
        mSamplesLoaded = false;

        if(!mDataFile->isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Data file failed in load samples");
            return;
        }

        ArcMist::stream_size delta = mTransactionCount / SAMPLE_SIZE;
        if(delta < 1)
            return;

        if(mSamples == NULL)
        {
            try
            {
                mSamples = new SampleEntry[SAMPLE_SIZE];
            }
            catch(std::bad_alloc &pBadAlloc)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Bad allocation (Load Samples) : %s", pBadAlloc.what());
                return;
            }
        }

        // Populate samples
        SampleEntry *sample = mSamples;
        mUnspentFile->setReadOffset(HEADER_SIZE);
        ArcMist::stream_size indexOffset = HEADER_SIZE;
        for(unsigned int i=0;i<SAMPLE_SIZE-1;++i)
        {
            sample->indexOffset = indexOffset;
            sample->hash.clear();
            indexOffset += (delta * sizeof(IndexEntry));
            ++sample;
        }

        // Populate last sample
        mSamples[SAMPLE_SIZE-1].indexOffset = HEADER_SIZE + ((mTransactionCount - 1) * sizeof(IndexEntry));
        mSamples[SAMPLE_SIZE-1].hash.clear();

        mSamplesLoaded = true;
    }

    bool OutputSet::loadSample(unsigned int pSampleOffset)
    {
        SampleEntry &sample = mSamples[pSampleOffset];
        if(sample.hash.isEmpty())
        {
            IndexEntry index;
            mUnspentFile->setReadOffset(sample.indexOffset);
            if(!index.read(mUnspentFile))
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to read sample index at offset %llu", sample.indexOffset);
                return false;
            }
            mDataFile->setReadOffset(index.fileOffset);
            if(!sample.hash.read(mDataFile, 32))
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to read sample hash at data offset %llu", index.fileOffset);
                return false;
            }
        }
        return true;
    }

    bool OutputSet::findSample(const ArcMist::Hash &pTransactionID, ArcMist::stream_size &pBegin, ArcMist::stream_size &pEnd)
    {
        if(mSamplesLoaded)
        {
            // Check if is before the first
            if(!loadSample(0))
                return false;
            int compare = mSamples[0].hash.compare(pTransactionID);
            if(compare > 0)
                return false;
            else if(compare == 0)
            {
                pBegin = mSamples[0].indexOffset;
                pEnd   = mSamples[0].indexOffset;
                return true;
            }
            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              // "First : %s", mSamples[0].hash.hex().text());

            // Check if it is after the last
            if(!loadSample(SAMPLE_SIZE-1))
                return false;
            compare = mSamples[SAMPLE_SIZE-1].hash.compare(pTransactionID);
            if(compare < 0)
                return false;
            else if(compare == 0)
            {
                pBegin = mSamples[SAMPLE_SIZE-1].indexOffset;
                pEnd   = mSamples[SAMPLE_SIZE-1].indexOffset;
                return true;
            }
            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              // "Last : %s", mSamples[SAMPLE_SIZE - 1].hash.hex().text());

            // Binary search the samples
            unsigned int sampleBegin = 0;
            unsigned int sampleEnd = SAMPLE_SIZE - 1;
            unsigned int sampleCurrent;

            while(true)
            {
                sampleCurrent = (sampleBegin + sampleEnd) / 2;
                // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  // "Sample : %s", mSamples[sampleCurrent].hash.hex().text());

                if(sampleCurrent == sampleBegin || sampleCurrent == sampleEnd)
                    break;

                if(!loadSample(sampleCurrent))
                    return false;

                // Determine which half the desired item is in
                compare = pTransactionID.compare(mSamples[sampleCurrent].hash);
                if(compare > 0)
                    sampleBegin = sampleCurrent;
                else if(compare < 0)
                    sampleEnd = sampleCurrent;
                else
                {
                    sampleBegin = sampleCurrent;
                    sampleEnd = sampleCurrent;
                    break;
                }
            }

            // Setup index binary search on sample subset of indices
            pBegin = mSamples[sampleBegin].indexOffset;
            pEnd = mSamples[sampleEnd].indexOffset;
        }
        else
        {
            // Setup index binary search on all indices
            pBegin = HEADER_SIZE;
            pEnd   = HEADER_SIZE + ((mTransactionCount - 1) * sizeof(IndexEntry));
        }

        return true;
    }

    TransactionReference *OutputSet::pull(const ArcMist::Hash &pTransactionID, unsigned int &pItemsPulled)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Pull");
#endif
        if(mTransactionCount == 0)
            return NULL;

        int compare;
        IndexEntry index;
        ArcMist::Hash hash(32);
        ArcMist::stream_size first = HEADER_SIZE, begin, end, current;

        if(!mDataFile->isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Data file failed in pull");
            return NULL;
        }

        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
          // "Pull : %s", pTransactionID.hex().text());
        if(!findSample(pTransactionID, begin, end))
            return NULL; // Transaction id not within set

        if(begin == end)
            current = begin; // transaction ID was in sample set
        else
        {
            // Binary search the file indices
            while(true)
            {
                // Break the set in two halves
                current = (end - begin) / 2;
                current -= current % sizeof(IndexEntry);
                current += begin;

                if(current == begin)
                {
                    // Read the item
                    mUnspentFile->setReadOffset(current);
                    index.read(mUnspentFile);
                    mDataFile->setReadOffset(index.fileOffset);
                    if(!hash.read(mDataFile))
                        return NULL;

                    if(pTransactionID == hash)
                        break;
                    else if(current != end)
                    {
                        current = end;
                        mUnspentFile->setReadOffset(current);
                        index.read(mUnspentFile);
                        mDataFile->setReadOffset(index.fileOffset);
                        if(!hash.read(mDataFile))
                            return NULL;

                        if(pTransactionID == hash)
                            break;
                        else
                            return NULL;
                    }
                    else
                        return NULL;
                }

                // Read the middle item
                mUnspentFile->setReadOffset(current);
                index.read(mUnspentFile);
                mDataFile->setReadOffset(index.fileOffset);
                if(!hash.read(mDataFile))
                    return NULL;
                // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  // "Binary : %s", hash.hex().text());

                // Determine which half the desired item is in
                compare = pTransactionID.compare(hash);
                if(compare > 0)
                    begin = current;
                else if(compare < 0)
                    end = current;
                else
                    break;
            }
        }

        // Match likely found
        // Loop backwards to find the first matching
        while(current > first)
        {
            current -= sizeof(IndexEntry);
            mUnspentFile->setReadOffset(current);
            index.read(mUnspentFile);
            mDataFile->setReadOffset(index.fileOffset);
            if(!hash.read(mDataFile))
                return NULL;

            if(pTransactionID != hash)
            {
                current += sizeof(IndexEntry);
                break;
            }
        }

        // Read in all matching
        TransactionReference *result = NULL;
        TransactionReference *nextTransaction = new TransactionReference();
        while(current <= end)
        {
            mUnspentFile->setReadOffset(current);
            index.read(mUnspentFile);
            mDataFile->setReadOffset(index.fileOffset);
            if(!nextTransaction->readMatchingID(pTransactionID, mDataFile))
                break;

            if(mCache.insertSorted(nextTransaction))
            {
                if(result == NULL)
                    result = nextTransaction;
                ++pItemsPulled;
                mCacheOutputCount += nextTransaction->outputCount();
                nextTransaction = new TransactionReference();
            }
            current += sizeof(IndexEntry);
        }
        delete nextTransaction;
        return result;
    }

    TransactionReference *OutputSet::find(const ArcMist::Hash &pTransactionID, uint32_t pIndex)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Find");
#endif
        OutputReference *output;
        unsigned int blockHeight = 0xffffffff;
        unsigned int outputSpentHeight = 0xffffffff;

        // Look in cached
        mLock.readLock();
        for(TransactionReferenceList::iterator item=mCache.firstMatching(pTransactionID);item!=mCache.end();++item)
            if((*item)->id == pTransactionID)
            {
                if((*item)->markedDelete())
                    continue;

                blockHeight = (*item)->blockHeight;
                output = (*item)->outputAt(pIndex);
                if(output != NULL)
                {
                    if(output->spentBlockHeight == 0)
                    {
                        mLock.readUnlock();
                        return *item;
                    }
                    else
                        outputSpentHeight = output->spentBlockHeight;
                }
            }
            else
                break;
        mLock.readUnlock();

        // Pull from file
        mLock.writeLock("Pull");
        unsigned int foundCount = 0;
        bool deleted = false;
        TransactionReference *firstPulled = pull(pTransactionID, foundCount);

        // Check first pulled transaction for match
        if(firstPulled != NULL)
        {
            blockHeight = firstPulled->blockHeight;

            if(!firstPulled->markedDelete())
            {
                output = firstPulled->outputAt(pIndex);
                if(output != NULL)
                {
                    if(output->spentBlockHeight == 0)
                    {
                        mLock.writeUnlock();
                        return firstPulled;
                    }
                    else
                        outputSpentHeight = output->spentBlockHeight;
                }
            }
            else
            {
                deleted = true;

                for(TransactionReferenceList::iterator pulled=mCache.firstMatching(pTransactionID);pulled!=mCache.end();++pulled)
                    if((*pulled)->id == pTransactionID)
                    {
                        blockHeight = (*pulled)->blockHeight;

                        if((*pulled)->markedDelete())
                            continue;

                        output = (*pulled)->outputAt(pIndex);
                        if(output != NULL)
                        {
                            if(output->spentBlockHeight == 0)
                            {
                                mLock.writeUnlock();
                                return *pulled;
                            }
                            else
                                outputSpentHeight = output->spentBlockHeight;
                        }
                    }
                    else
                        break;
            }
        }

        mLock.writeUnlock();

        if(outputSpentHeight != 0xffffffff)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Output spent at block height %d : index %d - %s", outputSpentHeight, pIndex,
              pTransactionID.hex().text());
        else if(blockHeight != 0xffffffff)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Transaction found at block height %d, but output not found : index %d - %s", blockHeight,
              pIndex, pTransactionID.hex().text());
        else if(deleted)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Transaction found at block height %d, but was deleted : index %d - %s", blockHeight,
              pIndex, pTransactionID.hex().text());
        else
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME, "Transaction not found : %s",
              pTransactionID.hex().text());
        return NULL;
    }

    TransactionReference *OutputSet::find(const ArcMist::Hash &pTransactionID)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Find ID");
#endif
        // Look in cached
        mLock.readLock();
        for(TransactionReferenceList::iterator item=mCache.firstMatching(pTransactionID);item!=mCache.end();++item)
            if((*item)->id == pTransactionID)
            {
                if((*item)->markedDelete())
                    continue;

                mLock.readUnlock();
                return *item;
            }
            else
                break;
        mLock.readUnlock();

        // Pull from file
        mLock.writeLock("Pull");
        unsigned int foundCount = 0;
        TransactionReference *firstPulled = pull(pTransactionID, foundCount);

        // Check first pulled transaction for match
        if(firstPulled != NULL)
        {
            if(!firstPulled->markedDelete())
            {
                mLock.writeUnlock();
                return firstPulled;
            }

            // Check if there is a match that is not marked for delete
            for(TransactionReferenceList::iterator item=mCache.firstMatching(pTransactionID);item!=mCache.end();++item)
                if((*item)->id == pTransactionID)
                {
                    if((*item)->markedDelete())
                        continue;

                    mLock.writeUnlock();
                    return *item;
                }
                else
                    break;
        }

        mLock.writeUnlock();
        return NULL;
    }

    void OutputSet::add(TransactionReference *pTransaction)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Add");
#endif
        mCache.insertSorted(pTransaction);
        mCacheOutputCount += pTransaction->outputCount();
    }

    void OutputSet::commit(TransactionReference *pReference, std::vector<Output *> &pOutputs)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Commit");
#endif
        if(!mDataFile->isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Data file failed in commit");
            return;
        }

        mLock.writeLock("Commit");
        pReference->commit(pOutputs);
        mLock.writeUnlock();
    }

    void OutputSet::revert(unsigned int pBlockHeight, bool pHard)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Revert");
#endif
        if(pHard)
            pullBlocks(pBlockHeight, false);

        mLock.writeLock("Commit");
        for(TransactionReferenceList::iterator item=mCache.begin();item!=mCache.end();++item)
            (*item)->revert(pBlockHeight);
        mLock.writeUnlock();
    }

    TransactionOutputPool::TransactionOutputPool()
    {
        mValid = true;
        mModified = false;
        mNextBlockHeight = 0;
    }

    unsigned int TransactionOutputPool::transactionCount() const
    {
        unsigned int result = 0;
        const OutputSet *set = mSets;
        for(unsigned int i=0;i<SET_COUNT;i++)
        {
            result += set->transactionCount();
            ++set;
        }
        return result;
    }

    unsigned int TransactionOutputPool::outputCount() const
    {
        unsigned int result = 0;
        const OutputSet *set = mSets;
        for(unsigned int i=0;i<SET_COUNT;i++)
        {
            result += set->outputCount();
            ++set;
        }
        return result;
    }

    unsigned long long TransactionOutputPool::size() const
    {
        unsigned long result = 0;
        const OutputSet *set = mSets;
        for(unsigned int i=0;i<SET_COUNT;i++)
        {
            result += set->size();
            ++set;
        }
        return result;
    }

    unsigned long long TransactionOutputPool::cachedSize() const
    {
        unsigned long long result = 0;
        const OutputSet *set = mSets;
        for(unsigned int i=0;i<SET_COUNT;i++)
        {
            result += set->cachedSize();
            ++set;
        }
        return result;
    }

    const unsigned int TransactionOutputPool::BIP0030_HEIGHTS[BIP0030_HASH_COUNT] = { 91842, 91880 };
    const ArcMist::Hash TransactionOutputPool::BIP0030_HASHES[BIP0030_HASH_COUNT] =
    {
        ArcMist::Hash("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"),
        ArcMist::Hash("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")
    };

    bool TransactionOutputPool::checkDuplicates(const std::vector<Transaction *> &pBlockTransactions,
      unsigned int pBlockHeight, const ArcMist::Hash &pBlockHash)
    {
        TransactionReference *transactionReference;
        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
        {
            // Get references set for transaction ID
            transactionReference = mSets[(*transaction)->hash.lookup8()].find((*transaction)->hash);
            if(transactionReference != NULL && transactionReference->hasUnspentOutputs())
            {
                bool exceptionFound = false;
                for(unsigned int i=0;i<BIP0030_HASH_COUNT;++i)
                    if(BIP0030_HEIGHTS[i] == pBlockHeight && BIP0030_HASHES[i] == pBlockHash)
                        exceptionFound = true;
                if(exceptionFound)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                      "BIP-0030 Exception for duplicate transaction ID at block height %d : transaction %s",
                      transactionReference->blockHeight, (*transaction)->hash.hex().text());
                }
                else
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Transaction from block height %d has unspent outputs : %s", transactionReference->blockHeight,
                      (*transaction)->hash.hex().text());
                    return false;
                }
            }
        }

        return true;
    }

    // Add all the outputs from a block (cached since they have no block file IDs or offsets yet)
    bool TransactionOutputPool::add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Add Block");
#endif
        mToCommit.clearNoDelete();

        if(pBlockHeight != mNextBlockHeight)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't add transactions for non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight);
            return false;
        }

        TransactionReference *transactionReference;
        unsigned int count = 0;
        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
        {
            // Get references set for transaction ID
            transactionReference = new TransactionReference((*transaction)->hash, pBlockHeight, (*transaction)->outputs.size());
            mToCommit.push_back(transactionReference);
            mSets[(*transaction)->hash.lookup8()].add(transactionReference);
            ++count;
        }

        return true;
    }

    bool TransactionOutputPool::commit(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
        if(!mValid)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Can't commit invalid unspent pool");
            return false;
        }

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Commit");
#endif
        if(pBlockHeight != mNextBlockHeight)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't commit non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight - 1);
            return false;
        }

        if(mToCommit.size() != pBlockTransactions.size())
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't commit non matching transaction set");
            return false;
        }

        TransactionReferenceList::iterator reference = mToCommit.begin();
        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
        {
            if((*reference)->id == (*transaction)->hash)
            {
                mSets[(*reference)->id.lookup8()].commit(*reference, (*transaction)->outputs);
                ++reference;
            }
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Can't commit non matching transaction");
                return false;
            }
        }

        mToCommit.clearNoDelete();
        ++mNextBlockHeight;
        mModified = true;
        return true;
    }

    bool TransactionOutputPool::revert(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
        if(!mValid)
            return false;

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Revert");
#endif
        if(mToCommit.size() > 0)
        {
            if(pBlockHeight != mNextBlockHeight)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Can't revert non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight);
                return false;
            }
        }
        else if(pBlockHeight != mNextBlockHeight - 1)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't revert non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight - 1);
            return false;
        }

        std::vector<Input *>::const_iterator input;
        TransactionReference *reference;
        OutputReference *outputReference;
        bool success = true;
        // Process transactions in reverse since they can unspend previous transactions in the same block
        for(std::vector<Transaction *>::const_reverse_iterator transaction=pBlockTransactions.rbegin();transaction!=pBlockTransactions.rend();++transaction)
        {
            // Unspend inputs
            for(input=(*transaction)->inputs.begin();input!=(*transaction)->inputs.end();++input)
                if((*input)->outpoint.index != 0xffffffff) // Coinbase input has no outpoint transaction
                {
                    reference = find((*input)->outpoint.transactionID);
                    if(reference == NULL)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Transaction not found to revert spend : %s", (*input)->outpoint.transactionID.hex().text());
                        success = false;
                        break;
                    }

                    outputReference = reference->outputAt((*input)->outpoint.index);
                    if(outputReference == NULL)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Transaction output not found to revert spend : index %d %s", (*input)->outpoint.index,
                          (*input)->outpoint.transactionID.hex().text());
                        success = false;
                        break;
                    }

                    outputReference->spentBlockHeight = 0;
                }

            // Remove transaction
            reference = find((*transaction)->hash);
            if(reference == NULL)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Transaction not found to remove for revert : %s", (*transaction)->hash.hex().text());
                success = false;
                break;
            }

            reference->setDelete();
        }

        mToCommit.clearNoDelete();
        if(success)
            --mNextBlockHeight;
        mModified = true;
        return success;
    }

    bool TransactionOutputPool::bulkRevert(unsigned int pBlockHeight, bool pHard)
    {
        if(!mValid)
            return false;

        if(!pHard && pBlockHeight != mNextBlockHeight - 1)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't revert non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight - 1);
            return false;
        }

        if(pBlockHeight >= mNextBlockHeight)
            return true; // No revert needed

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Revert");
#endif

        if(pBlockHeight >= mSavedBlockHeight)
            pHard = false;

        OutputSet *set = mSets;
        for(unsigned int i=0;i<SET_COUNT;i++)
        {
            set->revert(pBlockHeight, pHard);
            ++set;
        }

        mToCommit.clearNoDelete();
        mNextBlockHeight = pBlockHeight + 1;
        mModified = true;
        return true;
    }

    TransactionReference *TransactionOutputPool::findUnspent(const ArcMist::Hash &pTransactionID, uint32_t pIndex)
    {
        if(!mValid)
            return NULL;

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Find Unspent");
#endif
        TransactionReference *result = mSets[pTransactionID.lookup8()].find(pTransactionID, pIndex);
        mModified = true;
        return result;
    }

    TransactionReference *TransactionOutputPool::find(const ArcMist::Hash &pTransactionID)
    {
        if(!mValid)
            return NULL;

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Find");
#endif
        TransactionReference *result = mSets[pTransactionID.lookup8()].find(pTransactionID);
        mModified = true;
        return result;
    }

    // Mark an output as spent
    void TransactionOutputPool::spend(TransactionReference *pReference, unsigned int pIndex, unsigned int pBlockHeight)
    {
        pReference->spendInternal(pIndex, pBlockHeight);
        mModified = true;
    }

    unsigned int TransactionOutputPool::loadCache(unsigned int pBlockHeight)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Caching unspent transaction outputs after block %d", pBlockHeight);

        uint32_t lastReport = getTime();
        unsigned int itemsAdded = 0;
        OutputSet *set = mSets;
        for(unsigned int i=0;i<SET_COUNT;i++)
        {
            if(getTime() - lastReport > 10)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Caching is %2d%% Complete", (int)(((float)i / (float)SET_COUNT) * 100.0f));
                lastReport = getTime();
            }
            itemsAdded += set->loadCache(pBlockHeight);
            ++set;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Cached %d transactions (%d KiB)", itemsAdded, cachedSize() / 1024);
        return itemsAdded;
    }

    unsigned int TransactionOutputPool::pullBlocks(unsigned int pBlockHeight)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Pulling block transactions after block %d", pBlockHeight);

        uint32_t lastReport = getTime();
        unsigned int itemsAdded = 0;
        OutputSet *set = mSets;
        for(unsigned int i=0;i<SET_COUNT;i++)
        {
            if(getTime() - lastReport > 10)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Pulling block transactions is %2d%% Complete", (int)(((float)i / (float)SET_COUNT) * 100.0f));
                lastReport = getTime();
            }
            itemsAdded += set->pullBlocks(pBlockHeight);
            ++set;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Cached %d transactions (%d KiB)", itemsAdded, cachedSize() / 1024);
        return itemsAdded;
    }

    bool TransactionOutputPool::load(const char *pPath, unsigned int pCacheAge, bool pPreCache)
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Loading transaction outputs");
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
          "Using cache block age %d", pCacheAge);

        mValid = true;
        mCacheAge = pCacheAge;
        ArcMist::String filePath = pPath;
        filePath.pathAppend("outputs");
        ArcMist::createDirectory(filePath);

        for(unsigned int i=0;i<SET_COUNT;++i)
            if(!mSets[i].setup(i, filePath))
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to setup set %d", i);
                mValid = false;
                return false;
            }

        ArcMist::String filePathName = filePath;
        filePathName.pathAppend("height");
        if(!ArcMist::fileExists(filePathName))
            mNextBlockHeight = 0;
        else
        {
            ArcMist::FileInputStream file(filePathName);
            if(!file.isValid())
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to open height file to load");
                mValid = false;
                return false;
            }

            // Read block height
            mNextBlockHeight = file.readUnsignedInt();
        }

        if(mValid)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
              "Loaded %d/%d transactions/outputs (%d KiB) at block height %d", transactionCount(),
              outputCount(), size() / 1024, mNextBlockHeight - 1);
            mSavedBlockHeight = mNextBlockHeight;

            if(pPreCache)
            {
                try
                {
                    loadCache(cacheBlockHeight());
                }
                catch(std::bad_alloc &pBadAlloc)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Bad allocation (Pull Blocks Uncaught) : %s", pBadAlloc.what());
                    mValid = false;
                }
            }
        }
        else
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Failed to load transaction outputs");
        return mValid;
    }

    bool TransactionOutputPool::purge(const char *pPath, unsigned int pThreshold)
    {
        if(cachedSize() > pThreshold)
            return save(pPath);
        return true;
    }

    bool TransactionOutputPool::save(const char *pPath)
    {
        if(!mValid)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Can't save invalid unspent pool");
            return false;
        }

        if(!mModified)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Not saving unspent transaction outputs. They weren't modified");
            return true;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Saving transaction outputs at block height %d (%d KiB cached)", mNextBlockHeight - 1,
          cachedSize() / 1024);

        bool success = true;
        ArcMist::String filePathName = pPath;
        filePathName.pathAppend("outputs");
        filePathName.pathAppend("height");
        ArcMist::FileOutputStream file(filePathName, true);
        if(!file.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to open height file to save");
            return false;
        }

        // Block Height
        file.writeUnsignedInt(mNextBlockHeight);
        file.flush();

        uint32_t lastReport = getTime();
        OutputSet *set = mSets;
        for(unsigned int i=0;i<SET_COUNT;i++)
        {
            if(getTime() - lastReport > 10)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Save is %2d%% Complete", (int)(((float)i / (float)SET_COUNT) * 100.0f));
                lastReport = getTime();
            }
            if(!set->save(cacheBlockHeight(), mNextBlockHeight - 1000))
            {
                success = false;
                break;
            }
            ++set;
        }

        if(success)
        {
            mSavedBlockHeight = mNextBlockHeight;
            mModified = false;
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
              "Saved %d/%d transactions/outputs (%d KiB) (%d KiB cached)", transactionCount(), outputCount(),
              size() / 1024, cachedSize() / 1024);
        }
        else
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to save transaction outputs");

        return success;
    }

    bool TransactionOutputPool::test()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "------------- Starting Outputs Tests -------------");

        bool success = true;

        /***********************************************************************************************
         * Check flags
         ***********************************************************************************************/
        TransactionReference transaction;

        transaction.setNew();
        transaction.setModified();
        transaction.setMightNeedIndexed();

        if(transaction.isModified())
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Passed modified flag");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Failed modified flag");
            success = false;
        }

        transaction.clearModified();

        if(!transaction.isModified())
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Passed clear modified flag");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Failed clear modified flag");
            success = false;
        }

        if(transaction.mightNeedIndexed())
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Passed might need indexed flag");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Failed might need indexed flag");
            success = false;
        }

        transaction.clearMightNeedIndexed();

        if(!transaction.mightNeedIndexed())
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Passed clear might need indexed flag");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Failed clear might need indexed flag");
            success = false;
        }

        transaction.clearMightNeedIndexed();

        if(!transaction.mightNeedIndexed())
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Passed redundant clear might need indexed flag");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Failed redundant clear might need indexed flag");
            success = false;
        }

        if(transaction.isNew())
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Passed new flag");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Failed new flag");
            success = false;
        }

        transaction.clearNew();

        if(!transaction.isNew())
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Passed clear new flag");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Failed clear new flag");
            success = false;
        }

        return success;
    }
}
