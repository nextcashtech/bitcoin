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

    bool TransactionReference::readMatchingID(const Hash &pHash, ArcMist::InputStream *pStream)
    {
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

    bool TransactionReference::readOld(ArcMist::InputStream *pHeaderStream, ArcMist::InputStream *pOutputStream)
    {
        // Header
        if(pHeaderStream->remaining() < SIZE)
            return false;

        id.read(pHeaderStream);
        blockHeight = pHeaderStream->readUnsignedInt();
        unsigned int outputFileOffset = pHeaderStream->readUnsignedLong();
        unsigned int outputCount = pHeaderStream->readUnsignedInt();

        // Outputs
        pOutputStream->setReadOffset(outputFileOffset);
        if(pOutputStream->remaining() < OutputReference::SIZE * outputCount)
            return false;

        if(!allocateOutputs(outputCount))
            return false;
        pOutputStream->read(mOutputs, mOutputCount * OutputReference::SIZE);

        clearFlags();
        fileOffset = ArcMist::INVALID_STREAM_SIZE;
        return true;
    }

    bool TransactionReference::read(ArcMist::InputStream *pStream)
    {
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
            fileOffset = pStream->length();

        if(pStream->writeOffset() != fileOffset)
            pStream->setWriteOffset(fileOffset);

        id.write(pStream);
        pStream->writeUnsignedInt(blockHeight);
        pStream->writeUnsignedInt(mOutputCount);
        pStream->write(mOutputs, mOutputCount * OutputReference::SIZE);
        clearModified();
        setWasModified();
        return true;
    }

    bool TransactionReference::writeIndex(ArcMist::OutputStream *pStream)
    {
        IndexEntry entry = this;
        pStream->write(&entry, sizeof(IndexEntry));
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
        if(mOutputs == NULL)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Trying to revert header only transaction : %s", id.hex().text());
            return false;
        }

        bool result = false;
        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
            if(output->spentBlockHeight >= pBlockHeight)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  "Unspending transaction output for block %d : index %d - %s",
                  output->spentBlockHeight, i, id.hex().text());
                output->spentBlockHeight = 0; // Spent at this block height, so "unspend"
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

        ArcMist::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Outputs:");
        OutputReference *output = mOutputs;
        unsigned int index = 0;
        for(unsigned int i=0;i<mOutputCount;++i,++index,++output)
        {
            ArcMist::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Output Reference");
            ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    Index       : %d", index);
            ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    File Offset : %d", output->blockFileOffset);
            ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    Spent       : %d", output->spentBlockHeight);
        }
    }

    bool TransactionReferenceList::insertSorted(TransactionReference *pItem)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Insert Sorted");
#endif
        if(size() == 0 || *back() < *pItem)
        {
            push_back(pItem);
            return true;
        }

        if(*front() > *pItem)
        {
            insert(begin(), pItem);
            return true;
        }

        int compare;
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

                if(**current == *pItem)
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

    TransactionReferenceList::iterator TransactionReferenceList::firstMatching(const Hash &pHash)
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
        std::vector<TransactionReference *> items = *this;
        clearNoDelete();
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

    void TransactionReferenceList::print(unsigned int pID)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Sorted list %02x", pID);

        for(iterator item=begin();item!=end();++item)
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, (*item)->id.hex().text());
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
        mIndexFile = NULL;
        mDataFile = NULL;
        mTransactionCount = 0;
        mOutputCount = 0;
        mCacheOutputCount = 0;
        mSamplesLoaded = false;
        mSamples = NULL;
    }

    OutputSet::~OutputSet()
    {
        if(mIndexFile != NULL)
            delete mIndexFile;
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
        if(mIndexFile != NULL)
            delete mIndexFile;
        mIndexFile = NULL;
        if(mDataFile != NULL)
            delete mDataFile;
        mDataFile = NULL;
    }

    bool OutputSet::setup(unsigned int pID, const char *pFilePath, unsigned int pCacheSize)
    {
        mLock.writeLock("Setup");

        mFilePath = pFilePath;
        ArcMist::String filePathName;
        mID = pID;
        if(mIndexFile != NULL)
            delete mIndexFile;
        mIndexFile = NULL;
        if(mDataFile != NULL)
            delete mDataFile;
        mDataFile = NULL;

        bool created = false;
        filePathName.writeFormatted("%s%s%02x.index", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        if(!ArcMist::fileExists(filePathName))
        {
            // Create file
            ArcMist::FileOutputStream *indexOutFile = new ArcMist::FileOutputStream(filePathName, true);
            indexOutFile->writeUnsignedInt(0);
            mTransactionCount = 0;
            indexOutFile->writeUnsignedInt(0);
            mOutputCount = 0;
            created = true;
            delete indexOutFile;
        }

        mIndexFile = new ArcMist::FileInputStream(filePathName);
        mIndexFile->setReadOffset(0);
        if(!created)
        {
            mTransactionCount = mIndexFile->readUnsignedInt();
            mOutputCount = mIndexFile->readUnsignedInt();
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

        if(!mIndexFile->isValid() || !mDataFile->isValid())
        {
            mLock.writeUnlock();
            return false;
        }

        loadSamples();
        mLock.writeUnlock();
        return true;
    }

    bool OutputSet::readOld(TransactionReferenceList &pList, const char *pHeaderFileName, const char *pOutputsFileName)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Read Old");
#endif
        ArcMist::FileStream headerFile(pHeaderFileName);
        ArcMist::FileStream outputsFile(pOutputsFileName);

        TransactionReference *newReference;
        bool success = true;
        headerFile.setReadOffset(0x100 * sizeof(ArcMist::stream_size));
        while(headerFile.remaining())
        {
            newReference = new TransactionReference();
            if(!newReference->readOld(&headerFile, &outputsFile))
            {
                delete newReference;
                success = false;
                break;
            }
            pList.push_back(newReference);
        }
        return success;
    }

    bool OutputSet::save(unsigned int pDropBlockHeight)
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

        //TODO Possibly skip save if no items have been modified

        bool success = true;

        // Count all added transactions
        unsigned int addedTransactionCount = 0, addedOutputCount = 0;
        unsigned int removedTransactionCount = 0, removedOutputCount = 0;
        for(TransactionReferenceList::iterator item=mCache.begin();item!=mCache.end();++item)
        {
            if((*item)->fileOffset == ArcMist::INVALID_STREAM_SIZE)
            {
                if(!(*item)->markedDelete())
                {
                    ++addedTransactionCount;
                    addedOutputCount += (*item)->outputCount();
                }
            }
            else if((*item)->markedDelete())
            {
                ++removedTransactionCount;
                removedOutputCount += (*item)->outputCount();
            }
        }

        TransactionReferenceList::iterator item;
        std::vector<IndexEntry> indices;
        std::vector<IndexEntry>::iterator index;
        TransactionReferenceList newList;
        TransactionReference *nextTransaction;
        int compare;
        ArcMist::String filePathName;

#ifdef PROFILER_ON
        ArcMist::Profiler readIndexProfiler("Outputs Save Read Index");
#endif
        // Read current index data
        indices.resize(mTransactionCount);
        mIndexFile->setReadOffset(HEADER_SIZE); // Transaction count, output count
        mIndexFile->read(indices.data(), mTransactionCount * sizeof(IndexEntry));

        // Reopen data file as an output stream
        delete mDataFile;
        mDataFile = NULL;
        filePathName.writeFormatted("%s%s%02x.data", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        ArcMist::FileOutputStream *dataOutFile = new ArcMist::FileOutputStream(filePathName);

        // Write all cached transactions (update/append) so they all have file offsets
        for(TransactionReferenceList::iterator item=mCache.begin();item!=mCache.end();++item)
            if(!(*item)->markedDelete())
                (*item)->write(dataOutFile);
        dataOutFile->flush();

        // Reopen data input file
        delete dataOutFile;
        filePathName.writeFormatted("%s%s%02x.data", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        mDataFile = new ArcMist::FileInputStream(filePathName);

#ifdef PROFILER_ON
        readIndexProfiler.stop();
#endif

        // Skip re-sort if no new items have been added or removed (only updated)
        if(addedTransactionCount == 0 && removedTransactionCount == 0)
        {
            // Clear "was modified" flags
            for(TransactionReferenceList::iterator item=mCache.begin();item!=mCache.end();++item)
                (*item)->clearWasModified();

            mLock.writeUnlock();
            return true;
        }

#ifdef PROFILER_ON
        ArcMist::Profiler updateIndexProfiler("Outputs Save Update Index");
#endif
        // Insert new values into index
        nextTransaction = new TransactionReference();
        item = mCache.begin();
        index = indices.begin();
        std::vector<IndexEntry> newIndices;
        unsigned int indexOffset = 1;

        newIndices.reserve(mTransactionCount + addedTransactionCount - removedTransactionCount);

        if(index != indices.end())
        {
            // Read first item header from file
            mDataFile->setReadOffset(index->fileOffset);
            if(!nextTransaction->readHeader(mDataFile))
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to read header at index %d offset %d", indexOffset, index->fileOffset);
                success = false;
            }
        }

        while(index != indices.end() && success)
        {
            if(item == mCache.end())
            {
                // Add most recently read transaction to new index
                newIndices.push_back(*index);
                ++index;
                ++indexOffset;
                if(index == indices.end())
                    break;
                mDataFile->setReadOffset(index->fileOffset);
                if(!nextTransaction->readHeader(mDataFile))
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed to read header at index %d offset %d", indexOffset, index->fileOffset);
                    success = false;
                    break;
                }
            }
            else
            {
                compare = nextTransaction->compare(**item);
                if(compare < 0)
                {
                    // Add most recently read transaction to new index
                    newIndices.push_back(*index);
                    ++index;
                    ++indexOffset;
                    if(index == indices.end())
                        break;
                    mDataFile->setReadOffset(index->fileOffset);
                    if(!nextTransaction->readHeader(mDataFile))
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed to read header at index %d offset %d", indexOffset, index->fileOffset);
                        success = false;
                        break;
                    }
                }
                else if(compare > 0)
                {
                    if(!(*item)->markedDelete())
                        newIndices.push_back(IndexEntry((*item))); // Add cache item to new index
                    ++item;
                }
                else
                {
                    // Item already in cache. Add cache item to new index and go to next item
                    if(!(*item)->markedDelete())
                        newIndices.push_back(IndexEntry((*item)));
                    ++item;

                    ++index;
                    ++indexOffset;
                    if(index == indices.end())
                        break;
                    mDataFile->setReadOffset(index->fileOffset);
                    if(!nextTransaction->readHeader(mDataFile))
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Failed to read header at index %d offset %d", indexOffset, indexOffset, index->fileOffset);
                        success = false;
                        break;
                    }
                }
            }
        }

        delete nextTransaction;

        // Add any remaining cache items to the new index
        while(item != mCache.end())
        {
            if(!(*item)->markedDelete())
                newIndices.push_back(IndexEntry((*item)));
            ++item;
        }

#ifdef PROFILER_ON
        updateIndexProfiler.stop();
#endif

#ifdef PROFILER_ON
        ArcMist::Profiler writeIndexProfiler("Outputs Save Write Index");
#endif
        // Reopen index file as an output stream
        delete mIndexFile;
        mIndexFile = NULL;
        filePathName.writeFormatted("%s%s%02x.index", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        ArcMist::FileOutputStream *indexOutFile = new ArcMist::FileOutputStream(filePathName);

        // Write the new index
        indexOutFile->setWriteOffset(0);
        indexOutFile->writeUnsignedInt(mTransactionCount + addedTransactionCount - removedTransactionCount);
        indexOutFile->writeUnsignedInt(mOutputCount + addedOutputCount - removedOutputCount);
        indexOutFile->write(newIndices.data(), newIndices.size() * sizeof(IndexEntry));

        // Overwrite any extra data at the end of the file
        IndexEntry padIndex;
        padIndex.invalidate();
        while(indexOutFile->writeOffset() < indexOutFile->length())
            padIndex.write(indexOutFile);
        indexOutFile->flush();

        // Reopen index file as an input stream
        delete indexOutFile;
        filePathName.writeFormatted("%s%s%02x.index", mFilePath.text(), ArcMist::PATH_SEPARATOR, mID);
        mIndexFile = new ArcMist::FileInputStream(filePathName);

#ifdef PROFILER_ON
        writeIndexProfiler.stop();
#endif

#ifdef PROFILER_ON
        ArcMist::Profiler dropProfiler("Outputs Save Drop");
#endif
        mCache.drop(pDropBlockHeight, mCacheOutputCount);
#ifdef PROFILER_ON
        dropProfiler.stop();
#endif

        // Assert the counts still match (otherwise something went wrong)
        if(mTransactionCount + addedTransactionCount - removedTransactionCount != newIndices.size())
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Output set index %02x update counts not adding up. Index %d, Transactions/added/removed %d/%d/%d",
              mID, newIndices.size(), mTransactionCount, addedTransactionCount, removedTransactionCount);
            success = false;
        }

        if(success)
        {
            // Update counts
            mTransactionCount += addedTransactionCount;
            mTransactionCount -= removedTransactionCount;
            mOutputCount += addedOutputCount;
            mOutputCount -= removedOutputCount;

            // Reload samples
            loadSamples();

            // Clear "was modified" flags
            for(TransactionReferenceList::iterator item=mCache.begin();item!=mCache.end();++item)
                (*item)->clearWasModified();
        }

        mLock.writeUnlock();
        return success;
    }

    // void OutputSet::print()
    // {
        // // Read current index data
        // IndexEntry index;
        // mIndexFile->setReadOffset(HEADER_SIZE); // Transaction count, output count

        // TransactionReference *nextTransaction = new TransactionReference();
        // for(unsigned int i=0;i<100;i++)
        // {
            // index.read(mIndexFile);
            // mDataFile->setReadOffset(index.fileOffset);
            // if(nextTransaction->read(mDataFile))
                // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  // "Hash : %s", nextTransaction->id.hex().text());
        // }

        // delete nextTransaction;
    // }

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

        // Read current index data
        IndexEntry index;
        mIndexFile->setReadOffset(HEADER_SIZE); // Transaction count, output count

        TransactionReference *nextTransaction;
        try
        {
            nextTransaction = new TransactionReference();
        }
        catch(std::bad_alloc &pBadAlloc)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Bad allocation (Pull Blocks Initial) : %s", pBadAlloc.what());
            return 0;
        }
        unsigned int itemsAdded = 0;
        while(mIndexFile->remaining())
        {
            index.read(mIndexFile);
            mDataFile->setReadOffset(index.fileOffset);
            if(nextTransaction->readAboveBlock(pBlockHeight, mDataFile) &&
              (!pUnspentOnly || nextTransaction->hasUnspentOutputs()) &&
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
                      "Bad allocation (Pull Blocks) : %s", pBadAlloc.what());
                    return itemsAdded;
                }
            }
        }

        delete nextTransaction;
        return itemsAdded;
    }

    unsigned int OutputSet::pullLinear(const Hash &pTransactionID)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Pull");
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
        Hash hash(32);
        unsigned int itemsAdded;
        bool first = true;

        mIndexFile->setReadOffset(HEADER_SIZE);

        while(mIndexFile->remaining())
        {
            index.read(mIndexFile);
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
                  "Linear : %s", hash.hex().text());
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
          "Last : %s", hash.hex().text());

        TransactionReference *nextTransaction = new TransactionReference();

        mIndexFile->setReadOffset(mIndexFile->readOffset() - sizeof(IndexEntry));
        while(mIndexFile->remaining())
        {
            index.read(mIndexFile);
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

    void OutputSet::loadSamples()
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Load Samples");
#endif
        mSamplesLoaded = false;

        if(!mDataFile->isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Data file failed in load samples");
            return;
        }

        unsigned int delta = mTransactionCount / SAMPLE_SIZE;
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

        // Load samples
        IndexEntry index;
        SampleEntry *sample = mSamples;
        mIndexFile->setReadOffset(HEADER_SIZE);
        for(unsigned int i=0;i<SAMPLE_SIZE-1;++i)
        {
            sample->indexOffset = mIndexFile->readOffset();
            if(!index.read(mIndexFile))
                return;

            mDataFile->setReadOffset(index.fileOffset);
            if(!sample->hash.read(mDataFile, 32))
                return;

            mIndexFile->setReadOffset(sample->indexOffset + ((ArcMist::stream_size)delta * sizeof(IndexEntry)));
            ++sample;
        }

        // Get last sample
        mSamples[SAMPLE_SIZE-1].indexOffset = HEADER_SIZE + ((mTransactionCount - 1) * sizeof(IndexEntry));
        mIndexFile->setReadOffset(mSamples[SAMPLE_SIZE-1].indexOffset);
        if(!index.read(mIndexFile))
            return;

        mDataFile->setReadOffset(index.fileOffset);
        if(!mSamples[SAMPLE_SIZE-1].hash.read(mDataFile, 32))
            return;

        mSamplesLoaded = true;
    }

    TransactionReference *OutputSet::pull(const Hash &pTransactionID, unsigned int &pItemsPulled)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Outputs Pull");
#endif
        if(mTransactionCount == 0)
            return NULL;

        int compare;
        IndexEntry index;
        Hash hash(32);
        bool found = false;
        ArcMist::stream_size first = HEADER_SIZE, begin, end, current;

        if(!mDataFile->isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Data file failed in pull");
            return NULL;
        }

        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
          // "Pull : %s", pTransactionID.hex().text());

        if(mSamplesLoaded)
        {
            // Check if is before the first
            compare = mSamples[0].hash.compare(pTransactionID);
            if(compare > 0)
                return NULL;
            else if(compare == 0)
            {
                found = true;
                current = mSamples[0].indexOffset;
            }
            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              // "First : %s", mSamples[0].hash.hex().text());

            // Check if it is after the last
            compare = mSamples[SAMPLE_SIZE-1].hash.compare(pTransactionID);
            if(compare < 0)
                return NULL;
            else if(compare == 0)
            {
                found = true;
                current = mSamples[SAMPLE_SIZE-1].indexOffset;
            }
            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              // "Last : %s", mSamples[SAMPLE_SIZE - 1].hash.hex().text());

            // Binary search the samples
            unsigned int sampleBegin = 0;
            unsigned int sampleEnd = SAMPLE_SIZE - 1;
            unsigned int sampleCurrent;

            while(!found)
            {
                sampleCurrent = (sampleBegin + sampleEnd) / 2;
                // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  // "Sample : %s", mSamples[sampleCurrent].hash.hex().text());

                if(sampleCurrent == sampleBegin || sampleCurrent == sampleEnd)
                    break;

                // Determine which half the desired item is in
                compare = pTransactionID.compare(mSamples[sampleCurrent].hash);
                if(compare > 0)
                    sampleBegin = sampleCurrent;
                else if(compare < 0)
                    sampleEnd = sampleCurrent;
                else
                {
                    found = true;
                    current = mSamples[sampleCurrent].indexOffset;
                    break;
                }
            }

            // Setup index binary search on sample subset of indices
            begin = mSamples[sampleBegin].indexOffset;
            end = mSamples[sampleEnd].indexOffset;
        }
        else
        {
            // Setup index binary search on all indices
            begin = first;
            end   = first + ((mTransactionCount - 1) * sizeof(IndexEntry));
        }

        // Binary search the file indices
        while(!found)
        {
            // Break the set in two halves
            current = (end - begin) / 2;
            current -= current % sizeof(IndexEntry);
            current += begin;

            if(current == begin)
            {
                // Read the item
                mIndexFile->setReadOffset(current);
                index.read(mIndexFile);
                mDataFile->setReadOffset(index.fileOffset);
                if(!hash.read(mDataFile))
                    return NULL;

                if(pTransactionID == hash)
                    break;
                else if(current != end)
                {
                    current = end;
                    mIndexFile->setReadOffset(current);
                    index.read(mIndexFile);
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
            mIndexFile->setReadOffset(current);
            index.read(mIndexFile);
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

        // Match found
        // Loop backwards to find the first matching
        while(current > first)
        {
            current -= sizeof(IndexEntry);
            mIndexFile->setReadOffset(current);
            index.read(mIndexFile);
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
            mIndexFile->setReadOffset(current);
            index.read(mIndexFile);
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

    TransactionReference *OutputSet::find(const Hash &pTransactionID, uint32_t pIndex)
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
        TransactionReference *firstPulled = pull(pTransactionID, foundCount);

        // Check first pulled transaction for match
        if(firstPulled != NULL && !firstPulled->markedDelete())
        {
            blockHeight = firstPulled->blockHeight;
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

        // Check other pulled transactions for matches
        if(foundCount > 1)
        {
            for(TransactionReferenceList::iterator pulled=mCache.firstMatching(pTransactionID);pulled!=mCache.end();++pulled)
                if((*pulled)->id == pTransactionID)
                {
                    if((*pulled)->markedDelete())
                        continue;

                    blockHeight = (*pulled)->blockHeight;
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

        mLock.writeUnlock();

        if(outputSpentHeight != 0xffffffff)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Output spent at block height %d : index %d - %s", outputSpentHeight, pIndex,
              pTransactionID.hex().text());
        else if(blockHeight != 0xffffffff)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Transaction found at block height %d, but output not found : index %d - %s", blockHeight,
              pIndex, pTransactionID.hex().text());
        else
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME, "Transaction not found : %s",
              pTransactionID.hex().text());
        return NULL;
    }

    TransactionReference *OutputSet::find(const Hash &pTransactionID)
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

                if((*item)->hasUnspentOutputs())
                {
                    mLock.readUnlock();
                    return *item;
                }
            }
            else
                break;
        mLock.readUnlock();

        // Pull from file
        mLock.writeLock("Pull");
        unsigned int foundCount = 0;
        TransactionReference *firstPulled = pull(pTransactionID, foundCount);

        // Check first pulled transaction for match
        if(firstPulled != NULL && !firstPulled->markedDelete())
        {
            if(firstPulled->hasUnspentOutputs())
            {
                mLock.writeUnlock();
                return firstPulled;
            }
        }

        // Check other pulled transactions for matches
        if(foundCount > 1)
        {
            for(TransactionReferenceList::iterator pulled=mCache.firstMatching(pTransactionID);pulled!=mCache.end();++pulled)
                if((*pulled)->id == pTransactionID)
                {
                    if((*pulled)->markedDelete())
                        continue;

                    if((*pulled)->hasUnspentOutputs())
                    {
                        mLock.writeUnlock();
                        return *pulled;
                    }
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
            pullBlocks(pBlockHeight);

        mLock.writeLock("Commit");
        for(TransactionReferenceList::iterator item=mCache.begin();item!=mCache.end();++item)
        {
            if((*item)->blockHeight >= pBlockHeight)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  "Deleting transaction for block %d : %s", (*item)->blockHeight, (*item)->id.hex().text());
                // Created at this block height, so mark for delete on next save
                (*item)->setDelete();
            }

            (*item)->revert(pBlockHeight);
        }
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
    const Hash TransactionOutputPool::BIP0030_HASHES[BIP0030_HASH_COUNT] =
    {
        Hash("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"),
        Hash("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")
    };

    bool TransactionOutputPool::checkDuplicates(const std::vector<Transaction *> &pBlockTransactions,
      unsigned int pBlockHeight, const Hash &pBlockHash)
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

    bool TransactionOutputPool::revert(unsigned int pBlockHeight, bool pHard)
    {
        if(!mValid)
            return false;

        if(!pHard && pBlockHeight != mNextBlockHeight)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't revert non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight - 1);
            return false;
        }

        if(pBlockHeight > mNextBlockHeight)
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
        mNextBlockHeight = pBlockHeight;
        mModified = true;
        return true;
    }

    TransactionReference *TransactionOutputPool::findUnspent(const Hash &pTransactionID, uint32_t pIndex)
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

    // Mark an output as spent
    void TransactionOutputPool::spend(TransactionReference *pReference, unsigned int pIndex, unsigned int pBlockHeight)
    {
        pReference->spendInternal(pIndex, pBlockHeight);
    }

    unsigned int TransactionOutputPool::pullBlocks(unsigned int pBlockHeight)
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
            itemsAdded += set->pullBlocks(pBlockHeight);
            ++set;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Cached %d transactions (%d KiB)", itemsAdded, cachedSize() / 1024);
        return itemsAdded;
    }

    bool TransactionOutputPool::load(bool pPreload)
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Loading transaction outputs");

        mValid = true;
        mCacheAge = Info::instance().outputsCacheAge;
        ArcMist::String filePath = Info::instance().path();
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

            if(pPreload)
            {
                try
                {
                    pullBlocks(cacheBlockHeight());
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

    bool TransactionOutputPool::purge()
    {
        if(cachedSize() > Info::instance().outputsThreshold)
            return save();
        return true;
    }

    bool TransactionOutputPool::save()
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
        ArcMist::String filePathName = Info::instance().path();
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
            if(!set->save(cacheBlockHeight()))
                success = false;
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

    bool TransactionOutputPool::convert()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Converting transaction outputs");

        bool success = true;
        mValid = true;
        ArcMist::String oldFilePath = Info::instance().path();
        oldFilePath.pathAppend("old_outputs");
        ArcMist::String filePathName = oldFilePath;
        filePathName.pathAppend("height");
        if(!ArcMist::fileExists(filePathName))
            return false;
        else
        {
            ArcMist::FileInputStream file(filePathName);
            if(!file.isValid())
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to open old height file to load");
                mValid = false;
                return false;
            }

            // Read block height
            mNextBlockHeight = file.readUnsignedInt();
        }

        ArcMist::String filePath = Info::instance().path();
        filePath.pathAppend("outputs");
        ArcMist::createDirectory(filePath);

        uint32_t lastReport = getTime();
        OutputSet *set = mSets;
        TransactionReferenceList list;
        list.reserve(1000000);
        for(unsigned int i=0;i<SET_COUNT;i++)
        {
            if(getTime() - lastReport > 10)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Convert is %2d%% Complete", (int)(((float)i / (float)SET_COUNT) * 100.0f));
                lastReport = getTime();
            }

            filePathName.writeFormatted("%s%s%02x", oldFilePath.text(), ArcMist::PATH_SEPARATOR, i);
            set->setup(i, filePath, 1000000);
            if(!OutputSet::readOld(list, filePathName, filePathName + ".outputs"))
            {
                success = false;
                break;
            }

            for(TransactionReferenceList::iterator item=list.begin();item!=list.end();++item)
                set->add(*item);

            if(!set->save(mNextBlockHeight))
            {
                success = false;
                break;
            }

            set->clear();
            list.clearNoDelete();
            ++set;
        }

        filePathName = filePath;
        filePathName.pathAppend("height");
        ArcMist::FileOutputStream file(filePathName, true);
        if(!file.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to open old height file to load");
            mValid = false;
            return false;
        }

        file.writeUnsignedInt(mNextBlockHeight);
        return success;
    }

    // void TransactionOutputPool::print()
    // {
        // ArcMist::String filePath = Info::instance().path();
        // filePath.pathAppend("outputs");
        // ArcMist::createDirectory(filePath);

        // ArcMist::String filePathName = filePath;
        // filePathName.pathAppend("data");
        // mDataFile = new ArcMist::FileStream(filePathName);

        // //filePathName.writeFormatted("%s%s%02x", filePath.text(), ArcMist::PATH_SEPARATOR, 0);
        // mSets[0].setup(0, filePath, mDataFile);
        // mSets[0].print();
    // }
}
