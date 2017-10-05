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

    bool TransactionReference::readHeaderOnly(ArcMist::InputStream *pHeaderStream)
    {
        // Outputs
        clearOutputs();

        // Header
        if(pHeaderStream->remaining() < SIZE)
            return false;

        id.read(pHeaderStream);
        blockHeight = pHeaderStream->readUnsignedInt();
        outputFileOffset = pHeaderStream->readUnsignedLong();
        mOutputCount = pHeaderStream->readUnsignedInt();
        return true;
    }

    bool TransactionReference::readMatchingID(const Hash &pHash, ArcMist::InputStream *pHeaderStream,
      ArcMist::InputStream *pOutputStream)
    {
        // Header
        if(!id.read(pHeaderStream) || id != pHash)
            return false;

        if(pHeaderStream->remaining() < SIZE - 32)
            return false;
        blockHeight = pHeaderStream->readUnsignedInt();
        outputFileOffset = pHeaderStream->readUnsignedLong();
        unsigned int outputCount = pHeaderStream->readUnsignedInt();

        // Outputs
        pOutputStream->setReadOffset(outputFileOffset);
        if(pOutputStream->remaining() < OutputReference::SIZE * outputCount)
            return false;

        allocateOutputs(outputCount);
        pOutputStream->read(mOutputs, mOutputCount * OutputReference::SIZE);
        return true;
    }

    bool TransactionReference::read(ArcMist::InputStream *pHeaderStream, ArcMist::InputStream *pOutputStream)
    {
        // Header
        if(pHeaderStream->remaining() < SIZE)
            return false;

        id.read(pHeaderStream);
        blockHeight = pHeaderStream->readUnsignedInt();
        outputFileOffset = pHeaderStream->readUnsignedLong();
        unsigned int outputCount = pHeaderStream->readUnsignedInt();

        // Outputs
        pOutputStream->setReadOffset(outputFileOffset);
        if(pOutputStream->remaining() < OutputReference::SIZE * outputCount)
            return false;

        allocateOutputs(outputCount);
        pOutputStream->read(mOutputs, mOutputCount * OutputReference::SIZE);
        return true;
    }

    bool TransactionReference::write(ArcMist::OutputStream *pHeaderStream, ArcMist::OutputStream *pOutputStream,
      bool pRewriteOutputs)
    {
        if(toDelete)
            return true;

        // Outputs
        if(mOutputs != NULL) // Check for header only mode
        {
            if(pRewriteOutputs || outputFileOffset == NOT_WRITTEN)
            {
                pOutputStream->setWriteOffset(pOutputStream->length());
                outputFileOffset = pOutputStream->length();
            }
            else
                pOutputStream->setWriteOffset(outputFileOffset);
            pOutputStream->write(mOutputs, mOutputCount * OutputReference::SIZE);
        }

        // Header
        id.write(pHeaderStream);
        pHeaderStream->writeUnsignedInt(blockHeight);
        pHeaderStream->writeUnsignedLong(outputFileOffset);
        pHeaderStream->writeUnsignedInt(mOutputCount);
        return true;
    }

    bool TransactionReference::readOld(ArcMist::InputStream *pStream)
    {
        outputFileOffset = NOT_WRITTEN;
        if(!id.read(pStream))
            return false;
        blockHeight = pStream->readUnsignedInt();
        unsigned int outputCount = pStream->readUnsignedInt();

        if(outputCount == 0)
        {
            clearOutputs();
            return true; // This should never happen, but isn't technically a failure
        }

        if(pStream->remaining() < outputCount * OutputReference::SIZE)
            return false;

        // Read all the outputs into allocated outputs, then remove spent outputs
        // Allocate the number of outputs needed
        allocateOutputs(outputCount);

        // Outputs
        pStream->read(mOutputs, outputCount * OutputReference::SIZE);
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

    bool TransactionReference::wasModifiedInBlock(unsigned int pBlockHeight) const
    {
        if(blockHeight == pBlockHeight)
            return true;

        if(mOutputCount == 0 || mOutputs == NULL)
            return false;

        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
            if(output->spentBlockHeight == pBlockHeight)
                return true;

        return false;
    }

    void TransactionReference::commit(std::vector<Output *> &pOutputs)
    {
        if(mOutputs == NULL)
            return;

        if(mOutputCount != pOutputs.size())
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Mismatched transaction outputs on commit %d != %d : %s", mOutputCount, pOutputs.size(),
              id.hex().text());
              return;
        }

        OutputReference *output = mOutputs;
        for(std::vector<Output *>::iterator fullOutput=pOutputs.begin();fullOutput!=pOutputs.end();++fullOutput,++output)
            output->commit(**fullOutput);
    }

    bool TransactionReference::revert(unsigned int pBlockHeight)
    {
        if(mOutputs == NULL)
            return false;

        bool result = false;
        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
            if(output->spentBlockHeight == pBlockHeight)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  "Unspending transaction output for block %d : index %d - %s",
                  output->spentBlockHeight, i, id.hex().text());
                output->spentBlockHeight = 0; // Spent at this block height, so "unspend"
                result = true;
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

    OutputSet::OutputSet() : mLock("Output Set")
    {
        mHeaderFile = NULL;
        mHeaderSize = 0;
        mOutputsFile = NULL;
        mOutputSize = 0;
        mPendingCount = 0;
        mPendingOutputCount = 0;
        mRewriteOutputs = false;
    }

    OutputSet::~OutputSet()
    {
        TransactionReferenceList *pending = mPending;
        HashList *lookup = mLookedUp;
        for(unsigned int i=0;i<SUBSET_COUNT;++i)
        {
            lookup->clear();
            ++pending;
            pending->clear();
            ++pending;
        }

        if(mHeaderFile != NULL)
            delete mHeaderFile;
        if(mOutputsFile != NULL)
            delete mOutputsFile;
    }

    void OutputSet::setup(unsigned int pID, const char *pFilePath)
    {
        mLock.writeLock("Setup");
        mID = pID;
        mFilePathName.writeFormatted("%s%s%02x", pFilePath, ArcMist::PATH_SEPARATOR, mID);
        if(!ArcMist::fileExists(mFilePathName))
        {
            // Create header file
            ArcMist::FileOutputStream outputHeaderFile(mFilePathName, true);

            // Write zeroized subset offsets
            ArcMist::stream_size subsetFileOffsets[SUBSET_COUNT];
            std::memset(subsetFileOffsets, 0, SUBSET_COUNT * 8);
            outputHeaderFile.write(subsetFileOffsets, SUBSET_COUNT * 8);
            mHeaderSize = SUBSET_COUNT * 8;
        }
        else
        {
            openHeaderFile();
            mHeaderSize = mHeaderFile->length();
            closeHeaderFile();
        }
        ArcMist::String outputsFilePathName = mFilePathName + ".outputs";
        if(!ArcMist::fileExists(outputsFilePathName))
        {
            ArcMist::FileOutputStream(outputsFilePathName, true); // Create file
            mOutputSize = 0;
        }
        else
        {
            openOutputsFile();
            mOutputSize = mOutputsFile->length();
            closeOutputFile();
        }
        mLock.writeUnlock();
    }

    void TransactionReferenceList::insertSorted(TransactionReference *pItem)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Insert Sorted");
#endif
        if(size() == 0 || *back() < *pItem)
        {
            push_back(pItem);
            return;
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
                if(**bottom > *pItem)
                    current = bottom; // Insert before bottom
                else if(current != top && **top > *pItem)
                    current = top; // Insert before top
                else
                    current = top + 1; // Insert after top
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
                    if((*current)->blockHeight > pItem->blockHeight)
                        break;
                    ++current;
                }

                break;
            }
        }

        iterator after = begin();
        after += (current - data());
        insert(after, pItem);
    }

    void TransactionReferenceList::mergeSorted(TransactionReferenceList &pRight)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Merge Sorted");
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
        ArcMist::Profiler profiler("First Matching");
#endif
        if(size() == 0 || back()->id.compare(pHash) < 0)
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

    bool OutputSet::save()
    {
        mLock.writeLock("Save");

        if(mPendingCount == 0)
        {
            mLock.writeUnlock();
            return true;
        }

        if(!openHeaderFile())
        {
            mLock.writeUnlock();
            return false;
        }

        if(mRewriteOutputs && !openOutputsFile())
        {
            mLock.writeUnlock();
            return false;
        }

        bool success = true;
        ArcMist::stream_size subsetFileOffsets[SUBSET_COUNT];
        TransactionReferenceList fileList[SUBSET_COUNT];
        TransactionReference *newReference;

        mHeaderFile->setReadOffset(0);
        mHeaderFile->read(subsetFileOffsets, SUBSET_COUNT * 8);

        // Read in file items
        while(mHeaderFile->remaining())
        {
            newReference = new TransactionReference();
            if(mRewriteOutputs)
            {
                if(!newReference->read(mHeaderFile, mOutputsFile))
                {
                    delete newReference;
                    success = false;
                    break;
                }
            }
            else if(!newReference->readHeaderOnly(mHeaderFile))
            {
                delete newReference;
                success = false;
                break;
            }
            fileList[newReference->id.getByte(1)].push_back(newReference);
        }

        if(!success)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to read output set %02x while saving", mID);
            mLock.writeUnlock();
            return false;
        }

        // Close the input files
        closeHeaderFile();
        closeOutputFile();

        // Rewrite the data
        ArcMist::FileOutputStream *headerFile = new ArcMist::FileOutputStream(mFilePathName, true); // Truncate
        ArcMist::FileOutputStream *outputFile;
        // Only truncate the output file if it needs rewritten
        if(mRewriteOutputs)
            outputFile = new ArcMist::FileOutputStream(mFilePathName + ".outputs", true); // Truncate
        else
            outputFile = new ArcMist::FileOutputStream(mFilePathName + ".outputs");

        TransactionReferenceList::iterator fileItem, fileEnd, pendingItem, pendingEnd;
        int compare;

        // Write current subset offsets to file
        headerFile->setWriteOffset(0);
        headerFile->write(subsetFileOffsets, SUBSET_COUNT * 8);

        for(unsigned int i=0;i<SUBSET_COUNT;++i)
        {
            subsetFileOffsets[i] = headerFile->writeOffset();
            fileItem = fileList[i].begin();
            fileEnd = fileList[i].end();
            pendingItem = mPending[i].begin();
            pendingEnd = mPending[i].end();

            // Write both lists to file while retaining sort
            while(fileItem != fileEnd || pendingItem != pendingEnd)
            {
                if(fileItem == fileEnd) // All file items already written
                    (*pendingItem++)->write(headerFile, outputFile, mRewriteOutputs);
                else if(pendingItem == pendingEnd) // All pending items already written
                    (*fileItem++)->write(headerFile, outputFile, mRewriteOutputs);
                else
                {
                    // Determine which item is next in sorted order
                    compare = (*fileItem)->compare(**pendingItem);
                    if(compare < 0)
                        (*fileItem++)->write(headerFile, outputFile, mRewriteOutputs);
                    else if(compare > 0)
                        (*pendingItem++)->write(headerFile, outputFile, mRewriteOutputs);
                    else
                    {
                        // They are both the same so only write the pending because it has been updated
                        (*pendingItem++)->write(headerFile, outputFile, mRewriteOutputs);
                        ++fileItem;
                    }
                }
            }
        }

        // Write updated subset offsets to file
        headerFile->setWriteOffset(0);
        headerFile->write(subsetFileOffsets, SUBSET_COUNT * 8);

        // Close the output files
        mHeaderSize = headerFile->length();
        delete headerFile;
        mOutputSize = outputFile->length();
        delete outputFile;

        clear(); // Clear pending data that was just saved
        mLock.writeUnlock();
        return true;
    }

    void OutputSet::clear()
    {
        TransactionReferenceList *pending = mPending;
        HashList *lookup = mLookedUp;
        for(unsigned int i=0;i<SUBSET_COUNT;++i)
        {
            lookup->clear();
            ++lookup;
            pending->clear();
            ++pending;
        }
        mPendingCount = 0;
        mPendingOutputCount = 0;
        mRewriteOutputs = false;
    }

    bool OutputSet::transactionIsPending(const Hash &pTransactionID, unsigned int pBlockHeight)
    {
        TransactionReferenceList &pending = mPending[pTransactionID.getByte(1)];

        // Look in pending
        mLock.readLock();
        for(TransactionReferenceList::iterator item=pending.firstMatching(pTransactionID);item!=pending.end();++item)
            if((*item)->id == pTransactionID && (*item)->blockHeight == pBlockHeight)
            {
                mLock.readUnlock();
                return true;
            }
        mLock.readUnlock();
        return false;
    }

    unsigned int OutputSet::pullBlock(unsigned int pBlockHeight)
    {
        if(!openHeaderFile() || !openOutputsFile())
            return 0;

        // Skip subset file offsets
        mHeaderFile->setReadOffset(SUBSET_COUNT * 8);

        TransactionReference *newReference = new TransactionReference();
        unsigned int itemsAdded = 0;
        while(mHeaderFile->remaining())
        {
            if(!newReference->read(mHeaderFile, mOutputsFile))
            {
                delete newReference;
                return itemsAdded;
            }
            else
            {
                if(newReference->wasModifiedInBlock(pBlockHeight) &&
                  !transactionIsPending(newReference->id, newReference->blockHeight))
                {
                    mPending[newReference->id.getByte(1)].insertSorted(newReference);
                    ++itemsAdded;
                    ++mPendingCount;
                    mPendingOutputCount += newReference->outputCount();
                    newReference = new TransactionReference();
                }
            }
        }

        delete newReference;
        return itemsAdded;
    }

    unsigned int OutputSet::pull(const Hash &pTransactionID, TransactionReferenceList &pList)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Pull");
#endif
        if(!openHeaderFile() || !openOutputsFile())
            return 0;

        Hash hash(32);
        int compare;
        ArcMist::stream_size current;

        // Get the file offset of this transaction ID's subset
        int setID = pTransactionID.getByte(1);
        mHeaderFile->setReadOffset(setID * 8);
        ArcMist::stream_size bottom = mHeaderFile->readUnsignedLong();

        // Read that file offset of the next subset
        ArcMist::stream_size top;
        if(setID == 0xff)
            top = mHeaderFile->length();
        else
            top = mHeaderFile->readUnsignedLong();

        while(true)
        {
            // Break the set in two halves
            current = (top - bottom) / 2;
            current -= current % TransactionReference::SIZE;
            current += bottom;

            if(current == bottom)
            {
                mHeaderFile->setReadOffset(bottom);
                break; // Check for match
            }

            // Read the item in the middle
            mHeaderFile->setReadOffset(current);
            hash.read(mHeaderFile);
            compare = pTransactionID.compare(hash);

            // Determine which half the desired item is in
            if(compare > 0)
            {
                // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  // "Hash > %s", hash.hex().text());
                bottom = current;
            }
            else if(compare < 0)
            {
                // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  // "Hash < %s", hash.hex().text());
                top = current;
            }
            else
            {
                // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                  // "Hash = %s", hash.hex().text());
                // Item found
                // Loop backwards until it doesn't match then loop forward adding all with matching transaction ID
                while(current > 0)
                {
                    current -= TransactionReference::SIZE;
                    mHeaderFile->setReadOffset(current);
                    hash.read(mHeaderFile);
                    if(hash != pTransactionID)
                    {
                        current += TransactionReference::SIZE;
                        mHeaderFile->setReadOffset(current);
                        break;
                    }
                }

                if(current == 0)
                    mHeaderFile->setReadOffset(current);

                break;
            }
        }

        mLookedUp[pTransactionID.getByte(1)].insertSorted(pTransactionID);

        TransactionReference *newReference;
        unsigned int itemsAdded = 0;
        while(mHeaderFile->remaining())
        {
            newReference = new TransactionReference();
            if(newReference->readMatchingID(pTransactionID, mHeaderFile, mOutputsFile))
            {
                pList.insertSorted(newReference);
                ++itemsAdded;
                ++mPendingCount;
                mPendingOutputCount += newReference->outputCount();
                newReference = new TransactionReference();
            }
            else
            {
                delete newReference;
                return itemsAdded;
            }
        }

        return itemsAdded;
    }

    TransactionReference *OutputSet::find(const Hash &pTransactionID, uint32_t pIndex)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Find");
#endif
        OutputReference *output;
        unsigned int blockHeight = 0xffffffff;
        unsigned int outputSpentHeight = 0xffffffff;
        TransactionReferenceList &pending = mPending[pTransactionID.getByte(1)];

        // Look in pending
        mLock.readLock();
        for(TransactionReferenceList::iterator item=pending.firstMatching(pTransactionID);item!=pending.end();++item)
            if((*item)->id == pTransactionID)
            {
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

        if(!mLookedUp[pTransactionID.getByte(1)].contains(pTransactionID))
        {
            // Pull from file
            mLock.writeLock("Pull");
            unsigned int foundCount = pull(pTransactionID, pending);
            if(foundCount > 0)
            {
                for(TransactionReferenceList::iterator pulled=pending.firstMatching(pTransactionID);pulled!=pending.end();++pulled)
                    if((*pulled)->id == pTransactionID)
                    {
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
        }

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
        ArcMist::Profiler profiler("Find ID");
#endif
        TransactionReferenceList &pending = mPending[pTransactionID.getByte(1)];

        // Look in pending
        mLock.readLock();
        for(TransactionReferenceList::iterator item=pending.firstMatching(pTransactionID);item!=pending.end();++item)
            if((*item)->id == pTransactionID)
            {
                if((*item)->hasUnspentOutputs())
                {
                    mLock.readUnlock();
                    return *item;
                }
            }
            else
                break;
        mLock.readUnlock();

        if(!mLookedUp[pTransactionID.getByte(1)].contains(pTransactionID))
        {
            // Pull from file
            mLock.writeLock("Pull");
            unsigned int foundCount = pull(pTransactionID, pending);
            if(foundCount > 0)
            {
                for(TransactionReferenceList::iterator pulled=pending.firstMatching(pTransactionID);pulled!=pending.end();++pulled)
                    if((*pulled)->id == pTransactionID)
                    {
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
        }

        return NULL;
    }

    void OutputSet::add(TransactionReference *pTransaction)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Add");
#endif
        mPending[pTransaction->id.getByte(1)].insertSorted(pTransaction);
        ++mPendingCount;
        mPendingOutputCount += pTransaction->outputCount();
    }

    void OutputSet::commit(const Hash &pTransactionID, std::vector<Output *> &pOutputs, unsigned int pBlockHeight)
    {
        mLock.writeLock("Commit");
        TransactionReferenceList &pending = mPending[pTransactionID.getByte(1)];
        for(TransactionReferenceList::iterator item=pending.begin();item!=pending.end();++item)
            if((*item)->blockHeight == pBlockHeight && (*item)->id == pTransactionID)
            {
                (*item)->commit(pOutputs);
                break;
            }
        mLock.writeUnlock();
    }

    void OutputSet::revert(unsigned int pBlockHeight, bool pHard)
    {
        if(pHard)
            pullBlock(pBlockHeight);

        mLock.writeLock("Commit");
        TransactionReferenceList *pending = mPending;
        for(unsigned int i=0;i<SUBSET_COUNT;++i)
        {
            for(TransactionReferenceList::iterator item=pending->begin();item!=pending->end();++item)
            {
                if((*item)->blockHeight == pBlockHeight)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                      "Deleting transaction for block %d : %s", (*item)->blockHeight, (*item)->id.hex().text());
                    // Created at this block height, so mark for delete on next save
                    (*item)->toDelete = true;
                    // If the outputs have already been written then they need to be removed from the outputs file.
                    if((*item)->outputFileOffset != TransactionReference::NOT_WRITTEN)
                        mRewriteOutputs = true;
                }

                (*item)->revert(pBlockHeight);
            }
            ++pending;
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

    unsigned long long TransactionOutputPool::pendingSize() const
    {
        unsigned long long result = 0;
        const OutputSet *set = mSets;
        for(unsigned int i=0;i<SET_COUNT;i++)
        {
            result += set->pendingSize();
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

    // Add all the outputs from a block (pending since they have no block file IDs or offsets yet)
    bool TransactionOutputPool::add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight, const Hash &pBlockHash)
    {
        if(pBlockHeight != mNextBlockHeight)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't add transactions for non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight);
            return false;
        }

        OutputSet *set;
        TransactionReference *transactionReference;
        unsigned int count = 0;
        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
        {
            // Get references set for transaction ID
            set = mSets + (*transaction)->hash.lookup8();
            transactionReference = set->find((*transaction)->hash);
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
            set->add(new TransactionReference((*transaction)->hash, pBlockHeight, (*transaction)->outputs.size()));
            ++count;
        }

        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
          // "Added %d transaction's outputs for block %d", count, pBlockHeight);
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

        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
            mSets[(*transaction)->hash.lookup8()].commit((*transaction)->hash, (*transaction)->outputs, pBlockHeight);

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

        OutputSet *set = mSets;
        for(unsigned int i=0;i<SET_COUNT;i++)
        {
            set->revert(pBlockHeight, pHard);
            ++set;
        }

        if(pBlockHeight == mNextBlockHeight)
            --mNextBlockHeight;
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
        OutputReference *output = pReference->outputAt(pIndex);
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
    }

    bool TransactionOutputPool::load()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Loading transaction outputs");

        mValid = true;
        ArcMist::String filePath = Info::instance().path();
        filePath.pathAppend("outputs");
        ArcMist::createDirectory(filePath);
        for(unsigned int i=0;i<SET_COUNT;++i)
            mSets[i].setup(i, filePath);

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
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
              "Loaded %d/%d transactions/outputs (%d KiB) at block height %d", transactionCount(),
              outputCount(), size() / 1024, mNextBlockHeight - 1);
        else
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Failed to load transaction outputs");
        return mValid;
    }

    bool TransactionOutputPool::purge()
    {
        if(pendingSize() > Info::instance().outputsThreshold)
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
          "Saving transaction outputs at block height %d (%d KiB pending)", mNextBlockHeight - 1,
          pendingSize() / 1024);

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
            if(!set->save())
                success = false;
            ++set;
        }

        if(success)
        {
            mModified = false;
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
              "Saved %d/%d transactions/outputs (%d KiB)", transactionCount(), outputCount(), size() / 1024);
        }
        else
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to save transaction outputs");

        return success;
    }

    bool TransactionOutputPool::convert()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Converting transaction outputs");

        mValid = true;

        ArcMist::String filePathName = Info::instance().path();
        filePathName.pathAppend("old_outputs");
        if(!ArcMist::fileExists(filePathName))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to open old outputs file");
            mValid = false;
            return false;
        }

        ArcMist::FileInputStream file(filePathName);

        // Read block height
        mNextBlockHeight = file.readUnsignedInt();

        ArcMist::String heightFilePathName = Info::instance().path();
        heightFilePathName.pathAppend("outputs");
        heightFilePathName.pathAppend("height");
        ArcMist::FileOutputStream heightFile(heightFilePathName, true);
        if(!heightFile.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to open height file to save");
            mValid = false;
            return false;
        }

        // Block Height
        heightFile.writeUnsignedInt(mNextBlockHeight);

        uint32_t lastReport = getTime();
        TransactionReference *newTransaction = new TransactionReference();
        while(file.remaining())
        {
            if(getTime() - lastReport > 10)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Convert is %2d%% Complete", (int)(((float)file.readOffset() / (float)file.length()) * 100.0f));

                // Purge after 1 GiB
                if(pendingSize() > 1073741824)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                      "Purging %d bytes", pendingSize());
                    save();
                }

                lastReport = getTime();
            }

            if(!newTransaction->readOld(&file))
            {
                mValid = false;
                break;
            }

            mSets[newTransaction->id.lookup8()].add(newTransaction);
            mModified = true;
            newTransaction = new TransactionReference();
        }

        delete newTransaction;
        return save();
    }
}
