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

#include "arcmist/base/log.hpp"
#include "arcmist/io/file_stream.hpp"
#include "base.hpp"
#include "info.hpp"
#include "interpreter.hpp"
#include "block.hpp"


namespace BitCoin
{
#ifdef PROFILER_ON
    static ArcMist::Profiler transReadProfiler("Trans Ref Read", false);
#endif
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

    OutputReference TransactionReference::sOutputs[TransactionReference::STATIC_OUTPUTS_SIZE];

    void TransactionReference::write(ArcMist::OutputStream *pStream)
    {
        fileOffset = pStream->writeOffset(); // Remember the offset in the file to make updates quicker
        id.write(pStream);
        pStream->writeUnsignedInt(blockHeight);
        pStream->writeUnsignedInt(mOutputCount);
        pStream->write(mOutputs, mOutputCount * OutputReference::SIZE);
    }

    bool TransactionReference::read(ArcMist::InputStream *pStream, unsigned int &pOutputCount)
    {
#ifdef PROFILER_ON
        transReadProfiler.start();
#endif
        // clearOutputs();

        if(pStream->remaining() < SIZE + OutputReference::SIZE)
        {
#ifdef PROFILER_ON
            transReadProfiler.stop();
#endif
            return false;
        }

        fileOffset = pStream->readOffset(); // Remember the offset in the file to make updates quicker
        if(!id.read(pStream))
        {
#ifdef PROFILER_ON
            transReadProfiler.stop();
#endif
            return false;
        }
        blockHeight = pStream->readUnsignedInt();
        unsigned int outputCount = pStream->readUnsignedInt();
        unsigned int spentOutputCount = 0;

        if(outputCount == 0)
        {
            clearOutputs();
#ifdef PROFILER_ON
            transReadProfiler.stop();
#endif
            return true; // This should never happen, but isn't technically a failure
        }

        if(pStream->remaining() < outputCount * OutputReference::SIZE)
        {
#ifdef PROFILER_ON
            transReadProfiler.stop();
#endif
            return false;
        }

        // Outputs
        if(outputCount < STATIC_OUTPUTS_SIZE)
        {
            // Read into static outputs
            pStream->read(sOutputs, outputCount * OutputReference::SIZE);

            // Count spent outputs
            OutputReference *output = sOutputs;
            for(unsigned int i=0;i<outputCount;++i,++output)
                if(output->spentBlockHeight != 0)
                    ++spentOutputCount;

            // Not all outputs spent
            if(outputCount > spentOutputCount)
            {
                // Copy only the unspent outputs from static outputs
                allocateOutputs(outputCount - spentOutputCount);

                // Copy unspent outputs into allocated outputs
                output = sOutputs;
                OutputReference *toOutput = mOutputs;
                unsigned int *index = mOutputIndices;
                for(unsigned int i=0;i<outputCount;++i,++output)
                    if(output->spentBlockHeight == 0)
                    {
                        *toOutput = *output;
                        *index = i;
                        ++toOutput;
                        ++index;
                    }

                pOutputCount += outputCount - spentOutputCount;
            }

#ifdef PROFILER_ON
            transReadProfiler.stop();
#endif
            return true;
        }

        // Read all the outputs into allocated outputs, then remove spent outputs
        // Allocate the number of outputs needed
        allocateOutputs(outputCount);

        // Outputs
        pStream->read(mOutputs, outputCount * OutputReference::SIZE);

        // Set indices and count spent
        OutputReference *output = mOutputs;
        unsigned int *index = mOutputIndices;
        for(unsigned int i=0;i<outputCount;++i,++index,++output)
        {
            *index = i;
            if(output->spentBlockHeight != 0)
                ++spentOutputCount;
        }

        if(spentOutputCount == outputCount)
        {
#ifdef PROFILER_ON
            transReadProfiler.stop();
#endif
            return true; // All outputs spent. Returning without incrementing pOutputCount will cause this object to be reused
        }

        if(spentOutputCount > 0)
            removeSpent(outputCount, spentOutputCount);

        pOutputCount += outputCount;
#ifdef PROFILER_ON
        transReadProfiler.stop();
#endif
        return true;
    }

    unsigned int TransactionReference::spentOutputCount() const
    {
        unsigned int result = 0;
        OutputReference *output=mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
            if(output->spentBlockHeight != 0)
                ++result;
        return result;
    }

    OutputReference *TransactionReference::outputAt(unsigned int pIndex)
    {
        OutputReference *output = mOutputs;
        unsigned int *index = mOutputIndices;
        for(unsigned int i=0;i<mOutputCount;++i,++index,++output)
            if(*index == pIndex)
                return output;
            else if(*index > pIndex)
                break;

        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Invalid output index : %d", pIndex);
        return NULL;
    }

    void TransactionReference::writeSpent(ArcMist::OutputStream *pStream, bool pWrote,
      unsigned int &pOutputCount, unsigned int &pSpentOutputCount)
    {
        if(pWrote)
            removeSpent(pOutputCount, pSpentOutputCount);
        else
        {
            bool spentFound = false;
            OutputReference *output = mOutputs;
            unsigned int *index = mOutputIndices;
            for(unsigned int i=0;i<mOutputCount;++i,++index,++output)
                if(output->spentBlockHeight != 0)
                {
                    spentFound = true;
                    // 40 (id 32, height 4, output count 4)
                    // + OutputReference::SIZE per output before this one to get to the start of this output
                    pStream->setWriteOffset(fileOffset + SIZE + (*index * OutputReference::SIZE));
                    // Write endian independent because of OutputReference read/write functions
                    pStream->write(&output->spentBlockHeight, 4);
                }
            if(spentFound)
                removeSpent(pOutputCount, pSpentOutputCount);
        }
    }

    void TransactionReference::removeSpent(unsigned int &pOutputCount, unsigned int &pSpentOutputCount)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler outputsProfiler("Remove Spent");
#endif
        if(mOutputs == NULL)
            return;

        unsigned int spentCount = 0;
        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
            if(output->spentBlockHeight != 0)
                ++spentCount;

        if(spentCount == 0)
            return;

        // All outputs are now spent
        if(spentCount == mOutputCount)
        {
            pOutputCount -= spentCount;
            pSpentOutputCount -= spentCount;
            clearOutputs();
            return;
        }

        // Allocate new outputs
        OutputReference *newOutputs = new OutputReference[mOutputCount - spentCount];
        unsigned int *newIndices = new unsigned int[mOutputCount - spentCount];
        OutputReference *newOutput = newOutputs;
        unsigned int *newIndex = newIndices;

        // Copy only unspent outputs to new outputs
        output = mOutputs;
        unsigned int *index = mOutputIndices;
        for(unsigned int i=0;i<mOutputCount;++i,++index,++output)
            if(output->spentBlockHeight == 0)
            {
                *newOutput = *output;
                *newIndex = *index;
                ++newOutput;
                ++newIndex;
            }

        // Delete old outputs and set to new outputs
        delete[] mOutputs;
        mOutputs = newOutputs;
        delete[] mOutputIndices;
        mOutputIndices = newIndices;
        mOutputCount -= spentCount;

        pOutputCount -= spentCount;
        pSpentOutputCount -= spentCount;
    }

    void TransactionReference::commit(std::vector<Output *> &pOutputs)
    {
        if(mOutputs == NULL)
            return;

        OutputReference *output = mOutputs;
        unsigned int *index = mOutputIndices;
        for(unsigned int i=0;i<mOutputCount;++i,++index,++output)
            output->commit(*pOutputs.at(*index));
    }

    void TransactionReference::revert(unsigned int pBlockHeight, unsigned int &pSpentOutputCount)
    {
        if(mOutputs == NULL)
            return;

        OutputReference *output=mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
            if(output->spentBlockHeight == pBlockHeight)
            {
                --pSpentOutputCount;
                output->spentBlockHeight = 0; // Spent at this block height, so "unspend"
            }
    }

    void TransactionReference::print(ArcMist::Log::Level pLevel)
    {
        ArcMist::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "Transaction Reference");
        ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Transaction ID : %s", id.hex().text());
        ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Height         : %d", blockHeight);

        if(mOutputs == NULL)
        {
            ArcMist::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  No outputs");
            return;
        }

        ArcMist::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Outputs:");
        OutputReference *output=mOutputs;
        unsigned int *index = mOutputIndices;
        for(unsigned int i=0;i<mOutputCount;++i,++index,++output)
        {
            ArcMist::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Output Reference");
            ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    Index       : %d", *index);
            ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    File Offset : %d", output->blockFileOffset);
            ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    Spent       : %d", output->spentBlockHeight);
        }
    }

    TransactionOutputSet::~TransactionOutputSet()
    {
        for(std::list<TransactionReference *>::iterator reference=mReferences.begin();reference!=mReferences.end();++reference)
            delete *reference;
    }

    void TransactionOutputSet::clear()
    {
        for(std::list<TransactionReference *>::iterator reference=mReferences.begin();reference!=mReferences.end();++reference)
            delete *reference;
        mReferences.clear();
        mLoaded = false;
    }

    bool TransactionOutputSet::load(unsigned int &pSetCount, unsigned int &pTransactionCount, unsigned int &pOutputCount)
    {
        if(mLoaded)
            return true;

        ArcMist::String filePathName;
        filePathName.writeFormatted("%s%s%04x", mFilePath.text(), PATH_SEPARATOR, mID);
        if(!ArcMist::fileExists(filePathName))
            return true;

        ArcMist::FileInputStream file(filePathName);
        if(!file.isValid())
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to load outputs set %04x", mID);
            return false;
        }

        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
          // "Load outputs set %04x", mID);
        mLoaded = read(&file, pTransactionCount, pOutputCount);
        if(mLoaded)
            ++pSetCount;
        return mLoaded;
    }

    bool TransactionOutputSet::save(unsigned int &pTransactionCount, unsigned int &pOutputCount,
      unsigned int &pSpentTransactionCount, unsigned int &pSpentOutputCount)
    {
        if(!mLoaded)
            return true;

        ArcMist::String filePathName;
        filePathName.writeFormatted("%s%s%04x", mFilePath.text(), PATH_SEPARATOR, mID);
        ArcMist::FileOutputStream file(filePathName);
        if(!file.isValid())
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to save outputs set %04x", mID);
            return false;
        }

        write(&file, pTransactionCount, pOutputCount, pSpentTransactionCount, pSpentOutputCount);
        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
          // "Saved outputs set %04x", mID);
        return true;
    }

    TransactionReference *TransactionOutputSet::findUnspent(const Hash &pTransactionID, uint32_t pIndex)
    {
        if(!mLoaded)
            return NULL;

        OutputReference *output;
        for(std::list<TransactionReference *>::iterator reference=mReferences.begin();reference!=mReferences.end();++reference)
            if((*reference)->id == pTransactionID)
            {
                output = (*reference)->outputAt(pIndex);
                if(output != NULL)
                {
                    if(output->spentBlockHeight == 0)
                        return *reference;

                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
                      "Output spent at block height %d", output->spentBlockHeight);
                    return NULL;
                }
                else
                {
                    ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME, "Output %d not found");
                    return NULL;
                }
            }

        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME, "Transaction %d not found");
        return NULL;
    }

    void TransactionOutputSet::write(ArcMist::OutputStream *pStream, unsigned int &pTransactionCount,
      unsigned int &pOutputCount, unsigned int &pSpentTransactionCount, unsigned int &pSpentOutputCount)
    {
        if(pStream->length() == 0) // Empty file
            pStream->writeString(START_STRING);

        bool wrote;
        for(std::list<TransactionReference *>::iterator reference=mReferences.begin();reference!=mReferences.end();)
        {
            if((*reference)->fileOffset == 0xffffffff) // Not written to file yet
            {
                // Append to file
                pStream->setWriteOffset(pStream->length());
                (*reference)->write(pStream);
                wrote = true;
            }
            else
                wrote = false;

            (*reference)->writeSpent(pStream, wrote, pOutputCount, pSpentOutputCount);
            if((*reference)->outputCount() == 0) // All outputs spent
            {
                --pTransactionCount;
                --pSpentTransactionCount;
                delete *reference;
                reference = mReferences.erase(reference);
            }
            else
                ++reference;
        }
    }

    // Keep only those with spent block == 0
    bool TransactionOutputSet::read(ArcMist::InputStream *pStream, unsigned int &pTransactionCount,
      unsigned int &pOutputCount)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Set Read");
#endif
        clear();

        ArcMist::String checkStart = pStream->readString(4);
        if(checkStart != START_STRING)
            return false;

        TransactionReference *newReference = new TransactionReference();
        unsigned int outputCount;
        while(pStream->remaining())
        {
            outputCount = 0;
            if(!newReference->read(pStream, outputCount))
            {
                delete newReference;
                return false;
            }

            if(outputCount > 0) // Not all outputs spent
            {
                pOutputCount += outputCount;
                ++pTransactionCount;
                mReferences.push_back(newReference);
                newReference = new TransactionReference();
            }
        }

        delete newReference;
        return true;
    }

    bool TransactionOutputSet::add(TransactionReference *pReference, unsigned int &pTransactionCount,
      unsigned int &pOutputCount)
    {
        if(!mLoaded)
            return false;

        mReferences.push_back(pReference);
        ++pTransactionCount;
        pOutputCount += pReference->outputCount();
        return true;
    }

    void TransactionOutputSet::commit(const Hash &pTransactionID, std::vector<Output *> &pOutputs,
      unsigned int pBlockHeight)
    {
        if(!mLoaded)
            return;

        for(std::list<TransactionReference *>::iterator reference=mReferences.begin();reference!=mReferences.end();++reference)
            if((*reference)->blockHeight == pBlockHeight && (*reference)->id == pTransactionID)
                (*reference)->commit(pOutputs);
    }

    void TransactionOutputSet::revert(unsigned int pBlockHeight, unsigned int &pTransactionCount,
      unsigned int &pOutputCount, unsigned int &pSpentTransactionCount, unsigned int &pSpentOutputCount)
    {
        if(!mLoaded)
            return;

        unsigned int spentOutputCount;
        for(std::list<TransactionReference *>::iterator reference=mReferences.begin();reference!=mReferences.end();)
            if((*reference)->fileOffset == 0xffffffff && (*reference)->blockHeight == pBlockHeight)
            {
                // Created at this block height, so just delete
                pOutputCount -= (*reference)->outputCount();
                spentOutputCount = (*reference)->spentOutputCount();
                pSpentOutputCount -= spentOutputCount;
                --pTransactionCount;
                if((*reference)->outputCount() == spentOutputCount)
                    --pSpentTransactionCount;
                delete *reference;
                reference = mReferences.erase(reference);
            }
            else
            {
                (*reference)->revert(pBlockHeight, pSpentOutputCount);
                ++reference;
            }
    }

    TransactionOutputPool::TransactionOutputPool() : mMutex("Output Pool")
    {
        mValid = true;
        mModified = false;
        mNextBlockHeight = 0;
        mSetCount = 0;
        mTransactionCount = 0;
        mOutputCount = 0;
        mSpentTransactionCount = 0;
        mSpentOutputCount = 0;
    }

    // Add all the outputs from a block (pending since they have no block file IDs or offsets yet)
    void TransactionOutputPool::add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
        mMutex.lock();
        TransactionOutputSet *set;
        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
        {
            // Get references set for transaction ID
            set = mReferences + (*transaction)->hash.lookup();
            set->load(mSetCount, mTransactionCount, mOutputCount);
            set->add(new TransactionReference((*transaction)->hash, pBlockHeight, (*transaction)->outputs.size()),
              mTransactionCount, mOutputCount);
        }
        mMutex.unlock();
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
              "Can't commit non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight);
            return false;
        }

        mMutex.lock();
        TransactionOutputSet *set;
        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
        {
            set = mReferences + (*transaction)->hash.lookup();
            set->commit((*transaction)->hash, (*transaction)->outputs, pBlockHeight);
        }
        mNextBlockHeight++;
        mMutex.unlock();

        mModified = true;
        return true;
    }

    void TransactionOutputPool::revert(unsigned int pBlockHeight)
    {
        if(!mValid)
            return;

        mMutex.lock();
        TransactionOutputSet *set = mReferences;
        for(unsigned int i=0;i<totalSets();i++)
        {
            set->revert(pBlockHeight, mTransactionCount, mOutputCount, mSpentTransactionCount, mSpentOutputCount);
            ++set;
        }
        mMutex.unlock();
    }

    TransactionReference *TransactionOutputPool::findUnspent(const Hash &pTransactionID, uint32_t pIndex)
    {
        if(!mValid)
            return NULL;

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Find Unspent");
#endif
        uint16_t lookup = pTransactionID.lookup();
        mMutex.lock();
        TransactionOutputSet *set = mReferences + lookup;
        set->load(mSetCount, mTransactionCount, mOutputCount);
        TransactionReference *result = set->findUnspent(pTransactionID, pIndex);
        mMutex.unlock();

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
        ++mSpentOutputCount;
        if(pReference->outputCount() == pReference->spentOutputCount())
            ++mSpentTransactionCount;
    }

    void TransactionOutputPool::preLoad(unsigned int pCount)
    {
        if(mSetCount == totalSets())
            return;

        mMutex.lock();
        TransactionOutputSet *set = mReferences;
        for(unsigned int i=0;i<totalSets();i++)
        {
            if(!set->isLoaded())
            {
                set->load(mSetCount, mTransactionCount, mOutputCount);
                --pCount;
                if(pCount == 0)
                    break;
            }
            ++set;
        }
        mMutex.unlock();
    }

    bool TransactionOutputPool::load(bool &pStop)
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Loading transaction outputs");

        mMutex.lock();
        mValid = true;
        mTransactionCount = 0;
        mOutputCount = 0;
        mSpentTransactionCount = 0;
        mSpentOutputCount = 0;

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Load Outputs");
#endif
        ArcMist::FileInputStream *file;
        ArcMist::String filePathName, filePath = Info::instance().path();
        filePath.pathAppend("outputs");

        filePathName.writeFormatted("%s%s%s", filePath.text(), PATH_SEPARATOR, "height");
        if(!ArcMist::fileExists(filePathName))
        {
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "No transaction outputs to load");
            mMutex.unlock();
            return mValid;
        }

        file = new ArcMist::FileInputStream(filePathName);
        file->setInputEndian(ArcMist::Endian::LITTLE);
        if(file->remaining() < 4)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to load height");
            mValid = false;
        }
        else
            mNextBlockHeight = file->readUnsignedInt();
        delete file;

        TransactionOutputSet *set = mReferences;
        for(unsigned int i=0;i<totalSets();i++)
        {
            set->set(i, filePath);
            ++set;
        }

        mMutex.unlock();
        return mValid;
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
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME, "Not saving unspent transaction outputs. They weren't modified");
            return true;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Saving transaction outputs at block height %d", mNextBlockHeight - 1);

        unsigned int previousTransctionCount = mTransactionCount;
        unsigned int previousOutputCount = mOutputCount;
        unsigned int previousSize = size();

        mMutex.lock();

        bool success = true;
        ArcMist::FileOutputStream *file;
        ArcMist::String filePathName, filePath = Info::instance().path();
        filePath.pathAppend("outputs");
        ArcMist::createDirectory(filePath);

        filePathName.writeFormatted("%s%s%s", filePath.text(), PATH_SEPARATOR, "height");
        file = new ArcMist::FileOutputStream(filePathName, true);
        if(file->isValid())
            file->writeUnsignedInt(mNextBlockHeight);
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to save height");
            success = false;
        }
        delete file;

        if(success)
        {
            uint32_t lastReport = getTime();
            TransactionOutputSet *set = mReferences;
            for(unsigned int i=0;i<totalSets();i++)
            {
                if(getTime() - lastReport > 10)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                      "Save is %2d%% Complete", (int)(((float)i / (float)totalSets()) * 100.0f));
                    lastReport = getTime();
                }
                set->save(mTransactionCount, mOutputCount, mSpentTransactionCount, mSpentOutputCount);
                ++set;
            }
        }

        mMutex.unlock();

        if(success)
        {
            mModified = false;
            if(mSpentTransactionCount != 0 || mSpentOutputCount != 0)
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to purge %d/%d spent transactions/outputs (%d bytes)", mSpentTransactionCount,
                  mSpentOutputCount, spentSize());

            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
              "Purged %d/%d transactions/outputs (%d bytes)", previousTransctionCount - mTransactionCount,
              previousOutputCount - mOutputCount, previousSize - size());
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
              "Currently %d/%d sets, %d/%d transactions/outputs (%d bytes) (%d bytes spent)",
              mSetCount, totalSets(), mTransactionCount, mOutputCount, size(), spentSize());
        }
        else
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to save transaction outputs");

        return success;
    }
}
