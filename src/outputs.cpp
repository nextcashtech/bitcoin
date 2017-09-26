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

#define BITCOIN_OUTPUTS_LOG_NAME "BitCoin Outputs"


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

    void TransactionOutputReference::write(ArcMist::OutputStream *pStream)
    {
        pStream->writeUnsignedInt(spentBlockHeight);
        pStream->writeUnsignedInt(blockFileOffset);
    }

    bool TransactionOutputReference::read(ArcMist::InputStream *pStream)
    {
        if(pStream->remaining() < FILE_SIZE)
            return false;

        index = 0; // Not in file (set when read by TransactionReference)
        spentBlockHeight = pStream->readUnsignedInt();
        blockFileOffset = pStream->readUnsignedInt();
        return true;
    }

    void TransactionOutputReference::print(ArcMist::Log::Level pLevel)
    {
        ArcMist::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Output Reference");
        ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    File Offset : %d", blockFileOffset);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    Spent       : %d", spentBlockHeight);
    }

    void TransactionReference::write(ArcMist::OutputStream *pStream)
    {
        fileOffset = pStream->writeOffset(); // Remember the offset in the file to make updates quicker
        id.write(pStream);
        pStream->writeUnsignedInt(blockHeight);
        pStream->writeUnsignedInt(mOutputCount);
        TransactionOutputReference *output=mOutputs;
        for(unsigned int index=0;index<mOutputCount;++index,++output)
            output->write(pStream);
    }

    bool TransactionReference::read(ArcMist::InputStream *pStream, unsigned int &pOutputCount,
      unsigned int &pSpentOutputCount)
    {
        if(pStream->remaining() < SIZE + TransactionOutputReference::FILE_SIZE)
            return false;

        fileOffset = pStream->readOffset(); // Remember the offset in the file to make updates quicker
        if(!id.read(pStream))
            return false;
        blockHeight = pStream->readUnsignedInt();

        // Output count
        unsigned int count = pStream->readUnsignedInt();
        if(mOutputCount != count)
        {
            if(mOutputs != NULL)
                delete[] mOutputs;
            mOutputCount = count;
            if(mOutputCount == 0)
            {
                mOutputs = NULL;
                return true;
            }
            mOutputs = new TransactionOutputReference[mOutputCount];
        }

        if(mOutputCount == 0)
            return true;

        if(pStream->remaining() < mOutputCount * TransactionOutputReference::FILE_SIZE)
            return false;

        // Outputs
        TransactionOutputReference *output=mOutputs;
        for(unsigned int index=0;index<mOutputCount;++output)
            if(output->read(pStream))
            {
                output->index = index++;
                ++pOutputCount;
                if(output->spentBlockHeight != 0)
                    ++pSpentOutputCount;
            }
            else
                return false;

        return true;
    }

    unsigned int TransactionReference::spentOutputCount() const
    {
        unsigned int result = 0;
        TransactionOutputReference *output=mOutputs;
        for(unsigned int index=0;index<mOutputCount;++index,++output)
            if(output->spentBlockHeight != 0)
                ++result;
        return result;
    }

    TransactionOutputReference *TransactionReference::outputAt(unsigned int pIndex)
    {
        TransactionOutputReference *output=mOutputs;
        for(unsigned int index=0;index<mOutputCount;++index,++output)
            if(output->index == pIndex)
                return output;
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Invalid output index : %d", pIndex);
        return NULL;
    }

    void TransactionReference::writeSpent(ArcMist::OutputStream *pStream, bool pWrote,
      unsigned int &pOutputCount, unsigned int &pSpentOutputCount)
    {
        if(!pWrote)
        {
            TransactionOutputReference *output=mOutputs;
            for(unsigned int index=0;index<mOutputCount;++index,++output)
                if(output->spentBlockHeight != 0)
                {
                    // 40 (id 32, height 4, output count 4)
                    // + TransactionOutputReference::FILE_SIZE per output before this one to get to the start of this output
                    pStream->setWriteOffset(fileOffset + SIZE + (output->index * TransactionOutputReference::FILE_SIZE));
                    pStream->writeUnsignedInt(output->spentBlockHeight);
                }
        }

        removeSpent(pOutputCount, pSpentOutputCount);
    }

    void TransactionReference::removeSpent(unsigned int &pOutputCount, unsigned int &pSpentOutputCount)
    {
        if(mOutputs == NULL)
            return;

        unsigned int spentCount = 0;
        TransactionOutputReference *output=mOutputs;
        for(unsigned int index=0;index<mOutputCount;++index,++output)
            if(output->spentBlockHeight != 0)
                ++spentCount;

        if(spentCount == 0)
            return;

        if(spentCount == mOutputCount)
        {
            pOutputCount -= mOutputCount;
            pSpentOutputCount -= mOutputCount;
            delete[] mOutputs;
            mOutputs = NULL;
            mOutputCount = 0;
            return;
        }

        TransactionOutputReference *newOutputs = new TransactionOutputReference[mOutputCount - spentCount];
        TransactionOutputReference *newOutput=newOutputs;
        output=mOutputs;
        for(unsigned int index=0;index<mOutputCount;++index,++output)
            if(output->spentBlockHeight == 0)
            {
                *newOutput = *output;
                ++newOutput;
            }

        delete[] mOutputs;
        mOutputs = newOutputs;
        mOutputCount -= spentCount;

        pOutputCount -= spentCount;
        pSpentOutputCount -= spentCount;
    }

    void TransactionReference::commit(std::vector<Output *> &pOutputs)
    {
        if(mOutputs == NULL)
            return;

        TransactionOutputReference *output=mOutputs;
        for(unsigned int index=0;index<mOutputCount;++index,++output)
            output->commit(*pOutputs.at(output->index));
    }

    void TransactionReference::revert(unsigned int pBlockHeight, unsigned int &pSpentOutputCount)
    {
        if(mOutputs == NULL)
            return;

        TransactionOutputReference *output=mOutputs;
        for(unsigned int index=0;index<mOutputCount;++index,++output)
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
        TransactionOutputReference *output=mOutputs;
        for(unsigned int index=0;index<mOutputCount;++index,++output)
            output->print(pLevel);
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
    }

    TransactionReference *TransactionOutputSet::findUnspent(const Hash &pTransactionID, uint32_t pIndex)
    {
        TransactionOutputReference *output;
        for(std::list<TransactionReference *>::iterator reference=mReferences.begin();reference!=mReferences.end();++reference)
            if((*reference)->id == pTransactionID)
            {
                output = (*reference)->outputAt(pIndex);
                if(output != NULL && output->spentBlockHeight == 0)
                    return *reference;
            }
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
      unsigned int &pOutputCount, unsigned int &pSpentTransactionCount, unsigned int &pSpentOutputCount)
    {
        clear();

        ArcMist::String checkStart = pStream->readString(4);

        if(checkStart != START_STRING)
            return false;

        TransactionReference *newReference = new TransactionReference();
        unsigned int outputCount, spentOutputCount;
        while(pStream->remaining())
        {
            outputCount = 0;
            spentOutputCount = 0;
            if(!newReference->read(pStream, outputCount, spentOutputCount))
            {
                delete newReference;
                return false;
            }

            if(outputCount > spentOutputCount) // Not all outputs spent
            {
                if(spentOutputCount > 0)
                    newReference->removeSpent(outputCount, spentOutputCount);
                pOutputCount += outputCount;
                ++pTransactionCount;
                mReferences.push_back(newReference);
                newReference = new TransactionReference();
            }
        }

        delete newReference;
        return true;
    }

    void TransactionOutputSet::add(TransactionReference *pReference, unsigned int &pTransactionCount,
      unsigned int &pOutputCount)
    {
        mReferences.push_back(pReference);
        ++pTransactionCount;
        pOutputCount += pReference->outputCount();
    }

    void TransactionOutputSet::commit(const Hash &pTransactionID, std::vector<Output *> &pOutputs,
      unsigned int pBlockHeight)
    {
        for(std::list<TransactionReference *>::iterator reference=mReferences.begin();reference!=mReferences.end();++reference)
            if((*reference)->blockHeight == pBlockHeight && (*reference)->id == pTransactionID)
                (*reference)->commit(pOutputs);
    }

    void TransactionOutputSet::revert(unsigned int pBlockHeight, unsigned int &pTransactionCount,
      unsigned int &pOutputCount, unsigned int &pSpentTransactionCount, unsigned int &pSpentOutputCount)
    {
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
        mTransactionCount = 0;
        mOutputCount = 0;
        mSpentTransactionCount = 0;
        mSpentOutputCount = 0;
    }

    // Add all the outputs from a block (pending since they have no block file IDs or offsets yet)
    void TransactionOutputPool::add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
        mMutex.lock();
        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
        {
            // Get references set for transaction ID
            mReferences[(*transaction)->hash.lookup()].add(new TransactionReference((*transaction)->hash,
              pBlockHeight, (*transaction)->outputs.size()), mTransactionCount, mOutputCount);
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
        ArcMist::Profiler profiler("Transaction Outputs Commit");
#endif
        if(pBlockHeight != mNextBlockHeight)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't commit non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight);
            return false;
        }

        mMutex.lock();
        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
            mReferences[(*transaction)->hash.lookup()].commit((*transaction)->hash, (*transaction)->outputs, pBlockHeight);
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
        for(unsigned int i=0;i<0x10000;i++)
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
        TransactionReference *result = mReferences[lookup].findUnspent(pTransactionID, pIndex);
        mMutex.unlock();

        return result;
    }

    bool TransactionOutputPool::load(bool &pStop)
    {
        mValid = true;
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME, "Loading transaction outputs");

        mMutex.lock();

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


        if(mValid)
        {
            uint32_t lastReport = getTime();
            TransactionOutputSet *set = mReferences;
            for(unsigned int i=0;i<0x10000&&!pStop;i++)
            {
                if(getTime() - lastReport > 10)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                      "Load is %2d%% Complete", (int)(((float)i / (float)0x10000) * 100.0f));
                    lastReport = getTime();
                }
                filePathName.writeFormatted("%s%s%04x", filePath.text(), PATH_SEPARATOR, i);
                file = new ArcMist::FileInputStream(filePathName);
                file->setInputEndian(ArcMist::Endian::LITTLE);
                if(!set->read(file, mTransactionCount, mOutputCount, mSpentTransactionCount, mSpentOutputCount))
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed to load outputs set %04x", i);
                    delete file;
                    mValid = false;
                    break;
                }
                delete file;
                ++set;
            }

            if(pStop)
                mValid = false;
        }

        mMutex.unlock();

        if(mValid)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
              "Loaded %d/%d transactions/outputs (%d bytes) (%d bytes spent) at block height %d",
              mTransactionCount, mOutputCount, size(), spentSize(), mNextBlockHeight - 1);
        else
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to load transaction outputs");

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
        file->setOutputEndian(ArcMist::Endian::LITTLE);
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
            for(unsigned int i=0;i<0x10000;i++)
            {
                if(getTime() - lastReport > 10)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                      "Save is %2d%% Complete", (int)(((float)i / (float)0x10000) * 100.0f));
                    lastReport = getTime();
                }
                filePathName.writeFormatted("%s%s%04x", filePath.text(), PATH_SEPARATOR, i);
                file = new ArcMist::FileOutputStream(filePathName);
                file->setOutputEndian(ArcMist::Endian::LITTLE);
                if(!file->isValid())
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed to save outputs set %04x", i);
                    delete file;
                    success = false;
                    break;
                }
                else
                    set->write(file, mTransactionCount, mOutputCount, mSpentTransactionCount, mSpentOutputCount);
                delete file;
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
              "Currently %d/%d transactions/outputs (%d bytes) (%d bytes spent)",
              mTransactionCount, mOutputCount, size(), spentSize());
        }
        else
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to save transaction outputs");

        return success;
    }
}
