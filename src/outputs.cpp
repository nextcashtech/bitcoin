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
        // Block File Offset
        pStream->writeUnsignedInt(blockFileOffset);

        // Spent Block Height
        pStream->writeUnsignedInt(spentBlockHeight);
    }

    bool TransactionOutputReference::read(ArcMist::InputStream *pStream)
    {
        if(pStream->remaining() < 8)
            return false;

        // Not in file (set when read by TransactionReference)
        index = 0;

        // Block File Offset
        blockFileOffset = pStream->readUnsignedInt();

        // Spent Block Height
        spentBlockHeight = pStream->readUnsignedInt();

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
        fileOffset = pStream->writeOffset();

        // Transaction Hash
        id.write(pStream);

        // Created Block Height
        pStream->writeUnsignedInt(blockHeight);

        // Output count
        pStream->writeUnsignedInt(mOutputs.size());

        // Outputs
        for(std::vector<TransactionOutputReference>::iterator output=mOutputs.begin();output!=mOutputs.end();++output)
            output->write(pStream);
    }

    bool TransactionReference::read(ArcMist::InputStream *pStream)
    {
        if(pStream->remaining() < 48)
            return false;

        // Transaction Hash
        if(!id.read(pStream))
            return false;

        // Created Block Height
        blockHeight = pStream->readUnsignedInt();

        // Output count
        unsigned int count = pStream->readUnsignedInt();

        // Outputs
        mOutputs.resize(count);
        unsigned int index = 0;
        for(std::vector<TransactionOutputReference>::iterator output=mOutputs.begin();output!=mOutputs.end();++output)
            if(output->read(pStream))
                output->index = index++;
            else
                return false;

        return true;
    }

    TransactionOutputReference *TransactionReference::output(unsigned int pIndex)
    {
        for(std::vector<TransactionOutputReference>::iterator output=mOutputs.begin();output!=mOutputs.end();++output)
            if(output->index == pIndex)
                return &(*output);
        return NULL;
    }

    void TransactionReference::writeSpent(ArcMist::OutputStream *pStream, bool pWrote)
    {
        for(std::vector<TransactionOutputReference>::iterator output=mOutputs.begin();output!=mOutputs.end();)
            if(output->spentBlockHeight != 0)
            {
                if(!pWrote)
                {
                    // 40 (id 32, height 4, output count 4) + 8 per output before this one + 4 to skip block file offset of output
                    pStream->setWriteOffset(fileOffset + 40 + (output->index * 8) + 4);
                    pStream->writeUnsignedInt(output->spentBlockHeight);
                }

                // Remove spent output reference
                output = mOutputs.erase(output);
            }
            else
                ++output;
    }

    void TransactionReference::removeSpent()
    {
        for(std::vector<TransactionOutputReference>::iterator output=mOutputs.begin();output!=mOutputs.end();)
            if(output->spentBlockHeight != 0)
                output = mOutputs.erase(output);
            else
                ++output;
    }

    void TransactionReference::update(std::vector<Output *> &pOutputs)
    {
        for(std::vector<TransactionOutputReference>::iterator output=mOutputs.begin();output!=mOutputs.end();++output)
            output->update(*pOutputs.at(output->index));
    }

    void TransactionReference::revert(unsigned int pBlockHeight)
    {
        for(std::vector<TransactionOutputReference>::iterator output=mOutputs.begin();output!=mOutputs.end();++output)
            if(output->spentBlockHeight == pBlockHeight)
                output->spentBlockHeight = 0; // Spent at this block height, so "unspend"
    }

    void TransactionReference::print(ArcMist::Log::Level pLevel)
    {
        ArcMist::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "Transaction Reference");
        ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Transaction ID : %s", id.hex().text());
        ArcMist::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Height         : %d", blockHeight);

        for(std::vector<TransactionOutputReference>::iterator output=mOutputs.begin();output!=mOutputs.end();++output)
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
                output = (*reference)->output(pIndex);
                if(output != NULL && output->spentBlockHeight == 0)
                    return *reference;
            }
        return NULL;
    }

    void TransactionOutputSet::write(ArcMist::OutputStream *pStream)
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

            (*reference)->writeSpent(pStream, wrote);

            (*reference)->removeSpent();
            if((*reference)->outputCount() == 0) // All outputs unspent
            {
                delete *reference;
                reference = mReferences.erase(reference);
            }
            else
                ++reference;
        }
    }

    // Keep only those with spent block == 0
    bool TransactionOutputSet::read(ArcMist::InputStream *pStream)
    {
        clear();

        ArcMist::String checkStart = pStream->readString(4);

        if(checkStart != START_STRING)
            return false;

        TransactionReference *newReference = new TransactionReference();
        while(pStream->remaining())
        {
            newReference->fileOffset = pStream->readOffset();
            if(!newReference->read(pStream))
            {
                delete newReference;
                return false;
            }

            newReference->removeSpent();
            if(newReference->outputCount() != 0) // Some outputs unspent
            {
                mReferences.push_back(newReference);
                newReference = new TransactionReference();
            }
        }

        delete newReference;
        return true;
    }

    unsigned int TransactionOutputSet::count() const
    {
        unsigned int result = 0;
        for(std::list<TransactionReference *>::const_iterator reference=mReferences.begin();reference!=mReferences.end();++reference)
            result += (*reference)->outputCount();
        return result;
    }

    void TransactionOutputSet::add(TransactionReference *pReference)
    {
        mReferences.push_back(pReference);
    }

    void TransactionOutputSet::commit(const Hash &pTransactionID, std::vector<Output *> &pOutputs, unsigned int pBlockHeight)
    {
        for(std::list<TransactionReference *>::iterator reference=mReferences.begin();reference!=mReferences.end();++reference)
            if((*reference)->blockHeight == pBlockHeight && (*reference)->id == pTransactionID)
                (*reference)->update(pOutputs);
    }

    unsigned int TransactionOutputSet::revert(unsigned int pBlockHeight)
    {
        unsigned int result = 0;
        for(std::list<TransactionReference *>::iterator reference=mReferences.begin();reference!=mReferences.end();)
            if((*reference)->fileOffset == 0xffffffff && (*reference)->blockHeight == pBlockHeight)
            {
                // Created at this block height, so just delete
                delete *reference;
                reference = mReferences.erase(reference);
            }
            else
            {
                (*reference)->revert(pBlockHeight);
                result += (*reference)->outputCount();
                ++reference;
            }
        return result;
    }

    TransactionOutputPool::TransactionOutputPool() : mMutex("Output Pool")
    {
        mValid = true;
        mModified = false;
        mNextBlockHeight = 0;
        mCount = 0;
    }

    TransactionOutputPool::~TransactionOutputPool()
    {

    }

    // Add all the outputs from a block (pending since they have no block file IDs or offsets yet)
    void TransactionOutputPool::add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
        mMutex.lock();
        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
        {
            // Get references set for transaction ID
            mReferences[(*transaction)->hash.lookup()].add(new TransactionReference((*transaction)->hash, pBlockHeight, (*transaction)->outputs.size()));
            mCount += (*transaction)->outputs.size();
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
        mMutex.unlock();

        mNextBlockHeight++;
        mModified = true;
        return true;
    }

    void TransactionOutputPool::revert(unsigned int pBlockHeight)
    {
        if(!mValid)
            return;

        mMutex.lock();
        TransactionOutputSet *set = mReferences;
        mCount = 0;
        for(unsigned int i=0;i<0x10000;i++)
        {
            mCount += set->revert(pBlockHeight);
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

    bool TransactionOutputPool::load()
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
            TransactionOutputSet *set = mReferences;
            for(unsigned int i=0;i<0x10000;i++)
            {
                filePathName.writeFormatted("%s%s%04x", filePath.text(), PATH_SEPARATOR, i);
                file = new ArcMist::FileInputStream(filePathName);
                file->setInputEndian(ArcMist::Endian::LITTLE);
                if(!set->read(file))
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Failed to load outputs set %04x", i);
                    delete file;
                    mValid = false;
                    break;
                }
                delete file;
                mCount += set->count();
                ++set;
            }
        }

        mMutex.unlock();

        if(mValid)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
              "Loaded %d transaction outputs at block height of %d", mCount, mNextBlockHeight);
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

        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME, "Saving unspent transaction outputs");

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
            TransactionOutputSet *set = mReferences;
            for(unsigned int i=0;i<0x10000;i++)
            {
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
                    set->write(file);
                delete file;
                ++set;
            }
        }

        mMutex.unlock();

        if(success)
        {
            mModified = false;
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
              "Saved %d transaction outputs at block height of %d", mCount, mNextBlockHeight);
        }
        else
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to save transaction outputs");

        return success;
    }
}
