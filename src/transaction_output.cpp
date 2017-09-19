/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "transaction_output.hpp"

#ifdef PROFILER_ON
#include "arcmist/dev/profiler.hpp"
#endif

#include "arcmist/base/log.hpp"
#include "arcmist/io/file_stream.hpp"
#include "base.hpp"
#include "info.hpp"
#include "interpreter.hpp"

#define BITCOIN_TRANSACTION_OUTPUT_LOG_NAME "BitCoin Transaction Output"


namespace BitCoin
{
    TransactionOutput::TransactionOutput(TransactionOutput &pValue)
    {
        amount = pValue.amount;
        pValue.script.setReadOffset(0);
        script.writeStream(&pValue.script, pValue.script.length());
        transactionID = pValue.transactionID;
        index = pValue.index;
        height = pValue.height;
    }

    TransactionOutput &TransactionOutput::operator = (TransactionOutput &pRight)
    {
        amount = pRight.amount;
        pRight.script.setReadOffset(0);
        script.writeStream(&pRight.script, pRight.script.length());
        transactionID = pRight.transactionID;
        index = pRight.index;
        height = pRight.height;
        return *this;
    }

    void TransactionOutput::write(ArcMist::OutputStream *pStream)
    {
        // Amount
        pStream->writeUnsignedLong(amount);

        // Script Size
        writeCompactInteger(pStream, script.length());

        // Script
        script.setReadOffset(0);
        pStream->writeStream(&script, script.length());

        // Transaction ID Size
        writeCompactInteger(pStream, transactionID.size());

        // Transaction ID
        transactionID.write(pStream);

        // Index
        pStream->writeUnsignedInt(index);

        // Height
        pStream->writeUnsignedInt(height);
    }

    bool TransactionOutput::read(ArcMist::InputStream *pStream)
    {
        // Not in this format
        spendHeight = 0;

        if(pStream->remaining() < 5)
            return false;

        // Amount
        amount = pStream->readUnsignedLong();

        // Script Size
        uint64_t size = readCompactInteger(pStream);
        if(pStream->remaining() < size)
            return false;

        // Script
        script.clear();
        pStream->readStream(&script, size);
        script.compact();

        // Transaction ID Size
        size = readCompactInteger(pStream);
        if(pStream->remaining() < size)
            return false;

        // Transaction ID
        if(!transactionID.read(pStream, size))
            return false;

        if(pStream->remaining() < 8)
            return false;

        // Index
        index = pStream->readUnsignedInt();

        // Height
        height = pStream->readUnsignedInt();

        return true;
    }

    void TransactionOutput::writeSpent(ArcMist::OutputStream *pStream)
    {
        // Transaction ID Size
        writeCompactInteger(pStream, transactionID.size());

        // Transaction ID
        transactionID.write(pStream);

        // Index
        pStream->writeUnsignedInt(index);

        // Height
        pStream->writeUnsignedInt(height);

        // Spend Height
        pStream->writeUnsignedInt(spendHeight);
    }

    bool TransactionOutput::readSpent(ArcMist::InputStream *pStream)
    {
        // Not in this format
        amount = 0;
        script.clear();

        if(pStream->remaining() < 13)
            return false;

        // Transaction ID Size
        uint64_t size = readCompactInteger(pStream);
        if(pStream->remaining() < size)
            return false;

        // Transaction ID
        if(!transactionID.read(pStream, size))
            return false;

        if(pStream->remaining() < 12)
            return false;

        // Index
        index = pStream->readUnsignedInt();

        // Height
        height = pStream->readUnsignedInt();

        // Spend Height
        spendHeight = pStream->readUnsignedInt();

        return true;
    }

    void TransactionOutput::print(ArcMist::Log::Level pLevel)
    {
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Amount         : %.08f", bitcoins(amount));
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Script : (%d bytes)", script.length());
        script.setReadOffset(0);
        ScriptInterpreter::printScript(script, pLevel);
        script.setReadOffset(0);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Transaction ID : %s", transactionID.hex().text());
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Index          : %x", index);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Height         : %d", height);
    }

    TransactionOutputSet::~TransactionOutputSet()
    {
        for(std::list<TransactionOutput *>::iterator iter=mPool.begin();iter!=mPool.end();++iter)
            delete *iter;
    }

    void TransactionOutputSet::clear()
    {
        for(std::list<TransactionOutput *>::iterator iter=mPool.begin();iter!=mPool.end();++iter)
            delete *iter;
        mPool.clear();
    }

    TransactionOutput *TransactionOutputSet::find(const Hash &pTransactionID, uint32_t pIndex)
    {
        for(std::list<TransactionOutput *>::iterator iter=mPool.begin();iter!=mPool.end();++iter)
            if((*iter)->transactionID == pTransactionID && (*iter)->index == pIndex)
                return *iter;
        return NULL;
    }

    void TransactionOutputSet::add(TransactionOutput *pTransactionOutput)
    {
        mPool.push_back(pTransactionOutput);
    }

    void TransactionOutputSet::remove(TransactionOutput *pTransactionOutput)
    {
        mPool.remove(pTransactionOutput);
    }

    void TransactionOutputSet::write(ArcMist::OutputStream *pStream)
    {
        for(std::list<TransactionOutput *>::iterator iter=mPool.begin();iter!=mPool.end();++iter)
            (*iter)->write(pStream);
    }

    void TransactionOutputSet::writeSpent(ArcMist::OutputStream *pStream)
    {
        for(std::list<TransactionOutput *>::iterator iter=mPool.begin();iter!=mPool.end();++iter)
            (*iter)->writeSpent(pStream);
    }

    bool TransactionOutputSet::compare(TransactionOutputSet &pOther, const char *pName, const char *pOtherName)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME,
          "Comparing unspent transaction output sets : %s (%d) - %s (%d)", pName, mPool.size(),
          pOtherName, pOther.mPool.size());

        bool found;
        bool result = true;

        // Loop through all unspent transaction outputs in this set
        for(std::list<TransactionOutput *>::iterator iter=mPool.begin();iter!=mPool.end();++iter)
        {
            found = false;

            // Find a matching unspent transaction output in the other set
            for(std::list<TransactionOutput *>::iterator otherIter=pOther.mPool.begin();otherIter!=pOther.mPool.end();++otherIter)
                if(**iter == **otherIter)
                {
                    found = true;
                    pOther.mPool.erase(otherIter);
                    break;
                }

            if(!found)
            {
                // This one doesn't match
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Only in %s", pName);
                (*iter)->print(ArcMist::Log::INFO);
                result = false;
            }
        }

        // Any remaining in pOther are not matching
        for(std::list<TransactionOutput *>::iterator iter=pOther.mPool.begin();iter!=pOther.mPool.end();)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Only in %s", pOtherName);
            (*iter)->print(ArcMist::Log::INFO);
            result = false;
        }

        return result;
    }

    TransactionOutputPool::TransactionOutputPool() : mMutex("Transaction Output Pool")
    {
        mValid = true;
        mModified = false;
        mNextBlockHeight = 0;
    }

    TransactionOutputPool::~TransactionOutputPool()
    {
        mMutex.lock();
        for(std::list<TransactionOutput *>::iterator iter=mPendingAdd.begin();iter!=mPendingAdd.end();++iter)
            delete *iter;
        mMutex.unlock();

        for(std::list<TransactionOutput *>::iterator iter=mSpentToDelete.begin();iter!=mSpentToDelete.end();++iter)
            delete *iter;
    }

    TransactionOutput *TransactionOutputPool::findUnspent(const Hash &pTransactionID, uint32_t pIndex)
    {
        if(!mValid)
            return NULL;

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Find Unspent");
#endif
        //TODO Special case needed for coinbase transactions whose index == 0xffffffff
        uint16_t lookup = pTransactionID.lookup();
        mMutex.lock();
        TransactionOutput *result = mUnspent[lookup].find(pTransactionID, pIndex);

        if(result == NULL)
        {
            // Check if it is in pending add
            for(std::list<TransactionOutput *>::iterator iter=mPendingAdd.begin();iter!=mPendingAdd.end();++iter)
                if((*iter)->transactionID == pTransactionID && (*iter)->index == pIndex)
                {
                    result = *iter;
                    break;
                }
        }
        else if(result != NULL && !mTest)
        {
            // Check if it is in pending spend
            for(std::list<TransactionOutput *>::iterator iter=mPendingSpend.begin();iter!=mPendingSpend.end();++iter)
                if(result == *iter)
                {
                    result = NULL;
                    break;
                }
        }

        mMutex.unlock();

        if(result == NULL && mTest)
            return findSpent(pTransactionID, pIndex);

        return result;
    }

    void TransactionOutputPool::add(TransactionOutput *pTransactionOutput)
    {
        if(!mValid)
            return;

        mMutex.lock();
        mPendingAdd.push_back(pTransactionOutput);
        mMutex.unlock();
    }

    void TransactionOutputPool::spend(TransactionOutput *pTransactionOutput)
    {
        if(!mValid)
            return;

        pTransactionOutput->spendHeight = mNextBlockHeight;

        mMutex.lock();
        mPendingSpend.push_back(pTransactionOutput);
        mMutex.unlock();
    }

    bool TransactionOutputPool::commit(unsigned int pBlockHeight)
    {
        if(!mValid)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Can't commit invalid unspent pool");
            return false;
        }

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Transaction Outputs Commit");
#endif
        if(pBlockHeight != mNextBlockHeight)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME,
              "Can't commit non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight);
            return false;
        }

        uint16_t lookup;
        mMutex.lock();
        for(std::list<TransactionOutput *>::iterator iter=mPendingAdd.begin();iter!=mPendingAdd.end();++iter)
        {
            lookup = (*iter)->transactionID.lookup();
            mUnspent[lookup].add(*iter);
            mTransactionOutputCount++;
        }
        mPendingAdd.clear();

        for(std::list<TransactionOutput *>::iterator iter=mPendingSpend.begin();iter!=mPendingSpend.end();++iter)
        {
            lookup = (*iter)->transactionID.lookup();
            mSpent[lookup].add(*iter);
            mUnspent[lookup].remove(*iter);
            mTransactionOutputCount--;
        }
        mPendingSpend.clear();

        mNextBlockHeight++;
        mModified = true;
        mMutex.unlock();
        return true;
    }

    void TransactionOutputPool::revert()
    {
        if(!mValid)
            return;

        mMutex.lock();
        for(std::list<TransactionOutput *>::iterator iter=mPendingAdd.begin();iter!=mPendingAdd.end();++iter)
            delete *iter;

        mPendingAdd.clear();
        mPendingSpend.clear();
        mMutex.unlock();
    }

    bool TransactionOutputPool::load()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Loading unspent transaction outputs");

        ArcMist::String filePathName = Info::instance().path();
        ArcMist::FileInputStream *file;
        TransactionOutput *nextTransactionOutput;

        filePathName.pathAppend("unspent");

        if(ArcMist::fileExists(filePathName))
        {
            file = new ArcMist::FileInputStream(filePathName);
            file->setInputEndian(ArcMist::Endian::LITTLE);

            if(!file->isValid())
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME,
                  "Failed to open unspent transaction outputs file");
                delete file;
                mValid = false;
                return false;
            }

            // Read height from file
            mNextBlockHeight = file->readUnsignedInt();

            mMutex.lock();
            while(file->remaining() > 0)
            {
                nextTransactionOutput = new TransactionOutput();
                if(nextTransactionOutput->read(file))
                {
                    mUnspent[nextTransactionOutput->transactionID.lookup()].add(nextTransactionOutput);
                    mTransactionOutputCount++;
                }
                else
                {
                    mValid = false;
                    delete nextTransactionOutput;
                    break;
                }
            }
            mMutex.unlock();
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME,
          "Loaded %d unspent transaction outputs at block height %d", mTransactionOutputCount, mNextBlockHeight);

        return mValid;
    }

    bool TransactionOutputPool::save()
    {
        if(!mValid)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Can't save invalid unspent pool");
            return false;
        }

        if(!mModified)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Not saving unspent transaction outputs. They weren't modified");
            return true;
        }

        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Saving unspent transaction outputs");

        ArcMist::String filePathName = Info::instance().path();
        ArcMist::FileOutputStream *file;

        filePathName.pathAppend("unspent");
        file = new ArcMist::FileOutputStream(filePathName, true);
        file->setOutputEndian(ArcMist::Endian::LITTLE);

        if(!file->isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME, "Failed to open unspent file for writing");
            delete file;
            return false;
        }

        // Write height to file
        file->writeUnsignedInt(mNextBlockHeight);

        mMutex.lock();

        // Write all the unspent sets to the file
        TransactionOutputSet *set = mUnspent;
        for(unsigned int i=0;i<0x10000;i++)
        {
            set->write(file);
            ++set;
        }
        mModified = false;
        delete file;

        ArcMist::String filePath = Info::instance().path();
        ArcMist::String fileName;
        filePath.pathAppend("spent");
        ArcMist::createDirectory(filePath);

        // Append all the spent sets to the files
        set = mSpent;
        uint16_t bigID;
        for(unsigned int fileID=0x0000;fileID<0x10000;fileID++)
        {
            filePathName = filePath;
            bigID = ArcMist::Endian::convert(fileID, ArcMist::Endian::BIG);
            fileName.writeHex(&bigID, 2);
            filePathName.pathAppend(fileName);
            file = new ArcMist::FileOutputStream(filePathName, false, true); // Append to file
            if(!file->isValid())
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME,
                  "Failed to open spent file for writing : %04x", fileID);
                delete file;
                return false;
            }
            else
            {
                file->setOutputEndian(ArcMist::Endian::LITTLE);
                set->writeSpent(file);
                set->clear(); // Clear so they don't get appended again
            }
            delete file;
            ++set;
        }

        mMutex.unlock();
        return true;
    }

    // Find a spent transaction output
    TransactionOutput *TransactionOutputPool::findSpent(const Hash &pTransactionID, uint32_t pIndex)
    {
        uint16_t lookup = pTransactionID.lookup();
        TransactionOutput *result;

        // Search through spent not saved to files yet
        mMutex.lock();
        result = mSpent[lookup].find(pTransactionID, pIndex);
        mMutex.unlock();

        if(result != NULL)
            return result;

        // Search file associated with lookup
        ArcMist::FileInputStream *file;
        ArcMist::String filePathName = Info::instance().path();
        ArcMist::String fileName;
        filePathName.pathAppend("spent");
        uint16_t bigID;
        bigID = ArcMist::Endian::convert(lookup, ArcMist::Endian::BIG);
        fileName.writeHex(&bigID, 2);
        filePathName.pathAppend(fileName);
        file = new ArcMist::FileInputStream(filePathName);
        file->setInputEndian(ArcMist::Endian::LITTLE);

        if(!file->isValid())
            return NULL;

        result = new TransactionOutput;
        while(file->remaining())
        {
            if(result->readSpent(file) && result->transactionID == pTransactionID && result->index == pIndex)
            {
                delete file;
                mSpentToDelete.push_back(result);
                return result;
            }
        }

        delete file;
        delete result;
        return NULL;
    }

    bool TransactionOutputPool::compare(TransactionOutputPool &pOther, const char *pName, const char *pOtherName)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME,
          "Comparing unspent transaction output pools : %s (%d) - %s (%d)", pName, count(), pOtherName, pOther.count());

        bool result = true;
        unsigned int i = 0;
        TransactionOutputSet *otherSet = pOther.mUnspent;

        for(TransactionOutputSet *set=mUnspent;i<0x10000;++i,++set)
            result = set->compare(*otherSet++, pName, pOtherName) && result;

        if(result)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_TRANSACTION_OUTPUT_LOG_NAME,
              "TransactionOutput transaction output pools are equal : %s (%d) == %s (%d)", pName, count(), pOtherName, pOther.count());

        return result;
    }
}
