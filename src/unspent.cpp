#include "unspent.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/io/file_stream.hpp"
#include "base.hpp"
#include "info.hpp"
#include "events.hpp"

#define BITCOIN_UNSPENT_LOG_NAME "BitCoin Unspent"


namespace BitCoin
{
    Unspent::Unspent(Unspent &pValue)
    {
        amount = pValue.amount;
        pValue.script.setReadOffset(0);
        script.writeStream(&pValue.script, pValue.script.length());
        transactionID = pValue.transactionID;
        index = pValue.index;
        hash = pValue.hash;
    }

    UnspentPool *UnspentPool::sInstance = NULL;

    UnspentPool &UnspentPool::instance()
    {
        if(sInstance == NULL)
        {
            sInstance = new UnspentPool();
            std::atexit(destroy);
        }
        return *sInstance;
    }

    void UnspentPool::destroy()
    {
        delete UnspentPool::sInstance;
        UnspentPool::sInstance = 0;
    }

    UnspentPool::UnspentPool()
    {
        mValid = true;
        mModified = false;
        mLastBlockID = 0;
    }

    UnspentPool::~UnspentPool()
    {
        save();

        for(std::list<Unspent *>::iterator iter=mPendingAdd.begin();iter!=mPendingAdd.end();++iter)
            delete *iter;
    }

    Unspent *UnspentPool::find(const Hash &pTransactionID, uint32_t pIndex)
    {
        if(!mValid)
            return NULL;

        //TODO Special case needed for coinbase transactions whose index == 0xffffffff
        uint16_t lookup = pTransactionID.lookup();
        Unspent *result = mSets[lookup].find(pTransactionID, pIndex);

        if(result == NULL)
        {
            // Check if it is in pending add
            for(std::list<Unspent *>::iterator iter=mPendingAdd.begin();iter!=mPendingAdd.end();++iter)
                if((*iter)->transactionID == pTransactionID && (*iter)->index == pIndex)
                {
                    result = *iter;
                    break;
                }
        }
        else if(result != NULL)
        {
            // Check if it is in pending spend
            for(std::list<Unspent *>::iterator iter=mPendingSpend.begin();iter!=mPendingSpend.end();++iter)
                if(result == *iter)
                    return NULL;
        }

        return result;
    }

    void UnspentPool::add(Unspent &pUnspent)
    {
        if(!mValid)
            return;

        Unspent *newUnspent = new Unspent(pUnspent);
        mPendingAdd.push_back(newUnspent);
    }

    void UnspentPool::spend(Unspent *pUnspent)
    {
        if(!mValid)
            return;

        mPendingSpend.push_back(pUnspent);
    }

    void UnspentPool::commit(unsigned int pBlockID)
    {
        if(!mValid)
            return;

        uint16_t lookup;
        for(std::list<Unspent *>::iterator iter=mPendingAdd.begin();iter!=mPendingAdd.end();++iter)
        {
            lookup = (*iter)->transactionID.lookup();
            mSets[lookup].add(*iter);
        }
        mPendingAdd.clear();

        for(std::list<Unspent *>::iterator iter=mPendingSpend.begin();iter!=mPendingSpend.end();++iter)
        {
            lookup = (*iter)->transactionID.lookup();
            mSets[lookup].remove(*iter);
            delete *iter;
        }
        mPendingSpend.clear();

        mModified = true;
        save();
    }

    void UnspentPool::revert()
    {
        if(!mValid)
            return;

        for(std::list<Unspent *>::iterator iter=mPendingAdd.begin();iter!=mPendingAdd.end();++iter)
            delete *iter;

        mPendingAdd.clear();
        mPendingSpend.clear();
    }

    bool UnspentPool::load()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_UNSPENT_LOG_NAME, "Loading unspent transactions");
        clear();

        // Load from file system
        ArcMist::String filePath = Info::instance().path();
        ArcMist::String filePathName, fileName;
        ArcMist::FileInputStream *file;
        uint16_t fileID;

        filePath.pathAppend("unspent");

        ArcMist::createDirectory(filePath.text());

        for(unsigned int i=0;i<0xffff;i++)
        {
            fileName.clear();
            fileID = ArcMist::Endian::convert(i, ArcMist::Endian::LITTLE);
            fileName.writeHex(&fileID, 2);
            filePathName = filePath;
            filePathName.pathAppend(fileName);

            if(ArcMist::fileExists(filePathName))
            {
                file = new ArcMist::FileInputStream(filePathName);
                file->setInputEndian(ArcMist::Endian::LITTLE);
                if(!mSets[i].read(file))
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_UNSPENT_LOG_NAME, "Failed to read set %04x", fileID);
                    mValid = false;
                }
                delete file;
            }
            //else
            //    ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_UNSPENT_LOG_NAME, "No file for set %04x", fileID);
        }

        return mValid;
    }

    bool UnspentPool::save()
    {
        Events::instance().post(Event::UNSPENTS_SAVED);

        if(!mValid)
        {
            Events::instance().post(Event::UNSPENTS_SAVED);
            return false;
        }

        if(!mModified)
        {
            Events::instance().post(Event::UNSPENTS_SAVED);
            return false;
        }

        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_UNSPENT_LOG_NAME, "Saving unspent transactions");

        ArcMist::String filePath = Info::instance().path();
        ArcMist::String filePathName, fileName;
        ArcMist::FileOutputStream *file;
        uint16_t fileID;

        filePath.pathAppend("unspent");

        ArcMist::createDirectory(filePath.text());

        for(unsigned int i=0;i<0xffff;i++)
        {
            fileName.clear();
            fileID = ArcMist::Endian::convert(i, ArcMist::Endian::LITTLE);
            fileName.writeHex(&fileID, 2);
            filePathName = filePath;
            filePathName.pathAppend(fileName);

            file = new ArcMist::FileOutputStream(filePathName, true);
            file->setOutputEndian(ArcMist::Endian::LITTLE);
            mSets[i].write(file);
            delete file;
        }

        mModified = false;
        return true;
    }

    UnspentSet::~UnspentSet()
    {
        for(std::list<Unspent *>::iterator iter=mPool.begin();iter!=mPool.end();++iter)
            delete *iter;
    }

    void UnspentSet::clear()
    {
        for(std::list<Unspent *>::iterator iter=mPool.begin();iter!=mPool.end();++iter)
            delete *iter;
        mPool.clear();
    }

    Unspent *UnspentSet::find(const Hash &pTransactionID, uint32_t pIndex)
    {
        for(std::list<Unspent *>::iterator iter=mPool.begin();iter!=mPool.end();++iter)
            if((*iter)->transactionID == pTransactionID && (*iter)->index == pIndex)
                return *iter;
        return NULL;
    }

    void UnspentSet::add(Unspent *pUnspent)
    {
        mPool.push_back(pUnspent);
    }

    void UnspentSet::remove(Unspent *pUnspent)
    {
        mPool.remove(pUnspent);
    }

    void UnspentSet::write(ArcMist::OutputStream *pStream)
    {
        pStream->writeString(START_STRING);
        pStream->writeUnsignedInt(mPool.size());
        for(std::list<Unspent *>::iterator iter=mPool.begin();iter!=mPool.end();++iter)
            (*iter)->write(pStream);
    }

    bool UnspentSet::read(ArcMist::InputStream *pStream)
    {
        ArcMist::String startString = pStream->readString(8);
        if(startString != START_STRING)
            return false;
        if(pStream->remaining() < 4)
            return false;
        unsigned int count = pStream->readUnsignedInt();
        Unspent *newUnspent;
        for(unsigned int i=0;i<count;i++)
        {
            newUnspent = new Unspent();
            if(!newUnspent->read(pStream))
            {
                delete newUnspent;
                return false;
            }
            mPool.push_back(newUnspent);
        }
        return true;
    }

    void Unspent::write(ArcMist::OutputStream *pStream)
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

        // Hash Size
        writeCompactInteger(pStream, hash.size());

        // Hash
        hash.write(pStream);
    }

    bool Unspent::read(ArcMist::InputStream *pStream)
    {
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

        // Transaction ID Size
        size = readCompactInteger(pStream);
        if(pStream->remaining() < size)
            return false;

        // Transaction ID
        if(!transactionID.read(pStream, size))
            return false;

        if(pStream->remaining() < 4)
            return false;

        // Index
        index = pStream->readUnsignedInt();

        // Hash Size
        size = readCompactInteger(pStream);
        if(pStream->remaining() < size)
            return false;

        // Hash
        if(!hash.read(pStream, size))
            return false;

        return true;
    }
}
