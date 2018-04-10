/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                   *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "forks.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#endif

#include "log.hpp"
#include "file_stream.hpp"
#include "base.hpp"
#include "info.hpp"

#include <algorithm>


namespace BitCoin
{
    BlockStats::~BlockStats()
    {
        mMutex.lock();
#ifdef LOW_MEM
        for(std::vector<BlockStat *>::iterator stat=mCached.begin();stat!=mCached.end();++stat)
            delete *stat;
        if(mFileStream != NULL)
            delete mFileStream;
#else
        for(iterator stat=begin();stat!=end();++stat)
            delete *stat;
#endif
        mMutex.unlock();
    }

    bool BlockStats::load(bool pLocked)
    {
        if(!pLocked)
            mMutex.lock();

#ifdef LOW_MEM
        if(mFileStream != NULL)
            delete mFileStream;
        mFileStream = NULL;
        mCachedOffset = 0;
        for(std::vector<BlockStat *>::iterator stat=mCached.begin();stat!=mCached.end();++stat)
            delete *stat;
        mCached.clear();
#else
        for(std::vector<BlockStat *>::iterator stat=begin();stat!=end();++stat)
            delete *stat;
        clear();
#endif

        NextCash::String filePathName = Info::instance().path();
        BlockStat *newStat;
        filePathName.pathAppend("block_stats");
        if(!NextCash::fileExists(filePathName))
        {
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "No block stats file to load");
            mIsValid = true;
            if(!pLocked)
                mMutex.unlock();
            return true;
        }

#ifdef LOW_MEM
        mFileStream = new NextCash::FileInputStream(filePathName);
        if(!mFileStream->isValid())
        {
            delete mFileStream;
            mFileStream = NULL;
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
                               "Failed to open block stats file to load");
            mIsValid = false;
            if(!pLocked)
                mMutex.unlock();
            return false;
        }

        // Cache 2500 block stats
        if((mFileStream->length() / BlockStat::SIZE) > 2500)
            mCachedOffset = (mFileStream->length() / BlockStat::SIZE) - 2500;
        else
            mCachedOffset = 0;
        mFileStream->setReadOffset(mCachedOffset * BlockStat::SIZE);
        mCached.reserve(2500);
        while(mFileStream->remaining() > 0)
        {
            newStat = new BlockStat();
            newStat->read(mFileStream);
            mCached.push_back(newStat);
        }
#else
        NextCash::FileInputStream file(filePathName);
        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
                               "Failed to open block stats file to load");
            mIsValid = false;
            if(!pLocked)
                mMutex.unlock();
            return false;
        }

        reserve(file.length() / BlockStat::SIZE);
        while(file.remaining() > 0)
        {
            newStat = new BlockStat();
            newStat->read(&file);
            push_back(newStat);
        }
#endif

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
          "Loaded block statistics at height %d", height());
        mIsValid = true;
        mIsModified = false;
        if(!pLocked)
            mMutex.unlock();
        return true;
    }

    bool BlockStats::save()
    {
        mMutex.lock();

        if(!mIsModified)
        {
            mMutex.unlock();
            return true;
        }

        if(!mIsValid)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
              "Not saving block stats. Not valid.");
            mMutex.unlock();
            return false;
        }

        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend("block_stats");

#ifdef LOW_MEM
        int previousHeight = height();
        NextCash::FileOutputStream *outputFile = new NextCash::FileOutputStream(filePathName + ".temp", true);
        if(!outputFile->isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
                               "Failed to open temp block stats file to save");
            mMutex.unlock();
            return false;
        }

        // Write uncached data to new file
        if(mFileStream != NULL && mCachedOffset > 0)
        {
            mFileStream->setReadOffset(0);
            outputFile->writeStream(mFileStream, mCachedOffset * BlockStat::SIZE);
            delete mFileStream;
            mFileStream = NULL;
        }

        // Write cache to file
        for(std::vector<BlockStat *>::iterator stat=mCached.begin();stat!=mCached.end();++stat)
        {
            (*stat)->write(outputFile);
            delete *stat;
        }
        mCachedOffset = 0;
        mCached.clear();
        delete outputFile;

        // Rename new file to original name
        NextCash::removeFile(filePathName);
        NextCash::renameFile(filePathName + ".temp", filePathName);

        // Reload
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
          "Saved block statistics at height %d", previousHeight);
        bool success = load(true);
        if(success)
            mIsModified = false;
        mMutex.unlock();
        return success;
#else
        NextCash::FileOutputStream file(filePathName, true);
        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
                               "Failed to open block stats file to save");
            mMutex.unlock();
            return false;
        }

        for(iterator stat=begin();stat!=end();++stat)
            (*stat)->write(&file);

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
          "Saved block statistics at height %d", height());
        mIsModified = false;
        mMutex.unlock();
        return true;
#endif
    }

    int32_t BlockStats::version(unsigned int pBlockHeight)
    {
        mMutex.lock();

#ifdef LOW_MEM
        if(pBlockHeight >= mCachedOffset + mCached.size())
        {
            mMutex.unlock();
            return 0;
        }

        // Read from cache if possible
        if(pBlockHeight >= mCachedOffset)
        {
            int32_t result = mCached.at(pBlockHeight - mCachedOffset)->version;
            mMutex.unlock();
            return result;
        }

        // Read from file
        mFileStream->setReadOffset(pBlockHeight * BlockStat::SIZE);
        BlockStat stat;
        stat.read(mFileStream);
        mMutex.unlock();
        return stat.version;
#else
        if(pBlockHeight >= size())
        {
            mMutex.unlock();
            return 0;
        }
        int32_t result = at(pBlockHeight)->version;
        mMutex.unlock();
        return result;
#endif
    }

    int32_t BlockStats::time(unsigned int pBlockHeight, bool pLocked)
    {
        if(!pLocked)
            mMutex.lock();

#ifdef LOW_MEM
        if(pBlockHeight >= mCachedOffset + mCached.size())
        {
            if(!pLocked)
                mMutex.unlock();
            return 0;
        }

        // Read from cache if possible
        if(pBlockHeight >= mCachedOffset)
        {
            int32_t result = mCached.at(pBlockHeight - mCachedOffset)->time;
            if(!pLocked)
                mMutex.unlock();
            return result;
        }

        // Read from file
        mFileStream->setReadOffset(pBlockHeight * BlockStat::SIZE);
        BlockStat stat;
        stat.read(mFileStream);
        if(!pLocked)
            mMutex.unlock();
        return stat.time;
#else
        if(pBlockHeight >= size())
        {
            if(!pLocked)
                mMutex.unlock();
            return 0;
        }
        int32_t result = at(pBlockHeight)->time;
        if(!pLocked)
            mMutex.unlock();
        return result;
#endif
    }

    uint32_t BlockStats::targetBits(unsigned int pBlockHeight)
    {
        mMutex.lock();

#ifdef LOW_MEM
        if(pBlockHeight >= mCachedOffset + mCached.size())
        {
            mMutex.unlock();
            return 0;
        }

        // Read from cache if possible
        if(pBlockHeight >= mCachedOffset)
        {
            uint32_t result = mCached.at(pBlockHeight - mCachedOffset)->targetBits;
            mMutex.unlock();
            return result;
        }

        // Read from file
        mFileStream->setReadOffset(pBlockHeight * BlockStat::SIZE);
        BlockStat stat;
        stat.read(mFileStream);
        mMutex.unlock();
        return stat.targetBits;
#else
        if(pBlockHeight >= size())
        {
            mMutex.unlock();
            return 0;
        }
        uint32_t result = at(pBlockHeight)->targetBits;
        mMutex.unlock();
        return result;
#endif
    }

    const NextCash::Hash BlockStats::accumulatedWork(unsigned int pBlockHeight)
    {
        static NextCash::Hash zeroHash(32);

        mMutex.lock();

#ifdef LOW_MEM
        if(pBlockHeight >= mCachedOffset + mCached.size())
        {
            mMutex.unlock();
            return zeroHash;
        }

        // Read from cache if possible
        if(pBlockHeight >= mCachedOffset)
        {
            NextCash::Hash result = mCached.at(pBlockHeight - mCachedOffset)->accumulatedWork;
            mMutex.unlock();
            return result;
        }

        // Read from file
        mFileStream->setReadOffset(pBlockHeight * BlockStat::SIZE);
        BlockStat stat;
        stat.read(mFileStream);
        mMutex.unlock();
        return stat.accumulatedWork;
#else
        if(pBlockHeight >= size())
        {
            mMutex.unlock();
            return zeroHash;
        }
        NextCash::Hash result = at(pBlockHeight)->accumulatedWork;
        mMutex.unlock();
        return result;
#endif
    }

    int32_t BlockStats::getMedianPastTime(unsigned int pBlockHeight, unsigned int pMedianCount)
    {
        std::vector<int32_t> times;

        mMutex.lock();

#ifdef LOW_MEM
        if(pBlockHeight >= mCachedOffset + mCached.size())
        {
            mMutex.unlock();
            return 0;
        }

        for(unsigned int i=pBlockHeight-pMedianCount;i<pBlockHeight;++i)
            times.push_back(time(i, true));
#else
        if(pBlockHeight > size())
        {
            if(!pLocked)
                mMutex.unlock();
            return 0;
        }

        const_iterator stat = begin() + (pBlockHeight - pMedianCount);
        const_iterator endStat = begin() + pBlockHeight;
        while(stat < endStat)
        {
            times.push_back((*stat)->time);
            ++stat;
        }
#endif

        mMutex.unlock();

        // Sort times
        std::sort(times.begin(), times.end());

        // Return the median time
        return times[pMedianCount / 2];
    }

    bool blockStatLessThan(const BlockStat *pLeft, const BlockStat *pRight)
    {
        return *pLeft < *pRight;
    }

    void BlockStats::getMedianPastTimeAndWork(unsigned int pBlockHeight, int32_t &pTime,
      NextCash::Hash &pAccumulatedWork, unsigned int pMedianCount)
    {
        std::vector<BlockStat *> values, toDelete;
        unsigned int statHeight = pBlockHeight - pMedianCount + 1;

        mMutex.lock();

#ifdef LOW_MEM
        BlockStat *newStat;
        for(unsigned int i=pBlockHeight-pMedianCount+1;i<pBlockHeight+1;++i)
        {
            if(i >= mCachedOffset)
                values.push_back(mCached[i-mCachedOffset]);
            else
            {
                newStat = new BlockStat();
                mFileStream->setReadOffset(i * BlockStat::SIZE);
                newStat->read(mFileStream);
                toDelete.push_back(newStat);
                values.push_back(newStat);
            }
            ++statHeight;
        }
#else
        const_iterator stat = begin() + (pBlockHeight - pMedianCount + 1);
        const_iterator endStat = begin() + (pBlockHeight + 1);
        while(stat < endStat)
        {
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_FORKS_LOG_NAME,
              // "Adding stat to median calculate height %d, time %d, diff 0x%08x, work %s", statHeight, (*stat)->time, (*stat)->targetBits,
              // (*stat)->accumulatedWork.hex().text());
            values.push_back(*stat);
            ++stat;
            ++statHeight;
        }
#endif

        mMutex.unlock();

        // Sort
        std::sort(values.begin(), values.end(), blockStatLessThan);

        // for(std::vector<BlockStat *>::iterator item=values.begin();item!=values.end();++item)
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_FORKS_LOG_NAME,
              // "Sorted stat median calculate time %d, work %s", (*item)->time, (*item)->accumulatedWork.hex().text());

        pTime = values[pMedianCount / 2]->time;
        pAccumulatedWork = values[pMedianCount / 2]->accumulatedWork;
        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_FORKS_LOG_NAME,
          // "Using median calculate time %d, work %s", pTime, pAccumulatedWork.hex().text());

#ifdef LOW_MEM
        for(std::vector<BlockStat *>::iterator stat=toDelete.begin();stat!=toDelete.end();++stat)
            delete *stat;
#endif
    }

    void SoftFork::write(NextCash::OutputStream *pStream)
    {
        pStream->writeByte(name.length());
        pStream->writeString(name);
        pStream->writeUnsignedInt(id);
        pStream->writeByte(bit);
        pStream->writeUnsignedInt(startTime);
        pStream->writeUnsignedInt(timeout);

        pStream->writeByte(state);
        pStream->writeInt(lockedHeight);
    }

    bool SoftFork::read(NextCash::InputStream *pStream)
    {
        if(pStream->remaining() < 1)
            return false;

        unsigned int nameLength = pStream->readByte();

        if(pStream->remaining() < nameLength + 18)
            return false;

        name = pStream->readString(nameLength);
        id = pStream->readUnsignedInt();
        bit = pStream->readByte();
        startTime = pStream->readUnsignedInt();
        timeout = pStream->readUnsignedInt();

        state = static_cast<SoftFork::State>(pStream->readByte());
        lockedHeight = pStream->readInt();
        return true;
    }

    const char *SoftFork::stateName()
    {
        switch(state)
        {
        default:
        case UNDEFINED:
            return "Undefined";
        case DEFINED:
            return "Defined";
        case STARTED:
            return "Started";
        case LOCKED_IN:
            return "Locked In";
        case ACTIVE:
            return "Active";
        case FAILED:
            return "Failed";
        }
    }

    NextCash::String SoftFork::description()
    {
        NextCash::String result;
        switch(state)
        {
        default:
        case UNDEFINED:
            result = "Undefined";
            break;
        case DEFINED:
        {
            NextCash::String startTimeText;
            startTimeText.writeFormattedTime(startTime);
            result.writeFormatted("Defined : start at %s", startTimeText.text());
            break;
        }
        case STARTED:
        {
            NextCash::String timeoutText;
            timeoutText.writeFormattedTime(timeout);
            result.writeFormatted("Started : timeout at %s", timeoutText.text());
            break;
        }
        case LOCKED_IN:
            result.writeFormatted("Locked in at block height %d", lockedHeight);
            break;
        case ACTIVE:
            result.writeFormatted("Active at block height %d", lockedHeight + RETARGET_PERIOD);
            break;
        case FAILED:
            NextCash::String timeoutText;
            timeoutText.writeFormattedTime(timeout);
            result.writeFormatted("Failed : timeout at %s", timeoutText.text());
            break;
        }
        return result;
    }

    void SoftFork::revert(BlockStats &pBlockStats, int pBlockHeight)
    {
        switch(state)
        {
        default:
        case UNDEFINED:
        case DEFINED:
            break;
        case STARTED:
            if(pBlockStats.time(pBlockHeight) < startTime)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Soft fork %s reverted from STARTED to DEFINED", name.text());
                state = DEFINED;
            }
            break;
        case LOCKED_IN:
            if(pBlockHeight < lockedHeight)
            {
                lockedHeight = NOT_LOCKED;
                if(pBlockStats.time(pBlockHeight) < startTime)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Soft fork %s reverted from LOCKED_IN to DEFINED", name.text());
                    state = DEFINED;
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Soft fork %s reverted from LOCKED_IN to STARTED", name.text());
                    state = STARTED;
                }
            }
            break;
        case ACTIVE:
            if(pBlockHeight < lockedHeight)
            {
                lockedHeight = NOT_LOCKED;
                if(pBlockStats.time(pBlockHeight) < startTime)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Soft fork %s reverted from ACTIVE to DEFINED", name.text());
                    state = DEFINED;
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Soft fork %s reverted from ACTIVE to STARTED", name.text());
                    state = STARTED;
                }
            }
            else if(pBlockHeight < lockedHeight + RETARGET_PERIOD)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Soft fork %s reverted from ACTIVE to LOCKED_IN", name.text());
                state = LOCKED_IN;
            }
            break;
        case FAILED:
            if(pBlockStats.time(pBlockHeight) < startTime)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Soft fork %s reverted from FAILED to DEFINED", name.text());
                state = DEFINED;
            }
            else if(pBlockStats.time(pBlockHeight) < timeout)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Soft fork %s reverted from FAILED to STARTED", name.text());
                state = STARTED;
            }
            break;
        }
    }

    Forks::Forks() : mMutex("Forks")
    {
        mHeight = 0;
        mEnabledVersion = 1;
        mRequiredVersion = 1;
        mCashForkBlockHeight = -1;
        mBlockMaxSize = HARD_MAX_BLOCK_SIZE;
        mModified = false;

        for(unsigned int i=0;i<3;i++)
        {
            mVersionEnabledHeights[i] = -1;
            mVersionRequiredHeights[i] = -1;
        }

        switch(network())
        {
        case MAINNET:
            mThreshHold = 1916;

            // Add known soft forks
            mForks.push_back(new SoftFork("BIP-0068,BIP-0112,BIP-0113", SoftFork::BIP0068, 0, 1462060800, 1493596800));
            mForks.push_back(new SoftFork("BIP-0141", SoftFork::BIP0141, 1, 1479168000, 1510704000));
            mForks.push_back(new SoftFork("BIP-0091", SoftFork::BIP0091, 4, 1496275200, 1510704000));
            break;
        default:
        case TESTNET:
            mThreshHold = 1512;

            // Add known soft forks
            mForks.push_back(new SoftFork("BIP-0068,BIP-0112,BIP-0113", SoftFork::BIP0068, 0, 1462060800, 1493596800));
            mForks.push_back(new SoftFork("BIP-0141", SoftFork::BIP0141, 1, 1462060800, 1493596800));
            break;
        }
    }

    Forks::~Forks()
    {
        mMutex.lock();
        for(std::vector<SoftFork *>::iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            delete *softFork;
        mMutex.unlock();
    }

    SoftFork::State Forks::softForkState(unsigned int pID)
    {
        SoftFork::State result = SoftFork::UNDEFINED;
        mMutex.lock();

        for(std::vector<SoftFork *>::const_iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            if((*softFork)->id == pID)
            {
                result = (*softFork)->state;
                break;
            }

        mMutex.unlock();
        return result;
    }

    void Forks::process(BlockStats &pBlockStats, int pBlockHeight)
    {
        mMutex.lock();

#ifdef PROFILER_ON
        NextCash::Profiler outputsProfiler("Forks Process");
#endif
        if(pBlockHeight < 0)
        {
            mMutex.unlock();
            return;
        }

        unsigned int offset;
        int topStatHeight = pBlockHeight;

        if(mRequiredVersion < 4)
        {
            unsigned int totalCount = 1000;
            int activateCount = 750;
            int requireCount = 950;

            if(network() == TESTNET)
            {
                totalCount = 100;
                activateCount = 51;
                requireCount = 75;
            }

            int version4OrHigherCount = 0;
            int version3OrHigherCount = 0;
            int version2OrHigherCount = 0;
            offset = 0;
            for(int height=topStatHeight;height>=0&&offset<totalCount;--height,++offset)
            {
                switch(pBlockStats.version(height))
                {
                default:
                case 4:
                    version4OrHigherCount++;
                case 3:
                    version3OrHigherCount++;
                case 2:
                    version2OrHigherCount++;
                case 1:
                case 0:
                    break;
                }
            }

            // BIP-0065
            if(version4OrHigherCount >= requireCount)
            {
                if(mRequiredVersion < 4)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Version 4 blocks now required (height %d)", pBlockHeight);
                    mVersionRequiredHeights[2] = pBlockHeight;
                    mRequiredVersion = 4;
                    mModified = true;
                }
                if(mEnabledVersion < 4)
                {
                    mVersionEnabledHeights[2] = pBlockHeight;
                    mEnabledVersion = 4;
                    mModified = true;
                }
            }
            else if(mEnabledVersion < 4 && version4OrHigherCount >= activateCount)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Version 4 blocks now enabled (height %d)", pBlockHeight);
                mVersionEnabledHeights[2] = pBlockHeight;
                mEnabledVersion = 4;
                mModified = true;
            }

            // BIP-0066
            if(version3OrHigherCount >= requireCount)
            {
                if(mRequiredVersion < 3)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Version 3 blocks now required (height %d)", pBlockHeight);
                    mVersionRequiredHeights[1] = pBlockHeight;
                    mRequiredVersion = 3;
                    mModified = true;
                }
                if(mEnabledVersion < 3)
                {
                    mVersionEnabledHeights[1] = pBlockHeight;
                    mEnabledVersion = 3;
                    mModified = true;
                }
            }
            else if(mEnabledVersion < 3 && version3OrHigherCount >= activateCount)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Version 3 blocks now enabled (height %d)", pBlockHeight);
                mVersionEnabledHeights[1] = pBlockHeight;
                mEnabledVersion = 3;
                mModified = true;
            }

            // BIP-0034
            if(version2OrHigherCount >= requireCount)
            {
                if(mRequiredVersion < 2)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Version 2 blocks now required (height %d)", pBlockHeight);
                    mVersionRequiredHeights[0] = pBlockHeight;
                    mRequiredVersion = 2;
                    mModified = true;
                }
                if(mEnabledVersion < 2)
                {
                    mVersionEnabledHeights[0] = pBlockHeight;
                    mEnabledVersion = 2;
                    mModified = true;
                }
            }
            else if(mEnabledVersion < 2 && version2OrHigherCount >= activateCount)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Version 2 blocks now enabled (height %d)", pBlockHeight);
                mVersionEnabledHeights[0] = pBlockHeight;
                mEnabledVersion = 2;
                mModified = true;
            }
        }

        mHeight = pBlockHeight;
        mModified = true;

        if(mRequiredVersion >= 4 && pBlockHeight != 0 && pBlockHeight % RETARGET_PERIOD == 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "Updating for block height %d", pBlockHeight);

            uint32_t compositeValue = 0;
            int32_t version;
            int32_t medianTimePast = pBlockStats.getMedianPastTime(pBlockHeight);
            for(std::vector<SoftFork *>::iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            {
                compositeValue |= (0x01 << (*softFork)->bit);

                switch((*softFork)->state)
                {
                    case SoftFork::DEFINED:
                        if(medianTimePast > (*softFork)->timeout)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) failed (height %d)", (*softFork)->name.text(), pBlockHeight);
                            (*softFork)->state = SoftFork::FAILED;
                            mModified = true;
                        }
                        else if(medianTimePast > (*softFork)->startTime)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) started (height %d)", (*softFork)->name.text(), pBlockHeight);
                            (*softFork)->state = SoftFork::STARTED;
                            mModified = true;
                        }
                        break;
                    case SoftFork::STARTED:
                    {
                        if(medianTimePast > (*softFork)->timeout)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) failed (height %d)", (*softFork)->name.text(), pBlockHeight);
                            (*softFork)->state = SoftFork::FAILED;
                            mModified = true;
                            break;
                        }

                        unsigned int support = 0;
                        offset = 0;
                        for(int height=topStatHeight;height>=0&&offset<RETARGET_PERIOD;--height,++offset)
                        {
                            version = pBlockStats.version(height);
                            if((version & 0xE0000000) == 0x20000000 && (version >> (*softFork)->bit) & 0x01)
                                ++support;
                        }

                        if(support >= mThreshHold)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) locked in with support %d/%d (height %d)", (*softFork)->name.text(), support,
                              mThreshHold, pBlockHeight);
                            (*softFork)->lockedHeight = pBlockHeight;
                            (*softFork)->state = SoftFork::LOCKED_IN;
                            mModified = true;
                        }
                        else
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) still started with support %d/%d (height %d)", (*softFork)->name.text(), support,
                              mThreshHold, pBlockHeight);
                        }

                        break;
                    }
                    case SoftFork::LOCKED_IN:
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                          "Soft fork (%s) active (height %d)", (*softFork)->name.text(), pBlockHeight);
                        (*softFork)->state = SoftFork::ACTIVE;
                        mModified = true;
                        break;
                    default:
                    case SoftFork::ACTIVE:
                    case SoftFork::FAILED:
                        break;
                }
            }

            // Warn about unknown forks (bits set in version not corresponding to known soft forks)
            unsigned int i;
            unsigned int unknownSupport[29];
            for(i=0;i<29;i++)
                unknownSupport[i] = 0;

            offset = 0;
            for(int height=topStatHeight;height>=0&&offset<RETARGET_PERIOD;--height,++offset)
            {
                version = pBlockStats.version(height);
                if((version & 0xE0000000) != 0x20000000)
                    continue;
                if((version | compositeValue) != compositeValue)
                {
                    for(i=0;i<29;i++)
                        if((version & (0x01 << i)) && !(compositeValue & (0x01 << i)))
                            ++unknownSupport[i]; // Bit set in version and not in composite
                }
            }

            for(i=0;i<29;i++)
                if(unknownSupport[i] > 0)
                {
                    NextCash::Log::addFormatted(NextCash::Log::NOTIFICATION, BITCOIN_FORKS_LOG_NAME,
                      "Unknown soft fork for bit %d with %d/%d support (height %d)", i, unknownSupport[i],
                      RETARGET_PERIOD, pBlockHeight);
                }
        }

        if(pBlockHeight > 12 && mCashForkBlockHeight == -1 && CASH_ACTIVATION_TIME != 0 &&
          pBlockStats.getMedianPastTime(pBlockHeight) >= CASH_ACTIVATION_TIME)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "Cash fork activated at block height %d", pBlockHeight);
            mCashForkBlockHeight = mHeight - 1;
            mBlockMaxSize = CASH_START_MAX_BLOCK_SIZE;
        }

        mMutex.unlock();
    }

    void Forks::revert(BlockStats &pBlockStats, int pBlockHeight)
    {
        mMutex.lock();

        // Back out any version enabled/required heights below new block height
        for(unsigned int i=0;i<3;++i)
        {
            if(mVersionRequiredHeights[i] != -1 && mVersionRequiredHeights[i] > pBlockHeight)
                mVersionRequiredHeights[i] = -1;
            if(mVersionEnabledHeights[i] != -1 && mVersionEnabledHeights[i] > pBlockHeight)
                mVersionEnabledHeights[i] = -1;
        }

        if(mVersionRequiredHeights[2] != -1 && pBlockHeight >= mVersionRequiredHeights[2])
            mRequiredVersion = 4;
        else if(mVersionRequiredHeights[1] != -1 && pBlockHeight >= mVersionRequiredHeights[1])
            mRequiredVersion = 3;
        else if(mVersionRequiredHeights[0] != -1 && pBlockHeight >= mVersionRequiredHeights[0])
            mRequiredVersion = 2;
        else
            mRequiredVersion = 1;

        if(mVersionEnabledHeights[2] != -1 && pBlockHeight >= mVersionEnabledHeights[2])
            mEnabledVersion = 4;
        else if(mVersionEnabledHeights[1] != -1 && pBlockHeight >= mVersionEnabledHeights[1])
            mEnabledVersion = 3;
        else if(mVersionEnabledHeights[0] != -1 && pBlockHeight >= mVersionEnabledHeights[0])
            mEnabledVersion = 2;
        else
            mEnabledVersion = 1;

        if(mCashForkBlockHeight != -1 && pBlockHeight < mCashForkBlockHeight)
        {
            // Undo cash fork
            mCashForkBlockHeight = -1;
            mBlockMaxSize = HARD_MAX_BLOCK_SIZE;
        }

        for(std::vector<SoftFork *>::iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            (*softFork)->revert(pBlockStats, pBlockHeight);

        mHeight = pBlockHeight - 1;
        mModified = true;
        mMutex.unlock();
    }

    void Forks::reset()
    {
        mMutex.lock();

        mEnabledVersion = 0;
        mRequiredVersion = 0;
        for(unsigned int i=0;i<3;i++)
        {
            mVersionEnabledHeights[i] = -1;
            mVersionRequiredHeights[i] = -1;
        }
        mCashForkBlockHeight = -1;
        mBlockMaxSize = HARD_MAX_BLOCK_SIZE;
        for(std::vector<SoftFork *>::iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            (*softFork)->reset();

        mMutex.unlock();
    }

    void Forks::add(SoftFork *pSoftFork, bool pLocked)
    {
        if(!pLocked)
            mMutex.lock();

        // Overwrite if it is already in here
        bool found = false;
        for(std::vector<SoftFork *>::iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            if((*softFork)->id == pSoftFork->id)
            {
                delete *softFork;
                *softFork = pSoftFork;
                found = true;
                break;
            }

        if(!found)
            mForks.push_back(pSoftFork);

        if(!pLocked)
            mMutex.unlock();
    }

    bool Forks::load(const char *pFileName)
    {
        mMutex.lock();

        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend(pFileName);

        if(!NextCash::fileExists(filePathName))
        {
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "No soft forks file to load");
            mMutex.unlock();
            return true;
        }

        NextCash::FileInputStream file(filePathName);

        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
              "Failed to open soft forks file");
            mMutex.unlock();
            return false;
        }

        // Read height
        mHeight = file.readInt();

        // Read versions block heights
        for(unsigned int i=0;i<3;++i)
            mVersionEnabledHeights[i] = file.readInt();
        for(unsigned int i=0;i<3;++i)
            mVersionRequiredHeights[i] = file.readInt();

        if(mVersionRequiredHeights[2] != -1 && mHeight >= mVersionRequiredHeights[2])
            mRequiredVersion = 4;
        else if(mVersionRequiredHeights[1] != -1 && mHeight >= mVersionRequiredHeights[1])
            mRequiredVersion = 3;
        else if(mVersionRequiredHeights[0] != -1 && mHeight >= mVersionRequiredHeights[0])
            mRequiredVersion = 2;
        else
            mRequiredVersion = 1;

        if(mVersionEnabledHeights[2] != -1 && mHeight >= mVersionEnabledHeights[2])
            mEnabledVersion = 4;
        else if(mVersionEnabledHeights[1] != -1 && mHeight >= mVersionEnabledHeights[1])
            mEnabledVersion = 3;
        else if(mVersionEnabledHeights[0] != -1 && mHeight >= mVersionEnabledHeights[0])
            mEnabledVersion = 2;
        else
            mEnabledVersion = 1;

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
          "Block versions %d/%d enabled/required", mEnabledVersion, mRequiredVersion);

        // Read cash fork block height and max size
        mCashForkBlockHeight = file.readInt();
        mBlockMaxSize = file.readUnsignedInt();

        if(mCashForkBlockHeight != -1)
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "Cash fork active since block height %d, max block size %d", mCashForkBlockHeight, mBlockMaxSize);

        SoftFork *newSoftFork;
        while(file.remaining())
        {
            newSoftFork = new SoftFork();
            if(!newSoftFork->read(&file))
            {
                delete newSoftFork;
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
                  "Failed to read soft fork");
                mMutex.unlock();
                return false;
            }
            add(newSoftFork, true);
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_FORKS_LOG_NAME,
              "Loaded soft fork %s : %s", newSoftFork->name.text(), newSoftFork->description().text());
        }

        mModified = false;
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
          "Loaded %d soft forks at height %d", mForks.size(), mHeight);
        mMutex.unlock();
        return true;
    }

    bool Forks::save(const char *pFileName)
    {
        mMutex.lock();
        if(!mModified)
        {
            mMutex.unlock();
            return true;
        }

        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend(pFileName);
        NextCash::FileOutputStream file(filePathName, true);

        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
              "Failed to open soft forks file to save");
            mMutex.unlock();
            return false;
        }

        // Write height
        file.writeInt(mHeight);

        // Write versions block heights
        for(unsigned int i=0;i<3;++i)
            file.writeInt(mVersionEnabledHeights[i]);
        for(unsigned int i=0;i<3;++i)
            file.writeInt(mVersionRequiredHeights[i]);

        // Write cash fork block height and max size
        file.writeInt(mCashForkBlockHeight);
        file.writeUnsignedInt(mBlockMaxSize);

        for(std::vector<SoftFork *>::iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            (*softFork)->write(&file);

        mModified = false;
        mMutex.unlock();
        return true;
    }
}
