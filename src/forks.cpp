/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "forks.hpp"

#ifdef PROFILER_ON
#include "arcmist/dev/profiler.hpp"
#endif

#include "arcmist/base/log.hpp"
#include "arcmist/io/file_stream.hpp"
#include "base.hpp"
#include "info.hpp"

#include <algorithm>

#define BITCOIN_FORKS_LOG_NAME "BitCoin Forks"


namespace BitCoin
{
    bool BlockStats::load()
    {
        ArcMist::String filePathName = Info::instance().path();
        filePathName.pathAppend("block_stats");
        if(!ArcMist::fileExists(filePathName))
        {
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "No block stats file to load");
            mIsValid = true;
            return true;
        }

        ArcMist::FileInputStream file(filePathName);
        if(!file.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
              "Failed to open block stats file to load");
            mIsValid = false;
            return false;
        }

        resize(file.length() / sizeof(BlockStat));
        file.read(data(), file.length());
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
          "Loaded %d block statistics", size());
        mIsValid = true;
        return true;
    }

    bool BlockStats::save()
    {
        if(!mIsValid)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
              "Not saving block stats. Not valid.");
            return false;
        }

        ArcMist::String filePathName = Info::instance().path();
        filePathName.pathAppend("block_stats");
        ArcMist::FileOutputStream file(filePathName, true);
        if(!file.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
              "Failed to open block stats file to save");
            return false;
        }

        file.write(data(), size() * sizeof(BlockStat));
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
          "Saved %d block statistics", size());
        return true;
    }

    uint32_t BlockStats::time(unsigned int pBlockHeight) const
    {
        if(pBlockHeight >= size())
            return 0;
        return at(pBlockHeight).time;
    }

    uint32_t BlockStats::targetBits(unsigned int pBlockHeight) const
    {
        if(pBlockHeight >= size())
            return 0;
        return at(pBlockHeight).targetBits;
    }

    uint32_t BlockStats::getMedianPastTime(unsigned int pBlockHeight, unsigned int pMedianCount) const
    {
        if(pBlockHeight >= size())
            return 0;

        unsigned int offset = 0;
        std::vector<uint32_t> times;
        // Minus one because it is the previous blocks not including the current block
        for(const BlockStat *stat=data()+pBlockHeight-1;stat!=data()-1&&offset<pMedianCount;--stat,++offset)
            times.push_back(stat->time);

        // Sort times
        std::sort(times.begin(), times.end());

        // Return the median time
        return times[pMedianCount / 2];
    }

    void SoftFork::write(ArcMist::OutputStream *pStream)
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

    bool SoftFork::read(ArcMist::InputStream *pStream)
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

    ArcMist::String SoftFork::description()
    {
        ArcMist::String result;
        switch(state)
        {
        default:
        case UNDEFINED:
            result = "Undefined";
            break;
        case DEFINED:
        {
            ArcMist::String startTimeText;
            startTimeText.writeFormattedTime(startTime);
            result.writeFormatted("Defined - start time %s", startTimeText.text());
            break;
        }
        case STARTED:
        {
            ArcMist::String timeoutText;
            timeoutText.writeFormattedTime(timeout);
            result.writeFormatted("Started - timeout %s", timeoutText.text());
            break;
        }
        case LOCKED_IN:
            result.writeFormatted("Locked In - block height %d", lockedHeight);
            break;
        case ACTIVE:
            result.writeFormatted("Active - block height %d", lockedHeight + RETARGET_PERIOD);
            break;
        case FAILED:
            ArcMist::String timeoutText;
            timeoutText.writeFormattedTime(timeout);
            result.writeFormatted("Failed - timeout %s", timeoutText.text());
            break;
        }
        return result;
    }

    void SoftFork::revert(const BlockStats &pBlockStats, int pBlockHeight)
    {
        switch(state)
        {
        default:
        case UNDEFINED:
        case DEFINED:
            break;
        case STARTED:
            if(pBlockStats.time(pBlockHeight) < startTime)
                state = DEFINED;
            break;
        case LOCKED_IN:
            if(pBlockHeight < lockedHeight)
            {
                lockedHeight = NOT_LOCKED;
                if(pBlockStats.time(pBlockHeight) < startTime)
                    state = DEFINED;
                else
                    state = STARTED;
            }
            break;
        case ACTIVE:
            if(pBlockHeight < lockedHeight)
            {
                lockedHeight = NOT_LOCKED;
                if(pBlockStats.time(pBlockHeight) < startTime)
                    state = DEFINED;
                else
                    state = STARTED;
            }
            else if(pBlockHeight < lockedHeight + RETARGET_PERIOD)
                state = LOCKED_IN;
            break;
        case FAILED:
            if(pBlockStats.time(pBlockHeight) < startTime)
                state = DEFINED;
            else if(pBlockStats.time(pBlockHeight) < timeout)
                state = STARTED;
            break;
        }
    }

    Forks::Forks()
    {
        mHeight = 0;
        mActiveVersion = 1;
        mRequiredVersion = 1;
        mCashForkBlockHeight = -1;
        mBlockMaxSize = HARD_MAX_BLOCK_SIZE;
        mModified = false;

        for(unsigned int i=0;i<3;i++)
        {
            mVersionActivationHeights[i] = -1;
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
        for(std::vector<SoftFork *>::iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            delete *softFork;
    }

    SoftFork::State Forks::softForkState(unsigned int pID) const
    {
        for(std::vector<SoftFork *>::const_iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            if((*softFork)->id == pID)
                return (*softFork)->state;

        return SoftFork::UNDEFINED;
    }

    void Forks::process(const BlockStats &pBlockStats, int pBlockHeight)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler outputsProfiler("Forks Process");
#endif
        unsigned int offset;

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
            for(const BlockStat *stat=pBlockStats.data()+pBlockHeight-1;stat!=pBlockStats.data()-1&&offset<totalCount;--stat,++offset)
            {
                switch(stat->version)
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
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Version 4 blocks now required (height %d)", pBlockHeight);
                    mVersionRequiredHeights[2] = pBlockHeight;
                    mRequiredVersion = 4;
                    mModified = true;
                }
                if(mActiveVersion < 4)
                {
                    mVersionActivationHeights[2] = pBlockHeight;
                    mActiveVersion = 4;
                    mModified = true;
                }
            }
            else if(mActiveVersion < 4 && version4OrHigherCount >= activateCount)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Version 4 blocks now active (height %d)", pBlockHeight);
                mVersionActivationHeights[2] = pBlockHeight;
                mActiveVersion = 4;
                mModified = true;
            }

            // BIP-0066
            if(version3OrHigherCount >= requireCount)
            {
                if(mRequiredVersion < 3)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Version 3 blocks now required (height %d)", pBlockHeight);
                    mVersionRequiredHeights[1] = pBlockHeight;
                    mRequiredVersion = 3;
                    mModified = true;
                }
                if(mActiveVersion < 3)
                {
                    mVersionActivationHeights[1] = pBlockHeight;
                    mActiveVersion = 3;
                    mModified = true;
                }
            }
            else if(mActiveVersion < 3 && version3OrHigherCount >= activateCount)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Version 3 blocks now active (height %d)", pBlockHeight);
                mVersionActivationHeights[1] = pBlockHeight;
                mActiveVersion = 3;
                mModified = true;
            }

            // BIP-0034
            if(version2OrHigherCount >= requireCount)
            {
                if(mRequiredVersion < 2)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Version 2 blocks now required (height %d)", pBlockHeight);
                    mVersionRequiredHeights[0] = pBlockHeight;
                    mRequiredVersion = 2;
                    mModified = true;
                }
                if(mActiveVersion < 2)
                {
                    mVersionActivationHeights[0] = pBlockHeight;
                    mActiveVersion = 2;
                    mModified = true;
                }
            }
            else if(mActiveVersion < 2 && version2OrHigherCount >= activateCount)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Version 2 blocks now active (height %d)", pBlockHeight);
                mVersionActivationHeights[0] = pBlockHeight;
                mActiveVersion = 2;
                mModified = true;
            }
        }

        mHeight = pBlockHeight;
        mModified = true;

        if(mRequiredVersion >= 4 && pBlockHeight != 0 && pBlockHeight % RETARGET_PERIOD == 0)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "Updating for block height %d", pBlockHeight);

            uint32_t compositeValue = 0;
            uint32_t medianTimePast = pBlockStats.getMedianPastTime(pBlockHeight);
            for(std::vector<SoftFork *>::iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            {
                compositeValue |= (0x01 << (*softFork)->bit);

                switch((*softFork)->state)
                {
                    case SoftFork::DEFINED:
                        if(medianTimePast > (*softFork)->timeout)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) failed (height %d)", (*softFork)->name.text(), pBlockHeight);
                            (*softFork)->state = SoftFork::FAILED;
                            mModified = true;
                        }
                        else if(medianTimePast > (*softFork)->startTime)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) started (height %d)", (*softFork)->name.text(), pBlockHeight);
                            (*softFork)->state = SoftFork::STARTED;
                            mModified = true;
                        }
                        break;
                    case SoftFork::STARTED:
                    {
                        if(medianTimePast > (*softFork)->timeout)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) failed (height %d)", (*softFork)->name.text(), pBlockHeight);
                            (*softFork)->state = SoftFork::FAILED;
                            mModified = true;
                            break;
                        }

                        unsigned int support = 0;
                        offset = 0;
                        for(const BlockStat *stat=pBlockStats.data()+pBlockHeight-1;stat!=pBlockStats.data()-1&&offset<RETARGET_PERIOD;--stat,++offset)
                        {
                            if((stat->version & 0xE0000000) == 0x20000000 && (stat->version >> (*softFork)->bit) & 0x01)
                                ++support;
                        }

                        if(support >= mThreshHold)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) locked in %d/%d (height %d)", (*softFork)->name.text(), support,
                              mThreshHold, pBlockHeight);
                            (*softFork)->lockedHeight = pBlockHeight;
                            (*softFork)->state = SoftFork::LOCKED_IN;
                            mModified = true;
                        }
                        else
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) not locked in %d/%d (height %d)", (*softFork)->name.text(), support,
                              mThreshHold, pBlockHeight);
                        }

                        break;
                    }
                    case SoftFork::LOCKED_IN:
                        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
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
            for(const BlockStat *stat=pBlockStats.data()+pBlockHeight-1;stat!=pBlockStats.data()-1&&offset<RETARGET_PERIOD;--stat,++offset)
            {
                if((stat->version & 0xE0000000) != 0x20000000)
                    continue;
                if((stat->version | compositeValue) != compositeValue)
                {
                    for(i=0;i<29;i++)
                        if((stat->version & (0x01 << i)) && !(compositeValue & (0x01 << i)))
                            ++unknownSupport[i]; // Bit set in version and not in composite
                }
            }

            for(i=0;i<29;i++)
                if(unknownSupport[i] > 0)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::NOTIFICATION, BITCOIN_FORKS_LOG_NAME,
                      "Unknown soft fork for bit %d with %d/%d support (height %d)", i, unknownSupport[i],
                      RETARGET_PERIOD, pBlockHeight);
                }
        }

        if(pBlockHeight > 12 && mCashForkBlockHeight == -1 && CASH_ACTIVATION_TIME != 0 &&
          pBlockStats.getMedianPastTime(pBlockHeight) >= CASH_ACTIVATION_TIME)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "Cash fork activated at block height %d", pBlockHeight);
            mCashForkBlockHeight = mHeight;
            mBlockMaxSize = CASH_START_MAX_BLOCK_SIZE;
        }
    }

    void Forks::revert(const BlockStats &pBlockStats, int pBlockHeight)
    {
        // Back out any version active/required heights below new block height
        for(unsigned int i=0;i<3;++i)
        {
            if(mVersionRequiredHeights[i] != -1 && mVersionRequiredHeights[i] > pBlockHeight)
                mVersionRequiredHeights[i] = -1;
            if(mVersionActivationHeights[i] != -1 && mVersionActivationHeights[i] > pBlockHeight)
                mVersionActivationHeights[i] = -1;
        }

        if(mVersionRequiredHeights[2] != -1 && pBlockHeight >= mVersionRequiredHeights[2])
            mRequiredVersion = 4;
        else if(mVersionRequiredHeights[1] != -1 && pBlockHeight >= mVersionRequiredHeights[1])
            mRequiredVersion = 3;
        else if(mVersionRequiredHeights[0] != -1 && pBlockHeight >= mVersionRequiredHeights[0])
            mRequiredVersion = 2;
        else
            mRequiredVersion = 1;

        if(mVersionActivationHeights[2] != -1 && pBlockHeight >= mVersionActivationHeights[2])
            mActiveVersion = 4;
        else if(mVersionActivationHeights[1] != -1 && pBlockHeight >= mVersionActivationHeights[1])
            mActiveVersion = 3;
        else if(mVersionActivationHeights[0] != -1 && pBlockHeight >= mVersionActivationHeights[0])
            mActiveVersion = 2;
        else
            mActiveVersion = 1;

        if(mCashForkBlockHeight != -1 && pBlockHeight < mCashForkBlockHeight)
        {
            // Undo cash fork
            mCashForkBlockHeight = -1;
            mBlockMaxSize = HARD_MAX_BLOCK_SIZE;
        }

        for(std::vector<SoftFork *>::iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            (*softFork)->revert(pBlockStats, pBlockHeight);

        mHeight = pBlockHeight;
        mModified = true;
    }

    void Forks::reset()
    {
        mActiveVersion = 0;
        mRequiredVersion = 0;
        for(unsigned int i=0;i<3;i++)
        {
            mVersionActivationHeights[i] = -1;
            mVersionRequiredHeights[i] = -1;
        }
        mCashForkBlockHeight = -1;
        mBlockMaxSize = HARD_MAX_BLOCK_SIZE;
        for(std::vector<SoftFork *>::iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            (*softFork)->reset();
    }

    void Forks::add(SoftFork *pSoftFork)
    {
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
    }

    bool Forks::load(const char *pFileName)
    {
        ArcMist::String filePathName = Info::instance().path();
        filePathName.pathAppend(pFileName);

        if(!ArcMist::fileExists(filePathName))
        {
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "No soft forks file to load");
            return true;
        }

        ArcMist::FileInputStream file(filePathName);

        if(!file.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
              "Failed to open soft forks file");
            return false;
        }

        // Read height
        mHeight = file.readInt();

        // Read versions block heights
        for(unsigned int i=0;i<3;++i)
            mVersionActivationHeights[i] = file.readInt();
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

        if(mVersionActivationHeights[2] != -1 && mHeight >= mVersionActivationHeights[2])
            mActiveVersion = 4;
        else if(mVersionActivationHeights[1] != -1 && mHeight >= mVersionActivationHeights[1])
            mActiveVersion = 3;
        else if(mVersionActivationHeights[0] != -1 && mHeight >= mVersionActivationHeights[0])
            mActiveVersion = 2;
        else
            mActiveVersion = 1;

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
          "Block versions %d/%d active/required", mActiveVersion, mRequiredVersion);

        // Read cash fork block height and max size
        mCashForkBlockHeight = file.readUnsignedInt();
        mBlockMaxSize = file.readUnsignedInt();

        if(mCashForkBlockHeight != -1)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "Block cash fork height %d, max block size %d", mCashForkBlockHeight, mBlockMaxSize);

        SoftFork *newSoftFork;
        while(file.remaining())
        {
            newSoftFork = new SoftFork();
            if(!newSoftFork->read(&file))
            {
                delete newSoftFork;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
                  "Failed to read soft fork");
                return false;
            }
            add(newSoftFork);
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_FORKS_LOG_NAME,
              "Loaded soft fork %s : %s", newSoftFork->name.text(), newSoftFork->description().text());
        }

        mModified = false;
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_FORKS_LOG_NAME,
          "Loaded %d soft forks", mForks.size());
        return true;
    }

    bool Forks::save(const char *pFileName)
    {
        if(!mModified)
            return true;

        ArcMist::String filePathName = Info::instance().path();
        filePathName.pathAppend(pFileName);
        ArcMist::FileOutputStream file(filePathName, true);

        if(!file.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_FORKS_LOG_NAME, "Failed to open soft forks file to save");
            return false;
        }

        // Write height
        file.writeInt(mHeight);

        // Write versions block heights
        for(unsigned int i=0;i<3;++i)
            file.writeInt(mVersionActivationHeights[i]);
        for(unsigned int i=0;i<3;++i)
            file.writeInt(mVersionRequiredHeights[i]);

        // Write cash fork block height and max size
        file.writeUnsignedInt(mCashForkBlockHeight);
        file.writeUnsignedInt(mBlockMaxSize);

        for(std::vector<SoftFork *>::iterator softFork=mForks.begin();softFork!=mForks.end();++softFork)
            (*softFork)->write(&file);

        mModified = false;
        return true;
    }
}
