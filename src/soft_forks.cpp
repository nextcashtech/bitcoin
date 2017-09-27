/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "soft_forks.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/io/file_stream.hpp"
#include "base.hpp"
#include "info.hpp"

#include <algorithm>

#define BITCOIN_SOFT_FORKS_LOG_NAME "BitCoin Soft Forks"


namespace BitCoin
{
    uint32_t getMedianTimePast(std::list<BlockStats> pBlockStats, unsigned int pBlockCount)
    {
        std::vector<uint32_t> times;
        for(std::list<BlockStats>::reverse_iterator stat=pBlockStats.rbegin();stat!=pBlockStats.rend();++stat)
        {
            times.push_back(stat->time);
            if(times.size() >= pBlockCount)
                break;
        }

        // Sort times
        std::sort(times.begin(), times.end());

        // Return the median time
        return times[pBlockCount / 2];
    }

    void SoftFork::write(ArcMist::OutputStream *pStream)
    {
        pStream->writeByte(name.length());
        pStream->writeString(name);
        pStream->writeUnsignedInt(id);
        pStream->writeByte(state);
        pStream->writeByte(bit);
        pStream->writeUnsignedInt(startTime);
        pStream->writeUnsignedInt(timeout);
        pStream->writeUnsignedInt(lockedHeight);
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
        state = static_cast<SoftFork::State>(pStream->readByte());
        bit = pStream->readByte();
        startTime = pStream->readUnsignedInt();
        timeout = pStream->readUnsignedInt();
        lockedHeight = pStream->readUnsignedInt();
        return true;
    }

    SoftForks::SoftForks()
    {
        mHeight = 0;
        mPreviousHeight = 0;
        mActiveVersion = 1;
        mRequiredVersion = 1;
        mModified = false;

        switch(network())
        {
        case MAINNET:
            mThreshHold = 1916;

            // Add known soft forks
            mSoftForks.push_back(new SoftFork("BIP-0068", SoftFork::BIP0068, 0, 1462060800, 1493596800));
            mSoftForks.push_back(new SoftFork("BIP-0112", SoftFork::BIP0112, 0, 1462060800, 1493596800));
            mSoftForks.push_back(new SoftFork("BIP-0113", SoftFork::BIP0113, 0, 1462060800, 1493596800));
            break;
        default:
        case TESTNET:
            mThreshHold = 1512;

            // Add known soft forks
            mSoftForks.push_back(new SoftFork("BIP-0068", SoftFork::BIP0068, 0, 1456790400, 1493596800));
            mSoftForks.push_back(new SoftFork("BIP-0112", SoftFork::BIP0112, 0, 1456790400, 1493596800));
            mSoftForks.push_back(new SoftFork("BIP-0113", SoftFork::BIP0113, 0, 1456790400, 1493596800));
            break;
        }

    }

    SoftForks::~SoftForks()
    {
        for(std::vector<SoftFork *>::iterator softFork=mSoftForks.begin();softFork!=mSoftForks.end();++softFork)
            delete *softFork;
    }

    SoftFork::State SoftForks::softForkState(unsigned int pID)
    {
        for(std::vector<SoftFork *>::iterator softFork=mSoftForks.begin();softFork!=mSoftForks.end();++softFork)
            if((*softFork)->id == pID)
                return (*softFork)->state;

        return SoftFork::UNDEFINED;
    }

    void SoftForks::process(std::list<BlockStats> pBlockStats, unsigned int pBlockHeight)
    {
        mPreviousHeight = mHeight;

        if(pBlockHeight != 0 && pBlockHeight % RETARGET_PERIOD == 0)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
              "Updating for block height %d", pBlockHeight);

            uint32_t medianTime = getMedianTimePast(pBlockStats, 11);
            uint32_t compositeValue = 0;

            for(std::vector<SoftFork *>::iterator softFork=mSoftForks.begin();softFork!=mSoftForks.end();++softFork)
            {
                compositeValue |= (0x01 << (*softFork)->bit);

                (*softFork)->previousState = (*softFork)->state;
                switch((*softFork)->state)
                {
                    case SoftFork::DEFINED:
                        if(medianTime > (*softFork)->timeout)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                              "(%s) failed (height %d)", (*softFork)->name.text(), pBlockHeight);
                            (*softFork)->state = SoftFork::FAILED;
                            mModified = true;
                        }
                        else if(medianTime > (*softFork)->startTime)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                              "(%s) started (height %d)", (*softFork)->name.text(), pBlockHeight);
                            (*softFork)->state = SoftFork::STARTED;
                            mModified = true;
                        }
                        break;
                    case SoftFork::STARTED:
                    {
                        if(medianTime > (*softFork)->timeout)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                              "(%s) failed (height %d)", (*softFork)->name.text(), pBlockHeight);
                            (*softFork)->state = SoftFork::FAILED;
                            mModified = true;
                            break;
                        }

                        unsigned int support = 0;
                        for(std::list<BlockStats>::reverse_iterator stat=++pBlockStats.rbegin();stat!=pBlockStats.rend();++stat)
                        {
                            if((stat->version & 0xE0000000) == 0x20000000 && (stat->version >> (*softFork)->bit) & 0x01)
                                ++support;
                        }

                        if(support >= mThreshHold)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                              "(%s) locked in (height %d)", (*softFork)->name.text(), pBlockHeight);
                            (*softFork)->lockedHeight = pBlockHeight;
                            (*softFork)->state = SoftFork::LOCKED_IN;
                            mModified = true;
                        }

                        break;
                    }
                    case SoftFork::LOCKED_IN:
                        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
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

            for(std::list<BlockStats>::reverse_iterator stat=++pBlockStats.rbegin();stat!=pBlockStats.rend();++stat)
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
                    ArcMist::Log::addFormatted(ArcMist::Log::NOTIFICATION, BITCOIN_SOFT_FORKS_LOG_NAME,
                      "Unknown soft fork for bit %d with %d/%d support (height %d)", i, unknownSupport[i],
                      pBlockStats.size(), pBlockHeight);
                }
        }

        mHeight = pBlockHeight;
        mModified = true;

        mPreviousActiveVersion = mActiveVersion;
        mPreviousRequiredVersion = mRequiredVersion;

        int totalCount = 1000;
        int activateCount = 750;
        int requireCount = 950;

        if(network() == TESTNET)
        {
            totalCount = 100;
            activateCount = 51;
            requireCount = 75;
        }

        if(mRequiredVersion < 4)
        {
            int version4OrHigherCount = 0;
            int version3OrHigherCount = 0;
            int version2OrHigherCount = 0;
            int count = 0;
            for(std::list<BlockStats>::reverse_iterator stat=pBlockStats.rbegin();stat!=pBlockStats.rend();++stat)
            {
                if(++count > totalCount)
                    break;

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
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                      "Version 4 blocks now required (height %d)", pBlockHeight);
                    mRequiredVersion = 4;
                    mModified = true;
                }
                if(mActiveVersion < 4)
                {
                    mActiveVersion = 4;
                    mModified = true;
                }
            }
            else if(mActiveVersion < 4 && version4OrHigherCount >= activateCount)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                  "Version 4 blocks now active (height %d)", pBlockHeight);
                mActiveVersion = 4;
                mModified = true;
            }

            // BIP-0066
            if(version3OrHigherCount >= requireCount)
            {
                if(mRequiredVersion < 3)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                      "Version 3 blocks now required (height %d)", pBlockHeight);
                    mRequiredVersion = 3;
                    mModified = true;
                }
                if(mActiveVersion < 3)
                {
                    mActiveVersion = 3;
                    mModified = true;
                }
            }
            else if(mActiveVersion < 3 && version3OrHigherCount >= activateCount)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                  "Version 3 blocks now active (height %d)", pBlockHeight);
                mActiveVersion = 3;
                mModified = true;
            }

            // BIP-0034
            if(version2OrHigherCount >= requireCount)
            {
                if(mRequiredVersion < 2)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                      "Version 2 blocks now required (height %d)", pBlockHeight);
                    mRequiredVersion = 2;
                    mModified = true;
                }
                if(mActiveVersion < 2)
                {
                    mActiveVersion = 2;
                    mModified = true;
                }
            }
            else if(mActiveVersion < 2 && version2OrHigherCount >= activateCount)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                  "Version 2 blocks now active (height %d)", pBlockHeight);
                mActiveVersion = 2;
                mModified = true;
            }
        }
    }

    void SoftForks::revert()
    {
        mActiveVersion = mPreviousActiveVersion;
        mRequiredVersion = mPreviousRequiredVersion;

        if(mHeight != 0 && mHeight % RETARGET_PERIOD == 0)
            for(std::vector<SoftFork *>::iterator softFork=mSoftForks.begin();softFork!=mSoftForks.end();++softFork)
                (*softFork)->revert();

        --mHeight;
    }

    void SoftForks::reset()
    {
        mActiveVersion = 0;
        mRequiredVersion = 0;
        for(std::vector<SoftFork *>::iterator softFork=mSoftForks.begin();softFork!=mSoftForks.end();++softFork)
            (*softFork)->reset();
    }

    void SoftForks::add(SoftFork *pSoftFork)
    {
        // Overwrite if it is already in here
        bool found = false;
        for(std::vector<SoftFork *>::iterator softFork=mSoftForks.begin();softFork!=mSoftForks.end();++softFork)
            if((*softFork)->id == pSoftFork->id)
            {
                delete *softFork;
                *softFork = pSoftFork;
                found = true;
                break;
            }

        if(!found)
            mSoftForks.push_back(pSoftFork);
    }

    bool SoftForks::load(const char *pFileName)
    {
        ArcMist::String filePathName = Info::instance().path();
        filePathName.pathAppend(pFileName);

        if(!ArcMist::fileExists(filePathName))
        {
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
              "No soft forks file to load");
            return true;
        }

        ArcMist::FileInputStream file(filePathName);

        if(!file.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_SOFT_FORKS_LOG_NAME,
              "Failed to open soft forks file");
            return false;
        }

        // Read height
        mHeight = file.readUnsignedInt();

        // Read versions
        mActiveVersion = file.readUnsignedInt();
        mRequiredVersion = file.readUnsignedInt();
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
          "Block versions %d/%d active/required", mActiveVersion, mRequiredVersion);

        SoftFork *newSoftFork;
        while(file.remaining())
        {
            newSoftFork = new SoftFork();
            if(!newSoftFork->read(&file))
            {
                delete newSoftFork;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_SOFT_FORKS_LOG_NAME,
                  "Failed to read soft fork");
                return false;
            }
            add(newSoftFork);
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_SOFT_FORKS_LOG_NAME,
              "Loaded soft fork : %s", newSoftFork->name.text());
        }

        mModified = false;
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
          "Loaded %d soft forks", mSoftForks.size());
        return true;
    }

    bool SoftForks::save(const char *pFileName)
    {
        if(!mModified)
            return true;

        ArcMist::String filePathName = Info::instance().path();
        filePathName.pathAppend(pFileName);
        ArcMist::FileOutputStream file(filePathName, true);

        if(!file.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_SOFT_FORKS_LOG_NAME, "Failed to open soft forks file to save");
            return false;
        }

        // Write height
        file.writeUnsignedInt(mHeight);

        // Write versions
        file.writeUnsignedInt(mActiveVersion);
        file.writeUnsignedInt(mRequiredVersion);

        for(std::vector<SoftFork *>::iterator softFork=mSoftForks.begin();softFork!=mSoftForks.end();++softFork)
            (*softFork)->write(&file);

        mModified = false;
        return true;
    }
}
