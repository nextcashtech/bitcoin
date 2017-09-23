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
        mActiveVersion = 1;
        mRequiredVersion = 1;

        switch(network())
        {
        case MAINNET:
            mThreshHold = 1916;
            break;
        default:
        case TESTNET:
            mThreshHold = 1512;
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
        if(pBlockHeight != 0 && pBlockHeight % RETARGET_PERIOD == 0)
        {
            uint32_t medianTime = getMedianTimePast(pBlockStats, 11);
            save("soft_forks_previous");

            //TODO Warn about unknown forks (bits set in version not corresponding to known soft forks)

            for(std::vector<SoftFork *>::iterator softFork=mSoftForks.begin();softFork!=mSoftForks.end();++softFork)
            {
                (*softFork)->previousState = (*softFork)->state;
                switch((*softFork)->state)
                {
                    case SoftFork::DEFINED:
                        if(medianTime > (*softFork)->timeout)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                              "Soft fork (%s) failed", (*softFork)->name.text());
                            (*softFork)->state = SoftFork::FAILED;
                        }
                        else if(medianTime > (*softFork)->startTime)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                              "Soft fork (%s) started", (*softFork)->name.text());
                            (*softFork)->state = SoftFork::STARTED;
                        }
                        break;
                    case SoftFork::STARTED:
                    {
                        if(medianTime > (*softFork)->timeout)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                              "Soft fork (%s) failed", (*softFork)->name.text());
                            (*softFork)->state = SoftFork::FAILED;
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
                              "Soft fork (%s) locked in", (*softFork)->name.text());
                            (*softFork)->lockedHeight = pBlockHeight;
                            (*softFork)->state = SoftFork::LOCKED_IN;
                        }

                        break;
                    }
                    case SoftFork::LOCKED_IN:
                        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                          "Soft fork (%s) active", (*softFork)->name.text());
                        (*softFork)->state = SoftFork::ACTIVE;
                        break;
                    default:
                    case SoftFork::ACTIVE:
                    case SoftFork::FAILED:
                        break;
                }
            }
        }

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
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                      "Version 4 blocks now required");
                    mRequiredVersion = 4;
                }
                if(mActiveVersion < 4)
                    mActiveVersion = 4;
                return;
            }
            else if(mActiveVersion < 4 && version4OrHigherCount >= activateCount)
            {
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                  "Version 4 blocks now active");
                mActiveVersion = 4;
            }

            // BIP-0066
            if(version3OrHigherCount >= requireCount)
            {
                if(mRequiredVersion < 3)
                {
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                      "Version 3 blocks now required");
                    mRequiredVersion = 3;
                }
                if(mActiveVersion < 3)
                    mActiveVersion = 3;
                return;
            }
            else if(mActiveVersion < 3 && version3OrHigherCount >= activateCount)
            {
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                  "Version 3 blocks now active");
                mActiveVersion = 3;
            }

            // BIP-0034
            if(version2OrHigherCount >= requireCount)
            {
                if(mRequiredVersion < 2)
                {
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                      "Version 2 blocks now required");
                    mRequiredVersion = 2;
                }
                if(mActiveVersion < 2)
                    mActiveVersion = 2;
                return;
            }
            else if(mActiveVersion < 2 && version2OrHigherCount >= activateCount)
            {
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME,
                  "Version 2 blocks now active");
                mActiveVersion = 2;
            }
        }
    }

    void SoftForks::revert(unsigned int pBlockHeight)
    {
        mActiveVersion = mPreviousActiveVersion;
        mRequiredVersion = mPreviousRequiredVersion;

        if(pBlockHeight != 0 && pBlockHeight % RETARGET_PERIOD == 0)
            for(std::vector<SoftFork *>::iterator softFork=mSoftForks.begin();softFork!=mSoftForks.end();++softFork)
                (*softFork)->revert();
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
            mSoftForks.push_back(newSoftFork);
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME, "Loaded %d soft forks",
          mSoftForks.size());
        return true;
    }

    bool SoftForks::save(const char *pFileName)
    {
        ArcMist::String filePathName = Info::instance().path();
        filePathName.pathAppend(pFileName);
        ArcMist::FileOutputStream file(filePathName, true);

        if(!file.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_SOFT_FORKS_LOG_NAME, "Failed to open soft forks file to save");
            return false;
        }

        for(std::vector<SoftFork *>::iterator softFork=mSoftForks.begin();softFork!=mSoftForks.end();++softFork)
            (*softFork)->write(&file);

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_SOFT_FORKS_LOG_NAME, "Saved %d soft forks", mSoftForks.size());
        return true;
    }
}
