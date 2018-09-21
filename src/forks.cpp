/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
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
#include "chain.hpp"

#include <algorithm>


namespace BitCoin
{
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

    bool SoftFork::isActive(unsigned int pHeight)
    {
        return lockedHeight != NOT_LOCKED &&
          pHeight >= (unsigned int)lockedHeight + RETARGET_PERIOD;
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

    void SoftFork::revert(Chain *pChain, unsigned int pHeight)
    {
        switch(state)
        {
        default:
        case UNDEFINED:
        case DEFINED:
            break;
        case STARTED:
            if(pChain->time(pHeight - 1) < startTime)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Soft fork %s reverted from STARTED to DEFINED", name.text());
                state = DEFINED;
            }
            break;
        case LOCKED_IN:
            if(pHeight <= lockedHeight)
            {
                lockedHeight = NOT_LOCKED;
                if(pChain->time(pHeight - 1) < startTime)
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
            if(pHeight <= lockedHeight)
            {
                lockedHeight = NOT_LOCKED;
                if(pChain->time(pHeight - 1) < startTime)
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
            else if(pHeight <= lockedHeight + RETARGET_PERIOD)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Soft fork %s reverted from ACTIVE to LOCKED_IN", name.text());
                state = LOCKED_IN;
            }
            break;
        case FAILED:
            if(pChain->time(pHeight - 1) < startTime)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Soft fork %s reverted from FAILED to DEFINED", name.text());
                state = DEFINED;
            }
            else if(pChain->time(pHeight - 1) < timeout)
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
        mBlockMaxSize = HARD_MAX_BLOCK_SIZE;
        mElementMaxSize = 520;
        mCashActivationBlockHeight = 0;
        mCashFork201711BlockHeight = 0;
        mCashFork201805BlockHeight = 0;
        mCashFork201811BlockHeight = 0;
        mCashForkID = 0;
        mModified = false;

        for(unsigned int i = 0; i < 3; i++)
        {
            mBlockVersionEnabledHeights[i] = 0;
            mBlockVersionRequiredHeights[i] = 0;
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
        for(std::vector<SoftFork *>::const_iterator softFork = mForks.begin();
          softFork != mForks.end(); ++softFork)
            delete *softFork;
        mMutex.unlock();
    }

    bool Forks::softForkIsActive(unsigned int pHeight, unsigned int pID)
    {
        bool result = false;
        mMutex.lock();

        for(std::vector<SoftFork *>::const_iterator softFork = mForks.begin();
          softFork != mForks.end(); ++softFork)
            if((*softFork)->id == pID)
            {
                result = (*softFork)->isActive(pHeight);
                break;
            }

        mMutex.unlock();
        return result;
    }

    void Forks::process(Chain *pChain, unsigned int pHeight)
    {
        mMutex.lock();

#ifdef PROFILER_ON
        NextCash::Profiler outputsProfiler("Forks Process");
#endif

        if(mBlockVersionRequiredHeights[2] == 0)
        {
            unsigned int totalCount = 1000;
            unsigned int activateCount = 750;
            unsigned int requireCount = 950;

            if(network() == TESTNET)
            {
                totalCount = 100;
                activateCount = 51;
                requireCount = 75;
            }

            // Update versions
            if(mBlockVersions.size() < totalCount &&
              mBlockVersions.size() < pHeight)
            {
                mBlockVersions.clear();
                for(unsigned int height = pHeight; mBlockVersions.size() < totalCount;
                  --height)
                {
                    mBlockVersions.push_front(pChain->version(height));
                    if(height == 0)
                        break;
                }
            }
            mBlockVersions.push_back(pChain->version(pHeight));
            while(mBlockVersions.size() > totalCount)
                mBlockVersions.pop_front();

            unsigned int version4OrHigherCount = 0;
            unsigned int version3OrHigherCount = 0;
            unsigned int version2OrHigherCount = 0;
            for(std::list<int32_t>::iterator version = mBlockVersions.begin();
              version != mBlockVersions.end(); ++version)
                switch(*version)
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

            // BIP-0065
            if(version4OrHigherCount >= requireCount)
            {
                if(mBlockVersionRequiredHeights[2] == 0)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Version 4 blocks now required (height %d)", pHeight);
                    mBlockVersionRequiredHeights[2] = pHeight;
                    mModified = true;
                    mBlockVersions.clear();
                }
                if(mBlockVersionEnabledHeights[2] == 0)
                {
                    mBlockVersionEnabledHeights[2] = pHeight;
                    mModified = true;
                }
            }
            else if(mBlockVersionEnabledHeights[2] == 0 && version4OrHigherCount >= activateCount)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Version 4 blocks now enabled (height %d)", pHeight);
                mBlockVersionEnabledHeights[2] = pHeight;
                mModified = true;
            }

            // BIP-0066
            if(version3OrHigherCount >= requireCount)
            {
                if(mBlockVersionRequiredHeights[1] == 0)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Version 3 blocks now required (height %d)", pHeight);
                    mBlockVersionRequiredHeights[1] = pHeight;
                    mModified = true;
                }
                if(mBlockVersionEnabledHeights[1] == 0)
                {
                    mBlockVersionEnabledHeights[1] = pHeight;
                    mModified = true;
                }
            }
            else if(mBlockVersionEnabledHeights[1] == 0 && version3OrHigherCount >= activateCount)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Version 3 blocks now enabled (height %d)", pHeight);
                mBlockVersionEnabledHeights[1] = pHeight;
                mModified = true;
            }

            // BIP-0034
            if(version2OrHigherCount >= requireCount)
            {
                if(mBlockVersionRequiredHeights[0] == 0)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Version 2 blocks now required (height %d)", pHeight);
                    mBlockVersionRequiredHeights[0] = pHeight;
                    mModified = true;
                }
                if(mBlockVersionEnabledHeights[0] == 0)
                {
                    mBlockVersionEnabledHeights[0] = pHeight;
                    mModified = true;
                }
            }
            else if(mBlockVersionEnabledHeights[0] == 0 && version2OrHigherCount >= activateCount)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Version 2 blocks now enabled (height %d)", pHeight);
                mBlockVersionEnabledHeights[0] = pHeight;
                mModified = true;
            }
        }

        mHeight = pHeight;
        mModified = true;

        if(mBlockVersionRequiredHeights[2] != 0 && pHeight != 0 && pHeight % RETARGET_PERIOD == 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "Updating at height %d", pHeight);

            uint32_t compositeValue = 0;
            int32_t version;
            int32_t medianTimePast = pChain->getMedianPastTime(pHeight, 11);
            for(std::vector<SoftFork *>::iterator softFork = mForks.begin();
              softFork != mForks.end(); ++softFork)
            {
                compositeValue |= (0x01 << (*softFork)->bit);

                switch((*softFork)->state)
                {
                    case SoftFork::DEFINED:
                        if(medianTimePast > (*softFork)->timeout)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) failed at height %d", (*softFork)->name.text(), pHeight);
                            (*softFork)->state = SoftFork::FAILED;
                            mModified = true;
                        }
                        else if(medianTimePast > (*softFork)->startTime)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) started at height %d", (*softFork)->name.text(), pHeight);
                            (*softFork)->state = SoftFork::STARTED;
                            mModified = true;
                        }
                        break;
                    case SoftFork::STARTED:
                    {
                        if(medianTimePast > (*softFork)->timeout)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) failed at height %d", (*softFork)->name.text(), pHeight);
                            (*softFork)->state = SoftFork::FAILED;
                            mModified = true;
                            break;
                        }

                        unsigned int support = 0;
                        int offset = 0;
                        for(unsigned int height = pHeight; offset < RETARGET_PERIOD;
                          --height, ++offset)
                        {
                            version = pChain->version(height);
                            if((version & 0xE0000000) == 0x20000000 &&
                              (version >> (*softFork)->bit) & 0x01)
                                ++support;
                            if(height == 0)
                                break;
                        }

                        if(support >= mThreshHold)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) locked in with support %d/%d at height %d",
                              (*softFork)->name.text(), support, mThreshHold, pHeight);
                            (*softFork)->lockedHeight = pHeight;
                            (*softFork)->state = SoftFork::LOCKED_IN;
                            mModified = true;
                        }
                        else
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "(%s) still started with support %d/%d at height %d",
                              (*softFork)->name.text(), support, mThreshHold, pHeight);
                        }

                        break;
                    }
                    case SoftFork::LOCKED_IN:
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                          "Soft fork (%s) active at height %d", (*softFork)->name.text(),
                          pHeight);
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
            for(i = 0; i < 29; i++)
                unknownSupport[i] = 0;

            unsigned int offset = 0;
            for(unsigned int height = pHeight; offset < RETARGET_PERIOD;
              --height, ++offset)
            {
                version = pChain->version(height);
                if((version & 0xE0000000) != 0x20000000)
                {
                    if(height == 0)
                        break;
                    else
                        continue;
                }
                if((version | compositeValue) != compositeValue)
                {
                    for(i = 0; i < 29; i++)
                        if((version & (0x01 << i)) && !(compositeValue & (0x01 << i)))
                            ++unknownSupport[i]; // Bit set in version and not in composite
                }

                if(height == 0)
                    break;
            }

            for(i = 0; i < 29; i++)
                if(unknownSupport[i] > 0)
                {
                    NextCash::Log::addFormatted(NextCash::Log::NOTIFICATION, BITCOIN_FORKS_LOG_NAME,
                      "Unknown soft fork for bit %d with %d/%d support (height %d)", i, unknownSupport[i],
                      RETARGET_PERIOD, pHeight);
                }
        }

        if(CASH_ACTIVATION_TIME != 0)
        {
            if(mCashActivationBlockHeight == 0)
            {
                if(pChain->time(pHeight) > CASH_ACTIVATION_TIME &&
                  pChain->getMedianPastTime(pHeight, 11) >= CASH_ACTIVATION_TIME)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Cash fork activated at block height %d", pHeight);
                    mCashActivationBlockHeight = pHeight;
                    mBlockMaxSize = CASH_START_MAX_BLOCK_SIZE;
                }
            }
            else if(mCashFork201711BlockHeight == 0)
            {
                if(pChain->time(pHeight) > CASH_FORK_201711_ACTIVATION_TIME &&
                   pChain->getMedianPastTime(pHeight, 11) >= CASH_FORK_201711_ACTIVATION_TIME)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "Cash DAA activated at block height %d", pHeight);
                    mCashFork201711BlockHeight = pHeight;
                }
            }
            else if(mCashFork201805BlockHeight == 0)
            {
                if(pChain->time(pHeight) > CASH_FORK_201805_ACTIVATION_TIME &&
                   pChain->getMedianPastTime(pHeight, 11) >= CASH_FORK_201805_ACTIVATION_TIME)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "2018 May fork activated at block height %d", pHeight);
                    mCashFork201805BlockHeight = pHeight;
                    mBlockMaxSize = FORK_201805_MAX_BLOCK_SIZE;
                }
            }
            else if(mCashFork201811BlockHeight == 0)
            {
                if(pChain->time(pHeight) > CASH_FORK_201811_ACTIVATION_TIME &&
                   pChain->getMedianPastTime(pHeight, 11) >= CASH_FORK_201811_ACTIVATION_TIME)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                      "2018 Nov fork activated at block height %d", pHeight);
                    mCashFork201811BlockHeight = pHeight;
                    mCashForkID = 0x00FF0001;
                }
            }
        }

        mMutex.unlock();
    }

    void Forks::revert(Chain *pChain, unsigned int pHeight)
    {
        mMutex.lock();

        mBlockVersions.clear();

        // Back out any version enabled/required heights below new block height
        for(unsigned int i = 0; i < 3; ++i)
        {
            if(mBlockVersionRequiredHeights[i] != 0 && mBlockVersionRequiredHeights[i] >= pHeight)
                mBlockVersionRequiredHeights[i] = 0;
            if(mBlockVersionEnabledHeights[i] != 0 && mBlockVersionEnabledHeights[i] >= pHeight)
                mBlockVersionEnabledHeights[i] = 0;
        }

        if(mCashFork201811BlockHeight != 0 && pHeight <= mCashFork201811BlockHeight)
        {
            // Undo Nov 2018 fork
            mCashFork201811BlockHeight = 0;
            mBlockMaxSize = FORK_201805_MAX_BLOCK_SIZE;
            mCashForkID = 0;
        }

        if(mCashFork201805BlockHeight != 0 && pHeight <= mCashFork201805BlockHeight)
        {
            // Undo May 2018 fork
            mCashFork201805BlockHeight = 0;
            mBlockMaxSize = CASH_START_MAX_BLOCK_SIZE;
        }

        if(mCashFork201711BlockHeight != 0 && pHeight <= mCashFork201711BlockHeight)
            mCashFork201711BlockHeight = 0; // Undo Nov 2017 fork

        if(mCashActivationBlockHeight != 0 && pHeight <= mCashActivationBlockHeight)
        {
            // Undo cash fork
            mCashActivationBlockHeight = 0;
            mBlockMaxSize = HARD_MAX_BLOCK_SIZE;
        }

        for(std::vector<SoftFork *>::iterator softFork = mForks.begin(); softFork != mForks.end();
          ++softFork)
            (*softFork)->revert(pChain, pHeight);

        mHeight = pHeight;
        mModified = true;
        mMutex.unlock();
    }

    void Forks::reset()
    {
        mMutex.lock();

        mBlockVersions.clear();
        for(unsigned int i = 0; i < 3; i++)
        {
            mBlockVersionEnabledHeights[i] = 0;
            mBlockVersionRequiredHeights[i] = 0;
        }
        mCashActivationBlockHeight = 0;
        mCashFork201711BlockHeight = 0;
        mCashFork201805BlockHeight = 0;
        mCashFork201811BlockHeight = 0;
        mCashForkID = 0;
        mBlockMaxSize = HARD_MAX_BLOCK_SIZE;
        for(std::vector<SoftFork *>::iterator softFork = mForks.begin(); softFork != mForks.end();
          ++softFork)
            (*softFork)->reset();

        mMutex.unlock();
    }

    void Forks::add(SoftFork *pSoftFork, bool pLocked)
    {
        if(!pLocked)
            mMutex.lock();

        // Overwrite if it is already in here
        bool found = false;
        for(std::vector<SoftFork *>::iterator softFork = mForks.begin(); softFork != mForks.end();
          ++softFork)
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

    bool Forks::load(Chain *pChain)
    {
        mMutex.lock();

        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend("forks");

        if(!NextCash::fileExists(filePathName))
        {
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "No forks file to load");
            mMutex.unlock();
            return true;
        }

        NextCash::FileInputStream file(filePathName);

        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
              "Failed to open forks file");
            mMutex.unlock();
            return false;
        }

        // Read version
        unsigned int version = file.readUnsignedInt();

        if(version != 1 && version != 2)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
              "Unknown forks file version");
            mMutex.unlock();
            return false;
        }

        // Read height
        mHeight = file.readInt();

        // Read versions block heights
        for(unsigned int i = 0; i < 3; ++i)
            mBlockVersionEnabledHeights[i] = file.readInt();
        for(unsigned int i = 0; i < 3; ++i)
            mBlockVersionRequiredHeights[i] = file.readInt();

        unsigned int requiredBlockVersion = 1;
        if(mBlockVersionRequiredHeights[2] != 0)
            requiredBlockVersion = 4;
        else if(mBlockVersionRequiredHeights[1] != 0)
            requiredBlockVersion = 3;
        else if(mBlockVersionRequiredHeights[0] != 0)
            requiredBlockVersion = 2;

        unsigned int enabledBlockVersion = 1;
        if(mBlockVersionEnabledHeights[2] != 0)
            enabledBlockVersion = 4;
        else if(mBlockVersionEnabledHeights[1] != 0)
            enabledBlockVersion = 3;
        else if(mBlockVersionEnabledHeights[0] != 0)
            enabledBlockVersion = 2;

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
          "Block versions %d/%d enabled/required", enabledBlockVersion, requiredBlockVersion);

        if(version == 1)
        {
            mCashActivationBlockHeight = file.readInt();

            mBlockMaxSize = file.readUnsignedInt();
            mCashForkID = file.readUnsignedInt();

            if(mCashActivationBlockHeight != 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Cash fork active since block height %d, max block size %d",
                  mCashActivationBlockHeight, CASH_START_MAX_BLOCK_SIZE);

                // Determine Cash fork heights
                for(unsigned int height = mCashActivationBlockHeight; height <= mHeight; ++height)
                {
                    if(mCashFork201711BlockHeight == 0)
                    {
                        if(pChain->time(height) > CASH_FORK_201711_ACTIVATION_TIME &&
                          pChain->getMedianPastTime(height, 11) > CASH_FORK_201711_ACTIVATION_TIME)
                        {
                            mCashFork201711BlockHeight = height;
                            NextCash::Log::addFormatted(NextCash::Log::INFO,
                              BITCOIN_FORKS_LOG_NAME,
                              "Cash DAA active since block height %d", mCashFork201711BlockHeight);
                        }
                    }
                    else if(mCashFork201805BlockHeight == 0)
                    {
                        if(pChain->time(height) > CASH_FORK_201805_ACTIVATION_TIME &&
                          pChain->getMedianPastTime(height, 11) > CASH_FORK_201805_ACTIVATION_TIME)
                        {
                            mCashFork201805BlockHeight = height;
                            NextCash::Log::addFormatted(NextCash::Log::INFO,
                              BITCOIN_FORKS_LOG_NAME,
                              "2018 May fork active since block height %d, max block size %d",
                              mCashFork201805BlockHeight, FORK_201805_MAX_BLOCK_SIZE);
                        }
                    }
                    else if(mCashFork201811BlockHeight == 0)
                    {
                        if(pChain->time(height) > CASH_FORK_201811_ACTIVATION_TIME &&
                          pChain->getMedianPastTime(height, 11) > CASH_FORK_201811_ACTIVATION_TIME)
                        {
                            mCashFork201811BlockHeight = height;
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                              "2018 Nov fork active since block height %d",
                              mCashFork201811BlockHeight);
                        }
                        break;
                    }
                }
            }
        }
        else if(version == 2)
        {
            mBlockMaxSize = file.readUnsignedInt();
            mCashForkID = file.readUnsignedInt();

            unsigned int cashForkCount = file.readUnsignedInt();
            if(cashForkCount != 4)
                return false;

            mCashActivationBlockHeight = file.readInt();
            mCashFork201711BlockHeight = file.readInt();
            mCashFork201805BlockHeight = file.readInt();
            mCashFork201811BlockHeight = file.readInt();

            if(mCashActivationBlockHeight != 0)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Cash fork active since block height %d", mCashActivationBlockHeight);

            if(mCashFork201711BlockHeight != 0)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "Cash DAA active since block height %d", mCashFork201711BlockHeight);

            if(mCashFork201805BlockHeight != 0)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "2018 May fork active since block height %d", mCashFork201805BlockHeight);

            if(mCashFork201811BlockHeight != 0)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
                  "2018 Nov fork active since block height %d", mCashFork201811BlockHeight);

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "Max block size %d", mBlockMaxSize);

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_FORKS_LOG_NAME,
              "Cash fork ID 0x%08x", mCashForkID);
        }

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

    bool Forks::save()
    {
        mMutex.lock();
        if(!mModified)
        {
            mMutex.unlock();
            return true;
        }

        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend("forks");
        NextCash::FileOutputStream file(filePathName, true);

        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_FORKS_LOG_NAME,
              "Failed to open soft forks file to save");
            mMutex.unlock();
            return false;
        }

        // Write version
        file.writeUnsignedInt(2);

        // Write height
        file.writeInt(mHeight);

        // Write versions block heights
        for(unsigned int i = 0; i < 3; ++i)
            file.writeInt(mBlockVersionEnabledHeights[i]);
        for(unsigned int i = 0; i < 3; ++i)
            file.writeInt(mBlockVersionRequiredHeights[i]);

        // Write max size and cash fork ID
        file.writeUnsignedInt(mBlockMaxSize);
        file.writeUnsignedInt(mCashForkID);

        // Write cash fork block heights
        file.writeUnsignedInt(4);
        file.writeInt(mCashActivationBlockHeight);
        file.writeInt(mCashFork201711BlockHeight);
        file.writeInt(mCashFork201805BlockHeight);
        file.writeInt(mCashFork201811BlockHeight);

        for(std::vector<SoftFork *>::iterator softFork = mForks.begin(); softFork != mForks.end();
          ++softFork)
            (*softFork)->write(&file);

        mModified = false;
        mMutex.unlock();
        return true;
    }

    int32_t Forks::enabledBlockVersion(unsigned int pHeight) const
    {
        // Block version 1 is enabled by default
        // Height at offset 0 represents version 2
        // Height at offset 1 represents version 3
        // Height at offset 2 represents version 4
        for(int i = 2; i >= 0; --i)
            if(mBlockVersionEnabledHeights[i] != 0 &&
              (unsigned int)mBlockVersionEnabledHeights[i] > pHeight)
                return i + 2;

        return 1;
    }

    int32_t Forks::requiredBlockVersion(unsigned int pHeight) const
    {
        // Block version 1 is enabled by default
        // Height at offset 0 represents version 2
        // Height at offset 1 represents version 3
        // Height at offset 2 represents version 4
        for(int i = 2; i >= 0; --i)
            if(mBlockVersionRequiredHeights[i] != 0 &&
              (unsigned int)mBlockVersionRequiredHeights[i] > pHeight)
                return i + 2;

        return 1;
    }
}
