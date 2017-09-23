/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_SOFT_FORKS_HPP
#define BITCOIN_SOFT_FORKS_HPP

#include "arcmist/base/string.hpp"
#include "arcmist/io/stream.hpp"

#include <cstdint>
#include <list>
#include <vector>


namespace BitCoin
{
    class BlockStats
    {
    public:
        BlockStats(int32_t pVersion, uint32_t pTime) { version = pVersion; time = pTime; }

        int32_t version;
        uint32_t time;
    };

    // Note : Call after block has been added to stats
    uint32_t getMedianTimePast(std::list<BlockStats> pBlockStats, unsigned int pBlockCount);

    class SoftFork
    {
    public:
        enum State
        {
            UNDEFINED, // Unknown soft fork ID
            DEFINED,   // Soft fork implemented
            STARTED,   // Start time reached
            LOCKED_IN, // Support threshold reached
            ACTIVE,    // Support threshold reached last retarget
            FAILED     // Timeout reached without support threshold
        };

        SoftFork() { state = UNDEFINED; id = 0; bit = 0; startTime = 0; timeout = 0; lockedHeight = 0xffffffff; }
        SoftFork(const char *pName, unsigned int pID, uint8_t pBit, uint32_t pStartTime, uint32_t pTimeout)
        {
            state = DEFINED;
            name = pName;
            id = pID;
            bit = pBit;
            startTime = pStartTime;
            timeout = pTimeout;
            lockedHeight = 0xffffffff;
        }

        void revert() { state = previousState; }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        ArcMist::String name;
        unsigned int id;
        State state;
        uint8_t bit;
        uint32_t startTime;
        uint32_t timeout;
        unsigned int lockedHeight;

        State previousState;
    };

    class SoftForks
    {
    public:

        SoftForks();
        ~SoftForks();

        int32_t activeVersion() const { return mActiveVersion; }
        int32_t requiredVersion() const { return mRequiredVersion; }

        SoftFork::State softForkState(unsigned int pID);

        void process(std::list<BlockStats> pBlockStats, unsigned int pBlockHeight);

        void revert(unsigned int pBlockHeight);

        // Load from/Save to file system
        bool load(const char *pFileName = "soft_forks");
        bool save(const char *pFileName = "soft_forks");

    private:

        std::vector<SoftFork *> mSoftForks;

        int32_t mActiveVersion;
        int32_t mRequiredVersion;

        int32_t mPreviousActiveVersion;
        int32_t mPreviousRequiredVersion;

        unsigned int mThreshHold;

    };
}

#endif