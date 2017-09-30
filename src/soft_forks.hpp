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
    class BlockStat
    {
    public:
        BlockStat() {}
        BlockStat(int32_t pVersion, uint32_t pTime) { version = pVersion; time = pTime; }

        int32_t version;
        uint32_t time;
    };

    class BlockStats : public std::vector<BlockStat>
    {
    public:

        int height() const { return size() - 1; }

        uint32_t time(unsigned int pBlockHeight) const;

        // Note : Call after block has been added to stats
        uint32_t getMedianPastTime(unsigned int pBlockHeight, unsigned int pMedianCount = 11) const;

        void revert() { erase(end()); }

        bool load();
        bool save();
    };

    class SoftFork
    {
    public:
        enum ID
        {
            // These all share the same start time, timeout, and bit, so they will share one ID
            BIP0068 = 1, // Relative lock-time using consensus-enforced sequence numbers
            BIP0112 = 1, // CHECKSEQUENCEVERIFY
            BIP0113 = 1, // Median time-past as endpoint for lock-time calculations
        };

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

        // Reset to initial state
        void reset()
        {
            state = DEFINED;
            lockedHeight = 0xffffffff;
        }

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        const char *stateName();
        ArcMist::String description();

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

        int height() const { return mHeight; }

        int32_t activeVersion() const { return mActiveVersion; }
        int32_t requiredVersion() const { return mRequiredVersion; }

        SoftFork::State softForkState(unsigned int pID) const;

        void process(const BlockStats &pBlockStats, unsigned int pBlockHeight);

        void revert();

        // Reset all soft forks to initial state
        void reset();

        // Load from/Save to file system
        bool load(const char *pFileName = "soft_forks");
        bool save(const char *pFileName = "soft_forks");

    private:

        void add(SoftFork *pSoftFork);

        int mHeight;
        unsigned int mPreviousHeight;

        std::vector<SoftFork *> mSoftForks;

        int32_t mActiveVersion;
        int32_t mRequiredVersion;

        int32_t mPreviousActiveVersion;
        int32_t mPreviousRequiredVersion;

        unsigned int mThreshHold;
        bool mModified;

    };
}

#endif