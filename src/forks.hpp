/**************************************************************************
 * Copyright 2017 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_FORKS_HPP
#define BITCOIN_FORKS_HPP

#include "string.hpp"
#include "hash.hpp"
#include "log.hpp"
#include "stream.hpp"
#include "base.hpp"

#include <cstdint>
#include <list>
#include <vector>

#define BITCOIN_FORKS_LOG_NAME "Forks"


namespace BitCoin
{
    class BlockStat
    {
    public:
        BlockStat() : accumulatedWork(32) {}
        BlockStat(int32_t pVersion, uint32_t pTime, uint32_t pTargetBits, const NextCash::Hash &pAccumulatedWork) :
          accumulatedWork(pAccumulatedWork)
          { version = pVersion; time = pTime; targetBits = pTargetBits; }

        void write(NextCash::OutputStream *pStream) const
        {
            pStream->write(this, 12);
            accumulatedWork.write(pStream);
        }

        bool read(NextCash::InputStream *pStream)
        {
            if(pStream->remaining() < 12)
                return false;

            pStream->read(this, 12);

            if(!accumulatedWork.read(pStream))
                return false;
            return true;
        }

        bool operator <(const BlockStat &pRight) const { return time < pRight.time; }

        static const unsigned int SIZE = 44;

        int32_t       version;
        uint32_t      time;
        uint32_t      targetBits;
        NextCash::Hash accumulatedWork;
    };

    class BlockStats : public std::vector<BlockStat *>
    {
    public:

        BlockStats() { mIsValid = false; }
        ~BlockStats();

        int height() const { return size() - 1; }

        uint32_t time(unsigned int pBlockHeight) const;
        uint32_t targetBits(unsigned int pBlockHeight) const;
        const NextCash::Hash &accumulatedWork(unsigned int pBlockHeight) const;

        // Note : Call after block has been added to stats
        uint32_t getMedianPastTime(unsigned int pBlockHeight, unsigned int pMedianCount = 11) const;

        void getMedianPastTimeAndWork(unsigned int pBlockHeight, uint32_t &pTime, NextCash::Hash &pAccumulatedWork,
          unsigned int pMedianCount = 3) const;

        void add(int32_t pVersion, uint32_t pTime, uint32_t pTargetBits)
        {
            NextCash::Hash work(32);
            NextCash::Hash target(32);
            target.setDifficulty(pTargetBits);
            target.getWork(work);
            work += accumulatedWork(height());
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_FORKS_LOG_NAME,
              // "Block work at height %d : %s", size(), work.hex().text());
            push_back(new BlockStat(pVersion, pTime, pTargetBits, work));
        }

        void revert(unsigned int pBlockHeight)
        {
            if(size() <= pBlockHeight + 1)
                return;

            while(size() > pBlockHeight + 1)
            {
                delete back();
                pop_back();
            }
        }

        bool load();
        bool save();

    private:
        bool mIsValid;
    };

    class SoftFork
    {
    public:
        enum ID
        {
            // These all share the same start time, timeout, and bit, so they will share one ID
            BIP0068 = 1, // Relative lock-time using consensus-enforced sequence numbers(activated height 419328)
            BIP0112 = 1, // CHECKSEQUENCEVERIFY(activated height 419328)
            BIP0113 = 1, // Median time-past as endpoint for lock-time calculations(activated height 419328)
            BIP0141 = 2, // Segregated Witness (BIP-0141, BIP-0143, BIP-0147, BIP-0148)
            BIP0091 = 3, // Segregated Witness (Reduced Threshold)
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

        static const int NOT_LOCKED = -1;

        SoftFork()
        {
            id = 0;
            bit = 0;
            startTime = 0;
            timeout = 0;

            state = UNDEFINED;
            lockedHeight = NOT_LOCKED;
        }
        SoftFork(const char *pName, unsigned int pID, uint8_t pBit, unsigned int pStartTime, unsigned int pTimeout)
        {
            name = pName;
            id = pID;
            bit = pBit;
            startTime = pStartTime;
            timeout = pTimeout;

            state = DEFINED;
            lockedHeight = NOT_LOCKED;
        }

        void revert(const BlockStats &pBlockStats, int pBlockHeight);

        // Reset to initial state
        void reset()
        {
            state        = DEFINED;
            lockedHeight = NOT_LOCKED;
        }

        void write(NextCash::OutputStream *pStream);
        bool read(NextCash::InputStream *pStream);

        const char *stateName();
        NextCash::String description();

        // Predefined values
        NextCash::String name;
        unsigned int id;
        uint8_t bit;
        unsigned int startTime;
        unsigned int timeout;

        // Values that change based on chain state
        State state;
        int lockedHeight;
    };

    class Forks
    {
    public:

        Forks();
        ~Forks();

        int height() const { return mHeight; }

        // Version 2 BIP0034 Block height as first part of coinbase input script
        //   Became required on mainnet at block height 227931
        // Version 3 BIP0066 Strict DER signature formatting
        //   Became required on mainnet at block height 363725
        // Version 4 BIP0065 OP_CHECKLOCKTIMEVERIFY
        //   Became required on mainnet at block height 388381
        int32_t enabledVersion() const { return mEnabledVersion; }
        int32_t requiredVersion() const { return mRequiredVersion; }

        SoftFork::State softForkState(unsigned int pID) const;

        // BitCoin Cash
#ifdef DISABLE_CASH
        static const uint32_t CASH_ACTIVATION_TIME = 0;
#else
        static const uint32_t CASH_ACTIVATION_TIME = 1501590000; // Block height on mainnet 478558
#endif
        static const unsigned int HARD_MAX_BLOCK_SIZE = 1000000;
        static const unsigned int CASH_START_MAX_BLOCK_SIZE = 8000000;

        bool cashActive() const { return mCashForkBlockHeight != -1 && mHeight >= mCashForkBlockHeight; }
        int cashForkBlockHeight() const { return mCashForkBlockHeight; }
        unsigned int blockMaxSize() const { return mBlockMaxSize; }

        void process(const BlockStats &pBlockStats, int pBlockHeight);

        void revert(const BlockStats &pBlockStats, int pBlockHeight);

        // Reset all soft forks to initial state
        void reset();

        // Load from/Save to file system
        bool load(const char *pFileName = "forks");
        bool save(const char *pFileName = "forks");

    private:

        void add(SoftFork *pSoftFork);

        int mHeight;

        std::vector<SoftFork *> mForks;

        int32_t mEnabledVersion;
        int32_t mRequiredVersion;

        // For revert
        int mVersionEnabledHeights[3];
        int mVersionRequiredHeights[3];

        int mCashForkBlockHeight;
        unsigned int mBlockMaxSize;

        unsigned int mThreshHold;
        bool mModified;

    };
}

#endif