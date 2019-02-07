/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_FORKS_HPP
#define BITCOIN_FORKS_HPP

#include "string.hpp"
#include "file_stream.hpp"
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
    class Chain;

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

        static const unsigned int NOT_LOCKED = 0;

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

        // Revert to pHeight.
        void revert(Chain *pChain, unsigned int pHeight);

        // Reset to initial state
        void reset()
        {
            state        = DEFINED;
            lockedHeight = NOT_LOCKED;
        }

        void write(NextCash::OutputStream *pStream);
        bool read(NextCash::InputStream *pStream);

        bool isActive(unsigned int pHeight);

        const char *stateName();
        NextCash::String description();

        // Predefined values
        NextCash::String name;
        unsigned int id;
        uint8_t bit;
        Time startTime;
        Time timeout;

        // Values that change based on chain state
        State state;
        unsigned int lockedHeight;
    };

    class Forks
    {
    public:

        Forks();
        ~Forks();

        unsigned int height() const { return mHeight; }

        // Version 2 BIP0034 Block height as first part of coinbase input script.
        //   Became enabled on mainnet at block height 224412.
        //   Became active/required on mainnet at block height 227930.
        // Version 3 BIP0066 Strict DER signature formatting.
        //   Became enabled on mainnet at block height 359752.
        //   Became active/enforced on mainnet at block height 363724.
        // Version 4 BIP0065 OP_CHECKLOCKTIMEVERIFY.
        //   Became enabled on mainnet at block height 387277.
        //   Became active/enforced on mainnet at block height 388380.
        int32_t enabledBlockVersion(unsigned int pHeight) const;
        int32_t requiredBlockVersion(unsigned int pHeight) const;

        bool softForkIsActive(unsigned int pHeight, unsigned int pID);

        static const unsigned int HARD_MAX_BLOCK_SIZE = 1000000;

        // BitCoin Cash
#ifdef DISABLE_CASH
        static const Time CASH_ACTIVATION_TIME = 0;
#else
        static const Time CASH_ACTIVATION_TIME = 1501590000; // Block height on mainnet 478558
#endif
        static const unsigned int CASH_START_MAX_BLOCK_SIZE = 8000000;

        // TODO Change cash forks to be more dynamic, like the soft forks, like a list.
        bool cashActive(unsigned int pHeight) const
          { return mCashActivationBlockHeight != 0 && pHeight > mCashActivationBlockHeight; }
        unsigned int cashForkBlockHeight() const { return mCashActivationBlockHeight; }

        // New Cash DAA (Nov 13th 2018)
        static const Time CASH_FORK_201711_ACTIVATION_TIME = 1510600000;

        bool cashFork201711IsActive(unsigned int pHeight) const
          { return mCashFork201711BlockHeight != 0 && pHeight > mCashFork201711BlockHeight; }

        // 2018 May Hard Fork
        static const Time CASH_FORK_201805_ACTIVATION_TIME = 1526400000;
        static const unsigned int FORK_201805_MAX_BLOCK_SIZE = 32000000;

        bool cashFork201805IsActive(unsigned int pHeight) const
          { return mCashFork201805BlockHeight != 0 && pHeight > mCashFork201805BlockHeight; }

        // 2018 Nov Hard Fork
        static const Time CASH_FORK_201811_ACTIVATION_TIME = 1542300000;
        static const unsigned int FORK_201811_MAX_BLOCK_SIZE = 128000000;

        // Enable OP_CHECKDATASIG and OP_CHECKDATASIGVERIFY opcodes
        // Enforce 100 byte minimum transaction size
        // Enforce "push only" rule for scriptSig
        // Enforce "clean stack" rule
        bool cashFork201811IsActive(unsigned int pHeight) const
          { return mCashFork201811BlockHeight != 0 && pHeight > mCashFork201811BlockHeight; }

        unsigned int blockMaxSize(unsigned int pHeight) const
        {
            if(pHeight >= mHeight)
                return mBlockMaxSize;
            else if(mCashFork201811BlockHeight != 0 &&
              pHeight >= mCashFork201811BlockHeight)
                return FORK_201811_MAX_BLOCK_SIZE;
            else if(mCashFork201805BlockHeight != 0 &&
              pHeight >= mCashFork201805BlockHeight)
                return FORK_201805_MAX_BLOCK_SIZE;
            else if(mCashActivationBlockHeight != 0 &&
              pHeight >= mCashActivationBlockHeight)
                return CASH_START_MAX_BLOCK_SIZE;
            else
                return HARD_MAX_BLOCK_SIZE;
        }

        unsigned int elementMaxSize(unsigned int pHeight) const { return mElementMaxSize; }

        uint32_t cashForkID(unsigned int pHeight) const { return mCashForkID; }

        void process(Chain *pChain, unsigned int pHeight);

        // Revert to pHeight.
        void revert(Chain *pChain, unsigned int pHeight);

        // Reset all soft forks to initial state
        void reset();

        // Load from/Save to file system
        bool load(Chain *pChain);
        bool save();

        // For testing
        void setFork201805Active(unsigned int pHeight)
        {
            mHeight = pHeight;
            mCashFork201805BlockHeight = pHeight;
        }

    private:

        void add(SoftFork *pSoftFork, bool pLocked = false);

        unsigned int mHeight;

        std::vector<SoftFork *> mForks;

        std::list<int32_t> mBlockVersions;

        // For revert
        unsigned int mBlockVersionEnabledHeights[3];
        unsigned int mBlockVersionRequiredHeights[3];

        unsigned int mCashActivationBlockHeight;
        unsigned int mCashFork201711BlockHeight;
        unsigned int mCashFork201805BlockHeight;
        unsigned int mCashFork201811BlockHeight;

        unsigned int mBlockMaxSize;
        unsigned int mElementMaxSize;

        uint32_t mCashForkID;

        unsigned int mThreshHold;
        bool mModified;

        NextCash::MutexWithConstantName mMutex;

    };
}

#endif
