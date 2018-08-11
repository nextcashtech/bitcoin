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

        // Revert last block added to soft fork data.
        //   pBlockHeight is the height of the block being reverted.
        void revertLast(Chain *pChain, int pBlockHeight);

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
        int32_t startTime;
        int32_t timeout;

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

        // Version 2 BIP0034 Block height as first part of coinbase input script.
        //   Became enabled on mainnet at block height 224412.
        //   Became active/required on mainnet at block height 227930.
        // Version 3 BIP0066 Strict DER signature formatting.
        //   Became enabled on mainnet at block height 359752.
        //   Became active/enforced on mainnet at block height 363724.
        // Version 4 BIP0065 OP_CHECKLOCKTIMEVERIFY.
        //   Became enabled on mainnet at block height 387277.
        //   Became active/enforced on mainnet at block height 388380.
        int32_t enabledBlockVersion() const { return mEnabledBlockVersion; }
        int32_t requiredBlockVersion() const { return mRequiredBlockVersion; }

        SoftFork::State softForkState(unsigned int pID);

        static const unsigned int HARD_MAX_BLOCK_SIZE = 1000000;

        // BitCoin Cash
#ifdef DISABLE_CASH
        static const int32_t CASH_ACTIVATION_TIME = 0;
#else
        static const int32_t CASH_ACTIVATION_TIME = 1501590000; // Block height on mainnet 478558
#endif
        static const unsigned int CASH_START_MAX_BLOCK_SIZE = 8000000;

        // TODO Change cash forks to be more dynamic, like the soft forks, like a list.
        bool cashActive() const
          { return mCashActivationBlockHeight != -1 && mHeight > mCashActivationBlockHeight; }
        int cashForkBlockHeight() const { return mCashActivationBlockHeight; }

        // New Cash DAA (Nov 13th 2018)
        static const int32_t CASH_FORK_201711_ACTIVATION_TIME = 1510600000;

        bool cashFork201711IsActive() const
          { return mCashFork201711BlockHeight != -1 && mHeight > mCashFork201711BlockHeight; }

        // 2018 May Hard Fork
        static const int32_t CASH_FORK_201805_ACTIVATION_TIME = 1526400000;
        static const unsigned int FORK_201805_MAX_BLOCK_SIZE = 32000000;

        bool cashFork201805IsActive() const
          { return mCashFork201805BlockHeight != -1 && mHeight > mCashFork201805BlockHeight; }

        // 2018 Nov Hard Fork
        static const int32_t CASH_FORK_201811_ACTIVATION_TIME = 1542300000;

        bool cashFork201811IsActive() const
          { return mCashFork201811BlockHeight != -1 && mHeight > mCashFork201811BlockHeight; }

        unsigned int blockMaxSize() const { return mBlockMaxSize; }

        unsigned int elementMaxSize() const { return mElementMaxSize; }

        uint32_t cashForkID() const { return mCashForkID; }

        void process(Chain *pChain, int pBlockHeight);

        // Revert last block added to fork data.
        //   pBlockHeight is the height of the block being reverted.
        void revertLast(Chain *pChain, int pBlockHeight);

        // Reset all soft forks to initial state
        void reset();

        // Load from/Save to file system
        bool load(Chain *pChain);
        bool save();

        // For testing
        void setFork201805Active()
        {
            mHeight = 1;
            mCashFork201805BlockHeight = 0;
        }

    private:

        void add(SoftFork *pSoftFork, bool pLocked = false);

        int mHeight;

        std::vector<SoftFork *> mForks;

        std::list<int32_t> mBlockVersions;
        int32_t mEnabledBlockVersion;
        int32_t mRequiredBlockVersion;

        // For revert
        int mBlockVersionEnabledHeights[3];
        int mBlockVersionRequiredHeights[3];

        int mCashActivationBlockHeight;
        int mCashFork201711BlockHeight;
        int mCashFork201805BlockHeight;
        int mCashFork201811BlockHeight;

        unsigned int mBlockMaxSize;
        unsigned int mElementMaxSize;

        uint32_t mCashForkID;

        unsigned int mThreshHold;
        bool mModified;

        NextCash::MutexWithConstantName mMutex;

    };
}

#endif
