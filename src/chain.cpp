/**************************************************************************
 * Copyright 2017 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "chain.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#endif

#include "log.hpp"
#include "thread.hpp"
#include "file_stream.hpp"
#include "digest.hpp"
#include "info.hpp"
#include "daemon.hpp"
#include "monitor.hpp"

#define BITCOIN_CHAIN_LOG_NAME "Chain"


namespace BitCoin
{
    NextCash::Hash Chain::sBTCForkBlockHash("00000000000000000019f112ec0a9982926f1258cdcc558dd7c3b7e5dc7fa148");

    Chain::Chain() : mInfo(Info::instance()), mPendingLock("Chain Pending"), mProcessMutex("Chain Process")
    {
        mNextBlockHeight = 0;
        mLastFileID = 0;
        mPendingSize = 0;
        mPendingBlockCount = 0;
        mMaxTargetBits = 0x1d00ffff;
        mTargetBits = 0;
        mLastBlockFile = NULL;
        mLastFullPendingOffset = 0;
        mStop = false;
        mIsInSync = false;
        mAnnouncedAdded = false;
        mAnnounceBlock = NULL;
        mAccumulatedProofOfWork = 0;
        mPendingAccumulatedWork.setSize(32);
        mMonitor = NULL;
    }

    Chain::~Chain()
    {
        mPendingLock.writeLock("Destroy");
        if(mLastBlockFile != NULL)
            delete mLastBlockFile;
        for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
            delete *pending;
        for(std::vector<Branch *>::iterator branch=mBranches.begin();branch!=mBranches.end();++branch)
            delete *branch;
        if(mAnnounceBlock != NULL)
            delete mAnnounceBlock;
        mPendingLock.writeUnlock();
    }

    Branch::~Branch()
    {
        for(std::list<PendingBlockData *>::iterator pending=pendingBlocks.begin();pending!=pendingBlocks.end();++pending)
            delete *pending;
    }

    bool Chain::updateTargetBits()
    {
        double adjustFactor;
        uint32_t lastTargetBits;

        if(mBlockStats.height() <= 1)
        {
            mTargetBits = mMaxTargetBits;
            return true;
        }

        if(mForks.cashActive())
        {
            if(mBlockStats.getMedianPastTime(mBlockStats.height()) > 1510600000)
            {
                if(mBlockStats.height() > 146)
                {
                    // Nov 13th Bitcoin Cash Hard Fork DAA
                    // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      // "Using cash DAA for block height %d", mBlockStats.height());

                    // Get first and last block times and accumulated work
                    int32_t lastTime, firstTime;
                    NextCash::Hash lastWork, firstWork;

                    mBlockStats.getMedianPastTimeAndWork(mBlockStats.height() - 1, lastTime, lastWork, 3);
                    mBlockStats.getMedianPastTimeAndWork(mBlockStats.height() - 145, firstTime, firstWork, 3);

                    int32_t timeSpan = lastTime - firstTime;
                    // NextCash::String timeText;

                    // timeText.writeFormattedTime(firstTime);
                    // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      // "First time : %d (%s)", firstTime, timeText.text());
                    // timeText.writeFormattedTime(lastTime);
                    // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      // "Last time  : %d (%s)", lastTime, timeText.text());
                    // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      // "Time Span : %d", timeSpan);

                    // Apply limits
                    if(timeSpan < 72 * 600)
                        timeSpan = 72 * 600;
                    else if(timeSpan > 288 * 600)
                        timeSpan = 288 * 600;

                    // Let the Work Performed (W) be equal to the difference in chainwork[3] between B_last and B_first.
                    NextCash::Hash work = lastWork - firstWork;

                    // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      // "First work : %s", firstWork.hex().text());
                    // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      // "Last work  : %s", lastWork.hex().text());
                    // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      // "Work       : %s", work.hex().text());

                    // Let the Projected Work (PW) be equal to (W * 600) / TS.
                    work *= 600;
                    work /= timeSpan;

                    // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      // "Proj Work  : %s", work.hex().text());

                    // Let Target (T) be equal to the (2^256 - PW) / PW. This is calculated by
                    //   taking the two’s complement of PW (-PW) and dividing it by PW (-PW / PW).
                    NextCash::Hash target = (-work) / work;

                    // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      // "Target     : %s", target.hex().text());

                    // The target difficulty for block B_n+1 is then equal to the lesser of T and
                    //   0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
                    static NextCash::Hash sMaxTarget("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                    if(target > sMaxTarget)
                        sMaxTarget.getDifficulty(mTargetBits, mMaxTargetBits);
                    else
                        target.getDifficulty(mTargetBits, mMaxTargetBits);

                    // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      // "Target Bits : 0x%08x", mTargetBits);
                }
            }
            else if(mBlockStats.height() > 7)
            {
                // Bitcoin Cash EDA (Emergency Difficulty Adjustment)
                uint32_t mptDiff = mBlockStats.getMedianPastTime(mBlockStats.height()) -
                  mBlockStats.getMedianPastTime(mBlockStats.height() - 6);

                // If more than 12 hours on the last 6 blocks then reduce difficulty by 20%
                if(mptDiff >= 43200)
                {
                    lastTargetBits = mBlockStats.targetBits(mBlockStats.height() - 1);
                    adjustFactor = 1.25;
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "EDA increasing target bits 0x%08x by a factor of %f to reduce difficulty by %.02f%%", lastTargetBits,
                      adjustFactor, (1.0 - (1.0 / adjustFactor)) * 100.0);

                    // Treat targetValue as a 256 bit number and multiply it by adjustFactor
                    mTargetBits = multiplyTargetBits(lastTargetBits, adjustFactor, mMaxTargetBits);

                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "EDA new target bits for block height %d : 0x%08x", mBlockStats.height(), mTargetBits);
                }
            }
        }

        if(mBlockStats.height() % RETARGET_PERIOD != 0 || // Not an original DAA retarget block
          (mForks.cashActive() && mBlockStats.getMedianPastTime(mBlockStats.height()) > 1510600000)) // Disable original DAA when new Cash DAA becomes active
            return true;

        int32_t lastBlockTime      = mBlockStats.time(mBlockStats.height() - 1);
        int32_t lastAdjustmentTime = mBlockStats.time(mBlockStats.height() - RETARGET_PERIOD);

        lastTargetBits = mBlockStats.targetBits(mBlockStats.height() - 1);

        // Calculate percent of time actually taken for the last 2016 blocks by the goal time of 2 weeks
        // Adjust factor over 1.0 means the target is going up, which also means the difficulty to
        //   find a hash under the target goes down
        // Adjust factor below 1.0 means the target is going down, which also means the difficulty to
        //   find a hash under the target goes up
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Time spent on last 2016 blocks %d - %d = %d", lastBlockTime, lastAdjustmentTime, lastBlockTime - lastAdjustmentTime);
        adjustFactor = (double)(lastBlockTime - lastAdjustmentTime) / 1209600.0;

        if(adjustFactor > 1.0)
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Increasing target bits 0x%08x by a factor of %f to reduce difficulty by %.02f%%", lastTargetBits,
              adjustFactor, (1.0 - (1.0 / adjustFactor)) * 100.0);
        else
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Decreasing target bits 0x%08x by a factor of %f to increase difficulty by %.02f%%", lastTargetBits,
              adjustFactor, ((1.0 / adjustFactor) - 1.0) * 100.0);

        if(adjustFactor < 0.25)
        {
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Changing target adjust factor to 0.25 because of maximum decrease of 75%");
            adjustFactor = 0.25; // Maximum decrease of 75%
        }
        else if(adjustFactor > 4.0)
        {
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Changing target adjust factor to 4.0 because of maximum increase of 400%");
            adjustFactor = 4.0; // Maximum increase of 400%
        }

        /* Note: an off-by-one error in the Bitcoin Core implementation causes the difficulty to be
         * updated every 2,016 blocks using timestamps from only 2,015 blocks, creating a slight skew.
         */

        // Treat targetValue as a 256 bit number and multiply it by adjustFactor
        mTargetBits = multiplyTargetBits(lastTargetBits, adjustFactor, mMaxTargetBits);

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "New target bits for block height %d : 0x%08x", mBlockStats.height(), mTargetBits);
        return true;
    }

    bool Chain::headerAvailable(const NextCash::Hash &pHash)
    {
        if(blockInChain(pHash))
            return true;

        bool found = false;
        mPendingLock.readLock();
        for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
            if((*pending)->block->hash == pHash)
            {
                found = true;
                break;
            }
        mPendingLock.readUnlock();
        return found;
    }

    unsigned int Chain::blockFileID(const NextCash::Hash &pHash)
    {
        if(pHash.isEmpty())
            return 0; // Empty hash means start from the beginning

        BlockSet &blockSet = mBlockLookup[pHash.lookup16()];
        unsigned int result = INVALID_FILE_ID;

        blockSet.lock();
        for(BlockSet::iterator i=blockSet.begin();i!=blockSet.end();++i)
            if(pHash == (*i)->hash)
            {
                result = (*i)->fileID;
                blockSet.unlock();
                return result;
            }
        blockSet.unlock();
        return result;
    }

    int Chain::blockHeight(const NextCash::Hash &pHash)
    {
        int result = -1;
        if(pHash.isEmpty())
            return result; // Empty hash means start from the beginning

        BlockSet &blockSet = mBlockLookup[pHash.lookup16()];
        blockSet.lock();
        for(BlockSet::iterator i=blockSet.begin();i!=blockSet.end();++i)
            if(pHash == (*i)->hash)
            {
                result = (*i)->height;
                break;
            }
        blockSet.unlock();

        if(result == -1)
        {
            // Check pending
            int currentHeight = height();
            mPendingLock.readLock();
            for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
            {
                ++currentHeight;
                if((*pending)->block->hash == pHash)
                {
                    result = currentHeight;
                    break;
                }
            }
            mPendingLock.readUnlock();
        }

        return result;
    }

    unsigned int Chain::pendingCount()
    {
        mPendingLock.readLock();
        unsigned int result = mPendingBlocks.size();
        mPendingLock.readUnlock();
        return result;
    }

    unsigned int Chain::pendingBlockCount()
    {
        mPendingLock.readLock();
        unsigned int result = mPendingBlockCount;
        mPendingLock.readUnlock();
        return result;
    }

    unsigned int Chain::pendingSize()
    {
        mPendingLock.readLock();
        unsigned int result = mPendingSize;
        mPendingLock.readUnlock();
        return result;
    }

    std::vector<unsigned int> Chain::blackListedNodeIDs()
    {
        mPendingLock.writeLock("Black Listed Nodes");
        std::vector<unsigned int> result = mBlackListedNodeIDs;
        mBlackListedNodeIDs.clear();
        mPendingLock.writeUnlock();
        return result;
    }

    void Chain::addBlackListedBlock(const NextCash::Hash &pHash)
    {
        if(!mBlackListBlocks.contains(pHash))
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Added block to black list : %s", pHash.hex().text());
            // Keep list at 1024 or less
            if(mBlackListBlocks.size() > 1024)
                mBlackListBlocks.erase(mBlackListBlocks.begin());
            mBlackListBlocks.push_back(pHash);
        }
    }

    Block *Chain::blockToAnnounce()
    {
        Block *result = NULL;
        NextCash::Hash hash;
        mPendingLock.writeLock("Announce");
        if(mBlocksToAnnounce.size() > 0)
        {
            hash = mBlocksToAnnounce.front();
            mBlocksToAnnounce.erase(mBlocksToAnnounce.begin());
            if(mAnnounceBlock != NULL && mAnnounceBlock->hash == hash)
            {
                result = mAnnounceBlock;
                mAnnounceBlock = NULL;
            }
            else
            {
                // Get block from file
                result = new Block();
                if(!getBlock(hash, *result))
                {
                    delete result;
                    result = NULL;
                }
            }
        }
        mPendingLock.writeUnlock();
        return result;
    }

    bool Chain::blocksNeeded()
    {
        // Check for pending block
        bool result = false;
        mPendingLock.readLock();
        for(std::list<PendingBlockData *>::iterator pendingBlock=mPendingBlocks.begin();pendingBlock!=mPendingBlocks.end();++pendingBlock)
            if((*pendingBlock)->requestingNode == 0 || getTime() - (*pendingBlock)->requestedTime > 10)
            {
                result = true;
                break;
            }
        mPendingLock.readUnlock();
        return result;
    }

    bool Chain::headersNeeded()
    {
        // Check for pending header
        bool result = false;
        mPendingLock.readLock();
        for(std::list<PendingHeaderData *>::iterator pendingHeader=mPendingHeaders.begin();pendingHeader!=mPendingHeaders.end();++pendingHeader)
            if((*pendingHeader)->requestingNode == 0 || getTime() - (*pendingHeader)->requestedTime > 2)
            {
                // NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
                  // "Pending header needed : %s", (*pendingHeader)->hash.hex().text());
                result = true;
                break;
            }
        mPendingLock.readUnlock();
        return result;
    }

    bool Chain::headerInBranch(const NextCash::Hash &pHash)
    {
        // Loop through all branches
        mPendingLock.readLock();
        for(std::vector<Branch *>::iterator branch=mBranches.begin();branch!=mBranches.end();++branch)
        {
            // Loop through all pending blocks on the branch
            for(std::list<PendingBlockData *>::iterator pending=(*branch)->pendingBlocks.begin();pending!=(*branch)->pendingBlocks.end();++pending)
                if((*pending)->block->hash == pHash)
                {
                    mPendingLock.readUnlock();
                    return true;
                }
        }
        mPendingLock.readUnlock();
        return false;
    }

    bool Chain::checkBranches()
    {
        NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME, "Checking branches");

        mPendingLock.writeLock("Check Branches");
        if(mBranches.size() == 0)
        {
            mPendingLock.writeUnlock();
            return true;
        }

        // Check each branch to see if it has more "work" than the main chain
        Branch *longestBranch = NULL;
        unsigned int offset = 1;
        int diff;
        for(std::vector<Branch *>::iterator branch=mBranches.begin();branch!=mBranches.end();)
        {
            diff = (*branch)->accumulatedWork.compare(pendingAccumulatedWork());

            if(diff < 0)
            {
                if(height() > 144 &&
                  (*branch)->height + (*branch)->pendingBlocks.size() < (unsigned int)height() - 144)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME, "Dropping branch %d", offset);

                    // Drop branches that are 144 blocks behind the main chain
                    delete *branch;
                    branch = mBranches.erase(branch);
                    continue;
                }
            }
            else if(diff > 0 && (longestBranch == NULL || (*branch)->accumulatedWork > longestBranch->accumulatedWork))
                longestBranch = *branch;

            ++branch;
            ++offset;
        }

        if(longestBranch == NULL)
        {
            mPendingLock.writeUnlock();
            return true;
        }

        // Swap the branch with the most "work" for the main chain.
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Activating branch at height %d", longestBranch->height);

        // Currently main chain (save in case it switches back)
        Branch *newBranch = new Branch(longestBranch->height - 1, mBlockStats.accumulatedWork(longestBranch->height - 1));

        // Read all main chain blocks above branch height and put them in a branch.
        int currentHeight = height();
        Block *block;
        for(int i=longestBranch->height;i<currentHeight;++i)
        {
            block = new Block();
            getBlock(i, *block);
            newBranch->addBlock(block);
        }

        // Add current main pending blocks to branch
        for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
        {
            newBranch->addBlock((*pending)->block);
            (*pending)->block = NULL;
            delete *pending;
        }

        // Clear main pending blocks
        mPendingBlocks.clear();
        mPendingSize = 0;
        mLastFullPendingOffset = 0;
        mPendingBlockCount = 0;
        mLastPendingHash.clear();
        mPendingAccumulatedWork = accumulatedWork();

        // Revert the main chain to the before branch height.
        if(!revert(longestBranch->height - 1))
        {
            delete newBranch;
            mPendingLock.writeUnlock();
            return false;
        }

        // Put all the branch pending blocks into the main pending blocks.
        //    Then normal processing will complete and process them.
        offset = 0;
        NextCash::Hash work(32);
        NextCash::Hash target(32);
        for(std::list<PendingBlockData *>::iterator pending=longestBranch->pendingBlocks.begin();pending!=longestBranch->pendingBlocks.end();++pending)
        {
            mPendingBlocks.push_back(*pending);
            target.setDifficulty((*pending)->block->targetBits);
            target.getWork(work);
            mPendingAccumulatedWork += work;
            mPendingSize += (*pending)->block->size();
            if((*pending)->isFull())
            {
                mLastFullPendingOffset = offset;
                ++mPendingBlockCount;
            }
            ++offset;
        }
        longestBranch->pendingBlocks.clear(); // No deletes necessary since they were reused

        // Delete the branch
        for(std::vector<Branch *>::iterator branch=mBranches.begin();branch!=mBranches.end();++branch)
            if(*branch == longestBranch)
            {
                mBranches.erase(branch);
                delete longestBranch;
                break;
            }

        // Add the new branch
        mBranches.push_back(newBranch);

        if(mInfo.spvMode)
        {
            // Process headers into the main chain
            bool success = true;
            for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
            {
                if(success && !processHeader((*pending)->block))
                    success = false;

                // Add header to chain
                if(success && !writeBlock((*pending)->block))
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to write header to chain at height %d : %s",
                      mNextBlockHeight, (*pending)->block->hash.hex().text());
                    revert(mNextBlockHeight);
                    success = false;
                }

                if(success)
                {
                    addBlockHash((*pending)->block->hash);

                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Added header to chain at height %d : %s",
                      mNextBlockHeight - 1, (*pending)->block->hash.hex().text());
                }

                delete *pending;
            }

            mPendingBlocks.clear();
            mPendingSize = 0;
            mLastFullPendingOffset = 0;
            mPendingBlockCount = 0;
            mLastPendingHash.clear();
            mPendingAccumulatedWork = accumulatedWork();
        }

        mPendingLock.writeUnlock();
        return true;
    }

    Chain::HashStatus Chain::addPendingHash(const NextCash::Hash &pHash, unsigned int pNodeID)
    {
        mPendingLock.readLock();
        if(mBlackListBlocks.contains(pHash))
        {
            mPendingLock.readUnlock();
            return BLACK_LISTED;
        }
        else if(Forks::CASH_ACTIVATION_TIME == 1501590000)
        {
            // Manually reject BTC fork block hash since SPV mode can't tell the difference without
            //   block size or transaction verification
            if(sBTCForkBlockHash == pHash)
            {
                mPendingLock.readUnlock();
                mPendingLock.writeLock("Black List");
                addBlackListedBlock(pHash);
                mPendingLock.writeUnlock();
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
                  "Rejecting BTC fork block hash : %s", pHash.hex().text());
                return BLACK_LISTED;
            }
        }
        mPendingLock.readUnlock();

        if(blockInChain(pHash) || headerInBranch(pHash))
            return ALREADY_HAVE;

        mPendingLock.readLock();
        // Check if block is requested for the chain
        for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
            if((*pending)->block->hash == pHash)
            {
                if(!mInfo.spvMode && !(*pending)->isFull() && (*pending)->requestingNode == 0)
                {
                    mPendingLock.readUnlock();
                    return NEED_BLOCK;
                }
                else
                {
                    mPendingLock.readUnlock();
                    return ALREADY_HAVE;
                }
                break;
            }
        mPendingLock.readUnlock();

        // Check for a preexisting pending header
        mPendingLock.writeLock("Add Pending Hash");
        for(std::list<PendingHeaderData *>::iterator pendingHeader=mPendingHeaders.begin();pendingHeader!=mPendingHeaders.end();++pendingHeader)
            if((*pendingHeader)->hash == pHash)
            {
                if((*pendingHeader)->requestingNode == 0 || getTime() - (*pendingHeader)->requestedTime > 2)
                {
                    (*pendingHeader)->requestingNode = pNodeID;
                    (*pendingHeader)->requestedTime = getTime();
                    (*pendingHeader)->updateTime = getTime();
                    mPendingLock.writeUnlock();
                    return NEED_HEADER;
                }
                else
                {
                    mPendingLock.writeUnlock();
                    return ALREADY_HAVE;
                }
                break;
            }

        // Add a new pending header
        // NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
          // "Adding pending header : %s", pHash.hex().text());
        mPendingHeaders.push_back(new PendingHeaderData(pHash, pNodeID, getTime()));
        mPendingLock.writeUnlock();
        return NEED_HEADER;
    }

    bool Chain::getPendingHeaderHashes(NextCash::HashList &pList)
    {
        pList.clear();
        mPendingLock.readLock();
        for(std::list<PendingHeaderData *>::iterator pendingHeader=mPendingHeaders.begin();pendingHeader!=mPendingHeaders.end();++pendingHeader)
            pList.push_back((*pendingHeader)->hash);
        mPendingLock.readUnlock();
        return true;
    }

    bool Chain::processHeader(Block *pBlock)
    {
        // Add to block stats
        mBlockStats.add(pBlock->version, pBlock->time, pBlock->targetBits);
        uint32_t previousTargetBits = mTargetBits;

        updateTargetBits();

        // Check target bits
        if(pBlock->targetBits != mTargetBits)
        {
            bool useTestMinDifficulty = network() == TESTNET &&
              pBlock->time - mBlockStats.time(mBlockStats.height() - 1) > 1200;

            // If on TestNet and 20 minutes since last block
            if(useTestMinDifficulty && pBlock->targetBits == 0x1d00ffff)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                  "Using TestNet special minimum difficulty rule 1d00ffff for block %d", mNextBlockHeight);
            }
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Block target bits don't match chain's current target bits : chain %08x != block %08x",
                  mTargetBits, pBlock->targetBits);
                mTargetBits = previousTargetBits;
                mBlockStats.revert(mNextBlockHeight - 1);
                return false;
            }
        }

        mForks.process(mBlockStats, mNextBlockHeight);
        return true;
    }

    // Add block header to queue to be requested and downloaded
    bool Chain::addPendingBlock(Block *pBlock)
    {
        mPendingLock.writeLock("Add");

        // Remove pending header
        bool foundInPendingHeader = false;
        for(std::list<PendingHeaderData *>::iterator pendingHeader=mPendingHeaders.begin();pendingHeader!=mPendingHeaders.end();++pendingHeader)
            if((*pendingHeader)->hash == pBlock->hash)
            {
                // NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
                  // "Removed pending header : %s", pBlock->hash.hex().text());
                foundInPendingHeader = true;
                delete *pendingHeader;
                mPendingHeaders.erase(pendingHeader);
                break;
            }

        if(mBlackListBlocks.contains(pBlock->hash))
        {
            mPendingLock.writeUnlock();
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Rejecting black listed block hash : %s", pBlock->hash.hex().text());
            return false;
        }
        else if(Forks::CASH_ACTIVATION_TIME == 1501590000)
        {
            // Manually reject BTC fork block hash since SPV mode can't tell the difference without
            //   block size or transaction verification
            if(sBTCForkBlockHash == pBlock->hash)
            {
                addBlackListedBlock(pBlock->hash);
                mPendingLock.writeUnlock();
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
                  "Rejecting BTC fork block header : %s", pBlock->hash.hex().text());
                return false;
            }
        }

        if(blockInChain(pBlock->hash))
        {
            mPendingLock.writeUnlock();
            // NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
              // "Header already in chain : %s", pBlock->hash.hex().text());
            return false;
        }

        // This just checks that the proof of work meets the target bits in the header.
        //   The validity of the target bits value is checked before adding the full block to the chain.
        if(!pBlock->hasProofOfWork())
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Invalid proof of work : %s", pBlock->hash.hex().text());
            NextCash::Hash target;
            target.setDifficulty(pBlock->targetBits);
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Target                   : %s", target.hex().text());
            addBlackListedBlock(pBlock->hash);
            mPendingLock.writeUnlock();
            return false;
        }

        bool added = false;
        bool alreadyHave = false;
        bool filled = false;
        bool branchesUpdated = false;

        if((mPendingBlocks.size() == 0 &&
          ((pBlock->previousHash.isZero() && mLastBlockHash.isEmpty()) ||
          pBlock->previousHash == mLastBlockHash)) ||
          (mPendingBlocks.size() != 0 && mPendingBlocks.back()->block->hash == pBlock->previousHash))
        {
            if(mInfo.spvMode)
            {
                if(!processHeader(pBlock))
                {
                    addBlackListedBlock(pBlock->hash);
                    mPendingLock.writeUnlock();
                    return false;
                }

                // Add header to chain
                if(writeBlock(pBlock))
                {
                    addBlockHash(pBlock->hash);

                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Added header to chain at height %d : %s",
                      mNextBlockHeight - 1, pBlock->hash.hex().text());

                    added = true;

                    // Block was in pendingHeaders which is populated by announce hashes
                    if(foundInPendingHeader && !mAnnouncedAdded)
                    {
                        if(!mIsInSync)
                            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME, "Announced block header added");
                        mAnnouncedAdded = true;

                        if(!mIsInSync && getTime() - pBlock->time < 600)
                        {
                            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Chain is in sync");
                            mIsInSync = true;
                        }
                    }

                    // Since this function will return true, the calling function will assume this
                    //   function now owns the memory.
                    // It is no longer needed since it has been written to the block file.
                    delete pBlock;
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to write header to chain at height %d : %s",
                      mNextBlockHeight, pBlock->hash.hex().text());
                    revert(mNextBlockHeight);
                    mPendingLock.writeUnlock();
                    return false;
                }
            }
            else
            {
                // Add to main pending list
                mPendingBlocks.push_back(new PendingBlockData(pBlock));
                NextCash::Hash work(32);
                NextCash::Hash target(32);
                target.setDifficulty(pBlock->targetBits);
                target.getWork(work);
                mPendingAccumulatedWork += work;
                mLastPendingHash = pBlock->hash;
                mPendingSize += pBlock->size();
                added = true;

                // NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
                  // "Added header to pending : %s", pBlock->hash.hex().text());
            }
        }

        if(!added)
        {
            // Check if it is in pending already
            unsigned int offset = 0;
            for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending,++offset)
                if((*pending)->block->hash == pBlock->hash)
                {
                    alreadyHave = true;
                    if(pBlock->transactionCount > 0)
                    {
                        if((*pending)->isFull())
                        {
                            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                              "Block already received from [%d]: %s", (*pending)->requestingNode, pBlock->hash.hex().text());
                        }
                        else
                        {
                            mPendingSize -= (*pending)->block->size();
                            (*pending)->replace(pBlock);
                            mPendingSize += pBlock->size();
                            ++mPendingBlockCount;
                            if(offset > mLastFullPendingOffset)
                                mLastFullPendingOffset = offset;
                            filled = true;
                        }
                    }
                    break;
                }
        }

        if(!alreadyHave && !added && !filled)
        {
            // Check if it is already in a branch
            unsigned int branchID = 1;
            for(std::vector<Branch *>::iterator branch=mBranches.begin();branch!=mBranches.end();++branch,++branchID)
            {
                for(std::list<PendingBlockData *>::iterator pending=(*branch)->pendingBlocks.begin();pending!=(*branch)->pendingBlocks.end();++pending)
                    if((*pending)->block->hash == pBlock->hash)
                    {
                        alreadyHave = true;
                        if((*pending)->isFull())
                            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                              "Block already received on branch %d from [%d]: %s", branchID,
                              (*pending)->requestingNode, pBlock->hash.hex().text());
                        else
                        {
                            (*pending)->replace(pBlock);
                            filled = true;
                        }
                        break;
                    }

                if(alreadyHave)
                    break;
            }
        }

        if(!alreadyHave && !added && !filled)
        {
            // Check if it is in pending already or fits on a pending block
            unsigned int offset = 0;
            for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending,++offset)
                if((*pending)->block->hash == pBlock->previousHash)
                {
                    added = true;
                    branchesUpdated = true;
                    Branch *newBranch = new Branch(height() + offset + 1, mBlockStats.accumulatedWork(height() + offset + 1));
                    newBranch->addBlock(pBlock);
                    mBranches.push_back(newBranch);
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Started branch with header at pending height %d : %s", newBranch->height, pBlock->hash.hex().text());
                    break;
                }
        }

        if(!alreadyHave && !added && !filled)
        {
            // Check if it fits on a branch
            unsigned int branchID = 1;
            for(std::vector<Branch *>::iterator branch=mBranches.begin();branch!=mBranches.end();++branch,++branchID)
                if((*branch)->pendingBlocks.size() > 0 && (*branch)->pendingBlocks.back()->block->hash == pBlock->previousHash)
                {
                    (*branch)->addBlock(pBlock);
                    added = true;
                    branchesUpdated = true;
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Added header to branch %d (%d blocks) : %s", branchID, (*branch)->pendingBlocks.size(),
                      pBlock->hash.hex().text());
                    break;
                }
        }

        if(!alreadyHave && !added && !filled)
        {
            // Check if it fits on one of the last 5000 blocks in the chain
            int chainHeight = height();
#ifdef LOW_MEM
            NextCash::HashList::reverse_iterator hash = mLastBlockHashes.rbegin();
            for(int i=0;hash!=mLastBlockHashes.rend()&&i<5000;++i,++hash,--chainHeight)
#else
            NextCash::HashList::reverse_iterator hash = mBlockHashes.rbegin();
            for(int i=0;hash!=mBlockHashes.rend()&&i<5000;++i,++hash,--chainHeight)
#endif
                if(*hash == pBlock->previousHash)
                {
                    added = true;
                    branchesUpdated = true;
                    Branch *newBranch = new Branch(chainHeight, mBlockStats.accumulatedWork(chainHeight));
                    newBranch->addBlock(pBlock);
                    mBranches.push_back(newBranch);
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Started branch with header at height %d : %s", newBranch->height, pBlock->hash.hex().text());
                    break;
                }
                else if(chainHeight == 0)
                    break;
        }

        if(!alreadyHave && !added && !filled)
        {
            mPendingLock.writeUnlock();
            if(alreadyHave)
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                  "Header already downloaded : %s", pBlock->hash.hex().text());
            else
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                  "Unknown header : %s", pBlock->hash.hex().text());
            return false;
        }

        // Block was in pendingHeaders which is populated by announce hashes
        if(added && foundInPendingHeader && !mAnnouncedAdded)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME, "Announced block added to pending");
            mAnnouncedAdded = true;
        }

        mPendingLock.writeUnlock();

        if(branchesUpdated)
            checkBranches();

        return added || filled;
    }

    bool Chain::savePending()
    {
        mPendingLock.readLock();
        if(mPendingBlocks.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "No pending blocks/headers to save to the file system");
            mPendingLock.readUnlock();
            return true;
        }

        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend("pending");
        NextCash::FileOutputStream file(filePathName, true);

        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed to open file to save pending blocks/headers to the file system");
            mPendingLock.readUnlock();
            return false;
        }

        for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
            (*pending)->block->write(&file, true, true);

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Saved %d/%d pending blocks/headers to the file system",
          mPendingBlockCount, mPendingBlocks.size() - mPendingBlockCount);

        mPendingLock.readUnlock();
        return true;
    }

    bool Chain::loadPending()
    {
        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend("pending");
        if(!NextCash::fileExists(filePathName))
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "No file to load pending blocks/headers from the file system");
            return true;
        }

        NextCash::FileInputStream file(filePathName);
        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed to open file to load pending blocks/headers from the file system");
            return false;
        }

        bool success = true;
        Block *newBlock;

        mPendingLock.writeLock("Load");

        // Clear pending (just in case)
        for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
            delete *pending;
        mPendingBlocks.clear();
        mPendingSize = 0;
        mPendingBlockCount = 0;
        mPendingAccumulatedWork = accumulatedWork();
        unsigned int offset = 0;
        NextCash::Hash work(32);
        NextCash::Hash target(32);

        // Read pending blocks/headers from file
        while(file.remaining())
        {
            newBlock = new Block();
            if(!newBlock->read(&file, true, true, true))
            {
                delete newBlock;
                success = false;
                break;
            }
            if(!blockInChain(newBlock->hash))
            {
                mPendingSize += newBlock->size();
                if(newBlock->transactionCount > 0)
                    mPendingBlockCount++;
                mPendingBlocks.push_back(new PendingBlockData(newBlock));
                target.setDifficulty(newBlock->targetBits);
                target.getWork(work);
                mPendingAccumulatedWork += work;
                if(mPendingBlocks.back()->isFull())
                    mLastFullPendingOffset = offset;
                ++offset;
            }
            else
                delete newBlock;
        }

        if(success)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Loaded %d/%d pending blocks/headers from the file system",
              mPendingBlockCount, mPendingBlocks.size() - mPendingBlockCount);
            if(mPendingBlocks.size() > 0)
                mLastPendingHash = mPendingBlocks.back()->block->hash;
        }
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed to load pending blocks/headers from the file system");
            // Clear all pending that were read because they may be invalid
            for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
                delete *pending;
            mPendingBlocks.clear();
            mPendingSize = 0;
            mPendingBlockCount = 0;
            mLastFullPendingOffset = 0;
            mPendingAccumulatedWork = accumulatedWork();
        }

        mPendingLock.writeUnlock();
        return success;
    }

    void Chain::updateBlockProgress(const NextCash::Hash &pHash, unsigned int pNodeID, int32_t pTime)
    {
        mPendingLock.readLock();
        for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
            if((*pending)->block->hash == pHash)
            {
                (*pending)->updateTime = pTime;
                (*pending)->requestingNode = pNodeID;
                break;
            }
        mPendingLock.readUnlock();
    }

    void Chain::markBlocksForNode(NextCash::HashList &pHashes, unsigned int pNodeID)
    {
        mPendingLock.readLock();
        int32_t time = getTime();
        for(NextCash::HashList::iterator hash=pHashes.begin();hash!=pHashes.end();++hash)
            for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
                if((*pending)->block->hash == *hash)
                {
                    (*pending)->requestingNode = pNodeID;
                    (*pending)->requestedTime = time;
                    break;
                }
        mPendingLock.readUnlock();
    }

    void Chain::releaseBlocksForNode(unsigned int pNodeID)
    {
        mPendingLock.readLock();
        for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
            if(!(*pending)->isFull() && (*pending)->requestingNode == pNodeID)
            {
                (*pending)->requestingNode = 0;
                (*pending)->requestedTime = 0;
            }
        for(std::list<PendingHeaderData *>::iterator pendingHeader=mPendingHeaders.begin();pendingHeader!=mPendingHeaders.end();++pendingHeader)
            if((*pendingHeader)->requestingNode == pNodeID)
            {
                (*pendingHeader)->requestingNode = 0;
                (*pendingHeader)->requestedTime = 0;
            }
        mPendingLock.readUnlock();
    }

    bool Chain::getBlocksNeeded(NextCash::HashList &pHashes, unsigned int pCount, bool pReduceOnly)
    {
        pHashes.clear();

        if(mInfo.spvMode)
            return true;

        mPendingLock.readLock();
        unsigned int offset = 0;
        for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
        {
            // If "reduce only" don't request blocks unless there is a full pending block after them
            if(pReduceOnly && offset >= mLastFullPendingOffset)
                break;
            ++offset;

            if(!(*pending)->isFull() && (*pending)->requestingNode == 0)
            {
                pHashes.push_back((*pending)->block->hash);
                if(pHashes.size() >= pCount)
                    break;
            }
        }
        mPendingLock.readUnlock();

        return pHashes.size() > 0;
    }

    bool Chain::writeBlock(Block *pBlock)
    {
        // Add the block or header to a block file
        bool success = true;
        if(mLastFileID == INVALID_FILE_ID)
        {
            // Create first block file
            mLastFileID = 0;
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Creating first block file %08x", mLastFileID);
            BlockFile::lock(mLastFileID);
            mLastBlockFile = BlockFile::create(mLastFileID);
            if(mLastBlockFile == NULL) // Failed to create file
                success = false;
        }
        else
        {
            // Check if last block file is full
            BlockFile::lock(mLastFileID);
            if(mLastBlockFile == NULL)
                mLastBlockFile = new BlockFile(mLastFileID);

            if(!mLastBlockFile->isValid())
            {
                success = false;
                BlockFile::unlock(mLastFileID);
                delete mLastBlockFile;
            }
            else if(mLastBlockFile->isFull())
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Block file %08x is full. Starting new block file %08x", mLastFileID, mLastFileID + 1);

                BlockFile::unlock(mLastFileID);
                delete mLastBlockFile;

                // Create next file
                ++mLastFileID;
                BlockFile::lock(mLastFileID);
                mLastBlockFile = BlockFile::create(mLastFileID);
                if(mLastBlockFile == NULL) // Failed to create file
                {
                    success = false;
                    BlockFile::unlock(mLastFileID);
                }
            }
        }

        if(success)
        {
            success = mLastBlockFile->addBlock(*pBlock);
            BlockFile::unlock(mLastFileID);
        }

        return success;
    }

    void Chain::addBlockHash(NextCash::Hash &pHash)
    {
        BlockSet &blockSet = mBlockLookup[pHash.lookup16()];
        blockSet.lock();
#ifdef LOW_MEM
        mLastBlockHashes.push_back(pHash);
        while(mLastBlockHashes.size() > RECENT_BLOCK_COUNT)
            mLastBlockHashes.erase(mLastBlockHashes.begin());
#else
        mBlockHashes.push_back(pHash);
#endif
        blockSet.push_back(new BlockInfo(pHash, mLastFileID, mNextBlockHeight));
        blockSet.unlock();
        ++mNextBlockHeight;
        mLastBlockHash = pHash;
    }

    bool Chain::processBlock(Block *pBlock)
    {
#ifdef PROFILER_ON
        NextCash::Profiler outputsProfiler("Chain Process Block");
#endif
        mProcessMutex.lock();

        mBlockProcessStartTime = getTime();

        uint32_t previousTargetBits = mTargetBits;
        if(!processHeader(pBlock))
        {
            mProcessMutex.unlock();
            return false;
        }

        // Process block
        if(!pBlock->process(mOutputs, mNextBlockHeight, mBlockStats, mForks))
        {
            mOutputs.revert(pBlock->transactions, mNextBlockHeight);
            mForks.revert(mBlockStats, mNextBlockHeight - 1);
            mBlockStats.revert(mNextBlockHeight - 1);
            mTargetBits = previousTargetBits;
            mProcessMutex.unlock();
            return false;
        }

        mMemPool.remove(pBlock->transactions);

        mAddresses.add(pBlock->transactions, mNextBlockHeight);

        // Add the block to the chain
        bool success = writeBlock(pBlock);

        // Commit and save changes to transaction output pool
        if(success && !mOutputs.commit(pBlock->transactions, mNextBlockHeight))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed to commit transaction outputs to pool");
            mMemPool.revert(pBlock->transactions);
            mOutputs.revert(pBlock->transactions, mNextBlockHeight);
            mForks.revert(mBlockStats, mNextBlockHeight - 1);
            mBlockStats.revert(mNextBlockHeight - 1);
            mTargetBits = previousTargetBits;
            mProcessMutex.unlock();
            return false;
        }

        if(success)
        {
            addBlockHash(pBlock->hash);

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Added block to chain at height %d (%d trans) (%d KiB) (%d s) : %s",
              mNextBlockHeight - 1, pBlock->transactionCount, pBlock->size() / 1024, getTime() - mBlockProcessStartTime,
              pBlock->hash.hex().text());
        }
        else
        {
            mMemPool.revert(pBlock->transactions);
            mAddresses.remove(pBlock->transactions, mNextBlockHeight - 1);
            mForks.revert(mBlockStats, mNextBlockHeight - 1);
            mBlockStats.revert(mNextBlockHeight - 1);
            mTargetBits = previousTargetBits;
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed to add block to file %08x : %s", mLastFileID, pBlock->hash.hex().text());
        }

        mProcessMutex.unlock();
        return success;
    }

    bool Chain::revertBlockFileHeight(int pHeight)
    {
        if(mLastBlockFile != NULL)
        {
            delete mLastBlockFile;
            mLastBlockFile = NULL;
        }

        unsigned int fileID = pHeight / 100;
        unsigned int offset = pHeight - (fileID * 100);

        if(fileID > mLastFileID)
            return false;

        // Remove block files over new file height
        for(unsigned int i=fileID+1;i<=mLastFileID;++i)
        {
            BlockFile::lock(i);
            if(!BlockFile::remove(i))
            {
                BlockFile::unlock(i);
                return false;
            }
            BlockFile::unlock(i);
        }

        // Remove any blocks necessary from last block file
        mLastFileID = fileID;
        BlockFile::lock(mLastFileID);
        mLastBlockFile = new BlockFile(mLastFileID);
        if(!mLastBlockFile->removeBlocksAbove(offset))
        {
            BlockFile::unlock(mLastFileID);
            return false;
        }
        BlockFile::unlock(mLastFileID);
        return true;
    }

    bool Chain::revert(int pHeight)
    {
        if(height() == pHeight)
            return true;

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Reverting from height %d to height %d", height(), pHeight);

        Block block;
        while(height() >= pHeight)
        {
            if(!mInfo.spvMode)
            {
                if(!getBlock(height(), block))
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to get block at height %d to revert", height());
                    return false;
                }

                if(height() == pHeight)
                {
                    mLastBlockHash = block.hash;
                    break;
                }

                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                  "Reverting block at height %d : %s", height(), block.hash.hex().text());

                if(mMonitor != NULL)
                    mMonitor->revertBlock(block.hash, height());

                if(!mOutputs.revert(block.transactions, height()))
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to revert outputs from block at height %d to revert", height());
                    return false;
                }

                mMemPool.revert(block.transactions);

                mAddresses.remove(block.transactions, height());
            }

            // Remove hash
            BlockSet &blockSet = mBlockLookup[block.hash.lookup16()];
            blockSet.lock();
            blockSet.remove(block.hash);
#ifdef LOW_MEM
            mLastBlockHashes.erase(mLastBlockHashes.end() - 1);
#else
            mBlockHashes.erase(mBlockHashes.end() - 1);
#endif
            blockSet.unlock();
            --mNextBlockHeight;
        }

        mForks.revert(mBlockStats, pHeight);
        mBlockStats.revert(pHeight);

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
          "New last block hash : %s", lastBlockHash().hex().text());

        // Remove blocks from block files
        return revertBlockFileHeight(height());
    }

    void Chain::process()
    {
#ifdef PROFILER_ON
        NextCash::Profiler outputsProfiler("Chain Process");
#endif
        if(mStop)
            return;

        mPendingLock.readLock();
        if(mPendingBlocks.size() == 0)
        {
            // Expire pending headers
            for(std::list<PendingHeaderData *>::iterator pendingHeader=mPendingHeaders.begin();pendingHeader!=mPendingHeaders.end();)
            {
                if(getTime() - (*pendingHeader)->updateTime > 120)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Expiring pending header : %s", (*pendingHeader)->hash.hex().text());
                    delete *pendingHeader;
                    pendingHeader = mPendingHeaders.erase(pendingHeader);
                }
                else
                    ++pendingHeader;
            }

            // No pending blocks or headers
            mPendingLock.readUnlock();
            BlockFile::lock(mLastFileID);
            if(mLastBlockFile != NULL)
                mLastBlockFile->updateCRC();
            BlockFile::unlock(mLastFileID);
            mForks.save();
            return;
        }

        mPendingLock.readUnlock();

        if(mInfo.spvMode)
            return;

        // Check if first pending header is actually a full block and process it
        PendingBlockData *nextPending = mPendingBlocks.front();
        if(!nextPending->isFull()) // Next pending block is not full yet
        {
            BlockFile::lock(mLastFileID);
            if(mLastBlockFile != NULL)
                mLastBlockFile->updateCRC();
            BlockFile::unlock(mLastFileID);
            mForks.save();
            return;
        }

        // Check this front block and add it to the chain
        if(processBlock(nextPending->block))
        {
            mPendingLock.writeLock("Process");

            if(!mIsInSync && mAnnouncedAdded && getTime() - nextPending->block->time < 600)
            {
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Chain is in sync");
                mIsInSync = true;
            }

            mPendingSize -= nextPending->block->size();
            mPendingBlockCount--;

            if(isInSync())
            {
                mBlocksToAnnounce.push_back(nextPending->block->hash);
                if(mAnnounceBlock == NULL)
                    mAnnounceBlock = nextPending->block;
                nextPending->block = NULL;
            }

            // Delete block
            delete nextPending;

            // Remove from pending
            mPendingBlocks.erase(mPendingBlocks.begin());
            if(mPendingBlocks.size() == 0)
                mLastPendingHash.clear();
            if(mLastFullPendingOffset > 0)
                --mLastFullPendingOffset;

            mPendingLock.writeUnlock();
        }
        else
        {
            BlockFile::lock(mLastFileID);
            if(mLastBlockFile != NULL)
            {
                delete mLastBlockFile;
                mLastBlockFile = NULL;
            }
            BlockFile::unlock(mLastFileID);

            // if(nextPending->block->size() > 1000000)
            // {
                // // Stop daemon
                // NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  // "Stopping daemon because this is currently unrecoverable");
                // Daemon::instance().requestStop();
                // mStop = true;
            // }
            // else
            // {
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Clearing all pending blocks/headers");

                // Clear pending blocks since they assumed this block was good
                mPendingLock.writeLock("Clear Pending");
                mBlackListedNodeIDs.push_back(nextPending->requestingNode);
                // Add hash to blacklist. So it isn't downloaded again.
                addBlackListedBlock(nextPending->block->hash);
                for(std::list<PendingBlockData *>::iterator pending=mPendingBlocks.begin();pending!=mPendingBlocks.end();++pending)
                    delete *pending;
                mPendingBlocks.clear();
                mLastPendingHash.clear();
                mLastFullPendingOffset = 0;
                mPendingSize = 0;
                mPendingBlockCount = 0;
                mPendingLock.writeUnlock();
                mPendingAccumulatedWork = accumulatedWork();
            // }

            checkBranches(); // Possibly switch to a branch that is valid
        }
    }

    bool Chain::getBlockHashes(NextCash::HashList &pHashes, const NextCash::Hash &pStartingHash, unsigned int pCount)
    {
        int hashHeight;
#ifdef LOW_MEM
        NextCash::Hash hash;
#endif

        pHashes.clear();

        if(pStartingHash.isEmpty())
            hashHeight = 0;
        else
            hashHeight = blockHeight(pStartingHash);

        if(hashHeight == -1)
            return false;

        while(pHashes.size() < pCount)
        {
#ifdef LOW_MEM
            if(!getBlockHash(hashHeight, hash))
                break;
            pHashes.push_back(hash);
#else
            if(hashHeight >= mBlockHashes.size())
                break;
            pHashes.push_back(mBlockHashes[hashHeight]);
#endif
            ++hashHeight;
        }

        return pHashes.size() > 0;
    }

    bool Chain::getReverseBlockHashes(NextCash::HashList &pHashes, unsigned int pCount)
    {
        pHashes.clear();
        mProcessMutex.lock();
#ifdef LOW_MEM
        unsigned int hashHeight = (unsigned int)height();
        NextCash::Hash hash;
        while(pHashes.size() < pCount)
        {
            if(!getBlockHash(hashHeight, hash))
                break;
            pHashes.push_back(hash);
            hashHeight -= 500;
        }
#else
        int height = mBlockHashes.size();
        for(NextCash::HashList::reverse_iterator hash=mBlockHashes.rbegin();
          hash!=mBlockHashes.rend() && pHashes.size() < pCount && height > 0;hash+=500,height-=500)
            pHashes.push_back(*hash);
#endif
        mProcessMutex.unlock();
        return true;
    }

    bool Chain::getBlockHeaders(BlockList &pBlockHeaders, const NextCash::Hash &pStartingHash, const NextCash::Hash &pStoppingHash,
      unsigned int pCount)
    {
        BlockFile *blockFile;
        NextCash::Hash hash = pStartingHash;
        unsigned int fileID = blockFileID(hash);
        bool found = false;
        unsigned int previousCount;

        pBlockHeaders.clear();

        if(fileID == INVALID_FILE_ID)
            return false; // hash not found

        while(pBlockHeaders.size() < pCount)
        {
            BlockFile::lock(fileID);
            if(fileID == mLastFileID && mLastBlockFile != NULL)
                blockFile = mLastBlockFile;
            else
                blockFile = new BlockFile(fileID);

            previousCount = pBlockHeaders.size();

            if(!blockFile->isValid() || !blockFile->readBlockHeaders(pBlockHeaders, hash, pStoppingHash, pCount))
            {
                if(blockFile != mLastBlockFile)
                    delete blockFile;
                BlockFile::unlock(fileID);
                break;
            }

            if(blockFile != mLastBlockFile)
                delete blockFile;
            BlockFile::unlock(fileID);

            found = true;
            if(previousCount == pBlockHeaders.size() || // No more headers added from this block file
              (pBlockHeaders.size() > 0 && pBlockHeaders.back()->hash == pStoppingHash)) // Stop hash found
                break;

            hash.clear();
            if(++fileID > mLastFileID)
                break;
        }

        return found;
    }

    bool Chain::getBlockHash(unsigned int pHeight, NextCash::Hash &pHash)
    {
        if(pHeight > height())
            return false;
#ifdef LOW_MEM
        unsigned int blocksFromTop = height() - pHeight;
        if(blocksFromTop < mLastBlockHashes.size())
            pHash = mLastBlockHashes[mLastBlockHashes.size() - blocksFromTop - 1];
        else
        {
            // Get hash from block file
            unsigned int fileID = pHeight / 100;
            unsigned int offset = pHeight - (fileID * 100);

            if(fileID > mLastFileID)
                return false;

            BlockFile *blockFile;

            BlockFile::lock(fileID);
            if(fileID == mLastFileID && mLastBlockFile != NULL)
                blockFile = mLastBlockFile;
            else
                blockFile = new BlockFile(fileID);

            bool success = blockFile->isValid() && blockFile->readHash(offset, pHash);

            if(blockFile != mLastBlockFile)
                delete blockFile;
            BlockFile::unlock(fileID);
            return success;
        }
#else
        if(pHeight >= mBlockHashes.size())
        {
            pHash.clear();
            return false;
        }

        pHash = mBlockHashes[pHeight];
#endif
        return true;
    }

    bool Chain::getBlock(unsigned int pHeight, Block &pBlock)
    {
        unsigned int fileID = pHeight / 100;
        unsigned int offset = pHeight - (fileID * 100);

        if(fileID > mLastFileID)
            return false;

        BlockFile *blockFile;

        BlockFile::lock(fileID);
        if(fileID == mLastFileID && mLastBlockFile != NULL)
            blockFile = mLastBlockFile;
        else
            blockFile = new BlockFile(fileID, false);

        bool success = blockFile->isValid() && blockFile->readBlock(offset, pBlock, true);

        if(blockFile != mLastBlockFile)
            delete blockFile;
        BlockFile::unlock(fileID);
        return success;
    }

    bool Chain::getBlock(const NextCash::Hash &pHash, Block &pBlock)
    {
        int thisBlockHeight = blockHeight(pHash);
        if(thisBlockHeight == -1)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Get block failed. Hash not found : %s", pHash.hex().text());
            return false;
        }
        return getBlock(thisBlockHeight, pBlock);
    }

    bool Chain::getHeader(unsigned int pHeight, Block &pBlockHeader)
    {
        unsigned int fileID = pHeight / 100;
        unsigned int offset = pHeight - (fileID * 100);

        if(fileID > mLastFileID)
            return false;

        BlockFile *blockFile;

        BlockFile::lock(fileID);
        if(fileID == mLastFileID && mLastBlockFile != NULL)
            blockFile = mLastBlockFile;
        else
            blockFile = new BlockFile(fileID);

        bool success = blockFile->isValid() && blockFile->readBlock(offset, pBlockHeader, false);

        if(blockFile != mLastBlockFile)
            delete blockFile;
        BlockFile::unlock(fileID);
        return success;
    }

    bool Chain::getHeader(const NextCash::Hash &pHash, Block &pBlockHeader)
    {
        int thisBlockHeight = blockHeight(pHash);
        if(thisBlockHeight == -1)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Get header failed. Hash not found : %s", pHash.hex().text());
            return false;
        }
        return getHeader(thisBlockHeight, pBlockHeader);
    }

    bool Chain::updateOutputs()
    {
        int currentHeight = mOutputs.height();
        if(currentHeight == height())
            return true;

        if(currentHeight > height())
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Outputs height %d above block height %d", mOutputs.height(), height());
            return false;
        }

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Updating unspent transaction outputs from block height %d to %d", currentHeight, height());

        ++currentHeight;

        unsigned int fileID = currentHeight / 100;
        unsigned int offset = currentHeight - (fileID * 100);

        if(fileID > mLastFileID)
            return false;

        BlockFile *blockFile = NULL;
        Block block;
        Forks emptyForks;
        int32_t lastPurgeTime = getTime();

        while(currentHeight <= height() && !mStop)
        {
            BlockFile::lock(fileID);
            blockFile = new BlockFile(fileID);
            if(!blockFile->isValid())
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Block file %08x is invalid", fileID);
                delete blockFile;
                BlockFile::unlock(fileID);
                return false;
            }

            while(currentHeight <= height() && offset < BlockFile::MAX_BLOCKS)
            {
                if(blockFile->readBlock(offset, block, true))
                {
                    // NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      // "Processing block %d : %s", currentHeight, block.hash.hex().text());

                    mBlockProcessStartTime = getTime();

                    if(block.updateOutputs(mOutputs, currentHeight))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                          "Processed outputs in block %d (%d trans) (%d KiB) (%d s)", currentHeight, block.transactionCount,
                          block.size() / 1024, getTime() - mBlockProcessStartTime);

                        mOutputs.commit(block.transactions, currentHeight);
                    }
                    else
                    {
                        mOutputs.revert(block.transactions, currentHeight);
                        mOutputs.save();
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Failed to process block at height %d. At offset %d in block file %08x : %s",
                          currentHeight, offset, fileID, block.hash.hex().text());
                        delete blockFile;
                        BlockFile::unlock(fileID);
                        return false;
                    }
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to read block %d from block file %08x", offset, fileID);
                    delete blockFile;
                    BlockFile::unlock(fileID);
                    mOutputs.save();
                    return false;
                }

                ++currentHeight;
                ++offset;
            }

            delete blockFile;
            BlockFile::unlock(fileID);

            if(getTime() - lastPurgeTime > 10)
            {
                if(mOutputs.needsPurge() && !mOutputs.save())
                {
                    delete blockFile;
                    BlockFile::unlock(fileID);
                    return false;
                }
                lastPurgeTime = getTime();
            }

            offset = 0;
            fileID++;
        }

        mOutputs.save();
        return mOutputs.height() == height();
    }

    bool Chain::updateAddresses()
    {
        int currentHeight = mAddresses.height();
        if(currentHeight == height())
            return true;

        if(currentHeight > height())
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Addresses height %d above block height %d", mAddresses.height(), height());
            return false;
        }

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Updating transaction addresses from block height %d to %d", currentHeight, height());

        ++currentHeight;

        unsigned int fileID = currentHeight / 100;
        unsigned int offset = currentHeight - (fileID * 100);

        if(fileID > mLastFileID)
            return false;

        BlockFile *blockFile = NULL;
        Block block;
        Forks emptyForks;
        int32_t lastPurgeTime = getTime();
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Chain Update Addresses", false);
#endif

        while(currentHeight <= height() && !mStop)
        {
            BlockFile::lock(fileID);
            blockFile = new BlockFile(fileID);
            if(!blockFile->isValid())
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Block file %08x is invalid", fileID);
                delete blockFile;
                BlockFile::unlock(fileID);
                return false;
            }

            while(currentHeight <= height() && offset < BlockFile::MAX_BLOCKS)
            {
#ifdef PROFILER_ON
                profiler.start();
#endif
                if(blockFile->readBlock(offset, block, true))
                {
                    // NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      // "Processing block %d : %s", currentHeight, block.hash.hex().text());

                    mBlockProcessStartTime = getTime();

                    mAddresses.add(block.transactions, currentHeight);

                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Processed addresses in block %d (%d trans) (%d KiB) (%d s)", currentHeight, block.transactionCount,
                      block.size() / 1024, getTime() - mBlockProcessStartTime);
                }
                else
                {
#ifdef PROFILER_ON
                    profiler.stop();
#endif
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to read block %d from block file %08x", offset, fileID);
                    delete blockFile;
                    BlockFile::unlock(fileID);
                    mAddresses.save();
                    return false;
                }

#ifdef PROFILER_ON
                profiler.stop();
#endif
                ++currentHeight;
                ++offset;
            }

            delete blockFile;
            BlockFile::unlock(fileID);

            if(getTime() - lastPurgeTime > 10)
            {
                if(mAddresses.needsPurge() && !mAddresses.save())
                {
                    delete blockFile;
                    BlockFile::unlock(fileID);
                    return false;
                }
                lastPurgeTime = getTime();
            }

            offset = 0;
            fileID++;
        }

        mAddresses.save();
        return mAddresses.height() == height();
    }

    bool Chain::save()
    {
        if(mLastBlockFile != NULL)
        {
            BlockFile::lock(mLastFileID);
            // Check again just to make sure it wasn't deleted while waiting for the lock
            if(mLastBlockFile != NULL)
                delete mLastBlockFile;
            BlockFile::unlock(mLastFileID);
        }
        mLastBlockFile = NULL;
        bool success = true;
        if(!mBlockStats.save())
            success = false;
        if(!mForks.save())
            success = false;
        if(!savePending())
            success = false;
        if(!Info::instance().spvMode)
        {
            if(!mOutputs.save())
                success = false;
            if(!mAddresses.save())
                success = false;
        }
        return success;
    }

    // Load block info from files
    bool Chain::load(bool pPreCacheOutputs)
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Indexing block hashes");

        BlockFile *blockFile = NULL;
        NextCash::String filePathName;
        NextCash::HashList hashes;
        bool success = true;
        NextCash::Hash emptyHash;
        unsigned int fileID;

        mProcessMutex.lock();
        mStop = false;

        for(fileID=0;;fileID++)
        {
            filePathName = BlockFile::fileName(fileID);
            if (!NextCash::fileExists(filePathName))
                break;
        }

        mLastFileID = INVALID_FILE_ID;
        mNextBlockHeight = 0;
        mLastBlockHash.clear();

#ifndef LOW_MEM
        mBlockHashes.clear();
        mBlockHashes.reserve(fileID * BlockFile::MAX_BLOCKS);
#endif

        for(fileID=0;;fileID++)
        {
            BlockFile::lock(fileID);
            filePathName = BlockFile::fileName(fileID);
            if(NextCash::fileExists(filePathName))
            {
                blockFile = new BlockFile(fileID, false);
                if(!blockFile->isValid())
                {
                    delete blockFile;
                    BlockFile::unlock(fileID);
                    success = false;
                    break;
                }

                if(!blockFile->readBlockHashes(hashes))
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to read hashes from block file %08x", fileID);
                    delete blockFile;
                    BlockFile::unlock(fileID);
                    success = false;
                    break;
                }
                delete blockFile;
                BlockFile::unlock(fileID);

                mLastFileID = fileID;
                for(NextCash::HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
                {
                    BlockSet &blockSet = mBlockLookup[hash->lookup16()];
                    blockSet.lock();
#ifndef LOW_MEM
                    mBlockHashes.push_back(*hash);
#endif
                    blockSet.push_back(new BlockInfo(*hash, fileID, mNextBlockHeight));
                    blockSet.unlock();
                    mNextBlockHeight++;
                }
            }
            else
            {
                BlockFile::unlock(fileID);
                break;
            }
        }

#ifdef LOW_MEM
        mLastBlockHashes.clear();
        mLastBlockHashes.reserve(RECENT_BLOCK_COUNT);

        // Get top block hashes
        if(height() > 0)
        {
            unsigned int startHeight;
            if(height() > RECENT_BLOCK_COUNT)
                startHeight = (unsigned int) height() - RECENT_BLOCK_COUNT;
            else
                startHeight = 0;

            fileID = startHeight / 100;
            while(true)
            {
                BlockFile::lock(fileID);
                filePathName = BlockFile::fileName(fileID);
                if(NextCash::fileExists(filePathName))
                {
                    blockFile = new BlockFile(fileID, false);
                    if (!blockFile->isValid())
                    {
                        delete blockFile;
                        BlockFile::unlock(fileID);
                        break;
                    }

                    if(!blockFile->readBlockHashes(hashes))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Failed to read hashes from block file %08x", fileID);
                        delete blockFile;
                        BlockFile::unlock(fileID);
                        break;
                    }

                    for(NextCash::HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
                        mLastBlockHashes.push_back(*hash);

                    while(mLastBlockHashes.size() > RECENT_BLOCK_COUNT)
                        mLastBlockHashes.erase(mLastBlockHashes.begin());
                }
                else
                {
                    BlockFile::unlock(fileID);
                    break;
                }
                BlockFile::unlock(fileID);
                ++fileID;
            }
        }
#endif

        if(success)
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Indexed block hashes to height %d", mNextBlockHeight - 1);

        if(success && !mBlockStats.load())
            success = false;

        if(success)
        {
            if(mBlockStats.height() > mNextBlockHeight - 1)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Reverting block statistics to height of %d", mNextBlockHeight - 1);
                mBlockStats.revert(mNextBlockHeight - 1);
            }

            if(mBlockStats.height() < mNextBlockHeight - 1)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Updating block statistics to height %d", mNextBlockHeight - 1);

                fileID = (mBlockStats.height() + 1) / BlockFile::MAX_BLOCKS;
                unsigned int offset = (mBlockStats.height() + 1) - (fileID * BlockFile::MAX_BLOCKS);
                int32_t lastReport = getTime();
                for(;fileID<=mLastFileID;++fileID)
                {
                    if(getTime() - lastReport > 10)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                          "Block statistics load is %2d%% Complete", (int)(((float)fileID / (float)mLastFileID) * 100.0f));
                        lastReport = getTime();
                    }

                    BlockFile::lock(fileID);
                    blockFile = new BlockFile(fileID, false);

                    if(!blockFile->isValid())
                        success = false;

                    if(success && !blockFile->readStats(mBlockStats, offset))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Failed to read stats from block file %08x", fileID);
                        success = false;
                    }

                    delete blockFile;
                    BlockFile::unlock(fileID);
                    offset = 0;

                    if(!success || mStop)
                        break;
                }

                if(success)
                    mBlockStats.save();
            }
        }

        if(success)
        {
            if(mBlockStats.height() > 0)
            {
                mTargetBits = mBlockStats.targetBits(mBlockStats.height());
                mPendingAccumulatedWork = accumulatedWork();
            }
            else
            {
                mTargetBits = mMaxTargetBits;
                mPendingAccumulatedWork.zeroize();
            }
        }

        if(mStop)
        {
            mProcessMutex.unlock();
            return false;
        }

        success = success && mForks.load();

        if(success)
        {
            if(mForks.height() > mNextBlockHeight - 1)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Reverting forks to height of %d", mNextBlockHeight - 1);
                mForks.revert(mBlockStats, mNextBlockHeight - 1);
            }

            if(mForks.height() < mNextBlockHeight - 1)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Updating forks to height %d", mNextBlockHeight - 1);

                int32_t lastReport = getTime();
                for(int i=mForks.height()+1;i<mNextBlockHeight;++i)
                {
                    if(getTime() - lastReport > 10)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                          "Forks load is %2d%% Complete", (int)(((float)i / (float)mNextBlockHeight) * 100.0f));
                        lastReport = getTime();
                    }

                    if(mStop)
                        break;

                    mForks.process(mBlockStats, i);
                }
            }

            mForks.save();
        }

        mProcessMutex.unlock();

        if(mStop || !success)
            return false;

        Info &info = Info::instance();

        if(!info.spvMode)
        {
            // Load transaction addresses
            success = success && mAddresses.load(info.path(), 0); // 10485760); // 10 MiB

            // Update transaction addresses if they aren't up to current chain block height
            success = success && updateAddresses();

            if(mStop || !success)
                return false;

            // Load transaction outputs
            success = success && mOutputs.load(info.path(), info.outputsThreshold);

            // Update transaction outputs if they aren't up to current chain block height
            success = success && updateOutputs();
        }

        if(success)
        {
            if(mNextBlockHeight == 0)
            {
                // Add genesis block
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Creating genesis block");
                Block *genesis = Block::genesis(mMaxTargetBits);
                if(info.spvMode)
                {
                    success = processHeader(genesis);

                    // Add header to chain
                    if(success)
                        success = writeBlock(genesis);

                    if(success)
                    {
                        addBlockHash(genesis->hash);

                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                          "Added genesis header to chain at height %d : %s",
                          mNextBlockHeight - 1, genesis->hash.hex().text());
                    }
                }
                else
                    success = processBlock(genesis);
                delete genesis;
                if(!success)
                    return false;
            }
        }

        return success && loadPending();
    }

    bool Chain::validate(bool pRebuild)
    {
        BlockFile *blockFile;
        NextCash::Hash previousHash(32), merkleHash;
        Block block;
        unsigned int i, height = 0;
        bool useTestMinDifficulty;
        NextCash::String filePathName;

        for(unsigned int fileID=0;!mStop;fileID++)
        {
            filePathName = BlockFile::fileName(fileID);
            if(!NextCash::fileExists(filePathName))
                break;

            BlockFile::lock(fileID);
            blockFile = new BlockFile(fileID);

            if(!blockFile->isValid())
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Block file %08x isn't valid", fileID);
                break;
            }

            for(i=0;i<BlockFile::MAX_BLOCKS;i++)
            {
                if(blockFile->readBlock(i, block, true))
                {
                    if(block.previousHash != previousHash)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Block %010d previous hash doesn't match", height);
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Included Previous Hash : %s", block.previousHash.hex().text());
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Previous Block's Hash  : %s", previousHash.hex().text());
                        return false;
                    }

                    block.calculateMerkleHash(merkleHash);
                    if(block.merkleHash != merkleHash)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Block %010d has invalid merkle hash", height);
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Included Merkle Hash : %s", block.merkleHash.hex().text());
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Correct Merkle Hash  : %s", merkleHash.hex().text());
                        return false;
                    }

                    useTestMinDifficulty = network() == TESTNET && block.time - mBlockStats.time(mBlockStats.height() - 1) > 1200;
                    mBlockStats.add(block.version, block.time, block.targetBits);
                    updateTargetBits();
                    mForks.process(mBlockStats, height);
                    if(mTargetBits != block.targetBits)
                    {
                        // If on TestNet and 20 minutes since last block
                        if(useTestMinDifficulty && block.targetBits == 0x1d00ffff)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                              "Using TestNet special minimum difficulty rule 1d00ffff for block %d", height);
                        }
                        else
                        {
                            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                              "Block %010d target bits don't match chain's current target bits : chain %08x != block %08x",
                              height, mTargetBits, block.targetBits);
                            mForks.revert(mBlockStats, height);
                            mBlockStats.revert(height);
                            return false;
                        }
                    }

                    if(!block.process(mOutputs, height, mBlockStats, mForks))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Block %010d failed to process", height);
                        return false;
                    }

                    if(!mOutputs.commit(block.transactions, height))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Block %010d unspent transaction outputs commit failed", height);
                        return false;
                    }

                    if(!mAddresses.add(block.transactions, height))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Block %010d addresses update failed", height);
                        return false;
                    }

                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Block %010d is valid : %6d trans, %d KiB", height, block.transactions.size(), block.size() / 1024);
                    //block.print();

                    previousHash = block.hash;
                    height++;
                }
                else // End of chain
                    break;
            }

            delete blockFile;
            BlockFile::unlock(fileID);
        }

        if(pRebuild)
        {
            if(!mInfo.spvMode)
            {
                mOutputs.save();
                mAddresses.save();
            }
            if(!mForks.save())
                return false;
        }

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Transactions : %d", mOutputs.size());
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Validated block height of %d", height);
        return true;
    }

    bool Chain::test()
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "------------- Starting Block Chain Tests -------------");

        bool success = true;
        NextCash::Buffer checkData;
        NextCash::Hash checkHash(32);
        Block *genesis = Block::genesis(0x1d00ffff);

        //genesis->print(NextCash::Log::INFO);

        //NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Current coin base amount : %f",
        // (double)bitcoins(Block::coinBaseAmount(485000)));

        /***********************************************************************************************
         * Genesis block merkle hash
         ***********************************************************************************************/
        checkData.clear();
        checkData.writeHex("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a");
        checkHash.read(&checkData);

        if(genesis->merkleHash == checkHash)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed genesis block merkle hash");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed genesis block merkle hash");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Block merkle hash   : %s", genesis->merkleHash.hex().text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct merkle hash : %s", checkHash.hex().text());
            success = false;
        }

        /***********************************************************************************************
         * Genesis block hash
         ***********************************************************************************************/
        //Big Endian checkData.writeHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        if(network() == TESTNET)
            checkData.writeHex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000");
        else
            checkData.writeHex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000");
        checkHash.read(&checkData);

        if(genesis->hash == checkHash)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed genesis block hash");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed genesis block hash");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Block hash   : %s", genesis->hash.hex().text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct hash : %s", checkHash.hex().text());
            success = false;
        }

        /***********************************************************************************************
         * Genesis block read hash
         ***********************************************************************************************/
        //Big Endian checkData.writeHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        checkData.clear();
        if(network() == TESTNET)
            checkData.writeHex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000");
        else
            checkData.writeHex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000");
        checkHash.read(&checkData);
        Block readGenesisBlock;
        NextCash::Buffer blockBuffer;
        genesis->write(&blockBuffer, true, true);
        readGenesisBlock.read(&blockBuffer, true, true, true);

        if(readGenesisBlock.hash == checkHash)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed genesis block read hash");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed genesis block read hash");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Block hash   : %s", readGenesisBlock.hash.hex().text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct hash : %s", checkHash.hex().text());
            success = false;
        }

        /***********************************************************************************************
         * Genesis block raw
         ***********************************************************************************************/
        NextCash::Buffer data;
        genesis->write(&data, true, true);

        checkData.clear();
        if(network() == TESTNET)
        {
            checkData.writeHex("01000000000000000000000000000000"); //   ................
            checkData.writeHex("00000000000000000000000000000000"); //   ................
            checkData.writeHex("000000003BA3EDFD7A7B12B27AC72C3E"); //   ....;£íýz{.²zÇ,>
            checkData.writeHex("67768F617FC81BC3888A51323A9FB8AA"); //   gv.a.È.ÃˆŠQ2:Ÿ¸ª
            checkData.writeHex("4b1e5e4adae5494dffff001d1aa4ae18"); //   <CHANGED>
            checkData.writeHex("01010000000100000000000000000000"); //   ................
            checkData.writeHex("00000000000000000000000000000000"); //   ................
            checkData.writeHex("000000000000FFFFFFFF4D04FFFF001D"); //   ......ÿÿÿÿM.ÿÿ..
            checkData.writeHex("0104455468652054696D65732030332F"); //   ..EThe Times 03/
            checkData.writeHex("4A616E2F32303039204368616E63656C"); //   Jan/2009 Chancel
            checkData.writeHex("6C6F72206F6E206272696E6B206F6620"); //   lor on brink of
            checkData.writeHex("7365636F6E64206261696C6F75742066"); //   second bailout f
            checkData.writeHex("6F722062616E6B73FFFFFFFF0100F205"); //   or banksÿÿÿÿ..ò.
            checkData.writeHex("2A01000000434104678AFDB0FE554827"); //   *....CA.gŠý°þUH'
            checkData.writeHex("1967F1A67130B7105CD6A828E03909A6"); //   .gñ¦q0·.\Ö¨(à9.¦
            checkData.writeHex("7962E0EA1F61DEB649F6BC3F4CEF38C4"); //   ybàê.aÞ¶Iö¼?Lï8Ä
            checkData.writeHex("F35504E51EC112DE5C384DF7BA0B8D57"); //   óU.å.Á.Þ\8M÷º..W
            checkData.writeHex("8A4C702B6BF11D5FAC00000000");       //   ŠLp+kñ._¬....
        }
        else
        {
            checkData.writeHex("01000000000000000000000000000000"); //   ................
            checkData.writeHex("00000000000000000000000000000000"); //   ................
            checkData.writeHex("000000003BA3EDFD7A7B12B27AC72C3E"); //   ....;£íýz{.²zÇ,>
            checkData.writeHex("67768F617FC81BC3888A51323A9FB8AA"); //   gv.a.È.ÃˆŠQ2:Ÿ¸ª
            checkData.writeHex("4B1E5E4A29AB5F49FFFF001D1DAC2B7C"); //   K.^J)«_Iÿÿ...¬+|
            checkData.writeHex("01010000000100000000000000000000"); //   ................
            checkData.writeHex("00000000000000000000000000000000"); //   ................
            checkData.writeHex("000000000000FFFFFFFF4D04FFFF001D"); //   ......ÿÿÿÿM.ÿÿ..
            checkData.writeHex("0104455468652054696D65732030332F"); //   ..EThe Times 03/
            checkData.writeHex("4A616E2F32303039204368616E63656C"); //   Jan/2009 Chancel
            checkData.writeHex("6C6F72206F6E206272696E6B206F6620"); //   lor on brink of
            checkData.writeHex("7365636F6E64206261696C6F75742066"); //   second bailout f
            checkData.writeHex("6F722062616E6B73FFFFFFFF0100F205"); //   or banksÿÿÿÿ..ò.
            checkData.writeHex("2A01000000434104678AFDB0FE554827"); //   *....CA.gŠý°þUH'
            checkData.writeHex("1967F1A67130B7105CD6A828E03909A6"); //   .gñ¦q0·.\Ö¨(à9.¦
            checkData.writeHex("7962E0EA1F61DEB649F6BC3F4CEF38C4"); //   ybàê.aÞ¶Iö¼?Lï8Ä
            checkData.writeHex("F35504E51EC112DE5C384DF7BA0B8D57"); //   óU.å.Á.Þ\8M÷º..W
            checkData.writeHex("8A4C702B6BF11D5FAC00000000");       //   ŠLp+kñ._¬....
        }

        if(checkData.length() != data.length())
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed genesis block raw data size : actual %d != correct %d", data.length(), checkData.length());
            success = false;
        }
        else
        {
            // Check in 16 byte sections
            uint8_t actualRaw[16], checkRaw[16];
            NextCash::String actualHex, checkHex;
            bool matches = true;
            for(unsigned int lineNo=1;checkData.remaining() > 0;lineNo++)
            {
                data.read(actualRaw, 16);
                checkData.read(checkRaw, 16);

                if(std::memcmp(actualRaw, checkRaw, 16) != 0)
                {
                    matches = false;
                    actualHex.writeHex(actualRaw, 16);
                    checkHex.writeHex(checkRaw, 16);

                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed genesis block raw data line %d", lineNo);
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Actual  : %s", actualHex.text());
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct : %s", checkHex.text());
                    success = false;
                }
            }

            if(matches)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed genesis block raw data");
        }

        /***********************************************************************************************
         * Block read
         ***********************************************************************************************/
        Block readBlock;
        NextCash::FileInputStream readFile("tests/06128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000.pending_block");
        NextCash::removeDirectory("chain_test");
        Info::instance().setPath("./chain_test");
        TransactionOutputPool outputs;
        BlockStats blockStats;
        Forks softForks;

        outputs.load(Info::instance().path(), Info::instance().outputsThreshold);

        if(!readBlock.read(&readFile, true, true, true))
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed to read block");
            success = false;
        }
        else
        {
            //readBlock.print(NextCash::Log::INFO);

            /***********************************************************************************************
             * Block read hash
             ***********************************************************************************************/
            checkData.clear();
            checkData.writeHex("06128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000");
            checkHash.read(&checkData);

            if(readBlock.hash == checkHash)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed read block hash");
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed read block hash");
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Block hash   : %s", readBlock.hash.hex().text());
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct hash : %s", checkHash.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Block read previous hash
             ***********************************************************************************************/
            checkData.clear();
            checkData.writeHex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000");
            checkHash.read(&checkData);

            if(readBlock.previousHash == checkHash)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed read block previous hash");
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed read block previous hash");
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Block previous hash   : %s", readBlock.previousHash.hex().text());
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct previous hash : %s", checkHash.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Block read merkle hash
             ***********************************************************************************************/
            readBlock.calculateMerkleHash(checkHash);

            if(readBlock.merkleHash == checkHash)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed read block merkle hash");
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed read block merkle hash");
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Block merkle hash      : %s", readBlock.merkleHash.hex().text());
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Calculated merkle hash : %s", checkHash.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Block read process
             ***********************************************************************************************/
            if(readBlock.process(outputs, 0, blockStats, softForks))
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed read block process");
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed read block process");
                success = false;
            }
        }

        delete genesis;
        return success;
    }

    void Chain::tempTest()
    {
        // setNetwork(MAINNET);
        // Info::instance().setPath("/var/bitcoin/mainnet");
        // Chain chain;

        // chain.load();

        // Info::instance().setPath("/var/bitcoin/mainnet");
        // TransactionOutputPool outputs;

        // outputs.load(Info::instance().path(), Info::instance().outputsCacheAge, true);

        // outputs.bulkRevert(506570, true);
        // outputs.save(Info::instance().path());

        // NextCash::FileInputStream file("00000000000000000343e9875012f2062554c8752929892c82a0c0743ac7dcfd");
        // Block block;

        // // BlockFile::readBlock(386340, block);

        // if(!block.read(&file, true, true, true))
        // {
            // NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed to read block");
            // return;
        // }

        // // block.print(NextCash::Log::VERBOSE, true);

        // if(chain.processBlock(&block))
            // NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed block");
        // else
            // NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed block");


        // NextCash::Hash hash("ffff5d1293ae9fa73bcd3aa9f4620e29f8a8f46d8e41a55767e12fa30592bc7e");
        // unsigned int index = 0;

        // // // // Load transactions from block
        // // // outputs.add(block.transactions, outputs.blockHeight() + 1, block.hash);

        // // // // Check for matching transaction in block
        // // // for(std::vector<Transaction *>::iterator tran=block.transactions.begin();tran!=block.transactions.end();++tran)
            // // // if((*tran)->hash == hash)
                // // // NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  // // // "Added transaction : %s", hash.hex().text());

        // TransactionReference *reference = outputs.findUnspent(hash, index);
        // Output output;
        // if(reference != NULL)
        // {
            // reference->print();

            // // if((int)reference->blockHeight == outputs.blockHeight())
            // // {
                // // for(std::vector<Transaction *>::iterator tran=block.transactions.begin();tran!=block.transactions.end();++tran)
                    // // if((*tran)->hash == reference->id)
                    // // {
                        // // unsigned int outputIndex = 0;
                        // // for(std::vector<Output *>::iterator item=(*tran)->outputs.begin();item!=(*tran)->outputs.end();++item)
                        // // {
                            // // if(outputIndex == index)
                            // // {
                                // // output = **item;
                                // // output.print();
                                // // break;
                            // // }
                            // // ++outputIndex;
                        // // }
                    // // }
            // // }
            // // else
            // // {
                // if(BlockFile::readOutput(reference, index, output))
                    // output.print();
                // else
                    // NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                      // "Failed to read output for transaction");
            // // }
        // }
        // else
            // NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              // "Failed to find transaction : %s", hash.hex().text());


        // block.print(NextCash::Log::INFO, false);






        // setNetwork(MAINNET);
        // Info::instance().setPath("/var/bitcoin/mainnet");
        // Chain chain;

        // chain.load(false, false);
        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME, "Height %d", chain.blockStats().height());

        // uint32_t time = chain.blockStats().getMedianPastTime(419436);
        // NextCash::String timeString;
        // timeString.writeFormattedTime(time);

        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME, "Median Time %d : %s", time, timeString.text());


        // chain.savePending();




        // NextCash::String filePathName = "/var/bitcoin/mainnet";
        // filePathName.pathAppend("outputs");
        // filePathName.pathAppend("height");
        // NextCash::FileOutputStream file(filePathName, true);
        // if(!file.isValid())
        // {
            // NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              // "Failed to open height file to save");
        // }

        // // Block Height
        // file.writeUnsignedInt(506581);
        // file.flush();




#ifdef PROFILER_ON
        NextCash::String profilerTime;
        profilerTime.writeFormattedTime(getTime(), "%Y%m%d.%H%M");
        NextCash::String profilerFileName = "profiler.";
        profilerFileName += profilerTime;
        profilerFileName += ".txt";
        NextCash::FileOutputStream profilerFile(profilerFileName, true);
        NextCash::ProfilerManager::write(&profilerFile);
#endif
    }
}
