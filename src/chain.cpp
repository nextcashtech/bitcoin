/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
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

#include <algorithm>

#define BITCOIN_CHAIN_LOG_NAME "Chain"
#define BLOCK_STATS_CACHE_SIZE 2500


namespace BitCoin
{
    NextCash::Hash Chain::sBTCForkBlockHash("00000000000000000019f112ec0a9982926f1258cdcc558dd7c3b7e5dc7fa148");

    Chain::Chain() : mInfo(Info::instance()), mPendingLock("Chain Pending"),
      mProcessMutex("Chain Process"), mHeadersLock("Chain Headers"), mBranchLock("Chain Branches")
    {
        mNextHeaderHeight = 0;
        mNextBlockHeight = 0;
        mPendingSize = 0;
        mPendingBlockCount = 0;
        mMaxTargetBits = 0x1d00ffff;
        mLastFullPendingOffset = 0;
        mStopRequested = false;
        mIsInSync = false;
        mWasInSync = false;
        mHeadersNeeded = true;
        mAnnounceBlock = NULL;
        mMonitor = NULL;
        mBlockStatHeight = 0;
        mMemPoolRequests = 0;

        if(mInfo.approvedHash.isEmpty())
            mApprovedBlockHeight = 0x00000000; // Not set
        else
            mApprovedBlockHeight = 0xffffffff; // Not found yet
    }

    Chain::~Chain()
    {
        mPendingLock.writeLock("Destroy");
        clearBlockStats();
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
            delete *pending;
        mBranchLock.lock();
        for(std::vector<Branch *>::iterator branch = mBranches.begin();
          branch != mBranches.end(); ++branch)
            delete *branch;
        mBranchLock.unlock();
        if(mAnnounceBlock != NULL)
            delete mAnnounceBlock;
        mPendingLock.writeUnlock();
    }

    Branch::~Branch()
    {
        for(std::list<PendingBlockData *>::iterator pending = pendingBlocks.begin();
          pending != pendingBlocks.end(); ++pending)
            delete *pending;
    }

    bool Chain::blockAvailable(const NextCash::Hash &pHash)
    {
        return hashHeight(pHash) < mNextBlockHeight;
    }

    bool Chain::headerAvailable(const NextCash::Hash &pHash)
    {
        return mHashLookup[pHash.lookup16()].contains(pHash);
    }

    unsigned int Chain::hashHeight(const NextCash::Hash &pHash)
    {
        unsigned int result = 0xffffffff;
        if(pHash.isEmpty())
            return result; // Empty hash means start from the beginning

        HashLookupSet &blockSet = mHashLookup[pHash.lookup16()];
        blockSet.lock();
        for(HashLookupSet::iterator i = blockSet.begin(); i != blockSet.end(); ++i)
            if(pHash == (*i)->hash)
            {
                result = (*i)->height;
                break;
            }
        blockSet.unlock();

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

    void Chain::addBlackListedHash(const NextCash::Hash &pHash)
    {
        if(!mBlackListHashes.contains(pHash))
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Added block to black list : %s", pHash.hex().text());
            // Keep list at 1024 or less
            if(mBlackListHashes.size() > 1024)
                mBlackListHashes.erase(mBlackListHashes.begin());
            mBlackListHashes.push_back(pHash);
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
            if(mAnnounceBlock != NULL && mAnnounceBlock->header.hash == hash)
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
        for(std::list<PendingBlockData *>::iterator pendingBlock = mPendingBlocks.begin();
          pendingBlock != mPendingBlocks.end(); ++pendingBlock)
            if((*pendingBlock)->requestingNode == 0 ||
              getTime() - (*pendingBlock)->requestedTime > 10)
            {
                result = true;
                break;
            }
        mPendingLock.readUnlock();
        return result;
    }

    bool Chain::headersNeeded()
    {
        if(mHeadersNeeded)
        {
            mHeadersNeeded = false;
            return true;
        }

        // Check for pending header
        bool result = false;
        mPendingLock.readLock();
        for(std::list<PendingHeaderData *>::iterator pendingHeader = mPendingHeaders.begin();
          pendingHeader != mPendingHeaders.end(); ++pendingHeader)
            if((*pendingHeader)->requestingNode == 0 ||
              getTime() - (*pendingHeader)->requestedTime > 2)
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
        mBranchLock.lock();
        for(std::vector<Branch *>::iterator branch = mBranches.begin(); branch != mBranches.end();
          ++branch)
        {
            // Loop through all pending blocks on the branch
            for(std::list<PendingBlockData *>::iterator pending = (*branch)->pendingBlocks.begin();
              pending != (*branch)->pendingBlocks.end(); ++pending)
                if((*pending)->block->header.hash == pHash)
                {
                    mBranchLock.unlock();
                    return true;
                }
        }
        mBranchLock.unlock();
        return false;
    }

    bool Chain::checkBranches()
    {
        NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME, "Checking branches");

        mHeadersLock.writeLock("Check Branches");
        mBranchLock.lock();
        if(mBranches.size() == 0)
        {
            mBranchLock.unlock();
            mHeadersLock.writeUnlock();
            return true;
        }

        // Check each branch to see if it has more "work" than the main chain
        Branch *longestBranch = NULL;
        unsigned int offset = 1;
        int diff;
        NextCash::Hash mainAccumulatedWork = accumulatedWork(headerHeight());
        for(std::vector<Branch *>::iterator branch = mBranches.begin(); branch != mBranches.end();)
        {
            diff = (*branch)->accumulatedWork.compare(mainAccumulatedWork);

            if(diff < 0)
            {
                if(headerHeight() > HISTORY_BRANCH_CHECKING &&
                  (*branch)->height + (*branch)->pendingBlocks.size() <
                  headerHeight() - HISTORY_BRANCH_CHECKING)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Dropping branch %d", offset);

                    // Drop branches that are HISTORY_BRANCH_CHECKING blocks behind the main chain
                    delete *branch;
                    branch = mBranches.erase(branch);
                    continue;
                }
            }
            else if(diff > 0 && (longestBranch == NULL ||
              (*branch)->accumulatedWork > longestBranch->accumulatedWork))
                longestBranch = *branch;

            ++branch;
            ++offset;
        }

        if(longestBranch == NULL)
        {
            mBranchLock.unlock();
            mHeadersLock.writeUnlock();
            return true;
        }

        // Swap the branch with the most "work" for the main chain.
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Activating branch at height %d (%d headers)", longestBranch->height,
          longestBranch->pendingBlocks.size());

        // Remove branch from branch list
        for(std::vector<Branch *>::iterator branch = mBranches.begin(); branch != mBranches.end();
          ++branch)
            if(*branch == longestBranch)
            {
                mBranches.erase(branch);
                break;
            }

        // Move main chain to a branch.
        Branch *newBranch = new Branch(longestBranch->height,
          accumulatedWork(longestBranch->height - 1));

        // Read all main chain blocks above branch height and put them in a branch.
        Block *block;
        Info &info = Info::instance();
        for(unsigned int height = longestBranch->height; height < headerHeight(); ++height)
        {
            block = new Block();
            if(info.spvMode || blockHeight() < height)
                getHeader(height, block->header);
            else
                getBlock(height, *block);
            newBranch->addBlock(block);
        }

        if(!info.spvMode)
        {
            // Clear main pending blocks
            mPendingLock.writeLock("Activate Branch");
            for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
              pending != mPendingBlocks.end(); ++pending)
                delete *pending;
            mPendingBlocks.clear();
            mPendingSize = 0;
            mLastFullPendingOffset = 0;
            mPendingBlockCount = 0;
        }

        // Revert the main chain to the before branch height.
        if(!revert(longestBranch->height - 1, true))
        {
            delete newBranch;
            mBranchLock.unlock();
            mHeadersLock.writeUnlock();
            if(!info.spvMode)
                mPendingLock.writeUnlock();
            return false;
        }

        // Add headers from branch.
        bool success = true;
        for(std::list<PendingBlockData *>::iterator pending = longestBranch->pendingBlocks.begin();
          pending != longestBranch->pendingBlocks.end(); ++pending)
            if(addHeader((*pending)->block->header, true, true) != 0)
            {
                success = false; // Main branch will be re-activated
                break;
            }

        if(!mInfo.spvMode && success && mNextBlockHeight == longestBranch->height)
        {
            // Move branch's pending blocks to the main chain's pending blocks
            offset = 0;
            for(std::list<PendingBlockData *>::iterator branchPending =
              longestBranch->pendingBlocks.begin();
              branchPending != longestBranch->pendingBlocks.end(); ++branchPending, ++offset)
            {
                mPendingBlocks.push_back(*branchPending);
                mPendingSize += (*branchPending)->block->size();
                if((*branchPending)->isFull())
                {
                    ++mPendingBlockCount;
                    mLastFullPendingOffset = offset;
                }
            }
        }
        else
        {
            for(std::list<PendingBlockData *>::iterator branchPending =
              longestBranch->pendingBlocks.begin();
              branchPending != longestBranch->pendingBlocks.end(); ++branchPending)
                delete *branchPending;
        }

        longestBranch->pendingBlocks.clear(); // No deletes necessary since they were reused

        if(!success)
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
              "Failed to activate branch at height %d", longestBranch->height);

        delete longestBranch;

        // Add the previous main branch as a new branch
        mBranches.push_back(newBranch);

        mBranchLock.unlock();
        mHeadersLock.writeUnlock();
        if(!info.spvMode)
            mPendingLock.writeUnlock();

        if(!success)
            return checkBranches(); // Call recursively to re-activate main branch
        else if(!info.spvMode)
            updatePendingBlocks();

        return success;
    }

    Chain::HashStatus Chain::addPendingHash(const NextCash::Hash &pHash, unsigned int pNodeID)
    {
        mHeadersLock.readLock();
        if(mBlackListHashes.contains(pHash))
        {
            mHeadersLock.readUnlock();
            return BLACK_LISTED;
        }
        else if(Forks::CASH_ACTIVATION_TIME == 1501590000)
        {
            // Manually reject BTC fork block hash since SPV mode can't tell the difference without
            //   block size or transaction verification
            if(sBTCForkBlockHash == pHash)
            {
                mHeadersLock.readUnlock();
                mHeadersLock.writeLock("Black List");
                addBlackListedHash(pHash);
                mHeadersLock.writeUnlock();
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
                  "Rejecting BTC fork block hash : %s", pHash.hex().text());
                return BLACK_LISTED;
            }
        }
        mHeadersLock.readUnlock();

        if(headerAvailable(pHash) || headerInBranch(pHash))
            return ALREADY_HAVE;

        // Check if block is requested for the chain
        mPendingLock.readLock();
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
            if((*pending)->block->header.hash == pHash)
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
        mHeadersLock.writeLock("Add Pending Hash");
        for(std::list<PendingHeaderData *>::iterator pendingHeader = mPendingHeaders.begin();
          pendingHeader != mPendingHeaders.end(); ++pendingHeader)
            if((*pendingHeader)->hash == pHash)
            {
                if((*pendingHeader)->requestingNode == 0 || getTime() -
                  (*pendingHeader)->requestedTime > 2)
                {
                    (*pendingHeader)->requestingNode = pNodeID;
                    (*pendingHeader)->requestedTime = getTime();
                    (*pendingHeader)->updateTime = getTime();
                    mHeadersLock.writeUnlock();
                    return NEED_HEADER;
                }
                else
                {
                    mHeadersLock.writeUnlock();
                    return ALREADY_HAVE;
                }
                break;
            }

        // Add a new pending header
        // NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
          // "Adding pending header : %s", pHash.hex().text());
        mPendingHeaders.push_back(new PendingHeaderData(pHash, pNodeID, getTime()));
        mHeadersLock.writeUnlock();
        return NEED_HEADER;
    }

    bool Chain::getPendingHeaderHashes(NextCash::HashList &pList)
    {
        pList.clear();
        mHeadersLock.readLock();
        for(std::list<PendingHeaderData *>::iterator pendingHeader = mPendingHeaders.begin();
          pendingHeader != mPendingHeaders.end(); ++pendingHeader)
            pList.push_back((*pendingHeader)->hash);
        mHeadersLock.readUnlock();
        return true;
    }

    bool Chain::revertFileHeight(unsigned int pHeight)
    {
        Header::revertToHeight(pHeight);
        if(!mInfo.spvMode)
            Block::revertToHeight(pHeight);
        return true;
    }

    bool Chain::revert(unsigned int pHeight, bool pHeadersLocked)
    {
        if(headerHeight() == pHeight)
            return true;

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Reverting from height %d to height %d", headerHeight(), pHeight);

        NextCash::Hash hash;
        while(headerHeight() >= pHeight)
        {
            if(!getHash(headerHeight(), hash))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to get hash (%d) to revert", headerHeight());
                return false;
            }

            if(headerHeight() == pHeight)
            {
                mLastHeaderHash = hash;
                break;
            }

            if(!mInfo.spvMode && blockHeight() == headerHeight())
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                  "Reverting block (%d) : %s", blockHeight(), hash.hex().text());

                Block block;
                if(!getBlock(blockHeight(), block))
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to get block (%d) to revert", blockHeight());
                    return false;
                }

                if(!mOutputs.revert(block.transactions, blockHeight()))
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to revert outputs from block (%d) to revert", blockHeight());
                    return false;
                }

                mMemPool.revert(block.transactions);

#ifndef DISABLE_ADDRESSES
                mAddresses.remove(block.transactions, blockHeight());
#endif
                --mNextBlockHeight;
            }
            else
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                  "Reverting header (%d) : %s", headerHeight(), hash.hex().text());

            // Remove hash
            if(!pHeadersLocked)
                mHeadersLock.writeLock("Remove");
            HashLookupSet &blockSet = mHashLookup[hash.lookup16()];
            blockSet.lock();
            blockSet.remove(hash);
#ifdef LOW_MEM
            mLastHashes.erase(mLastHashes.end() - 1);
#else
            mHashes.erase(mHashes.end() - 1);
#endif
            blockSet.unlock();

            mForks.revert(this, mNextHeaderHeight);
            revertLastBlockStat();
            --mNextHeaderHeight;
            if(!pHeadersLocked)
                mHeadersLock.writeUnlock();
        }

        if(mMonitor != NULL)
            mMonitor->revertToHeight(headerHeight());

        // Save accumulated work to prevent an invalid value in the file
        saveAccumulatedWork();

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
          "New last header (%d) : %s", mNextHeaderHeight - 1, mLastHeaderHash.hex().text());
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
          "New last block (%d)", mNextBlockHeight - 1);

        // Remove blocks from block/header files
        return revertFileHeight(headerHeight());
    }

    void Chain::updatePendingBlocks()
    {
        if(mInfo.spvMode)
            return;

        mPendingLock.writeLock("Update Pending");

        if(mApprovedBlockHeight == 0xffffffff)
        {
            mPendingLock.writeUnlock();
            return; // Wait until approved header is found.
        }

        // Add pending blocks if necessary.
        unsigned int nextHeight = mNextBlockHeight + mPendingBlocks.size();
        Header header;
        NextCash::Hash previousHash(32);

        if(!getHash(nextHeight - 1, previousHash))
        {
            mPendingLock.writeUnlock();
            return;
        }

        while(mPendingBlocks.size() < mInfo.pendingBlocks * 2 &&
          nextHeight < mNextHeaderHeight)
        {
            // Get header
            if(Header::getHeader(nextHeight, header))
            {
                if(previousHash != header.previousHash)
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                      "Next pending block (%d) failed : Invalid previous hash : %s",
                      nextHeight, header.previousHash.hex().text());
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                      "Correct previous hash : %s", previousHash.hex().text());
                    break;
                }

                mPendingBlocks.push_back(new PendingBlockData(new Block(header)));
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
                  "Added pending block : %s", header.hash.hex().text());
                previousHash = header.hash;
            }
            else
                break;

            ++nextHeight;
        }

        mPendingLock.writeUnlock();
    }

    void Chain::addBlockStat(int32_t pVersion, int32_t pTime, uint32_t pTargetBits)
    {
        if(mBlockStats.size() == 0)
            mBlockStats.emplace_back(pVersion, pTime, pTargetBits);
        else
            mBlockStats.emplace_back(pVersion, pTime, pTargetBits,
              mBlockStats.back().accumulatedWork);
        ++mBlockStatHeight;

        while(mBlockStats.size() > BLOCK_STATS_CACHE_SIZE)
            mBlockStats.pop_front();
    }

    void Chain::revertLastBlockStat()
    {
        if(mBlockStats.size() == 0)
            return;

        if(mBlockStats.size() < BLOCK_STATS_CACHE_SIZE && mBlockStatHeight > BLOCK_STATS_CACHE_SIZE)
        {
            // Calculate up to 5000 again on front.
            NextCash::Hash target(32), blockWork(32), accumulatedWork(32);
            Header header;
            unsigned int accumulatedWorkHeight = mBlockStatHeight - mBlockStats.size();

            accumulatedWork = mBlockStats.front().accumulatedWork;

            while(mBlockStats.size() < 5000)
            {
                if(!getHeader(accumulatedWorkHeight, header))
                    break;

                mBlockStats.emplace_front(header.version, header.time, header.targetBits);
                mBlockStats.front().accumulatedWork = accumulatedWork;

                target.setDifficulty(header.targetBits);
                target.getWork(blockWork);
                accumulatedWork -= blockWork;
                if(accumulatedWorkHeight == 0)
                    break;
                --accumulatedWorkHeight;
            }
        }

        // Remove last
        mBlockStats.pop_back();
        --mBlockStatHeight;
    }

    void Chain::clearBlockStats()
    {
        mBlockStats.clear();
        mBlockStatHeight = 0;
    }

    uint32_t Chain::calculateTargetBits()
    {
        uint32_t lastTargetBits = targetBits(mNextHeaderHeight - 1), result;

        if(mNextHeaderHeight == 0)
            return mMaxTargetBits;

        if(mForks.cashActive(mNextHeaderHeight))
        {
            if(mForks.cashFork201711IsActive(mNextHeaderHeight))
            {
                // Get first and last block times and accumulated work
                int32_t lastTime, firstTime;
                NextCash::Hash lastWork, firstWork;

                getMedianPastTimeAndWork(headerHeight(), lastTime, lastWork, 3);
                getMedianPastTimeAndWork(headerHeight() - 144, firstTime, firstWork, 3);

                int32_t timeSpan = lastTime - firstTime;

                // Apply limits
                if(timeSpan < 72 * 600)
                    timeSpan = 72 * 600;
                else if(timeSpan > 288 * 600)
                    timeSpan = 288 * 600;

                // Let the Work Performed (W) be equal to the difference in chainwork[3] between
                //   B_last and B_first.
                NextCash::Hash work = lastWork - firstWork;

                // Let the Projected Work (PW) be equal to (W * 600) / TS.
                work *= 600;
                work /= timeSpan;

                // Let Target (T) be equal to the (2^256 - PW) / PW. This is calculated by
                //   taking the two’s complement of PW (-PW) and dividing it by PW (-PW / PW).
                NextCash::Hash target = (-work) / work;

                // The target difficulty for block B_n+1 is then equal to the lesser of T and
                //   0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
                static NextCash::Hash sMaxTarget("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                if(target > sMaxTarget)
                    sMaxTarget.getDifficulty(result, mMaxTargetBits);
                else
                    target.getDifficulty(result, mMaxTargetBits);

                return result;
            }
            else if(mNextHeaderHeight >= 7)
            {
                // Bitcoin Cash EDA (Emergency Difficulty Adjustment)
                int32_t mptDiff = getMedianPastTime(mNextHeaderHeight - 1, 11) -
                  getMedianPastTime(mNextHeaderHeight - 7, 11);

                // If more than 12 hours on the last 6 blocks then reduce difficulty by 20%
                if(mptDiff >= 43200)
                {
                    double adjustFactor = 1.25;
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Cash EDA increasing target bits 0x%08x by a factor of %f to reduce difficulty by %.02f%%",
                      lastTargetBits, adjustFactor, (1.0 - (1.0 / adjustFactor)) * 100.0);

                    // Treat targetValue as a 256 bit number and multiply it by adjustFactor
                    result = multiplyTargetBits(lastTargetBits, adjustFactor, mMaxTargetBits);

                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Cash EDA new target bits for block height %d : 0x%08x", mNextHeaderHeight,
                      result);

                    return result;
                }
            }
        }

        if(mNextHeaderHeight % RETARGET_PERIOD != 0) // Not a DAA retarget block
            return lastTargetBits;

        int32_t lastBlockTime      = time(mNextHeaderHeight - 1);
        int32_t lastAdjustmentTime = time(mNextHeaderHeight - RETARGET_PERIOD);

        // Calculate percent of time actually taken for the last 2016 blocks by the goal time of 2
        //   weeks.
        // Adjust factor over 1.0 means the target is going up, which also means the difficulty to
        //   find a hash under the target goes down.
        // Adjust factor below 1.0 means the target is going down, which also means the difficulty
        //   to find a hash under the target goes up.
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Time spent on last 2016 blocks %d - %d = %d", lastBlockTime, lastAdjustmentTime,
          lastBlockTime - lastAdjustmentTime);
        double adjustFactor = (double)(lastBlockTime - lastAdjustmentTime) / 1209600.0;

        if(adjustFactor > 1.0)
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Increasing target bits 0x%08x by a factor of %f to reduce difficulty by %.02f%%",
              lastTargetBits, adjustFactor, (1.0 - (1.0 / adjustFactor)) * 100.0);
        else
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Decreasing target bits 0x%08x by a factor of %f to increase difficulty by %.02f%%",
              lastTargetBits, adjustFactor, ((1.0 / adjustFactor) - 1.0) * 100.0);

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
         * updated every 2,016 blocks using timestamps from only 2,015 blocks, creating a slight
         * skew.
         */

        // Treat targetValue as a 256 bit number and multiply it by adjustFactor
        result = multiplyTargetBits(lastTargetBits, adjustFactor, mMaxTargetBits);

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "New target bits for block height %d : 0x%08x", mNextHeaderHeight, result);

        return result;
    }

    bool Chain::processHeader(Header &pHeader)
    {
        addBlockStat(pHeader.version, pHeader.time, pHeader.targetBits);
        mForks.process(this, mNextHeaderHeight);

        // Check block version
        if(mForks.requiredBlockVersion(mNextHeaderHeight) > pHeader.version)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
              "Version %d required", mForks.requiredBlockVersion(mNextHeaderHeight));
            mForks.revert(this, mNextHeaderHeight);
            revertLastBlockStat();
            addBlackListedHash(pHeader.hash);
            return false;
        }

        // Check target bits
        uint32_t requiredTargetBits = calculateTargetBits();
        if(pHeader.targetBits != requiredTargetBits)
        {
            // If on TestNet and 20 minutes since last block
            bool useTestMinDifficulty = network() == TESTNET &&
              pHeader.time - time(mBlockStatHeight - 1) > 1200;

            if(useTestMinDifficulty && pHeader.targetBits == 0x1d00ffff)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                  "Using TestNet special minimum difficulty rule 0x1d00ffff for block %d",
                  mNextHeaderHeight);
            }
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                  "Header (%d) target bits invalid : required 0x%08x != header 0x%08x",
                  mNextHeaderHeight, requiredTargetBits, pHeader.targetBits);
                mForks.revert(this, mNextHeaderHeight);
                revertLastBlockStat();
                addBlackListedHash(pHeader.hash);
                return false;
            }
        }

        // Write header to file
        if(!Header::add(mNextHeaderHeight, pHeader))
        {
            mForks.revert(this, mNextHeaderHeight);
            revertLastBlockStat();
            return false;
        }

        // Add hash to lookup
        HashLookupSet &blockSet = mHashLookup[pHeader.hash.lookup16()];
        blockSet.lock();
#ifdef LOW_MEM
        mLastHashes.push_back(pHeader.hash);
        while(mLastHashes.size() > RECENT_BLOCK_COUNT)
            mLastHashes.erase(mLastHashes.begin());
#else
        mHashes.push_back(pHeader.hash);
#endif
        blockSet.push_back(new HashInfo(pHeader.hash, mNextHeaderHeight));
        blockSet.unlock();

        if(mApprovedBlockHeight == 0xffffffff && mInfo.approvedHash == pHeader.hash)
        {
            mApprovedBlockHeight = mNextHeaderHeight;
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Approved header found (%d) : %s", mNextHeaderHeight, pHeader.hash.hex().text());
        }

        ++mNextHeaderHeight;
        mLastHeaderHash = pHeader.hash;

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Added header (%d) : %s", mNextHeaderHeight - 1, pHeader.hash.hex().text());

        return true;
    }

    // Add/Verify block header
    int Chain::addHeader(Header &pHeader, bool pHeadersLocked, bool pBranchesLocked)
    {
        if(!pHeadersLocked)
            mHeadersLock.writeLock("Add");

        // Remove pending header
        for(std::list<PendingHeaderData *>::iterator pendingHeader = mPendingHeaders.begin();
          pendingHeader != mPendingHeaders.end(); ++pendingHeader)
            if((*pendingHeader)->hash == pHeader.hash)
            {
                // NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
                  // "Removed pending header : %s", pHeader->hash.hex().text());
                delete *pendingHeader;
                mPendingHeaders.erase(pendingHeader);
                break;
            }

        if(mBlackListHashes.contains(pHeader.hash))
        {
            if(!pHeadersLocked)
                mHeadersLock.writeUnlock();
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Rejecting black listed block hash : %s", pHeader.hash.hex().text());
            return -1;
        }
        else if(Forks::CASH_ACTIVATION_TIME != 0 && sBTCForkBlockHash == pHeader.hash)
        {
            // Manually reject BTC fork block hash.
            if(!pHeadersLocked)
                mHeadersLock.writeUnlock();
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
              "Rejecting BTC fork block header : %s", pHeader.hash.hex().text());
            return -1;
        }

        // This just checks that the proof of work meets the target bits in the header.
        //   The validity of the target bits value is checked before adding the full block to the chain.
        if(!pHeader.hasProofOfWork())
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Invalid proof of work : %s", pHeader.hash.hex().text());
            NextCash::Hash target;
            target.setDifficulty(pHeader.targetBits);
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Target                   : %s", target.hex().text());
            addBlackListedHash(pHeader.hash);
            if(!pHeadersLocked)
                mHeadersLock.writeUnlock();
            return -1;
        }

        if(pHeader.previousHash == mLastHeaderHash)
        {
            if(!processHeader(pHeader))
            {
                if(!pHeadersLocked)
                    mHeadersLock.writeUnlock();
                return -1;
            }

            if(!pHeadersLocked)
                mHeadersLock.writeUnlock();
            return 0;
        }

        if(headerAvailable(pHeader.hash))
        {
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
              "Header already in chain : %s", pHeader.hash.hex().text());
            if(!pHeadersLocked)
                mHeadersLock.writeUnlock();
            return 1;
        }

        // Check branches
        unsigned int branchID = 1;
        if(!pBranchesLocked)
            mBranchLock.lock();
        for(std::vector<Branch *>::iterator branch = mBranches.begin();
          branch != mBranches.end(); ++branch, ++branchID)
        {
            if(pHeader.previousHash == (*branch)->pendingBlocks.back()->block->header.hash)
            {
                // Add at end of branch
                (*branch)->addBlock(new Block(pHeader));
                if(!pBranchesLocked)
                    mBranchLock.unlock();
                if(!pHeadersLocked)
                    mHeadersLock.writeUnlock();
                checkBranches();
                return 0;
            }

            for(std::list<PendingBlockData *>::iterator pending =
              (*branch)->pendingBlocks.begin(); pending != (*branch)->pendingBlocks.end();
              ++pending)
                if((*pending)->block->header.hash == pHeader.hash)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Header already in branch %d (%d blocks) : %s", branchID,
                      (*branch)->pendingBlocks.size(), pHeader.hash.hex().text());
                    if(!pBranchesLocked)
                        mBranchLock.unlock();
                    if(!pHeadersLocked)
                        mHeadersLock.writeUnlock();
                    return 1;
                }
        }

        if(headerAvailable(pHeader.previousHash))
        {
            // Check if it fits on one of the last HISTORY_BRANCH_CHECKING blocks in the chain
            int chainHeight = headerHeight();
            unsigned int checkedCount = 0;
#ifdef LOW_MEM
            for(NextCash::HashList::reverse_iterator hash = mLastHashes.rbegin();
              hash != mLastHashes.rend() && checkedCount < HISTORY_BRANCH_CHECKING;
              ++checkedCount, ++hash, --chainHeight)
#else

            for(NextCash::HashList::reverse_iterator hash = mHashes.rbegin();
              hash != mHashes.rend() && checkedCount < HISTORY_BRANCH_CHECKING;
              ++checkedCount, ++hash, --chainHeight)
#endif
                if(*hash == pHeader.previousHash)
                {
                    // Create new branch
                    Branch *newBranch = new Branch(chainHeight + 1, accumulatedWork(chainHeight));
                    newBranch->addBlock(new Block(pHeader));
                    mBranches.push_back(newBranch);
                    if(!pBranchesLocked)
                        mBranchLock.unlock();
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Started branch at height %d : %s", newBranch->height,
                      pHeader.hash.hex().text());
                    if(!pHeadersLocked)
                        mHeadersLock.writeUnlock();
                    checkBranches();
                    return 0;
                }
                else if(chainHeight == 0)
                    break;
        }

        if(!pBranchesLocked)
            mBranchLock.unlock();

        NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
          "Unknown header : %s", pHeader.hash.hex().text());
        if(!pHeadersLocked)
            mHeadersLock.writeUnlock();
        return -1;
    }

    void Chain::updateBlockProgress(const NextCash::Hash &pHash, unsigned int pNodeID, int32_t pTime)
    {
        mPendingLock.readLock();
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
            if((*pending)->block->header.hash == pHash)
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
            for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
              pending != mPendingBlocks.end(); ++pending)
                if((*pending)->block->header.hash == *hash)
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
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
            if(!(*pending)->isFull() && (*pending)->requestingNode == pNodeID)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                  "Releasing block : %s", (*pending)->block->header.hash.hex().text());
                (*pending)->requestingNode = 0;
                (*pending)->requestedTime = 0;
            }
        for(std::list<PendingHeaderData *>::iterator pendingHeader = mPendingHeaders.begin();
          pendingHeader != mPendingHeaders.end(); ++pendingHeader)
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
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
        {
            // If "reduce only" don't request blocks unless there is a full pending block after them
            if(pReduceOnly && offset >= mLastFullPendingOffset)
                break;
            ++offset;

            if(!(*pending)->isFull() && (*pending)->requestingNode == 0)
            {
                pHashes.push_back((*pending)->block->header.hash);
                if(pHashes.size() >= pCount)
                    break;
            }
        }
        mPendingLock.readUnlock();

        return pHashes.size() > 0;
    }

    bool Chain::processBlock(Block &pBlock)
    {
#ifdef PROFILER_ON
        NextCash::Profiler outputsProfiler("Chain Process Block");
#endif
        mProcessMutex.lock();

        int32_t startTime = getTime();
        bool success = true, fullyValidated = true;
        if(mApprovedBlockHeight >= mNextBlockHeight) // Just update transaction outputs
        {
            fullyValidated = false;
            if(pBlock.transactions.size() > 200) // Enough to cover overhead of creating threads.
                success = pBlock.updateOutputsMultiThreaded(this, mNextBlockHeight,
                  mInfo.threadCount);
            else
                success = pBlock.updateOutputsSingleThreaded(this, mNextBlockHeight);

            if(!success)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to update approved block (%d) (%d trans) (%d KB) : %s",
                  mNextBlockHeight, pBlock.transactions.size(), pBlock.size() / 1000,
                  pBlock.header.hash.hex().text());
            }
        }
        else // Fully validate block
        {
            if(pBlock.transactions.size() > 100) // Enough to cover overhead of creating threads.
                success = pBlock.processMultiThreaded(this, mNextBlockHeight, mInfo.threadCount);
            else
                success = pBlock.processSingleThreaded(this, mNextBlockHeight);

            if(!success)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to process block (%d) (%d trans) (%d KB) : %s",
                  mNextBlockHeight, pBlock.transactions.size(), pBlock.size() / 1000,
                  pBlock.header.hash.hex().text());
            }
        }

        if(!success)
        {
            mOutputs.revert(pBlock.transactions, mNextBlockHeight);
            revert(mNextBlockHeight - 1);
            mProcessMutex.unlock();
            return false;
        }

        mMemPool.remove(pBlock.transactions); // Remove confirmed transactions from mempool

#ifndef DISABLE_ADDRESSES
        mAddresses.add(pBlock.transactions, mNextBlockHeight); // Update address database
#endif

        // Add the block to the chain
        if(!Block::add(mNextBlockHeight, pBlock))
        {
            mMemPool.revert(pBlock.transactions);
            mOutputs.revert(pBlock.transactions, mNextBlockHeight);
#ifndef DISABLE_ADDRESSES
            mAddresses.remove(pBlock.transactions, mNextBlockHeight);
#endif
            revert(mNextBlockHeight - 1);
            mProcessMutex.unlock();
            return false;
        }

        ++mNextBlockHeight;

        mProcessMutex.unlock();

        if(fullyValidated)
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Added validated block (%d) (%d trans) (%d KB) (%d s) : %s",
              mNextBlockHeight - 1, pBlock.transactions.size(), pBlock.size() / 1000,
              getTime() - startTime, pBlock.header.hash.hex().text());
        else
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Added approved block (%d) (%d trans) (%d KB) (%d s) : %s",
              mNextBlockHeight - 1, pBlock.transactions.size(), pBlock.size() / 1000,
              getTime() - startTime, pBlock.header.hash.hex().text());

        return true;
    }

    int Chain::addBlock(Block *pBlock)
    {
        // Ensure header has been processed. For when block is seen before header.
        int result = addHeader(pBlock->header);
        if(result < 0)
            return -1;
        else if(result == 0)
            updatePendingBlocks();

        if(!pBlock->validate(this, mNextBlockHeight))
        {
            // Block is incomplete or has the wrong transactions.
            return -1;
        }

        if(!pBlock->checkSize(this, mNextBlockHeight))
        {
            // Block is an invalid size and headers need to be reverted out.
            revert(mNextBlockHeight - 1);
            addBlackListedHash(pBlock->header.hash);
            return -1;
        }

        mPendingLock.writeLock("Add Block");

        unsigned int offset = 0;
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending, ++offset)
            if((*pending)->block->header.hash == pBlock->header.hash)
            {
                if((*pending)->isFull())
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                      BITCOIN_CHAIN_LOG_NAME, "Block already received from [%d]: %s",
                      (*pending)->requestingNode, pBlock->header.hash.hex().text());
                    mPendingLock.writeUnlock();
                    return 1;
                }
                else
                {
                    mPendingSize -= (*pending)->block->size();
                    (*pending)->replace(pBlock);
                    mPendingSize += pBlock->size();
                    ++mPendingBlockCount;
                    if(offset > mLastFullPendingOffset)
                        mLastFullPendingOffset = offset;
                    mPendingLock.writeUnlock();
                    return 0;
                }
            }

        mPendingLock.writeUnlock();

        // Check if it is in a branch
        unsigned int branchID = 1;
        mBranchLock.lock();
        for(std::vector<Branch *>::iterator branch = mBranches.begin();
          branch != mBranches.end(); ++branch, ++branchID)
            for(std::list<PendingBlockData *>::iterator pending =
              (*branch)->pendingBlocks.begin(); pending != (*branch)->pendingBlocks.end();
              ++pending)
                if((*pending)->block->header.hash == pBlock->header.hash)
                {
                    if((*pending)->isFull())
                    {
                        mBranchLock.unlock();
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                          "Block already received on branch %d from [%d]: %s", branchID,
                          (*pending)->requestingNode, pBlock->header.hash.hex().text());
                        return 1;
                    }
                    else
                    {
                        (*pending)->replace(pBlock);
                        mBranchLock.unlock();
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                          "Block received on branch %d from [%d]: %s", branchID,
                          (*pending)->requestingNode, pBlock->header.hash.hex().text());
                        return 0;
                    }
                }

        mBranchLock.unlock();
        return 1;
    }

    bool Chain::process()
    {
#ifdef PROFILER_ON
        NextCash::Profiler outputsProfiler("Chain Process");
#endif
        if(mStopRequested || mApprovedBlockHeight == 0xffffffff)
            return false;

        updatePendingBlocks();

        mPendingLock.readLock();

        if(mPendingBlocks.size() == 0)
        {
            // Expire pending headers
            for(std::list<PendingHeaderData *>::iterator pendingHeader = mPendingHeaders.begin();
              pendingHeader != mPendingHeaders.end();)
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
            Header::save();
            Block::save();
            mForks.save();
            return false;
        }

        mPendingLock.readUnlock();

        if(mInfo.spvMode)
            return false;

        mPendingLock.writeLock("Process");

        // Check if first pending header is actually a full block and process it
        PendingBlockData *nextPending = mPendingBlocks.front();
        if(!nextPending->isFull()) // Next pending block is not full yet
        {
            Header::save();
            Block::save();
            mForks.save();
            mPendingLock.writeUnlock();
            return false;
        }

        // Remove from pending
        mPendingBlocks.erase(mPendingBlocks.begin());
        if(mLastFullPendingOffset > 0)
            --mLastFullPendingOffset;
        mPendingSize -= nextPending->block->size();
        --mPendingBlockCount;

        mPendingLock.writeUnlock();

        // Process the next block and add it to the chain
        if(processBlock(*nextPending->block))
        {
            if(isInSync())
            {
                mBlocksToAnnounce.push_back(nextPending->block->header.hash);
                if(mAnnounceBlock == NULL)
                    mAnnounceBlock = nextPending->block;
                nextPending->block = NULL;
            }

            // Delete block
            delete nextPending;
            return true;
        }
        else
        {
            mPendingLock.writeLock("Clear");

            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Clearing all pending blocks/headers");

            // Clear pending blocks since they assumed this block was good
            mBlackListedNodeIDs.push_back(nextPending->requestingNode);
            // Add hash to blacklist. So it isn't downloaded again.
            addBlackListedHash(nextPending->block->header.hash);
            // Delete block
            delete nextPending;
            for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
              pending != mPendingBlocks.end(); ++pending)
                delete *pending;
            mPendingBlocks.clear();
            mLastFullPendingOffset = 0;
            mPendingSize = 0;
            mPendingBlockCount = 0;

            mPendingLock.writeUnlock();

            checkBranches(); // Possibly switch to a branch that is valid
            return false;
        }
    }

    bool Chain::getHashes(NextCash::HashList &pHashes, const NextCash::Hash &pStartingHash,
      unsigned int pCount)
    {
        unsigned int height;
#ifdef LOW_MEM
        NextCash::Hash hash;
#endif

        pHashes.clear();

        if(pStartingHash.isEmpty())
            height = 0;
        else
            height = hashHeight(pStartingHash);

        if(height == 0xffffffff)
            return false;

        mHeadersLock.readLock();
        while(pHashes.size() < pCount)
        {
#ifdef LOW_MEM
            if(!getHash(height, hash))
                break;
            pHashes.push_back(hash);
#else
            if(height >= mHashes.size())
                break;
            pHashes.push_back(mHashes[height]);
#endif
            ++height;
        }
        mHeadersLock.readUnlock();

        return pHashes.size() > 0;
    }

    bool Chain::getReverseHashes(NextCash::HashList &pHashes, unsigned int pOffset,
      unsigned int pCount, unsigned int pSpacing)
    {
        pHashes.clear();
        pHashes.reserve(pCount);

        if(pOffset > headerHeight())
            pOffset = 0;

        mHeadersLock.readLock();
        unsigned int height = headerHeight() - pOffset;
#ifdef LOW_MEM
        NextCash::Hash hash;
        while(pHashes.size() < pCount)
        {
            if(!getHash(height, hash))
                break;
            pHashes.emplace_back(hash);
            if(height <= pSpacing)
                break;
            height -= pSpacing;
        }
#else
        for(NextCash::HashList::reverse_iterator hash = mHashes.rbegin() + pOffset;
          hash != mHashes.rend() && pHashes.size() < pCount; hash += pSpacing, height -= pSpacing)
        {
            pHashes.emplace_back(*hash);
            if(height <= pSpacing)
                break;
        }
#endif
        mHeadersLock.readUnlock();
        return true;
    }

    bool Chain::getHeaders(HeaderList &pBlockHeaders, const NextCash::Hash &pStartingHash,
      const NextCash::Hash &pStoppingHash, unsigned int pCount)
    {
        unsigned int startingHeight = hashHeight(pStartingHash);
        if(startingHeight == 0xffffffff)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Unknown starting header : %s", pStartingHash.hex().text());
            return false;
        }

        unsigned int stoppingHeight = 0xffffffff;
        if(!pStoppingHash.isEmpty())
            stoppingHeight = hashHeight(pStoppingHash);
        unsigned int count = pCount;
        if(stoppingHeight != 0xffffffff)
        {
            if(stoppingHeight < startingHeight)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                  "Header stopping height %d below starting header %d", stoppingHeight,
                  startingHeight);
                return false;
            }
            if(stoppingHeight - startingHeight < pCount)
                count = stoppingHeight - startingHeight;
        }

        return Header::getHeaders(startingHeight + 1, count, pBlockHeaders);
    }

    bool Chain::getHash(unsigned int pBlockHeight, NextCash::Hash &pHash)
    {
        if(pBlockHeight > headerHeight())
            return false;
#ifdef LOW_MEM
        unsigned int blocksFromTop = headerHeight() - pBlockHeight;
        if(blocksFromTop < mLastHashes.size())
            pHash = mLastHashes[mLastHashes.size() - blocksFromTop - 1];
        else
            return Header::getHash(pBlockHeight, pHash); // Get hash from header file
#else
        if(pBlockHeight >= mHashes.size())
        {
            pHash.clear();
            return false;
        }

        pHash = mHashes[pBlockHeight];
#endif
        return true;
    }

    bool Chain::getBlock(unsigned int pBlockHeight, Block &pBlock)
    {
        return Block::getBlock(pBlockHeight, pBlock);
    }

    bool Chain::getBlock(const NextCash::Hash &pHash, Block &pBlock)
    {
        unsigned int thisBlockHeight = hashHeight(pHash);
        if(thisBlockHeight == 0xffffffff)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Get block failed. Hash not found : %s", pHash.hex().text());
            return false;
        }
        return Block::getBlock(thisBlockHeight, pBlock);
    }

    bool Chain::getHeader(unsigned int pBlockHeight, Header &pBlockHeader)
    {
        return Header::getHeader(pBlockHeight, pBlockHeader);
    }

    bool Chain::getHeader(const NextCash::Hash &pHash, Header &pHeader)
    {
        unsigned int thisBlockHeight = hashHeight(pHash);
        if(thisBlockHeight == 0xffffffff)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Get header failed. Hash not found : %s", pHash.hex().text());
            return false;
        }
        return Header::getHeader(thisBlockHeight, pHeader);
    }

    BlockStat *Chain::blockStat(unsigned int pBlockHeight)
    {
        if(pBlockHeight > mBlockStatHeight ||
          pBlockHeight < (mBlockStatHeight + 1) - mBlockStats.size())
            return NULL;

        unsigned int statHeight = mBlockStatHeight;
        std::list<BlockStat>::iterator iter = --mBlockStats.end();

        while(statHeight > pBlockHeight)
        {
            --iter;
            --statHeight;
        }

        return &*iter;
    }

    int32_t Chain::version(unsigned int pBlockHeight)
    {
        if(pBlockHeight > mBlockStatHeight)
            return 0;

        BlockStat *stat = blockStat(pBlockHeight);
        if(stat != NULL)
            return stat->version;

        Header header;
        if(!Header::getHeader(pBlockHeight, header))
            return 0;

        return header.version;
    }

    int32_t Chain::time(unsigned int pBlockHeight)
    {
        if(pBlockHeight > mBlockStatHeight)
            return 0;

        BlockStat *stat = blockStat(pBlockHeight);
        if(stat != NULL)
            return stat->time;

        Header header;
        if(!Header::getHeader(pBlockHeight, header))
            return 0;

        return header.time;
    }

    uint32_t Chain::targetBits(unsigned int pBlockHeight)
    {
        if(pBlockHeight > mBlockStatHeight)
            return 0;

        BlockStat *stat = blockStat(pBlockHeight);
        if(stat != NULL)
            return stat->targetBits;

        Header header;
        if(!Header::getHeader(pBlockHeight, header))
            return 0;

        return header.targetBits;
    }

    NextCash::Hash Chain::accumulatedWork(unsigned int pBlockHeight)
    {
        if(pBlockHeight == 0 || pBlockHeight > mBlockStatHeight)
            return NextCash::Hash(32); // Zero hash

        BlockStat *stat = blockStat(pBlockHeight);
        if(stat != NULL)
            return stat->accumulatedWork;

        // Get nearest accumulated work, top or bottom, and calculate to correct block height
        NextCash::Hash target(32), blockWork(32), accumulatedWork(32);
        Header header;
        unsigned int accumulatedWorkHeight = (mBlockStatHeight + 1 - mBlockStats.size());

        accumulatedWork = mBlockStats.front().accumulatedWork;

        while(accumulatedWorkHeight > pBlockHeight)
        {
            if(!Header::getHeader(accumulatedWorkHeight, header))
                break;

            target.setDifficulty(header.targetBits);
            target.getWork(blockWork);
            accumulatedWork -= blockWork;
            --accumulatedWorkHeight;
        }

        return accumulatedWork;
    }

    int32_t Chain::getMedianPastTime(unsigned int pBlockHeight, unsigned int pMedianCount)
    {
        if(pBlockHeight > mBlockStatHeight || pMedianCount > pBlockHeight)
            return 0;

        std::vector<int32_t> times;
        for(unsigned int i = pBlockHeight - pMedianCount + 1; i <= pBlockHeight; ++i)
            times.push_back(time(i));

        // Sort times
        std::sort(times.begin(), times.end());

        // Return the median time
        return times[pMedianCount / 2];
    }

    bool blockStatTimeLessThan(const BlockStat *pLeft, const BlockStat *pRight)
    {
        return pLeft->time < pRight->time;
    }

    void Chain::getMedianPastTimeAndWork(unsigned int pBlockHeight, int32_t &pTime,
      NextCash::Hash &pAccumulatedWork, unsigned int pMedianCount)
    {
        if(pBlockHeight > mBlockStatHeight || pMedianCount > pBlockHeight)
        {
            pTime = 0;
            pAccumulatedWork.zeroize();
            return;
        }

        std::vector<BlockStat *> values, toDelete;
        BlockStat *newStat;
        for(unsigned int i = pBlockHeight - pMedianCount + 1;
          i <= pBlockHeight; ++i)
        {
            newStat = blockStat(i);
            if(newStat == NULL)
            {
                newStat = new BlockStat();
                newStat->time = time(i);
                newStat->accumulatedWork = accumulatedWork(i);
                toDelete.push_back(newStat);
            }
            values.push_back(newStat);
        }

        // Sort
        std::sort(values.begin(), values.end(), blockStatTimeLessThan);

        // for(std::vector<BlockStat *>::iterator item=values.begin();item!=values.end();++item)
        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_FORKS_LOG_NAME,
        // "Sorted stat median calculate time %d, work %s", (*item)->time, (*item)->accumulatedWork.hex().text());

        pTime = values[pMedianCount / 2]->time;
        pAccumulatedWork = values[pMedianCount / 2]->accumulatedWork;
        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_FORKS_LOG_NAME,
        // "Using median calculate time %d, work %s", pTime, pAccumulatedWork.hex().text());
        NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
          "Median accumulated time/work at height %d : %d %s", pBlockHeight,
          pTime, pAccumulatedWork.hex().text());

        for(std::vector<BlockStat *>::iterator stat = toDelete.begin(); stat != toDelete.end();
          ++stat)
            delete *stat;
    }

    bool Chain::updateOutputs()
    {
        Block block;
        int32_t startTime;
        if(mOutputs.height() == 0xffffffff)
        {
            // Process genesis block
            startTime = getTime();
            if(Block::getBlock(0, block))
            {
                if(block.updateOutputsSingleThreaded(this, 0))
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Updated outputs for genesis block (%d trans) (%d KB) (%d s)",
                      block.transactions.size(), block.size() / 1000, getTime() - startTime);
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to update outputs for genesis block : %s",
                      block.header.hash.hex().text());
                    mOutputs.revert(block.transactions, 0);
                    mOutputs.save(mInfo.threadCount);
                    return false;
                }
            }
        }

        unsigned int currentHeight = mOutputs.height();

        if(currentHeight == blockHeight())
            return true;

        if(currentHeight > blockHeight())
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Outputs height %d above block height %d", mOutputs.height(), blockHeight());
            return false;
        }

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Updating outputs from height %d to %d", currentHeight,
          blockHeight());

        int32_t lastCheckTime = getTime();
        bool success;
        while(currentHeight < blockHeight() && !mStopRequested)
        {
            ++currentHeight;

            startTime = getTime();
            if(Block::getBlock(currentHeight, block))
            {
                if(block.transactions.size() > 200) // Enough to cover overhead of creating threads.
                    success = block.updateOutputsMultiThreaded(this, currentHeight,
                      mInfo.threadCount);
                else
                    success = block.updateOutputsSingleThreaded(this, currentHeight);

                if(success)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Updated outputs for block %d (%d trans) (%d KB) (%d s)", currentHeight,
                      block.transactions.size(), block.size() / 1000, getTime() - startTime);
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to update outputs for block %d : %s", currentHeight,
                      block.header.hash.hex().text());
                    mOutputs.revert(block.transactions, currentHeight);
                    mOutputs.save(mInfo.threadCount);
                    return false;
                }
            }
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to read block %d from block file", currentHeight);
                mOutputs.save(mInfo.threadCount);
                return false;
            }

            if(getTime() - lastCheckTime > 60)
            {
                if(mOutputs.cacheNeedsTrim())
                {
                    if(!mOutputs.save(mInfo.threadCount))
                        return false;
                }
                else
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Outputs : %d K trans (%d K, %d KB cached)", mOutputs.size() / 1000,
                      mOutputs.cacheSize() / 1000, mOutputs.cacheDataSize() / 1000);

                lastCheckTime = getTime();
            }
        }

        mOutputs.save(mInfo.threadCount);
        return mOutputs.height() == blockHeight();
    }

#ifndef DISABLE_ADDRESSES
    bool Chain::updateAddresses()
    {
        unsigned int currentHeight = mAddresses.height();
        if(currentHeight == blockHeight())
            return true;

        if(currentHeight > blockHeight())
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Addresses height %d above block height %d", mAddresses.height(), blockHeight());
            return false;
        }

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Updating addresses from block height %d to %d", currentHeight, blockHeight());

        Block block;
        Forks emptyForks;
        int32_t lastPurgeTime = getTime();
        int32_t startTime;
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Chain Update Addresses", false);
#endif

        while(currentHeight <= blockHeight() && !mStopRequested)
        {
            ++currentHeight;

#ifdef PROFILER_ON
            profiler.start();
#endif
            if(Block::getBlock(currentHeight, block))
            {
                // NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  // "Processing block %d : %s", currentHeight, block.hash.hex().text());

                startTime = getTime();

                mAddresses.add(block.transactions, currentHeight);

                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Updated addresses in block %d (%d trans) (%d KB) (%d s)", currentHeight,
                  block.transactions.size(), block.size() / 1000,
                  getTime() - startTime);
            }
            else
            {
#ifdef PROFILER_ON
                profiler.stop();
#endif
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to get block %d from block file", currentHeight);
                mAddresses.save(mInfo.threadCount);
                return false;
            }

#ifdef PROFILER_ON
            profiler.stop();
#endif

            if(getTime() - lastPurgeTime > 10)
            {
                if(mAddresses.needsPurge() && !mAddresses.save(mInfo.threadCount))
                    return false;
                lastPurgeTime = getTime();
            }
        }

        mAddresses.save(mInfo.threadCount);
        return mAddresses.height() == blockHeight();
    }
#endif

    bool Chain::saveAccumulatedWork()
    {
        // Save accumulated proof of work.
        if(mBlockStats.size() > 0)
        {
            NextCash::String proofOfWorkTempFileName = mInfo.path();
            proofOfWorkTempFileName.pathAppend("pow.temp");
            NextCash::FileOutputStream proofOfWorkFile(proofOfWorkTempFileName, true);

            if(!proofOfWorkFile.isValid())
                return false;
            else
            {
                proofOfWorkFile.writeUnsignedInt(mBlockStatHeight);
                mBlockStats.back().accumulatedWork.write(&proofOfWorkFile);

                NextCash::String proofOfWorkFileName = mInfo.path();
                proofOfWorkFileName.pathAppend("pow");
                return NextCash::renameFile(proofOfWorkTempFileName, proofOfWorkFileName);
            }
        }

        return true;
    }

    bool Chain::save()
    {
        bool success = true;

        if(!saveAccumulatedWork())
            success = false;
        if(!mForks.save())
            success = false;
        if(!savePending())
            success = false;
        if(!saveData())
            success = false;
        return success;
    }

    bool Chain::saveData()
    {
        if(Info::instance().spvMode)
            return true;

        mSaveDataInProgress = true;

        Header::save();
        Block::save();

        bool succes = mOutputs.save(mInfo.threadCount);
#ifndef DISABLE_ADDRESSES
        if(!mAddresses.save(mInfo.threadCount))
            succes = false;
#endif

        mSaveDataInProgress = false;
        return succes;
    }

    bool Chain::savePending()
    {
        mPendingLock.readLock();
        if(mPendingBlocks.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "No pending blocks to save");
            mPendingLock.readUnlock();
            return true;
        }

        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend("pending");
        NextCash::FileOutputStream file(filePathName, true);

        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed to open file to save pending blocks");
            mPendingLock.readUnlock();
            return false;
        }

        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
            (*pending)->block->write(&file);

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Saved %d pending blocks", mPendingBlocks.size());

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
              "No file to load pending blocks");
            return true;
        }

        NextCash::FileInputStream file(filePathName);
        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed to open file to load pending blocks");
            return false;
        }

        bool success = true;
        Block *newBlock;

        mPendingLock.writeLock("Load");

        // Clear pending (just in case)
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
            delete *pending;
        mPendingBlocks.clear();
        mPendingSize = 0;
        mPendingBlockCount = 0;
        unsigned int offset = 0;

        // Read pending blocks/headers from file
        while(file.remaining())
        {
            newBlock = new Block();
            if(!newBlock->read(&file))
            {
                delete newBlock;
                success = false;
                break;
            }

            NextCash::Hash nextHash(32);
            if(getHash(blockHeight() + mPendingBlocks.size(), nextHash) &&
              nextHash == newBlock->header.previousHash)
            {
                mPendingSize += newBlock->size();
                if(newBlock->transactions.size() > 0)
                    mPendingBlockCount++;
                mPendingBlocks.push_back(new PendingBlockData(newBlock));
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
              "Loaded %d pending blocks", mPendingBlocks.size());
        }
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed to load pending blocks from the file system");
            // Clear all pending that were read because they may be invalid
            for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
              pending != mPendingBlocks.end(); ++pending)
                delete *pending;
            mPendingBlocks.clear();
            mPendingSize = 0;
            mPendingBlockCount = 0;
            mLastFullPendingOffset = 0;
        }

        mPendingLock.writeUnlock();
        return success;
    }

    // Load block info from files
    bool Chain::load()
    {
        mStopRequested = false;
        mWasInSync = false;

        mHeadersLock.writeLock("Load");
        bool success = true;
        Block *genesisBlock = NULL;
        NextCash::Hash emptyHash;

        Header::clean(); // Close any open files
        // Validate latest file and get count.
        unsigned int headerCount = Header::validate(mStopRequested);
        if(mStopRequested)
        {
            mHeadersLock.writeUnlock();
            return false;
        }

        Block::clean(); // Close any open files
        // Validate latest file and get count.
        unsigned int blockCount = Block::validate(mStopRequested);
        if(mStopRequested)
        {
            mHeadersLock.writeUnlock();
            return false;
        }

        if(blockCount > headerCount)
        {
            // Revert blocks to latest header.
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Reverting blocks to valid header height %d", headerCount - 1);
            Block::revertToHeight(headerCount - 1);
            blockCount = headerCount;
        }

        mBlockStatHeight = 0;
        mNextHeaderHeight = 0;
        mNextBlockHeight = blockCount;
        mLastHeaderHash.clear();
#ifdef LOW_MEM
        mLastHashes.clear();
#else
        mHashes.clear();
#endif
        clearBlockStats();

        HashLookupSet *lookup = mHashLookup;
        for(unsigned int i = 0; i < 0x10000; ++i)
        {
            lookup->clear();
            ++lookup;
            if(mStopRequested)
            {
                mHeadersLock.writeUnlock();
                return false;
            }
        }

        if(headerCount == 0)
        {
            // Add genesis header to chain
            genesisBlock = Block::genesis(mMaxTargetBits);

            addBlockStat(genesisBlock->header.version, genesisBlock->header.time,
              genesisBlock->header.targetBits);
            mBlockStatHeight = 0;

            if(!Header::add(0, genesisBlock->header))
            {
                mHeadersLock.writeUnlock();
                delete genesisBlock;
                return false;
            }
            ++headerCount;

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Added genesis header to chain : %s", genesisBlock->header.hash.hex().text());
        }

        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Indexing header hashes");

#ifndef LOW_MEM
        mHashes.reserve(headerCount);
#endif

        // Load header files
        NextCash::HashList hashes;
        hashes.reserve(1000);
        while(!mStopRequested && mNextHeaderHeight < headerCount)
        {
            if(!Header::getHashes(mNextHeaderHeight, 1000, hashes) || hashes.size() == 0)
            {
                success = false;
                break;
            }

            for(NextCash::HashList::iterator hash = hashes.begin(); hash != hashes.end(); ++hash)
            {
                HashLookupSet &blockSet = mHashLookup[hash->lookup16()];
                blockSet.lock();
                blockSet.push_back(new HashInfo(*hash, mNextHeaderHeight));
                blockSet.unlock();
#ifndef LOW_MEM
                mHashes.push_back(*hash);
#endif
                ++mNextHeaderHeight;
            }
        }

        if(mStopRequested)
        {
            mHeadersLock.writeUnlock();
            if(genesisBlock != NULL)
                delete genesisBlock;
            return false;
        }

#ifdef LOW_MEM
        mLastHashes.reserve(RECENT_BLOCK_COUNT);

        // Get top block hashes
        if(mNextHeaderHeight > 0)
        {
            unsigned int startHeight;
            unsigned int hashCount = RECENT_BLOCK_COUNT;
            if(headerCount > RECENT_BLOCK_COUNT)
                startHeight = headerCount - RECENT_BLOCK_COUNT;
            else
            {
                hashCount = headerCount;
                startHeight = 0;
            }

            if(!Header::getHashes(startHeight, hashCount, mLastHashes))
                success = false;

            if(mLastHashes.size() > 0)
                mLastHeaderHash = mLastHashes.back();
        }
#else
        if(mHashes.size() > 0)
            mLastHeaderHash = mHashes.back();
#endif

        if(success)
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Indexed header hashes to height %d", headerHeight());

        // Lookup approved hash
        if(mApprovedBlockHeight == 0xffffffff)
            mApprovedBlockHeight = hashHeight(mInfo.approvedHash);

        if(mApprovedBlockHeight == 0xffffffff)
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Approved hash not found yet : %s", mInfo.approvedHash.hex().text());
        else if(mApprovedBlockHeight == 0x00000000)
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Approved hash not specified. Fully validating all blocks.");
        else
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Approved hash found (%d) : %s", mApprovedBlockHeight,
              mInfo.approvedHash.hex().text());

        if(mNextHeaderHeight > 0)
        {
            if(success)
            {
                // Load accumulated proof of work.
                NextCash::String accumulatedWorkFileName = mInfo.path();
                accumulatedWorkFileName.pathAppend("pow");
                NextCash::FileInputStream accumulatedWorkFile(accumulatedWorkFileName);

                unsigned int accumulatedWorkHeight;
                NextCash::Hash target(32), accumulatedWork(32);
                if(accumulatedWorkFile.isValid() && accumulatedWorkFile.remaining() == 36)
                {
                    accumulatedWorkHeight = accumulatedWorkFile.readUnsignedInt();
                    accumulatedWork.read(&accumulatedWorkFile);

                    if(accumulatedWorkHeight > headerHeight())
                    {
                        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                          "Calculating accumulated work from genesis");

                        // Calculate genesis block work
                        accumulatedWorkHeight = 0;
                        accumulatedWork.zeroize();
                    }
                }
                else
                {
                    NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Calculating accumulated work from genesis");

                    // Calculate genesis block work
                    accumulatedWorkHeight = 0;
                    accumulatedWork.zeroize();
                }

                // Calculate accumulated work up to chain height
                NextCash::Hash blockWork(32);
                std::vector<uint32_t> targetBits;
                unsigned int accumulatedCount;

                targetBits.reserve(1000);

                while(!mStopRequested && accumulatedWorkHeight < headerHeight())
                {
                    accumulatedCount = headerHeight() - accumulatedWorkHeight;

                    if(accumulatedCount > 1000)
                        accumulatedCount = 1000;

                    if(!Header::getTargetBits(accumulatedWorkHeight, accumulatedCount, targetBits))
                    {
                        success = false;
                        break;
                    }

                    if(targetBits.size() == 0)
                        break;

                    for(std::vector<uint32_t>::iterator bits = targetBits.begin();
                      bits != targetBits.end(); ++bits)
                    {
                        target.setDifficulty(*bits);
                        target.getWork(blockWork);
                        accumulatedWork += blockWork;

                        if(accumulatedWorkHeight == headerHeight())
                            break;

                        ++accumulatedWorkHeight;
                    }
                }

                if(mStopRequested)
                {
                    mHeadersLock.writeUnlock();
                    if(genesisBlock != NULL)
                        delete genesisBlock;
                    return false;
                }

                // Calculate previous block stats
                if(success)
                {
                    mBlockStatHeight = accumulatedWorkHeight;
                    if(Header::getBlockStatsReverse(accumulatedWorkHeight, BLOCK_STATS_CACHE_SIZE,
                      mBlockStats))
                    {
                        // Update accumulated work
                        for(std::list<BlockStat>::reverse_iterator stat = mBlockStats.rbegin();
                          stat != mBlockStats.rend(); ++stat)
                        {
                            stat->accumulatedWork = accumulatedWork;

                            target.setDifficulty(stat->targetBits);
                            target.getWork(blockWork);
                            accumulatedWork -= blockWork;
                            --accumulatedWorkHeight;
                        }
                    }
                    else
                    {
                        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                          "Failed to load block stats");
                        success = false;
                    }
                }

                if(success)
                    saveAccumulatedWork();
            }
        }

        if(mStopRequested)
        {
            mHeadersLock.writeUnlock();
            if(genesisBlock != NULL)
                delete genesisBlock;
            return false;
        }

        success = success && mForks.load(this);

        if(success)
        {
            if(mForks.height() > headerHeight())
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Reverting forks to height of %d", headerHeight());
                mForks.revert(this, headerHeight());
                mForks.save();
            }

            if(mForks.height() < headerHeight())
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Updating forks to height %d", headerHeight());

                int32_t lastReport = getTime();
                for(unsigned int i = mForks.height() + 1; i < mNextHeaderHeight; ++i)
                {
                    if(getTime() - lastReport > 10)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                          "Forks load is %2d%% Complete",
                          (int)(((float)i / (float)mNextHeaderHeight) * 100.0f));
                        lastReport = getTime();
                    }

                    if(mStopRequested)
                        break;

                    mForks.process(this, i);
                }

                mForks.save();
            }
        }

        mHeadersLock.writeUnlock();

        if(mStopRequested || !success)
        {
            if(genesisBlock != NULL)
                delete genesisBlock;
            return false;
        }

        if(!mInfo.spvMode)
        {
            try
            {
#ifndef DISABLE_ADDRESSES
                // Load transaction addresses
                success = success && mAddresses.load(mInfo.path(), 0); // 10485760); // 10 MiB

                // Update transaction addresses if they aren't up to current chain block height
                success = success && updateAddresses();

                if(mStopRequested || !success)
                    return false;
#endif

                // Load transaction outputs
                success = success && mOutputs.load(mInfo.path(), mInfo.outputsCacheSize,
                  mInfo.outputsCacheDelta);

                // Update transaction outputs if they aren't up to current chain block height
                success = success && updateOutputs();
            }
            catch(std::bad_alloc &pBadAlloc)
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to load. Bad allocation : %s", pBadAlloc.what());
                success = false;
            }

            if(success && genesisBlock != NULL)
            {
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Processing genesis block");
                processBlock(*genesisBlock);
                delete genesisBlock;
            }
        }
        else if(genesisBlock != NULL)
            delete genesisBlock;

        return success && loadPending();
    }

    bool Chain::test()
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "------------- Starting Block Chain Tests -------------");

        bool success = true;
        NextCash::Buffer checkData;
        NextCash::Hash checkHash(32);
        Block *genesis = Block::genesis(0x1d00ffff);

        //genesis->print(NextCash::Log::INFO);

        //NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
        // "Current coin base amount : %f",
        // (double)bitcoins(Block::coinBaseAmount(485000)));

        /*******************************************************************************************
         * Genesis block merkle hash
         ******************************************************************************************/
        checkData.clear();
        checkData.writeHex("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a");
        checkHash.read(&checkData);

        if(genesis->header.merkleHash == checkHash)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Passed genesis block merkle hash");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed genesis block merkle hash");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Block merkle hash   : %s", genesis->header.merkleHash.hex().text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Correct merkle hash : %s", checkHash.hex().text());
            success = false;
        }

        /*******************************************************************************************
         * Genesis block hash
         ******************************************************************************************/
        //Big Endian checkData.writeHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        if(network() == TESTNET)
            checkData.writeHex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000");
        else
            checkData.writeHex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000");
        checkHash.read(&checkData);

        if(genesis->header.hash == checkHash)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Passed genesis block hash");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed genesis block hash");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Block hash   : %s", genesis->header.hash.hex().text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Correct hash : %s", checkHash.hex().text());
            success = false;
        }

        /*******************************************************************************************
         * Genesis block read hash
         ******************************************************************************************/
        //Big Endian checkData.writeHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        checkData.clear();
        if(network() == TESTNET)
            checkData.writeHex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000");
        else
            checkData.writeHex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000");
        checkHash.read(&checkData);
        Block readGenesisBlock;
        NextCash::Buffer blockBuffer;
        genesis->write(&blockBuffer);
        readGenesisBlock.read(&blockBuffer);

        if(readGenesisBlock.header.hash == checkHash)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Passed genesis block read hash");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed genesis block read hash");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Block hash   : %s", readGenesisBlock.header.hash.hex().text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Correct hash : %s", checkHash.hex().text());
            success = false;
        }

        /*******************************************************************************************
         * Genesis block raw
         ******************************************************************************************/
        NextCash::Buffer data;
        genesis->write(&data);

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
              "Failed genesis block raw data size : actual %d != correct %d", data.length(),
              checkData.length());
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

                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                      "Failed genesis block raw data line %d", lineNo);
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                      "Actual  : %s", actualHex.text());
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                      "Correct : %s", checkHex.text());
                    success = false;
                }
            }

            if(matches)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Passed genesis block raw data");
        }

        /*******************************************************************************************
         * Block read
         ******************************************************************************************/
        Block readBlock;
        NextCash::FileInputStream readFile("tests/06128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000.pending_block");
        NextCash::removeDirectory("chain_test");
        Info::setPath("./chain_test");
        TransactionOutputPool outputs;
        Forks softForks;

        outputs.load(Info::instance().path(), Info::instance().outputsCacheSize,
          Info::instance().outputsCacheDelta);

        if(!readBlock.read(&readFile))
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed to read block");
            success = false;
        }
        else
        {
            //readBlock.print(NextCash::Log::INFO);

            /***************************************************************************************
             * Block read hash
             **************************************************************************************/
            checkData.clear();
            checkData.writeHex("06128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000");
            checkHash.read(&checkData);

            if(readBlock.header.hash == checkHash)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Passed read block hash");
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Failed read block hash");
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Block hash   : %s", readBlock.header.hash.hex().text());
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Correct hash : %s", checkHash.hex().text());
                success = false;
            }

            /***************************************************************************************
             * Block read previous hash
             **************************************************************************************/
            checkData.clear();
            checkData.writeHex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000");
            checkHash.read(&checkData);

            if(readBlock.header.previousHash == checkHash)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Passed read block previous hash");
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Failed read block previous hash");
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Block previous hash   : %s", readBlock.header.previousHash.hex().text());
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Correct previous hash : %s", checkHash.hex().text());
                success = false;
            }

            /***************************************************************************************
             * Block read merkle hash
             **************************************************************************************/
            readBlock.calculateMerkleHash(checkHash);

            if(readBlock.header.merkleHash == checkHash)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Passed read block merkle hash");
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Failed read block merkle hash");
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Block merkle hash      : %s", readBlock.header.merkleHash.hex().text());
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Calculated merkle hash : %s", checkHash.hex().text());
                success = false;
            }

            /***************************************************************************************
             * Block read process
             **************************************************************************************/
            NextCash::removeDirectory("chain_test");
            Info::instance().setPath("chain_test");
            Chain chain;
            chain.load();
            if(readBlock.processSingleThreaded(&chain, 0))
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Passed read block process");
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Failed read block process");
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
        // // // outputs.add(block.transactions, outputs.hashHeight() + 1, block.hash);

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

            // // if((int)reference->hashHeight == outputs.blockHeight())
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
