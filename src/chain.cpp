/**************************************************************************
 * Copyright 2017-2019 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "chain.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#include "profiler_setup.hpp"
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
#define HEADER_STATS_CACHE_SIZE 2500


namespace BitCoin
{
    Chain::Chain() : mInfo(Info::instance()), mPendingLock("Chain Pending"),
      mProcessMutex("Chain Process"), mHeadersLock("Chain Headers"), mMemPool(this),
      mBranchLock("Chain Branches"), mBlockStatLock("Block Stat")
    {
        mNextHeaderHeight = 0;
        mNextBlockHeight = 0;
        mPendingSize = 0;
        mPendingBlockCount = 0;
        mMaxTargetBits = 0x1d00ffff;
        mLastFullPendingOffset = 0;
        mStopRequested = false;
        mSaveDataInProgress = false;
        mIsInSync = false;
        mWasInSync = false;
        mHeadersNeeded = true;
        mMonitor = NULL;
        mHeaderStatHeight = 0;
        mMemPoolRequests = 0;
        mLastDataSaveTime = 0;

        if(mInfo.approvedHash.isEmpty())
            mApprovedBlockHeight = 0x00000000; // Not set
        else
            mApprovedBlockHeight = 0xffffffff; // Not found yet
    }

    Chain::~Chain()
    {
        mMemPool.stop();
        mPendingLock.writeLock("Destroy");
        clearHeaderStats();
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
            delete *pending;

        mBranchLock.lock();
        for(std::vector<Branch *>::iterator branch = mBranches.begin();
          branch != mBranches.end(); ++branch)
            delete *branch;
    }

    Branch::~Branch()
    {
        for(std::vector<PendingBlockData *>::iterator pending = pendingBlocks.begin();
          pending != pendingBlocks.end(); ++pending)
            delete *pending;
    }

    void Chain::setInSync()
    {
        mIsInSync = true;
        mWasInSync = true;
        mInfo.setInitialBlockDownloadComplete();
        mMonitor->updatePasses(this);
        mMonitor->incrementChange();
        mMemPool.start();
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

    std::vector<unsigned int> Chain::invalidNodeIDs()
    {
        mPendingLock.writeLock("Invalid Nodes");
        std::vector<unsigned int> result = mInvalidNodeIDs;
        mInvalidNodeIDs.clear();
        mPendingLock.writeUnlock();
        return result;
    }

    void Chain::addInvalidHash(const NextCash::Hash &pHash)
    {
        if(!mInvalidHashes.contains(pHash))
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Added header hash to invalid list : %s", pHash.hex().text());
            mInvalidHashes.push_back(pHash);
            // Keep list at 1024 or less
            if(mInvalidHashes.size() > 1024)
                mInvalidHashes.erase(mInvalidHashes.begin());
        }
    }

    BlockReference Chain::blockToAnnounce()
    {
        BlockReference result;
        NextCash::Hash hash;
        mPendingLock.writeLock("Announce");
        if(mBlocksToAnnounce.size() > 0)
        {
            result = mBlocksToAnnounce.front();
            mBlocksToAnnounce.erase(mBlocksToAnnounce.begin());
        }
        mPendingLock.writeUnlock();

        // Transaction hashes were already calculated during validation, so this block is safe to
        //   hand out.
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
            for(std::vector<PendingBlockData *>::iterator pending =
              (*branch)->pendingBlocks.begin(); pending != (*branch)->pendingBlocks.end();
              ++pending)
                if((*pending)->block->header.hash() == pHash)
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

        Info &info = Info::instance();
        if(!info.spvMode)
            mPendingLock.writeLock("Check Branches");
        mHeadersLock.writeLock("Check Branches");
        mBranchLock.lock();
        if(mBranches.size() == 0)
        {
            mBranchLock.unlock();
            mHeadersLock.writeUnlock();
            if(!info.spvMode)
                mPendingLock.writeUnlock();
            return false;
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
                    ++offset;
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
            if(!info.spvMode)
                mPendingLock.writeUnlock();
            return false;
        }

        // Swap the branch with the most "work" for the main chain.
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Activating branch at height %d (%d blocks)", longestBranch->height,
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
        BlockReference block;
        for(unsigned int height = longestBranch->height; height <= headerHeight(); ++height)
        {
            if(info.spvMode || blockHeight() < height)
            {
                block = new Block();
                if(!getHeader(height, block->header))
                    block.clear();
            }
            else
                block = getBlock(height);
            if(!block)
                break;
            newBranch->addBlock(block);
        }

        if(!info.spvMode)
        {
            // Clear main pending blocks
            for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
              pending != mPendingBlocks.end(); ++pending)
                delete *pending;
            mPendingBlocks.clear();
            mPendingSize = 0;
            mLastFullPendingOffset = 0;
            mPendingBlockCount = 0;
        }

        if(newBranch->pendingBlocks.size() > 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Main converted to branch at height %d (%d blocks)", newBranch->height,
              newBranch->pendingBlocks.size());

            // Add the previous main branch as a new branch
            mBranches.push_back(newBranch);
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Main branch has no blocks left");

        // Revert the main chain to the before branch height.

        mProcessMutex.lock();
        uint8_t locks = LOCK_HEADERS | LOCK_BRANCHES | LOCK_PROCESS;
        if(!info.spvMode)
            locks |= LOCK_PENDING;
        if(!revert(longestBranch->height - 1, locks))
        {
            mProcessMutex.unlock();
            mBranchLock.unlock();
            mHeadersLock.writeUnlock();
            if(!info.spvMode)
                mPendingLock.writeUnlock();
            return false;
        }

        // Add headers from branch.
        bool success = true;
        for(std::vector<PendingBlockData *>::iterator pending =
          longestBranch->pendingBlocks.begin(); pending != longestBranch->pendingBlocks.end();
          ++pending)
            if(addHeader((*pending)->block->header, 0, locks, true) == INVALID)
            {
                success = false; // Main branch will be re-activated
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to activate branch at height %d", longestBranch->height);
                break;
            }

        if(!mInfo.spvMode && success && mNextBlockHeight == longestBranch->height)
        {
            // Move branch's pending blocks to the main chain's pending blocks
            offset = 0;
            for(std::vector<PendingBlockData *>::iterator branchPending =
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
            for(std::vector<PendingBlockData *>::iterator branchPending =
              longestBranch->pendingBlocks.begin();
              branchPending != longestBranch->pendingBlocks.end(); ++branchPending)
                delete *branchPending;
        }

        longestBranch->pendingBlocks.clear(); // No deletes necessary since they were reused
        delete longestBranch;

        mProcessMutex.unlock();
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
        if(mInfo.invalidHashes.contains(pHash))
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Predefined invalid hash : %s", pHash.hex().text());
            return INVALID;
        }

        mHeadersLock.readLock();
        if(mInvalidHashes.contains(pHash))
        {
            mHeadersLock.readUnlock();
            return INVALID;
        }
        else if(Forks::CASH_ACTIVATION_TIME == 1501590000)
        {
            // Manually reject BTC fork block hash since SPV mode can't tell the difference without
            //   block size or transaction verification
            if(BTC_SPLIT_HASH == pHash)
            {
                mHeadersLock.readUnlock();
                mHeadersLock.writeLock("Invalid List");
                addInvalidHash(pHash);
                mHeadersLock.writeUnlock();
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
                  "Rejecting BTC fork block hash : %s", pHash.hex().text());
                return INVALID;
            }
        }
        mHeadersLock.readUnlock();

        if(headerAvailable(pHash) || headerInBranch(pHash))
            return ALREADY_HAVE;

        // Check if block is requested for the chain
        mPendingLock.readLock();
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
            if((*pending)->block->header.hash() == pHash)
            {
                if(!mInfo.spvMode && !(*pending)->isFull() && (*pending)->requestingNode == 0)
                {
                    mPendingLock.readUnlock();
                    return BLOCK_NEEDED;
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
                    return HEADER_NEEDED;
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
        return HEADER_NEEDED;
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

    bool Chain::revert(unsigned int pHeight, uint8_t pLocks)
    {
        if(headerHeight() == pHeight)
            return true;

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Reverting from height %d to height %d", headerHeight(), pHeight);

        if(!mInfo.spvMode && !(pLocks & LOCK_PENDING))
            mPendingLock.writeLock("Revert");
        if(!(pLocks & LOCK_HEADERS))
            mHeadersLock.writeLock("Revert");
        if(!(pLocks & LOCK_PROCESS))
            mProcessMutex.lock();
        if(!(pLocks & LOCK_BRANCHES))
            mBranchLock.lock();

        // Revert pending blocks
        if(!mInfo.spvMode && mNextBlockHeight - 1 < pHeight)
            while(mNextBlockHeight + mPendingBlocks.size() - 1 > pHeight)
            {
                delete mPendingBlocks.back();
                mPendingBlocks.pop_back();
            }

        NextCash::Hash hash;
        while(headerHeight() >= pHeight)
        {
            if(!getHash(headerHeight(), hash,
              LOCK_PENDING | LOCK_HEADERS | LOCK_PROCESS | LOCK_BRANCHES))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to get hash (%d) to revert", headerHeight());
                if(!(pLocks & LOCK_BRANCHES))
                    mBranchLock.unlock();
                if(!(pLocks & LOCK_PROCESS))
                    mProcessMutex.unlock();
                if(!(pLocks & LOCK_HEADERS))
                    mHeadersLock.writeUnlock();
                if(!mInfo.spvMode && !(pLocks & LOCK_PENDING))
                    mPendingLock.writeUnlock();
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

                BlockReference block = getBlock(blockHeight());
                if(!block)
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to get block (%d) to revert", blockHeight());
                    if(!(pLocks & LOCK_BRANCHES))
                        mBranchLock.unlock();
                    if(!(pLocks & LOCK_PROCESS))
                        mProcessMutex.unlock();
                    if(!(pLocks & LOCK_HEADERS))
                        mHeadersLock.writeUnlock();
                    if(!mInfo.spvMode && !(pLocks & LOCK_PENDING))
                        mPendingLock.writeUnlock();
                    return false;
                }

                if(!mOutputs.revert(block->transactions, blockHeight()))
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to revert outputs from block (%d) to revert", blockHeight());
                    if(!(pLocks & LOCK_BRANCHES))
                        mBranchLock.unlock();
                    if(!(pLocks & LOCK_PROCESS))
                        mProcessMutex.unlock();
                    if(!(pLocks & LOCK_HEADERS))
                        mHeadersLock.writeUnlock();
                    if(!mInfo.spvMode && !(pLocks & LOCK_PENDING))
                        mPendingLock.writeUnlock();
                    return false;
                }

                mMemPool.revert(block->transactions, false);

#ifndef DISABLE_ADDRESSES
                mAddresses.remove(block->transactions, blockHeight());
#endif
                --mNextBlockHeight;
            }
            else
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                  "Reverting header (%d) : %s", headerHeight(), hash.hex().text());

            // Remove hash
            HashLookupSet &blockSet = mHashLookup[hash.lookup16()];
            blockSet.lock();
            blockSet.remove(hash);
            blockSet.unlock();
#ifdef LOW_MEM
            if(mLastHashes.size() > 0)
                mLastHashes.pop_back();
#else
            mHashes.erase(mHashes.end() - 1);
#endif

            mForks.revert(this, mNextHeaderHeight);
            revertLastHeaderStat();
            --mNextHeaderHeight;
        }

        // Save accumulated work to prevent an invalid value in the file
        saveAccumulatedWork();

        bool success = true;
#ifdef LOW_MEM
        // Rebuild recent header hashes
        mLastHashes.clear();
        mLastHashes.reserve(RECENT_BLOCK_COUNT);

        // Get top block hashes
        if(mNextHeaderHeight > 0)
        {
            unsigned int hashCount = RECENT_BLOCK_COUNT;
            unsigned int startHeight;
            if(headerHeight() > hashCount)
                startHeight = mNextHeaderHeight - hashCount;
            else
            {
                hashCount = mNextHeaderHeight;
                startHeight = 0;
            }

            if(!Header::getHashes(startHeight, hashCount, mLastHashes))
                success = false;

            if(mLastHashes.back() != mLastHeaderHash)
                success = false;
        }
#endif

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
          "New last header (%d) : %s", headerHeight(), mLastHeaderHash.hex().text());
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
          "New last block (%d)", headerHeight());

        // Remove blocks from block/header files
        if(!revertFileHeight(headerHeight()))
            success = false;

        if(!(pLocks & LOCK_BRANCHES))
            mBranchLock.unlock();
        if(!(pLocks & LOCK_PROCESS))
            mProcessMutex.unlock();
        if(!(pLocks & LOCK_HEADERS))
            mHeadersLock.writeUnlock();
        if(!mInfo.spvMode && !(pLocks & LOCK_PENDING))
            mPendingLock.writeUnlock();

        // This has a dependency on the chain header lock, so must be done outside of the locks.
        if(mMonitor != NULL)
            mMonitor->revertToHeight(headerHeight());
        return success;
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

        if(!getHash(nextHeight - 1, previousHash, LOCK_PENDING))
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

                BlockReference reference(new Block(header));
                mPendingBlocks.push_back(new PendingBlockData(reference));
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
                  "Added pending block : %s", header.hash().hex().text());
                previousHash = header.hash();
            }
            else
                break;

            ++nextHeight;
        }

        mPendingLock.writeUnlock();
    }

    void Chain::addHeaderStat(int32_t pVersion, Time pTime, uint32_t pTargetBits)
    {
        if(mHeaderStats.size() == 0)
            mHeaderStats.emplace_back(pVersion, pTime, pTargetBits);
        else
            mHeaderStats.emplace_back(pVersion, pTime, pTargetBits,
              mHeaderStats.back().accumulatedWork);
        ++mHeaderStatHeight;

        while(mHeaderStats.size() > HEADER_STATS_CACHE_SIZE)
            mHeaderStats.pop_front();
    }

    void Chain::revertLastHeaderStat()
    {
        if(mHeaderStats.size() == 0)
            return;

        if(mHeaderStats.size() < HEADER_STATS_CACHE_SIZE && mHeaderStatHeight > HEADER_STATS_CACHE_SIZE)
        {
            // Calculate up to 5000 again on front.
            NextCash::Hash target(32), blockWork(32);
            Header header;
            unsigned int accumulatedWorkHeight = mHeaderStatHeight - mHeaderStats.size();
            NextCash::Hash accumulatedWork = mHeaderStats.front().accumulatedWork;

            target.setDifficulty(mHeaderStats.front().targetBits);
            target.getWork(blockWork);
            accumulatedWork -= blockWork;

            while(mHeaderStats.size() < 5000)
            {
                if(!getHeader(accumulatedWorkHeight, header))
                    break;

                mHeaderStats.emplace_front(header.version, header.time, header.targetBits);
                mHeaderStats.front().accumulatedWork = accumulatedWork;

                target.setDifficulty(header.targetBits);
                target.getWork(blockWork);
                accumulatedWork -= blockWork;
                if(accumulatedWorkHeight == 0)
                    break;
                --accumulatedWorkHeight;
            }
        }

        // Remove last
        mHeaderStats.pop_back();
        --mHeaderStatHeight;
    }

    void Chain::clearHeaderStats()
    {
        mHeaderStats.clear();
        mHeaderStatHeight = 0;
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
                Time lastTime, firstTime;
                NextCash::Hash lastWork, firstWork;

                getMedianPastTimeAndWork(headerHeight(), lastTime, lastWork, 3);
                getMedianPastTimeAndWork(headerHeight() - 144, firstTime, firstWork, 3);

                Time timeSpan = lastTime - firstTime;

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
                Time mptDiff = getMedianPastTime(mNextHeaderHeight - 1, 11) -
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

        Time lastBlockTime      = time(mNextHeaderHeight - 1);
        Time lastAdjustmentTime = time(mNextHeaderHeight - RETARGET_PERIOD);

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
        addHeaderStat(pHeader.version, pHeader.time, pHeader.targetBits);
        mForks.process(this, mNextHeaderHeight);

        // Check block version
        if(mForks.requiredBlockVersion(mNextHeaderHeight) > pHeader.version)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
              "Version %d required", mForks.requiredBlockVersion(mNextHeaderHeight));
            mForks.revert(this, mNextHeaderHeight);
            revertLastHeaderStat();
            addInvalidHash(pHeader.hash());
            return false;
        }

        // Check target bits
        uint32_t requiredTargetBits = calculateTargetBits();
        if(pHeader.targetBits != requiredTargetBits)
        {
            // If on TestNet and 20 minutes since last block
            bool useTestMinDifficulty = network() == TESTNET &&
              pHeader.time - time(mHeaderStatHeight - 1) > 1200;

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
                revertLastHeaderStat();
                addInvalidHash(pHeader.hash());
                return false;
            }
        }

        // Write header to file
        if(!Header::add(mNextHeaderHeight, pHeader))
        {
            mForks.revert(this, mNextHeaderHeight);
            revertLastHeaderStat();
            return false;
        }

        // Add hash to lookup
        HashLookupSet &blockSet = mHashLookup[pHeader.hash().lookup16()];
        blockSet.lock();
#ifdef LOW_MEM
        mLastHashes.push_back(pHeader.hash());
        while(mLastHashes.size() > RECENT_BLOCK_COUNT)
            mLastHashes.erase(mLastHashes.begin());
#else
        mHashes.push_back(pHeader.hash());
#endif
        blockSet.push_back(new HashInfo(pHeader.hash(), mNextHeaderHeight));
        blockSet.unlock();

        if(mApprovedBlockHeight == 0xffffffff && mInfo.approvedHash == pHeader.hash())
        {
            mApprovedBlockHeight = mNextHeaderHeight;
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Approved header found (%d) : %s", mNextHeaderHeight, pHeader.hash().hex().text());
        }

        ++mNextHeaderHeight;
        mLastHeaderHash = pHeader.hash();

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Added header (%d) : %s", mNextHeaderHeight - 1, pHeader.hash().hex().text());
        return true;
    }

    // Add/Verify block header
    Chain::HashStatus Chain::addHeader(Header &pHeader, unsigned int pMarkNodeID, uint8_t pLocks,
      bool pMainBranchOnly)
    {
        if(mInfo.invalidHashes.contains(pHeader.hash()))
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Predefined invalid hash : %s", pHeader.hash().hex().text());
            return INVALID;
        }

        if(!mInfo.spvMode && !(pLocks & LOCK_PENDING))
            mPendingLock.writeLock("Add Pending Header");
        if(!(pLocks & LOCK_HEADERS))
            mHeadersLock.writeLock("Add");

        if(pHeader.hash() == mLastHeaderHash)
        {
            if(!(pLocks & LOCK_HEADERS))
                mHeadersLock.writeUnlock();
            if(!mInfo.spvMode && !(pLocks & LOCK_PENDING))
                mPendingLock.writeUnlock();
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
              "Header is latest in chain : %s", pHeader.hash().hex().text());
            if(!mInfo.spvMode && pMarkNodeID != 0 && markBlockForNode(pHeader.hash(), pMarkNodeID))
                return BLOCK_NEEDED;
            else
                return ALREADY_HAVE;
        }

        // Remove pending header
        for(std::list<PendingHeaderData *>::iterator pendingHeader = mPendingHeaders.begin();
          pendingHeader != mPendingHeaders.end(); ++pendingHeader)
            if((*pendingHeader)->hash == pHeader.hash())
            {
                // NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
                  // "Removed pending header : %s", pHeader->hash.hex().text());
                delete *pendingHeader;
                mPendingHeaders.erase(pendingHeader);
                break;
            }

        if(mInvalidHashes.contains(pHeader.hash()))
        {
            if(!(pLocks & LOCK_HEADERS))
                mHeadersLock.writeUnlock();
            if(!mInfo.spvMode && !(pLocks & LOCK_PENDING))
                mPendingLock.writeUnlock();
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Rejecting invalid block hash : %s", pHeader.hash().hex().text());
            return INVALID;
        }
        else if(Forks::CASH_ACTIVATION_TIME != 0 && BTC_SPLIT_HASH == pHeader.hash())
        {
            // Manually reject BTC fork block hash.
            if(!(pLocks & LOCK_HEADERS))
                mHeadersLock.writeUnlock();
            if(!mInfo.spvMode && !(pLocks & LOCK_PENDING))
                mPendingLock.writeUnlock();
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
              "Rejecting BTC fork block header : %s", pHeader.hash().hex().text());
            return INVALID;
        }

        // This just checks that the proof of work meets the target bits in the header.
        //   The validity of the target bits value is checked before adding the full block to the chain.
        if(!pHeader.hasProofOfWork())
        {
            addInvalidHash(pHeader.hash());
            if(!(pLocks & LOCK_HEADERS))
                mHeadersLock.writeUnlock();
            if(!mInfo.spvMode && !(pLocks & LOCK_PENDING))
                mPendingLock.writeUnlock();
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Invalid proof of work : %s", pHeader.hash().hex().text());
            NextCash::Hash target;
            target.setDifficulty(pHeader.targetBits);
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Target                : %s", target.hex().text());
            return INVALID;
        }

        if(pHeader.previousHash == mLastHeaderHash)
        {
            if(!processHeader(pHeader))
            {
                if(!(pLocks & LOCK_HEADERS))
                    mHeadersLock.writeUnlock();
                if(!mInfo.spvMode && !(pLocks & LOCK_PENDING))
                    mPendingLock.writeUnlock();
                return INVALID;
            }

            if(!(pLocks & LOCK_HEADERS))
                mHeadersLock.writeUnlock();

            if(!mInfo.spvMode && mApprovedBlockHeight != 0xffffffff &&
              mPendingBlocks.size() < mInfo.pendingBlocks * 2)
            {
                // Add pending block if necessary.
                bool addPending = false;
                if(mPendingBlocks.size() == 0)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "No pending blocks. Block height %d", mNextBlockHeight - 1);
                    addPending = mNextBlockHeight == mNextHeaderHeight - 1;
                }
                else if(mPendingBlocks.back()->block->header.hash() == pHeader.previousHash)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Last of %d pending blocks : %s", mPendingBlocks.size(),
                      mPendingBlocks.back()->block->header.hash().hex().text());
                    addPending = true;
                }

                if(addPending)
                {
                    BlockReference reference(new Block(pHeader));
                    mPendingBlocks.push_back(new PendingBlockData(reference));
                    if(pMarkNodeID != 0)
                    {
                        mPendingBlocks.back()->requestingNode = pMarkNodeID;
                        mPendingBlocks.back()->requestedTime = getTime();
                    }
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Pending block added : %s", pHeader.hash().hex().text());
                    if(!(pLocks & LOCK_PENDING))
                        mPendingLock.writeUnlock();
                    return BLOCK_NEEDED;
                }
                else
                {
                    bool full = false;
                    for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
                      pending != mPendingBlocks.end(); ++pending)
                        if((*pending)->block->header.hash() == pHeader.hash())
                        {
                            full = (*pending)->isFull();
                            if(pMarkNodeID != 0)
                            {
                                (*pending)->requestingNode = pMarkNodeID;
                                (*pending)->requestedTime = getTime();
                            }
                            break;
                        }

                    if(!(pLocks & LOCK_PENDING))
                        mPendingLock.writeUnlock();
                    if(!full)
                        return BLOCK_NEEDED;
                    else
                        return HEADER_ADDED;
                }
            }

            if(!mInfo.spvMode && !(pLocks & LOCK_PENDING))
                mPendingLock.writeUnlock();
            return HEADER_ADDED;
        }

        if(headerAvailable(pHeader.hash()))
        {
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
              "Header already in chain : %s", pHeader.hash().hex().text());
            if(!(pLocks & LOCK_HEADERS))
                mHeadersLock.writeUnlock();
            if(!(pLocks & LOCK_PENDING))
                mPendingLock.writeUnlock();
            if(!mInfo.spvMode && pMarkNodeID != 0 && markBlockForNode(pHeader.hash(), pMarkNodeID))
                return BLOCK_NEEDED;
            else
                return ALREADY_HAVE;
        }

        if(pMainBranchOnly)
        {
            if(!(pLocks & LOCK_HEADERS))
                mHeadersLock.writeUnlock();
            if(!(pLocks & LOCK_PENDING))
                mPendingLock.writeUnlock();
            return INVALID;
        }

        // Check branches
        unsigned int branchID = 1;
        if(!(pLocks & LOCK_BRANCHES))
            mBranchLock.lock();
        for(std::vector<Branch *>::iterator branch = mBranches.begin(); branch != mBranches.end();
          ++branch, ++branchID)
        {
            if(pHeader.previousHash == (*branch)->pendingBlocks.back()->block->header.hash())
            {
                // Add at end of branch
                BlockReference reference(new Block(pHeader));
                (*branch)->addBlock(reference);
                unsigned int branchHeight = (*branch)->height + (*branch)->pendingBlocks.size() - 1;
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                  "Added header to branch %d (%d blocks) at height %d : %s", branchID,
                  (*branch)->pendingBlocks.size(), branchHeight, pHeader.hash().hex().text());
                if(!(pLocks & LOCK_BRANCHES))
                    mBranchLock.unlock();
                if(!(pLocks & LOCK_HEADERS))
                    mHeadersLock.writeUnlock();
                if(!(pLocks & LOCK_PENDING))
                    mPendingLock.writeUnlock();
                if(checkBranches())
                    return HEADER_ADDED;
                else
                {
                    if(branchHeight < headerHeight() && headerHeight() - branchHeight > 10)
                        return SHORT_CHAIN;
                    else
                        return HEADER_ADDED;
                }
            }

            unsigned int branchHeaderHeight = (*branch)->height;
            for(std::vector<PendingBlockData *>::iterator pending =
              (*branch)->pendingBlocks.begin(); pending != (*branch)->pendingBlocks.end();
              ++pending, ++branchHeaderHeight)
                if((*pending)->block->header.hash() == pHeader.hash())
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Header already in branch %d (%d blocks) at height %d : %s", branchID,
                      (*branch)->pendingBlocks.size(), branchHeaderHeight,
                      pHeader.hash().hex().text());
                    unsigned int branchHeight = (*branch)->height +
                      (*branch)->pendingBlocks.size() - 1;
                    if(!(pLocks & LOCK_BRANCHES))
                        mBranchLock.unlock();
                    if(!(pLocks & LOCK_HEADERS))
                        mHeadersLock.writeUnlock();
                    if(!(pLocks & LOCK_PENDING))
                        mPendingLock.writeUnlock();
                    if(branchHeight < headerHeight() && headerHeight() - branchHeight > 10)
                        return SHORT_CHAIN;
                    else
                        return HEADER_ADDED;
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
                    BlockReference reference(new Block(pHeader));
                    newBranch->addBlock(reference);
                    mBranches.push_back(newBranch);
                    if(!(pLocks & LOCK_BRANCHES))
                        mBranchLock.unlock();
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Started branch at height %d : %s", newBranch->height,
                      pHeader.hash().hex().text());
                    if(!(pLocks & LOCK_HEADERS))
                        mHeadersLock.writeUnlock();
                    if(!(pLocks & LOCK_PENDING))
                        mPendingLock.writeUnlock();
                    if(checkBranches())
                        return HEADER_ADDED;
                    else
                    {
                        if((unsigned int)chainHeight + 1 < headerHeight() &&
                          headerHeight() - chainHeight + 1 > 10)
                            return SHORT_CHAIN;
                        else
                            return HEADER_ADDED;
                    }
                }
                else if(chainHeight == 0)
                    break;
        }

        if(!(pLocks & LOCK_BRANCHES))
            mBranchLock.unlock();
        if(!(pLocks & LOCK_HEADERS))
            mHeadersLock.writeUnlock();
        if(!(pLocks & LOCK_PENDING))
            mPendingLock.writeUnlock();

        NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
          "Unknown header : %s", pHeader.hash().hex().text());
        return UNKNOWN;
    }

    void Chain::updateBlockProgress(const NextCash::Hash &pHash, unsigned int pNodeID, Time pTime)
    {
        mPendingLock.readLock();
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
            if((*pending)->block->header.hash() == pHash)
            {
                (*pending)->updateTime = pTime;
                (*pending)->requestingNode = pNodeID;
                break;
            }
        mPendingLock.readUnlock();
    }

    bool Chain::markBlockForNode(const NextCash::Hash &pHash, unsigned int pNodeID)
    {
        bool result = false;
        mPendingLock.readLock();
        Time time = getTime();
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
            if((*pending)->block->header.hash() == pHash)
            {
                if(!(*pending)->isFull() &&
                  ((*pending)->requestingNode == 0 || (*pending)->requestingNode == pNodeID))
                {
                    (*pending)->requestingNode = pNodeID;
                    (*pending)->requestedTime = time;
                    result = true;
                }
                break;
            }
        mPendingLock.readUnlock();
        return result;
    }

    void Chain::markBlocksForNode(NextCash::HashList &pHashes, unsigned int pNodeID)
    {
        mPendingLock.readLock();
        Time time = getTime();
        for(NextCash::HashList::iterator hash=pHashes.begin();hash!=pHashes.end();++hash)
            for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
              pending != mPendingBlocks.end(); ++pending)
                if((*pending)->block->header.hash() == *hash)
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
                  "Releasing block (%d) : %s", hashHeight((*pending)->block->header.hash()),
                  (*pending)->block->header.hash().hex().text());
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

    void Chain::releaseBlockForNode(const NextCash::Hash &pHash, unsigned int pNodeID)
    {
        mPendingLock.readLock();
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
            if((*pending)->block->header.hash() == pHash && !(*pending)->isFull() &&
              (*pending)->requestingNode == pNodeID)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                  "Releasing block (%d) : %s", hashHeight((*pending)->block->header.hash()),
                  (*pending)->block->header.hash().hex().text());
                (*pending)->requestingNode = 0;
                (*pending)->requestedTime = 0;
            }
        for(std::list<PendingHeaderData *>::iterator pendingHeader = mPendingHeaders.begin();
          pendingHeader != mPendingHeaders.end(); ++pendingHeader)
            if((*pendingHeader)->hash == pHash && (*pendingHeader)->requestingNode == pNodeID)
            {
                (*pendingHeader)->requestingNode = 0;
                (*pendingHeader)->requestedTime = 0;
            }
        mPendingLock.readUnlock();
    }

    bool Chain::needBlock(const NextCash::Hash &pHash)
    {
        mPendingLock.readLock();
        bool result = false;
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending)
            if((*pending)->block->header.hash() == pHash)
            {
                result = !(*pending)->isFull() && (*pending)->requestingNode == 0;
                break;
            }
        mPendingLock.readUnlock();
        return result;
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
                pHashes.push_back((*pending)->block->header.hash());
                if(pHashes.size() >= pCount)
                    break;
            }
        }
        mPendingLock.readUnlock();

        return pHashes.size() > 0;
    }

    bool Chain::processBlock(BlockReference &pBlock)
    {
        mProcessMutex.lock();

        // Pull status (precomputed data) from mempool.
        // Remove confirmed transactions from mempool.
        unsigned int pullCount = mMemPool.pull(pBlock->transactions);

        NextCash::Timer timer(true);
        bool success = true, fullyValidated = true;
        if(mApprovedBlockHeight >= mNextBlockHeight) // Just update transaction outputs
        {
            fullyValidated = false;
            if(pBlock->size() > 500000) // Enough to cover overhead of creating threads.
                success = pBlock->updateOutputsMultiThreaded(this, mNextBlockHeight,
                  mInfo.threadCount);
            else
                success = pBlock->updateOutputsSingleThreaded(this, mNextBlockHeight);

            if(!success)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to update approved block (%d) (%d trans) (%d KB) : %s",
                  mNextBlockHeight, pBlock->transactions.size(), pBlock->size() / 1000,
                  pBlock->header.hash().hex().text());
            }
        }
        else // Fully validate block
        {
#ifdef PROFILER_ON
            if(mNextBlockHeight == mApprovedBlockHeight + 1)
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                  "Resetting profilers for block validation mode");
                NextCash::printProfilerDataToLog(NextCash::Log::VERBOSE);
                NextCash::resetProfilers();
            }
#endif

            if(pBlock->size() > 250000) // Enough to cover overhead of creating threads.
                success = pBlock->processMultiThreaded(this, mNextBlockHeight, mInfo.threadCount);
            else
                success = pBlock->processSingleThreaded(this, mNextBlockHeight);

            if(!success)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to process block (%d) (%d trans) (%d KB) : %s",
                  mNextBlockHeight, pBlock->transactions.size(), pBlock->size() / 1000,
                  pBlock->header.hash().hex().text());
            }
        }

        if(!success)
        {
            mMemPool.revert(pBlock->transactions, true);
            mOutputs.revert(pBlock->transactions, mNextBlockHeight);
            revert(mNextBlockHeight - 1, LOCK_PROCESS);
            mProcessMutex.unlock();
            return false;
        }

        // Add the block to the chain
        if(!Block::add(mNextBlockHeight, pBlock.pointer()))
        {
            mMemPool.revert(pBlock->transactions, true);
            mOutputs.revert(pBlock->transactions, mNextBlockHeight);
#ifndef DISABLE_ADDRESSES
            mAddresses.remove(pBlock->transactions, mNextBlockHeight);
#endif
            revert(mNextBlockHeight - 1, LOCK_PROCESS);
            mProcessMutex.unlock();
            return false;
        }

        mMemPool.finalize(pBlock->transactions);

#ifndef DISABLE_ADDRESSES
        mAddresses.add(pBlock->transactions, mNextBlockHeight); // Update address database
#endif

        ++mNextBlockHeight;

        mProcessMutex.unlock();

        addBlockStat(pBlock, mNextBlockHeight - 1);

        timer.stop();

        if(fullyValidated)
        {
            unsigned int convertedPercent = 100;
            if(pBlock->transactions.size() > 1)
                convertedPercent = (unsigned int)(((double)pullCount /
                  (double)(pBlock->transactions.size() - 1)) * 100.0);

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Added validated block (%d) (%d trans) (%d KB) (%d ms) (%d%% conv) : %s",
              mNextBlockHeight - 1, pBlock->transactions.size(), pBlock->size() / 1000,
              timer.milliseconds(), convertedPercent, pBlock->header.hash().hex().text());
        }
        else
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Added approved block (%d) (%d trans) (%d KB) (%d ms) : %s",
              mNextBlockHeight - 1, pBlock->transactions.size(), pBlock->size() / 1000,
              timer.milliseconds(), pBlock->header.hash().hex().text());

        return true;
    }

    Chain::HashStatus Chain::addBlock(BlockReference &pBlock)
    {
        // Ensure header has been processed. For when block is seen before header.
        switch(addHeader(pBlock->header))
        {
        case HEADER_ADDED:
            updatePendingBlocks();
            break;
        case ALREADY_HAVE:
        case HEADER_NEEDED:
        case BLOCK_NEEDED:
        case BLOCK_ADDED:
            break;
        case SHORT_CHAIN:
        case INVALID:
        case UNKNOWN:
        default:
            return INVALID;
        }

        if(!pBlock->validate())
        {
            // Block is incomplete or has the wrong transactions.
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Block is invalid : %s", pBlock->header.hash().hex().text());
            return INVALID;
        }

        mPendingLock.writeLock("Add Block");

        unsigned int offset = 0;
        for(std::list<PendingBlockData *>::iterator pending = mPendingBlocks.begin();
          pending != mPendingBlocks.end(); ++pending, ++offset)
            if((*pending)->block->header.hash() == pBlock->header.hash())
            {
                if((*pending)->isFull())
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                      BITCOIN_CHAIN_LOG_NAME, "Block already received from [%d]: %s",
                      (*pending)->requestingNode, pBlock->header.hash().hex().text());
                    mPendingLock.writeUnlock();
                    return ALREADY_HAVE;
                }
                else
                {
                    if(!pBlock->checkSize(this, mNextBlockHeight + offset))
                    {
                        // Block is an invalid size and headers need to be reverted out.
                        addInvalidHash(pBlock->header.hash());
                        revert(mNextBlockHeight + offset, LOCK_PENDING);
                        mPendingLock.writeUnlock();
                        return INVALID;
                    }

                    mPendingSize -= (*pending)->block->size();
                    (*pending)->replace(pBlock);
                    mPendingSize += pBlock->size();
                    ++mPendingBlockCount;
                    if(offset > mLastFullPendingOffset)
                        mLastFullPendingOffset = offset;
                    mPendingLock.writeUnlock();
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Block added to pending : %s", pBlock->header.hash().hex().text());
                    return BLOCK_ADDED;
                }
            }

        mPendingLock.writeUnlock();

        // Check if it is in a branch
        unsigned int branchID = 1;
        unsigned int height;
        mBranchLock.lock();
        for(std::vector<Branch *>::iterator branch = mBranches.begin(); branch != mBranches.end();
          ++branch, ++branchID)
        {
            height = (*branch)->height;
            for(std::vector<PendingBlockData *>::iterator pending = (*branch)->pendingBlocks.begin();
              pending != (*branch)->pendingBlocks.end(); ++pending, ++height)
                if((*pending)->block->header.hash() == pBlock->header.hash())
                {
                    if((*pending)->isFull())
                    {
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                          "Block already received on branch %d from [%d]: %s", branchID,
                          (*pending)->requestingNode, pBlock->header.hash().hex().text());
                        unsigned int branchHeight = (*branch)->height +
                          (*branch)->pendingBlocks.size() - 1;
                        mBranchLock.unlock();
                        if(branchHeight < headerHeight() && headerHeight() - branchHeight > 10)
                            return SHORT_CHAIN;
                        else
                            return ALREADY_HAVE;
                    }
                    else
                    {
                        if(!pBlock->checkSize(this, height))
                        {
                            // Block is an invalid size and headers need to be reverted out.
                            addInvalidHash(pBlock->header.hash());
                            return INVALID;
                        }

                        (*pending)->replace(pBlock);
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                          "Block received on branch %d from [%d]: %s", branchID,
                          (*pending)->requestingNode, pBlock->header.hash().hex().text());
                        unsigned int branchHeight = (*branch)->height +
                          (*branch)->pendingBlocks.size() - 1;
                        mBranchLock.unlock();
                        if(branchHeight < headerHeight() && headerHeight() - branchHeight > 10)
                            return SHORT_CHAIN;
                        else
                            return ALREADY_HAVE;
                    }
                }
        }

        mBranchLock.unlock();
        return UNKNOWN;
    }

    bool Chain::process()
    {
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
            if(getTime() - mLastDataSaveTime > 10)
            {
                mLastDataSaveTime = getTime();
                Header::save();
                Block::save();
                mForks.save();
            }
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
            if(getTime() - mLastDataSaveTime > 10)
            {
                mLastDataSaveTime = getTime();
                Header::save();
                Block::save();
                mForks.save();
            }
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
        if(processBlock(nextPending->block))
        {
            if(isInSync())
            {
                mPendingLock.writeLock("Add Announce");
                mBlocksToAnnounce.push_back(nextPending->block);
                mPendingLock.writeUnlock();
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
            mInvalidNodeIDs.push_back(nextPending->requestingNode);
            // Add hash to invalid list. So it isn't downloaded again.
            addInvalidHash(nextPending->block->header.hash());
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
            if(!getHash(height, hash, true))
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
            if(!getHash(height, hash, true))
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
        unsigned int startingHeight;
        if (pStartingHash.isEmpty())
            startingHeight = 0;
        else
            startingHeight = hashHeight(pStartingHash);

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

    bool Chain::getHash(unsigned int pHeight, NextCash::Hash &pHash, uint8_t pLocks)
    {
        if(pHeight > headerHeight())
            return false;

        if(!(pLocks & LOCK_HEADERS))
            mHeadersLock.readLock();
#ifdef LOW_MEM
        unsigned int blocksFromTop = headerHeight() - pHeight;
        if(blocksFromTop < mLastHashes.size())
            pHash = mLastHashes[mLastHashes.size() - blocksFromTop - 1];
        else
        {
            if(!(pLocks & LOCK_HEADERS))
                mHeadersLock.readUnlock();
            return Header::getHash(pHeight, pHash); // Get hash from header file
        }
#else
        if(pHeight >= mHashes.size())
        {
            pHash.clear();
            if(!(pLocks & LOCK_HEADERS))
                mHeadersLock.readUnlock();
            return false;
        }

        pHash = mHashes[pHeight];
#endif
        if(!(pLocks & LOCK_HEADERS))
            mHeadersLock.readUnlock();
        return true;
    }

    BlockReference Chain::getBlock(unsigned int pHeight)
    {
        return BlockReference(Block::getBlock(pHeight));
    }

    BlockReference Chain::getBlock(const NextCash::Hash &pHash)
    {
        unsigned int thisBlockHeight = hashHeight(pHash);
        if(thisBlockHeight == 0xffffffff)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Get block failed. Hash not found : %s", pHash.hex().text());
            return BlockReference();
        }
        return BlockReference(Block::getBlock(thisBlockHeight));
    }

    bool Chain::getHeader(unsigned int pHeight, Header &pBlockHeader)
    {
        return Header::getHeader(pHeight, pBlockHeader);
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

    HeaderStat *Chain::blockStat(unsigned int pHeight)
    {
        if(pHeight == INVALID_HEIGHT)
            pHeight = mHeaderStatHeight;

        if(pHeight > mHeaderStatHeight || pHeight < (mHeaderStatHeight + 1) - mHeaderStats.size())
            return NULL;

        unsigned int statHeight = mHeaderStatHeight;
        std::list<HeaderStat>::iterator iter = --mHeaderStats.end();

        while(statHeight > pHeight)
        {
            --iter;
            --statHeight;
        }

        return &*iter;
    }

    int32_t Chain::version(unsigned int pHeight)
    {
        if(pHeight == INVALID_HEIGHT)
            pHeight = mHeaderStatHeight;

        if(pHeight > mHeaderStatHeight)
            return 0;

        HeaderStat *stat = blockStat(pHeight);
        if(stat != NULL)
            return stat->version;

        Header header;
        if(!Header::getHeader(pHeight, header))
            return 0;

        return header.version;
    }

    Time Chain::time(unsigned int pHeight)
    {
        if(pHeight == INVALID_HEIGHT)
            pHeight = mHeaderStatHeight;

        if(pHeight > mHeaderStatHeight)
            return 0;

        HeaderStat *stat = blockStat(pHeight);
        if(stat != NULL)
            return stat->time;

        Header header;
        if(!Header::getHeader(pHeight, header))
            return 0;

        return header.time;
    }

    uint32_t Chain::targetBits(unsigned int pHeight)
    {
        if(pHeight == INVALID_HEIGHT)
            pHeight = mHeaderStatHeight;

        if(pHeight > mHeaderStatHeight)
            return 0;

        HeaderStat *stat = blockStat(pHeight);
        if(stat != NULL)
            return stat->targetBits;

        Header header;
        if(!Header::getHeader(pHeight, header))
            return 0;

        return header.targetBits;
    }

    NextCash::Hash Chain::accumulatedWork(unsigned int pHeight)
    {
        if(pHeight == INVALID_HEIGHT)
            pHeight = mHeaderStatHeight;

        if(pHeight == 0 || pHeight > mHeaderStatHeight)
            return NextCash::Hash(32); // Zero hash

        HeaderStat *stat = blockStat(pHeight);
        if(stat != NULL)
            return stat->accumulatedWork;

        // Get nearest accumulated work, top or bottom, and calculate to correct block height
        NextCash::Hash target(32), blockWork(32), accumulatedWork(32);
        Header header;
        unsigned int accumulatedWorkHeight = (mHeaderStatHeight + 1 - mHeaderStats.size());

        accumulatedWork = mHeaderStats.front().accumulatedWork;

        while(accumulatedWorkHeight > pHeight)
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

    Time Chain::getMedianPastTime(unsigned int pHeight, unsigned int pMedianCount)
    {
        if(pHeight == INVALID_HEIGHT)
            pHeight = mHeaderStatHeight;

        if(pHeight > mHeaderStatHeight || pMedianCount > pHeight)
            return 0;

        std::vector<Time> times;
        for(unsigned int i = pHeight - pMedianCount + 1; i <= pHeight; ++i)
            times.push_back(time(i));

        // Sort times
        std::sort(times.begin(), times.end());

        // Return the median time
        return times[pMedianCount / 2];
    }

    bool blockStatTimeLessThan(const HeaderStat *pLeft, const HeaderStat *pRight)
    {
        return pLeft->time < pRight->time;
    }

    void Chain::getMedianPastTimeAndWork(unsigned int pHeight, Time &pTime,
      NextCash::Hash &pAccumulatedWork, unsigned int pMedianCount)
    {
        if(pHeight > mHeaderStatHeight || pMedianCount > pHeight)
        {
            pTime = 0;
            pAccumulatedWork.zeroize();
            return;
        }

        std::vector<HeaderStat *> values, toDelete;
        HeaderStat *newStat;
        for(unsigned int i = pHeight - pMedianCount + 1;
          i <= pHeight; ++i)
        {
            newStat = blockStat(i);
            if(newStat == NULL)
            {
                newStat = new HeaderStat();
                newStat->time = time(i);
                newStat->accumulatedWork = accumulatedWork(i);
                toDelete.push_back(newStat);
            }
            values.push_back(newStat);
        }

        // Sort
        std::sort(values.begin(), values.end(), blockStatTimeLessThan);

        // for(std::vector<HeaderStat *>::iterator item=values.begin();item!=values.end();++item)
        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_FORKS_LOG_NAME,
        // "Sorted stat median calculate time %d, work %s", (*item)->time, (*item)->accumulatedWork.hex().text());

        pTime = values[pMedianCount / 2]->time;
        pAccumulatedWork = values[pMedianCount / 2]->accumulatedWork;
        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_FORKS_LOG_NAME,
        // "Using median calculate time %d, work %s", pTime, pAccumulatedWork.hex().text());
        NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
          "Median accumulated time/work at height %d : %d %s", pHeight,
          pTime, pAccumulatedWork.hex().text());

        for(std::vector<HeaderStat *>::iterator stat = toDelete.begin(); stat != toDelete.end();
          ++stat)
            delete *stat;
    }

    unsigned int Chain::heightBefore(Time pTime)
    {
        unsigned int beginHeight = 0;
        unsigned int endHeight = headerHeight();
        if(endHeight - beginHeight <= 1)
            return beginHeight;
        if(pTime < time(beginHeight))
            return beginHeight;
        if(pTime > time(endHeight))
            return endHeight;

        // Binary search
        unsigned int currentHeight = beginHeight + ((endHeight - beginHeight) / 2);
        Time currentTime = time(currentHeight);

        while(true)
        {
            // Check which half the desired time is in.
            if(currentTime > pTime)
                endHeight = currentHeight;
            else if(currentTime < pTime)
                beginHeight = currentHeight;
            else
                return currentHeight;

            if(endHeight - beginHeight <= 1)
                return beginHeight;

            // Get new middle.
            currentHeight = beginHeight + ((endHeight - beginHeight) / 2);
            currentTime = time(currentHeight);
        }

        return beginHeight;
    }

    bool Chain::updateOutputs()
    {
        BlockReference block;
        NextCash::Timer timer;
        if(mOutputs.height() == 0xffffffff)
        {
            // Process genesis block
            timer.start();
            block = Block::getBlock(0);
            if(block)
            {
                if(block->updateOutputsSingleThreaded(this, 0))
                {
                    timer.stop();
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Updated outputs for genesis block (%d trans) (%d KB) (%d ms)",
                      block->transactions.size(), block->size() / 1000, timer.milliseconds());
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to update outputs for genesis block : %s",
                      block->header.hash().hex().text());
                    mOutputs.revert(block->transactions, 0);
                    mOutputs.saveFull(mInfo.threadCount);
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
          "Updating outputs from height %d to %d", currentHeight, blockHeight());

        Time lastCheckTime = getTime();
        bool success;
        while(currentHeight < blockHeight() && !mStopRequested)
        {
            ++currentHeight;

            timer.clear(true);
            block = Block::getBlock(currentHeight);
            if(block)
            {
                if(block->size() > 500000) // Enough to cover overhead of creating threads.
                    success = block->updateOutputsMultiThreaded(this, currentHeight,
                      mInfo.threadCount);
                else
                    success = block->updateOutputsSingleThreaded(this, currentHeight);

                timer.stop();
                if(success)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Updated outputs for block %d (%d trans) (%d KB) (%d ms)", currentHeight,
                      block->transactions.size(), block->size() / 1000, timer.milliseconds());
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                      "Failed to update outputs for block %d : %s", currentHeight,
                      block->header.hash().hex().text());
                    mOutputs.revert(block->transactions, currentHeight);
                    mOutputs.saveFull(mInfo.threadCount);
                    return false;
                }
            }
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to read block %d from block file", currentHeight);
                mOutputs.saveFull(mInfo.threadCount);
                return false;
            }

            if(getTime() - lastCheckTime > 60)
            {
                if(mOutputs.cacheNeedsTrim())
                {
                    if(!mOutputs.saveFull(mInfo.threadCount))
                        return false;
                }
                else
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                      "Outputs : %d K trans (%d K, %d KB cached)", mOutputs.size() / 1000,
                      mOutputs.cacheSize() / 1000, mOutputs.cacheDataSize() / 1000);

                lastCheckTime = getTime();
            }
        }

        mOutputs.saveFull(mInfo.threadCount);
        return mOutputs.height() == blockHeight();
    }

#ifndef DISABLE_ADDRESSES
    bool Chain::updateAddresses()
    {
        BlockReference block;
        milliseconds startTime;
        if(mAddresses.height() == 0xffffffff)
        {
            // Process genesis block
            startTime = getTimeMilliseconds();
            block = Block::getBlock(0);
            if(block)
            {
                mAddresses.add(block->transactions, 0);

                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Updated addresses for genesis block (%d trans) (%d KB) (%d ms)",
                  block->transactions.size(), block->size() / 1000,
                  getTimeMilliseconds() - startTime);
            }
        }

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

        Forks emptyForks;
        Time lastPurgeTime = getTime();
        milliseconds startTime;

        while(currentHeight <= blockHeight() && !mStopRequested)
        {
            ++currentHeight;

            block = Block::getBlock(currentHeight);
            if(block)
            {
                // NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  // "Processing block %d : %s", currentHeight, block.hash.hex().text());

                startTime = getTimeMilliseconds();

                mAddresses.add(block->transactions, currentHeight);

                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Updated addresses in block %d (%d trans) (%d KB) (%d ms)", currentHeight,
                  block->transactions.size(), block->size() / 1000,
                  getTimeMilliseconds() - startTime);
            }
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to get block %d from block file", currentHeight);
                mAddresses.save(mInfo.threadCount);
                return false;
            }

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
        if(mHeaderStats.size() > 0)
        {
            NextCash::String proofOfWorkTempFileName = mInfo.path();
            proofOfWorkTempFileName.pathAppend("pow.temp");
            NextCash::FileOutputStream proofOfWorkFile(proofOfWorkTempFileName, true);

            if(!proofOfWorkFile.isValid())
                return false;
            else
            {
                proofOfWorkFile.writeUnsignedInt(mHeaderStatHeight);
                mHeaderStats.back().accumulatedWork.write(&proofOfWorkFile);

                NextCash::String proofOfWorkFileName = mInfo.path();
                proofOfWorkFileName.pathAppend("pow");
                return NextCash::renameFile(proofOfWorkTempFileName, proofOfWorkFileName);
            }
        }

        return true;
    }

    bool Chain::save(bool pFast)
    {
        bool success = true;

        if(!saveAccumulatedWork())
            success = false;
        if(!mForks.save())
            success = false;
        if(!savePending())
            success = false;
        if(!saveData(pFast))
            success = false;
        return success;
    }

    bool Chain::saveData(bool pFast)
    {
        if(Info::instance().spvMode)
            return true;

        mSaveDataInProgress = true;

        Header::save();
        Block::save();

        bool success;
        if(pFast)
            success = mOutputs.saveCache();
        else
            success = mOutputs.saveFull(mInfo.threadCount);
#ifndef DISABLE_ADDRESSES
        if(!mAddresses.save(mInfo.threadCount))
            success = false;
#endif

        mSaveDataInProgress = false;
        return success;
    }

    bool Chain::savePending()
    {
        NextCash::String filePathName = Info::instance().path();
        filePathName.pathAppend("pending");

        mPendingLock.readLock();
        if(mPendingBlocks.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "No pending blocks to save");
            mPendingLock.readUnlock();
            NextCash::removeFile(filePathName);
            return true;
        }

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
        BlockReference newBlock;

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
                success = false;
                break;
            }

            NextCash::Hash nextHash(32);
            if(getHash(blockHeight() + mPendingBlocks.size(), nextHash, false) &&
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
        }

        file.close();
        NextCash::removeFile(filePathName);

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

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Validated block/header files to height of %d/%d", blockCount - 1, headerCount - 1);

        if(blockCount > headerCount)
        {
            // Revert blocks to latest header.
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Reverting blocks to valid header height %d", headerCount - 1);
            Block::revertToHeight(headerCount - 1);
            blockCount = headerCount;
        }

        mHeaderStatHeight = 0;
        mNextHeaderHeight = 0;
        mNextBlockHeight = blockCount;
        mLastHeaderHash.clear();
#ifdef LOW_MEM
        mLastHashes.clear();
#else
        mHashes.clear();
#endif
        clearHeaderStats();

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
            BlockReference genesisBlock(Block::genesis(mMaxTargetBits));

            addHeaderStat(genesisBlock->header.version, genesisBlock->header.time,
              genesisBlock->header.targetBits);
            mHeaderStatHeight = 0;

            if(!Header::add(0, genesisBlock->header))
            {
                mHeadersLock.writeUnlock();
                return false;
            }
            ++headerCount;

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Added genesis header to chain : %s", genesisBlock->header.hash().hex().text());

            if(blockCount == 0)
            {
                if(!Block::add(0, genesisBlock.pointer()))
                {
                    mHeadersLock.writeUnlock();
                    return false;
                }
                addBlockStat(genesisBlock, 0);
                ++blockCount;
                ++mNextBlockHeight;
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Added genesis block to chain : %s", genesisBlock->header.hash().hex().text());
            }
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
                    return false;
                }

                // Calculate previous block stats
                if(success)
                {
                    mHeaderStatHeight = accumulatedWorkHeight;
                    if(Header::getHeaderStatsReverse(accumulatedWorkHeight,
                      HEADER_STATS_CACHE_SIZE, mHeaderStats))
                    {
                        // Update accumulated work
                        for(std::list<HeaderStat>::reverse_iterator stat = mHeaderStats.rbegin();
                          stat != mHeaderStats.rend(); ++stat)
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

                Time lastReport = getTime();
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
            return false;

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

                success = success && updateBlockStats();
            }
            catch(std::bad_alloc &pBadAlloc)
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Failed to load. Bad allocation : %s", pBadAlloc.what());
                success = false;
            }
        }

        return success && loadPending();
    }

    bool Chain::updateBlockStats()
    {
        mBlockStatLock.lock();
        NextCash::String blockStatFileName = mInfo.path();
        blockStatFileName.pathAppend("block_statistics");
        NextCash::FileOutputStream blockStatFile(blockStatFileName, false, true);

        if(!blockStatFile.isValid())
        {
            mBlockStatLock.unlock();
            return false;
        }

        unsigned int blockStatHeight = blockStatFile.length() / BlockStat::DATA_SIZE;
        BlockReference block;
        BlockStat blockStat;
        Time lastReportTime = getTime();

        // Ensure a partial block was not written.
        blockStatFile.setWriteOffset(blockStatHeight * BlockStat::DATA_SIZE);

        while(blockStatHeight < mNextBlockHeight)
        {
            if(mStopRequested)
                break;

            if(getTime() - lastReportTime > 10)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Updating block stats : height %d", blockStatHeight);
                lastReportTime = getTime();
            }

            block = Block::getBlock(blockStatHeight);
            if(!block)
            {
                mBlockStatLock.unlock();
                return false;
            }

            blockStat.set(block, blockStatHeight);

            blockStat.write(&blockStatFile);
            ++blockStatHeight;
        }

        mBlockStatLock.unlock();
        return true;
    }

    bool Chain::addBlockStat(BlockReference &pBlock, unsigned int pHeight)
    {
        mBlockStatLock.lock();
        NextCash::String blockStatFileName = mInfo.path();
        blockStatFileName.pathAppend("block_statistics");
        NextCash::FileOutputStream blockStatFile(blockStatFileName);
        NextCash::stream_size offset = pHeight * BlockStat::DATA_SIZE;

        if(!blockStatFile.isValid() || blockStatFile.length() < offset)
        {
            mBlockStatLock.unlock();
            return false;
        }

        BlockStat blockStat(pBlock, pHeight);
        blockStatFile.setWriteOffset(offset);
        blockStat.write(&blockStatFile);
        blockStatFile.close();
        mBlockStatLock.unlock();
        return true;
    }

    bool Chain::getBlockStat(unsigned int pHeight, BlockStat &pBlockStat)
    {
        mBlockStatLock.lock();
        NextCash::String blockStatFileName = mInfo.path();
        blockStatFileName.pathAppend("block_statistics");
        NextCash::FileInputStream blockStatFile(blockStatFileName);
        NextCash::stream_size offset = pHeight * BlockStat::DATA_SIZE;

        if(!blockStatFile.isValid() || blockStatFile.length() < offset + BlockStat::DATA_SIZE)
        {
            mBlockStatLock.unlock();
            return false;
        }

        blockStatFile.setReadOffset(offset);
        bool success = pBlockStat.read(&blockStatFile);
        blockStatFile.close();
        mBlockStatLock.unlock();
        return success;
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

        if(genesis->header.hash() == checkHash)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Passed genesis block hash");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed genesis block hash");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Block hash   : %s", genesis->header.hash().hex().text());
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

        if(readGenesisBlock.header.hash() == checkHash)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Passed genesis block read hash");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed genesis block read hash");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Block hash   : %s", readGenesisBlock.header.hash().hex().text());
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
        Outputs outputs;
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

            if(readBlock.header.hash() == checkHash)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Passed read block hash");
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Failed read block hash");
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Block hash   : %s", readBlock.header.hash().hex().text());
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
            if(readBlock.processSingleThreaded(&chain, 1))
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
        // Outputs outputs;

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
        NextCash::printProfilerDataToLog(NextCash::Log::VERBOSE);
#endif
    }
}
