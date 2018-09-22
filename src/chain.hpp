/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_CHAIN_HPP
#define BITCOIN_CHAIN_HPP

#include "string.hpp"
#include "hash.hpp"
#include "mutex.hpp"
#include "base.hpp"
#include "info.hpp"
#include "message.hpp"
#include "forks.hpp"
#include "block.hpp"
#include "outputs.hpp"
#include "mem_pool.hpp"
#ifndef DISABLE_ADDRESSES
#include "addresses.hpp"
#endif

#include <list>
#include <vector>
#include <stdlib.h>

#define HISTORY_BRANCH_CHECKING 5000


namespace BitCoin
{
    class Monitor;

    class HashInfo
    {
    public:
        HashInfo(const NextCash::Hash &pHash, int pBlockHeight)
        {
            hash   = pHash;
            height = pBlockHeight;
        }

        NextCash::Hash hash;
        int            height;

    private:
        HashInfo(HashInfo &pCopy);
        HashInfo &operator = (HashInfo &pRight);
    };

    class HashLookupSet : public std::list<HashInfo *>, public NextCash::MutexWithConstantName
    {
    public:
        HashLookupSet() : NextCash::MutexWithConstantName("Block Set") {}
        ~HashLookupSet()
        {
            for(iterator info = begin(); info != end(); ++info)
                delete *info;
        }

        bool contains(const NextCash::Hash &pHash) const
        {
            for(const_iterator info = begin(); info != end(); ++info)
                if((*info)->hash == pHash)
                    return true;
            return false;
        }

        void clear()
        {
            for(iterator info = begin(); info != end(); ++info)
                delete *info;
            std::list<HashInfo *>::clear();
        }

        bool remove(const NextCash::Hash &pHash)
        {
            for(iterator info = begin(); info != end(); ++info)
                if((*info)->hash == pHash)
                {
                    delete *info;
                    erase(info);
                    return true;
                }

            return false;
        }

        typedef std::list<HashInfo *>::iterator iterator;
        typedef std::list<HashInfo *>::const_iterator const_iterator;

    private:
        HashLookupSet(HashLookupSet &pCopy);
        HashLookupSet &operator = (HashLookupSet &pRight);
    };

    class PendingHeaderData
    {
    public:

        PendingHeaderData(const NextCash::Hash &pHash, unsigned int pNodeID, int32_t pTime)
        {
            hash = pHash;
            requestedTime = pTime;
            updateTime = pTime;
            requestingNode = pNodeID;
        }

        NextCash::Hash hash;
        int32_t requestedTime;
        int32_t updateTime;
        unsigned int requestingNode;

    private:
        PendingHeaderData(PendingHeaderData &pCopy);
        PendingHeaderData &operator = (PendingHeaderData &pRight);
    };

    class PendingBlockData
    {
    public:

        PendingBlockData(Block *pBlock)
        {
            block = pBlock;
            requestedTime = 0;
            updateTime = 0;
            requestingNode = 0;
        }
        ~PendingBlockData()
        {
            if(block != NULL)
                delete block;
        }

        void replace(Block *pBlock)
        {
            if(block != NULL)
                delete block;
            block = pBlock;
        }

        // Return true if this is a full block and not just a header
        bool isFull() { return block->transactions.size() > 0; }

        Block *block;
        int32_t requestedTime;
        int32_t updateTime;
        unsigned int requestingNode;

    private:
        PendingBlockData(PendingBlockData &pCopy);
        PendingBlockData &operator = (PendingBlockData &pRight);
    };

    /* Branches
     * When a valid header is seen that doesn't link to the top of the current chain it is
     *   saved and built on.
     * If it builds to more proof of work than the current chain before it gets too old then
     *   revert the current chain to the height of the branch and apply the branch. Also, turn
     *   the previous chain before above the branch into a branch in case it flips back and
     *   forth.
     */
    class Branch
    {
    public:

        Branch(unsigned int pBlockHeight, const NextCash::Hash &pWork) : accumulatedWork(pWork)
          { height = pBlockHeight; }
        ~Branch();

        void addBlock(Block *pBlock)
        {
            pendingBlocks.push_back(new PendingBlockData(pBlock));
            NextCash::Hash work(32);
            NextCash::Hash target(32);
            target.setDifficulty(pBlock->header.targetBits);
            target.getWork(work);
            accumulatedWork += work;
        }

        unsigned int height; // The chain height of the first block in the branch
        std::list<PendingBlockData *> pendingBlocks;
        NextCash::Hash accumulatedWork;
    };

    class Chain
    {
    public:

        Chain();
        ~Chain();

        unsigned int headerHeight() const
        {
            if(mNextHeaderHeight == 0)
                return 0;
            else
                return mNextHeaderHeight - 1;
        }
        unsigned int blockHeight() const
        {
            if(mNextBlockHeight == 0)
                return 0;
            else
                return mNextBlockHeight - 1;
        }
        NextCash::Hash lastHeaderHash()
        {
            mHeadersLock.readLock();
            NextCash::Hash result = mLastHeaderHash;
            mHeadersLock.readUnlock();
            return result;
        }
        unsigned int highestFullPendingHeight() const
          { return mLastFullPendingOffset + mNextBlockHeight - 1; }

        TransactionOutputPool &outputs() { return mOutputs; }
        Forks &forks() { return mForks; }
        MemPool &memPool() { return mMemPool; }
#ifndef DISABLE_ADDRESSES
        Addresses &addresses() { return mAddresses; }
#endif

        unsigned int memPoolRequests() const { return mMemPoolRequests; }
        void addMemPoolRequest() { ++mMemPoolRequests; }

        unsigned int branchCount() const { return mBranches.size(); }
        const Branch *branchAt(unsigned int pOffset) const
        {
            if(mBranches.size() <= pOffset)
                return NULL;
            else
                return mBranches[pOffset];
        }

        // Chain is up to date with most chains
        bool isInSync() { return mIsInSync; }
        void setInSync()
          { mIsInSync = true; mWasInSync = true; mInfo.setInitialBlockDownloadComplete(); }
        void clearInSync() { mIsInSync = false; }
        bool wasInSync() { return mWasInSync; }
        Block *blockToAnnounce();

        // Check if a block is already in the chain
        bool blockAvailable(const NextCash::Hash &pHash);
        // Check if a header has been downloaded
        bool headerAvailable(const NextCash::Hash &pHash);

        // Branches
        bool headerInBranch(const NextCash::Hash &pHash);

        // Return true if a header request at the top of the chain is needed
        bool headersNeeded();
        void setHeadersNeeded() { mHeadersNeeded = true; }
        bool blocksNeeded(); // Return true if a block request is needed

        unsigned int pendingCount();  // Number of pending headers/blocks
        unsigned int pendingBlockCount();  // Number of pending full blocks
        unsigned int pendingSize();  // Bytes used by pending blocks

        bool getPendingHeaderHashes(NextCash::HashList &pList);

        enum HashStatus { ALREADY_HAVE, NEED_HEADER, NEED_BLOCK, BLACK_LISTED };

        // Return the status of the specified block hash
        HashStatus addPendingHash(const NextCash::Hash &pHash, unsigned int pNodeID);

        // Builds a list of blocks that need to be requested and marks them as requested by the node
        //   specified
        bool getBlocksNeeded(NextCash::HashList &pHashes, unsigned int pCount, bool pReduceOnly);
        // Mark that download progress has increased for this block
        void updateBlockProgress(const NextCash::Hash &pHash, unsigned int pNodeID, int32_t pTime);
        // Mark blocks as requested by the specified node
        void markBlocksForNode(NextCash::HashList &pHashes, unsigned int pNodeID);
        // Release all blocks requested by a specified node so they will be requested again
        void releaseBlocksForNode(unsigned int pNodeID);

        // Add header/block to queue to be processed and added to top of chain
        //   Returns:
        //      < 0 Invalid/unknown block/header
        //     == 0  Block/header added
        //      > 0  Valid block/header not added (i.e. already have)
        int addHeader(Header &pHeader, bool pHeadersLocked = false, bool pBranchesLocked = false);
        int addBlock(Block *pBlock);

        // Retrieve block hashes starting at a specific hash. (empty starting hash for first block)
        bool getHashes(NextCash::HashList &pHashes, const NextCash::Hash &pStartingHash,
          unsigned int pCount);
        // Retrieve list of block hashes starting at top, going down and skipping around 100 between
        //   each.
        bool getReverseHashes(NextCash::HashList &pHashes, unsigned int pOffset,
          unsigned int pCount, unsigned int pSpacing);

        // Retrieve block headers starting at a specific hash. (empty starting hash for first block)
        bool getHeaders(HeaderList &pBlockHeaders, const NextCash::Hash &pStartingHash,
          const NextCash::Hash &pStoppingHash, unsigned int pCount);

        // Get block or hash at specific height
        bool getHash(unsigned int pBlockHeight, NextCash::Hash &pHash);
        bool getBlock(unsigned int pBlockHeight, Block &pBlock);
        bool getHeader(unsigned int pBlockHeight, Header &pHeader);

        // Returns 0xffffffff when hash is not found
        unsigned int hashHeight(const NextCash::Hash &pHash);

        bool getBlock(const NextCash::Hash &pHash, Block &pBlock);
        bool getHeader(const NextCash::Hash &pHash, Header &pHeader);

        int32_t version(unsigned int pBlockHeight);
        int32_t time(unsigned int pBlockHeight);
        uint32_t targetBits(unsigned int pBlockHeight);
        NextCash::Hash accumulatedWork(unsigned int pBlockHeight);

        int32_t getMedianPastTime(unsigned int pBlockHeight, unsigned int pMedianCount);

        void getMedianPastTimeAndWork(unsigned int pBlockHeight, int32_t &pTime,
          NextCash::Hash &pAccumulatedWork, unsigned int pMedianCount);

        // Return height of last block before specified time.
        unsigned int heightBefore(int32_t pTime);

        bool load();
        bool save();

        // Save transaction outputs and addresses databases.
        bool saveData();
#ifndef DISABLE_ADDRESSES
        bool saveDataNeeded() { return mOutputs.cacheNeedsTrim() || mAddresses.needsPurge(); }
#else
        bool saveDataNeeded() { return mOutputs.cacheNeedsTrim(); }
#endif
        bool saveDataInProgress() const { return mSaveDataInProgress; }

        // Process pending headers and blocks.
        // Returns true if it did something.
        bool process();

        std::vector<unsigned int> blackListedNodeIDs();

        // Set flag to stop processing
        void requestStop() { mStopRequested = true; }

        // For testing only
        void setMaxTargetBits(uint32_t pMaxTargetBits) { mMaxTargetBits = pMaxTargetBits; }
        static bool test();
        static void tempTest();

        void setMonitor(Monitor &pMonitor) { mMonitor = &pMonitor; }

    private:

        static NextCash::Hash sBTCForkBlockHash;

        TransactionOutputPool mOutputs;
#ifndef DISABLE_ADDRESSES
        Addresses mAddresses;
#endif
        Info &mInfo;
#ifndef LOW_MEM
        NextCash::HashList mHashes;
#else
        NextCash::HashList mLastHashes;
        static const int RECENT_BLOCK_COUNT = 5000;
#endif

        HashLookupSet mHashLookup[0x10000];

        // Block headers for blocks not yet on chain
        NextCash::ReadersLock mPendingLock;
        std::list<PendingBlockData *> mPendingBlocks;
        unsigned int mPendingSize, mPendingBlockCount, mLastFullPendingOffset;

        // Save pending data to the file system
        bool savePending();
        // Load pending data from the file system
        bool loadPending();

        // Update the transaction outputs for any blocks it is missing
        bool updateOutputs();

#ifndef DISABLE_ADDRESSES
        // Update the transaction addresses for any blocks it is missing
        bool updateAddresses();
#endif

        Monitor *mMonitor;

        // Verify and process block then add it to the chain
        NextCash::MutexWithConstantName mProcessMutex;
        bool mStopRequested;
        bool mIsInSync, mWasInSync;
        bool mHeadersNeeded;
        bool mSaveDataInProgress;

        NextCash::ReadersLock mHeadersLock;
        std::list<PendingHeaderData *> mPendingHeaders;
        unsigned int mNextHeaderHeight;
        NextCash::Hash mLastHeaderHash;
        uint32_t mMaxTargetBits;

        // Block height of approved header hash.
        //   0x00000000 - Not set (fully validating all blocks)
        //   0xffffffff - Not found yet
        unsigned int mApprovedBlockHeight;

        void updatePendingBlocks();

        // Revert to a lower height
        bool revert(unsigned int pHeight, bool pHeadersLocked = false);
        bool revertFileHeight(unsigned int pHeight);

        uint32_t calculateTargetBits(); // Calculate required target bits for new header.
        bool processHeader(Header &pHeader); // Validate header and add it to the chain.

        unsigned int mBlockStatHeight; // Height of block referenced by last item in mBlockStats.
        std::list<BlockStat> mBlockStats;

        Forks mForks; // Info about soft and hard fork states.

        BlockStat *blockStat(unsigned int pBlockHeight); // Get block stat for height.
        void addBlockStat(int32_t pVersion, int32_t pTime, uint32_t pTargetBits);
        void revertLastBlockStat();
        void clearBlockStats();
        bool saveAccumulatedWork();

        unsigned int mNextBlockHeight; // Number of next block that will be added to the chain.

        bool processBlock(Block &pBlock);

        MemPool mMemPool;
        unsigned int mMemPoolRequests;

        NextCash::HashList mBlocksToAnnounce;
        Block *mAnnounceBlock;

        // Block header hashes that have been proven invalid.
        NextCash::HashList mBlackListHashes;
        std::vector<unsigned int> mBlackListedNodeIDs;

        void addBlackListedHash(const NextCash::Hash &pHash);

        // Branches being monitored for possible future most proof of work
        std::vector<Branch *> mBranches;
        NextCash::Mutex mBranchLock;

        // Check if a branch has more accumulated proof of work than the main chain
        bool checkBranches();

    };
}

#endif
