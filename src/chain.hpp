#ifndef BITCOIN_CHAIN_HPP
#define BITCOIN_CHAIN_HPP

#include "arcmist/base/string.hpp"
#include "arcmist/base/mutex.hpp"
#include "base.hpp"
#include "block.hpp"

#include <list>
#include <vector>
#include <stdlib.h>


namespace BitCoin
{
    class BlockList;
    class BlockFile;

    class BlockInfo
    {
    public:
        BlockInfo(const Hash &pHash, unsigned int pFileID, unsigned int pHeight)
        {
            hash = pHash;
            fileID = pFileID;
            height = pHeight;
        }

        Hash hash;
        unsigned int fileID;
        unsigned int height;

    private:
        BlockInfo(BlockInfo &pCopy);
        BlockInfo &operator = (BlockInfo &pRight);
    };

    class BlockSet : public std::list<BlockInfo *>, public ArcMist::Mutex
    {
    public:
        BlockSet() : Mutex("Block Set") {}
        ~BlockSet()
        {
            for(iterator info=begin();info!=end();++info)
                delete *info;
        }

        bool contains(Hash &pHash)
        {
            for(iterator info=begin();info!=end();++info)
                if((*info)->hash == pHash)
                    return true;
            return false;
        }

        void clear()
        {
            for(iterator info=begin();info!=end();++info)
                delete *info;
            std::list<BlockInfo *>::clear();
        }

    private:
        BlockSet(BlockSet &pCopy);
        BlockSet &operator = (BlockSet &pRight);
    };

    class PendingData
    {
    public:

        PendingData(Block *pBlock)
        {
            block = pBlock;
            requestedTime = 0;
            priority = 1;
            requestingNode = 0;
        }
        ~PendingData()
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
        bool isFull() { return block->transactionCount > 0; }

        unsigned int timeout();

        Block *block;
        uint64_t requestedTime;
        unsigned int priority;
        unsigned int requestingNode;

    private:
        PendingData(PendingData &pCopy);
        PendingData &operator = (PendingData &pRight);
    };

    class Chain
    {
    public:

        Chain();
        ~Chain();

        unsigned int blockHeight() const { return mNextBlockHeight - 1; }
        const Hash &lastBlockHash() const { return mLastBlockHash; }
        unsigned int pendingBlockHeight() const { return mNextBlockHeight - 1 + mPending.size(); }
        const Hash &lastPendingBlockHash() const { if(!mLastPendingHash.isEmpty()) return mLastPendingHash; return mLastBlockHash; }

        // Chain is up to date with most chains
        bool isInSync() { return false; }

        // Check if a block is already in the chain
        bool blockInChain(Hash &pHash) { return mBlockLookup[pHash.lookup()].contains(pHash); }
        // Check if a header has been downloaded
        bool headerAvailable(Hash &pHash);

        // Number of pending headers/blocks
        unsigned int pendingCount();
        // Number of pending full blocks
        unsigned int pendingBlockCount();
        // Bytes used by pending blocks
        unsigned int pendingSize();
        // Update priorities on pending data
        void prioritizePending();
        // Add block header to queue to be requested and downloaded
        bool addPendingHeader(Block *pBlock);
        // Save pending data to the file system
        bool savePending();
        // Load pending data from the file system
        bool loadPending();
        // Returns the hash of the next block needed
        Hash nextBlockNeeded(bool pReduceOnly);
        // Mark a block as requested
        void markBlockRequested(const Hash &pHash, unsigned int pNodeID);
        void markBlockNotRequested(const Hash &pHash);
        // Release all blocks requested by a specified node so they will be requested again
        void releaseBlocksForNode(unsigned int pNodeID);

        // Add block to queue to be processed and added to top of chain
        bool addPendingBlock(Block *pBlock);

        // Retrieve block hashes starting at a specific hash. (empty starting hash for first block)
        bool getBlockHashes(HashList &pHashes, const Hash &pStartingHash, unsigned int pCount);
        // Retrieve list of block hashes starting at top, going down and skipping around 100 between each.
        void getReverseBlockHashes(HashList &pHashes, unsigned int pCount);

        // Retrieve block headers starting at a specific hash. (empty starting hash for first block)
        bool getBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, const Hash &pStoppingHash, unsigned int pCount);

        // Get block or hash at specific height
        bool getBlockHash(unsigned int pHeight, Hash &pHash);
        bool getBlock(unsigned int pHeight, Block &pBlock);

        // Get the block or height for a specific hash
        unsigned int height(const Hash &pHash); // Returns 0xffffffff when hash is not found
        bool getBlock(const Hash &pHash, Block &pBlock);

        // Update the unspent transaction pool for any blocks it is missing
        // Note : Doesn't use block version flags
        bool updateUnspent(UnspentPool &pUnspentPool);

        // Load block data from file system
        //   If pList is true then all the block hashes will be output
        bool load(UnspentPool &pUnspentPool, bool pList);

        // Process pending headers and blocks
        void process(UnspentPool &pUnspentPool);

        // Validate the local block chain. Print output to log
        //   If pRebuildUnspent then it rebuilds unspent transactions
        bool validate(UnspentPool &pUnspentPool, bool pRebuildUnspent);

        static bool test();

    private:

        BlockSet mBlockLookup[0x10000];

        // Block headers for blocks not yet on chain
        ArcMist::Mutex mPendingMutex;
        std::list<PendingData *> mPending;
        Hash mLastPendingHash;
        unsigned int mPendingSize, mPendingBlocks;

        // Verify and process block then add it to the chain
        ArcMist::Mutex mProcessMutex;
        bool processBlock(Block *pBlock, UnspentPool &pUnspentPool);
        //TODO Remove orphaned blocks //bool removeBlock(const Hash &pHash);

        Hash mLastBlockHash; // Hash of last/top block on chain
        uint64_t mNextBlockHeight; // Number of next block that will be added to the chain

        // Blocks
        ArcMist::String blockFilePath();
        ArcMist::String blockFileName(unsigned int pID);
        unsigned int blockFileID(const Hash &pHash);
        void lockBlockFile(unsigned int pFileID);
        void unlockBlockFile(unsigned int pFileID);

        ArcMist::Mutex mBlockFileMutex;
        std::vector<unsigned int> mLockedBlockFileIDs;
        unsigned int mLastFileID;

        // Target
        uint32_t mTargetBits; // Current target bits
        uint32_t mLastTargetTime; // Time of last block that was used to update target
        uint32_t mLastBlockTime; // Time of last block
        uint32_t mLastTargetBits; // Target bits of last block
        // For reverting target
        uint32_t mRevertTargetBits;
        uint32_t mRevertLastTargetTime;
        uint32_t mRevertLastBlockTime;
        uint32_t mRevertLastTargetBits;

        // Update target bits based on new block
        bool updateTargetBits(unsigned int pHeight, uint32_t pNextBlockTime, uint32_t pNextBlockTargetBits);
        // Revert target bits to state before last update
        bool revertTargetBits();

        // Save/Load target bits state from file system
        bool saveTargetBits();
        bool loadTargetBits();

        // Last 2016 block's versions
        std::list<uint32_t> mBlockVersions;
        void addBlockVersion(uint32_t pVersion)
        {
            mBlockVersions.push_back(pVersion);
            if(mBlockVersions.size() > 2016)
                mBlockVersions.erase(mBlockVersions.begin());
        }
        uint32_t mBlockVersionFlags;
        void updateBlockVersionFlags();
        void updateTimeFlags();

        static Chain *sInstance;

    };
}

#endif
