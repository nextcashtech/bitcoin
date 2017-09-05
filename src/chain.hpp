#ifndef BITCOIN_HAIN_HPP
#define BITCOIN_CHAIN_HPP

#include "arcmist/base/string.hpp"
#include "arcmist/base/mutex.hpp"
#include "base.hpp"
#include "block.hpp"

#include <list>
#include <vector>


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
            for(std::list<BlockInfo *>::iterator iter=begin();iter!=end();++iter)
                delete *iter;
        }

        bool contains(Hash &pHash)
        {
            for(std::list<BlockInfo *>::iterator iter=begin();iter!=end();++iter)
                if((*iter)->hash == pHash)
                    return true;
            return false;
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

        uint64_t requestedTime;
        Block *block;

    private:
        PendingData(PendingData &pCopy);
        PendingData &operator = (PendingData &pRight);
    };

    class Chain
    {
    public:

        static Chain &instance();
        static void destroy();

        unsigned int blockHeight() const { return mNextBlockHeight - 1; }
        const Hash &lastBlockHash() const { return mLastBlockHash; }
        const Hash &lastPendingBlockHash() const { if(!mLastPendingHash.isEmpty()) return mLastPendingHash; return mLastBlockHash; }

        // All but most recent blocks are downloaded
        bool chainIsCurrent() { return false; }

        // Check if a block is already in the chain
        bool blockInChain(Hash &pHash) { return mBlockLookup[pHash.lookup()].contains(pHash); }
        // Check if a header has been downloaded
        bool headerAvailable(Hash &pHash);

        // Number of pending headers/blocks
        unsigned int pendingCount();
        // Add block header to queue to be requested and downloaded
        bool addPendingHeader(Block *pBlock);
        // Returns the hash of the next block needed
        Hash nextBlockNeeded();
        // Mark a block as requested
        void markBlockRequested(const Hash &pHash);

        // Add block to queue to be processed and added to top of chain
        bool addPendingBlock(Block *pBlock);

        // Retrieve block hashes starting at a specific hash. (empty starting hash for first block)
        void getBlockHashes(HashList &pHashes, const Hash &pStartingHash, unsigned int pCount);
        // Retrieve list of block hashes starting at top, going down and skipping around 100 between each.
        void getReverseBlockHashes(HashList &pHashes, unsigned int pCount);

        // Retrieve block headers starting at a specific hash. (empty starting hash for first block)
        void getBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, unsigned int pCount);

        // Get the block with a specific hash
        bool getBlockHash(unsigned int pHeight, Hash &pHash);
        bool getBlock(unsigned int pHeight, Block &pBlock);
        bool getBlock(const Hash &pHash, Block &pBlock);

        // Load block data from file system
        //   If pList is true then all the block hashes will be output
        bool loadBlocks(bool pList);

        // Process pending headers and blocks
        void process();

        // Validate the local block chain. Print output to log
        //   If pRebuildUnspent then it rebuilds unspent transactions
        bool validate(bool pRebuildUnspent);

        static bool test();

    private:

        Chain();
        ~Chain();

        BlockSet mBlockLookup[0xffff];

        // Block headers for blocks not yet on chain
        ArcMist::Mutex mPendingMutex;
        std::list<PendingData *> mPending;
        Hash mLastPendingHash;

        // Verify and process block then add it to the chain
        ArcMist::Mutex mProcessMutex;
        bool processBlock(Block *pBlock);
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

        static Chain *sInstance;

    };
}

#endif
