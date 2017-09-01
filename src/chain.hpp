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
    };

    class Chain
    {
    public:

        static Chain &instance();
        static void destroy();

        unsigned int blockCount() const { return mNextBlockHeight; }
        const Hash &lastBlockHash() const { return mLastBlockHash; }
        const Hash &lastPendingBlockHash() const { if(!mLastPendingHash.isEmpty()) return mLastPendingHash; return mLastBlockHash; }

        // All but most recent blocks are downloaded
        bool chainIsCurrent() { return false; }

        // Check if a block is already in the chain
        bool blockInChain(Hash &pHash) { return mBlockLookup[pHash.lookup()].contains(pHash); }
        // Check if a header has been downloaded
        bool headerAvailable(Hash &pHash);

        unsigned int pendingHeaders();
        // Add block header to queue to be requested and downloaded
        bool addPendingBlockHeader(Block *pBlock);
        // Returns the header of the next block needed
        Hash nextBlockNeeded();

        // Add block to queue to be processed and added to top of chain
        bool addPendingBlock(Block *pBlock);

        // Retrieve block hashes starting at a specific hash. (empty starting hash for first block)
        void getBlockHashes(HashList &pHashes, const Hash &pStartingHash, unsigned int pCount);
        // Retrieve list of block hashes starting at top, going down and skipping around 100 between each.
        void getReverseBlockHashes(HashList &pHashes, unsigned int pCount);

        // Retrieve block headers starting at a specific hash. (empty starting hash for first block)
        void getBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, unsigned int pCount);

        // Get the block with a specific hash
        bool getBlock(const Hash &pHash, Block &pBlock);

        // Load block data from file system
        bool loadBlocks();

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
        ArcMist::Mutex mPendingHeaderMutex;
        std::list<Block *> mPendingHeaders;




        //TODO Build queue of block headers and blocks that are sorted and have empty slots while waiting for them to download.
        //  Then they process as soon as the earliest are complete.

        //TODO Save block headers somewhere. Not necessarily files. Just don't request them from every node.
        //  Only inventory messages are needed to know if they have the needed blocks.




        // Blocks not yet verified and on chain
        ArcMist::Mutex mPendingBlockMutex;
        std::vector<Block *> mPendingBlocks;
        Hash mLastPendingHash;

        // Verify and process block then add it to the chain
        ArcMist::Mutex mProcessBlockMutex;
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

    class BlockList : public std::vector<Block *>
    {
    public:
        ~BlockList()
        {
            for(unsigned int i=0;i<size();i++)
                delete at(i);
        }
    };
}

#endif
