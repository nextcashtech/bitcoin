#ifndef BITCOIN_BLOCK_CHAIN_HPP
#define BITCOIN_BLOCK_CHAIN_HPP

#include "arcmist/base/string.hpp"
#include "arcmist/base/mutex.hpp"
#include "base.hpp"
#include "block.hpp"

#include <list>
#include <vector>


namespace BitCoin
{
    class BlockList : public std::vector<Block *>
    {
    public:
        ~BlockList()
        {
            for(unsigned int i=0;i<size();i++)
                delete at(i);
        }
    };

    class BlockInfo
    {
    public:
        BlockInfo(const Hash &pHash, unsigned int pFileID) { hash = pHash; fileID = pFileID; }
        Hash hash;
        unsigned int fileID;
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
    };

    class BlockFile;

    class BlockChain
    {
    public:

        static BlockChain &instance();
        static void destroy();

        unsigned int blockCount() const { return mNextBlockID; }
        Hash lastBlockHash() const { return mLastBlockHash; }
        Hash lastPendingBlockHash() const { if(!mLastPendingHash.isEmpty()) return mLastPendingHash; return mLastBlockHash; }

        Hash lastBlockHeaderHash()
        {
            Hash result;
            mPendingBlockHeaderMutex.lock();
            if(mPendingBlockHeaders.size() > 0)
                result = mPendingBlockHeaders.back()->hash;
            else
                result = mLastBlockHash;
            mPendingBlockHeaderMutex.unlock();
            return result;
        }

        // Add block header to queue to be requested and downloaded
        bool addPendingBlockHeader(Block *pBlock);
        Block *nextBlockNeeded(); // Returns the header of the next block needed

        // Add block to queue to be processed and added to top of chain
        bool addPendingBlock(Block *pBlock);

        // Retrieve block hashes starting at a specific hash. (empty starting hash for first block)
        void getBlockHashes(HashList &pHashes, const Hash &pStartingHash, unsigned int pCount);

        // Retrieve block headers starting at a specific hash. (empty starting hash for first block)
        void getBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, unsigned int pCount);

        // Get the block with a specific hash
        bool getBlock(const Hash &pHash, Block &pBlock);

        // Load block data from file system
        bool loadBlocks();

        // Process pending headers and blocks
        void process();

        static bool test();

    private:

        BlockChain();
        ~BlockChain();

        // Blocks
        ArcMist::String blockFilePath();
        ArcMist::String blockFileName(unsigned int pID);
        unsigned int getFileID(const Hash &pHash);
        BlockSet mSets[0xffff];
        std::vector<unsigned int> mLockedFileIDs;

        // Block headers to request blocks
        ArcMist::Mutex mPendingBlockHeaderMutex;
        std::list<Block *> mPendingBlockHeaders;

        // Pending Blocks
        ArcMist::Mutex mPendingBlockMutex;
        std::vector<Block *> mPendingBlocks;
        Hash mLastPendingHash;

        // Process block and add it to the chain if it is valid
        ArcMist::Mutex mProcessBlockMutex;
        bool processBlock(Block *pBlock);

        Hash mLastBlockHash;
        uint64_t mNextBlockID;

        ArcMist::Mutex mBlockFileMutex;
        void lockFile(unsigned int pFileID);
        void unlockFile(unsigned int pFileID);
        unsigned int mLastFileID;

        static BlockChain *sInstance;

    };
}

#endif
