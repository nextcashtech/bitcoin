#ifndef BITCOIN_BLOCK_HPP
#define BITCOIN_BLOCK_HPP

#include "arcmist/base/mutex.hpp"
#include "arcmist/base/string.hpp"
#include "arcmist/io/stream.hpp"
#include "base.hpp"
#include "transaction.hpp"


namespace BitCoin
{
    class Block
    {
    public:

        Block() : previousHash(32), merkleHash(32) { version = 4; transactionCount = 0; }

        // Checks if block follows version specific validation rules
        bool versionIsValid(unsigned int pHeight);

        void write(ArcMist::OutputStream *pStream, bool pIncludeTransactions);

        // pCalculateHash will calculate the hash of the block data while it reads it
        bool read(ArcMist::InputStream *pStream, bool pIncludeTransactions, bool pCalculateHash = true);

        // Hash
        Hash hash;

        // Header
        uint32_t version;
        Hash previousHash;
        Hash merkleHash;
        uint32_t time;
        uint32_t bits;
        uint32_t nonce;
        uint64_t transactionCount;

        // Transactions (empty when "header only")
        std::vector<Transaction> transactions;

        void calculateHash();
        bool process(UnspentPool &pUnspentPool);

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

        unsigned int blockCount() const { return mLastBlockID; }
        Hash lastBlockHash() const { return mLastBlockHash; }

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

        void process();

        static bool test();

    private:

        BlockChain();
        ~BlockChain();

        // Blocks
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
        bool processBlock(Block *pBlock);

        Hash mLastBlockHash;
        unsigned int mLastBlockID;

        ArcMist::Mutex mBlockFileMutex;
        void lockFile(unsigned int pFileID);
        void unlockFile(unsigned int pFileID);
        unsigned int mLastFileID;
        
        bool loadBlocks();

        static BlockChain *sInstance;

    };
}

#endif
