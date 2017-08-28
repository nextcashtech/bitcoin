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

        Block() : previousHash(32), merkleHash(32) { version = 4; }

        // Checks if block follows version specific validation rules
        bool versionIsValid(unsigned int pHeight);

        void write(ArcMist::OutputStream *pStream, bool pIncludeTransactions);
        bool read(ArcMist::InputStream *pStream, bool pIncludeTransactions);

        // Header
        uint32_t version;
        Hash previousHash;
        Hash merkleHash;
        uint32_t time;
        uint32_t bits;
        uint32_t nonce;

        // Transactions (empty when "header only")
        std::vector<Transaction> transactions;

        bool process();

    };

    class BlockList : public std::vector<Block *>
    {
    public:
        ~BlockList()
        {
            for(unsigned int i=0;i<size();i++)
                delete (at(i));
        }
    };

    class BlockFile;

    class BlockChain
    {
    public:

        static BlockChain &instance();
        static void destroy();

        ~BlockChain();

        unsigned int blockCount() { return mBlocks.size(); }
        bool addBlock(const Block &pBlock);

        // Retrieve block hashes starting at a specific hash. (zero starting hash for first block)
        void getBlockHashes(std::vector<Hash *> &pHashes, const Hash &pStartingHash, unsigned int pCount);

        // Retrieve block headers starting at a specific hash. (zero starting hash for first block)
        void getBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, unsigned int pCount);

        // Get the block with a specific hash
        bool getBlock(const Hash &pHash, Block &pBlock);

        static bool test();

    private:

        BlockChain();

        // Blocks
        ArcMist::Mutex mBlockMutex;
        class BlockInfo
        {
        public:
            BlockInfo(const Hash &pHash, unsigned int pFileID) { hash = pHash; fileID = pFileID; }
            Hash hash;
            unsigned int fileID;
        };
        BlockFile *mLastBlockFile;
        ArcMist::String blockFileName(unsigned int pID);
        std::list<BlockInfo *> mBlocks;
        bool loadBlocks();

        static BlockChain *sInstance;

    };
}

#endif
