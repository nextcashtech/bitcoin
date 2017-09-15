#ifndef BITCOIN_BLOCK_HPP
#define BITCOIN_BLOCK_HPP

#include "arcmist/base/log.hpp"
#include "arcmist/io/stream.hpp"
#include "arcmist/io/file_stream.hpp"
#include "base.hpp"
#include "transaction.hpp"


namespace BitCoin
{
    class Block
    {
    public:

        Block() : previousHash(32), merkleHash(32) { version = 4; transactionCount = 0; mFees = 0; mSize = 0; }
        ~Block();

        // Verify hash is lower than target difficulty specified by targetBits
        bool hasProofOfWork();

        void write(ArcMist::OutputStream *pStream, bool pIncludeTransactions, bool pIncludeTransactionCount = true);

        // pCalculateHash will calculate the hash of the block data while it reads it
        bool read(ArcMist::InputStream *pStream, bool pIncludeTransactions, bool pCalculateHash = true);

        void clear();

        // Print human readable version to log
        void print(ArcMist::Log::Level pLevel = ArcMist::Log::DEBUG, bool pIncludeTransactions = true);

        // Hash
        Hash hash;

        // Header
        int32_t version;
        Hash previousHash;
        Hash merkleHash;
        uint32_t time;
        uint32_t targetBits;
        uint32_t nonce;
        uint64_t transactionCount;

        // Transactions (empty when "header only")
        std::vector<Transaction *> transactions;

        // Total of fees collected from transactions (set during process), not including coin base
        uint64_t fees() const { return mFees; }
        unsigned int size() const { return mSize; }

        void calculateHash();
        void calculateMerkleHash(Hash &pMerkleHash);
        bool process(UnspentPool &pUnspentPool, uint64_t pBlockHeight, int32_t pBlockVersionFlags);

        // Amount of Satoshis generated for mining a block at this height
        static uint64_t coinBaseAmount(uint64_t pBlockHeight);

        // Generate the Genesis block for the chain
        static Block *genesis();

    private:

        uint64_t mFees;
        unsigned int mSize;

        Block(Block &pCopy);
        Block &operator = (Block &pRight);

    };

    class BlockList : public std::vector<Block *>
    {
    public:
        BlockList() {}
        ~BlockList()
        {
            for(iterator block=begin();block!=end();++block)
                delete *block;
        }

        void clear()
        {
            for(iterator block=begin();block!=end();++block)
                delete *block;
            std::vector<Block *>::clear();
        }

    private:
        BlockList(BlockList &pCopy);
        BlockList &operator = (BlockList &pRight);
    };

    class BlockFile
    {
    public:
        /* File format
         *   Version = "AMBLKS01"
         *   CRC32 of data after CRC in file
         *   MAX_BLOCKS x Headers (32 byte block hash, 4 byte offset into file of block data)
         *   n x Blocks in default read/write stream "network" format (where n <= MAX_BLOCKS)
         */
        static const unsigned int MAX_BLOCKS = 100;
        static const unsigned int CRC_OFFSET = 8;
        static const unsigned int HASHES_OFFSET = 12;
        static const unsigned int HEADER_ITEM_SIZE = 36; // 32 byte hash, 4 byte data offset
        static constexpr const char *START_STRING = "AMBLKS01";

        // Create a new block file. BlockFile objects will be invalid if the block file doesn't already exist
        static BlockFile *create(unsigned int pID, const char *pFilePathName);

        BlockFile(unsigned int pID, const char *pFilePathName);
        ~BlockFile() { updateCRC(); if(mInputFile != NULL) delete mInputFile; }

        unsigned int id() const { return mID; }
        bool isValid() const { return mValid; }
        bool isFull() const { return mCount == MAX_BLOCKS; }
        unsigned int blockCount() const { return mCount; }
        const Hash &lastHash() const { return mLastHash; }

        // Add a block to the file
        bool addBlock(Block &pBlock);

        //TODO Remove blocks from file when they are orphaned

        // Read block at specified offset in file. Return false if the offset is too high.
        bool readHash(unsigned int pOffset, Hash &pHash);
        bool readBlock(unsigned int pOffset, Block &pBlock, bool pIncludeTransactions);

        // Read list of block hashes from this file. If pStartingHash is empty then start with first block
        bool readBlockHashes(HashList &pHashes);
        bool readVersions(std::list<uint32_t> &pVersions);

        // Read list of block headers from this file. If pStartingHash is empty then start with first block
        bool readBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash,
          const Hash &pStoppingHash, unsigned int pCount);

        // Read block for specified hash
        bool readBlock(const Hash &pHash, Block &pBlock, bool pIncludeTransactions);

        // Give the offset of a specific hash into the file
        unsigned int hashOffset(const Hash &pHash);

        void updateCRC();

    private:

        // Open and validate a file stream for reading
        bool openFile();

        unsigned int mID;
        ArcMist::FileInputStream *mInputFile;
        ArcMist::String mFilePathName;
        bool mValid;
        Hash mLastHash;
        unsigned int mCount;
        bool mModified;

        BlockFile(BlockFile &pCopy);
        BlockFile &operator = (BlockFile &pRight);

    };
}

#endif
