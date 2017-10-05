/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_BLOCK_HPP
#define BITCOIN_BLOCK_HPP

#include "arcmist/base/log.hpp"
#include "arcmist/io/stream.hpp"
#include "arcmist/io/file_stream.hpp"
#include "base.hpp"
#include "forks.hpp"
#include "transaction.hpp"
#include "outputs.hpp"


namespace BitCoin
{
    class Block
    {
    public:

        Block() : previousHash(32), merkleHash(32) { version = 4; transactionCount = 0; mFees = 0; mSize = 0; }
        ~Block();

        // Verify hash is lower than target difficulty specified by targetBits
        bool hasProofOfWork();

        void write(ArcMist::OutputStream *pStream, bool pIncludeTransactions, bool pIncludeTransactionCount,
          bool pBlockFile = false);

        // pCalculateHash will calculate the hash of the block data while it reads it
        bool read(ArcMist::InputStream *pStream, bool pIncludeTransactions, bool pIncludeTransactionCount,
          bool pCalculateHash, bool pBlockFile = false);

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

        bool process(TransactionOutputPool &pOutputs, int pBlockHeight, const BlockStats &pBlockStats,
          const Forks &pForks);

        bool updateOutputs(TransactionOutputPool &pOutputs, int pBlockHeight);

        // Amount of Satoshis generated for mining a block at this height
        static uint64_t coinBaseAmount(int pBlockHeight);

        // Create the Genesis block
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

        // Blocks
        static const ArcMist::String &path();
        static ArcMist::String fileName(unsigned int pID);
        static void lock(unsigned int pFileID);
        static void unlock(unsigned int pFileID);

        static const unsigned int MAX_BLOCKS = 100; // Maximum count of blocks in one file

        // Get block from appropriate block file
        static bool readBlock(unsigned int pHeight, Block &pBlock);

        // Get transaction output from appropriate block file
        static bool readOutput(TransactionReference *pReference, unsigned int pIndex, Output &pOutput);

        // Create a new block file. BlockFile objects will be invalid if the block file doesn't already exist
        static BlockFile *create(unsigned int pID, const char *pFilePathName);

        BlockFile(unsigned int pID, const char *pFilePathName, bool pValidate = true);
        ~BlockFile() { updateCRC(); if(mInputFile != NULL) delete mInputFile; }

        unsigned int id() const { return mID; }
        bool isValid() const { return mValid; }
        bool isFull() { return blockCount() == MAX_BLOCKS; }
        unsigned int blockCount() { getLastCount(); return mCount; }
        const Hash &lastHash() { getLastCount(); return mLastHash; }

        // Add a block to the file
        bool addBlock(Block &pBlock);

        //TODO Remove blocks from file when they are orphaned

        // Read block at specified offset in file. Return false if the offset is too high.
        bool readHash(unsigned int pOffset, Hash &pHash);
        bool readBlock(unsigned int pOffset, Block &pBlock, bool pIncludeTransactions);

        // Read list of block hashes from this file. If pStartingHash is empty then start with first block
        bool readBlockHashes(HashList &pHashes);

        // Append block stats from this file to the list specified
        bool readStats(BlockStats &pStats);

        // Read list of block headers from this file. If pStartingHash is empty then start with first block
        bool readBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash,
          const Hash &pStoppingHash, unsigned int pCount);

        // Read block for specified hash
        bool readBlock(const Hash &pHash, Block &pBlock, bool pIncludeTransactions);

        // Read transaction output at specified offset in file
        bool readTransactionOutput(unsigned int pFileOffset, Output &pTransactionOutput);

        // Give the offset of a specific hash into the file
        unsigned int hashOffset(const Hash &pHash);

        void updateCRC();

    private:

        /* File format
         *   Version = "AMBLKS01"
         *   CRC32 of data after CRC in file
         *   MAX_BLOCKS x Headers (32 byte block hash, 4 byte offset into file of block data)
         *   n x Blocks in default read/write stream "network" format (where n <= MAX_BLOCKS)
         */
        static const unsigned int CRC_OFFSET = 8;
        static const unsigned int HASHES_OFFSET = 12;
        static const unsigned int HEADER_ITEM_SIZE = 36; // 32 byte hash, 4 byte data offset
        static constexpr const char *START_STRING = "AMBLKS01";
        static const unsigned int INVALID_COUNT = 0xffffffff;

        // Open and validate a file stream for reading
        bool openFile();

        unsigned int mID;
        ArcMist::FileInputStream *mInputFile;
        ArcMist::String mFilePathName;
        bool mValid;
        bool mModified;

        void getLastCount();
        unsigned int mCount;
        Hash mLastHash;

        static ArcMist::Mutex mBlockFileMutex;
        static std::vector<unsigned int> mLockedBlockFileIDs;
        static ArcMist::String mBlockFilePath;

        BlockFile(BlockFile &pCopy);
        BlockFile &operator = (BlockFile &pRight);

    };
}

#endif
