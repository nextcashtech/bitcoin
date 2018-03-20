/**************************************************************************
 * Copyright 2017 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_BLOCK_HPP
#define BITCOIN_BLOCK_HPP

#include "nextcash/base/hash.hpp"
#include "nextcash/base/log.hpp"
#include "nextcash/io/stream.hpp"
#include "nextcash/io/file_stream.hpp"
#include "base.hpp"
#include "forks.hpp"
#include "transaction.hpp"
#include "outputs.hpp"
#include "bloom_filter.hpp"


namespace BitCoin
{
    class Block
    {
    public:

        Block() : previousHash(32), merkleHash(32) { version = 4; transactionCount = 0; mFees = 0; mSize = 0; }
        ~Block();

        // Verify hash is lower than target difficulty specified by targetBits
        bool hasProofOfWork();

        void write(NextCash::OutputStream *pStream, bool pIncludeTransactions, bool pIncludeTransactionCount,
          bool pBlockFile = false);

        // pCalculateHash will calculate the hash of the block data while it reads it
        bool read(NextCash::InputStream *pStream, bool pIncludeTransactions, bool pIncludeTransactionCount,
          bool pCalculateHash, bool pBlockFile = false);

        void clear();

        // Print human readable version to log
        void print(NextCash::Log::Level pLevel = NextCash::Log::DEBUG, bool pIncludeTransactions = true);

        // Hash
        NextCash::Hash hash;

        // Header
        int32_t version;
        NextCash::Hash previousHash;
        NextCash::Hash merkleHash;
        uint32_t time;
        uint32_t targetBits;
        uint32_t nonce;
        uint64_t transactionCount;

        // Transactions (empty when "header only")
        std::vector<Transaction *> transactions;

        // Total of fees collected from transactions (set during process), not including coin base
        uint64_t fees() const { return mFees; }
        unsigned int size() const { return mSize; }

        uint64_t actualCoinbaseAmount(); // Amount from coinbase transaction

        void calculateHash();
        void calculateMerkleHash(NextCash::Hash &pMerkleHash);

        bool process(TransactionOutputPool &pOutputs, int pBlockHeight, const BlockStats &pBlockStats,
          const Forks &pForks);

        bool updateOutputs(TransactionOutputPool &pOutputs, int pBlockHeight);

        // Create the Genesis block
        static Block *genesis(uint32_t pTargetBits);

        // Update coinbase transaction to take all the fees
        void finalize();

    private:

        uint64_t mFees;
        unsigned int mSize;

        Block(Block &pCopy);
        Block &operator = (Block &pRight);

    };

    class MerkleNode
    {
    public:

        MerkleNode()
        {
            transaction = NULL;
            left = NULL;
            right = NULL;
            matches = false;
        }
        MerkleNode(Transaction *pTransaction, bool pMatches) : hash(pTransaction->hash)
        {
            transaction = pTransaction;
            left = NULL;
            right = NULL;
            matches = pMatches;
            hash = transaction->hash;
        }
        MerkleNode(MerkleNode *pLeft, MerkleNode *pRight, bool pMatches)
        {
            transaction = NULL;
            left = pLeft;
            right = pRight;
            matches = pMatches;

            calculateHash();
        }
        ~MerkleNode()
        {
            if(left != NULL)
                delete left;
            if(left != right)
                delete right;
        }

        bool calculateHash();

        void print(unsigned int pDepth = 0);

        NextCash::Hash hash;
        Transaction *transaction;
        MerkleNode *left, *right;
        bool matches;

    };

    MerkleNode *buildMerkleTree(std::vector<Transaction *> &pBlockTransactions, BloomFilter &pFilter);
    MerkleNode *buildEmptyMerkleTree(unsigned int pNodeCount);

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
        void clearNoDelete() { std::vector<Block *>::clear(); }

    private:
        BlockList(BlockList &pCopy);
        BlockList &operator = (BlockList &pRight);
    };

    class BlockFile
    {
    public:

        // Blocks
        static const NextCash::String &path();
        static NextCash::String fileName(unsigned int pID);
        static void lock(unsigned int pFileID);
        static void unlock(unsigned int pFileID);

        static const unsigned int MAX_BLOCKS = 100; // Maximum count of blocks in one file

        // Get block from appropriate block file
        static bool readBlock(unsigned int pHeight, Block &pBlock);

        // Read transaction from block
        static bool readBlockTransaction(unsigned int pHeight, unsigned int pTransactionOffset, Transaction &pTransaction);

        static bool readBlockTransactionOutput(unsigned int pHeight, unsigned int pTransactionOffset,
          unsigned int pOutputIndex, NextCash::Hash &pTransactionID, Output &pOutput);

        // Get transaction output from appropriate block file
        static bool readOutput(unsigned int pBlockHeight, OutputReference *pReference, unsigned int pIndex, Output &pOutput);

        // Create a new block file. BlockFile objects will be invalid if the block file doesn't already exist
        static BlockFile *create(unsigned int pID);

        // Remove a block file
        static bool remove(unsigned int pID);

        BlockFile(unsigned int pID, bool pValidate = false);
        ~BlockFile() { updateCRC(); if(mInputFile != NULL) delete mInputFile; }

        unsigned int id() const { return mID; }
        bool isValid() const { return mValid; }
        bool isFull() { return blockCount() == MAX_BLOCKS; }
        unsigned int blockCount() { getLastCount(); return mCount; }
        const NextCash::Hash &lastHash() { getLastCount(); return mLastHash; }

        // Add a block to the file
        bool addBlock(Block &pBlock);

        // Remove blocks from file above a specific offset in the file
        bool removeBlocksAbove(unsigned int pOffset);

        // Read block at specified offset in file. Return false if the offset is too high.
        bool readHash(unsigned int pOffset, NextCash::Hash &pHash);
        bool readBlock(unsigned int pOffset, Block &pBlock, bool pIncludeTransactions);

        // Read list of block hashes from this file. If pStartingHash is empty then start with first block
        bool readBlockHashes(NextCash::HashList &pHashes);

        // Append block stats from this file to the list specified
        bool readStats(BlockStats &pStats, unsigned int pOffset);

        // Read list of block headers from this file. If pStartingHash is empty then start with first block
        bool readBlockHeaders(BlockList &pBlockHeaders, const NextCash::Hash &pStartingHash,
          const NextCash::Hash &pStoppingHash, unsigned int pCount);

        // Read block for specified hash
        bool readBlock(const NextCash::Hash &pHash, Block &pBlock, bool pIncludeTransactions);

        // Read only transaction at specified offset of block
        bool readTransaction(unsigned int pBlockOffset, unsigned int pTransactionOffset, Transaction &pTransaction);

        // Read transaction output at specified offset in file
        bool readTransactionOutput(unsigned int pFileOffset, Output &pTransactionOutput);

        bool readTransactionOutput(unsigned int pBlockOffset, unsigned int pTransactionOffset,
          unsigned int pOutputIndex, NextCash::Hash &pTransactionID, Output &pOutput);

        // Give the offset of a specific hash into the file
        unsigned int hashOffset(const NextCash::Hash &pHash);

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
        NextCash::FileInputStream *mInputFile;
        NextCash::String mFilePathName;
        bool mValid;
        bool mModified;
        bool mSPVMode;

        void getLastCount();
        unsigned int mCount;
        NextCash::Hash mLastHash;

        static NextCash::Mutex mBlockFileMutex;
        static std::vector<unsigned int> mLockedBlockFileIDs;
        static NextCash::String mBlockFilePath;

        BlockFile(BlockFile &pCopy);
        BlockFile &operator = (BlockFile &pRight);

    };
}

#endif
