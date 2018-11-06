/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_BLOCK_HPP
#define BITCOIN_BLOCK_HPP

#include "hash.hpp"
#include "log.hpp"
#include "stream.hpp"
#include "file_stream.hpp"
#include "base.hpp"
#include "forks.hpp"
#include "header.hpp"
#include "transaction.hpp"
#include "outputs.hpp"
#include "bloom_filter.hpp"


namespace BitCoin
{
    class Block
    {
    public:

        Block()
        {
            mFees = 0;
            mSize = 0;
        }
        Block(const Header &pHeader) : header(pHeader)
        {
            mFees = 0;
            mSize = 0;
        }
        ~Block();

        void write(NextCash::OutputStream *pStream);
        bool read(NextCash::InputStream *pStream);

        void clear();
        void clearTransactions();

        // Print human readable version to log
        void print(Forks &pForks, bool pIncludeTransactions,
          NextCash::Log::Level pLevel = NextCash::Log::DEBUG);

        Header header;
        std::vector<Transaction *> transactions;

        // Total of fees collected from transactions (set during process), not including coin base
        uint64_t fees() const { return mFees; }
        NextCash::stream_size size() const { return mSize; }

        void setSize(NextCash::stream_size pSize) { mSize = pSize; }

        uint64_t actualCoinbaseAmount(); // Amount from coinbase transaction

        void calculateMerkleHash(NextCash::Hash &pMerkleHash);

        bool checkSize(Chain *pChain, unsigned int pHeight);

        // Validate anything that doesn't require UTXO.
        bool validate(Chain *pChain, unsigned int pHeight);

        // Validate transactions and update outputs.
        bool processSingleThreaded(Chain *pChain, unsigned int pHeight);
        bool processMultiThreaded(Chain *pChain, unsigned int pHeight, unsigned int pThreadCount);

        bool updateOutputsSingleThreaded(Chain *pChain, unsigned int pHeight);
        bool updateOutputsMultiThreaded(Chain *pChain, unsigned int pHeight,
          unsigned int pThreadCount);

        // Create the Genesis block
        static Block *genesis(uint32_t pTargetBits);

        // Update coinbase transaction to take all the fees
        void finalize();

        static unsigned int totalCount();

        // Get block from appropriate block file.
        static bool getBlock(unsigned int pHeight, Block &pBlock);

        // Read output from block file.
        static bool getOutput(unsigned int pHeight, unsigned int pTransactionOffset,
          unsigned int pOutputIndex, NextCash::Hash &pTransactionID, Output &pOutput);

        // Add block to appropriate block file.
        static bool add(unsigned int pHeight, const Block &pBlock);

        static bool revertToHeight(unsigned int pHeight);

        // Validate block file CRCs and revert to last valid.
        // Returns valid block count.
        // pMaxCount is the maximum count that can be valid. Anything above that is removed.
        static unsigned int validate(bool &pAbort);

        static void save(); // Save any unsaved data in files (i.e. update CRCs)
        static void clean();  // Release any static cache data

    private:

        uint64_t mFees;
        NextCash::stream_size mSize;

        Block(Block &pCopy);
        Block &operator = (Block &pRight);

        class ProcessThreadData
        {
        public:

            ProcessThreadData(Chain *pChain, Block *pBlock, unsigned int pHeight,
              std::vector<Transaction *>::iterator pTransactionsBegin, unsigned int pCount) :
              mutex("ProcessThreadData"), spentAgeLock("Spent Age"), timeLock("Time")
            {
                chain = pChain;
                block = pBlock;
                height = pHeight;
                transaction = pTransactionsBegin;
                count = pCount;
                offset = 0;
                success = true;
                complete = new bool[count];
                std::memset(complete, 0, count);
                checkDupTime = 0L;
                outputsTime = 0L;
                sigTime = 0L;
                fullTime = 0L;
            }
            ~ProcessThreadData()
            {
                delete[] complete;
            }

            NextCash::Mutex mutex;
            Chain *chain;
            Block *block;
            unsigned int height, offset, count;
            std::vector<Transaction *>::iterator transaction;
            NextCash::Mutex spentAgeLock;
            std::vector<unsigned int> spentAges;
            bool success;
            bool *complete;
            NextCash::Mutex timeLock;
            uint64_t checkDupTime, outputsTime, sigTime, fullTime;

            Transaction *getNext(unsigned int &pOffset)
            {
                Transaction *result = NULL;
                mutex.lock();
                if(success && offset < count)
                {
                    pOffset = offset;
                    result = *transaction++;
                    ++offset;
                }
                else
                    pOffset = 0xffffffff;
                mutex.unlock();
                return result;
            }

            void markComplete(unsigned int pOffset, bool pValid)
            {
                complete[pOffset] = true;
                if(!pValid)
                    success = false;
            }

        };

        static void processThreadRun(); // Thread for process tasks
        static void updateOutputsThreadRun(); // Thread for update outputs tasks

    };

    class BlockList : public std::vector<Block *>
    {
    public:
        BlockList() {}
        ~BlockList()
        {
            for(iterator block = begin(); block != end(); ++block)
                delete *block;
        }

        void clear()
        {
            for(iterator block = begin(); block != end(); ++block)
                delete *block;
            std::vector<Block *>::clear();
        }
        void clearNoDelete() { std::vector<Block *>::clear(); }

    private:
        BlockList(BlockList &pCopy);
        BlockList &operator = (BlockList &pRight);
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

    MerkleNode *buildMerkleTree(std::vector<Transaction *> &pBlockTransactions,
      BloomFilter &pFilter);
    MerkleNode *buildEmptyMerkleTree(unsigned int pNodeCount);
}

#endif
