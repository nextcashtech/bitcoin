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

        bool validateSize(Chain *pChain, unsigned int pBlockHeight);

        // Validate anything that doesn't require UTXO.
        bool validate(Chain *pChain, unsigned int pBlockHeight);

        // Validate transactions and update outputs.
        bool process(Chain *pChain, unsigned int pBlockHeight);

        bool updateOutputs(Chain *pChain, unsigned int pBlockHeight);

        // Create the Genesis block
        static Block *genesis(uint32_t pTargetBits);

        // Update coinbase transaction to take all the fees
        void finalize();

        static unsigned int totalCount();

        // Get block from appropriate block file.
        static bool getBlock(unsigned int pBlockHeight, Block &pBlock);

        // Read output from block file.
        static bool getOutput(unsigned int pBlockHeight, OutputReference &pReference,
          Output &pOutput);
        static bool getOutput(unsigned int pBlockHeight, unsigned int pTransactionOffset,
          unsigned int pOutputIndex, NextCash::Hash &pTransactionID, Output &pOutput);

        // Add block to appropriate block file.
        static bool add(unsigned int pBlockHeight, const Block &pBlock);

        static bool revertToHeight(unsigned int pBlockHeight);

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
