#ifndef BITCOIN_BLOCK_HPP
#define BITCOIN_BLOCK_HPP

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

        void write(ArcMist::OutputStream *pStream, bool pIncludeTransactions, bool pIncludeTransactionCount = true);

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
        void calculateMerkleHash(Hash &pMerkleHash);
        bool process(UnspentPool &pUnspentPool, uint64_t pBlockHeight, bool pTest);
        
        static uint64_t coinBaseAmount(uint64_t pBlockHeight);
        static Block *genesis();

    };
}

#endif
