#ifndef BITCOIN_BLOCK_HPP
#define BITCOIN_BLOCK_HPP

#include "arcmist/base/log.hpp"
#include "arcmist/io/stream.hpp"
#include "base.hpp"
#include "transaction.hpp"


namespace BitCoin
{
    class Block
    {
    public:

        Block() : previousHash(32), merkleHash(32) { version = 4; transactionCount = 0; mFees = 0; }

        // Checks if block follows version specific validation rules
        bool versionIsValid(unsigned int pHeight);
        
        // Verify hash is lower than target difficulty specified by targetBits
        bool hasProofOfWork();

        void write(ArcMist::OutputStream *pStream, bool pIncludeTransactions, bool pIncludeTransactionCount = true);

        // pCalculateHash will calculate the hash of the block data while it reads it
        bool read(ArcMist::InputStream *pStream, bool pIncludeTransactions, bool pCalculateHash = true);

        // Print human readable version to log
        void print(ArcMist::Log::Level pLevel = ArcMist::Log::DEBUG);

        // Hash
        Hash hash;

        // Header
        uint32_t version;
        Hash previousHash;
        Hash merkleHash;
        uint32_t time;
        uint32_t targetBits;
        uint32_t nonce;
        uint64_t transactionCount;

        // Transactions (empty when "header only")
        std::vector<Transaction> transactions;

        // Total of fees collected from transactions (set during process), not including coin base
        uint64_t fees() const { return mFees; }

        void calculateHash();
        void calculateMerkleHash(Hash &pMerkleHash);
        bool process(UnspentPool &pUnspentPool, uint64_t pBlockHeight);

        // Amount of Satoshis generated for mining a block at this height
        static uint64_t coinBaseAmount(uint64_t pBlockHeight);

        // Generate the Genesis block for the chain
        static Block *genesis();

    private:

        uint64_t mFees;

    };
}

#endif
