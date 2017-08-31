#include "block.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/base/endian.hpp"
#include "arcmist/crypto/digest.hpp"
#include "interpreter.hpp"

#define BITCOIN_BLOCK_LOG_NAME "BitCoin Block"


namespace BitCoin
{
    bool Block::versionIsValid(unsigned int pHeight)
    {
        // Version 1 - Reject version 1 blocks at block 227,930
        if(version == 1 && pHeight >= 227930)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Version 1 block after 227,930 : %d", pHeight);
            return false;
        }

        /* Version 2 - Requires block height in coinbase
         *   Reject version 2 blocks without block height at block 224,412
         *   Reject version 1 blocks at block 227,930
         */
        if((version == 2 && pHeight >= 224412) || version > 2)
        {
            // Check for block height in coinbase (first) transaction
            if(transactions.size() > 0 && transactions[0].blockHeight() != pHeight)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
                  "Version 2 block with non matching block height after 224,412 : actual %d, included %d",
                  pHeight, transactions[0].blockHeight());
                return false;
            }
        }

        //TODO Version 3 - Requires ECDSA DER encoded signatures
        //TODO Version 4 - Added support for OP_CHECKLOCKTIMEVERIFY operation code.

        return true;
    }

    void Block::write(ArcMist::OutputStream *pStream, bool pIncludeTransactions, bool pIncludeTransactionCount)
    {
        // Version
        pStream->writeUnsignedInt(version);

        // Hash of previous block
        previousHash.write(pStream);

        // Merkle Root Hash
        merkleHash.write(pStream);

        // Time
        pStream->writeUnsignedInt(time);

        // Encoded version of target threshold
        pStream->writeUnsignedInt(bits);

        // Nonce
        pStream->writeUnsignedInt(nonce);

        if(!pIncludeTransactionCount)
            return;

        // Transaction Count
        if(pIncludeTransactions)
            writeCompactInteger(pStream, transactionCount);
        else
        {
            writeCompactInteger(pStream, 0);
            return;
        }

        // Transactions
        for(uint64_t i=0;i<transactions.size();i++)
            transactions[i].write(pStream);
    }

    bool Block::read(ArcMist::InputStream *pStream, bool pIncludeTransactions, bool pCalculateHash)
    {
        // Create hash
        ArcMist::Digest *digest = NULL;
        if(pCalculateHash)
        {
            digest = new ArcMist::Digest(ArcMist::Digest::SHA256_SHA256);
            digest->setOutputEndian(ArcMist::Endian::LITTLE);
        }
        hash.clear();

        if(pStream->remaining() < 81)
        {
            if(digest != NULL)
                delete digest;
            return false;
        }

        // Version
        version = pStream->readUnsignedInt();
        if(pCalculateHash)
            digest->writeUnsignedInt(version);

        // Hash of previous block
        previousHash.read(pStream);
        if(pCalculateHash)
            previousHash.write(digest);

        // Merkle Root Hash
        merkleHash.read(pStream);
        if(pCalculateHash)
            previousHash.write(digest);

        // Time
        time = pStream->readUnsignedInt();
        if(pCalculateHash)
            digest->writeUnsignedInt(time);

        // Encoded version of target threshold
        bits = pStream->readUnsignedInt();
        if(pCalculateHash)
            digest->writeUnsignedInt(bits);

        // Nonce
        nonce = pStream->readUnsignedInt();
        if(pCalculateHash)
            digest->writeUnsignedInt(nonce);

        if(pCalculateHash)
            digest->getResult(&hash);

        if(digest != NULL)
        {
            delete digest;
            digest = NULL;
        }

        // Transaction Count (Zero when header only)
        transactionCount = readCompactInteger(pStream);

        if(!pIncludeTransactions)
            return true;

        if(pStream->remaining() < transactionCount)
        {
            if(digest != NULL)
                delete digest;
            return false;
        }

        // Transactions
        transactions.clear();
        transactions.resize(transactionCount);
        for(uint64_t i=0;i<transactionCount;i++)
            if(!transactions[i].read(pStream))
                return false;

        return true;
    }

    void Block::calculateHash()
    {
        hash.clear();

        if(transactions.size() == 0)
            return;

        // Write into digest
        ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
        digest.setOutputEndian(ArcMist::Endian::LITTLE);
        write(&digest, false, false);

        // Get SHA256_SHA256 of block data
        digest.getResult(&hash);
    }

    void concatHash(const Hash *pFirst, const Hash *pSecond, Hash &pResult)
    {
        ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
        digest.setOutputEndian(ArcMist::Endian::LITTLE);
        pFirst->write(&digest);
        pSecond->write(&digest);
        digest.getResult(&pResult);
    }

    void calculateMerkleHashLevel(std::vector<Hash *>::iterator pIter, std::vector<Hash *>::iterator pEnd, Hash &pResult)
    {
        std::vector<Hash *>::iterator next = pIter;
        ++next;
        if(next == pEnd)
        {
            // Only one entry. Hash it with itself and return
            concatHash(*pIter, *pIter, pResult);
            return;
        }

        std::vector<Hash *>::iterator nextNext = next;
        ++nextNext;
        if(nextNext == pEnd)
        {
            // Two entries. Hash them together and return
            concatHash(*pIter, *next, pResult);
            return;
        }

        // More than two entries. Move up the tree a level.
        std::vector<Hash *> nextLevel;
        Hash *one, *two, *newHash;

        while(pIter != pEnd)
        {
            // Get one
            one = *pIter++;

            // Get two (first one again if no second)
            if(pIter == pEnd)
                two = one;
            else
                two = *pIter++;

            // Hash these and add to the next level
            newHash = new Hash(32);
            concatHash(one, two, *newHash);
            nextLevel.push_back(newHash);
        }

        // Calculate the next level
        calculateMerkleHashLevel(nextLevel.begin(), nextLevel.end(), pResult);

        // Destroy the next level
        for(std::vector<Hash *>::iterator i=nextLevel.begin();i!=nextLevel.end();++i)
            delete *i;
    }

    void Block::calculateMerkleHash(Hash &pMerkleHash)
    {
        pMerkleHash.setSize(32);
        if(transactions.size() == 0)
            pMerkleHash.zeroize();
        else if(transactions.size() == 1)
        {
            //concatHash(&transactions.front().hash, &transactions.front().hash, pMerkleHash);
            pMerkleHash = transactions.front().hash;
        }
        else
        {
            // Collect transaction hashes
            std::vector<Hash *> hashes;
            for(std::vector<Transaction>::iterator i=transactions.begin();i!=transactions.end();++i)
                hashes.push_back(&(*i).hash);

            // Calculate the next level
            calculateMerkleHashLevel(hashes.begin(), hashes.end(), pMerkleHash);
        }
    }
    
    uint64_t Block::coinBaseAmount(uint64_t pBlockHeight)
    {
        if(pBlockHeight >= 6930000)
            return 0;

        uint64_t result = 5000000000; // 50 bitcoins
        while(pBlockHeight > 210000)
        {
            // Half every 210,000 blocks
            result /= 2;
            pBlockHeight -= 210000;
        }

        return result;
    }

    bool Block::process(UnspentPool &pUnspentPool, uint64_t pBlockHeight, bool pTest)
    {
        //TODO Validate target "bits" (mining difficulty)

        // Validate Merkle Hash
        Hash calculatedMerkleHash;
        calculateMerkleHash(calculatedMerkleHash);
        if(calculatedMerkleHash != merkleHash)
        {
            ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Block merkle root hash is invalid");
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Included   : %s", merkleHash.hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Calculated : %s", merkleHash.hex().text());
            return false;
        }

        // Validate and process transactions
        bool isCoinBase = true;
        for(std::vector<Transaction>::iterator i=transactions.begin();i!=transactions.end();++i)
        {
            if(!(*i).process(pUnspentPool, pBlockHeight, isCoinBase, pTest))
                return false;
            isCoinBase = false;
        }

        //TODO Check that coinbase output amount - fees is correct for block height
        //if((*output)->amount != coinBaseAmount(pBlockHeight))
        //{
        //    ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME,
        //      "Coinbase outputs  %d script did not verify", i + 1);
        //    return false;
        //}

        return true;
    }

    Block *Block::genesis()
    {
        Block *result = new Block();

        result->version = 1;
        result->previousHash.zeroize();
        
        if(network() == TESTNET)
        {
            result->time = 1296688602;
            result->bits = 0x1d00ffff;
            result->nonce = 414098458;
        }
        else
        {
            result->time = 1231006505;
            result->bits = 0x1d00ffff;
            result->nonce = 2083236893;
        }
        result->transactionCount = 1;

        Transaction transaction;

        Input *input = new Input();
        input->script.writeHex("04FFFF001D0104455468652054696D65732030332F4A616E2F32303039204368616E63656C6C6F72206F6E206272696E6B206F66207365636F6E64206261696C6F757420666F722062616E6B73");
        input->script.compact();
        transaction.inputs.push_back(input);

        Output *output = new Output();
        output->amount = 5000000000;
        output->script.writeHex("4104678AFDB0FE5548271967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC");
        output->script.compact();
        transaction.outputs.push_back(output);

        transaction.lockTime = 0;
        transaction.calculateHash();

        result->transactions.push_back(transaction);

        // Calculate hashes
        result->calculateMerkleHash(result->merkleHash);
        result->calculateHash();

        return result;
    }
}
