/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "block.hpp"

#ifdef PROFILER_ON
#include "arcmist/dev/profiler.hpp"
#endif

#include "arcmist/base/log.hpp"
#include "arcmist/base/endian.hpp"
#include "arcmist/base/thread.hpp"
#include "arcmist/crypto/digest.hpp"
#include "interpreter.hpp"
#include "info.hpp"

#define BITCOIN_BLOCK_LOG_NAME "BitCoin Block"


namespace BitCoin
{
    Block::~Block()
    {
        for(std::vector<Transaction *>::iterator transaction=transactions.begin();transaction!=transactions.end();++transaction)
            if(*transaction != NULL)
                delete *transaction;
    }

    bool Block::hasProofOfWork()
    {
        Hash target;
        target.setDifficulty(targetBits);
        return hash <= target;
    }

    void Block::write(ArcMist::OutputStream *pStream, bool pIncludeTransactions, bool pIncludeTransactionCount,
      bool pBlockFile)
    {
        unsigned int startOffset = pStream->writeOffset();
        mSize = 0;

        // Version
        pStream->writeUnsignedInt(version);

        // Hash of previous block
        previousHash.write(pStream);

        // Merkle Root Hash
        merkleHash.write(pStream);

        // Time
        pStream->writeUnsignedInt(time);

        // Encoded version of target threshold
        pStream->writeUnsignedInt(targetBits);

        // Nonce
        pStream->writeUnsignedInt(nonce);

        if(!pIncludeTransactionCount)
        {
            mSize = pStream->writeOffset() - startOffset;
            return;
        }

        // Transaction Count
        if(pIncludeTransactions)
            writeCompactInteger(pStream, transactionCount);
        else
        {
            writeCompactInteger(pStream, 0);
            mSize = pStream->writeOffset() - startOffset;
            return;
        }

        // Transactions
        for(uint64_t i=0;i<transactions.size();i++)
            transactions[i]->write(pStream, pBlockFile);

        mSize = pStream->writeOffset() - startOffset;
    }

    bool Block::read(ArcMist::InputStream *pStream, bool pIncludeTransactions, bool pIncludeTransactionCount,
      bool pCalculateHash, bool pBlockFile)
    {
        unsigned int startOffset = pStream->readOffset();
        mSize = 0;

        // Create hash
        ArcMist::Digest *digest = NULL;
        if(pCalculateHash)
        {
            digest = new ArcMist::Digest(ArcMist::Digest::SHA256_SHA256);
            digest->setOutputEndian(ArcMist::Endian::LITTLE);
        }
        hash.clear();

        if((pIncludeTransactionCount && pStream->remaining() < 81) ||
          (!pIncludeTransactionCount && pStream->remaining() < 80))
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
        if(!previousHash.read(pStream))
            return false;
        if(pCalculateHash)
            previousHash.write(digest);

        // Merkle Root Hash
        if(!merkleHash.read(pStream))
            return false;
        if(pCalculateHash)
            merkleHash.write(digest);

        // Time
        time = pStream->readUnsignedInt();
        if(pCalculateHash)
            digest->writeUnsignedInt(time);

        // Encoded version of target threshold
        targetBits = pStream->readUnsignedInt();
        if(pCalculateHash)
            digest->writeUnsignedInt(targetBits);

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

        if(!pIncludeTransactionCount)
        {
            transactionCount = 0;
            return true;
        }

        // Transaction Count (Zero when header only)
        transactionCount = readCompactInteger(pStream);

        if(!pIncludeTransactions)
        {
            mSize = pStream->readOffset() - startOffset;
            return true;
        }

        if(pStream->remaining() < transactionCount)
        {
            if(digest != NULL)
                delete digest;
            return false;
        }

        // Transactions
        transactions.clear();
        transactions.resize(transactionCount);
        bool fail = false;
        for(std::vector<Transaction *>::iterator transaction=transactions.begin();transaction!=transactions.end();++transaction)
        {
            if(!fail)
            {
                *transaction = new Transaction();
                if(!(*transaction)->read(pStream, true, pBlockFile))
                    fail = true;
            }
            else
                *transaction = NULL;
        }

        mSize = pStream->readOffset() - startOffset;
        return !fail;
    }

    void Block::clear()
    {
        hash.clear();
        version = 0;
        previousHash.zeroize();
        merkleHash.zeroize();
        time = 0;
        targetBits = 0;
        nonce = 0;
        transactionCount = 0;
        for(std::vector<Transaction *>::iterator transaction=transactions.begin();transaction!=transactions.end();++transaction)
            if(*transaction != NULL)
                delete *transaction;
        transactions.clear();
        mFees = 0;
        mSize = 0;
    }

    void Block::print(ArcMist::Log::Level pLevel, bool pIncludeTransactions)
    {
        ArcMist::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Hash          : %s", hash.hex().text());
        ArcMist::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Version       : %d", version);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Previous Hash : %s", previousHash.hex().text());
        ArcMist::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "MerkleHash    : %s", merkleHash.hex().text());
        ArcMist::String timeText;
        timeText.writeFormattedTime(time);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Time          : %s (%d)", timeText.text(), time);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Bits          : 0x%08x", targetBits);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Nonce         : 0x%08x", nonce);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Total Fees    : %f", bitcoins(mFees));
        ArcMist::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Size (bytes)  : %d", mSize);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "%d Transactions", transactionCount);

        if(!pIncludeTransactions)
            return;

        unsigned int index = 0;
        for(std::vector<Transaction *>::iterator transaction=transactions.begin();transaction!=transactions.end();++transaction)
        {
            if(index == 0)
                ArcMist::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Coinbase Transaction", index++);
            else
                ArcMist::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Transaction %d", index++);
            (*transaction)->print(pLevel);
        }
    }

    void Block::calculateHash()
    {
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
            pMerkleHash = transactions.front()->hash;
        }
        else
        {
            // Collect transaction hashes
            std::vector<Hash *> hashes;
            for(std::vector<Transaction *>::iterator i=transactions.begin();i!=transactions.end();++i)
                hashes.push_back(&(*i)->hash);

            // Calculate the next level
            calculateMerkleHashLevel(hashes.begin(), hashes.end(), pMerkleHash);
        }
    }

    bool Block::updateOutputs(TransactionOutputPool &pOutputs, int pBlockHeight)
    {
        if(transactions.size() == 0)
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME, "No transactions. At least a coin base is required");
            return false;
        }

        // Add the transaction outputs from this block to the output pool
        pOutputs.add(this->transactions, pBlockHeight);

        unsigned int transactionOffset = 0;
        std::vector<unsigned int> spentAges;
        for(std::vector<Transaction *>::iterator transaction=transactions.begin();transaction!=transactions.end();++transaction)
        {
            if(!(*transaction)->updateOutputs(pOutputs, transactions, pBlockHeight, spentAges))
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME, "Transaction %d update failed",
                  transactionOffset);
                return false;
            }
            ++transactionOffset;
        }

        if(spentAges.size() > 0)
        {
            unsigned int totalSpentAge = 0;
            for(std::vector<unsigned int>::iterator spentAge=spentAges.begin();spentAge!=spentAges.end();++spentAge)
                totalSpentAge += *spentAge;
            unsigned int averageSpentAge = totalSpentAge / spentAges.size();
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
              "Average spent age for block %d is %d", pBlockHeight, averageSpentAge);
        }
        return true;
    }

    bool Block::process(TransactionOutputPool &pOutputs, int pBlockHeight, const BlockStats &pBlockStats,
      const Forks &pForks)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Block Process");
#endif
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
          "Processing block at height %d (%d trans) (%d bytes) : %s", pBlockHeight, transactionCount,
          size(), hash.hex().text());

        if(transactions.size() == 0)
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME, "No transactions. At least a coin base is required");
            return false;
        }

        if(pForks.requiredVersion() > version)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME, "Version %d required",
              pForks.requiredVersion());
            return false;
        }

        if(pForks.cashForkBlockHeight() == pBlockHeight && size() < Forks::HARD_MAX_BLOCK_SIZE)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Cash fork block size must be greater than %d bytes : %d bytes", Forks::HARD_MAX_BLOCK_SIZE, size());
            return false;
        }

        if(size() > pForks.blockMaxSize())
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Block size must be less than %d bytes : %d", pForks.blockMaxSize(), size());
            return false;
        }

        // Validate Merkle Hash
        Hash calculatedMerkleHash;
        calculateMerkleHash(calculatedMerkleHash);
        if(calculatedMerkleHash != merkleHash)
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME, "Block merkle root hash is invalid");
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME, "Included   : %s", merkleHash.hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME, "Calculated : %s", merkleHash.hex().text());
            return false;
        }

        //TODO Turn this check back on after reaching a reasonable block height
        // Check that this block doesn't have any duplicate transaction IDs
        // if(!pOutputs.checkDuplicates(transactions, pBlockHeight, hash))
            // return false;

        // Add the transaction outputs from this block to the output pool
        if(!pOutputs.add(transactions, pBlockHeight))
            return false;

        // Validate and process transactions
        bool isCoinBase = true;
        mFees = 0;
        unsigned int transactionOffset = 0;
        std::vector<unsigned int> spentAges;
        for(std::vector<Transaction *>::iterator transaction=transactions.begin();transaction!=transactions.end();++transaction)
        {
            if(!(*transaction)->process(pOutputs, transactions, pBlockHeight, isCoinBase, version,
              pBlockStats, pForks, spentAges))
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME, "Transaction %d failed",
                  transactionOffset);
                return false;
            }
            if(!isCoinBase)
                mFees += (*transaction)->fee();
            isCoinBase = false;
            ++transactionOffset;
        }

        if(spentAges.size() > 0)
        {
            unsigned int totalSpentAge = 0;
            for(std::vector<unsigned int>::iterator spentAge=spentAges.begin();spentAge!=spentAges.end();++spentAge)
                totalSpentAge += *spentAge;
            unsigned int averageSpentAge = totalSpentAge / spentAges.size();
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
              "Average spent age for block %d is %d for %d inputs", pBlockHeight, averageSpentAge, spentAges.size());
        }

        // Check that coinbase output amount - fees is correct for block height
        if(-transactions.front()->fee() - mFees > coinBaseAmount(pBlockHeight))
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME, "Coinbase outputs are too high");
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME, "Coinbase %.08f",
              bitcoins(-transactions.front()->fee()));
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME, "Fees     %.08f", bitcoins(mFees));
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Block %d Coinbase amount should be %.08f", pBlockHeight, bitcoins(coinBaseAmount(pBlockHeight)));
            return false;
        }

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
            result->targetBits = 0x1d00ffff;
            result->nonce = 414098458;
        }
        else
        {
            result->time = 1231006505;
            result->targetBits = 0x1d00ffff;
            result->nonce = 2083236893;
        }
        result->transactionCount = 1;

        Transaction *transaction = new Transaction();
        transaction->version = 1;

        Input *input = new Input();
        input->script.writeHex("04FFFF001D0104455468652054696D65732030332F4A616E2F32303039204368616E63656C6C6F72206F6E206272696E6B206F66207365636F6E64206261696C6F757420666F722062616E6B73");
        input->script.compact();
        transaction->inputs.push_back(input);

        Output *output = new Output();
        output->amount = 5000000000;
        output->script.writeHex("4104678AFDB0FE5548271967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC");
        output->script.compact();
        transaction->outputs.push_back(output);

        transaction->lockTime = 0;
        transaction->calculateHash();

        result->transactions.push_back(transaction);

        // Calculate hashes
        result->calculateMerkleHash(result->merkleHash);
        result->calculateHash();

        return result;
    }

    void Block::finalize()
    {
        //TODO Update total coinbase amount

        transactionCount = transactions.size();
        nonce = ArcMist::Math::randomLong();
        calculateMerkleHash(merkleHash);
        calculateHash();
    }

    ArcMist::Mutex BlockFile::mBlockFileMutex("Block File");
    std::vector<unsigned int> BlockFile::mLockedBlockFileIDs;
    ArcMist::String BlockFile::mBlockFilePath;

    BlockFile::BlockFile(unsigned int pID, bool pValidate)
    {
        mValid = true;
        mFilePathName = fileName(pID);
        mInputFile = NULL;
        mID = pID;
        mModified = false;
        mCount = INVALID_COUNT;

        if(!openFile())
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_LOG_NAME,
              "Failed to open block file : %s", mFilePathName.text());
            mValid = false;
            return;
        }

        // Read start string
        ArcMist::String startString = mInputFile->readString(8);

        // Check start string
        if(startString != START_STRING)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_LOG_NAME,
              "Block file %08x missing start string", mID);
            mValid = false;
            return;
        }

        // Read CRC
        unsigned int crc = mInputFile->readUnsignedInt();

        if(pValidate)
        {
            // Calculate CRC
            ArcMist::Digest digest(ArcMist::Digest::CRC32);
            digest.setOutputEndian(ArcMist::Endian::LITTLE);
            digest.writeStream(mInputFile, mInputFile->remaining());

            // Get Calculated CRC
            ArcMist::Buffer crcBuffer;
            crcBuffer.setEndian(ArcMist::Endian::LITTLE);
            digest.getResult(&crcBuffer);
            unsigned int calculatedCRC = crcBuffer.readUnsignedInt();

            // Check CRC
            if(crc != calculatedCRC)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_LOG_NAME,
                  "Block file %08x has invalid CRC : %08x != %08x", mID, crc, calculatedCRC);
                mValid = false;
                return;
            }
        }
    }

    bool BlockFile::openFile()
    {
        if(mInputFile != NULL && mInputFile->isValid())
            return true;

        if(mInputFile != NULL)
            delete mInputFile;

        mInputFile = new ArcMist::FileInputStream(mFilePathName);
        mInputFile->setInputEndian(ArcMist::Endian::LITTLE);
        mInputFile->setReadOffset(0);

        return mInputFile->isValid();
    }

    BlockFile *BlockFile::create(unsigned int pID)
    {
        ArcMist::createDirectory(path());
        ArcMist::FileOutputStream *outputFile = new ArcMist::FileOutputStream(fileName(pID), true);
        outputFile->setOutputEndian(ArcMist::Endian::LITTLE);

        if(!outputFile->isValid())
        {
            delete outputFile;
            return NULL;
        }

        // Write start string
        outputFile->writeString(START_STRING);

        // Write empty CRC
        outputFile->writeUnsignedInt(0);

        // Write zero hashes
        ArcMist::Digest digest(ArcMist::Digest::CRC32);
        digest.setOutputEndian(ArcMist::Endian::LITTLE);
        Hash zeroHash(32);
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            zeroHash.write(outputFile);
            outputFile->writeUnsignedInt(0);

            // For digest
            zeroHash.write(&digest);
            digest.writeUnsignedInt(0);
        }

        // Get CRC
        ArcMist::Buffer crcBuffer;
        crcBuffer.setEndian(ArcMist::Endian::LITTLE);
        digest.getResult(&crcBuffer);
        unsigned int crc = crcBuffer.readUnsignedInt();

        // Write CRC
        outputFile->setWriteOffset(CRC_OFFSET);
        outputFile->writeUnsignedInt(crc);
        delete outputFile;

        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME,
          "Block file %08x created with CRC : %08x", pID, crc);

        // Create and return block file object
        BlockFile *result = new BlockFile(pID);
        if(result->isValid())
            return result;
        else
        {
            delete result;
            return NULL;
        }
    }

    void BlockFile::getLastCount()
    {
        if(mCount != INVALID_COUNT)
            return;

        if(!openFile())
        {
            mValid = false;
            mCount = 0;
            return;
        }

        // Go to the last data offset in the header
        mInputFile->setReadOffset(HASHES_OFFSET + ((MAX_BLOCKS - 1) * HEADER_ITEM_SIZE) + 32);

        // Check each data offset until it is a valid
        for(mCount=MAX_BLOCKS;mCount>0;--mCount)
        {
            if(mInputFile->readUnsignedInt() != 0)
            {
                // Back up to hash for this data offset
                mInputFile->setReadOffset(mInputFile->readOffset() - HEADER_ITEM_SIZE);
                if(!mLastHash.read(mInputFile, 32))
                {
                    mLastHash.clear();
                    mValid = false;
                }
                break;
            }
            else // Back up to previous data offset
                mInputFile->setReadOffset(mInputFile->readOffset() - HEADER_ITEM_SIZE - 4);
        }
    }

    bool BlockFile::addBlock(Block &pBlock)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Block Add");
#endif
        if(!mValid)
            return false;

        unsigned int count = blockCount();

        if(count == MAX_BLOCKS)
            return false;

        if(mInputFile != NULL)
            delete mInputFile;
        mInputFile = NULL;

        ArcMist::FileOutputStream *outputFile = new ArcMist::FileOutputStream(mFilePathName);
        outputFile->setOutputEndian(ArcMist::Endian::LITTLE);
        if(!outputFile->isValid())
        {
            delete outputFile;
            return false;
        }

        // Write hash and offset to file
        outputFile->setWriteOffset(HASHES_OFFSET + (count * HEADER_ITEM_SIZE));
        pBlock.hash.write(outputFile);
        outputFile->writeUnsignedInt(outputFile->length());

        // Write block data at end of file
        outputFile->setWriteOffset(outputFile->length());
        pBlock.write(outputFile, true, true, true);
        delete outputFile;

        mLastHash = pBlock.hash;
        ++mCount;
        mModified = true;
        return true;
    }

    // If pStartingHash is empty then start with first hash in file
    bool BlockFile::readBlockHashes(HashList &pHashes)
    {
        pHashes.clear();
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        Hash hash(32);
        mInputFile->setReadOffset(HASHES_OFFSET);
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            if(!hash.read(mInputFile))
                return false;

            if(mInputFile->readUnsignedInt() == 0)
                return true;

            pHashes.push_back(new Hash(hash));
        }

        return true;
    }

    // Append block stats from this file to the list specified
    bool BlockFile::readStats(BlockStats &pStats)
    {
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        mInputFile->setReadOffset(HASHES_OFFSET + 32); // Set offset to offset of first data offset location in file
        unsigned int blockOffset, previousOffset;
        uint32_t version, time, targetBits;
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            // Read location of block in file from header
            blockOffset = mInputFile->readUnsignedInt();
            if(blockOffset == 0)
                return true;

            // Save location of next block
            previousOffset = mInputFile->readOffset() + 32; // Add 32 to skip header hash

            // Go to location of block in file
            mInputFile->setReadOffset(blockOffset);

            // Read stats from file
            version = mInputFile->readUnsignedInt();
            mInputFile->setReadOffset(mInputFile->readOffset() + 64); // Skip previous and merkle hashes
            time = mInputFile->readUnsignedInt();
            targetBits = mInputFile->readUnsignedInt();
            pStats.push_back(BlockStat(version, time, targetBits));

            // Go back to header in file
            mInputFile->setReadOffset(previousOffset);
        }

        return true;
    }

    // If pStartingHash is empty then start with first block in file
    bool BlockFile::readBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash,
      const Hash &pStoppingHash, unsigned int pCount)
    {
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        Hash hash(32);
        Block *newBlockHeader;
        unsigned int fileOffset;
        unsigned int fileHashOffset = 0;
        bool startAtFirst = pStartingHash.isEmpty();
        bool found = false;

        // Find starting hash
        mInputFile->setReadOffset(HASHES_OFFSET);
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            if(!hash.read(mInputFile))
                return false;

            if(mInputFile->readUnsignedInt() == 0)
                return false;

            if(startAtFirst || hash == pStartingHash)
            {
                found = true;
                break;
            }

            fileHashOffset++;
        }

        if(!found)
            return false; // Hash not found

        while(pBlockHeaders.size() < pCount)
        {
            mInputFile->setReadOffset(HASHES_OFFSET + (fileHashOffset * HEADER_ITEM_SIZE));
            if(!hash.read(mInputFile))
                return false;

            fileOffset = mInputFile->readUnsignedInt();
            if(fileOffset == 0)
                return pBlockHeaders.size() > 0;

            fileHashOffset++;

            // Go to file offset of block data
            mInputFile->setReadOffset(fileOffset);
            newBlockHeader = new Block();
            if(!newBlockHeader->read(mInputFile, false, false, true))
            {
                delete newBlockHeader;
                return false;
            }

            pBlockHeaders.push_back(newBlockHeader);
            if(newBlockHeader->hash == pStoppingHash)
                break;

            if(fileHashOffset == MAX_BLOCKS)
                return pBlockHeaders.size() > 0; // Reached last block in file
        }

        return pBlockHeaders.size() > 0;
    }

    bool BlockFile::readHash(unsigned int pOffset, Hash &pHash)
    {
        pHash.clear();
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        // Go to location in header where the data offset to the block is
        mInputFile->setReadOffset(HASHES_OFFSET + (pOffset * HEADER_ITEM_SIZE));
        pHash.read(mInputFile, 32);
        bool success = mInputFile->readUnsignedInt() != 0;
        return success;
    }

    bool BlockFile::readBlock(unsigned int pOffset, Block &pBlock, bool pIncludeTransactions)
    {
        pBlock.clear();
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        // Go to location in header where the data offset to the block is
        mInputFile->setReadOffset(HASHES_OFFSET + (pOffset * HEADER_ITEM_SIZE) + 32);

        unsigned int offset = mInputFile->readUnsignedInt();
        if(offset == 0)
            return false;

        mInputFile->setReadOffset(offset);
        bool success = pBlock.read(mInputFile, pIncludeTransactions, pIncludeTransactions, true, true);
        return success;
    }

    bool BlockFile::readBlock(const Hash &pHash, Block &pBlock, bool pIncludeTransactions)
    {
        pBlock.clear();
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        // Find offset
        Hash hash(32);
        unsigned int fileOffset;
        mInputFile->setReadOffset(HASHES_OFFSET);
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            if(!hash.read(mInputFile))
                return false;

            fileOffset = mInputFile->readUnsignedInt();
            if(fileOffset == 0)
                return false;

            if(hash == pHash)
            {
                // Read block
                mInputFile->setReadOffset(fileOffset);
                bool success = pBlock.read(mInputFile, pIncludeTransactions, pIncludeTransactions, true, true);
                return success;
            }
        }

        return false;
    }

    bool BlockFile::readTransactionOutput(unsigned int pFileOffset, Output &pTransactionOutput)
    {
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        mInputFile->setReadOffset(pFileOffset);
        return pTransactionOutput.read(mInputFile);
    }

    unsigned int BlockFile::hashOffset(const Hash &pHash)
    {
        if(!openFile())
        {
            mValid = false;
            return 0;
        }

        // Find offset
        Hash hash(32);
        mInputFile->setReadOffset(HASHES_OFFSET);
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            if(!hash.read(mInputFile))
                return 0;

            if(mInputFile->readUnsignedInt() == 0)
                return 0;

            if(hash == pHash)
                return i;
        }

        return 0;
    }

    void BlockFile::updateCRC()
    {
        if(!mModified)
            return;

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Block Update CRC");
#endif
        if(!openFile())
        {
            mValid = false;
            return;
        }

        // Calculate new CRC
        ArcMist::Digest digest(ArcMist::Digest::CRC32);
        digest.setOutputEndian(ArcMist::Endian::LITTLE);

        // Read file into digest
        mInputFile->setReadOffset(HASHES_OFFSET);
        digest.writeStream(mInputFile, mInputFile->remaining());
        delete mInputFile;
        mInputFile = NULL;

        // Get CRC result
        ArcMist::Buffer crcBuffer;
        crcBuffer.setEndian(ArcMist::Endian::LITTLE);
        digest.getResult(&crcBuffer);
        unsigned int crc = crcBuffer.readUnsignedInt();

        // Write CRC to file
        ArcMist::FileOutputStream *outputFile = new ArcMist::FileOutputStream(mFilePathName);
        outputFile->setOutputEndian(ArcMist::Endian::LITTLE);
        outputFile->setWriteOffset(CRC_OFFSET);
        outputFile->writeUnsignedInt(crc);
        outputFile->flush();
        delete outputFile;

        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME,
          "Block file %08x CRC updated : %08x", mID, crc);
    }

    void BlockFile::lock(unsigned int pFileID)
    {
        bool found;
        while(true)
        {
            found = false;
            mBlockFileMutex.lock();
            for(std::vector<unsigned int>::iterator i=mLockedBlockFileIDs.begin();i!=mLockedBlockFileIDs.end();++i)
                if(*i == pFileID)
                {
                    found = true;
                    break;
                }
            if(!found)
            {
                mLockedBlockFileIDs.push_back(pFileID);
                mBlockFileMutex.unlock();
                return;
            }
            mBlockFileMutex.unlock();
            ArcMist::Thread::sleep(100);
        }
    }

    void BlockFile::unlock(unsigned int pFileID)
    {
        mBlockFileMutex.lock();
        for(std::vector<unsigned int>::iterator i=mLockedBlockFileIDs.begin();i!=mLockedBlockFileIDs.end();++i)
            if(*i == pFileID)
            {
                mLockedBlockFileIDs.erase(i);
                break;
            }
        mBlockFileMutex.unlock();
    }

    const ArcMist::String &BlockFile::path()
    {
        if(!mBlockFilePath)
        {
            // Build path
            mBlockFilePath = Info::instance().path();
            mBlockFilePath.pathAppend("blocks");
        }
        return mBlockFilePath;
    }

    ArcMist::String BlockFile::fileName(unsigned int pID)
    {
        // Build path
        ArcMist::String result;
        result.writeFormatted("%s%s%08x", path().text(), ArcMist::PATH_SEPARATOR, pID);
        return result;
    }

    bool BlockFile::readBlock(unsigned int pHeight, Block &pBlock)
    {
        unsigned int fileID = pHeight / 100;
        unsigned int offset = pHeight - (fileID * 100);

        BlockFile *blockFile;
        BlockFile::lock(fileID);
        blockFile = new BlockFile(fileID, BlockFile::fileName(fileID));
        bool success = blockFile->isValid() && blockFile->readBlock(offset, pBlock, true);
        BlockFile::unlock(fileID);
        return success;
    }

    bool BlockFile::readOutput(TransactionReference *pReference, unsigned int pIndex, Output &pOutput)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Block Read Output");
#endif
        if(pReference == NULL || pReference->outputAt(pIndex)->blockFileOffset == 0)
            return false;

        unsigned int fileID = pReference->blockHeight / MAX_BLOCKS;

        lock(fileID);
        BlockFile *blockFile = new BlockFile(fileID, false);

        bool success = blockFile->isValid() &&
          blockFile->readTransactionOutput(pReference->outputAt(pIndex)->blockFileOffset, pOutput);

        delete blockFile;
        unlock(fileID);

        return success;
    }
}
