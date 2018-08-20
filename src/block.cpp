/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "block.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#endif

#include "log.hpp"
#include "endian.hpp"
#include "thread.hpp"
#include "digest.hpp"
#include "interpreter.hpp"
#include "info.hpp"
#include "header.hpp"
#include "chain.hpp"

#define BITCOIN_BLOCK_LOG_NAME "Block"


namespace BitCoin
{
    Block::~Block()
    {
        for(std::vector<Transaction *>::iterator transaction = transactions.begin();
          transaction != transactions.end(); ++transaction)
            if(*transaction != NULL)
                delete *transaction;
    }

    uint64_t Block::actualCoinbaseAmount()
    {
        if(transactions.size() == 0)
            return 0;

        uint64_t result = 0;
        Transaction *coinbase = transactions.front();
        for(std::vector<Output>::iterator output = coinbase->outputs.begin();
          output != coinbase->outputs.end(); ++output)
            result += output->amount;

        return result;
    }

    void Block::write(NextCash::OutputStream *pStream)
    {
        NextCash::stream_size startOffset = pStream->writeOffset();
        mSize = 0;

        header.write(pStream, false);

        writeCompactInteger(pStream, transactions.size());

        // Transactions
        for(std::vector<Transaction *>::iterator trans = transactions.begin();
          trans != transactions.end(); ++trans)
            (*trans)->write(pStream, false);

        mSize = pStream->writeOffset() - startOffset;
    }

    bool Block::read(NextCash::InputStream *pStream)
    {
        NextCash::stream_size startOffset = pStream->readOffset();
        mSize = 0;

        if(!header.read(pStream, true, true))
            return false;

        // Transactions
        Transaction *transaction;
        clearTransactions();
        transactions.reserve(header.transactionCount);
        for(unsigned int i = 0; i < header.transactionCount; ++i)
        {
            transaction = new Transaction();
            if(transaction->read(pStream, true, false))
                transactions.push_back(transaction);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
                  "Block read failed : transaction %d read failed", i + 1);
                delete transaction;
                return false;
            }
        }

        mSize = pStream->readOffset() - startOffset;
        return true;
    }

    void Block::clear()
    {
        header.clear();
        for(std::vector<Transaction *>::iterator transaction = transactions.begin();
          transaction != transactions.end(); ++transaction)
            if(*transaction != NULL)
                delete *transaction;
        transactions.clear();
        mFees = 0;
        mSize = 0;
    }

    void Block::clearTransactions()
    {
        for(std::vector<Transaction *>::iterator transaction = transactions.begin();
          transaction != transactions.end(); ++transaction)
            if(*transaction != NULL)
                delete *transaction;
        transactions.clear();
    }

    void Block::print(Forks &pForks, bool pIncludeTransactions, NextCash::Log::Level pLevel)
    {
        header.print(pLevel);

        NextCash::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Total Fees    : %f",
          bitcoins(mFees));
        NextCash::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Size (KiB)    : %d",
          mSize / 1024);

        if(!pIncludeTransactions)
            return;

        unsigned int index = 0;
        for(std::vector<Transaction *>::iterator transaction = transactions.begin();
          transaction != transactions.end(); ++transaction)
        {
            if(index == 0)
                NextCash::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Coinbase Transaction",
                  index++);
            else
                NextCash::Log::addFormatted(pLevel, BITCOIN_BLOCK_LOG_NAME, "Transaction %d",
                  index++);
            (*transaction)->print(pForks, pLevel);
        }
    }

    void concatHash(const NextCash::Hash &pLeft, const NextCash::Hash &pRight,
      NextCash::Hash &pResult)
    {
        NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
        digest.setOutputEndian(NextCash::Endian::LITTLE);
        pLeft.write(&digest);
        pRight.write(&digest);
        pResult.setSize(32);
        digest.getResult(&pResult);
    }

    void calculateMerkleHashLevel(std::vector<NextCash::Hash> &pHashes, NextCash::Hash &pResult)
    {
        std::vector<NextCash::Hash>::iterator next = pHashes.begin();
        ++next;
        if(next == pHashes.end())
        {
            // Only one entry. Hash it with itself and return
            concatHash(*pHashes.begin(), *pHashes.begin(), pResult);
            return;
        }

        std::vector<NextCash::Hash>::iterator nextNext = next;
        ++nextNext;
        if(nextNext == pHashes.end())
        {
            // Two entries. Hash them together and return
            concatHash(*pHashes.begin(), *next, pResult);
            return;
        }

        // More than two entries. Move up the tree a level.
        std::vector<NextCash::Hash> nextLevel;
        NextCash::Hash one, two, newHash;
        std::vector<NextCash::Hash>::iterator hash = pHashes.begin();

        while(hash != pHashes.end())
        {
            // Get one
            one = *hash++;

            // Get two (first one again if no second)
            if(hash == pHashes.end())
                two = one;
            else
                two = *hash++;

            // Hash these and add to the next level
            concatHash(one, two, newHash);
            nextLevel.push_back(newHash);
        }

        // Clear current level
        pHashes.clear();

        // Calculate the next level
        calculateMerkleHashLevel(nextLevel, pResult);
    }

    void Block::calculateMerkleHash(NextCash::Hash &pMerkleHash)
    {
        pMerkleHash.setSize(32);
        if(transactions.size() == 0)
            pMerkleHash.zeroize();
        else if(transactions.size() == 1)
            pMerkleHash = transactions.front()->hash;
        else
        {
            // Collect transaction hashes
            std::vector<NextCash::Hash> hashes;
            for(std::vector<Transaction *>::iterator trans = transactions.begin();
              trans != transactions.end(); ++trans)
                hashes.push_back((*trans)->hash);

            // Calculate the next level
            calculateMerkleHashLevel(hashes, pMerkleHash);
        }
    }

    bool MerkleNode::calculateHash()
    {
        if(left == NULL)
        {
            hash.setSize(32);
            hash.zeroize();
            return true;
        }

        if(left->hash.isEmpty() || right->hash.isEmpty())
            return false;

        NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
        digest.setOutputEndian(NextCash::Endian::LITTLE);
        left->hash.write(&digest);
        right->hash.write(&digest);
        hash.setSize(32);
        digest.getResult(&hash);
        return true;
    }

    MerkleNode *buildMerkleTreeLevel(std::vector<MerkleNode *> pNodes)
    {
        std::vector<MerkleNode *>::iterator node = pNodes.begin(), left, right;
        std::vector<MerkleNode *>::iterator next = pNodes.begin();
        MerkleNode *newNode;

        ++next;
        if(next == pNodes.end())
        {
            // Only one entry. It is the root.
            return *pNodes.begin();
        }

        ++next;
        if(next == pNodes.end())
        {
            // Only two entries. Combine the hash and return it.
            left = pNodes.begin();
            right = pNodes.begin();
            ++right;
            newNode = new MerkleNode(*left, *right, (*left)->matches || (*right)->matches);
            return newNode;
        }

        // Move up the tree a level.
        std::vector<MerkleNode *> nextLevel;

        while(node != pNodes.end())
        {
            // Get left
            left = node++;

            // Get right, if none remaining use same again
            if(node == pNodes.end())
                right = left;
            else
                right = node++;

            // Hash these and add to the next level
            newNode = new MerkleNode(*left, *right, (*left)->matches || (*right)->matches);
            nextLevel.push_back(newNode);
        }

        // Clear current level
        pNodes.clear();

        // Build the next level
        return buildMerkleTreeLevel(nextLevel);
    }

    MerkleNode *buildMerkleTree(std::vector<Transaction *> &pBlockTransactions,
      BloomFilter &pFilter)
    {
        if(pBlockTransactions.size() == 0)
            return new MerkleNode(NULL, NULL, false);
        else if(pBlockTransactions.size() == 1)
            return new MerkleNode(pBlockTransactions.front(),
              pFilter.contains(*pBlockTransactions.front()));

        // Build leaf nodes
        std::vector<MerkleNode *> nodes;
        for(std::vector<Transaction *>::iterator trans = pBlockTransactions.begin();
          trans != pBlockTransactions.end(); ++trans)
            nodes.push_back(new MerkleNode(*trans, pFilter.contains(**trans)));

        // Calculate the next level
        return buildMerkleTreeLevel(nodes);
    }

    MerkleNode *buildEmptyMerkleTree(unsigned int pNodeCount)
    {
        // Build leaf nodes
        std::vector<MerkleNode *> nodes;
        for(unsigned int i=0;i<pNodeCount;++i)
            nodes.push_back(new MerkleNode());

        return buildMerkleTreeLevel(nodes);
    }

    // bool MerkleNode::calculateHash()
    // {
        // if(!hash.isEmpty())
            // return true;

        // if(left == NULL || right == NULL)
            // return false;
        // if(!left->calculateHash() || !right->calculateHash())
            // return false;
        // calculateHashFromChildren();
    // }

    void MerkleNode::print(unsigned int pDepth)
    {
        NextCash::String padding;
        for(unsigned int i=0;i<pDepth;i++)
            padding += "  ";

        if(transaction != NULL)
        {
            if(matches)
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME,
                  "%sTrans (match) : %s", padding.text(), hash.hex().text());
            else
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME,
                  "%sTrans (no)    : %s", padding.text(), hash.hex().text());
        }
        else if(matches)
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME,
              "%sHash (match) : %s", padding.text(), hash.hex().text());
        else
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME,
              "%sHash (no)    : %s", padding.text(), hash.hex().text());

        if(matches && left != NULL)
        {
            if(matches)
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME,
                  "%s  Left", padding.text(), hash.hex().text());

            left->print(pDepth + 1);

            if(left != right)
            {
                if(matches)
                    NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME,
                      "%s  Right", padding.text(), hash.hex().text());
                right->print(pDepth + 1);
            }
        }
    }

    bool Block::updateOutputs(TransactionOutputPool &pOutputs, int pBlockHeight)
    {
        if(transactions.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "No transactions. At least a coin base is required");
            return false;
        }

        // Add the transaction outputs from this block to the output pool
        pOutputs.add(this->transactions, pBlockHeight);

        unsigned int transactionOffset = 0;
        std::vector<unsigned int> spentAges;
        for(std::vector<Transaction *>::iterator transaction = transactions.begin();
          transaction != transactions.end(); ++transaction)
        {
            if(!(*transaction)->updateOutputs(pOutputs, transactions, pBlockHeight, spentAges))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
                  "Transaction %d update failed", transactionOffset);
                return false;
            }
            ++transactionOffset;
        }

        if(spentAges.size() > 0)
        {
            unsigned int totalSpentAge = 0;
            for(std::vector<unsigned int>::iterator spentAge = spentAges.begin();
              spentAge != spentAges.end(); ++spentAge)
                totalSpentAge += *spentAge;
            unsigned int averageSpentAge = totalSpentAge / spentAges.size();
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
              "Average spent age for block %d is %d for %d inputs", pBlockHeight, averageSpentAge,
              spentAges.size());
        }
        return true;
    }

    bool Block::validateSize(Chain *pChain, unsigned int pBlockHeight)
    {
        if(pChain->forks().cashForkBlockHeight() == pBlockHeight &&
          size() < Forks::HARD_MAX_BLOCK_SIZE)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Cash fork block size must be greater than %d bytes : %d bytes",
              Forks::HARD_MAX_BLOCK_SIZE, size());
            return false;
        }

        if(size() > pChain->forks().blockMaxSize(pBlockHeight))
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Block size must be less than %d bytes : %d",
              pChain->forks().blockMaxSize(pBlockHeight), size());
            return false;
        }

        return true;
    }

    bool Block::validate(Chain *pChain, unsigned int pBlockHeight)
    {
        if(transactions.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "No transactions. At least a coin base is required");
            return false;
        }

        // Validate Merkle Hash
        NextCash::Hash calculatedMerkleHash;
        calculateMerkleHash(calculatedMerkleHash);
        if(calculatedMerkleHash != header.merkleHash)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Block merkle root hash is invalid");
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Included   : %s", header.merkleHash.hex().text());
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Calculated : %s", header.merkleHash.hex().text());
            return false;
        }

        return true;
    }

    bool Block::process(Chain *pChain, unsigned int pBlockHeight)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Block Process");
#endif
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
          "Processing block at height %d (%d trans) (%d KiB) : %s", pBlockHeight,
          transactions.size(), size() / 1024, header.hash.hex().text());

        // Check that this block doesn't have any duplicate transaction IDs
        if(!pChain->outputs().checkDuplicates(transactions, pBlockHeight, header.hash))
            return false;

        // Add the transaction outputs from this block to the output pool
        if(!pChain->outputs().add(transactions, pBlockHeight))
            return false;

        // Validate and process transactions
        bool isCoinBase = true;
        mFees = 0;
        unsigned int transactionOffset = 0;
        std::vector<unsigned int> spentAges;
        for(std::vector<Transaction *>::iterator transaction = transactions.begin();
          transaction != transactions.end(); ++transaction)
        {
            // NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME,
              // "Processing transaction %d", transactionOffset);
            if(!(*transaction)->process(pChain, transactions, pBlockHeight, isCoinBase,
              header.version, spentAges))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
                  "Transaction %d failed", transactionOffset);
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
            for(std::vector<unsigned int>::iterator spentAge = spentAges.begin();
              spentAge != spentAges.end(); ++spentAge)
                totalSpentAge += *spentAge;
            unsigned int averageSpentAge = totalSpentAge / spentAges.size();
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
              "Average spent age for block %d is %d for %d inputs", pBlockHeight, averageSpentAge,
              spentAges.size());
        }

        // Check that coinbase output amount - fees is correct for block height
        if(-transactions.front()->fee() - mFees > coinBaseAmount(pBlockHeight))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Coinbase outputs are too high");
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Coinbase %.08f", bitcoins(-transactions.front()->fee()));
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Fees     %.08f", bitcoins(mFees));
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Block %d Coinbase amount should be %.08f", pBlockHeight,
              bitcoins(coinBaseAmount(pBlockHeight)));
            return false;
        }

        return true;
    }

    Block *Block::genesis(uint32_t pTargetBits)
    {
        Block *result = new Block();

        result->header.version = 1;
        result->header.previousHash.zeroize();

        if(network() == TESTNET)
        {
            result->header.time = 1296688602;
            result->header.targetBits = pTargetBits;
            result->header.nonce = 414098458;
        }
        else
        {
            result->header.time = 1231006505;
            result->header.targetBits = pTargetBits;
            result->header.nonce = 2083236893;
        }
        result->header.transactionCount = 1;

        Transaction *transaction = new Transaction();
        transaction->version = 1;

        transaction->inputs.emplace_back();
        Input &input = transaction->inputs.back();
        input.script.writeHex("04FFFF001D0104455468652054696D65732030332F4A616E2F32303039204368616E63656C6C6F72206F6E206272696E6B206F66207365636F6E64206261696C6F757420666F722062616E6B73");
        input.script.compact();

        transaction->outputs.emplace_back();
        Output &output = transaction->outputs.back();
        output.amount = 5000000000;
        output.script.writeHex("4104678AFDB0FE5548271967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC");
        output.script.compact();

        transaction->lockTime = 0;
        transaction->calculateHash();

        result->transactions.push_back(transaction);

        result->calculateMerkleHash(result->header.merkleHash);
        result->header.calculateHash();

        return result;
    }

    void Block::finalize()
    {
        //TODO Update total coinbase amount

        header.transactionCount = transactions.size();
        calculateMerkleHash(header.merkleHash);
        header.calculateHash();

        while(!header.hasProofOfWork())
        {
            header.nonce = NextCash::Math::randomLong();
            header.calculateHash();
        }
    }

    class BlockFile
    {
    public:

        static const unsigned int MAX_COUNT = 100; // Maximum count of blocks in one file.

        static unsigned int fileID(unsigned int pHeight) { return pHeight / MAX_COUNT; }
        static unsigned int fileOffset(unsigned int pHeight) { return pHeight - (fileID(pHeight) * MAX_COUNT); }
        static NextCash::String filePathName(unsigned int pID);

        static const unsigned int CACHE_COUNT = 5;
        static NextCash::MutexWithConstantName sCacheLock;
        static BlockFile *sCache[CACHE_COUNT];

        // Return locked header file.
        static BlockFile *get(unsigned int pFileID, bool pCreate = false);

        // Moves cached header file to the front of the list
        static void moveToFront(unsigned int pOffset);

        static bool exists(unsigned int pID);

        static void save();

        // Cleans up cached data.
        static void clean();

        // Remove a block file
        static bool remove(unsigned int pID);


        BlockFile(unsigned int pID, bool pCreate);
        ~BlockFile() { updateCRC(); if(mInputFile != NULL) delete mInputFile; }

        void lock() { mMutex.lock(); }
        void unlock() { mMutex.unlock(); }

        unsigned int id() const { return mID; }
        bool isValid() const { return mValid; }
        bool isFull() { return itemCount() == MAX_COUNT; }
        unsigned int itemCount() { getLastCount(); return mCount; }
        const NextCash::Hash &lastHash() { getLastCount(); return mLastHash; }

        bool validate(); // Validate CRC

        // Add a block to the file
        bool writeBlock(const Block &pBlock);

        // Remove blocks from file above a specific offset in the file
        bool removeBlocksAbove(unsigned int pOffset);

        // Read block at specified offset in file. Return false if the offset is too high.
        bool readTransactions(unsigned int pOffset, std::vector<Transaction *> &pTransactions);

        // Read an output at the specified file offset.
        bool readOutput(NextCash::stream_size pFileOffset, Output &pOutput);

        bool readOutput(unsigned int pBlockOffset, unsigned int pTransactionOffset,
          unsigned int pOutputIndex, NextCash::Hash &pTransactionID, Output &pOutput);

    private:

        /* File format
         *   Start string
         *   CRC32 of data after CRC in file
         *   MAX_COUNT Index entries (32 byte block hash, 4 byte offset into file of block data)
         *   Data - Transactions for blocks
         */
        static const unsigned int CRC_OFFSET = 8; // After start string
        static const unsigned int HEADER_START_OFFSET = 12;
        static const unsigned int HEADER_ITEM_SIZE = 36; // 32 byte hash, 4 byte data offset
        static const unsigned int DATA_START_OFFSET = HEADER_START_OFFSET +
          (MAX_COUNT * HEADER_ITEM_SIZE);
        static constexpr const char *START_STRING = "NCBLKS01";
        static const unsigned int INVALID_COUNT = 0xffffffff;

        static NextCash::String sFilePath;

        // Open and validate a file stream for reading
        bool openFile(bool pCreate = false);

        void updateCRC();

        unsigned int mID;
        NextCash::MutexWithConstantName mMutex;
        NextCash::FileInputStream *mInputFile;
        NextCash::String mFilePathName;
        bool mValid;
        bool mModified;

        void getLastCount();
        unsigned int mCount;
        NextCash::Hash mLastHash;

        BlockFile(BlockFile &pCopy);
        BlockFile &operator = (BlockFile &pRight);

    };

    NextCash::String BlockFile::sFilePath;
    NextCash::MutexWithConstantName BlockFile::sCacheLock("BlockFileCache");
    BlockFile *BlockFile::sCache[CACHE_COUNT] = { NULL, NULL, NULL, NULL, NULL };

    void BlockFile::moveToFront(unsigned int pOffset)
    {
        static BlockFile *swap[CACHE_COUNT] = { NULL, NULL, NULL, NULL, NULL };

        if(pOffset == 0)
            return;

        unsigned int next = 0;
        swap[next++] = sCache[pOffset];
        for(unsigned int j = 0; j < (int)CACHE_COUNT; ++j)
            if(j != pOffset)
                swap[next++] = sCache[j];

        // Swap back
        for(unsigned int j = 0; j < CACHE_COUNT; ++j)
            sCache[j] = swap[j];
    }

    bool BlockFile::exists(unsigned int pFileID)
    {
        return NextCash::fileExists(BlockFile::filePathName(pFileID));
    }

    BlockFile *BlockFile::get(unsigned int pFileID, bool pCreate)
    {
        sCacheLock.lock();

        // Check if the file is already open
        for(unsigned int i = 0; i < CACHE_COUNT; ++i)
            if(sCache[i] != NULL && sCache[i]->mID == pFileID)
            {
                BlockFile *result = sCache[i];
                result->lock();
                moveToFront(i);
                sCacheLock.unlock();
                return result;
            }

        // Open file
        BlockFile *result = new BlockFile(pFileID, pCreate);
        if(!result->isValid())
        {
            delete result;
            sCacheLock.unlock();
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME,
              "Block file %08x failed to open.", pFileID);
            return NULL;
        }

        result->lock();

        for(unsigned int i = 0; i < CACHE_COUNT; ++i)
            if(sCache[i] == NULL)
            {
                sCache[i] = result;
                moveToFront(i);
                sCacheLock.unlock();
                return result;
            }

        // Replace the last file
        delete sCache[CACHE_COUNT - 1];
        sCache[CACHE_COUNT - 1] = result;
        moveToFront(CACHE_COUNT-1);
        sCacheLock.unlock();
        return result;
    }

    bool BlockFile::remove(unsigned int pFileID)
    {
        // Remove from cache.
        sCacheLock.lock();

        // Check if the file is already open.
        bool found = false;
        for(unsigned int i = 0; i < CACHE_COUNT; ++i)
            if(sCache[i] != NULL && sCache[i]->mID == pFileID)
            {
                delete sCache[i];
                sCache[i] = NULL;
                found = true;
                break;
            }

        if(found)
        {
            // Push any files after up a slot.
            for(unsigned int i = 0; i < CACHE_COUNT - 1; ++i)
                if(sCache[i] == NULL)
                {
                    sCache[i] = sCache[i+1];
                    sCache[i+1] = NULL;
                }
        }

        sCacheLock.unlock();

        if(NextCash::removeFile(filePathName(pFileID)))
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_BLOCK_LOG_NAME,
              "Removed block file %08x", pFileID);
            return true;
        }

        return false;
    }

    void BlockFile::save()
    {
        sCacheLock.lock();
        for(int i = CACHE_COUNT-1; i >= 0; --i)
            if(sCache[i] != NULL)
                sCache[i]->updateCRC();
        sCacheLock.unlock();
    }

    void BlockFile::clean()
    {
        sCacheLock.lock();
        for(int i = CACHE_COUNT-1; i >= 0; --i)
            if(sCache[i] != NULL)
            {
                delete sCache[i];
                sCache[i] = NULL;
            }
        sCacheLock.unlock();

        sFilePath.clear();
    }

    void Block::save()
    {
        BlockFile::save();
    }

    void Block::clean()
    {
        BlockFile::clean();
    }

    NextCash::String BlockFile::filePathName(unsigned int pID)
    {
        if(!sFilePath)
        {
            // Build path
            sFilePath = Info::instance().path();
            sFilePath.pathAppend("blocks");
            NextCash::createDirectory(sFilePath);
        }

        // Build path
        NextCash::String result;
        result.writeFormatted("%s%s%08x", sFilePath.text(), NextCash::PATH_SEPARATOR, pID);
        return result;
    }

    BlockFile::BlockFile(unsigned int pID, bool pCreate) : mMutex("BlockFile")
    {
        mValid = true;
        mFilePathName = filePathName(pID);
        mInputFile = NULL;
        mID = pID;
        mModified = false;
        mCount = INVALID_COUNT;

        if(!openFile(pCreate))
        {
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME,
              "Failed to open block file : %s", mFilePathName.text());
            mValid = false;
            return;
        }

        // Read start string
        NextCash::String startString = mInputFile->readString(8);

        // Check start string
        if(startString != START_STRING)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_BLOCK_LOG_NAME,
              "Block file %08x missing start string", mID);
            mValid = false;
            return;
        }
    }

    bool BlockFile::openFile(bool pCreate)
    {
        if(mInputFile != NULL && mInputFile->isValid())
            return true;

        if(mInputFile != NULL)
            delete mInputFile;

        mInputFile = new NextCash::FileInputStream(mFilePathName);
        mInputFile->setInputEndian(NextCash::Endian::LITTLE);
        mInputFile->setReadOffset(0);

        if(mInputFile->isValid())
            return true;
        else if(!pCreate)
        {
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME,
              "Block file %08x not found.", mID);
            return false;
        }

        // Create new file
        delete mInputFile;
        mInputFile = NULL;

        NextCash::FileOutputStream *outputFile = new NextCash::FileOutputStream(mFilePathName,
          true);
        outputFile->setOutputEndian(NextCash::Endian::LITTLE);

        if(!outputFile->isValid())
        {
            delete outputFile;
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
              "Block file %08x failed to open.", mID);
            return false;
        }

        // Write start string
        outputFile->writeString(START_STRING);

        // Write empty CRC
        outputFile->writeUnsignedInt(0);

        // Write empty index entries
        NextCash::Digest digest(NextCash::Digest::CRC32);
        digest.setOutputEndian(NextCash::Endian::LITTLE);
        NextCash::Hash zeroHash(32);
        for(unsigned int i = 0; i < MAX_COUNT; ++i)
        {
            zeroHash.write(outputFile); // Block hash
            outputFile->writeUnsignedInt(0); // Data offset

            // For digest
            zeroHash.write(&digest);
            digest.writeUnsignedInt(0);
        }

        // Get initial CRC
        NextCash::Buffer crcBuffer;
        crcBuffer.setEndian(NextCash::Endian::LITTLE);
        digest.getResult(&crcBuffer);
        uint32_t crc = crcBuffer.readUnsignedInt();

        // Write CRC
        outputFile->setWriteOffset(CRC_OFFSET);
        outputFile->writeUnsignedInt(crc);

        // Close file
        delete outputFile;

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
          "Block file %08x created with CRC : %08x", mID, crc);

        // Re-open file
        mInputFile = new NextCash::FileInputStream(mFilePathName);
        mInputFile->setInputEndian(NextCash::Endian::LITTLE);
        mInputFile->setReadOffset(0);

        return mInputFile->isValid();
    }

    void BlockFile::updateCRC()
    {
        if(!mModified || !mValid)
            return;

#ifdef PROFILER_ON
        NextCash::Profiler profiler("Block Update CRC", false);
        profiler.start();
#endif
        if(!openFile())
        {
            mValid = false;
            return;
        }

        // Calculate new CRC
        NextCash::Digest digest(NextCash::Digest::CRC32);
        digest.setOutputEndian(NextCash::Endian::LITTLE);

        // Read file into digest
        mInputFile->setReadOffset(HEADER_START_OFFSET);
        digest.writeStream(mInputFile, mInputFile->remaining());

        // Close input file
        delete mInputFile;
        mInputFile = NULL;

        // Get CRC result
        NextCash::Buffer crcBuffer;
        crcBuffer.setEndian(NextCash::Endian::LITTLE);
        digest.getResult(&crcBuffer);
        uint32_t crc = crcBuffer.readUnsignedInt();

        // Open output file
        NextCash::FileOutputStream *outputFile = new NextCash::FileOutputStream(mFilePathName);

        // Write CRC to file
        outputFile->setOutputEndian(NextCash::Endian::LITTLE);
        outputFile->setWriteOffset(CRC_OFFSET);
        outputFile->writeUnsignedInt(crc);

        // Close output file
        delete outputFile;
        mModified = false;

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
          "Block file %08x CRC updated : %08x", mID, crc);
    }

    bool BlockFile::validate()
    {
        // Read CRC
        mInputFile->setReadOffset(CRC_OFFSET);
        uint32_t crc = mInputFile->readUnsignedInt();

        // Calculate CRC
        NextCash::Digest digest(NextCash::Digest::CRC32);
        digest.setOutputEndian(NextCash::Endian::LITTLE);
        digest.writeStream(mInputFile, mInputFile->remaining());

        // Get Calculated CRC
        NextCash::Buffer crcBuffer;
        crcBuffer.setEndian(NextCash::Endian::LITTLE);
        digest.getResult(&crcBuffer);
        uint32_t calculatedCRC = crcBuffer.readUnsignedInt();

        // Check CRC
        if(crc != calculatedCRC)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_BLOCK_LOG_NAME,
              "Block file %08x has invalid CRC : %08x != %08x", mID, crc, calculatedCRC);
            return false;
        }

        return true;
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
        mInputFile->setReadOffset(HEADER_START_OFFSET + ((MAX_COUNT - 1) * HEADER_ITEM_SIZE) +
          32);

        // Check each data offset until it is not empty
        for(mCount = MAX_COUNT; mCount > 0; --mCount)
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

    bool BlockFile::writeBlock(const Block &pBlock)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Block Add");
#endif
        if(!openFile())
            return false;

        unsigned int count = itemCount();

        if(count == MAX_COUNT)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Block file %08x is already full", mID);
            return false;
        }

        // New blocks are appended to the file
        NextCash::stream_size nextBlockOffset = mInputFile->length();

        if(mInputFile != NULL)
            delete mInputFile;
        mInputFile = NULL;

        NextCash::FileOutputStream *outputFile = new NextCash::FileOutputStream(mFilePathName);
        outputFile->setOutputEndian(NextCash::Endian::LITTLE);
        if(!outputFile->isValid())
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Block file %08x output file failed to open", mID);
            delete outputFile;
            return false;
        }

        // Write hash and offset to file
        outputFile->setWriteOffset(HEADER_START_OFFSET + (count * HEADER_ITEM_SIZE));
        pBlock.header.hash.write(outputFile);
        outputFile->writeUnsignedInt(nextBlockOffset);

        // Write block data at end of file
        outputFile->setWriteOffset(nextBlockOffset);

        // Transaction count (4 bytes)
        outputFile->writeUnsignedInt(pBlock.transactions.size());

        // Transactions
        for(std::vector<Transaction *>::const_iterator trans = pBlock.transactions.begin();
          trans != pBlock.transactions.end(); ++trans)
            (*trans)->write(outputFile, true);

        delete outputFile;

        mLastHash = pBlock.header.hash;
        ++mCount;
        mModified = true;
        return true;
    }

    bool Block::add(unsigned int pBlockHeight, const Block &pBlock)
    {
        BlockFile *file = BlockFile::get(BlockFile::fileID(pBlockHeight), true);
        if(file == NULL)
            return false;

        if(pBlockHeight != 0)
        {
            // Check previous hash
            if(file->itemCount() == 0)
            {
                // First block in file. Verify last hash of previous file.
                BlockFile *previousFile = BlockFile::get(BlockFile::fileID(pBlockHeight) - 1);
                if(previousFile == NULL)
                {
                    file->unlock();
                    return false;
                }

                if(previousFile->lastHash() != pBlock.header.previousHash)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
                      "Block file %08x add block failed : Invalid previous file last hash : %s",
                      BlockFile::fileID(pBlockHeight), previousFile->lastHash().hex().text());
                    file->unlock();
                    previousFile->unlock();
                    return false;
                }

                previousFile->unlock();
            }
            else if(file->lastHash() != pBlock.header.previousHash)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
                  "Block file %08x add block failed : Invalid previous hash : %s",
                  BlockFile::fileID(pBlockHeight), file->lastHash().hex().text());
                file->unlock();
                return false;
            }
        }

        bool success = file->writeBlock(pBlock);
        file->unlock();
        return success;
    }

    bool BlockFile::removeBlocksAbove(unsigned int pOffset)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Block Remove Above");
#endif
        if(!openFile())
            return false;

        unsigned int count = itemCount();
        if(count <= pOffset || pOffset >= (MAX_COUNT - 1))
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Block file %08x offset not above %d", mID, pOffset);
            return false;
        }

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
          "Block file %08x reverting to count of %d", mID, pOffset);

        NextCash::String swapFilePathName = mFilePathName + ".swap";
        NextCash::FileOutputStream *swapFile = new NextCash::FileOutputStream(swapFilePathName,
          true);

        if(!swapFile->isValid())
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_BLOCK_LOG_NAME,
              "Block file %08x swap output file failed to open", mID);
            delete swapFile;
            return false;
        }

        // Write start string
        swapFile->writeString(START_STRING);

        // Write empty CRC
        swapFile->writeUnsignedInt(0);

        mInputFile->setReadOffset(HEADER_START_OFFSET);
        NextCash::Hash hash(32);

        // Transafer block to swap file
        for(unsigned int i = 0; i <= pOffset; ++i)
        {
            if(!hash.read(mInputFile))
                return false;
            hash.write(swapFile);
            swapFile->writeUnsignedInt(mInputFile->readUnsignedInt());
        }

        mLastHash = hash;

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
          "Block file %08x new last hash : %s", mID, mLastHash.hex().text());

        // Get data offset of first block to be removed
        if(!hash.read(mInputFile))
            return false;
        NextCash::stream_size newFileSize = mInputFile->readUnsignedInt();

        // Write the rest of the block as empty
        hash.zeroize();
        for(unsigned int i = pOffset + 1; i < MAX_COUNT; ++i)
        {
            hash.write(swapFile);
            swapFile->writeUnsignedInt(0);
        }

        // Copy block data to swap file
        mInputFile->setReadOffset(DATA_START_OFFSET);
        swapFile->writeStream(mInputFile, newFileSize - swapFile->writeOffset());

        delete mInputFile;
        mInputFile = NULL;
        delete swapFile;

        mCount = pOffset + 1;
        mModified = true;

        if(!NextCash::renameFile(swapFilePathName, mFilePathName))
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
              "Block file %08x failed to rename swap file", mID);
            return false;
        }

        return true;
    }

    bool Block::revertToHeight(unsigned int pBlockHeight)
    {
        unsigned int fileID = BlockFile::fileID(pBlockHeight);
        unsigned int fileOffset = BlockFile::fileOffset(pBlockHeight);

        // Truncate latest file
        if(fileOffset != BlockFile::MAX_COUNT - 1)
        {
            BlockFile *file = BlockFile::get(fileID, true);
            if(file == NULL)
                return false;

            file->removeBlocksAbove(fileOffset);
            file->unlock();
            ++fileID;
        }

        // Remove any files after that
        while(true)
        {
            if(!BlockFile::remove(fileID))
                return !BlockFile::exists(fileID);

            ++fileID;
        }

        return true;
    }

    bool BlockFile::readTransactions(unsigned int pOffset, std::vector<Transaction *> &pTransactions)
    {
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        // Go to location in header where the data offset to the block is
        mInputFile->setReadOffset(HEADER_START_OFFSET + (pOffset * HEADER_ITEM_SIZE) + 32);

        unsigned int offset = mInputFile->readUnsignedInt();
        if(offset == 0)
            return false;

        Transaction *transaction;
        mInputFile->setReadOffset(offset);
        uint32_t transactionCount = mInputFile->readUnsignedInt();
        pTransactions.reserve(transactionCount);
        for(unsigned int i = 0; i < transactionCount; ++i)
        {
            transaction = new Transaction();
            if(transaction->read(mInputFile, true, true))
                pTransactions.push_back(transaction);
            else
            {
                delete transaction;
                return false;
            }
        }

        return true;
    }

    bool Block::getBlock(unsigned int pBlockHeight, Block &pBlock)
    {
        pBlock.clearTransactions();

        if(!Header::getHeader(pBlockHeight, pBlock.header))
            return false;

        BlockFile *file = BlockFile::get(BlockFile::fileID(pBlockHeight));
        if(file == NULL)
            return false;

        bool success = file->readTransactions(BlockFile::fileOffset(pBlockHeight), pBlock.transactions);
        file->unlock();

        pBlock.header.transactionCount = pBlock.transactions.size();

        return success;
    }

    bool BlockFile::readOutput(NextCash::stream_size pFileOffset, Output &pOutput)
    {
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        // Go to location in header where the data offset to the block is
        mInputFile->setReadOffset(pFileOffset);
        return pOutput.read(mInputFile, true);
    }

    bool Block::getOutput(unsigned int pBlockHeight, OutputReference &pReference, Output &pOutput)
    {
        BlockFile *file = BlockFile::get(BlockFile::fileID(pBlockHeight));
        if(file == NULL)
            return false;

        bool success = file->readOutput(pReference.blockFileOffset, pOutput);
        file->unlock();
        return success;
    }

    bool BlockFile::readOutput(unsigned int pBlockOffset, unsigned int pTransactionOffset,
      unsigned int pOutputIndex, NextCash::Hash &pTransactionID, Output &pOutput)
    {
        if(!openFile())
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
              "Failed to read output. Block file 0x%08x couldn't be opened.", mID);
            mValid = false;
            return false;
        }

        // Go to location in header where the data offset to the block is
        mInputFile->setReadOffset(HEADER_START_OFFSET + (pBlockOffset * HEADER_ITEM_SIZE) + 32);

        unsigned int offset = mInputFile->readUnsignedInt();
        if(offset == 0)
            return false;

        mInputFile->setReadOffset(offset); // Go to block data

        uint32_t transactionCount = mInputFile->readUnsignedInt();
        if(transactionCount <= pTransactionOffset)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BLOCK_LOG_NAME,
              "Block at offset %d doesn't have enough transactions %d/%d. Block file 0x%08x couldn't be opened.",
              pBlockOffset, pTransactionOffset, transactionCount, mID);
            return false;
        }

        for(int i=0;i<(int)pTransactionOffset;++i)
            if(!Transaction::skip(mInputFile))
                return false;

        return Transaction::readOutput(mInputFile, pOutputIndex, pTransactionID, pOutput, true);
    }

    bool Block::getOutput(unsigned int pBlockHeight, unsigned int pTransactionOffset,
      unsigned int pOutputIndex, NextCash::Hash &pTransactionID, Output &pOutput)
    {
        BlockFile *file = BlockFile::get(BlockFile::fileID(pBlockHeight));
        if(file == NULL)
            return false;

        unsigned int offset = BlockFile::fileOffset(pBlockHeight);

        bool success = file->readOutput(offset, pTransactionOffset, pOutputIndex, pTransactionID,
          pOutput);
        file->unlock();
        return success;
    }

    unsigned int Block::totalCount()
    {
        unsigned int result = 0;
        unsigned int fileID = 0;
        while(BlockFile::exists(fileID))
        {
            result += BlockFile::MAX_COUNT;
            ++fileID;
        }

        if(fileID > 0)
        {
            // Adjust for last file not being full.
            --fileID;
            result -= BlockFile::MAX_COUNT;

            BlockFile *file = BlockFile::get(fileID);
            if(file != NULL)
            {
                result += file->itemCount();
                file->unlock();
            }
        }

        return result;
    }

    unsigned int Block::validate()
    {
        unsigned int result = 0;
        unsigned int fileID = 0;
        BlockFile *file;

        // Find top file ID.
        while(BlockFile::exists(fileID))
            fileID += 100;

        while(fileID > 0 && !BlockFile::exists(fileID))
            --fileID;

        result = fileID * BlockFile::MAX_COUNT;

        // Adjust for last file not being full.
        while(true)
        {
            file = BlockFile::get(fileID);
            if(file == NULL)
            {
                BlockFile::remove(fileID);
                if(fileID == 0)
                    break;
                --fileID;
                result -= BlockFile::MAX_COUNT;
            }
            else if(file->validate())
            {
                result += file->itemCount();
                file->unlock();
                break;
            }
            else
            {
                file->unlock();
                BlockFile::remove(fileID);
                if(fileID == 0)
                    break;
                --fileID;
                result -= BlockFile::MAX_COUNT;
            }

            if(fileID == 0)
                break;
        }

        return result;
    }
}
