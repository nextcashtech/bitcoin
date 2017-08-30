#include "block.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/base/thread.hpp"
#include "arcmist/io/file_stream.hpp"
#include "arcmist/crypto/digest.hpp"
#include "info.hpp"

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

    void Block::write(ArcMist::OutputStream *pStream, bool pIncludeTransactions)
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

        // Transaction Count
        writeCompactInteger(pStream, transactionCount);

        if(!pIncludeTransactions)
            return;

        // Transactions
        for(uint64_t i=0;i<transactions.size();i++)
            transactions[i].write(pStream);
    }

    bool Block::read(ArcMist::InputStream *pStream, bool pIncludeTransactions, bool pCalculateHash)
    {
        // Create hash
        ArcMist::Digest *sha256 = NULL;
        if(pCalculateHash)
            sha256 = new ArcMist::Digest(ArcMist::Digest::SHA256);
        hash.clear();

        if(pStream->remaining() < 81)
        {
            if(sha256 != NULL)
                delete sha256;
            return false;
        }

        // Version
        version = pStream->readUnsignedInt();
        if(pCalculateHash)
            sha256->writeUnsignedInt(version);

        // Hash of previous block
        previousHash.read(pStream);
        if(pCalculateHash)
            previousHash.write(sha256);

        // Merkle Root Hash
        merkleHash.read(pStream);
        if(pCalculateHash)
            previousHash.write(sha256);

        // Time
        time = pStream->readUnsignedInt();
        if(pCalculateHash)
            sha256->writeUnsignedInt(time);

        // Encoded version of target threshold
        bits = pStream->readUnsignedInt();
        if(pCalculateHash)
            sha256->writeUnsignedInt(bits);

        // Nonce
        nonce = pStream->readUnsignedInt();
        if(pCalculateHash)
            sha256->writeUnsignedInt(nonce);

        // Transaction Count
        transactionCount = readCompactInteger(pStream);
        if(pCalculateHash)
            writeCompactInteger(sha256, transactionCount);

        if(pCalculateHash)
        {
            // Get SHA256 of block data
            ArcMist::Buffer hashData(32);
            sha256->getResult(&hashData);

            // Double SHA256
            ArcMist::Buffer doubleHashData(32);
            ArcMist::Digest::sha256(&hashData, hashData.length(), &doubleHashData);

            // Write to hash
            hash.read(&doubleHashData, 32);
        }

        if(sha256 != NULL)
        {
            delete sha256;
            sha256 = NULL;
        }

        if(!pIncludeTransactions)
            return true;

        if(pStream->remaining() < transactionCount)
        {
            if(sha256 != NULL)
                delete sha256;
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
        ArcMist::Digest sha256(ArcMist::Digest::SHA256);
        write(&sha256, true);

        // Get SHA256 of block data
        ArcMist::Buffer hashData(32);
        sha256.getResult(&hashData);

        // Double SHA256
        ArcMist::Buffer doubleHashData(32);
        ArcMist::Digest::sha256(&hashData, hashData.length(), &doubleHashData);

        // Write to hash
        hash.read(&doubleHashData, 32);
    }

    void concatHash(const Hash *pFirst, const Hash *pSecond, Hash &pResult)
    {
        ArcMist::Buffer concatIDs;
        pFirst->write(&concatIDs);
        pSecond->write(&concatIDs);
        doubleSHA256(&concatIDs, concatIDs.length(), pResult);
    }

    void calculateMerkleHash(std::vector<Hash *>::iterator pIter, std::vector<Hash *>::iterator pEnd, Hash &pResult)
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
        calculateMerkleHash(nextLevel.begin(), nextLevel.end(), pResult);

        // Destroy the next level
        for(std::vector<Hash *>::iterator i=nextLevel.begin();i!=nextLevel.end();++i)
            delete *i;
    }

    bool Block::process(UnspentPool &pUnspentPool)
    {
        // Validate Merkle Hash
        Hash calculatedMerkleHash;
        if(transactions.size() == 1)
            calculatedMerkleHash = transactions.front().hash;
        else
        {
            // Collect transaction hashes
            std::vector<Hash *> hashes;
            for(std::vector<Transaction>::iterator i=transactions.begin();i!=transactions.end();++i)
                hashes.push_back(&(*i).hash);

            // Calculate the next level
            calculateMerkleHash(hashes.begin(), hashes.end(), calculatedMerkleHash);
        }

        if(calculatedMerkleHash != merkleHash)
        {
            ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Block merkle root hash is invalid");
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Included   : %s", merkleHash.hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Calculated : %s", merkleHash.hex().text());
            return false;
        }

        // Validate and process transactions
        for(std::vector<Transaction>::iterator i=transactions.begin();i!=transactions.end();++i)
            if(!(*i).process(pUnspentPool, false))
                return false;

        return true;
    }

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
        static constexpr const char *START_STRING = "AMBLKS01";

        BlockFile(unsigned int pID, const char *pFilePathName);
        ~BlockFile() { updateCRC(); }

        unsigned int id;
        ArcMist::FileStream stream;
        bool isValid;
        unsigned int crc;

        bool isFull();
        unsigned int blockCount();
        Hash lastHash();

        // Add a block to the file
        bool addBlock(Block &pBlock);

        // Read list of block hashes from this file. If pStartingHash is empty then start with first block
        bool readBlockHashes(HashList &pHashes, const Hash &pStartingHash, unsigned int pCount);

        // Read list of block headers from this file. If pStartingHash is empty then start with first block
        bool readBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, unsigned int pCount);

        // Read block for specified hash
        bool readBlock(const Hash &pHash, Block &pBlock, bool pIncludeTransactions);
        
        void updateCRC();

    };

    BlockFile::BlockFile(unsigned int pID, const char *pFilePathName) : stream(pFilePathName)
    {
        id = pID;

        stream.setInputEndian(ArcMist::Endian::LITTLE);
        stream.setOutputEndian(ArcMist::Endian::LITTLE);

        if(stream.remaining() == 0)
        {
            // Create empty header
            // Write start string
            stream.writeString(START_STRING);

            // Write empty CRC
            stream.writeUnsignedInt(0);

            // Write empty hashes
            Hash emptyHash(32);
            for(unsigned int i=0;i<MAX_BLOCKS;i++)
            {
                emptyHash.write(&stream);
                stream.writeUnsignedInt(0);
            }

            return;
        }

        // Check for minimum valid file size
        if(stream.remaining() < HASHES_OFFSET + (MAX_BLOCKS * (32 + 4)))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_LOG_NAME, "Block file smaller than header");
            isValid = false;
            return;
        }

        // Read start string
        ArcMist::String startString = stream.readString(8);

        // Check start string
        if(startString != START_STRING)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_LOG_NAME, "Block file missing start string");
            isValid = false;
            return;
        }

        // Read CRC
        crc = stream.readUnsignedInt();

        // Check CRC
        ArcMist::Buffer crcBuffer;
        crcBuffer.setInputEndian(ArcMist::Endian::LITTLE);
        crcBuffer.setOutputEndian(ArcMist::Endian::LITTLE);
        ArcMist::Digest::crc32(&stream, stream.remaining(), &crcBuffer);
        if(crc != crcBuffer.readUnsignedInt())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_LOG_NAME, "Block file has invalid CRC");
            isValid = false;
            return;
        }
    }
    
    bool BlockFile::isFull()
    {
        if(!isValid)
            return false;

        // Read last hash
        stream.setReadOffset(HASHES_OFFSET + ((MAX_BLOCKS - 1) * 36) + 32);
        return stream.readUnsignedInt() != 0;
    }

    unsigned int BlockFile::blockCount()
    {
        if(!isValid)
            return 0;

        // Find last non empty hash
        Hash hash(32);
        unsigned int result = 0;
        stream.setReadOffset(HASHES_OFFSET);
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            if(!hash.read(&stream, 32))
                return false;
            if(stream.readUnsignedInt() != 0)
                result++;
            else
                break;
        }

        return result;
    }

    Hash BlockFile::lastHash()
    {
        Hash result(32);

        if(!isValid)
            return result;

        // Find last non empty hash
        stream.setReadOffset(HASHES_OFFSET);
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            if(!result.read(&stream, 32))
                return false;
            if(stream.readUnsignedInt() == 0)
                break;
        }

        return result;
    }

    bool BlockFile::addBlock(Block &pBlock)
    {
        if(!isValid)
            return false;

        Hash hash(32);
        unsigned int hashOffset = 0;
        bool previousMatches = false;

        // Find next empty hash
        stream.setReadOffset(HASHES_OFFSET);
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            hashOffset = stream.readOffset();
            if(!hash.read(&stream, 32))
                return false;
            previousMatches = hash == pBlock.previousHash;
            if(hash.isZero())
                break;
            stream.readUnsignedInt(); // data offset
        }

        if(!hash.isZero())
            return false; // Block was full

        if(!previousMatches)
            return false; // previousHash from this block doesn't match the last block in this file so it isn't valid

        // Write block data at end of file
        unsigned int blockOffset = stream.length();
        stream.setWriteOffset(stream.length());
        pBlock.write(&stream, true);

        // Calculate hash
        stream.setReadOffset(blockOffset);
        doubleSHA256(&stream, stream.remaining(), hash);

        // Write hash entry at beginning of file
        stream.setWriteOffset(hashOffset);
        hash.write(&stream);
        stream.writeUnsignedInt(blockOffset);
        return true;
    }

    // If pStartingHash is empty then start with first hash in file
    bool BlockFile::readBlockHashes(HashList &pHashes, const Hash &pStartingHash, unsigned int pCount)
    {
        if(!isValid)
            return false;

        Hash hash(32);
        Hash *newHash;
        bool started = pStartingHash.isEmpty();
        stream.setReadOffset(HASHES_OFFSET);
        for(unsigned int i=0;i<MAX_BLOCKS && pHashes.size()<pCount;i++)
        {
            if(!hash.read(&stream))
                return false;
            if(started || hash == pStartingHash)
            {
                started = true;
                newHash = new Hash(32);
                (*newHash) = hash;
                pHashes.push_back(newHash);
            }
            stream.readUnsignedInt(); // skip over file offset to next hash
        }

        return true;
    }

    // If pStartingHash is empty then start with first block in file
    bool BlockFile::readBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, unsigned int pCount)
    {
        if(!isValid)
            return false;

        Hash hash(32);
        Block *newBlockHeader;
        unsigned int fileOffset;
        unsigned int nextHashOffset = 0;
        unsigned int fileHashOffset = 0;
        bool startAtFirst = pStartingHash.isEmpty();
        while(pBlockHeaders.size() < pCount)
        {
            if(nextHashOffset == 0)
            {
                // Find starting hash
                stream.setReadOffset(HASHES_OFFSET);
                for(unsigned int i=0;i<MAX_BLOCKS;i++)
                {
                    if(!hash.read(&stream))
                        return false;
                    if(startAtFirst || hash == pStartingHash)
                    {
                        // Go to file offset of block data
                        fileOffset = stream.readUnsignedInt();
                        nextHashOffset = stream.readOffset();
                        if(fileOffset == 0)
                            return false;
                        stream.setReadOffset(fileOffset);
                    }
                    stream.readUnsignedInt(); // skip over file offset to next hash
                    fileHashOffset++;
                }
                if(nextHashOffset == 0)
                    return false; // Hash not found
            }
            else
            {
                stream.setReadOffset(nextHashOffset);
                if(!hash.read(&stream))
                    return false;
                // Go to file offset of block data
                fileOffset = stream.readUnsignedInt();
                nextHashOffset = stream.readOffset();
                if(fileOffset == 0)
                    return false;
                stream.setReadOffset(fileOffset);
                fileHashOffset++;
            }

            newBlockHeader = new Block();
            newBlockHeader->read(&stream, false);
            pBlockHeaders.push_back(newBlockHeader);

            if(fileHashOffset == MAX_BLOCKS)
                return true; // Reached last block in file
        }

        return true;
    }

    bool BlockFile::readBlock(const Hash &pHash, Block &pBlock, bool pIncludeTransactions)
    {
        if(!isValid)
            return false;

        // Find offset
        Hash hash(32);
        stream.setReadOffset(HASHES_OFFSET);
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            if(!hash.read(&stream))
                return false;
            if(hash == pHash)
            {
                // Read block
                unsigned int fileOffset = stream.readUnsignedInt();
                if(fileOffset == 0)
                    return false;
                stream.setReadOffset(fileOffset);
                return pBlock.read(&stream, pIncludeTransactions);
            }
            stream.readUnsignedInt(); // data offset
        }

        return false;
    }

    void BlockFile::updateCRC()
    {
        // Calculate new CRC
        stream.setReadOffset(HASHES_OFFSET);
        ArcMist::Buffer crcBuffer;
        crcBuffer.setInputEndian(ArcMist::Endian::LITTLE);
        crcBuffer.setOutputEndian(ArcMist::Endian::LITTLE);
        ArcMist::Digest::crc32(&stream, stream.remaining(), &crcBuffer);
        unsigned int newCRC = crcBuffer.readUnsignedInt();
        stream.setWriteOffset(CRC_OFFSET);
        stream.writeUnsignedInt(newCRC);
        stream.flush();
    }

    BlockChain *BlockChain::sInstance = NULL;

    BlockChain &BlockChain::instance()
    {
        if(sInstance == NULL)
        {
            sInstance = new BlockChain();
            std::atexit(destroy);
        }
        return *sInstance;
    }

    void BlockChain::destroy()
    {
        delete BlockChain::sInstance;
        BlockChain::sInstance = 0;
    }

    BlockChain::BlockChain() : mPendingBlockHeaderMutex("Pending Block Header"), mPendingBlockMutex("Pending Blocks"), mBlockFileMutex("Block File")
    {
        mLastBlockID = 0;
        mLastFileID = 0;
    }

    BlockChain::~BlockChain()
    {
        mPendingBlockMutex.lock();
        for(std::vector<Block *>::iterator i=mPendingBlocks.begin();i!=mPendingBlocks.end();++i)
            delete *i;
        mPendingBlockMutex.unlock();
    }

    unsigned int BlockChain::getFileID(const Hash &pHash)
    {
        uint16_t lookup = pHash.lookup();
        unsigned int result = 0xffffffff;

        mSets[lookup].lock();

        std::list<BlockInfo *>::iterator end = mSets[lookup].end();
        for(std::list<BlockInfo *>::iterator i=mSets[lookup].begin();i!=end;++i)
            if(pHash == (*i)->hash)
            {
                result = (*i)->fileID;
                mSets[lookup].unlock();
                return result;
            }

        mSets[lookup].unlock();
        return result;
    }

    void BlockChain::lockFile(unsigned int pFileID)
    {
        bool found;
        while(true)
        {
            found = false;
            mBlockFileMutex.lock();
            for(std::vector<unsigned int>::iterator i=mLockedFileIDs.begin();i!=mLockedFileIDs.end();++i)
                if(*i == pFileID)
                {
                    found = true;
                    break;
                }
            if(!found)
            {
                mLockedFileIDs.push_back(pFileID);
                mBlockFileMutex.unlock();
                return;
            }
            ArcMist::Thread::sleep(100);
            mBlockFileMutex.unlock();
        }
    }

    void BlockChain::unlockFile(unsigned int pFileID)
    {
        mBlockFileMutex.lock();
        for(std::vector<unsigned int>::iterator i=mLockedFileIDs.begin();i!=mLockedFileIDs.end();++i)
            if(*i == pFileID)
            {
                mLockedFileIDs.erase(i);
                break;
            }
        mBlockFileMutex.unlock();
    }

    // Add block header to queue to be requested and downloaded
    bool BlockChain::addPendingBlockHeader(Block *pBlock)
    {
        bool result = true;
        mPendingBlockHeaderMutex.lock();
        if(mPendingBlockHeaders.size() == 0)
        {
            if(mLastBlockHash == pBlock->previousHash)
                mPendingBlockHeaders.push_back(pBlock);
            else
                result = false;
        }
        else if(mPendingBlockHeaders.size() > 0 && mPendingBlockHeaders.back()->hash == pBlock->previousHash)
            mPendingBlockHeaders.push_back(pBlock);
        else
            result = false;
        mPendingBlockHeaderMutex.unlock();

        if(result)
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Added pending block header : %s", pBlock->hash.hex().text());
        return result;
    }

    Block *BlockChain::nextBlockNeeded()
    {
        Block *result = NULL;
        mPendingBlockHeaderMutex.lock();
        if(mPendingBlockHeaders.size() > 0)
            result = mPendingBlockHeaders.front();
        mPendingBlockHeaderMutex.unlock();
        return result;
    }

    bool BlockChain::addPendingBlock(Block *pBlock)
    {
        mPendingBlockMutex.lock();

        if(mPendingBlocks.size() == 0 && mLastBlockHash != pBlock->previousHash)
        {
            ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Pending block is not next");
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Pending Previous : %s", pBlock->previousHash.hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Last             : %s", mLastBlockHash.hex().text());
            mPendingBlockMutex.unlock();
            return false;
        }
        else if(mPendingBlocks.size() != 0 && mLastPendingHash != pBlock->previousHash)
        {
            ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Pending block is not next");
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Pending Previous : %s", pBlock->previousHash.hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Last             : %s", mLastBlockHash.hex().text());
            mPendingBlockMutex.unlock();
            return false;
        }

        // Remove from pending headers
        mPendingBlockHeaderMutex.lock();
        if(mPendingBlockHeaders.size() > 0)
            if(mPendingBlockHeaders.front()->hash == pBlock->hash)
            {
                delete mPendingBlockHeaders.front();
                mPendingBlockHeaders.erase(mPendingBlockHeaders.begin());
            }
        mPendingBlockHeaderMutex.unlock();

        //TODO Remove this. Write to debug file
        ArcMist::String filePathName = Info::instance().path();
        filePathName.pathAppend(pBlock->hash.hex().text());
        filePathName += ".pending_block";
        if(!ArcMist::fileExists(filePathName))
        {
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Saving pending block to file : %s", pBlock->hash.hex().text());
            ArcMist::FileOutputStream file(filePathName, false, true);
            pBlock->write(&file, true);
        }

        // Add to pending
        // Set hash
        mLastPendingHash = pBlock->hash;
        mPendingBlocks.push_back(pBlock);
        mPendingBlockMutex.unlock();
        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_LOG_NAME, "Added pending block : %s", pBlock->hash.hex().text());
        return true;
    }

    bool BlockChain::processBlock(Block *pBlock)
    {
        UnspentPool &unspentPool = UnspentPool::instance();

        // Process block
        if(pBlock->process(unspentPool))
            unspentPool.commit(mLastBlockID+1);
        else
        {
            unspentPool.revert();
            return false;
        }

        // Add the block to the chain
        BlockFile *blockFile;

        lockFile(mLastFileID);
        blockFile = new BlockFile(mLastFileID, blockFileName(mLastFileID));

        if(blockFile->isFull())
        {
            unlockFile(mLastFileID);
            delete blockFile;

            // Move to next file
            mLastFileID++;
            lockFile(mLastFileID);
            blockFile = new BlockFile(mLastFileID, blockFileName(mLastFileID));
        }

        bool success = blockFile->addBlock(*pBlock);

        if(success)
        {
            mLastBlockID++;
            mLastBlockHash = blockFile->lastHash();
        }

        delete blockFile;
        unlockFile(mLastFileID);
        return success;
    }

    void BlockChain::getBlockHashes(HashList &pHashes, const Hash &pStartingHash, unsigned int pCount)
    {
        Hash hash = pStartingHash;
        unsigned int fileID = getFileID(hash);
        BlockFile *blockFile;

        pHashes.clear();

        while(pHashes.size() < pCount)
        {
            lockFile(fileID);
            blockFile = new BlockFile(fileID, blockFileName(fileID));

            if(!blockFile->readBlockHashes(pHashes, hash, pCount))
                break;

            delete blockFile;
            unlockFile(fileID);

            hash.clear();
            fileID++;
        }
    }

    void BlockChain::getBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, unsigned int pCount)
    {
        BlockFile *blockFile;
        Hash hash = pStartingHash;
        unsigned int fileID = getFileID(hash);

        pBlockHeaders.clear();

        while(pBlockHeaders.size() < pCount)
        {
            lockFile(fileID);
            blockFile = new BlockFile(fileID, blockFileName(fileID));

            if(!blockFile->readBlockHeaders(pBlockHeaders, hash, pCount))
                break;

            delete blockFile;
            unlockFile(fileID);

            hash.clear();
            fileID++;
        }
    }

    bool BlockChain::getBlock(const Hash &pHash, Block &pBlock)
    {
        unsigned int fileID = getFileID(pHash);
        if(fileID == 0xffffffff)
            return false;

        lockFile(fileID);
        BlockFile *blockFile = new BlockFile(fileID, blockFileName(fileID));

        bool success = blockFile->isValid && blockFile->readBlock(pHash, pBlock, true);

        delete blockFile;
        unlockFile(fileID);

        return success;
    }

    ArcMist::String BlockChain::blockFileName(unsigned int pID)
    {
        // Build path
        ArcMist::String result = Info::instance().path();
        result.pathAppend("blocks");

        // Encode ID
        ArcMist::String hexID;
        hexID.writeHex(&pID, 4);
        result.pathAppend(hexID);

        return result;
    }

    // Load block info from files
    bool BlockChain::loadBlocks()
    {
        // Load hashes from block files
        BlockFile *blockFile = NULL;
        uint16_t lookup;
        ArcMist::String filePathName;
        HashList hashes;
        Hash *lastBlock = NULL;
        bool success = true;
        bool done = false;
        Hash emptyHash;

        mLastFileID = 0;
        mLastBlockID = 0;
        mLastBlockHash.setSize(32);
        mLastBlockHash.zeroize();

        for(unsigned int fileID=1;!done;fileID++)
        {
            lockFile(fileID);
            filePathName = blockFileName(fileID);
            if(ArcMist::fileExists(filePathName))
            {
                // Load hashes from file
                blockFile = new BlockFile(fileID, filePathName);
                if(!blockFile->isValid)
                {
                    unlockFile(fileID);
                    success = false;
                    break;
                }

                blockFile->readBlockHashes(hashes, emptyHash, BlockFile::MAX_BLOCKS);
                delete blockFile;
                unlockFile(fileID);

                mLastFileID = fileID;
                for(HashList::iterator i=hashes.begin();i!=hashes.end();++i)
                    if((*i)->isZero())
                    {
                        done = true;
                        break;
                    }
                    else
                    {
                        lookup = (*i)->lookup();
                        mSets[lookup].lock();
                        mSets[lookup].push_back(new BlockInfo(**i, fileID));
                        mSets[lookup].unlock();
                        mLastBlockID++;
                        lastBlock = *i;
                    }
            }
            else
                break;
        }

        if(lastBlock != NULL)
            mLastBlockHash = *lastBlock;
        return success;
    }

    bool BlockChain::test()
    {
        bool success = true;
        
        return success;
    }
}
