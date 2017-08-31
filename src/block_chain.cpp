#include "block_chain.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/base/thread.hpp"
#include "arcmist/io/file_stream.hpp"
#include "arcmist/crypto/digest.hpp"
#include "info.hpp"

#define BITCOIN_BLOCK_CHAIN_LOG_NAME "BitCoin Block Chain"


namespace BitCoin
{
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
        static const unsigned int HEADER_ITEM_SIZE = 36; // 32 byte hash, 4 byte data offset
        static constexpr const char *START_STRING = "AMBLKS01";

        BlockFile(unsigned int pID, const char *pFilePathName);
        ~BlockFile() { updateCRC(); }

        unsigned int id;
        ArcMist::String filePathName;
        bool isValid;
        uint32_t crc;

        bool isFull() const { return mCount == MAX_BLOCKS; }
        unsigned int blockCount() const { return mCount; }
        const Hash &lastHash() const { return mLastHash; }

        // Add a block to the file
        bool addBlock(Block &pBlock);

        // Read list of block hashes from this file. If pStartingHash is empty then start with first block
        bool readBlockHashes(HashList &pHashes, const Hash &pStartingHash, unsigned int pCount);

        // Read list of block headers from this file. If pStartingHash is empty then start with first block
        bool readBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, unsigned int pCount);

        // Read block for specified hash
        bool readBlock(const Hash &pHash, Block &pBlock, bool pIncludeTransactions);

        void updateCRC();

    private:

        Hash mLastHash;
        unsigned int mCount;

    };

    BlockFile::BlockFile(unsigned int pID, const char *pFilePathName)
    {
        isValid = true;
        filePathName = pFilePathName;
        id = pID;
        crc = 0;
        mCount = 0;

        ArcMist::FileOutputStream *outputFile = new ArcMist::FileOutputStream(filePathName);
        outputFile->setOutputEndian(ArcMist::Endian::LITTLE);

        if(!outputFile->isValid())
        {
            delete outputFile;
            isValid = false;
            return;
        }

        if(outputFile->length() == 0)
        {
            // Create empty header
            outputFile->setWriteOffset(0);

            // Write start string
            outputFile->writeString(START_STRING);

            // Write empty CRC
            outputFile->writeUnsignedInt(0);

            // Write zero hashes
            Hash zeroHash(32);
            for(unsigned int i=0;i<MAX_BLOCKS;i++)
            {
                zeroHash.write(outputFile);
                outputFile->writeUnsignedInt(0);
            }

            mLastHash.setSize(32);
            mLastHash.zeroize();

            delete outputFile;
            return;
        }

        // Check for minimum valid file size
        if(outputFile->length() < HASHES_OFFSET + (MAX_BLOCKS * HEADER_ITEM_SIZE))
        {
            //TODO Recover from invalid file
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Block file smaller than header");
            isValid = false;
            delete outputFile;
            return;
        }

        delete outputFile;
        ArcMist::FileInputStream *inputFile = new ArcMist::FileInputStream(filePathName);
        inputFile->setInputEndian(ArcMist::Endian::LITTLE);

        // Read start string
        ArcMist::String startString = inputFile->readString(8);

        // Check start string
        if(startString != START_STRING)
        {
            delete inputFile;
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Block file missing start string");
            isValid = false;
            return;
        }

        // Read CRC
        crc = inputFile->readUnsignedInt();

        // Check CRC
        ArcMist::Digest digest(ArcMist::Digest::CRC32);
        digest.writeStream(inputFile, inputFile->remaining());
        ArcMist::Buffer crcBuffer;
        crcBuffer.setEndian(ArcMist::Endian::LITTLE);
        digest.getResult(&crcBuffer);
        if(crc != crcBuffer.readUnsignedInt())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Block file has invalid CRC");
            isValid = false;
        }

        // Pull last hash
        Hash nextHash(32);
        inputFile->setReadOffset(HASHES_OFFSET);
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            if(!nextHash.read(inputFile, 32))
            {
                delete inputFile;
                isValid = false;
                return;
            }
            if(inputFile->readUnsignedInt() == 0)
                break;
            mLastHash = nextHash;
            mCount++;
        }

        delete inputFile;
    }

    bool BlockFile::addBlock(Block &pBlock)
    {
        if(!isValid || mCount == MAX_BLOCKS)
            return false;

        ArcMist::FileOutputStream *outputFile = new ArcMist::FileOutputStream(filePathName);
        if(!outputFile->isValid())
        {
            delete outputFile;
            return false;
        }

        // Write hash and offset to file
        outputFile->setWriteOffset(HASHES_OFFSET + (mCount * HEADER_ITEM_SIZE));
        pBlock.hash.write(outputFile);
        outputFile->writeUnsignedInt(outputFile->length());

        // Write block data at end of file
        outputFile->setWriteOffset(outputFile->length());
        pBlock.write(outputFile, true);
        delete outputFile;

        mLastHash = pBlock.hash;
        mCount++;
        return true;
    }

    // If pStartingHash is empty then start with first hash in file
    bool BlockFile::readBlockHashes(HashList &pHashes, const Hash &pStartingHash, unsigned int pCount)
    {
        if(!isValid)
            return false;

        ArcMist::FileInputStream *inputFile = new ArcMist::FileInputStream(filePathName);
        Hash hash(32);
        bool started = pStartingHash.isEmpty();
        inputFile->setReadOffset(HASHES_OFFSET);
        for(unsigned int i=0;i<MAX_BLOCKS && pHashes.size()<pCount;i++)
        {
            if(!hash.read(inputFile))
            {
                delete inputFile;
                return false;
            }

            if(inputFile->readUnsignedInt() == 0)
            {
                delete inputFile;
                return true;
            }

            if(started || hash == pStartingHash)
            {
                started = true;
                pHashes.push_back(new Hash(hash));
            }
        }

        delete inputFile;
        return true;
    }

    // If pStartingHash is empty then start with first block in file
    bool BlockFile::readBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, unsigned int pCount)
    {
        if(!isValid)
            return false;

        ArcMist::FileInputStream *inputFile = new ArcMist::FileInputStream(filePathName);
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
                inputFile->setReadOffset(HASHES_OFFSET);
                for(unsigned int i=0;i<MAX_BLOCKS;i++)
                {
                    if(!hash.read(inputFile))
                    {
                        delete inputFile;
                        return false;
                    }

                    fileOffset = inputFile->readUnsignedInt();
                    if(fileOffset == 0)
                    {
                        delete inputFile;
                        return false;
                    }

                    if(startAtFirst || hash == pStartingHash)
                    {
                        // Go to file offset of block data
                        nextHashOffset = inputFile->readOffset();
                        inputFile->setReadOffset(fileOffset);
                    }

                    fileHashOffset++;
                }

                if(nextHashOffset == 0)
                {
                    delete inputFile;
                    return false; // Hash not found
                }
            }
            else
            {
                inputFile->setReadOffset(nextHashOffset);
                if(!hash.read(inputFile))
                {
                    delete inputFile;
                    return false;
                }

                fileOffset = inputFile->readUnsignedInt();
                if(fileOffset == 0)
                {
                    delete inputFile;
                    return pBlockHeaders.size() > 0;
                }

                // Go to file offset of block data
                nextHashOffset = inputFile->readOffset();
                inputFile->setReadOffset(fileOffset);
                fileHashOffset++;
                newBlockHeader = new Block();
                newBlockHeader->read(inputFile, false);
                pBlockHeaders.push_back(newBlockHeader);
            }

            if(fileHashOffset == MAX_BLOCKS)
            {
                delete inputFile;
                return pBlockHeaders.size() > 0; // Reached last block in file
            }
        }

        delete inputFile;
        return pBlockHeaders.size() > 0;
    }

    bool BlockFile::readBlock(const Hash &pHash, Block &pBlock, bool pIncludeTransactions)
    {
        if(!isValid)
            return false;

        // Find offset
        ArcMist::FileInputStream *inputFile = new ArcMist::FileInputStream(filePathName);
        Hash hash(32);
        unsigned int fileOffset;
        inputFile->setReadOffset(HASHES_OFFSET);
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            if(!hash.read(inputFile))
            {
                delete inputFile;
                return false;
            }

            fileOffset = inputFile->readUnsignedInt();
            if(fileOffset == 0)
            {
                delete inputFile;
                return false;
            }

            if(hash == pHash)
            {
                // Read block
                inputFile->setReadOffset(fileOffset);
                bool success = pBlock.read(inputFile, pIncludeTransactions);
                delete inputFile;
                return success;
            }
        }

        delete inputFile;
        return false;
    }

    void BlockFile::updateCRC()
    {
        if(!isValid)
            return;

        // Calculate new CRC
        ArcMist::FileInputStream *inputFile = new ArcMist::FileInputStream(filePathName);
        inputFile->setReadOffset(HASHES_OFFSET);

        ArcMist::Digest digest(ArcMist::Digest::CRC32);
        digest.writeStream(inputFile, inputFile->remaining());
        ArcMist::Buffer crcBuffer;
        crcBuffer.setEndian(ArcMist::Endian::LITTLE);
        digest.getResult(&crcBuffer);
        delete inputFile;

        ArcMist::FileOutputStream *outputFile = new ArcMist::FileOutputStream(filePathName);
        outputFile->setWriteOffset(CRC_OFFSET);
        outputFile->writeUnsignedInt(crcBuffer.readUnsignedInt());
        outputFile->flush();
        delete outputFile;
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

    BlockChain::BlockChain() : mPendingBlockHeaderMutex("Pending Block Header"), mPendingBlockMutex("Pending Blocks"),
      mProcessBlockMutex("Process Block"), mBlockFileMutex("Block File")
    {
        mNextBlockID = 0;
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
            if(pBlock->previousHash.isZero() && mLastBlockHash.isEmpty())
                mPendingBlockHeaders.push_back(pBlock); // First block of chain
            else if(mLastBlockHash == pBlock->previousHash)
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
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_CHAIN_LOG_NAME,
              "Added pending block header : %s", pBlock->hash.hex().text());
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

        if(mPendingBlocks.size() == 0)
        {
            if((!pBlock->previousHash.isZero() || !mLastBlockHash.isEmpty()) && mLastBlockHash != pBlock->previousHash)
            {
                ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Pending block is not next");
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Pending Previous : %s", pBlock->previousHash.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Last             : %s", mLastBlockHash.hex().text());
                mPendingBlockMutex.unlock();
                return false;
            }
        }
        else if(mPendingBlocks.size() != 0 && mLastPendingHash != pBlock->previousHash)
        {
            ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Pending block is not next");
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Pending Previous : %s", pBlock->previousHash.hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Last             : %s", mLastBlockHash.hex().text());
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
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Saving pending block to file : %s", pBlock->hash.hex().text());
            ArcMist::FileOutputStream file(filePathName, true);
            pBlock->write(&file, true);
        }

        // Add to pending
        // Set hash
        mLastPendingHash = pBlock->hash;
        mPendingBlocks.push_back(pBlock);
        mPendingBlockMutex.unlock();
        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Added pending block : %s", pBlock->hash.hex().text());
        return true;
    }

    void BlockChain::process()
    {
        mPendingBlockMutex.lock();

        if(mPendingBlocks.size() > 0)
        {
            // Check this front block and add it to the chain
            processBlock(mPendingBlocks.front());
            delete mPendingBlocks.front();
            mPendingBlocks.erase(mPendingBlocks.begin());

            if(mPendingBlocks.size() == 0)
                mLastBlockHash.clear();
        }
     
        mPendingBlockMutex.unlock();
    }

    bool BlockChain::processBlock(Block *pBlock)
    {
        UnspentPool &unspentPool = UnspentPool::instance();

        mProcessBlockMutex.lock();

        // Process block
        if(!pBlock->process(unspentPool, mNextBlockID, false))
        {
            unspentPool.revert();
            mProcessBlockMutex.unlock();
            return false;
        }

        // Add the block to the chain
        lockFile(mLastFileID);
        BlockFile *blockFile = new BlockFile(mLastFileID, blockFileName(mLastFileID));

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
            unspentPool.commit(mNextBlockID);
            mNextBlockID++;
            mLastBlockHash = blockFile->lastHash();
        }

        delete blockFile;
        unlockFile(mLastFileID);
        mProcessBlockMutex.unlock();
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

    ArcMist::String BlockChain::blockFilePath()
    {
        // Build path
        ArcMist::String result = Info::instance().path();
        result.pathAppend("blocks");
        return result;
    }

    ArcMist::String BlockChain::blockFileName(unsigned int pID)
    {
        // Build path
        ArcMist::String result = Info::instance().path();
        result.pathAppend("blocks");

        // Encode ID
        ArcMist::String hexID;
        uint32_t reverseID = ArcMist::Endian::convert(pID, ArcMist::Endian::BIG);
        hexID.writeHex(&reverseID, 4);
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

        mProcessBlockMutex.lock();

        mLastFileID = 0;
        mNextBlockID = 0;
        mLastBlockHash.setSize(32);
        mLastBlockHash.zeroize();

        ArcMist::createDirectory(blockFilePath());

        for(unsigned int fileID=0;!done;fileID++)
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
                        mNextBlockID++;
                        lastBlock = *i;
                    }
            }
            else
                break;
        }

        mProcessBlockMutex.unlock();

        if(mNextBlockID == 0)
        {
            // Add genesis block
            Block *genesis = Block::genesis();
            processBlock(genesis);
            delete genesis;
        }

        if(lastBlock != NULL)
            mLastBlockHash = *lastBlock;
        return success;
    }

    bool BlockChain::test()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "------------- Starting Block Chain Tests -------------");

        bool success = true;
        ArcMist::Buffer checkData;
        Hash checkHash(32);
        Block *genesis = Block::genesis();

        //ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Current coin base amount : %f",
        //  (double)Block::coinBaseAmount(485000) / 100000000.0); // 100,000,000 Satoshis in a BitCoin

        /***********************************************************************************************
         * Genesis block merkle hash
         ***********************************************************************************************/
        checkData.clear();
        checkData.writeHex("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a");
        checkHash.read(&checkData);

        if(genesis->merkleHash == checkHash)
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Passed genesis block merkle hash");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Failed genesis block merkle hash");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Block merkle hash   : %s", genesis->merkleHash.hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Correct merkle hash : %s", checkHash.hex().text());
            success = false;
        }

        /***********************************************************************************************
         * Genesis block hash
         ***********************************************************************************************/
        //Big Endian checkData.writeHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        if(network() == TESTNET)
            checkData.writeHex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000");
        else
            checkData.writeHex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000");
        checkHash.read(&checkData);

        if(genesis->hash == checkHash)
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Passed genesis block hash");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Failed genesis block hash");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Block hash   : %s", genesis->hash.hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Correct hash : %s", checkHash.hex().text());
            success = false;
        }

        /***********************************************************************************************
         * Genesis block raw
         ***********************************************************************************************/
        ArcMist::Buffer data;
        genesis->write(&data, true);

        checkData.clear();
        if(network() == TESTNET)
        {
            checkData.writeHex("01000000000000000000000000000000"); //   ................
            checkData.writeHex("00000000000000000000000000000000"); //   ................
            checkData.writeHex("000000003BA3EDFD7A7B12B27AC72C3E"); //   ....;£íýz{.²zÇ,>
            checkData.writeHex("67768F617FC81BC3888A51323A9FB8AA"); //   gv.a.È.ÃˆŠQ2:Ÿ¸ª
            checkData.writeHex("4b1e5e4adae5494dffff001d1aa4ae18"); //   <CHANGED>
            checkData.writeHex("01010000000100000000000000000000"); //   ................
            checkData.writeHex("00000000000000000000000000000000"); //   ................
            checkData.writeHex("000000000000FFFFFFFF4D04FFFF001D"); //   ......ÿÿÿÿM.ÿÿ..
            checkData.writeHex("0104455468652054696D65732030332F"); //   ..EThe Times 03/
            checkData.writeHex("4A616E2F32303039204368616E63656C"); //   Jan/2009 Chancel
            checkData.writeHex("6C6F72206F6E206272696E6B206F6620"); //   lor on brink of 
            checkData.writeHex("7365636F6E64206261696C6F75742066"); //   second bailout f
            checkData.writeHex("6F722062616E6B73FFFFFFFF0100F205"); //   or banksÿÿÿÿ..ò.
            checkData.writeHex("2A01000000434104678AFDB0FE554827"); //   *....CA.gŠý°þUH'
            checkData.writeHex("1967F1A67130B7105CD6A828E03909A6"); //   .gñ¦q0·.\Ö¨(à9.¦
            checkData.writeHex("7962E0EA1F61DEB649F6BC3F4CEF38C4"); //   ybàê.aÞ¶Iö¼?Lï8Ä
            checkData.writeHex("F35504E51EC112DE5C384DF7BA0B8D57"); //   óU.å.Á.Þ\8M÷º..W
            checkData.writeHex("8A4C702B6BF11D5FAC00000000");       //   ŠLp+kñ._¬....
        }
        else
        {
            checkData.writeHex("01000000000000000000000000000000"); //   ................
            checkData.writeHex("00000000000000000000000000000000"); //   ................
            checkData.writeHex("000000003BA3EDFD7A7B12B27AC72C3E"); //   ....;£íýz{.²zÇ,>
            checkData.writeHex("67768F617FC81BC3888A51323A9FB8AA"); //   gv.a.È.ÃˆŠQ2:Ÿ¸ª
            checkData.writeHex("4B1E5E4A29AB5F49FFFF001D1DAC2B7C"); //   K.^J)«_Iÿÿ...¬+|
            checkData.writeHex("01010000000100000000000000000000"); //   ................
            checkData.writeHex("00000000000000000000000000000000"); //   ................
            checkData.writeHex("000000000000FFFFFFFF4D04FFFF001D"); //   ......ÿÿÿÿM.ÿÿ..
            checkData.writeHex("0104455468652054696D65732030332F"); //   ..EThe Times 03/
            checkData.writeHex("4A616E2F32303039204368616E63656C"); //   Jan/2009 Chancel
            checkData.writeHex("6C6F72206F6E206272696E6B206F6620"); //   lor on brink of 
            checkData.writeHex("7365636F6E64206261696C6F75742066"); //   second bailout f
            checkData.writeHex("6F722062616E6B73FFFFFFFF0100F205"); //   or banksÿÿÿÿ..ò.
            checkData.writeHex("2A01000000434104678AFDB0FE554827"); //   *....CA.gŠý°þUH'
            checkData.writeHex("1967F1A67130B7105CD6A828E03909A6"); //   .gñ¦q0·.\Ö¨(à9.¦
            checkData.writeHex("7962E0EA1F61DEB649F6BC3F4CEF38C4"); //   ybàê.aÞ¶Iö¼?Lï8Ä
            checkData.writeHex("F35504E51EC112DE5C384DF7BA0B8D57"); //   óU.å.Á.Þ\8M÷º..W
            checkData.writeHex("8A4C702B6BF11D5FAC00000000");       //   ŠLp+kñ._¬....
        }

        if(checkData.length() != data.length())
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME,
              "Failed genesis block raw data size : actual %d != correct %d", data.length(), checkData.length());
            success = false;
        }
        else
        {
            // Check in 16 byte sections
            uint8_t actualRaw[16], checkRaw[16];
            ArcMist::String actualHex, checkHex;
            bool matches = true;
            for(unsigned int lineNo=1;checkData.remaining() > 0;lineNo++)
            {
                data.read(actualRaw, 16);
                checkData.read(checkRaw, 16);

                if(std::memcmp(actualRaw, checkRaw, 16) != 0)
                {
                    matches = false;
                    actualHex.writeHex(actualRaw, 16);
                    checkHex.writeHex(checkRaw, 16);

                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Failed genesis block raw data line %d", lineNo);
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Actual  : %s", actualHex.text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Correct : %s", checkHex.text());
                    success = false;
                }
            }

            if(matches)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Passed genesis block raw data");
        }

        delete genesis;

        return success;
    }
}
