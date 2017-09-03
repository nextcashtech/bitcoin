#include "chain.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/base/thread.hpp"
#include "arcmist/io/file_stream.hpp"
#include "arcmist/crypto/digest.hpp"
#include "info.hpp"
#include "daemon.hpp"

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

        //TODO Remove blocks from file when they are orphaned

        // Read block at specified offset in file. Return false if the offset is too high.
        bool readBlock(unsigned int pOffset, Block &pBlock);

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
        pHashes.clear();

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
        pBlockHeaders.clear();

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

    bool BlockFile::readBlock(unsigned int pOffset, Block &pBlock)
    {
        if(!isValid)
            return false;

        ArcMist::FileInputStream *inputFile = new ArcMist::FileInputStream(filePathName);

        // Go to location in header where the data offset to the block is
        inputFile->setReadOffset(HASHES_OFFSET + (pOffset * HEADER_ITEM_SIZE) + 32);

        unsigned int offset = inputFile->readUnsignedInt();
        if(offset == 0)
            return false;

        inputFile->setReadOffset(offset);
        return pBlock.read(inputFile, true);
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

    Chain *Chain::sInstance = NULL;

    Chain &Chain::instance()
    {
        if(sInstance == NULL)
        {
            sInstance = new Chain();
            std::atexit(destroy);
        }
        return *sInstance;
    }

    void Chain::destroy()
    {
        delete Chain::sInstance;
        Chain::sInstance = 0;
    }

    Chain::Chain() : mPendingMutex("Pending"),
      mProcessMutex("Process"), mBlockFileMutex("Block File")
    {
        mNextBlockHeight = 0;
        mLastFileID = 0;
    }

    Chain::~Chain()
    {
        mPendingMutex.lock();
        for(std::list<PendingData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            delete *pending;
        mPendingMutex.unlock();
    }

    bool Chain::headerAvailable(Hash &pHash)
    {
        if(blockInChain(pHash))
            return true;

        bool found = false;
        mPendingMutex.lock();
        for(std::list<PendingData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if((*pending)->block->hash == pHash)
            {
                found = true;
                break;
            }
        mPendingMutex.unlock();

        return found;
    }

    unsigned int Chain::blockFileID(const Hash &pHash)
    {
        if(pHash.isEmpty())
            return 0; // Empty hash means start from the beginning

        uint16_t lookup = pHash.lookup();
        unsigned int result = 0xffffffff;

        mBlockLookup[lookup].lock();

        std::list<BlockInfo *>::iterator end = mBlockLookup[lookup].end();
        for(std::list<BlockInfo *>::iterator i=mBlockLookup[lookup].begin();i!=end;++i)
            if(pHash == (*i)->hash)
            {
                result = (*i)->fileID;
                mBlockLookup[lookup].unlock();
                return result;
            }

        mBlockLookup[lookup].unlock();
        return result;
    }

    void Chain::lockBlockFile(unsigned int pFileID)
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
            ArcMist::Thread::sleep(100);
            mBlockFileMutex.unlock();
        }
    }

    void Chain::unlockBlockFile(unsigned int pFileID)
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

    unsigned int Chain::pendingCount()
    {
        mPendingMutex.lock();
        unsigned int result = mPending.size();
        mPendingMutex.unlock();
        return result;
    }

    // Add block header to queue to be requested and downloaded
    bool Chain::addPendingHeader(Block *pBlock)
    {
        bool result = false;
        mPendingMutex.lock();
        if(mPending.size() == 0)
        {
            if(pBlock->previousHash.isZero() && mLastBlockHash.isEmpty())
                result = true; // First block of chain
            else if(pBlock->previousHash == mLastBlockHash)
                result = true; // First pending entry
        }
        else if(mPending.back()->block->hash == pBlock->previousHash)
            result = true; // Add to pending

        if(!result)
        {
            mPendingMutex.unlock();
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BLOCK_CHAIN_LOG_NAME,
              "Pending header not next : %s", pBlock->hash.hex().text());
            return false;
        }

        if(!pBlock->hasProofOfWork())
        {
            mPendingMutex.unlock();
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BLOCK_CHAIN_LOG_NAME,
              "Not enough proof of work : %s", pBlock->hash.hex().text());
            Hash target;
            target.setDifficulty(pBlock->targetBits);
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BLOCK_CHAIN_LOG_NAME,
              "Target                   : %s", target.hex().text());
            return false;
        }

        // Add to pending list
        mPending.push_back(new PendingData(pBlock));
        mLastPendingHash = pBlock->hash;

        //TODO if(!result) check if this header is from an alternate chain.
        //  Check if previous hash is in the chain, but not at the top and determine if a fork is needed

        mPendingMutex.unlock();

        if(result)
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_CHAIN_LOG_NAME,
              "Added pending header : %s", pBlock->hash.hex().text());
        return result;
    }
    
    void Chain::markBlockRequested(const Hash &pHash)
    {
        mPendingMutex.lock();
        for(std::list<PendingData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if((*pending)->block->hash == pHash)
            {
                (*pending)->requestedTime = getTime();
                break;
            }
        mPendingMutex.unlock();
    }

    Hash Chain::nextBlockNeeded()
    {
        Hash result;
        uint64_t time = getTime();
        mPendingMutex.lock();
        for(std::list<PendingData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if(time - (*pending)->requestedTime > 120)
            {
                result = (*pending)->block->hash;
                break;
            }
        mPendingMutex.unlock();
        return result;
    }

    bool Chain::addPendingBlock(Block *pBlock)
    {
        //TODO Find pending header entry and replace the header with the full block
        bool success = false;

        mPendingMutex.lock();
        for(std::list<PendingData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if((*pending)->block->hash == pBlock->hash)
            {
                (*pending)->replace(pBlock);
                success = true;
                break;
            }
        mPendingMutex.unlock();

        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_BLOCK_CHAIN_LOG_NAME,
          "Added pending block : %s", pBlock->hash.hex().text());

        return success;
    }

    bool Chain::processBlock(Block *pBlock)
    {
        UnspentPool &unspentPool = UnspentPool::instance();

        mProcessMutex.lock();

        // Process block
        if(!pBlock->process(unspentPool, mNextBlockHeight))
        {
            //TODO Add hash to blacklist. So it isn't downloaded again.

            // Print the block info and save it to a file
            pBlock->print(ArcMist::Log::VERBOSE);
            ArcMist::String filePathName = Info::instance().path();
            filePathName.pathAppend(pBlock->hash.hex() + ".invalid");
            ArcMist::FileOutputStream file(filePathName, true);
            pBlock->write(&file, true);

            unspentPool.revert();
            mProcessMutex.unlock();
            return false;
        }

        // Commit and save changes to unspent pool
        if(!unspentPool.commit(mNextBlockHeight) || !unspentPool.save())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME,
              "Failed to commit or save unspent transaction pool");
            unspentPool.revert();
            mProcessMutex.unlock();
            return false;
        }

        // Add the block to the chain
        lockBlockFile(mLastFileID);
        BlockFile *blockFile = new BlockFile(mLastFileID, blockFileName(mLastFileID));

        if(blockFile->isFull())
        {
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME,
              "Block file %08d is full. Starting new file %08d", mLastFileID, mLastFileID + 1);

            unlockBlockFile(mLastFileID);
            delete blockFile;

            // Move to next file
            mLastFileID++;
            lockBlockFile(mLastFileID);
            blockFile = new BlockFile(mLastFileID, blockFileName(mLastFileID));
        }

        bool success = blockFile->addBlock(*pBlock);
        delete blockFile;
        unlockBlockFile(mLastFileID);

        if(success)
        {
            uint16_t lookup = pBlock->hash.lookup();
            mBlockLookup[lookup].lock();
            mBlockLookup[lookup].push_back(new BlockInfo(pBlock->hash, mLastFileID, mNextBlockHeight));
            mBlockLookup[lookup].unlock();

            mNextBlockHeight++;
            mLastBlockHash = pBlock->hash;
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME,
              "Added block to chain : %s", pBlock->hash.hex().text());
        }
        else
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME,
              "Failed to add to block file %08d : %s", mLastFileID, pBlock->hash.hex().text());
        }

        mProcessMutex.unlock();
        return success;
    }

    void Chain::process()
    {
        // Check if first pending header is actually a full block and process it
        mPendingMutex.lock();
        if(mPending.size() == 0)
        {
            // No pending blocks or headers
            mPendingMutex.unlock();
            return;
        }
        
        PendingData *nextPending = mPending.front();
        if(!nextPending->isFull())
        {
            // Next pending block is not full yet
            mPendingMutex.unlock();
            return;
        }

        mPendingMutex.unlock();

        // Check this front block and add it to the chain
        if(processBlock(nextPending->block))
        {
            mPendingMutex.lock();

            // Delete block
            delete nextPending;

            // Remove from pending
            mPending.erase(mPending.begin());
            if(mPending.size() == 0)
                mLastPendingHash.clear();

            mPendingMutex.unlock();
        }
        else
        {
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Clearing all pending blocks/headers");

            // Clear pending blocks since they assumed this block was good
            mPendingMutex.lock();
            for(std::list<PendingData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
                delete *pending;
            mPending.clear();
            mLastPendingHash.clear();
            mPendingMutex.unlock();

            //TODO Figure out how to recover from this

            // Stop daemon
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME,
              "Stopping daemon because this is currently unrecoverable");
            Daemon::instance().requestStop();
        }
    }

    void Chain::getBlockHashes(HashList &pHashes, const Hash &pStartingHash, unsigned int pCount)
    {
        Hash hash = pStartingHash;
        BlockFile *blockFile;
        unsigned int fileID = blockFileID(hash);

        if(fileID == 0xffffffff)
            return;

        pHashes.clear();

        while(pHashes.size() < pCount)
        {
            lockBlockFile(fileID);
            blockFile = new BlockFile(fileID, blockFileName(fileID));

            if(!blockFile->readBlockHashes(pHashes, hash, pCount))
                break;

            delete blockFile;
            unlockBlockFile(fileID);

            hash.clear();
            fileID++;
        }
    }

    void Chain::getReverseBlockHashes(HashList &pHashes, unsigned int pCount)
    {
        BlockFile *blockFile;
        Hash hash;

        pHashes.clear();

        // Don't start with latest block. Go back to previous file
        if(mLastFileID == 0)
            return;

        for(unsigned int fileID=mLastFileID-1;;fileID--)
        {
            lockBlockFile(fileID);
            blockFile = new BlockFile(fileID, blockFileName(fileID));

            hash = blockFile->lastHash();
            if(!hash.isEmpty())
                pHashes.push_back(new Hash(hash));

            delete blockFile;
            unlockBlockFile(fileID);

            if(pHashes.size() >= pCount || fileID == 0)
                break;
        }
    }

    void Chain::getBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, unsigned int pCount)
    {
        BlockFile *blockFile;
        Hash hash = pStartingHash;
        unsigned int fileID = blockFileID(hash);

        if(fileID == 0xffffffff)
            return; // hash not found

        pBlockHeaders.clear();

        while(pBlockHeaders.size() < pCount)
        {
            lockBlockFile(fileID);
            blockFile = new BlockFile(fileID, blockFileName(fileID));

            if(!blockFile->readBlockHeaders(pBlockHeaders, hash, pCount))
                break;

            delete blockFile;
            unlockBlockFile(fileID);

            hash.clear();
            fileID++;
        }
    }

    bool Chain::getBlock(const Hash &pHash, Block &pBlock)
    {
        unsigned int fileID = blockFileID(pHash);
        if(fileID == 0xffffffff)
            return false; // hash not found

        lockBlockFile(fileID);
        BlockFile *blockFile = new BlockFile(fileID, blockFileName(fileID));

        bool success = blockFile->isValid && blockFile->readBlock(pHash, pBlock, true);

        delete blockFile;
        unlockBlockFile(fileID);

        return success;
    }

    ArcMist::String Chain::blockFilePath()
    {
        // Build path
        ArcMist::String result = Info::instance().path();
        result.pathAppend("blocks");
        return result;
    }

    ArcMist::String Chain::blockFileName(unsigned int pID)
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
    bool Chain::loadBlocks(bool pList)
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Loading blocks");

        // Load hashes from block files
        BlockFile *blockFile = NULL;
        uint16_t lookup;
        ArcMist::String filePathName;
        HashList hashes;
        Hash *lastBlock = NULL;
        bool success = true;
        bool done = false;
        Hash emptyHash;

        mProcessMutex.lock();

        mLastFileID = 0;
        mNextBlockHeight = 0;
        mLastBlockHash.setSize(32);
        mLastBlockHash.zeroize();

        ArcMist::createDirectory(blockFilePath());

        for(unsigned int fileID=0;!done;fileID++)
        {
            lockBlockFile(fileID);
            filePathName = blockFileName(fileID);
            if(ArcMist::fileExists(filePathName))
            {
                // Load hashes from file
                blockFile = new BlockFile(fileID, filePathName);
                if(!blockFile->isValid)
                {
                    delete blockFile;
                    unlockBlockFile(fileID);
                    success = false;
                    break;
                }

                if(!blockFile->readBlockHashes(hashes, emptyHash, BlockFile::MAX_BLOCKS))
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Failed to read hashes from block file %s", filePathName.text());
                    delete blockFile;
                    unlockBlockFile(fileID);
                    success = false;
                    break;
                }
                delete blockFile;
                unlockBlockFile(fileID);

                if(pList)
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Block file %s", filePathName.text());

                mLastFileID = fileID;
                for(HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
                    if((*hash)->isZero())
                    {
                        done = true;
                        delete blockFile;
                        unlockBlockFile(fileID);
                        break;
                    }
                    else
                    {
                        if(pList)
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Block %08d : %s", mNextBlockHeight, (*hash)->hex().text());
                        lookup = (*hash)->lookup();
                        mBlockLookup[lookup].lock();
                        mBlockLookup[lookup].push_back(new BlockInfo(**hash, fileID, mNextBlockHeight));
                        mBlockLookup[lookup].unlock();
                        mNextBlockHeight++;
                        lastBlock = *hash;
                    }
            }
            else
            {
                unlockBlockFile(fileID);
                break;
            }
        }

        mProcessMutex.unlock();

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Loaded %d blocks", mNextBlockHeight);

        if(mNextBlockHeight == 0)
        {
            // Add genesis block
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Creating genesis block");
            Block *genesis = Block::genesis();
            processBlock(genesis);
            delete genesis;
        }

        if(lastBlock != NULL)
            mLastBlockHash = *lastBlock;
        return success;
    }

    bool Chain::validate(bool pRebuildUnspent)
    {
        BlockFile *blockFile;
        Hash previousHash(32), merkleHash;
        Block block;
        unsigned int i, height = 0;
        ArcMist::String filePathName;
        UnspentPool &unspent = UnspentPool::instance();

        unspent.reset();

        for(unsigned int fileID=0;;fileID++)
        {
            filePathName = blockFileName(fileID);
            if(!ArcMist::fileExists(filePathName))
                break;

            lockBlockFile(fileID);
            blockFile = new BlockFile(fileID, filePathName);

            for(i=0;i<BlockFile::MAX_BLOCKS;i++)
            {
                if(blockFile->readBlock(i, block))
                {
                    if(block.previousHash != previousHash)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME,
                          "Block %010d previous hash doesn't match", height);
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME,
                          "Included Previous Hash : %s", block.previousHash.hex().text());
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME,
                          "Previous Block's Hash  : %s", previousHash.hex().text());
                        return false;
                    }

                    block.calculateMerkleHash(merkleHash);
                    if(block.merkleHash != merkleHash)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME,
                          "Block %010d has invalid merkle hash", height);
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME,
                          "Included Merkle Hash : %s", block.merkleHash.hex().text());
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME,
                          "Correct Merkle Hash  : %s", merkleHash.hex().text());
                        return false;
                    }

                    if(!block.process(unspent, height))
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME,
                          "Block %010d failed to process", height);
                        return false;
                    }

                    if(!unspent.commit(height))
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME,
                          "Block %010d unspent commit failed", height);
                        return false;
                    }

                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BLOCK_CHAIN_LOG_NAME,
                      "Block %010d is valid : %d transactions", height, block.transactions.size());
                    block.print();

                    previousHash = block.hash;
                    height++;
                }
                else // End of chain
                    break;
            }

            delete blockFile;
            unlockBlockFile(fileID);
        }

        if(pRebuildUnspent)
            unspent.save();

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Unspent transactions :  %d", unspent.count());
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Validated block height of %d", height-1);
        return true;
    }

    bool Chain::test()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "------------- Starting Block Chain Tests -------------");

        bool success = true;
        ArcMist::Buffer checkData;
        Hash checkHash(32);
        Block *genesis = Block::genesis();

        //genesis->print(ArcMist::Log::INFO);

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Current coin base amount : %f",
         (double)Block::coinBaseAmount(485000) / 100000000.0); // 100,000,000 Satoshis in a BitCoin

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
         * Genesis block read hash
         ***********************************************************************************************/
        //Big Endian checkData.writeHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        checkData.clear();
        if(network() == TESTNET)
            checkData.writeHex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000");
        else
            checkData.writeHex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000");
        checkHash.read(&checkData);
        Block readGenesisBlock;
        ArcMist::Buffer blockBuffer;
        genesis->write(&blockBuffer, true);
        readGenesisBlock.read(&blockBuffer, true);

        if(readGenesisBlock.hash == checkHash)
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Passed genesis block read hash");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Failed genesis block read hash");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Block hash   : %s", readGenesisBlock.hash.hex().text());
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

        /***********************************************************************************************
         * Block read
         ***********************************************************************************************/
        Block readBlock;
        ArcMist::FileInputStream readFile("tests/06128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000.pending_block");
        Info::instance().setPath("../bcc_test");
        UnspentPool &unspents = UnspentPool::instance();

        if(!readBlock.read(&readFile, true))
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Failed to read block");
            success = false;
        }
        else
        {
            //readBlock.print(ArcMist::Log::INFO);

            /***********************************************************************************************
             * Block read hash
             ***********************************************************************************************/
            checkData.clear();
            checkData.writeHex("06128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000");
            checkHash.read(&checkData);

            if(readBlock.hash == checkHash)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Passed read block hash");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Failed read block hash");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Block hash   : %s", readBlock.hash.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Correct hash : %s", checkHash.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Block read previous hash
             ***********************************************************************************************/
            checkData.clear();
            checkData.writeHex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000");
            checkHash.read(&checkData);

            if(readBlock.previousHash == checkHash)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Passed read block previous hash");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Failed read block previous hash");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Block previous hash   : %s", readBlock.previousHash.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Correct previous hash : %s", checkHash.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Block read merkle hash
             ***********************************************************************************************/
            readBlock.calculateMerkleHash(checkHash);

            if(readBlock.merkleHash == checkHash)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Passed read block merkle hash");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Failed read block merkle hash");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Block merkle hash   : %s", readBlock.merkleHash.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Correct merkle hash : %s", checkHash.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Block read process
             ***********************************************************************************************/
            if(readBlock.process(unspents, 1))
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Passed read block process");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Failed read block process");
                success = false;
            }

            unspents.revert();
        }

        delete genesis;
        
        /***********************************************************************************************
         * New Block
         ***********************************************************************************************/
        // Requires unspents to be setup
        Info::instance().setPath("../bcc_test");
        unspents.load();

        ArcMist::FileInputStream file("../bcc_test/2077ea8e53ba9a132d83b91e40fb1f4c724217b8197c4533a5bee9e900000000.invalid");
        Block newBlock;

        newBlock.read(&file, true);
        newBlock.print();
        
        if(newBlock.process(unspents, 381))
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Passed New Block test");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOCK_CHAIN_LOG_NAME, "Failed New Block test");
            success = false;
        }
        
        return success;
    }
}
