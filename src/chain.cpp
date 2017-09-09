#include "chain.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/base/thread.hpp"
#include "arcmist/io/file_stream.hpp"
#include "arcmist/crypto/digest.hpp"
#include "info.hpp"
#include "daemon.hpp"

#define BITCOIN_CHAIN_LOG_NAME "BitCoin Chain"


namespace BitCoin
{
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
        mBlockVersionFlags = 0x00000000;
        mPendingSize = 0;
        mPendingBlocks = 0;
    }

    Chain::~Chain()
    {
        mPendingMutex.lock();
        for(std::list<PendingData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            delete *pending;
        mPendingMutex.unlock();
    }

    void Chain::updateTimeFlags()
    {
        if(!(mBlockVersionFlags & CHECKSEQUENCEVERIFY_ACTIVE))
        {
            //uint64_t time = getTime();
            switch(network())
            {
            case MAINNET:
                break;
            case TESTNET:
                break;
            default:
                break;
            }
        }
    }

    void Chain::updateBlockVersionFlags()
    {
        if(mBlockVersionFlags & REQUIRE_BLOCK_VERSION_4)
            return;

        int version4OrHigherCount = 0;
        int version2OrHigherCount = 0;
        int count = 0;
        for(std::list<uint32_t>::iterator version=mBlockVersions.begin();version!=mBlockVersions.end();++version)
        {
            if(count < 1000)
            {
                if(*version >= 4)
                {
                    version4OrHigherCount++;
                    version2OrHigherCount++;
                }
                else if(*version >= 2)
                    version2OrHigherCount++;
            }
            count++;
        }

        if(version4OrHigherCount >= 750)
            mBlockVersionFlags &= BLOCK_VERSION_4_ACTIVE;
        if(version4OrHigherCount >= 950)
            mBlockVersionFlags &= REQUIRE_BLOCK_VERSION_4;

        // BIP-0034
        if(version2OrHigherCount >= 750)
            mBlockVersionFlags &= BLOCK_VERSION_2_ACTIVE;
        if(version2OrHigherCount >= 950)
            mBlockVersionFlags &= REQUIRE_BLOCK_VERSION_2;
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

        BlockSet::iterator end = mBlockLookup[lookup].end();
        for(BlockSet::iterator i=mBlockLookup[lookup].begin();i!=end;++i)
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
            mBlockFileMutex.unlock();
            ArcMist::Thread::sleep(100);
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

    unsigned int Chain::pendingBlockCount()
    {
        mPendingMutex.lock();
        unsigned int result = mPendingBlocks;
        mPendingMutex.unlock();
        return result;
    }

    unsigned int Chain::pendingSize()
    {
        mPendingMutex.lock();
        unsigned int result = mPendingSize;
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
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Pending header not next : %s", pBlock->hash.hex().text());
            return false;
        }

        if(!pBlock->hasProofOfWork())
        {
            mPendingMutex.unlock();
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Not enough proof of work : %s", pBlock->hash.hex().text());
            Hash target;
            target.setDifficulty(pBlock->targetBits);
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
              "Target                   : %s", target.hex().text());
            return false;
        }

        // Add to pending list
        mPending.push_back(new PendingData(pBlock));
        mLastPendingHash = pBlock->hash;
        mPendingSize += pBlock->size();

        //TODO if(!result) check if this header is from an alternate chain.
        //  Check if previous hash is in the chain, but not at the top and determine if a fork is needed

        mPendingMutex.unlock();

        if(result)
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
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

    void Chain::markBlockNotRequested(const Hash &pHash)
    {
        mPendingMutex.lock();
        for(std::list<PendingData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if((*pending)->block->hash == pHash)
            {
                (*pending)->requestedTime = 0;
                break;
            }
        mPendingMutex.unlock();
    }

    unsigned int PendingData::timeout()
    {
        int tempPriority = priority;
        unsigned int result = 180;

        while(tempPriority > 0)
        {
            result /= 2;
            tempPriority--;
        }

        return result;
    }

    void Chain::prioritizePending()
    {
        unsigned int fullCount = 0;
        mPendingMutex.lock();
        for(std::list<PendingData *>::reverse_iterator pending=mPending.rbegin();pending!=mPending.rend();++pending)
        {
            if((*pending)->isFull())
                fullCount++;
            else
            {
                if(fullCount > 40)
                    (*pending)->priority = 4;
                else if(fullCount > 20)
                    (*pending)->priority = 3;
                else if(fullCount > 10)
                    (*pending)->priority = 2;
            }
        }
        mPendingMutex.unlock();
    }

    Hash Chain::nextBlockNeeded(bool pReduceOnly)
    {
        Hash result;
        uint64_t time = getTime();
        bool fullFoundAfter = false;
        mPendingMutex.lock();
        for(std::list<PendingData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
        {
            if((*pending)->isFull())
            {
                if(!result.isEmpty())
                {
                    fullFoundAfter = true;
                    break;
                }
                else
                    continue;
            }

            if(time - (*pending)->requestedTime > (*pending)->timeout())
            {
                if(pReduceOnly)
                {
                    if(result.isEmpty())
                        result = (*pending)->block->hash;
                }
                else
                {
                    result = (*pending)->block->hash;
                    break;
                }
            }
        }
        mPendingMutex.unlock();
        if(pReduceOnly && !fullFoundAfter)
            // Don't return hashes that don't have full blocks after them because we are trying to reduce pending memory usage
            result.clear();
        return result;
    }

    bool Chain::addPendingBlock(Block *pBlock)
    {
        bool success = false;
        bool found = false;

        mPendingMutex.lock();
        for(std::list<PendingData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
            if((*pending)->block->hash == pBlock->hash)
            {
                found = true;
                if(!(*pending)->isFull())
                {
                    mPendingSize -= (*pending)->block->size();
                    (*pending)->replace(pBlock);
                    mPendingSize += pBlock->size();
                    mPendingBlocks++;
                    success = true;
                }
                break;
            }
        mPendingMutex.unlock();

        if(success)
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_CHAIN_LOG_NAME,
              "Added pending block : %s", pBlock->hash.hex().text());
        else if(!found)
        {
            // Check if this is the latest block
            mPendingMutex.lock();
            if(pBlock->hash == mLastBlockHash && mPending.size() == 0)
            {
                if(!pBlock->hasProofOfWork())
                {
                    mPendingMutex.unlock();
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Not enough proof of work : %s", pBlock->hash.hex().text());
                    Hash target;
                    target.setDifficulty(pBlock->targetBits);
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Target                   : %s", target.hex().text());
                    return false;
                }

                // Add to pending list
                mPending.push_back(new PendingData(pBlock));
                mLastPendingHash = pBlock->hash;
                mPendingSize += pBlock->size();
                mPendingBlocks++;
                mPendingMutex.unlock();
            }
            else
            {
                mPendingMutex.unlock();
                if(blockInChain(pBlock->hash))
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Received block already in chain : %s", pBlock->hash.hex().text());
                else
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Received unknown block : %s", pBlock->hash.hex().text());
            }
        }

        return success;
    }

    bool Chain::processBlock(Block *pBlock)
    {
        UnspentPool &unspentPool = UnspentPool::instance();

        mProcessMutex.lock();

        updateTimeFlags();

        // Process block
        if(!pBlock->process(unspentPool, mNextBlockHeight, mBlockVersionFlags))
        {
            //TODO Add hash to blacklist. So it isn't downloaded again.

            // Save the block to a file
            ArcMist::String filePathName = Info::instance().path();
            filePathName.pathAppend(pBlock->hash.hex() + ".invalid");
            ArcMist::FileOutputStream file(filePathName, true);
            pBlock->write(&file, true);

            unspentPool.revert();
            mProcessMutex.unlock();
            return false;
        }

        // Commit and save changes to unspent pool
        if(!unspentPool.commit(mNextBlockHeight))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed to commit unspent transaction pool");
            unspentPool.revert();
            mProcessMutex.unlock();
            return false;
        }

        // Add the block to the chain
        BlockFile *blockFile = NULL;
        bool success = true;
        if(mLastFileID == 0xffffffff)
        {
            // Create first block file
            mLastFileID = 0;
            ArcMist::String filePathName = blockFileName(mLastFileID);
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Creating first block file %08d", mLastFileID, mLastFileID + 1);
            lockBlockFile(mLastFileID);
            blockFile = BlockFile::create(mLastFileID, filePathName);
            if(blockFile == NULL) // Failed to create file
                success = false;
        }
        else
        {
            // Check if last block file is full
            lockBlockFile(mLastFileID);
            blockFile = new BlockFile(mLastFileID, blockFileName(mLastFileID));

            if(blockFile->isFull())
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Block file %08d is full. Starting new block file %08d", mLastFileID, mLastFileID + 1);

                unlockBlockFile(mLastFileID);
                delete blockFile;

                // Create next file
                mLastFileID++;
                lockBlockFile(mLastFileID);
                ArcMist::String filePathName = blockFileName(mLastFileID);
                BlockFile::create(mLastFileID, filePathName);
                blockFile = new BlockFile(mLastFileID, filePathName);
            }
        }

        if(success)
        {
            success = blockFile->addBlock(*pBlock);
            delete blockFile;
            unlockBlockFile(mLastFileID);
        }

        if(success)
        {
            uint16_t lookup = pBlock->hash.lookup();
            mBlockLookup[lookup].lock();
            mBlockLookup[lookup].push_back(new BlockInfo(pBlock->hash, mLastFileID, mNextBlockHeight));
            mBlockLookup[lookup].unlock();

            addBlockVersion(pBlock->version);
            updateBlockVersionFlags();

            mNextBlockHeight++;
            mLastBlockHash = pBlock->hash;
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
              "Added block to chain at height %d (%d trans) (%d bytes) : %s", mNextBlockHeight - 1, pBlock->transactionCount,
              pBlock->size(), pBlock->hash.hex().text());
        }
        else
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
              "Failed to add to block to file %08d : %s", mLastFileID, pBlock->hash.hex().text());
        }

        mProcessMutex.unlock();
        return success;
    }

    void Chain::process()
    {
        while(true)
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
            mPendingMutex.unlock();
            if(!nextPending->isFull()) // Next pending block is not full yet
                return;

            // Check this front block and add it to the chain
            if(processBlock(nextPending->block))
            {
                mPendingMutex.lock();

                mPendingSize -= nextPending->block->size();
                mPendingBlocks--;

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
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Clearing all pending blocks/headers");

                // Clear pending blocks since they assumed this block was good
                mPendingMutex.lock();
                for(std::list<PendingData *>::iterator pending=mPending.begin();pending!=mPending.end();++pending)
                    delete *pending;
                mPending.clear();
                mLastPendingHash.clear();
                mPendingSize = 0;
                mPendingBlocks = 0;
                mPendingMutex.unlock();

                //TODO Figure out how to recover from this

                // Stop daemon
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
                  "Stopping daemon because this is currently unrecoverable");
                Daemon::instance().requestStop();
            }
        }
    }

    bool Chain::getBlockHashes(HashList &pHashes, const Hash &pStartingHash, unsigned int pCount)
    {
        BlockFile *blockFile;
        unsigned int fileID;
        HashList fileList;
        bool started = false;

        if(pStartingHash.isEmpty())
        {
            started = true;
            fileID = 0;
        }
        else
            fileID = blockFileID(pStartingHash);

        if(fileID == 0xffffffff)
            return false;

        pHashes.clear();

        while(pHashes.size() < pCount)
        {
            lockBlockFile(fileID);
            blockFile = new BlockFile(fileID, blockFileName(fileID));

            if(!blockFile->readBlockHashes(fileList))
                break;

            delete blockFile;
            unlockBlockFile(fileID);

            for(HashList::iterator i=fileList.begin();i!=fileList.end();)
                if(started || **i == pStartingHash)
                {
                    started = true;
                    pHashes.push_back(*i);
                    i = fileList.erase(i);
                    if(pHashes.size() >= pCount)
                        break;
                }
                else
                    ++i;

            if(pHashes.size() >= pCount)
                break;
            fileID++;
        }

        return pHashes.size() > 0;
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

    bool Chain::getBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, const Hash &pStoppingHash, unsigned int pCount)
    {
        BlockFile *blockFile;
        Hash hash = pStartingHash;
        unsigned int fileID = blockFileID(hash);

        pBlockHeaders.clear();

        if(fileID == 0xffffffff)
            return false; // hash not found

        while(pBlockHeaders.size() < pCount)
        {
            lockBlockFile(fileID);
            blockFile = new BlockFile(fileID, blockFileName(fileID));

            if(!blockFile->readBlockHeaders(pBlockHeaders, hash, pStoppingHash, pCount))
            {
                delete blockFile;
                unlockBlockFile(fileID);
                break;
            }

            delete blockFile;
            unlockBlockFile(fileID);

            if(pBlockHeaders.size() > 0 && pBlockHeaders.back()->hash == pStoppingHash)
                break;

            hash.clear();
            fileID++;
        }

        return pBlockHeaders.size() > 0;
    }

    bool Chain::getBlockHash(unsigned int pHeight, Hash &pHash)
    {
        unsigned int fileID = pHeight / 100;
        unsigned int offset = pHeight - (fileID * 100);

        lockBlockFile(fileID);
        BlockFile *blockFile = new BlockFile(fileID, blockFileName(fileID));

        bool success = blockFile->isValid() && blockFile->readHash(offset, pHash);

        delete blockFile;
        unlockBlockFile(fileID);
        return success;
    }

    bool Chain::getBlock(unsigned int pHeight, Block &pBlock)
    {
        unsigned int fileID = pHeight / 100;
        unsigned int offset = pHeight - (fileID * 100);

        lockBlockFile(fileID);
        BlockFile *blockFile = new BlockFile(fileID, blockFileName(fileID));

        bool success = blockFile->isValid() && blockFile->readBlock(offset, pBlock, true);

        delete blockFile;
        unlockBlockFile(fileID);
        return success;
    }

    bool Chain::getBlock(const Hash &pHash, Block &pBlock)
    {
        unsigned int fileID = blockFileID(pHash);
        if(fileID == 0xffffffff)
            return false; // hash not found

        lockBlockFile(fileID);
        BlockFile *blockFile = new BlockFile(fileID, blockFileName(fileID));

        bool success = blockFile->isValid() && blockFile->readBlock(pHash, pBlock, true);

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
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Loading blocks");

        // Load hashes from block files
        BlockFile *blockFile = NULL;
        uint16_t lookup;
        ArcMist::String filePathName;
        HashList hashes;
        Hash *lastBlock = NULL;
        bool success = true;
        bool done = false;
        Hash emptyHash;
        std::list<uint32_t> blockFileVersions;

        mProcessMutex.lock();

        mLastFileID = 0xffffffff;
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
                if(!blockFile->isValid())
                {
                    delete blockFile;
                    unlockBlockFile(fileID);
                    success = false;
                    break;
                }

                if(!blockFile->readBlockHashes(hashes) || !blockFile->readVersions(blockFileVersions))
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed to read hashes from block file %s", filePathName.text());
                    delete blockFile;
                    unlockBlockFile(fileID);
                    success = false;
                    break;
                }
                delete blockFile;
                unlockBlockFile(fileID);

                // Add block versions
                for(std::list<uint32_t>::iterator version=blockFileVersions.begin();version!=blockFileVersions.end();++version)
                    addBlockVersion(*version);

                if(pList)
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Block file %s", filePathName.text());

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
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Block %08d : %s", mNextBlockHeight, (*hash)->hex().text());
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

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME,
          "Loaded block chain height of %d", mNextBlockHeight);

        if(success && mNextBlockHeight == 0)
        {
            // Add genesis block
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Creating genesis block");
            Block *genesis = Block::genesis();
            bool success = processBlock(genesis);
            delete genesis;
            if(!success)
                return false;
        }

        if(success && lastBlock != NULL)
            mLastBlockHash = *lastBlock;
        updateBlockVersionFlags();
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

            if(!blockFile->isValid())
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                  "Block file %08d isn't valid", fileID);
                break;
            }

            for(i=0;i<BlockFile::MAX_BLOCKS;i++)
            {
                if(blockFile->readBlock(i, block, true))
                {
                    if(block.previousHash != previousHash)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Block %010d previous hash doesn't match", height);
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Included Previous Hash : %s", block.previousHash.hex().text());
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Previous Block's Hash  : %s", previousHash.hex().text());
                        return false;
                    }

                    block.calculateMerkleHash(merkleHash);
                    if(block.merkleHash != merkleHash)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Block %010d has invalid merkle hash", height);
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Included Merkle Hash : %s", block.merkleHash.hex().text());
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Correct Merkle Hash  : %s", merkleHash.hex().text());
                        return false;
                    }

                    if(!block.process(unspent, height, mBlockVersionFlags))
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Block %010d failed to process", height);
                        return false;
                    }

                    if(!unspent.commit(height))
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
                          "Block %010d unspent commit failed", height);
                        return false;
                    }

                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME,
                      "Block %010d is valid : %6d transactions, %d bytes", height, block.transactions.size(), block.size());
                    //block.print();

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

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Unspent transactions :  %d", unspent.count());
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Validated block height of %d", height);
        return true;
    }

    bool Chain::test()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "------------- Starting Block Chain Tests -------------");

        bool success = true;
        ArcMist::Buffer checkData;
        Hash checkHash(32);
        Block *genesis = Block::genesis();

        //genesis->print(ArcMist::Log::INFO);

        //ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Current coin base amount : %f",
        // (double)bitcoins(Block::coinBaseAmount(485000)));

        /***********************************************************************************************
         * Genesis block merkle hash
         ***********************************************************************************************/
        checkData.clear();
        checkData.writeHex("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a");
        checkHash.read(&checkData);

        if(genesis->merkleHash == checkHash)
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed genesis block merkle hash");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed genesis block merkle hash");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Block merkle hash   : %s", genesis->merkleHash.hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct merkle hash : %s", checkHash.hex().text());
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed genesis block hash");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed genesis block hash");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Block hash   : %s", genesis->hash.hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct hash : %s", checkHash.hex().text());
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed genesis block read hash");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed genesis block read hash");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Block hash   : %s", readGenesisBlock.hash.hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct hash : %s", checkHash.hex().text());
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
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME,
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

                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed genesis block raw data line %d", lineNo);
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Actual  : %s", actualHex.text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct : %s", checkHex.text());
                    success = false;
                }
            }

            if(matches)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed genesis block raw data");
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
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed to read block");
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
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed read block hash");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed read block hash");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Block hash   : %s", readBlock.hash.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct hash : %s", checkHash.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Block read previous hash
             ***********************************************************************************************/
            checkData.clear();
            checkData.writeHex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000");
            checkHash.read(&checkData);

            if(readBlock.previousHash == checkHash)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed read block previous hash");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed read block previous hash");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Block previous hash   : %s", readBlock.previousHash.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct previous hash : %s", checkHash.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Block read merkle hash
             ***********************************************************************************************/
            readBlock.calculateMerkleHash(checkHash);

            if(readBlock.merkleHash == checkHash)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed read block merkle hash");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed read block merkle hash");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Block merkle hash   : %s", readBlock.merkleHash.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Correct merkle hash : %s", checkHash.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Block read process
             ***********************************************************************************************/
            if(readBlock.process(unspents, 1, 0))
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed read block process");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed read block process");
                success = false;
            }
        }

        delete genesis;

        /***********************************************************************************************
         * New Block
         ***********************************************************************************************/
        // Requires unspents to be setup
        // Info::instance().setPath("/var/bitcoin/testnet");
        // unspents.load();

        // ArcMist::FileInputStream file("/var/bitcoin/testnet/4c9896aebed9238ed3090a4ef6fcff7c3a46b9487373cb3b33e2861500000000.invalid");
        // Block newBlock;

        // newBlock.read(&file, true);

        // if(newBlock.process(unspents, unspents.blockHeight(), 0))
            // ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_CHAIN_LOG_NAME, "Passed New Block test");
        // else
        // {
            // ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_CHAIN_LOG_NAME, "Failed New Block test");
            // success = false;
        // }

        // newBlock.print();

        // Info::instance().setPath("/var/bitcoin/testnet");
        // Test of get headers and printing
        // Chain &chain = Chain::instance();
        // BlockList headers;
        // Hash zeroHash(32);
        // ArcMist::Buffer hashData;
        // hashData.writeHex("add5df18f427437ace8b40064b3806583217a3f724672cf72cf8c18300000000");
        // Hash startingHash;
        // startingHash.read(&hashData, 32);
        // chain.loadBlocks(false);
        // chain.getBlockHeaders(headers, startingHash, zeroHash, 50);

        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME, "Retrieved %d headers", headers.size());
        // for(BlockList::iterator i=headers.begin();i!=headers.end();++i)
            // (*i)->print();

        // HashList list;
        // chain.getBlockHashes(list, startingHash, 500);
        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME, "Retreived %d hashes", list.size());

        // for(HashList::iterator i=list.begin();i!=list.end();++i)
            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_CHAIN_LOG_NAME, "Hash : %s", (*i)->hex().text());

        return success;
    }
}
