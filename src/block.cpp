#include "block.hpp"

#include "arcmist/base/log.hpp"
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
        writeCompactInteger(pStream, transactions.size());

        if(!pIncludeTransactions)
            return;

        // Transactions
        for(uint64_t i=0;i<transactions.size();i++)
            transactions[i].write(pStream);
    }

    bool Block::read(ArcMist::InputStream *pStream, bool pIncludeTransactions)
    {
        if(pStream->remaining() < 81)
            return false;

        // Version
        version = pStream->readUnsignedInt();

        // Hash of previous block
        previousHash.read(pStream);

        // Merkle Root Hash
        merkleHash.read(pStream);

        // Time
        time = pStream->readUnsignedInt();

        // Encoded version of target threshold
        bits = pStream->readUnsignedInt();

        // Nonce
        nonce = pStream->readUnsignedInt();

        // Transaction Count
        uint64_t count = readCompactInteger(pStream);
        if(pStream->remaining() < count)
            return false;

        transactions.clear();
        if(!pIncludeTransactions)
            return true;

        // Transactions
        transactions.resize(count);
        for(uint64_t i=0;i<count;i++)
            if(!transactions[i].read(pStream))
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
        ~BlockFile()
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
        }

        unsigned int id;
        ArcMist::FileStream stream;
        bool isValid;
        unsigned int crc;

        bool isFull();

        // Read list of hashes in this file
        bool readHashes(std::vector<Hash> &pHashes);

        // Read block for specified hash
        bool readBlock(const Hash &pHash, Block &pBlock, bool pIncludeTransactions);

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

    bool BlockFile::readHashes(std::vector<Hash> &pHashes)
    {
        pHashes.clear();

        if(!isValid)
            return false;

        // Read hashes
        stream.setReadOffset(HASHES_OFFSET);
        pHashes.resize(MAX_BLOCKS);
        for(unsigned int i=0;i<MAX_BLOCKS;i++)
        {
            if(!pHashes[i].read(&stream, 32))
                return false;
            stream.readUnsignedInt(); // data offset
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
            if(!hash.read(&stream, 32))
                return false;
            if(hash == pHash)
            {
                // Read block
                unsigned int fileOffset = stream.readUnsignedInt();
                if(fileOffset == 0)
                    return false;
                stream.setReadOffset(fileOffset);
                pBlock.read(&stream, pIncludeTransactions);
            }
            stream.readUnsignedInt(); // data offset
        }

        return false;
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

    BlockChain::BlockChain() : mBlockMutex("Block")
    {
        mLastBlockFile = NULL;
    }

    BlockChain::~BlockChain()
    {
        mBlockMutex.lock();
        for(std::list<BlockInfo *>::iterator i=mBlocks.begin();i!=mBlocks.end();++i)
            delete *i;
        mBlockMutex.unlock();

        if(mLastBlockFile != NULL)
            delete mLastBlockFile;
    }

    bool BlockChain::addBlock(const Block &pBlock)
    {
        bool valid = false;

        mBlockMutex.lock();

        // Verify previous hash of this block matchs hash of last block on chain
        if(mBlocks.size() == 0)
            valid = pBlock.previousHash.isZero();
        else
            valid = pBlock.previousHash == mBlocks.back()->hash;

        if(!valid)
        {
            mBlockMutex.unlock();
            return false;
        }

        // Write block to a file
        if(mLastBlockFile == NULL)
            mLastBlockFile = new BlockFile(0, blockFileName(0)); // Start first block file
        else if(mLastBlockFile->isFull())
        {
            unsigned int newID = mLastBlockFile->id + 1;
            delete mLastBlockFile;
            mLastBlockFile = new BlockFile(newID, blockFileName(newID)); // Start next block file
            
        }

        // Add block info to mBlocks

        mBlockMutex.unlock();
        return true;
    }

    void BlockChain::getBlockHashes(std::vector<Hash *> &pHashes, const Hash &pStartingHash, unsigned int pCount)
    {
        bool started = false;
        pHashes.clear();

        //TODO Build index of hashes for fast lookup
        mBlockMutex.lock();
        for(std::list<BlockInfo *>::iterator i=mBlocks.begin();i!=mBlocks.end() && pHashes.size()<pCount;++i)
        {
            if(pStartingHash == (*i)->hash)
                started = true;
            if(started)
                pHashes.push_back(&((*i)->hash));
        }
        mBlockMutex.unlock();
    }

    void BlockChain::getBlockHeaders(BlockList &pBlockHeaders, const Hash &pStartingHash, unsigned int pCount)
    {
        bool started = false;
        pBlockHeaders.clear();
        BlockFile *blockFile = NULL;
        unsigned int blockFileID;

        //TODO Build index of hashes for fast lookup
        mBlockMutex.lock();
        for(std::list<BlockInfo *>::iterator i=mBlocks.begin();i!=mBlocks.end() && pBlockHeaders.size()<pCount;++i)
        {
            if(pStartingHash == (*i)->hash)
                started = true;
            if(started)
            {
                if(blockFile == NULL && blockFileID != (*i)->fileID)
                {
                    if(blockFile != NULL)
                        delete blockFile;
                    blockFile = new BlockFile((*i)->fileID, blockFileName((*i)->fileID));
                    blockFileID = (*i)->fileID;
                }

                if(!blockFile->isValid)
                    break;

                Block *newBlockHeader = new Block();
                if(blockFile->readBlock((*i)->hash, *newBlockHeader, false))
                    pBlockHeaders.push_back(newBlockHeader);
                else
                    break;
            }
        }

        if(blockFile != NULL)
            delete blockFile;
        mBlockMutex.unlock();
    }

    bool BlockChain::getBlock(const Hash &pHash, Block &pBlock)
    {
        mBlockMutex.lock();
        for(std::list<BlockInfo *>::iterator i=mBlocks.begin();i!=mBlocks.end();++i)
            if(pHash == (*i)->hash)
            {
                //TODO Add individual mutexes for each block file
                BlockFile *blockFile;
                if(mLastBlockFile != NULL && mLastBlockFile->id == (*i)->fileID)
                    blockFile = mLastBlockFile;
                else
                    blockFile = new BlockFile((*i)->fileID, blockFileName((*i)->fileID));
                bool success = blockFile->isValid && blockFile->readBlock(pHash, pBlock, true);
                if(blockFile != mLastBlockFile)
                    delete blockFile;
                mBlockMutex.unlock();
                return success;
            }

        mBlockMutex.unlock();
        return false;
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
        // Load hashes from block info files
        mBlockMutex.lock();
        mLastBlockFile = NULL;
        ArcMist::String filePathName;
        for(unsigned int fileID=1;;fileID++)
        {
            filePathName = blockFileName(fileID);
            if(ArcMist::fileExists(filePathName))
            {
                // Load hashes from file
                if(mLastBlockFile != NULL)
                    delete mLastBlockFile;
                mLastBlockFile = new BlockFile(fileID, filePathName);
                if(!mLastBlockFile->isValid)
                    break;

                std::vector<Hash> hashes;
                mLastBlockFile->readHashes(hashes);
                for(unsigned int i=0;i<hashes.size();i++)
                    if(hashes[i].isZero())
                        break;
                    else
                        mBlocks.push_back(new BlockInfo(hashes[i], fileID));
            }
            else
                break;
        }

        mBlockMutex.unlock();
        return false;
    }

    bool BlockChain::test()
    {
        bool success = true;
        
        return success;
    }
}
