/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "header.hpp"

#include "log.hpp"
#include "endian.hpp"
#include "thread.hpp"
#include "digest.hpp"
#include "interpreter.hpp"
#include "info.hpp"
#include "chain.hpp"

#define BITCOIN_HEADER_LOG_NAME "Header"


namespace BitCoin
{
    bool Header::hasProofOfWork()
    {
        NextCash::Hash target;
        target.setDifficulty(targetBits);
        return hash <= target;
    }

    void Header::calculateHash()
    {
        // Write into digest
        NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
        digest.setOutputEndian(NextCash::Endian::LITTLE);
        write(&digest, false);

        // Get SHA256_SHA256 of block data
        digest.getResult(&hash);
    }

    void Header::write(NextCash::OutputStream *pStream, bool pIncludeTransactionCount) const
    {
        // Version
        pStream->writeInt(version);

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

        if(pIncludeTransactionCount)
            writeCompactInteger(pStream, 0);
    }

    bool Header::read(NextCash::InputStream *pStream, bool pIncludeTransactionCount,
      bool pCalculateHash)
    {
        // Create hash
        NextCash::Digest *digest = NULL;
        if(pCalculateHash)
        {
            digest = new NextCash::Digest(NextCash::Digest::SHA256_SHA256);
            digest->setOutputEndian(NextCash::Endian::LITTLE);
        }
        hash.clear();

        if(pStream->remaining() < 80)
        {
            if(digest != NULL)
                delete digest;
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_HEADER_LOG_NAME,
              "Header read failed : only %d bytes", pStream->remaining());
            return false;
        }

        // Version
        version = (int32_t)pStream->readInt();
        if(pCalculateHash)
            digest->writeUnsignedInt((unsigned int)version);

        // Hash of previous block
        if(!previousHash.read(pStream))
        {
            if(digest != NULL)
                delete digest;
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_HEADER_LOG_NAME,
              "Header read failed : read previous hash failed");
            return false;
        }
        if(pCalculateHash)
            previousHash.write(digest);

        // Merkle Root Hash
        if(!merkleHash.read(pStream))
        {
            if(digest != NULL)
                delete digest;
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_HEADER_LOG_NAME,
              "Header read failed : read merkle hash failed");
            return false;
        }
        if(pCalculateHash)
            merkleHash.write(digest);

        // Time
        time = pStream->readUnsignedInt();
        if(pCalculateHash)
            digest->writeInt(time);

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

        if(pIncludeTransactionCount)
            transactionCount = readCompactInteger(pStream);
        else
            transactionCount = 0;

        return true;
    }

    void Header::clear()
    {
        hash.clear();
        version = 0;
        previousHash.zeroize();
        merkleHash.zeroize();
        time = 0;
        targetBits = 0;
        nonce = 0;
        transactionCount = 0;
    }

    void Header::print(NextCash::Log::Level pLevel)
    {
        NextCash::Log::addFormatted(pLevel, BITCOIN_HEADER_LOG_NAME, "Hash          : %s",
          hash.hex().text());
        NextCash::Log::addFormatted(pLevel, BITCOIN_HEADER_LOG_NAME, "Version       : 0x%08x",
          version);
        NextCash::Log::addFormatted(pLevel, BITCOIN_HEADER_LOG_NAME, "Previous Hash : %s",
          previousHash.hex().text());
        NextCash::Log::addFormatted(pLevel, BITCOIN_HEADER_LOG_NAME, "MerkleHash    : %s",
          merkleHash.hex().text());
        NextCash::String timeText;
        timeText.writeFormattedTime(time);
        NextCash::Log::addFormatted(pLevel, BITCOIN_HEADER_LOG_NAME, "Time          : %s (%d)",
          timeText.text(), time);
        NextCash::Log::addFormatted(pLevel, BITCOIN_HEADER_LOG_NAME, "Bits          : 0x%08x",
          targetBits);
        NextCash::Log::addFormatted(pLevel, BITCOIN_HEADER_LOG_NAME, "Nonce         : 0x%08x",
          nonce);
        NextCash::Log::addFormatted(pLevel, BITCOIN_HEADER_LOG_NAME, "%d Transactions",
          transactionCount);
    }

    class HeaderFile
    {
    public:

        static const unsigned int MAX_COUNT = 1000; // Maximum count of headers in one file.

        static unsigned int fileID(unsigned int pHeight) { return pHeight / MAX_COUNT; }
        static unsigned int fileOffset(unsigned int pHeight) { return pHeight - (fileID(pHeight) * MAX_COUNT); }
        static NextCash::String filePathName(unsigned int pID);

        static const unsigned int CACHE_COUNT = 5;
        static NextCash::MutexWithConstantName sCacheLock;
        static HeaderFile *sCache[CACHE_COUNT];

        // Return locked header file.
        static HeaderFile *get(unsigned int pFileID, bool pWriteAccess, bool pCreate = false);

        static bool exists(unsigned int pFileID);

        // Moves cached header file to the front of the list
        static void moveToFront(unsigned int pOffset);

        static void save();

        // Cleans up cached data.
        static void clean();

        // Remove a header file.
        static bool remove(unsigned int pFileID);

        unsigned int id() const { return mID; }
        bool isValid() const { return mValid; }
        unsigned int itemCount();
        NextCash::Hash lastHash();

        void lock(bool pWriteAccess)
        {
            mLock.lock();
            // if(pWriteAccess)
                // mLock.writeLock();
            // else
                // mLock.readLock();
        }
        void unlock(bool pWriteAccess)
        {
            mLock.unlock();
            // if(pWriteAccess)
                // mLock.writeUnlock();
            // else
                // mLock.readUnlock();
        }

        bool validate(); // Validate CRC of file

        // Add a header to the file.
        bool writeHeader(const Header &pHeader);

        // Remove blocks from file above a specific offset in the file.
        bool removeHeadersAbove(unsigned int pOffset);

        // Read header at specified offset in file. Return false if the offset is too high.
        bool readHeader(unsigned int pOffset, Header &pHeader);

        // Read list of header headers from this file.
        bool readHeaders(unsigned int pOffset, unsigned int pCount, HeaderList &pHeaders);

        // Read hash at specified offset in file. Return false if the offset is too high.
        bool readHash(unsigned int pOffset, NextCash::Hash &pHash);

        bool readHashes(unsigned int pOffset, unsigned int pCount, NextCash::HashList &pHashes);
        bool readTargetBits(unsigned int pOffset, unsigned int pCount,
          std::vector<uint32_t> &pTargetBits);
        bool readHeaderStatsReverse(unsigned int pOffset, unsigned int pCount,
          std::list<HeaderStat> &pHeaderStats);

    private:

        HeaderFile(unsigned int pID, bool pCreate);
        ~HeaderFile() { lock(true); updateCRC(); if(mInputFile != NULL) delete mInputFile; }

        /* File format
         *   Start string
         *   CRC32 of data after CRC in file
         *   MAX_COUNT x Headers (32 byte block hash, 4 byte offset into file of block data)
         */
        static const unsigned int CRC_OFFSET = 8; // After start string
        static const unsigned int DATA_START_OFFSET = 12; // After CRC
        // 32 byte hash, 80 byte header, 4 byte transaction count
        static const unsigned int ITEM_SIZE = 116;
        static constexpr const char *START_STRING = "NCHDRS01";

        static NextCash::String sFilePath;

        // Open and validate a file stream for reading
        bool openFile(bool pCreate = false);

        void updateCRC();

        unsigned int mID;
        NextCash::MutexWithConstantName mLock;
        NextCash::FileInputStream *mInputFile;
        NextCash::String mFilePathName;
        bool mValid;
        bool mModified;

        HeaderFile(HeaderFile &pCopy);
        HeaderFile &operator = (HeaderFile &pRight);

    };

    NextCash::String HeaderFile::sFilePath;
    NextCash::MutexWithConstantName HeaderFile::sCacheLock("HeaderFileCache");
    HeaderFile *HeaderFile::sCache[CACHE_COUNT] = { NULL, NULL, NULL, NULL, NULL };

    void HeaderFile::moveToFront(unsigned int pOffset)
    {
        static HeaderFile *swap[CACHE_COUNT] = { NULL, NULL, NULL, NULL, NULL };

        if(pOffset == 0)
            return;

        unsigned int next = 0;
        swap[next++] = sCache[pOffset];
        for(unsigned int j = 0; j < CACHE_COUNT; ++j)
            if(j != pOffset)
                swap[next++] = sCache[j];

        // Swap back
        for(unsigned int j = 0; j < CACHE_COUNT; ++j)
            sCache[j] = swap[j];
    }

    bool HeaderFile::exists(unsigned int pFileID)
    {
        return NextCash::fileExists(HeaderFile::filePathName(pFileID));
    }

    HeaderFile *HeaderFile::get(unsigned int pFileID, bool pWriteAccess, bool pCreate)
    {
        sCacheLock.lock();

        // Check if the file is already open.
        for(unsigned int i = 0; i < CACHE_COUNT; ++i)
            if(sCache[i] != NULL && sCache[i]->mID == pFileID)
            {
                HeaderFile *result = sCache[i];
                result->lock(pWriteAccess);
                moveToFront(i);
                sCacheLock.unlock();
                return result;
            }

        // Open file
        HeaderFile *result = new HeaderFile(pFileID, pCreate);
        if(!result->isValid())
        {
            delete result;
            sCacheLock.unlock();
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_HEADER_LOG_NAME,
              "Header file %08x failed to open.", pFileID);
            return NULL;
        }

        result->lock(pWriteAccess);

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

    bool HeaderFile::remove(unsigned int pFileID)
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
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_HEADER_LOG_NAME,
              "Removed header file %08x", pFileID);
            return true;
        }

        return false;
    }

    void HeaderFile::save()
    {
        sCacheLock.lock();
        for(int i = CACHE_COUNT-1; i >= 0; --i)
            if(sCache[i] != NULL)
            {
                sCache[i]->lock(true);
                sCache[i]->updateCRC();
                sCache[i]->unlock(true);
            }
        sCacheLock.unlock();

        sFilePath.clear();
    }

    void Header::save()
    {
        HeaderFile::save();
    }

    void HeaderFile::clean()
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

    void Header::clean()
    {
        HeaderFile::clean();
    }

    NextCash::String HeaderFile::filePathName(unsigned int pID)
    {
        if(!sFilePath)
        {
            // Build path
            sFilePath = Info::instance().path();
            sFilePath.pathAppend("headers");
            NextCash::createDirectory(sFilePath);
        }

        // Build path
        NextCash::String result;
        result.writeFormatted("%s%s%08x", sFilePath.text(), NextCash::PATH_SEPARATOR, pID);
        return result;
    }

    HeaderFile::HeaderFile(unsigned int pID, bool pCreate) : mLock("HeaderFile")
    {
        mValid = true;
        mFilePathName = filePathName(pID);
        mInputFile = NULL;
        mID = pID;
        mModified = false;

        if(!openFile(pCreate))
        {
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_HEADER_LOG_NAME,
              "Failed to open header file : %s", mFilePathName.text());
            mValid = false;
            return;
        }

        // Read start string
        NextCash::String startString = mInputFile->readString(8);

        // Check start string
        if(startString != START_STRING)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_HEADER_LOG_NAME,
              "Header file %08x missing start string", mID);
            mValid = false;
            return;
        }
    }

    bool HeaderFile::openFile(bool pCreate)
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
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_HEADER_LOG_NAME,
              "Header file %08x not found.", mID);
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
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_HEADER_LOG_NAME,
              "Header file %08x failed to open.", mID);
            return false;
        }

        // Write start string
        outputFile->writeString(START_STRING);

        // Write empty CRC
        outputFile->writeUnsignedInt(0);

        // Get CRC (for empty data)
        NextCash::Digest digest(NextCash::Digest::CRC32);
        digest.setOutputEndian(NextCash::Endian::LITTLE);
        NextCash::Buffer crcBuffer;
        crcBuffer.setEndian(NextCash::Endian::LITTLE);
        digest.getResult(&crcBuffer);
        unsigned int crc = crcBuffer.readUnsignedInt();

        // Write CRC
        outputFile->setWriteOffset(CRC_OFFSET);
        outputFile->writeUnsignedInt(crc);

        // Close file
        delete outputFile;

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_HEADER_LOG_NAME,
          "Header file %08x created with CRC : %08x", mID, crc);

        // Re-open file
        mInputFile = new NextCash::FileInputStream(mFilePathName);
        mInputFile->setInputEndian(NextCash::Endian::LITTLE);
        mInputFile->setReadOffset(0);

        return mInputFile->isValid();
    }

    void HeaderFile::updateCRC()
    {
        if(!mModified || !mValid)
            return;

        if(!openFile())
        {
            mValid = false;
            return;
        }

        // Calculate new CRC
        NextCash::Digest digest(NextCash::Digest::CRC32);
        digest.setOutputEndian(NextCash::Endian::LITTLE);

        // Read file into digest
        mInputFile->setReadOffset(DATA_START_OFFSET);
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

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_HEADER_LOG_NAME,
          "Header file %08x CRC updated : 0x%08x", mID, crc);
    }

    bool HeaderFile::validate()
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
        if(crc == calculatedCRC)
            return true;

        // Attempt to verify the data in the file.
        mValid = true;
        mInputFile->setReadOffset(DATA_START_OFFSET);

        NextCash::Hash hash(BLOCK_HASH_SIZE);
        Header header;
        NextCash::stream_size lastGoodOffset = DATA_START_OFFSET;

        while(mInputFile->remaining())
        {
            if(!hash.read(mInputFile))
            {
                mValid = false;
                break;
            }

            if(!header.read(mInputFile, false, true))
            {
                mValid = false;
                break;
            }

            if(mInputFile->remaining() < 4)
            {
                mValid = false;
                break;
            }

            mInputFile->skip(4);

            if(hash != header.hash)
            {
                mValid = false;
                break;
            }

            lastGoodOffset = mInputFile->readOffset();
        }

        if(lastGoodOffset == DATA_START_OFFSET)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_HEADER_LOG_NAME,
              "Header file %08x has no good headers : 0x%08x != 0x%08x", mID, crc, calculatedCRC);
            return false;
        }

        NextCash::stream_size truncateSize = mInputFile->length() - lastGoodOffset;
        if(truncateSize != 0)
        {
            // Truncate end of file.
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_HEADER_LOG_NAME,
              "Header file %08x reverting to count of %d", mID,
              (lastGoodOffset - DATA_START_OFFSET) / ITEM_SIZE);

            NextCash::String swapFilePathName = mFilePathName + ".swap";
            NextCash::FileOutputStream *swapFile = new NextCash::FileOutputStream(swapFilePathName,
              true);

            if(!swapFile->isValid())
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
                  "Failed to repair header file %08x. Failed to open swap file", mID);
                delete swapFile;
                return false;
            }

            mInputFile->setReadOffset(0);
            swapFile->writeStream(mInputFile, lastGoodOffset);
            delete mInputFile;
            mInputFile = NULL;
            delete swapFile;

            if(!NextCash::renameFile(swapFilePathName, mFilePathName))
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_HEADER_LOG_NAME,
                  "Failed to repair header file %08x. Failed to rename swap file", mID);
                return false;
            }
        }

        if(mValid)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
              "Repaired header file %08x. Truncated %d headers", mID, truncateSize / ITEM_SIZE);
            mModified = true;
            updateCRC();
            return true;
        }
        else
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_HEADER_LOG_NAME,
              "Failed to repair header file %08x : 0x%08x != 0x%08x", mID, crc, calculatedCRC);
            return false;
        }
    }

    unsigned int HeaderFile::itemCount()
    {
        if(!openFile())
        {
            mValid = false;
            return 0;
        }
        return (mInputFile->length() - DATA_START_OFFSET) / ITEM_SIZE;
    }

    NextCash::Hash HeaderFile::lastHash()
    {
        NextCash::Hash result(BLOCK_HASH_SIZE);
        if(!openFile())
        {
            mValid = false;
            return result;
        }
        mInputFile->setReadOffset(DATA_START_OFFSET + ((itemCount() - 1) * ITEM_SIZE));
        result.read(mInputFile);
        return result;
    }

    bool HeaderFile::writeHeader(const Header &pHeader)
    {
        if(pHeader.hash.size() != BLOCK_HASH_SIZE)
            return false;

        if(!openFile())
        {
            mValid = false;
            return false;
        }

        unsigned int count = itemCount();

        if(count == MAX_COUNT)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
              "Header file %08x is already full", mID);
            return false;
        }

        if(mInputFile != NULL)
            delete mInputFile;
        mInputFile = NULL;

        NextCash::FileOutputStream *outputFile = new NextCash::FileOutputStream(mFilePathName,
          false, true);
        outputFile->setOutputEndian(NextCash::Endian::LITTLE);
        if(!outputFile->isValid())
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
              "Header file %08x output file failed to open", mID);
            delete outputFile;
            return false;
        }

        // Write header data at end of file
        pHeader.hash.write(outputFile);
        pHeader.write(outputFile, false);
        outputFile->writeUnsignedInt(pHeader.transactionCount);
        delete outputFile;

        mModified = true;

        // Update CRC when the file is full.
        if(count + 1 == MAX_COUNT)
            updateCRC();
        return true;
    }

    bool HeaderFile::removeHeadersAbove(unsigned int pOffset)
    {
        if(pOffset + 1 == MAX_COUNT - 1)
            return false;

        if(!openFile())
        {
            mValid = false;
            return false;
        }

        NextCash::stream_size newFileSize = DATA_START_OFFSET + ((pOffset + 1) * ITEM_SIZE);

        if(newFileSize > mInputFile->length())
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
              "Header file %08x offset not above %d", mID, pOffset);
            return false;
        }

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_HEADER_LOG_NAME,
          "Header file %08x reverting to count of %d", mID, pOffset);

        NextCash::String swapFilePathName = mFilePathName + ".swap";
        NextCash::FileOutputStream *swapFile = new NextCash::FileOutputStream(swapFilePathName,
          true);

        if(!swapFile->isValid())
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
              "Header file %08x swap output file failed to open", mID);
            delete swapFile;
            return false;
        }

        mInputFile->setReadOffset(0);
        swapFile->writeStream(mInputFile, newFileSize);
        delete mInputFile;
        mInputFile = NULL;
        delete swapFile;

        mModified = true;

        if(!NextCash::renameFile(swapFilePathName, mFilePathName))
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_HEADER_LOG_NAME,
              "Header file %08x failed to rename swap file", mID);
            return false;
        }

        updateCRC();
        return true;
    }

    bool HeaderFile::readHashes(unsigned int pOffset, unsigned int pCount, NextCash::HashList &pHashes)
    {
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        if(!mInputFile->setReadOffset(DATA_START_OFFSET + (pOffset * ITEM_SIZE)) ||
          mInputFile->remaining() < ITEM_SIZE)
            return false;

        NextCash::Hash hash(BLOCK_HASH_SIZE);
        unsigned int count = itemCount();
        unsigned int added = 0;
        for(unsigned int i = pOffset; i < count && added < pCount; ++i, ++added)
        {
            if(!hash.read(mInputFile))
                return false;

            pHashes.push_back(hash);

            if(i == count - 1)
                break;

            if(!mInputFile->skip(ITEM_SIZE - BLOCK_HASH_SIZE))
                return false;
        }

        return true;
    }

    bool HeaderFile::readTargetBits(unsigned int pOffset, unsigned int pCount,
      std::vector<uint32_t> &pTargetBits)
    {
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        if(!mInputFile->setReadOffset(DATA_START_OFFSET + (pOffset * ITEM_SIZE) + 104) ||
          mInputFile->remaining() < ITEM_SIZE - 104)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
              "Header file %08x too short for starting target bits offset %d", mID, pOffset);
            return false;
        }

        unsigned int count = itemCount();
        unsigned int added = 0;
        for(unsigned int i = pOffset; i < count && added < pCount; ++i)
        {
            pTargetBits.push_back(mInputFile->readUnsignedInt());
            ++added;

            if(i == count - 1)
                break;

            if(!mInputFile->skip(ITEM_SIZE - 4))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
                  "Header file %08x too short for target bits offset %d skip", mID, i);
                return false;
            }
        }

        return true;
    }

    bool HeaderFile::readHeaderStatsReverse(unsigned int pOffset, unsigned int pCount,
      std::list<HeaderStat> &pHeaderStats)
    {
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        if(!mInputFile->setReadOffset(DATA_START_OFFSET + (pOffset * ITEM_SIZE) + BLOCK_HASH_SIZE) ||
          mInputFile->remaining() < ITEM_SIZE - BLOCK_HASH_SIZE)
            return false;

        // 12 bytes read + 64 skipped, plus 32 hash gets to begining of this item. 12 + 32
        // Then backup a full item. + ITEM_SIZE
        // Then skip over hash of previous item. - 32
        NextCash::stream_size backupOffset = 12 + 64 + ITEM_SIZE;
        uint32_t version, targetBits;
        Time time;
        unsigned int added = 0;
        for(unsigned int i = pOffset; added < pCount; --i, ++added)
        {
            version = mInputFile->readUnsignedInt();
            mInputFile->skip(64); // Skip previous and merkle hashes
            time = mInputFile->readUnsignedInt();
            targetBits = mInputFile->readUnsignedInt();
            pHeaderStats.emplace_front(version, time, targetBits);

            if(i == 0)
                break;

            // Go to previous header.
            if(!mInputFile->setReadOffset(mInputFile->readOffset() - backupOffset))
                return false;
        }

        return true;
    }

    bool HeaderFile::readHeaders(unsigned int pOffset, unsigned int pCount, HeaderList &pHeaders)
    {
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        if(!mInputFile->setReadOffset(DATA_START_OFFSET + (pOffset * ITEM_SIZE) + BLOCK_HASH_SIZE) ||
          mInputFile->remaining() < ITEM_SIZE - BLOCK_HASH_SIZE)
            return false;

        unsigned int count = itemCount();
        unsigned int added = 0;
        for(unsigned int i = pOffset; i < count && added < pCount; ++i, ++added)
        {
            pHeaders.emplace_back();
            if(!pHeaders.back().read(mInputFile, false, true))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
                  "Failed to read header %d from file %08x", i, mID);
                pHeaders.pop_back();
                return false;
            }

            if(i == count - 1)
                break;

            if(!mInputFile->skip(ITEM_SIZE - 80))
                return false;
        }

        return true;
    }

    bool HeaderFile::readHeader(unsigned int pOffset, Header &pHeader)
    {
        pHeader.clear();
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        if(!mInputFile->setReadOffset(DATA_START_OFFSET + (pOffset * ITEM_SIZE) + BLOCK_HASH_SIZE) ||
          mInputFile->remaining() < 80)
            return false;

        if(!pHeader.read(mInputFile, false, true))
            return false;

        pHeader.transactionCount = mInputFile->readUnsignedInt();
        return true;
    }

    bool Header::getHeader(unsigned int pHeight, Header &pHeader)
    {
        HeaderFile *file = HeaderFile::get(HeaderFile::fileID(pHeight), false);
        if(file == NULL)
            return false;

        bool success = file->readHeader(HeaderFile::fileOffset(pHeight), pHeader);
        file->unlock(false);
        return success;
    }

    bool Header::getHeaders(unsigned int pStartHeight, unsigned int pCount, HeaderList &pHeaders)
    {
        pHeaders.clear();

        int fileID = HeaderFile::fileID(pStartHeight);

        HeaderFile *file = HeaderFile::get(fileID, false);
        if(file == NULL)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
              "Failed to get header file %08x for height %d", fileID, pStartHeight);
            return !HeaderFile::exists(fileID);
        }

        unsigned int offset = HeaderFile::fileOffset(pStartHeight);
        while(pHeaders.size() < pCount)
        {
            if(!file->readHeaders(offset, pCount - pHeaders.size(), pHeaders))
            {
                file->unlock(false);
                return false;
            }

            file->unlock(false);
            offset = 0;
            ++fileID;
            file = HeaderFile::get(fileID, false);
            if(file == NULL)
                return !HeaderFile::exists(fileID);
        }

        file->unlock(false);
        return true;
    }

    bool HeaderFile::readHash(unsigned int pOffset, NextCash::Hash &pHash)
    {
        pHash.clear();
        if(!openFile())
        {
            mValid = false;
            return false;
        }

        if(!mInputFile->setReadOffset(DATA_START_OFFSET + (pOffset * ITEM_SIZE)) ||
          mInputFile->remaining() < ITEM_SIZE)
            return false;

        return pHash.read(mInputFile, BLOCK_HASH_SIZE);
    }

    bool Header::getHash(unsigned int pHeight, NextCash::Hash &pHash)
    {
        int fileID = HeaderFile::fileID(pHeight);

        HeaderFile *file = HeaderFile::get(fileID, false);
        if(file == NULL)
            return false;

        bool success = file->readHash(HeaderFile::fileOffset(pHeight), pHash);
        file->unlock(false);
        return success;
    }

    bool Header::getHashes(unsigned int pStartHeight, unsigned int pCount,
      NextCash::HashList &pList)
    {
        pList.clear();

        int fileID = HeaderFile::fileID(pStartHeight);

        HeaderFile *file = HeaderFile::get(fileID, false);
        if(file == NULL)
            return !HeaderFile::exists(fileID);

        unsigned int offset = HeaderFile::fileOffset(pStartHeight);
        while(pList.size() < pCount)
        {
            if(!file->readHashes(offset, pCount - pList.size(), pList))
            {
                file->unlock(false);
                return false;
            }

            file->unlock(false);
            offset = 0;
            ++fileID;
            file = HeaderFile::get(fileID, false);
            if(file == NULL)
                return !HeaderFile::exists(fileID);
        }

        file->unlock(false);
        return true;
    }

    bool Header::getTargetBits(unsigned int pStartHeight, unsigned int pCount,
      std::vector<uint32_t> &pTargetBits)
    {
        pTargetBits.clear();

        int fileID = HeaderFile::fileID(pStartHeight);

        HeaderFile *file = HeaderFile::get(fileID, false);
        if(file == NULL)
        {
            if(HeaderFile::exists(fileID))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
                  "Failed to get header file %08x", fileID);
                return false;
            }
            else
                return true;
        }

        unsigned int offset = HeaderFile::fileOffset(pStartHeight);
        while(pTargetBits.size() < pCount)
        {
            if(!file->readTargetBits(offset, pCount - pTargetBits.size(), pTargetBits))
            {
                file->unlock(false);
                return false;
            }

            file->unlock(false);
            offset = 0;
            ++fileID;
            file = HeaderFile::get(fileID, false);
            if(file == NULL)
            {
                if(HeaderFile::exists(fileID))
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
                      "Failed to get header file %08x", fileID);
                    return false;
                }
                else
                    return true;
            }
        }

        file->unlock(false);
        return true;
    }

    bool Header::getHeaderStatsReverse(unsigned int pStartHeight, unsigned int pCount,
      std::list<HeaderStat> &pHeaderStats)
    {
        pHeaderStats.clear();

        int fileID = HeaderFile::fileID(pStartHeight);
        unsigned int offset = HeaderFile::fileOffset(pStartHeight);

        // if(offset == 0)
        // {
            // if(fileID == 0)
                // return true;
            // --fileID;
            // offset = HeaderFile::MAX_COUNT;
        // }

        HeaderFile *file = HeaderFile::get(fileID, false);
        if(file == NULL)
        {
            if(HeaderFile::exists(fileID))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
                  "Failed to get header file %08x", fileID);
                return false;
            }
            else
                return true;
        }

        while(pHeaderStats.size() < pCount)
        {
            if(!file->readHeaderStatsReverse(offset, pCount - pHeaderStats.size(), pHeaderStats))
            {
                file->unlock(false);
                return false;
            }

            file->unlock(false);
            offset = HeaderFile::MAX_COUNT - 1;
            --fileID;
            if(fileID == 0)
                break;
            file = HeaderFile::get(fileID, false);
            if(file == NULL)
            {
                if(HeaderFile::exists(fileID))
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
                      "Failed to get header file %08x", fileID);
                    return false;
                }
                else
                    return true;
            }
        }

        file->unlock(false);
        return true;

    }

    bool Header::add(unsigned int pHeight, const Header &pHeader)
    {
        HeaderFile *file = HeaderFile::get(HeaderFile::fileID(pHeight), true, true);
        if(file == NULL)
            return false;

        if(pHeight != 0)
        {
            if(file->itemCount() == 0)
            {
                // First header in file. Verify last hash of previous file.
                HeaderFile *previousFile = HeaderFile::get(HeaderFile::fileID(pHeight) - 1, false);
                if(previousFile == NULL)
                {
                    file->unlock(true);
                    return false;
                }

                if(previousFile->lastHash() != pHeader.previousHash)
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
                      "Header file %08x add header (%d) failed : Invalid previous hash : %s",
                      file->id(), pHeight, pHeader.previousHash.hex().text());
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
                      "Does not match last hash of previous block file : %s",
                      previousFile->lastHash().hex().text());
                    file->unlock(true);
                    previousFile->unlock(false);
                    return false;
                }

                previousFile->unlock(false);
            }
            else if(file->lastHash() != pHeader.previousHash)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
                  "Header file %08x add header (%d) failed : Invalid previous hash : %s",
                  file->id(), pHeight, pHeader.previousHash.hex().text());
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_HEADER_LOG_NAME,
                  "Does not match last hash of block file : %s", file->lastHash().hex().text());
                file->unlock(true);
                return false;
            }
        }

        bool success = file->writeHeader(pHeader);
        file->unlock(true);
        return success;
    }

    bool Header::revertToHeight(unsigned int pHeight)
    {
        unsigned int fileID = HeaderFile::fileID(pHeight);
        unsigned int fileOffset = HeaderFile::fileOffset(pHeight);

        // Truncate latest file
        if(fileOffset != HeaderFile::MAX_COUNT - 1)
        {
            HeaderFile *file = HeaderFile::get(fileID, true);
            if(file == NULL)
                return false;

            file->removeHeadersAbove(fileOffset);
            file->unlock(true);
            ++fileID;
        }

        // Remove any files after that
        while(true)
        {
            if(!HeaderFile::remove(fileID))
                return !HeaderFile::exists(fileID);

            ++fileID;
        }

        return true;
    }

    unsigned int Header::totalCount()
    {
        unsigned int result = 0;
        unsigned int fileID = 0;
        while(HeaderFile::exists(fileID))
        {
            result += HeaderFile::MAX_COUNT;
            ++fileID;
        }

        if(fileID > 0)
        {
            // Adjust for last file not being full.
            --fileID;
            result -= HeaderFile::MAX_COUNT;

            HeaderFile *file = HeaderFile::get(fileID, false);
            if(file != NULL)
            {
                result += file->itemCount();
                file->unlock(false);
            }
        }

        return result;
    }

    unsigned int Header::validate(bool &pAbort)
    {
        NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_HEADER_LOG_NAME,
          "Validating header files");

        unsigned int result = 0;
        unsigned int fileID = 0;
        HeaderFile *file;

        // Find top file ID.
        while(!pAbort && HeaderFile::exists(fileID))
            fileID += 50;

        if(pAbort)
            return 0;

        while(!pAbort && fileID > 0 && !HeaderFile::exists(fileID))
            --fileID;

        if(pAbort)
            return 0;

        result = fileID * HeaderFile::MAX_COUNT;

        // Adjust for last file not being full.
        while(!pAbort)
        {
            file = HeaderFile::get(fileID, false);
            if(file == NULL)
            {
                HeaderFile::remove(fileID);
                if(fileID == 0)
                    break;
                --fileID;
                result -= HeaderFile::MAX_COUNT;
            }
            else if(file->validate())
            {
                result += file->itemCount();
                file->unlock(false);
                break;
            }
            else
            {
                file->unlock(false);
                HeaderFile::remove(fileID);
                if(fileID == 0)
                    break;
                --fileID;
                result -= HeaderFile::MAX_COUNT;
            }
        }

        return result;
    }
}
