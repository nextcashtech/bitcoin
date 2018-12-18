/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "info.hpp"

#include "buffer.hpp"
#include "file_stream.hpp"
#include "network.hpp"
#include "log.hpp"
#include "digest.hpp"
#include "email.hpp"
#include "message.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <fstream>
#include <algorithm>

#define BITCOIN_INFO_LOG_NAME "Info"


namespace BitCoin
{
    void notify(const char *pSubject, const char *pMessage)
    {
        NextCash::String emailAddress = Info::instance().notifyEmail;
        if(!emailAddress)
            return;

        NextCash::Email::send(NULL, emailAddress, pSubject, pMessage);
    }

    Info *Info::sInstance = NULL;
    NextCash::MutexWithConstantName Info::sMutex("Info");
    NextCash::String Info::sPath;

    void Info::setPath(const char *pPath)
    {
        sMutex.lock();
        sPath = pPath;
        sMutex.unlock();
    }

    Info &Info::instance()
    {
        sMutex.lock();
        if(sInstance == NULL)
        {
            sInstance = new Info;
            std::atexit(destroy);
        }
        sMutex.unlock();

        return *sInstance;
    }

    void Info::destroy()
    {
        sMutex.lock();
        if(sInstance != NULL)
            delete sInstance;
        sInstance = NULL;
        sMutex.unlock();
    }

    Info::Info() : mPeerLock("Peer")
    {
        chainID = CHAIN_SV;

        uint8_t defaultIP[] = {127, 0, 0, 1};
        ip.set(NextCash::Network::IPAddress::IPV4, defaultIP, 8333);
#ifdef ANDROID
        spvMode = true;
#else
        spvMode = false;
#endif
        maxConnections = 64;
        mPeersModified = false;
        mPeersRead = false;
        pendingSize = 100000000UL; // 100 MB
        pendingBlocks = 256;
        outputsCacheSize = 1000000000UL; // 1 GB
        outputsCacheDelta = 500000000UL; // 500 MB
        minFee = 0; // satoshis per KB
        lowFee = 500; // satoshis per KB
        memPoolSize = 500000000UL; // 500 MB
        memPoolLowFeeSize = 32000000UL; // 32 MB
        addressesCacheSize = 500000000UL; // 500 MB
        merkleBlockCountRequired = 3;
        spvMemPoolCountRequired = 4;
        threadCount = 4;

        // Block height 540,288 (Jul 23, 2018 7:17:35 PM)
        approvedHash.setHex("000000000000000000cbcd34ba48ce30891af1e5b224de1a1a7eca8af24b05a6");

        mDataModified = false;
        mInitialBlockDownloadComplete = false;

        if(sPath)
        {
            NextCash::String configPath = sPath;
            configPath.pathAppend("config");
            NextCash::FileInputStream configFile(configPath);
            if(configFile.isValid())
                readSettingsFile(&configFile);
        }

        // Initialize random number generator for peer randomization.
        std::srand((unsigned int)std::time(0));
    }

    Info::~Info()
    {
        writeDataFile();
        writePeersFile();

        mPeerLock.writeLock("Destroy");
    }

    bool Info::load()
    {
        if(!readDataFile())
            return false;
        if(!readPeersFile())
            return false;
        return true;
    }

    void Info::save()
    {
        writeDataFile();
        writePeersFile();
    }

    void Info::applyValue(NextCash::Buffer &pName, NextCash::Buffer &pValue)
    {
        char *name = new char[pName.length()+1];
        pName.read(name, pName.length());
        name[pName.length()] = '\0';

        if(name[0] == '#')
        {
            // Commented line
            delete[] name;
            return;
        }

        char *value = new char[pValue.length()+1];
        pValue.read(value, pValue.length());
        value[pValue.length()] = '\0';

        if(std::strcmp(name, "spv_mode") == 0)
            spvMode = true;
        else if(std::strcmp(name, "chain_id") == 0)
        {
            if(std::strcmp(value, "ABC") == 0)
                configureChain(CHAIN_ABC);
            else if(std::strcmp(value, "SV") == 0)
                configureChain(CHAIN_SV);
        }
        else if(std::strcmp(name, "max_connections") == 0)
        {
            maxConnections = std::strtol(value, NULL, 0);
            if(maxConnections > 5000)
                maxConnections = 1;
            else if(maxConnections > 128)
                maxConnections = 128;
        }
        else if(std::strcmp(name, "fee_min") == 0)
        {
            minFee = std::strtol(value, NULL, 0);
            if(minFee < 0)
                minFee = 0;
            else if(minFee > 100000)
                minFee = 100000;
        }
        else if(std::strcmp(name, "fee_low") == 0)
        {
            lowFee = std::strtol(value, NULL, 0);
            if(lowFee < 1)
                lowFee = 1;
            else if(lowFee > 100000)
                lowFee = 100000;
        }
        else if(std::strcmp(name, "mem_pool_size") == 0)
            memPoolSize = std::strtol(value, NULL, 0);
        else if(std::strcmp(name, "mem_pool_low_size") == 0)
            memPoolLowFeeSize = std::strtol(value, NULL, 0);
        else if(std::strcmp(name, "ip") == 0)
            ip.setText(value);
        else if(std::strcmp(name, "port") == 0)
            ip.setPort(std::strtol(value, NULL, 0));
        else if(std::strcmp(name, "pending_size") == 0)
            pendingSize = std::strtol(value, NULL, 0);
        else if(std::strcmp(name, "pending_blocks") == 0)
            pendingBlocks = std::strtol(value, NULL, 0);
        else if(std::strcmp(name, "output_cache_size") == 0)
            outputsCacheSize = std::strtol(value, NULL, 0);
        else if(std::strcmp(name, "output_cache_delta") == 0)
            outputsCacheDelta = std::strtol(value, NULL, 0);
        else if(std::strcmp(name, "address_cache_size") == 0)
            addressesCacheSize = std::strtol(value, NULL, 0);
        else if(std::strcmp(name, "merkles_per_block") == 0)
            merkleBlockCountRequired = std::strtol(value, NULL, 0);
        else if(std::strcmp(name, "threads") == 0)
            threadCount = std::strtol(value, NULL, 0);
        else if(std::strcmp(name, "approved_hash") == 0)
        {
            NextCash::Hash newHash;
            newHash.setHex(value);
            if(newHash.size() == BLOCK_HASH_SIZE)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_INFO_LOG_NAME,
                  "Setting approved hash : %s", newHash.hex().text());
                approvedHash = newHash;
            }
        }
        else if(std::strcmp(name, "invalid_hash") == 0)
        {
            NextCash::Hash newHash;
            newHash.setHex(value);
            if(newHash.size() == BLOCK_HASH_SIZE)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_INFO_LOG_NAME,
                  "Adding invalid hash : %s", newHash.hex().text());
                invalidHashes.emplace_back(newHash);
            }
        }
        else if(std::strcmp(name, "notify_email") == 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_INFO_LOG_NAME,
              "Using notification email : %s", value);
            notifyEmail = value;
        }

        delete[] name;
        delete[] value;
    }

    void Info::readSettingsFile(NextCash::InputStream *pStream)
    {
        char newByte;
        bool equalFound = false;
        NextCash::Buffer name, value;

        while(pStream->remaining())
        {
            newByte = pStream->readByte();

            if(!equalFound && newByte == '=')
                equalFound = true;
            else if(newByte == '\n')
            {
                applyValue(name, value);
                equalFound = false;
                name.clear();
                value.clear();
            }
            else if(!equalFound)
                name.writeByte(newByte);
            else
                value.writeByte(newByte);
        }

        applyValue(name, value);
    }

    bool Info::readDataFile()
    {
        if(!sPath)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INFO_LOG_NAME,
              "No Path. Not reading data file.");
            return false;
        }

        NextCash::String dataFilePath = sPath;
        dataFilePath.pathAppend("data");

        if(!NextCash::fileExists(dataFilePath))
            return true;

        NextCash::FileInputStream file(dataFilePath);

        uint32_t version = file.readUnsignedInt();

        if(version != 1)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INFO_LOG_NAME,
              "Data file version %d not supported", version);
            return false;
        }

        mInitialBlockDownloadComplete = file.readByte() != 0;

        return true;
    }

    void Info::writeDataFile()
    {
        if(!mDataModified)
            return;

        if(!sPath)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INFO_LOG_NAME,
              "No Path. Not writing data file.");
            return;
        }

        // Write to temp file
        NextCash::String dataFileTempPath = sPath;
        dataFileTempPath.pathAppend("data.temp");
        NextCash::FileOutputStream file(dataFileTempPath, true);

        file.writeUnsignedInt(1); // Version

        // IBD Complete
        if(mInitialBlockDownloadComplete)
            file.writeByte(0x01);
        else
            file.writeByte(0x00);

        file.close();

        // Rename to actual file
        NextCash::String dataFilePath = sPath;
        dataFilePath.pathAppend("data");
        NextCash::renameFile(dataFileTempPath, dataFilePath);

        mDataModified = false;

        //NextCash::String dataFilePath = sPath;
        //dataFilePath.pathAppend("data");
        //NextCash::FileOutputStream file(dataFilePath, true);
    }

    void Info::writePeersFile()
    {
        if(!mPeersModified)
            return;

        if(!sPath)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INFO_LOG_NAME,
              "No Path. Not writing peers file.");
            return;
        }

        // Write to temp file
        NextCash::String dataFileTempPath = sPath;
        dataFileTempPath.pathAppend("peers.temp");
        NextCash::FileOutputStream file(dataFileTempPath, true);
        file.setOutputEndian(NextCash::Endian::LITTLE);

        // Version
        file.writeUnsignedInt(2);

        mPeerLock.readLock();
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INFO_LOG_NAME,
          "Writing peers file with %d peers", mPeers.size());
        for(NextCash::SortedSet::Iterator peer = mPeers.begin(); peer != mPeers.end(); ++peer)
        {
            try
            {
                dynamic_cast<const Peer *>(*peer)->write(&file);
            }
            catch(...)
            {
            }
        }
        mPeerLock.readUnlock();

        file.close();

        // Rename to actual file
        NextCash::String dataFilePath = sPath;
        dataFilePath.pathAppend("peers");
        NextCash::renameFile(dataFileTempPath, dataFilePath);

        mPeersModified = false;
    }

    bool Info::readPeersFile()
    {
        if(!sPath)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INFO_LOG_NAME,
              "No path to read peers file");
            return false;
        }

        NextCash::String dataFilePath = sPath;
        dataFilePath.pathAppend("peers");
        NextCash::FileInputStream file(dataFilePath);
        file.setInputEndian(NextCash::Endian::LITTLE);

        if(!file.isValid())
            return true;

        mPeerLock.writeLock("Load");
        mPeers.clear();

        // Check for start string at beginning of file.
        // If the file starts with a start string then it is version 1.
        // If it doesn't then it starts with a version number.
        static const char *match = Peer::START_STRING;
        bool matchFound = false;
        unsigned int matchOffset = 0;
        unsigned int version;
        for(unsigned int i = 0; i < 4; ++i)
        {
            if(file.readByte() == match[matchOffset])
            {
                ++matchOffset;
                if(matchOffset == 4)
                {
                    matchFound = true;
                    break;
                }
            }
            else
                break;
        }

        if(matchFound)
            version = 1;
        else
        {
            file.setReadOffset(0);
            version = file.readUnsignedInt();
        }

        Peer *newPeer;
        while(file.remaining())
        {
            newPeer = new Peer();
            if(!newPeer->read(&file, version))
            {
                delete newPeer;
                break;
            }
            else if(!mPeers.insert(newPeer))
                delete newPeer;
        }

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INFO_LOG_NAME,
          "Read peers file with %d peers", mPeers.size());
        mPeersRead = true;
        mPeerLock.writeUnlock();
        return true;
    }

    void Info::configureChain(ChainID pChainID)
    {
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_INFO_LOG_NAME,
          "Configuring for chain %s", chainName(pChainID));

        NextCash::Hash desiredHash, invalidHash;
        switch(pChainID)
        {
            case CHAIN_ABC:
                desiredHash = ABC_SPLIT_HASH;
                invalidHash = SV_SPLIT_HASH;
                break;
            case CHAIN_SV:
                desiredHash = SV_SPLIT_HASH;
                invalidHash = ABC_SPLIT_HASH;
                break;
            default:
                chainID = pChainID;
                return;
        }

        chainID = pChainID;

        // Remove desired hash from invalid hashes.
        invalidHashes.remove(desiredHash);

        // Add invalid hash to invalid hashes.
        if(!invalidHashes.contains(invalidHash))
            invalidHashes.emplace_back(invalidHash);
    }

    void Info::getRandomizedPeers(std::vector<Peer *> &pPeers, int pMinimumRating,
      uint64_t mServicesRequiredMask, ChainID pChainID, int pMaximumRating)
    {
        pPeers.clear();

        // For scenario when path was not set before loading instance
        if(!mPeersRead)
            readPeersFile();

        mPeerLock.readLock();
        Peer *peer;
        for(NextCash::SortedSet::Iterator iter = mPeers.begin(); iter != mPeers.end(); ++iter)
        {
            try
            {
                peer = dynamic_cast<Peer *>(*iter);
                if(peer->rating >= pMinimumRating && peer->rating <= pMaximumRating &&
                  (peer->services & mServicesRequiredMask) == mServicesRequiredMask &&
                  (pChainID == CHAIN_UNKNOWN || peer->chainID == pChainID))
                    pPeers.push_back(peer);
            }
            catch(...)
            {
            }

        }
        mPeerLock.readUnlock();

        // Sort Randomly
        std::random_shuffle(pPeers.begin(), pPeers.end());
    }

    void Info::addPeerFail(const NextCash::Network::IPAddress &pAddress, int pCount, int pMinimum)
    {
        if(!pAddress.isValid())
            return;

        // For scenario when path was not set before loading instance
        if(!mPeersRead)
            readPeersFile();

        //bool remove = false;
        mPeerLock.readLock();
        Peer lookup;
        lookup.address = pAddress;
        try
        {
            Peer *peer = dynamic_cast<Peer *>(mPeers.get(lookup));
            if(peer != NULL)
            {
                // Update
                if(peer->rating > pMinimum)
                {
                    peer->rating -= pCount;
                    if(peer->rating < pMinimum)
                        peer->rating = pMinimum;
                }
                peer->updateTime();
                // if((*peer)->rating < 0)
                    // remove = true;
                mPeersModified = true;
            }
        }
        catch(...)
        {
        }
        mPeerLock.readUnlock();

        // if(remove)
        // {
            // mPeerLock.writeLock("Remove");
            // for(std::list<Peer *>::iterator peer=mPeers.begin();peer!=mPeers.end();++peer)
                // if((*peer)->address.matches(pAddress))
                // {
                    // mPeers.erase(peer);
                    // NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_INFO_LOG_NAME, "Removed peer");
                    // break;
                // }
            // mPeerLock.writeUnlock();
        // }
    }

    void Info::markPeerChain(const NextCash::Network::IPAddress &pAddress, ChainID pChainID)
    {
        if(!pAddress.isValid())
            return;

        // For scenario when path was not set before loading instance
        if(!mPeersRead)
            readPeersFile();

        mPeerLock.readLock();
        Peer lookup;
        lookup.address = pAddress;
        try
        {
            Peer *peer = dynamic_cast<Peer *>(mPeers.get(lookup));
            if(peer != NULL)
            {
                // Update
                peer->updateTime();
                if(peer->chainID != pChainID)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INFO_LOG_NAME,
                      "Peer marked for chain %s : %s", chainName(pChainID), pAddress.text().text());
                    peer->chainID = pChainID;
                    mPeersModified = true;
                }
            }
            else
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INFO_LOG_NAME,
                  "Peer not found to mark chain %s : %s", chainName(pChainID), pAddress.text().text());
        }
        catch(...)
        {
        }
        mPeerLock.readUnlock();
    }

    void Info::updatePeer(const NextCash::Network::IPAddress &pAddress, const char *pUserAgent,
      uint64_t pServices)
    {
        if(!pAddress.isValid() || (pUserAgent != NULL && std::strlen(pUserAgent) > 256) ||
          pServices == 0)
            return;

        // For scenario when path was not set before loading instance
        if(!mPeersRead)
            readPeersFile();

        mPeerLock.readLock();
        Peer lookup;
        lookup.address = pAddress;
        try
        {
            Peer *peer = dynamic_cast<Peer *>(mPeers.get(lookup));
            if(peer != NULL)
            {
                // Update
                peer->updateTime();
                peer->services = pServices;
                if(pUserAgent != NULL)
                    peer->userAgent = pUserAgent;
                peer->rating += 5;
                mPeersModified = true;
            }
        }
        catch(...)
        {
        }
        mPeerLock.readUnlock();
    }

    void Info::addPeerSuccess(const NextCash::Network::IPAddress &pAddress, int pCount)
    {
        if(!pAddress.isValid())
            return;

        // For scenario when path was not set before loading instance
        if(!mPeersRead)
            readPeersFile();

        mPeerLock.readLock();
        Peer lookup;
        lookup.address = pAddress;
        try
        {
            Peer *peer = dynamic_cast<Peer *>(mPeers.get(lookup));
            if(peer != NULL)
            {
                // Update existing
                // Update existing
                peer->updateTime();
                peer->rating += 5;
                mPeersModified = true;
            }
        }
        catch(...)
        {
        }
        mPeerLock.readUnlock();
    }

    bool Info::addPeer(const NextCash::Network::IPAddress &pAddress, uint64_t pServices)
    {
        if(!pAddress.isValid() || (pServices & Message::VersionData::FULL_NODE_BIT) == 0)
            return false;

        // For scenario when path was not set before loading instance
        if(!mPeersRead)
            readPeersFile();

        // Add new
        bool result = true;
        Peer *newPeer = new Peer;
        newPeer->rating = 0;
        newPeer->updateTime();
        newPeer->address = pAddress;
        newPeer->services = pServices;

        mPeerLock.writeLock("Add");
        if(mPeers.insert(newPeer))
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INFO_LOG_NAME,
              "Added new peer %s", pAddress.text().text());
            mPeersModified = true;
        }
        else
        {
            delete newPeer;
            result = false;
        }
        mPeerLock.writeUnlock();
        return result;
    }

    void Info::resetPeers()
    {
        mPeerLock.writeLock("Reset");
        mPeers.clear();
        mPeerLock.writeUnlock();
        writePeersFile();
    }

    bool Info::test()
    {
        bool success = true;

        return success;
    }
}
