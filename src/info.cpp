/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "info.hpp"

#include "arcmist/io/buffer.hpp"
#include "arcmist/io/file_stream.hpp"
#include "arcmist/io/network.hpp"
#include "arcmist/base/log.hpp"
#include "arcmist/crypto/digest.hpp"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <algorithm>

#define BITCOIN_INFO_LOG_NAME "BitCoin Info"


namespace BitCoin
{
    void Peer::write(ArcMist::OutputStream *pStream) const
    {
        // Validation Header
        pStream->writeString("AMPR");

        // User Agent Bytes
        writeCompactInteger(pStream, userAgent.length());

        // User Agent
        pStream->writeString(userAgent);

        // Rating
        pStream->writeInt(rating);

        // Time
        pStream->writeUnsignedInt(time);

        // Services
        pStream->writeUnsignedLong(services);

        // Address
        address.write(pStream);
    }

    bool Peer::read(ArcMist::InputStream *pStream)
    {
        const char *match = "AMPR";
        bool matchFound = false;
        unsigned int matchOffset = 0;

        // Search for start string
        while(pStream->remaining())
        {
            if(pStream->readByte() == match[matchOffset])
            {
                matchOffset++;
                if(matchOffset == 4)
                {
                    matchFound = true;
                    break;
                }
            }
            else
                matchOffset = 0;
        }

        if(!matchFound)
            return NULL;

        // User Agent Bytes
        uint64_t userAgentLength = readCompactInteger(pStream);

        if(userAgentLength > 256)
            return false;

        // User Agent
        userAgent = pStream->readString(userAgentLength);

        // Rating
        rating = pStream->readInt();

        // Time
        time = pStream->readUnsignedInt();

        // Services
        services = pStream->readUnsignedLong();

        // Address
        return address.read(pStream);
    }

    Info *Info::sInstance = 0;
    ArcMist::String Info::sPath;

    void Info::setPath(const char *pPath)
    {
        sPath = pPath;
    }

    Info &Info::instance()
    {
        if(!sInstance)
        {
            sInstance = new Info;
            std::atexit(destroy);
        }

        return *Info::sInstance;
    }

    void Info::destroy()
    {
        delete Info::sInstance;
        Info::sInstance = 0;
    }

    Info::Info() : mPeerLock("Peer")
    {
        ip = 0;
        port = 8333;
        fullMode = false;
        maxConnections = 64;
        minFee = 1000; // satoshis per KiB
        mPeersModified = false;
        pendingSizeThreshold = 104857600; // 100 MiB
        pendingBlocksThreshold = 256;
        outputsThreshold = 536870912; // 512 MiB
        outputsCacheAge = 5000;

        if(sPath)
        {
            ArcMist::String configFilePath = sPath;
            configFilePath.pathAppend("config");
            readSettingsFile(configFilePath);

            ArcMist::String dataFilePath = sPath;
            dataFilePath.pathAppend("data");
            readSettingsFile(dataFilePath);
        }

        readPeersFile();
    }

    Info::~Info()
    {
        writeDataFile();
        writePeersFile();

        if(ip != 0)
            delete[] ip;

        mPeerLock.writeLock("Destroy");
        for(std::list<Peer *>::iterator i=mPeers.begin();i!=mPeers.end();++i)
            delete *i;
        mPeerLock.writeUnlock();
    }

    void Info::save()
    {
        writeDataFile();
        writePeersFile();
    }

    void Info::applyValue(ArcMist::Buffer &pName, ArcMist::Buffer &pValue)
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

        if(std::strcmp(name, "full_mode") == 0)
            fullMode = true;
        else if(std::strcmp(name, "max_connections") == 0)
        {
            maxConnections = std::stol(value, NULL, 0);
            if(maxConnections < 0)
                maxConnections = 1;
            else if(maxConnections > 128)
                maxConnections = 128;
        }
        else if(std::strcmp(name, "fee_min") == 0)
        {
            minFee = std::stol(value, NULL, 0);
            if(minFee < 1)
                minFee = 1;
            else if(minFee > 100000)
                minFee = 100000;
        }
        else if(std::strcmp(name, "ip") == 0)
            ip = ArcMist::Network::parseIPv6(value);
        else if(std::strcmp(name, "port") == 0)
            port = std::stol(value, NULL, 0);
        else if(std::strcmp(name, "pending_size") == 0)
            pendingSizeThreshold = std::stol(value, NULL, 0);
        else if(std::strcmp(name, "pending_blocks") == 0)
            pendingBlocksThreshold = std::stol(value, NULL, 0);
        else if(std::strcmp(name, "output_threshold") == 0)
            outputsThreshold = std::stol(value, NULL, 0);
        else if(std::strcmp(name, "output_cache_age") == 0)
            outputsCacheAge = std::stol(value, NULL, 0);

        delete[] name;
        delete[] value;
    }

    void Info::readSettingsFile(const char *pPath)
    {
        ArcMist::FileInputStream file(pPath);

        char newByte;
        bool equalFound = false;
        ArcMist::Buffer name, value;

        while(file.remaining())
        {
            newByte = file.readByte();

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

    void Info::writeDataFile()
    {
        if(!sPath)
            return;

        //ArcMist::String dataFilePath = sPath;
        //dataFilePath.pathAppend("data");
        //ArcMist::FileOutputStream file(dataFilePath, true);
    }

    void Info::writePeersFile()
    {
        if(!mPeersModified)
            return;

        if(!sPath)
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INFO_LOG_NAME, "No Path. Not writing peers file.");
            return;
        }

        ArcMist::String dataFilePath = sPath;
        dataFilePath.pathAppend("peers");
        ArcMist::FileOutputStream file(dataFilePath, true);
        file.setOutputEndian(ArcMist::Endian::LITTLE);

        mPeerLock.readLock();
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_INFO_LOG_NAME, "Writing peers file with %d peers", mPeers.size());
        for(std::list<Peer *>::iterator i=mPeers.begin();i!=mPeers.end();++i)
            (*i)->write(&file);
        mPeerLock.readUnlock();

        mPeersModified = false;
    }

    void Info::readPeersFile()
    {
        if(!sPath)
            return;

        ArcMist::String dataFilePath = sPath;
        dataFilePath.pathAppend("peers");
        ArcMist::FileInputStream file(dataFilePath);
        file.setInputEndian(ArcMist::Endian::LITTLE);

        mPeerLock.writeLock("Load");
        for(std::list<Peer *>::iterator i=mPeers.begin();i!=mPeers.end();++i)
            delete (*i);
        mPeers.clear();

        Peer *newPeer;
        while(file.remaining())
        {
            newPeer = new Peer();
            if(newPeer->read(&file))
                mPeers.push_back(newPeer);
        }

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_INFO_LOG_NAME, "Read peers file with %d peers", mPeers.size());
        mPeerLock.writeUnlock();
    }

    void Info::getRandomizedPeers(std::vector<Peer *> &pPeers, int pMinimumRating)
    {
        pPeers.clear();

        mPeerLock.readLock();
        for(std::list<Peer *>::iterator peer=mPeers.begin();peer!=mPeers.end();++peer)
            if((*peer)->rating >= pMinimumRating)
                pPeers.push_back(*peer);
        mPeerLock.readUnlock();

        // Sort Randomly
        std::random_shuffle(pPeers.begin(), pPeers.end());
    }

    void Info::addPeerFail(const IPAddress &pAddress, int pCount)
    {
        if(!pAddress.isValid())
            return;

        //bool remove = false;
        mPeerLock.readLock();
        for(std::list<Peer *>::iterator peer=mPeers.begin();peer!=mPeers.end();++peer)
            if((*peer)->address.matches(pAddress))
            {
                // Update
                (*peer)->rating -= pCount;
                (*peer)->updateTime();
                // if((*peer)->rating < 0)
                    // remove = true;
                mPeersModified = true;
                break;
            }
        mPeerLock.readUnlock();

        // if(remove)
        // {
            // mPeerLock.writeLock("Remove");
            // for(std::list<Peer *>::iterator peer=mPeers.begin();peer!=mPeers.end();++peer)
                // if((*peer)->address.matches(pAddress))
                // {
                    // mPeers.erase(peer);
                    // ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_INFO_LOG_NAME, "Removed peer");
                    // break;
                // }
            // mPeerLock.writeUnlock();
        // }
    }

    void Info::updatePeer(const IPAddress &pAddress, const char *pUserAgent, uint64_t pServices)
    {
        if(!pAddress.isValid() || (pUserAgent != NULL && std::strlen(pUserAgent) > 256) || pServices == 0)
            return;

        mPeerLock.readLock();
        for(std::list<Peer *>::iterator peer=mPeers.begin();peer!=mPeers.end();++peer)
        {
            if((*peer)->address.matches(pAddress))
            {
                // Update existing
                (*peer)->updateTime();
                (*peer)->services = pServices;
                (*peer)->userAgent = pUserAgent;
                (*peer)->address = pAddress;
                (*peer)->rating++;
                mPeersModified = true;
                mPeerLock.readUnlock();
                return;
            }
        }
        mPeerLock.readUnlock();

        mPeerLock.writeLock("Add");
        // Add new
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_INFO_LOG_NAME, "Adding new peer");
        Peer *newPeer = new Peer;
        newPeer->userAgent = pUserAgent;
        if(pUserAgent != NULL)
            newPeer->rating = 1;
        newPeer->updateTime();
        newPeer->address = pAddress;
        newPeer->services = pServices;
        mPeers.push_front(newPeer);
        mPeersModified = true;
        mPeerLock.writeUnlock();
    }

    bool Info::test()
    {
        bool success = true;

        return success;
    }
}
