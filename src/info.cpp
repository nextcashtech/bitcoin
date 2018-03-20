/**************************************************************************
 * Copyright 2017 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "info.hpp"

#include "nextcash/io/buffer.hpp"
#include "nextcash/io/file_stream.hpp"
#include "nextcash/io/network.hpp"
#include "nextcash/base/log.hpp"
#include "nextcash/crypto/digest.hpp"
#include "nextcash/io/email.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
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

    void Peer::write(NextCash::OutputStream *pStream) const
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

    bool Peer::read(NextCash::InputStream *pStream)
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
    NextCash::String Info::sPath;

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
        spvMode = false;
        maxConnections = 64;
        minFee = 1000; // satoshis per KiB
        mPeersModified = false;
        pendingSizeThreshold = 104857600; // 100 MiB
        pendingBlocksThreshold = 256;
        outputsThreshold = 1073741824; // 1 GiB
        memPoolThreshold = 536870912; // 512 MiB
        addressesThreshold = 268435456; // 256 MiB
        merkleBlockCountRequired = 4;
        spvMemPoolCountRequired = 4;

        if(sPath)
        {
            NextCash::String configFilePath = sPath;
            configFilePath.pathAppend("config");
            readSettingsFile(configFilePath);

            NextCash::String dataFilePath = sPath;
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
            ip = NextCash::Network::parseIPv6(value);
        else if(std::strcmp(name, "port") == 0)
            port = std::stol(value, NULL, 0);
        else if(std::strcmp(name, "pending_size") == 0)
            pendingSizeThreshold = std::stol(value, NULL, 0);
        else if(std::strcmp(name, "pending_blocks") == 0)
            pendingBlocksThreshold = std::stol(value, NULL, 0);
        else if(std::strcmp(name, "output_threshold") == 0)
            outputsThreshold = std::stol(value, NULL, 0);
        else if(std::strcmp(name, "mem_pool_size") == 0)
            memPoolThreshold = std::stol(value, NULL, 0);
        else if(std::strcmp(name, "address_threshold") == 0)
            addressesThreshold = std::stol(value, NULL, 0);
        else if(std::strcmp(name, "notify_email") == 0)
            notifyEmail = value;

        delete[] name;
        delete[] value;
    }

    void Info::readSettingsFile(const char *pPath)
    {
        NextCash::FileInputStream file(pPath);

        char newByte;
        bool equalFound = false;
        NextCash::Buffer name, value;

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
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INFO_LOG_NAME, "No Path. Not writing peers file.");
            return;
        }

        NextCash::String dataFilePath = sPath;
        dataFilePath.pathAppend("peers");
        NextCash::FileOutputStream file(dataFilePath, true);
        file.setOutputEndian(NextCash::Endian::LITTLE);

        mPeerLock.readLock();
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INFO_LOG_NAME, "Writing peers file with %d peers", mPeers.size());
        for(std::list<Peer *>::iterator i=mPeers.begin();i!=mPeers.end();++i)
            (*i)->write(&file);
        mPeerLock.readUnlock();

        mPeersModified = false;
    }

    void Info::readPeersFile()
    {
        if(!sPath)
            return;

        NextCash::String dataFilePath = sPath;
        dataFilePath.pathAppend("peers");
        NextCash::FileInputStream file(dataFilePath);
        file.setInputEndian(NextCash::Endian::LITTLE);

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

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INFO_LOG_NAME, "Read peers file with %d peers", mPeers.size());
        mPeerLock.writeUnlock();
    }

    void Info::getRandomizedPeers(std::vector<Peer *> &pPeers, int pMinimumRating, uint64_t mServicesRequiredMask)
    {
        pPeers.clear();

        mPeerLock.readLock();
        for(std::list<Peer *>::iterator peer=mPeers.begin();peer!=mPeers.end();++peer)
            if((*peer)->rating >= pMinimumRating && ((*peer)->services & mServicesRequiredMask) == mServicesRequiredMask)
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
                    // NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_INFO_LOG_NAME, "Removed peer");
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
        NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_INFO_LOG_NAME, "Adding new peer");
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
