#include "info.hpp"

#include "arcmist/io/buffer.hpp"
#include "arcmist/io/file_stream.hpp"
#include "arcmist/io/network.hpp"
#include "arcmist/base/log.hpp"
#include "arcmist/crypto/digest.hpp"
#include "events.hpp"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <algorithm>

#define BITCOIN_INFO_LOG_NAME "BitCoin Info"


namespace BitCoin
{
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

    Info::Info() : mPeerMutex("Peer")
    {
        ip = 0;
        port = 8333;
        fullMode = false;
        maxConnections = 32;
        minFee = 1; // satoshis per KiB
        mPeersModified = false;

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

        mPeerMutex.lock();
        for(std::list<Peer *>::iterator i=mPeers.begin();i!=mPeers.end();++i)
            delete *i;
        mPeerMutex.unlock();
    }

    void Info::save()
    {
        writeDataFile();
        writePeersFile();
        Events::instance().post(Event::INFO_SAVED);
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
        else if(std::strcmp(name, "peers_max") == 0)
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

        mPeerMutex.lock();
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_INFO_LOG_NAME, "Writing peers file with %d peers", mPeers.size());
        for(std::list<Peer *>::iterator i=mPeers.begin();i!=mPeers.end();++i)
            (*i)->write(&file);
        mPeerMutex.unlock();

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

        mPeerMutex.lock();
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
        mPeerMutex.unlock();
    }

    void Info::randomizePeers(std::vector<Peer *> &pPeers, int pMinimumRating)
    {
        pPeers.clear();

        mPeerMutex.lock();
        for(std::list<Peer *>::iterator peer=mPeers.begin();peer!=mPeers.end();++peer)
            if((*peer)->rating >= pMinimumRating)
                pPeers.push_back(*peer);
        mPeerMutex.unlock();

        // Sort Randomly
        std::random_shuffle(pPeers.begin(), pPeers.end());
    }

    void Info::addPeerFail(const IPAddress &pAddress)
    {
        if(!pAddress.isValid())
            return;

        mPeerMutex.lock();
        for(std::list<Peer *>::iterator peer=mPeers.begin();peer!=mPeers.end();++peer)
        {
            if((*peer)->address.matches(pAddress))
            {
                // Update
                (*peer)->rating--;
                if((*peer)->rating < -5)
                {
                    ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_INFO_LOG_NAME, "Removed peer");
                    mPeers.erase(peer);
                }
                mPeersModified = true;
                break;
            }
        }
        mPeerMutex.unlock();
    }

    void Info::updatePeer(const IPAddress &pAddress, const char *pUserAgent)
    {
        if(!pAddress.isValid() || (pUserAgent != NULL && std::strlen(pUserAgent) > 256) || !pAddress.services)
            return;

        mPeerMutex.lock();
        for(std::list<Peer *>::iterator peer=mPeers.begin();peer!=mPeers.end();++peer)
        {
            if((*peer)->address.matches(pAddress))
            {
                // Update existing
                (*peer)->userAgent = pUserAgent;
                (*peer)->address = pAddress;
                (*peer)->rating++;
                mPeersModified = true;
                mPeerMutex.unlock();
                return;
            }
        }

        // Add new
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_INFO_LOG_NAME, "Adding new peer");
        Peer *newPeer = new Peer;
        newPeer->userAgent = pUserAgent;
        if(pUserAgent == NULL)
            newPeer->rating = -5;
        newPeer->address = pAddress;
        mPeers.push_front(newPeer);
        mPeersModified = true;
        mPeerMutex.unlock();
    }

    bool Info::test()
    {
        bool success = true;

        return success;
    }
}
