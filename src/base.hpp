/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_BASE_HPP
#define BITCOIN_BASE_HPP

#include "arcmist/io/stream.hpp"
#include "arcmist/io/network.hpp"

#include <cstdint>
#include <ctime>

#define BITCOIN_USER_AGENT "/ArcMist 0.0.1/"
#define PROTOCOL_VERSION 70015


namespace BitCoin
{
    enum Network { MAINNET, TESTNET };

    Network network();
    void setNetwork(Network pNetwork);

    // Seconds since epoch
    inline int32_t getTime()
    {
        return std::time(NULL);
    }

    inline double bitcoins(int64_t pSatoshis)
    {
        return (double)pSatoshis / 100000000;
    }

    // Transaction functionality codes
    static const int32_t BLOCK_VERSION_2_ACTIVE     = 0x00000004;
    static const int32_t REQUIRE_BLOCK_VERSION_2    = 0x00000008;
    static const int32_t BLOCK_VERSION_4_ACTIVE     = 0x00000010;
    static const int32_t REQUIRE_BLOCK_VERSION_4    = 0x00000011;
    static const int32_t CHECKLOCKTIMEVERIFY_ACTIVE = 0x00000012;
    static const int32_t CHECKSEQUENCEVERIFY_ACTIVE = 0x00000014;

    const char *networkName();
    const char *networkStartString();
    const uint8_t *networkStartBytes();
    const char *networkPortString();
    uint16_t networkPort();

    class IPAddress
    {
    public:

        IPAddress()
        {
            std::memset(ip, 0, 16);
            port = 0;
        }
        IPAddress(const IPAddress &pCopy)
        {
            std::memcpy(ip, pCopy.ip, 16);
            port = pCopy.port;
        }

        void write(ArcMist::OutputStream *pStream) const;
        bool read(ArcMist::InputStream *pStream);

        bool matches(const IPAddress &pOther) const { return std::memcmp(ip, pOther.ip, 16) == 0 && port == pOther.port; }

        bool operator == (const IPAddress &pRight) const
        {
            return std::memcmp(ip, pRight.ip, 16) == 0 && port == pRight.port;
        }

        bool operator != (const IPAddress &pRight) const
        {
            return std::memcmp(ip, pRight.ip, 16) != 0 || port != pRight.port;
        }

        void operator = (ArcMist::Network::Connection &pConnection)
        {
            if(pConnection.ipv6Bytes())
                std::memcpy(ip, pConnection.ipv6Bytes(), 16);
            port = pConnection.port();
        }

        bool isValid() const
        {
            bool zeroes = true;
            for(int i=0;i<16;i++)
                if(ip[i] != 0)
                    zeroes = false;
            return !zeroes;
        }

        const IPAddress &operator = (const IPAddress &pRight)
        {
            port = pRight.port;
            std::memcpy(ip, pRight.ip, 16);
            return *this;
        }

        uint8_t ip[16];
        uint16_t port;
    };

    class Peer
    {
    public:

        Peer() { rating = 0; }
        Peer(const Peer &pCopy)
        {
            time = pCopy.time;
            services = pCopy.services;
            userAgent = pCopy.userAgent;
            rating = pCopy.rating;
            address = pCopy.address;
        }

        void write(ArcMist::OutputStream *pStream) const;
        bool read(ArcMist::InputStream *pStream);

        void updateTime() { time = getTime(); }

        Peer &operator = (const Peer &pRight)
        {
            time = pRight.time;
            services = pRight.services;
            userAgent = pRight.userAgent;
            rating = pRight.rating;
            address = pRight.address;
            return *this;
        }

        uint32_t time;
        uint64_t services;
        ArcMist::String userAgent;
        int32_t rating;
        IPAddress address;
    };

    class Statistics
    {
    public:
        Statistics()
        {
            startTime = getTime();
            bytesReceived = 0;
            bytesSent = 0;
            headersReceived = 0;
            headersSent = 0;
            blocksReceived = 0;
            blocksSent = 0;
            incomingConnections = 0;
            outgoingConnections = 0;
        }

        void clear()
        {
            startTime = getTime();
            bytesReceived = 0;
            bytesSent = 0;
            headersReceived = 0;
            headersSent = 0;
            blocksReceived = 0;
            blocksSent = 0;
            incomingConnections = 0;
            outgoingConnections = 0;
        }

        void operator += (Statistics &pRight)
        {
            bytesReceived += pRight.bytesReceived;
            bytesSent += pRight.bytesSent;
            headersReceived += pRight.headersReceived;
            headersSent += pRight.headersSent;
            blocksReceived += pRight.blocksReceived;
            blocksSent += pRight.blocksSent;
            incomingConnections += pRight.incomingConnections;
            outgoingConnections += pRight.outgoingConnections;
        }

        void write(ArcMist::OutputStream *pStream) const
        {
            pStream->writeString("AMST");
            pStream->writeByte(1); // Version
            pStream->writeUnsignedInt(startTime);
            pStream->writeUnsignedInt(bytesReceived);
            pStream->writeUnsignedInt(bytesSent);
            pStream->writeUnsignedInt(headersReceived);
            pStream->writeUnsignedInt(headersSent);
            pStream->writeUnsignedInt(blocksReceived);
            pStream->writeUnsignedInt(blocksSent);
            pStream->writeUnsignedInt(incomingConnections);
            pStream->writeUnsignedInt(outgoingConnections);
        }

        bool read(ArcMist::InputStream *pStream)
        {
            ArcMist::String startString = pStream->readString(4);
            if(startString != "AMST")
                return false;

            uint8_t version = pStream->readByte(); // Version
            if(version != 1)
                return false;

            if(pStream->remaining() < 36)
                return false;

            startTime = pStream->readUnsignedInt();
            bytesReceived = pStream->readUnsignedInt();
            bytesSent = pStream->readUnsignedInt();
            headersReceived = pStream->readUnsignedInt();
            headersSent = pStream->readUnsignedInt();
            blocksReceived = pStream->readUnsignedInt();
            blocksSent = pStream->readUnsignedInt();
            incomingConnections = pStream->readUnsignedInt();
            outgoingConnections = pStream->readUnsignedInt();

            return true;
        }

        unsigned int startTime;
        unsigned int bytesReceived;
        unsigned int bytesSent;
        unsigned int headersReceived;
        unsigned int headersSent;
        unsigned int blocksReceived;
        unsigned int blocksSent;
        unsigned int incomingConnections;
        unsigned int outgoingConnections;

    private:
        Statistics(const Statistics &pCopy);
        Statistics &operator = (const Statistics &pRight);

    };

    class Hash : public ArcMist::RawOutputStream // So ArcMist::Digest can write results to it
    {
    public:

        Hash() { mSize = 0; mData = NULL; }
        Hash(unsigned int pSize) { mSize = pSize; mData = new uint8_t[mSize]; zeroize(); }
        Hash(const Hash &pCopy) { mData = NULL; *this = pCopy; }
        ~Hash() { if(mData != NULL) delete[] mData; }

        unsigned int size() const { return mSize; }
        const uint8_t *value() const { return mData; }

        // Little endian (lease significant bytes first)
        ArcMist::String hex() const
        {
            ArcMist::String result;
            if(mSize == 0)
                return result;
            result.writeHex(mData, mSize);
            return result;
        }

        // Big endian (most significant bytes first, i.e. leading zeroes for block hashes)
        ArcMist::String bigHex() const
        {
            ArcMist::String result;
            if(mSize == 0)
                return result;
            uint8_t reverse[mSize];
            unsigned int i = mSize - 1;
            for(unsigned int j=0;j<mSize;j++)
                reverse[i--] = mData[j];
            result.writeHex(reverse, mSize);
            return result;
        }

        void setSize(unsigned int pSize)
        {
            if(mSize == pSize)
                return;
            if(mData != NULL)
                delete[] mData;
            mSize = pSize;
            if(mSize == 0)
                mData = NULL;
            else
            {
                mData = new uint8_t[mSize];
                zeroize();
            }
        }

        // Difficulty checks
        void setDifficulty(uint32_t pBits);
        bool operator <= (const Hash &pRight);

        // Set to zero size. Makes hash "empty"
        void clear() { setSize(0); }

        bool isEmpty() const { return mSize == 0; }

        bool isZero() const
        {
            if(mSize == 0)
                return false; // Empty is not zero
            for(unsigned int i=0;i<mSize;i++)
                if(mData[i] != 0)
                    return false;
            return true;
        }

        uint16_t lookup() const; // Used to split into 65,536 piles
        uint8_t lookup8() const; // Used to split into 256 piles

        void zeroize()
        {
            if(mSize > 0)
                std::memset(mData, 0, mSize);
        }

        void randomize()
        {
            uint32_t random;
            for(unsigned int i=0;i<mSize;i+=4)
            {
                random = ArcMist::Math::randomInt();
                std::memcpy(mData + i, &random, 4);
            }
        }

        bool operator == (const Hash &pRight) const
        {
            if(mSize != pRight.mSize)
                return false;

            if(mSize == 0)
                return true;

            return std::memcmp(mData, pRight.mData, mSize) == 0;
        }

        bool operator != (const Hash &pRight) const
        {
            if(mSize != pRight.mSize)
                return true;

            if(mSize == 0)
                return false;

            return std::memcmp(mData, pRight.mData, mSize) != 0;
        }

        const Hash &operator = (const Hash &pRight)
        {
            if(mData != NULL)
                delete[] mData;
            mSize = pRight.mSize;
            if(mSize > 0)
            {
                mData = new uint8_t[mSize];
                std::memcpy(mData, pRight.mData, mSize);
            }
            else
                mData = NULL;

            return *this;
        }

        void write(ArcMist::OutputStream *pStream) const
        {
            if(mSize == 0)
                return;

            pStream->write(mData, mSize);
        }

        bool read(ArcMist::InputStream *pStream)
        {
            if(mSize == 0)
                return true;

            if(pStream->remaining() < mSize)
                return false;

            pStream->read(mData, mSize);
            return true;
        }

        bool read(ArcMist::InputStream *pStream, unsigned int pSize)
        {
            setSize(pSize);
            return read(pStream);
        }

        // ArcMist::RawOutputStream virtual
        void write(const void *pInput, unsigned int pSize)
        {
            setSize(pSize);
            std::memcpy(mData, pInput, pSize);
        }

    private:

        unsigned int mSize;
        uint8_t *mData;

    };

    class HashList : public std::vector<Hash *>
    {
    public:
        HashList() {}
        ~HashList()
        {
            for(iterator hash=begin();hash!=end();++hash)
                delete *hash;
        }

        void clear()
        {
            for(iterator hash=begin();hash!=end();++hash)
                delete *hash;
            std::vector<Hash *>::clear();
        }

    private:
        HashList(HashList &pCopy);
        HashList &operator = (HashList &pRight);
    };

    // Multiply a target bits encoded 256 bit number by a factor
    uint32_t multiplyTargetBits(uint32_t pTargetBits, double factor, uint32_t pMax = 0x1d00ffff);

    enum Base58Type { PUBLIC_KEY_HASH, SCRIPT_HASH, PRIVATE_KEY, TEST_PUBLIC_KEY_HASH, TEST_SCRIPT_HASH };
    ArcMist::String base58Encode(Base58Type pType, ArcMist::InputStream *pStream, unsigned int pSize);
    //bool base58Decode(ArcMist::String pData, ArcMist::OutputStream *pStream);

    unsigned int compactIntegerSize(uint64_t pValue);
    unsigned int writeCompactInteger(ArcMist::OutputStream *pStream, uint64_t pValue);
    uint64_t readCompactInteger(ArcMist::InputStream *pStream);

    namespace Base
    {
        bool test();
    }
}

#endif
