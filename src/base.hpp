/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_BASE_HPP
#define BITCOIN_BASE_HPP

#include "stream.hpp"
#include "network.hpp"

#include <cstdint>
#include <ctime>

// BIP-0014 Specifies User Agent Format
#ifdef ANDROID
#define BITCOIN_USER_AGENT "/NextCash:0.9.0/NextCashWallet:0.5.2(Android)/"
#else
#define BITCOIN_USER_AGENT "/NextCash:0.9.0/"
#endif

#define PROTOCOL_VERSION 70015
#define PUB_KEY_HASH_SIZE 20


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

    // Convert Satoshis to Bitcoins
    inline double bitcoins(int64_t pSatoshis)
    {
        return (double)pSatoshis / 100000000;
    }

    inline int64_t satoshisFromBitcoins(double pBitcoins)
    {
        return (uint64_t)(pBitcoins * 100000000.0);
    }

    // Amount of Satoshis generated for mining a block at this height
    inline uint64_t coinBaseAmount(int pBlockHeight)
    {
        if(pBlockHeight >= 6930000)
            return 0;

        uint64_t result = 5000000000; // 50 bitcoins
        while(pBlockHeight > 210000)
        {
            // Half every 210,000 blocks
            result /= 2;
            pBlockHeight -= 210000;
        }

        return result;
    }

    // Number of blocks for each difficulty and soft fork update
    static const int RETARGET_PERIOD = 2016;

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
            std::memset(ip, 0, INET6_ADDRLEN);
            port = 0;
        }
        IPAddress(const IPAddress &pCopy)
        {
            std::memcpy(ip, pCopy.ip, INET6_ADDRLEN);
            port = pCopy.port;
        }
        IPAddress(uint8_t *pIP, uint16_t pPort)
        {
            std::memcpy(ip, pIP, INET6_ADDRLEN);
            port = pPort;
        }

        void write(NextCash::OutputStream *pStream) const;
        bool read(NextCash::InputStream *pStream);

        bool matches(const IPAddress &pOther) const
        {
            return std::memcmp(ip, pOther.ip, INET6_ADDRLEN) == 0 && port == pOther.port;
        }

        bool operator == (const IPAddress &pRight) const
        {
            return std::memcmp(ip, pRight.ip, INET6_ADDRLEN) == 0 && port == pRight.port;
        }

        bool operator != (const IPAddress &pRight) const
        {
            return std::memcmp(ip, pRight.ip, INET6_ADDRLEN) != 0 || port != pRight.port;
        }

        void operator = (NextCash::Network::Connection &pConnection)
        {
            if(pConnection.ipv6Bytes())
                std::memcpy(ip, pConnection.ipv6Bytes(), INET6_ADDRLEN);
            port = pConnection.port();
        }

        bool isValid() const
        {
            bool zeroes = true;
            for(int i=0;i<INET6_ADDRLEN;i++)
                if(ip[i] != 0)
                    zeroes = false;
            return !zeroes;
        }

        const IPAddress &operator = (const IPAddress &pRight)
        {
            port = pRight.port;
            std::memcpy(ip, pRight.ip, INET6_ADDRLEN);
            return *this;
        }

        void set(uint8_t *pIP, uint16_t pPort)
        {
            std::memcpy(ip, pIP, INET6_ADDRLEN);
            port = pPort;
        }

        uint8_t ip[INET6_ADDRLEN];
        uint16_t port;
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

        void write(NextCash::OutputStream *pStream) const
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

        bool read(NextCash::InputStream *pStream)
        {
            NextCash::String startString = pStream->readString(4);
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

    // Multiply a target bits encoded 256 bit number by a factor
    uint32_t multiplyTargetBits(uint32_t pTargetBits, double factor, uint32_t pMax = 0x1d00ffff);

    // Integer value for target
    uint64_t targetValue(uint32_t pTargetBits);

    unsigned int compactIntegerSize(uint64_t pValue);
    unsigned int writeCompactInteger(NextCash::OutputStream *pStream, uint64_t pValue);
    uint64_t readCompactInteger(NextCash::InputStream *pStream);

    namespace Base
    {
        bool test();
    }
}

#endif
