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

#define BITCOIN_USER_AGENT "/ArcMist:0.5.0/" // BIP-0014 Specifies User Agent Format
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

    // Convert Satoshis to Bitcoins
    inline double bitcoins(int64_t pSatoshis)
    {
        return (double)pSatoshis / 100000000;
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
            std::memset(ip, 0, 16);
            port = 0;
        }
        IPAddress(const IPAddress &pCopy)
        {
            std::memcpy(ip, pCopy.ip, 16);
            port = pCopy.port;
        }
        IPAddress(uint8_t *pIP, uint16_t pPort)
        {
            std::memcpy(ip, pIP, 16);
            port = pPort;
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

        void set(uint8_t *pIP, uint16_t pPort)
        {
            std::memcpy(ip, pIP, 16);
            port = pPort;
        }

        uint8_t ip[16];
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

    // Multiply a target bits encoded 256 bit number by a factor
    uint32_t multiplyTargetBits(uint32_t pTargetBits, double factor, uint32_t pMax = 0x1d00ffff);

    // Integer value for target
    uint64_t targetValue(uint32_t pTargetBits);

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
