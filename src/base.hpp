/**************************************************************************
 * Copyright 2017-2019 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_BASE_HPP
#define BITCOIN_BASE_HPP

#include "stream.hpp"
#include "network.hpp"
#include "hash_set.hpp"

#include <chrono>
#include <cstdint>

// BIP-0014 Specifies User Agent Format
#ifdef ANDROID
#define BITCOIN_USER_AGENT "/NextCash:0.13.0/NextCashWallet:0.15.2(Android)/"
#else
#define BITCOIN_USER_AGENT "/NextCash:0.13.0/"
#endif

#define PROTOCOL_VERSION 70015
#define PUB_KEY_HASH_SIZE 20
#define BLOCK_HASH_SIZE 32
#define TRANSACTION_HASH_SIZE 32

#ifndef MAX_BLOCK_TRANSACTIONS
#define MAX_BLOCK_TRANSACTIONS 500000
#endif

#ifndef MAX_TRANSACTION_INPUTS
#define MAX_TRANSACTION_INPUTS 100000
#endif

#ifndef MAX_TRANSACTION_OUTPUTS
#define MAX_TRANSACTION_OUTPUTS 100000
#endif

#ifndef MAX_SCRIPT_SIZE
#define MAX_SCRIPT_SIZE 50000
#endif

#ifndef OUTPUTS_SET_COUNT
#define OUTPUTS_SET_COUNT 1024
#endif

#ifndef OUTPUTS_SAMPLE_COUNT
#define OUTPUTS_SAMPLE_COUNT 1024
#endif


namespace BitCoin
{
    enum Network { MAINNET, TESTNET };

    Network network();
    void setNetwork(Network pNetwork);

    enum ChainID { CHAIN_UNKNOWN, CHAIN_BTC, CHAIN_ABC, CHAIN_SV };

    // First block of BTC split.
    static NextCash::Hash BTC_SPLIT_HASH("00000000000000000019f112ec0a9982926f1258cdcc558dd7c3b7e5dc7fa148");
    static unsigned int BTC_SPLIT_HEIGHT = 478559;

    // First block of ABC split.
    static NextCash::Hash ABC_SPLIT_HASH("0000000000000000004626ff6e3b936941d341c5932ece4357eeccac44e6d56c");
    static unsigned int ABC_SPLIT_HEIGHT = 556767;

    // First block of SV split.
    static NextCash::Hash SV_SPLIT_HASH("000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b");
    static unsigned int SV_SPLIT_HEIGHT = 556767;

    inline const char *chainName(ChainID pChainID)
    {
        switch(pChainID)
        {
        default:
        case CHAIN_UNKNOWN:
            return "Unknown";
        case CHAIN_BTC:
            return "BTC";
        case CHAIN_ABC:
            return "ABC";
        case CHAIN_SV:
            return "SV";
        }
    }

    inline const unsigned int chainSplitHeight(ChainID pChainID)
    {
        switch(pChainID)
        {
        default:
        case CHAIN_UNKNOWN:
            return 0;
        case CHAIN_BTC:
            return BTC_SPLIT_HEIGHT;
        case CHAIN_ABC:
            return ABC_SPLIT_HEIGHT;
        case CHAIN_SV:
            return SV_SPLIT_HEIGHT;
        }
    }

    typedef uint32_t Time;
    typedef uint64_t Milliseconds;
    typedef uint64_t Microseconds;

    // Seconds since epoch
    inline Time getTime()
    {
        return (Time)std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch()).count();
    }

    // Milliseconds since epoch
    inline Milliseconds getTimeMilliseconds()
    {
        return (Milliseconds)std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count();
    }

    // Convert Satoshis to Bitcoins
    inline double bitcoins(int64_t pSatoshis)
    {
        return (double)pSatoshis / 100000000.0;
    }

    inline int64_t satoshisFromBitcoins(double pBitcoins)
    {
        return (uint64_t)(pBitcoins * 100000000.0);
    }

    static uint64_t COINBASE_HALF_LIFE = 210000; // Half every 210,000 blocks

    // Amount of Satoshis generated for mining a block at this height
    inline uint64_t coinBaseAmount(unsigned int pHeight)
    {
        if(pHeight >= 6930000)
            return 0;

        uint64_t result = 5000000000UL; // 50 bitcoins
        while(pHeight > COINBASE_HALF_LIFE)
        {
            // Half every 210,000 blocks
            result /= 2;
            pHeight -= COINBASE_HALF_LIFE;
        }

        return result;
    }

    uint64_t currentSupply(unsigned int pHeight);

    // Number of blocks for each difficulty and soft fork update
    static const int RETARGET_PERIOD = 2016;

    const char *networkName();
    const char *networkStartString();
    const uint8_t *networkStartBytes();
    const char *networkPortString();
    uint16_t networkPort();

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

    // Object used to save hashes with times in a HashSet.
    class HashTime : public NextCash::HashObject
    {
    public:

        HashTime(const NextCash::Hash &pHash) : mHash(pHash) { time = getTime(); }
        HashTime(HashTime &pCopy) : mHash(pCopy.mHash) { time = pCopy.time; }
        ~HashTime() {}

        Time time;

        const NextCash::Hash &getHash() { return mHash; }

    private:
        NextCash::Hash mHash;
    };

    namespace Base
    {
        bool test();
    }
}

#endif
