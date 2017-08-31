#include "base.hpp"

#include "arcmist/base/endian.hpp"
#include "arcmist/base/log.hpp"
#include "arcmist/io/buffer.hpp"
#include "arcmist/crypto/digest.hpp"

#include <cstring>

#define BITCOIN_BASE_LOG_NAME "BitCoin Base"


namespace BitCoin
{
    static Network sNetwork = TESTNET;
    static const uint8_t sMainNetworkStartBytes[4] = { 0xf9, 0xbe, 0xb4, 0xd9 };
    static const uint8_t sTestNetworkStartBytes[4] = { 0xfa, 0xbf, 0xb5, 0xda };
    //static const uint8_t sTestNetworkStartBytes[4] = { 0x0b, 0x11, 0x09, 0x07 };

    Network network() { return sNetwork; }
    void setNetwork(Network pNetwork) { sNetwork = pNetwork; }

    const char *networkStartString()
    {
        switch(sNetwork)
        {
            case MAINNET:
                return "f9beb4d9";
            case TESTNET:
                return "fabfb5da";
                //return "0b110907";
        }

        return "";
    }

    const uint8_t *networkStartBytes()
    {
        switch(sNetwork)
        {
            case MAINNET:
                return sMainNetworkStartBytes;
            case TESTNET:
                return sTestNetworkStartBytes;
        }

        return 0x00000000;
    }

    const char *networkPortString()
    {
        switch(sNetwork)
        {
            case MAINNET:
                return "8333";
            case TESTNET:
                return "18333";
        }

        return "";
    }

    uint16_t networkPort()
    {
        switch(sNetwork)
        {
            case MAINNET:
                return 8333;
            case TESTNET:
                return 18333;
        }

        return 0;
    }

    void IPAddress::write(ArcMist::OutputStream *pStream) const
    {
        // Time
        pStream->writeUnsignedInt(time);

        // Services
        pStream->writeUnsignedLong(services);

        // IP
        pStream->write(ip, 16);

        // Port
        ArcMist::Endian::Type previousType = pStream->outputEndian();
        pStream->setOutputEndian(ArcMist::Endian::BIG);
        pStream->writeUnsignedShort(port);
        pStream->setOutputEndian(previousType);
    }

    bool IPAddress::read(ArcMist::InputStream *pStream)
    {
        // Time
        time = pStream->readUnsignedInt();

        // Services
        services = pStream->readUnsignedLong();

        // IP
        pStream->read(ip, 16);

        // Port
        ArcMist::Endian::Type previousType = pStream->inputEndian();
        pStream->setInputEndian(ArcMist::Endian::BIG);
        port = pStream->readUnsignedShort();
        pStream->setInputEndian(previousType);

        return true;
    }

    void Peer::write(ArcMist::OutputStream *pStream) const
    {
        // Validation Header
        pStream->writeString("AMPR");

        // User Agent Bytes
        writeCompactInteger(pStream, userAgent.length());

        // User Agent
        pStream->writeString(userAgent);

        // Fails
        pStream->writeUnsignedInt(fails);

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

        // Fails
        fails = pStream->readUnsignedInt();

        // Address
        return address.read(pStream);
    }

    uint16_t Hash::lookup() const
    {
        //unsigned int result = 0;
        //for(unsigned int i=0;i<mSize;i++)
        //{
        //    result = (result << 8) + mData[i];
        //    result /= 200;
        //}
        return ArcMist::Digest::crc32((const uint8_t *)mData, mSize) & 0xffff;
    }

    ArcMist::String base58Encode(Base58Type pType, ArcMist::InputStream *pStream, unsigned int pSize)
    {
        uint8_t data[pSize + 1];
        
        switch(pType)
        {
            case PUBLIC_KEY_HASH:
                data[0] = 0x00;
                break;
            case SCRIPT_HASH:
                data[0] = 0x05;
                break;
            case PRIVATE_KEY:
                data[0] = 0x80;
                break;
            case TEST_PUBLIC_KEY_HASH:
                data[0] = 0x6f;
                break;
            case TEST_SCRIPT_HASH:
                data[0] = 0xc4;
                break;
        }

        pStream->read(data + 1, pSize);

        ArcMist::String result;
        result.writeBase58(data, pSize + 1);
        return result;
    }

    //bool base58Decode(ArcMist::String pData, ArcMist::OutputStream *pStream)
    //{
    //    
    //}

    unsigned int compactIntegerSize(uint64_t pValue)
    {
        if(pValue < 0xFD)
            return 1;
        else if(pValue < 0xFFFF)
            return 3;
        else if(pValue < 0xFFFFFFFF)
            return 5;
        else
            return 9;
    }

    unsigned int writeCompactInteger(ArcMist::OutputStream *pStream, uint64_t pValue)
    {
        unsigned int result = 0;

        if(pValue < 0xFD)
            result += pStream->writeByte(pValue);
        else if(pValue < 0xFFFF)
        {
            result += pStream->writeByte(0xFD);
            result += pStream->writeUnsignedShort(pValue);
        }
        else if(pValue < 0xFFFFFFFF)
        {
            result += pStream->writeByte(0xFE);
            result += pStream->writeUnsignedInt(pValue);
        }
        else
        {
            result += pStream->writeByte(0xFF);
            result += pStream->writeUnsignedLong(pValue);
        }

        return result;
    }

    uint64_t readCompactInteger(ArcMist::InputStream *pStream)
    {
        if(pStream->remaining() < 1)
            return 0xFFFFFFFF;

        uint8_t firstByte = pStream->readByte();

        if(firstByte < 0xFD)
            return firstByte;
        else if(firstByte == 0xFD)
        {
            if(pStream->remaining() < 2)
                return 0xFFFFFFFF;
            return pStream->readUnsignedShort();
        }
        else if(firstByte == 0xFD)
        {
            if(pStream->remaining() < 4)
                return 0xFFFFFFFF;
            return pStream->readUnsignedInt();
        }
        else
        {
            if(pStream->remaining() < 8)
                return 0xFFFFFFFF;
            return pStream->readUnsignedLong();
        }
    }

    namespace Base
    {
        bool test()
        {
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "------------- Starting Base Tests -------------");

            bool success = true;

            /***********************************************************************************************
             * Hash lookup distribution
             ***********************************************************************************************/
            std::vector<unsigned int> values;
            for(unsigned int i=0;i<0xffff;i++)
                values.push_back(0);

            Hash hash(32);
            unsigned int count = 0xffff * 0x0f;
            for(unsigned int i=0;i<count;i++)
            {
                hash.randomize();
                values[hash.lookup()] += 1;
            }

            unsigned int highestCount = 0;
            unsigned int zeroCount = 0;
            for(unsigned int i=0;i<0xffff;i++)
            {
                if(values[i] == 0)
                    zeroCount++;
                else if(values[i] > highestCount)
                    highestCount = values[i];
            }

            //ArcMist::Buffer line;
            //for(unsigned int i=0;i<0xffff;i+=16)
            //{
            //    line.clear();
            //    line.writeFormatted("%d\t: ", i);
            //    for(unsigned int j=0;j<16;j++)
            //        line.writeFormatted("%d, ", values[i+j]);
            //    ArcMist::String lineText = line.readString(line.length());
            //    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, lineText);
            //}

            if(highestCount < 100 && zeroCount < 10)
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME,
                  "Passed hash lookup distribution : high %d, zeroes %d", highestCount, zeroCount);
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME,
                  "Failed hash lookup distribution : high %d, zeroes %d", highestCount, zeroCount);
                success = false;
            }

            return success;
        }
    }
}
