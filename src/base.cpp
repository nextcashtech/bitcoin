/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
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
    static const uint8_t sTestNetworkStartBytes[4] = { 0x0b, 0x11, 0x09, 0x07 };

    Network network() { return sNetwork; }
    void setNetwork(Network pNetwork) { sNetwork = pNetwork; }

    const char *networkName()
    {
        switch(sNetwork)
        {
            case MAINNET:
                return "Main Net";
            case TESTNET:
                return "Test Net";
        }

        return "Unknown Net";
    }

    const char *networkStartString()
    {
        switch(sNetwork)
        {
            case MAINNET:
                return "f9beb4d9";
            case TESTNET:
                return "0b110907";
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

    uint8_t Hash::lookup8() const
    {
        return ArcMist::Digest::crc32((const uint8_t *)mData, mSize) & 0xff;
    }

    // Set hash to highest possible value that is valid for a header hash proof of work
    void Hash::setDifficulty(uint32_t pBits)
    {
        uint8_t length = ((pBits >> 24) & 0xff) - 1;

        setSize(32);
        zeroize();

        if(length > 31)
            return;

        mData[length]   = (pBits >> 16) & 0xff;
        mData[length-1] = (pBits >> 8) & 0xff;
        mData[length-2] = pBits & 0xff;
    }

    // Header hash must be <= target difficulty hash
    bool Hash::operator <= (const Hash &pRight)
    {
        if(mSize != pRight.mSize)
            return false;

        for(int i=mSize-1;i>=0;i--)
            if(mData[i] < pRight.mData[i])
                return true;
            else if(mData[i] > pRight.mData[i])
                return false;

        // They are equal
        return true;
    }

    uint32_t multiplyTargetBits(uint32_t pTargetBits, double pFactor, uint32_t pMax)
    {
        // Note: Negative values are not handled by this function
        uint8_t length = (pTargetBits >> 24) & 0xff;
        uint32_t value = pTargetBits & 0x00ffffff;

        // Remove leading zero byte
        // if((value & 0x00ff0000) == 0x00)
        // {
            // --length;
            // value <<= 8;
        // }

        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BASE_LOG_NAME,
          // "Initial : length %02x value %08x", length, value);

        if(pFactor < 1.0) // Reduce
        {
            // Decrease length to handle a reduction in value
            --length;
            value <<= 8;
            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BASE_LOG_NAME,
              // "After shift up : length %02x value %08x", length, value);

            value *= pFactor;
            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BASE_LOG_NAME,
              // "After factor : length %02x value %08x", length, value);

            if(value & 0xff000000)
            {
                // Increase length
                ++length;
                value >>= 8;
                // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BASE_LOG_NAME,
                  // "After shift down : length %02x value %08x", length, value);
            }
        }
        else // Increase
        {
            value *= pFactor;
            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BASE_LOG_NAME,
              // "After factor : length %02x value %08x", length, value);

            if(value & 0xff000000)
            {
                // Increase length
                ++length;
                value >>= 8;
                // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_BASE_LOG_NAME,
                  // "After shift down : length %02x value %08x", length, value);
            }
        }

        // Apply maximum
        uint8_t maxLength = (pMax >> 24) & 0xff;
        uint32_t maxValue = pMax & 0x00ffffff;
        // Remove leading zero byte
        // if((maxValue & 0x00ff0000) == 0x00)
        // {
            // --maxLength;
            // maxValue <<= 8;
        // }

        if(maxLength < length || (maxLength == length && maxValue < value))
        {
            length = maxLength;
            value = maxValue;
        }

        if(value & 0x00800000) // Pad with zero byte so it isn't negative
        {
            ++length;
            value >>= 8;
        }

        uint32_t result = length << 24;
        result += value & 0x00ffffff;
        return result;
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
        if(pValue < 0xfd)
            return 1;
        else if(pValue < 0xffff)
            return 3;
        else if(pValue < 0xffffffff)
            return 5;
        else
            return 9;
    }

    unsigned int writeCompactInteger(ArcMist::OutputStream *pStream, uint64_t pValue)
    {
        unsigned int result = 0;

        if(pValue < 0xfd)
            result += pStream->writeByte(pValue);
        else if(pValue < 0xffff)
        {
            result += pStream->writeByte(0xfd);
            result += pStream->writeUnsignedShort(pValue);
        }
        else if(pValue < 0xffffffff)
        {
            result += pStream->writeByte(0xfe);
            result += pStream->writeUnsignedInt(pValue);
        }
        else
        {
            result += pStream->writeByte(0xff);
            result += pStream->writeUnsignedLong(pValue);
        }

        return result;
    }

    uint64_t readCompactInteger(ArcMist::InputStream *pStream)
    {
        if(pStream->remaining() < 1)
            return 0xffffffff;

        uint8_t firstByte = pStream->readByte();

        if(firstByte < 0xfd)
            return firstByte;
        else if(firstByte == 0xfd)
        {
            if(pStream->remaining() < 2)
                return 0xffffffff;
            return pStream->readUnsignedShort();
        }
        else if(firstByte == 0xfe)
        {
            if(pStream->remaining() < 4)
                return 0xffffffff;
            return pStream->readUnsignedInt();
        }
        else
        {
            if(pStream->remaining() < 8)
                return 0xffffffff;
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

            /***********************************************************************************************
             * Target Bits Decode 0x181bc330
             ***********************************************************************************************/
            Hash testDifficulty;
            Hash checkDifficulty(32);
            testDifficulty.setDifficulty(0x181bc330);
            ArcMist::Buffer testData;

            testData.writeHex("00000000000000000000000000000000000000000030c31b0000000000000000");
            checkDifficulty.read(&testData);

            if(testDifficulty == checkDifficulty)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Decode 0x181bc330");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Decode 0x181bc330");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Difficulty : %s", testDifficulty.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct    : %s", checkDifficulty.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Target Bits Decode 0x1b0404cb
             ***********************************************************************************************/
            testDifficulty.setDifficulty(0x1b0404cb);
            testData.clear();
            testData.writeHex("000000000000000000000000000000000000000000000000cb04040000000000");
            checkDifficulty.read(&testData);

            if(testDifficulty == checkDifficulty)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Decode 0x1b0404cb");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Decode 0x1b0404cb");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Difficulty : %s", testDifficulty.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct    : %s", checkDifficulty.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Target Bits Decode 0x1d00ffff
             ***********************************************************************************************/
            testDifficulty.setDifficulty(0x1d00ffff);
            testData.clear();
            testData.writeHex("0000000000000000000000000000000000000000000000000000ffff00000000");
            checkDifficulty.read(&testData);

            if(testDifficulty == checkDifficulty)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Decode 0x1d00ffff");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Decode 0x1d00ffff");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Difficulty : %s", testDifficulty.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct    : %s", checkDifficulty.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Target Bits Check less than
             ***********************************************************************************************/
            testDifficulty.setDifficulty(486604799); //0x1d00ffff
            testData.clear();
            testData.writeHex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000");
            checkDifficulty.read(&testData);

            if(checkDifficulty <= testDifficulty)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Check less than");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Check less than");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Check   : %s", checkDifficulty.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Highest : %s", testDifficulty.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Target Bits Check equal
             ***********************************************************************************************/
            testDifficulty.setDifficulty(486604799);
            checkDifficulty.setDifficulty(0x1d00ffff);

            if(checkDifficulty <= testDifficulty)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Check equal");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Check equal");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Check   : %s", checkDifficulty.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Highest : %s", testDifficulty.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Target Bits Check not less than
             ***********************************************************************************************/
            testDifficulty.setDifficulty(486604799); //0x1d00ffff
            testData.clear();
            testData.writeHex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330910000000");
            checkDifficulty.read(&testData);

            if(checkDifficulty <= testDifficulty)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Check not less than");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Check   : %s", checkDifficulty.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Highest : %s", testDifficulty.hex().text());
                success = false;
            }
            else
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Check not less than");

            /***********************************************************************************************
             * Target Bits Multiply MainNet High Bit - Block 32,256 Difficulty Adjustment
             ***********************************************************************************************/
            // Block 32,255 time 1262152739
            // Block 30,240 time 1261130161
            double adjustFactor = (double)(1262152739 - 1261130161) / 1209600.0;
            uint32_t previousTarget = 0x1d00ffff;
            uint32_t correctNewTarget = 0x1d00d86a;

            previousTarget = multiplyTargetBits(previousTarget, adjustFactor);

            if(previousTarget != correctNewTarget)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Multiply High Bit");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Result  : %08x", previousTarget);
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %08x", correctNewTarget);
                success = false;
            }
            else
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Multiply High Bit");

            /***********************************************************************************************
             * Target Bits Multiply No High Bit - TestNet Block 4,032 Difficulty Adjustment
             ***********************************************************************************************/
            previousTarget = 0x1d00ffff;
            correctNewTarget = 0x1c3fffc0;

            previousTarget = multiplyTargetBits(previousTarget, 0.25);

            if(previousTarget != correctNewTarget)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Multiply No High Bit");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Result  : %08x", previousTarget);
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %08x", correctNewTarget);
                success = false;
            }
            else
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Multiply No High Bit");

            /***********************************************************************************************
             * Target Bits Multiply Over Max
             ***********************************************************************************************/
            previousTarget = 0x1d00ffff;
            correctNewTarget = 0x1d00ffff;

            previousTarget = multiplyTargetBits(previousTarget, 4.0);

            if(previousTarget != correctNewTarget)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Multiply Over Max");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Result  : %08x", previousTarget);
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %08x", correctNewTarget);
                success = false;
            }
            else
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Multiply Over Max");

            /***********************************************************************************************
             * Target Bits Multiply by 4
             ***********************************************************************************************/
            previousTarget = 0x1c3fffc0;
            correctNewTarget = 0x1d00ffff;

            previousTarget = multiplyTargetBits(previousTarget, 4.0);

            if(previousTarget != correctNewTarget)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Multiply by 4");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Result  : %08x", previousTarget);
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %08x", correctNewTarget);
                success = false;
            }
            else
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Multiply by 4");

            return success;
        }
    }
}
