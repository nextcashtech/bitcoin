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

#define BITCOIN_BASE_LOG_NAME "Base"


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

    uint64_t targetValue(uint32_t pTargetBits)
    {
        uint8_t length = (pTargetBits >> 24) & 0xff;
        uint64_t value = pTargetBits & 0x00ffffff;
        return value << length;
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
            bool success = true;

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

            /***********************************************************************************************
             * Target Bits Block 415296 Adjustment
             ***********************************************************************************************/
            previousTarget = 0x18058436;
            correctNewTarget = 0x18059ba0;

            //adjustFactor = (double)(1465353421 - 1464123775) / 1209600.0;
            adjustFactor = (double)(1465353421 - 1464123766) / 1209600.0;

            previousTarget = multiplyTargetBits(previousTarget, adjustFactor);

            if(previousTarget != correctNewTarget)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Block 415296 Adjustment");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Result  : %08x", previousTarget);
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %08x", correctNewTarget);
                success = false;
            }
            else
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Block 415296 Adjustment");

            return success;
        }
    }
}
