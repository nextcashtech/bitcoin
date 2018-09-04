/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "base.hpp"

#include "endian.hpp"
#include "log.hpp"
#include "buffer.hpp"
#include "digest.hpp"

#include <cstring>
#include <arpa/inet.h>

#define BITCOIN_BASE_LOG_NAME "Base"


namespace BitCoin
{
    uint64_t currentSupply(unsigned int pHeight)
    {
        uint64_t amount = 5000000000UL; // 50 bitcoins
        uint64_t result = amount; // Block 0 (genesis block)
        while(pHeight > COINBASE_HALF_LIFE && pHeight < 6930000)
        {
            result += (uint64_t)COINBASE_HALF_LIFE * amount;
            amount /= 2UL;
            pHeight -= COINBASE_HALF_LIFE;
        }

        if(pHeight > 0)
            result += (uint64_t)pHeight * amount;

        return result;
    }

    static Network sNetwork = MAINNET;
    static const uint8_t sMainNetworkStartBytes[4] = { 0xf9, 0xbe, 0xb4, 0xd9 };
    static const uint8_t sTestNetworkStartBytes[4] = { 0x0b, 0x11, 0x09, 0x07 };
    static const uint8_t sCashMainNetworkStartBytes[4] = { 0xe3, 0xe1, 0xf3, 0xe8 };
    static const uint8_t sCashTestNetworkStartBytes[4] = { 0xf4, 0xe5, 0xf3, 0xf4 };

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
#ifdef DISABLE_CASH
                return "f9beb4d9";
#else
                return "e3e1f3e8";
#endif
            case TESTNET:
#ifdef DISABLE_CASH
                return "0b110907";
#else
                return "f4e5f3f4";
#endif
        }

        return "";
    }

    const uint8_t *networkStartBytes()
    {
        switch(sNetwork)
        {
            case MAINNET:
#ifdef DISABLE_CASH
                return sMainNetworkStartBytes;
#else
                return sCashMainNetworkStartBytes;
#endif
            case TESTNET:
#ifdef DISABLE_CASH
                return sTestNetworkStartBytes;
#else
                return sCashTestNetworkStartBytes;
#endif
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

        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BASE_LOG_NAME,
          // "Initial : length %02x value %08x", length, value);

        if(pFactor < 1.0) // Reduce
        {
            // Decrease length to handle a reduction in value
            --length;
            value <<= 8;
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BASE_LOG_NAME,
              // "After shift up : length %02x value %08x", length, value);

            value *= pFactor;
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BASE_LOG_NAME,
              // "After factor : length %02x value %08x", length, value);

            if(value & 0xff000000)
            {
                // Increase length
                ++length;
                value >>= 8;
                // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BASE_LOG_NAME,
                  // "After shift down : length %02x value %08x", length, value);
            }
        }
        else // Increase
        {
            value *= pFactor;
            // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BASE_LOG_NAME,
              // "After factor : length %02x value %08x", length, value);

            if(value & 0xff000000)
            {
                // Increase length
                ++length;
                value >>= 8;
                // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_BASE_LOG_NAME,
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

    unsigned int writeCompactInteger(NextCash::OutputStream *pStream, uint64_t pValue)
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

    uint64_t readCompactInteger(NextCash::InputStream *pStream)
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
             * Supply amounts
             ***********************************************************************************************/
            double supply = bitcoins(currentSupply(1));
            if(supply == 100.0)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_BASE_LOG_NAME,
                  "Passed supply for block height 1 = %0.2f", supply);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_BASE_LOG_NAME,
                  "Failed supply for block height 1 = %0.2f", supply);
                success = false;
            }

            supply = bitcoins(currentSupply(546191));
            if(supply == 17327437.5)
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_BASE_LOG_NAME,
                  "Passed supply for block height 546,191 = %0.2f", supply);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_BASE_LOG_NAME,
                  "Failed supply for block height 546,191 = %0.2f", supply);
                success = false;
            }

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
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Multiply High Bit");
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Result  : %08x", previousTarget);
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %08x", correctNewTarget);
                success = false;
            }
            else
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Multiply High Bit");

            /***********************************************************************************************
             * Target Bits Multiply No High Bit - TestNet Block 4,032 Difficulty Adjustment
             ***********************************************************************************************/
            previousTarget = 0x1d00ffff;
            correctNewTarget = 0x1c3fffc0;

            previousTarget = multiplyTargetBits(previousTarget, 0.25);

            if(previousTarget != correctNewTarget)
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Multiply No High Bit");
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Result  : %08x", previousTarget);
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %08x", correctNewTarget);
                success = false;
            }
            else
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Multiply No High Bit");

            /***********************************************************************************************
             * Target Bits Multiply Over Max
             ***********************************************************************************************/
            previousTarget = 0x1d00ffff;
            correctNewTarget = 0x1d00ffff;

            previousTarget = multiplyTargetBits(previousTarget, 4.0);

            if(previousTarget != correctNewTarget)
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Multiply Over Max");
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Result  : %08x", previousTarget);
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %08x", correctNewTarget);
                success = false;
            }
            else
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Multiply Over Max");

            /***********************************************************************************************
             * Target Bits Multiply by 4
             ***********************************************************************************************/
            previousTarget = 0x1c3fffc0;
            correctNewTarget = 0x1d00ffff;

            previousTarget = multiplyTargetBits(previousTarget, 4.0);

            if(previousTarget != correctNewTarget)
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Multiply by 4");
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Result  : %08x", previousTarget);
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %08x", correctNewTarget);
                success = false;
            }
            else
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Multiply by 4");

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
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Block 415296 Adjustment");
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Result  : %08x", previousTarget);
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %08x", correctNewTarget);
                success = false;
            }
            else
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Block 415296 Adjustment");

            return success;
        }
    }
}
