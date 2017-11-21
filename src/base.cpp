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

    Hash::Hash(const char *pHex)
    {
        mSize = 0;
        mData = NULL;
        setHex(pHex);
    }

    bool Hash::getShortID(Hash &pHash, const Hash &pHeaderHash)
    {
        pHash.clear();

        if(mSize != 32 || pHeaderHash.size() != 32)
            return false;

        // Use first two little endian 64 bit integers from header hash as keys
        uint64_t key0 = 0;
        uint64_t key1 = 0;
        unsigned int i;
        uint8_t *byte = pHeaderHash.mData;
        for(i=0;i<8;++i)
            key0 |= (uint64_t)*byte++ << (i * 8);
        for(i=0;i<8;++i)
            key1 |= (uint64_t)*byte++ << (i * 8);

        uint64_t sipHash24Value = ArcMist::Digest::sipHash24(mData, 32, key0, key1);

        // Put 6 least significant bytes of sipHash24Value into result
        pHash.setSize(6);
        for(i=0;i<6;++i)
            pHash.mData[i] = (sipHash24Value >> (i * 8)) & 0xff;

        return true;
    }

    unsigned int Hash::leadingZeroBits() const
    {
        if(mSize == 0)
            return 0;

        unsigned int result = 0;
        uint8_t *byte = mData + mSize - 1;

        for(unsigned int i=0;i<mSize;++i,--byte)
        {
            if(*byte == 0)
                result += 8;
            else
            {
                for(int j=7;j>=0;--j)
                {
                    if(*byte >> j != 0)
                        break;
                    else
                        ++result;
                }
                break;
            }
        }

        return result;
    }

    unsigned int leadingZeroBits(uint8_t pByte)
    {
        unsigned int result = 0;
        for(int j=7;j>=0;--j)
        {
            if(pByte >> j != 0)
                return result;
            else
                ++result;
        }

        return result;
    }

    unsigned int Hash::leadingZeroBytes() const
    {
        if(mSize == 0)
            return 0;

        unsigned int result = 0;
        uint8_t *byte = mData + mSize - 1;
        for(unsigned int i=0;i<mSize;++i,--byte)
        {
            if(*byte == 0)
                ++result;
            else
                break;
        }

        return result;
    }

    uint64_t Hash::shiftBytesDown(unsigned int pByteShift) const
    {
        if(pByteShift >= mSize)
            return 0;

        // Get least significant byte of shifted value
        uint8_t *byte = mData + mSize - pByteShift;
        uint64_t result = 0;

        // Add all available bytes to value
        for(unsigned int i=0;i<8 && byte>=mData;++i,--byte)
            result &= (uint64_t)*byte << (i * 8);

        return result;
    }

    Hash Hash::operator ~() const
    {
        Hash result(mSize);
        const uint8_t *byte = mData;
        uint8_t *resultByte = result.mData;

        for(unsigned int i=0;i<mSize;++i,++byte,++resultByte)
            *resultByte = ~*byte;

        return result;
    }

    Hash Hash::operator -() const
    {
        Hash result(*this);
        const uint8_t *byte = mData;
        uint8_t *resultByte = result.mData;

        for(unsigned int i=0;i<mSize;++i,++byte,++resultByte)
            *resultByte = ~*byte;

        ++result;
        return result;
    }

    Hash &Hash::operator ++()
    {
        // Prefix operator
        unsigned int i = 0;
        while(++mData[i] == 0 && i < mSize - 1)
            ++i;
        return *this;
    }

    Hash &Hash::operator --()
    {
        // Prefix operator
        unsigned int i = 0;
        while(--mData[i] == (uint8_t)-1 && i < mSize - 1)
            ++i;
        return *this;
    }

    Hash &Hash::operator +=(const Hash &pValue)
    {
        uint64_t carry = 0;
        uint8_t *byte = mData;
        const uint8_t *valueByte = pValue.mData;

        if(pValue.mSize != mSize)
            return *this; // Error

        for(unsigned int i=0;i<mSize;++i,++byte,++valueByte)
        {
            uint64_t n = carry + *byte + *valueByte;
            *byte = n & 0xff;
            carry = n >> 8;
        }

        return *this;
    }

    Hash &Hash::operator *=(const Hash &pValue)
    {
        Hash copy = *this;
        const uint8_t *valueByte;
        const uint8_t *copyByte = copy.mData;

        if(pValue.mSize != mSize)
            return *this; // Error

        zeroize();

        for(unsigned int j=0;j<mSize;++j)
        {
            uint64_t carry = 0;
            valueByte = pValue.mData;
            for(int i=0;i+j<mSize;++i)
            {
                uint64_t n = (uint64_t)carry + (uint64_t)mData[i + j] + ((uint64_t)*copyByte * (uint64_t)*valueByte);
                mData[i + j] = n & 0xff;
                carry = n >> 8;
                ++valueByte;
            }
            ++copyByte;
        }

        return *this;
    }

    Hash &Hash::operator /=(const Hash &pValue)
    {
        Hash div(pValue); // make a copy, so we can shift.
        Hash num(*this); // make a copy, so we can subtract.

        zeroize();

        // The quotient.
        int numBits = (mSize * 8) - num.leadingZeroBits();
        int divBits = (mSize * 8) - div.leadingZeroBits();

        if(divBits == 0)
            return *this; // Divide by zero

        if(divBits > numBits)
            return *this; // The result is certainly zero

        // Shift so that div and num align.
        int shift = numBits - divBits;
        div <<= shift;
        while(shift >= 0)
        {
            if(num.compare(div) >= 0)
            {
                num -= div;
                mData[shift / 8] |= (1 << (shift & 7)); // Set a bit of the result.
            }

            // Shift back.
            div >>= 1;
            shift--;
        }
        // num now contains the remainder of the division.

        return *this;
    }

    Hash &Hash::operator <<=(unsigned int pShiftBits)
    {
        Hash copy(*this);
        int offset = pShiftBits / 8;

        pShiftBits = pShiftBits % 8;
        zeroize();

        for(unsigned int i=0;i<mSize;++i)
        {
            if(i + offset + 1 < mSize && pShiftBits != 0)
                mData[i + offset + 1] |= (copy.mData[i] >> (8 - pShiftBits));
            if(i + offset < mSize)
                mData[i + offset] |= (copy.mData[i] << pShiftBits);
        }

        return *this;
    }

    Hash &Hash::operator >>=(unsigned int pShiftBits)
    {
        Hash copy(*this);
        int offset = pShiftBits / 8;

        pShiftBits = pShiftBits % 8;
        zeroize();

        for(unsigned int i=0;i<mSize;++i)
        {
            if((int)i - offset - 1 >= 0 && pShiftBits != 0)
                mData[(int)i - offset - 1] |= (copy.mData[i] << (8 - pShiftBits));
            if((int)i - offset >= 0)
                mData[i - offset] |= (copy.mData[i] >> pShiftBits);
        }

        return *this;
    }

    void Hash::setDifficulty(uint32_t pTargetBits)
    {
        int length = ((pTargetBits >> 24) & 0xff) - 1;

        // Starts with zero so increase
        if((pTargetBits & 0x00ff0000) == 0)
        {
            --length;
            pTargetBits <<= 8;
        }

        setSize(32);
        zeroize();

        if(length >= 0 && length < 32)
            mData[length] = (pTargetBits >> 16) & 0xff;
        if(length - 1 >= 0 && length - 1 < 32)
            mData[length-1] = (pTargetBits >> 8) & 0xff;
        if(length - 2 >= 0 && length - 2 < 32)
            mData[length-2] = pTargetBits & 0xff;
    }

    void Hash::getDifficulty(uint32_t &pTargetBits, uint32_t pMax)
    {
        uint8_t length = mSize - leadingZeroBytes();
        uint32_t value = 0;

        for(int i=1;i<4;++i)
        {
            value <<= 8;
            if((int)length - i < (int)mSize)
                value += getByte(length - i);
        }

        // Apply maximum
        uint8_t maxLength = (pMax >> 24) & 0xff;
        uint32_t maxValue = pMax & 0x00ffffff;

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

        pTargetBits = length << 24;
        pTargetBits += value & 0x00ffffff;
    }

    void Hash::getWork(Hash &pWork) const
    {
        // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
        // as it's too large for a arith_uint256. However, as 2**256 is at least as
        // large as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) /
        // (bnTarget+1)) + 1, or ~bnTarget / (bnTarget+1) + 1.
        pWork = ~*this;
        pWork /= (*this + 1);
        ++pWork;
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

    // Big endian (most significant bytes first, i.e. leading zeroes for block hashes)
    ArcMist::String Hash::hex() const
    {
        ArcMist::String result;
        if(mSize == 0)
            return result;
        result.writeReverseHex(mData, mSize);
        return result;
    }

    // Little endian (least significant bytes first)
    ArcMist::String Hash::littleHex() const
    {
        ArcMist::String result;
        if(mSize == 0)
            return result;
        result.writeHex(mData, mSize);
        return result;
    }

    // Big endian (most significant bytes first, i.e. leading zeroes for block hashes)
    void Hash::setHex(const char *pHex)
    {
        unsigned int length = std::strlen(pHex);

        setSize(length / 2);
        const char *hexChar = pHex + length - 1;
        uint8_t *byte = mData;
        bool second = false;

        while(hexChar >= pHex)
        {
            if(second)
            {
                (*byte) |= ArcMist::Math::hexToNibble(*hexChar) << 4;
                ++byte;
            }
            else
                (*byte) = ArcMist::Math::hexToNibble(*hexChar);

            second = !second;
            --hexChar;
        }
    }

    // Little endian (least significant bytes first)
    void Hash::setLittleHex(const char *pHex)
    {
        unsigned int length = std::strlen(pHex);

        setSize(length / 2);
        const char *hexChar = pHex;
        uint8_t *byte = mData;
        bool second = false;

        for(unsigned int i=0;i<length;++i)
        {
            if(second)
            {
                (*byte) |= ArcMist::Math::hexToNibble(*hexChar);
                ++byte;
            }
            else
                (*byte) = ArcMist::Math::hexToNibble(*hexChar) << 4;

            second = !second;
            ++hexChar;
        }
    }

    // Header hash must be <= target difficulty hash
    bool Hash::operator <= (const Hash &pRight) const
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

    void HashList::insertSorted(const Hash &pHash)
    {
        if(size() == 0 || back()->compare(pHash) < 0)
        {
            push_back(new Hash(pHash));
            return;
        }

        int compare;
        Hash **bottom = data();
        Hash **top = data() + size() - 1;
        Hash **current;

        while(true)
        {
            // Break the set in two halves
            current = bottom + ((top - bottom) / 2);
            compare = pHash.compare(**current);

            if(current == bottom)
            {
                if((*bottom)->compare(pHash) > 0)
                    current = bottom; // Insert before bottom
                else if(current != top && (*top)->compare(pHash) > 0)
                    current = top; // Insert before top
                else
                    current = top + 1; // Insert after top
                break;
            }

            // Determine which half the desired item is in
            if(compare > 0)
                bottom = current;
            else if(compare < 0)
                top = current;
            else
                break;
        }

        iterator after = begin();
        after += (current - data());
        insert(after, new Hash(pHash));
    }

    bool HashList::containsSorted(const Hash &pHash)
    {
        if(size() == 0 || back()->compare(pHash) < 0)
            return false;

        int compare;
        Hash **bottom = data();
        Hash **top = data() + size() - 1;
        Hash **current;

        while(true)
        {
            // Break the set in two halves
            current = bottom + ((top - bottom) / 2);
            compare = pHash.compare(**current);

            if(current == bottom)
                return **bottom == pHash;

            // Determine which half the desired item is in
            if(compare > 0)
                bottom = current;
            else if(compare < 0)
                top = current;
            else
                return true;
        }
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
            for(unsigned int i=0;i<0x100;i++)
                values.push_back(0);

            Hash hash(32);
            unsigned int count = 0x100 * 0x0f;
            for(unsigned int i=0;i<count;i++)
            {
                hash.randomize();
                values[hash.lookup8()] += 1;
            }

            unsigned int highestCount = 0;
            unsigned int zeroCount = 0;
            for(unsigned int i=0;i<0x100;i++)
            {
                if(values[i] == 0)
                    zeroCount++;
                else if(values[i] > highestCount)
                    highestCount = values[i];
            }

            //ArcMist::Buffer line;
            //for(unsigned int i=0;i<0x100;i+=16)
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
             * Hash set hex
             ***********************************************************************************************/
            Hash value;
            value.setHex("4d085aa37e61a1bf2a6a53b72394f57a6b5ecaca0e2c385a27f96551ea92ad96");
            ArcMist::String hex = "4d085aa37e61a1bf2a6a53b72394f57a6b5ecaca0e2c385a27f96551ea92ad96";

            if(value.hex() == hex)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Hash set hex");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Hash set hex");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Hash    : %s", value.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %s", hex.text());
                success = false;
            }

            /***********************************************************************************************
             * Hash set little hex
             ***********************************************************************************************/
            value.setLittleHex("96ad92ea5165f9275a382c0ecaca5e6b7af59423b7536a2abfa1617ea35a084d");

            if(value.hex() == hex)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Hash set little hex");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Hash set little hex");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Hash    : %s", value.hex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %s", hex.text());
                success = false;
            }

            /***********************************************************************************************
             * Hash little endian hex
             ***********************************************************************************************/
            hex = "96ad92ea5165f9275a382c0ecaca5e6b7af59423b7536a2abfa1617ea35a084d";

            if(value.littleHex() == hex)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Hash little endian hex");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Hash little endian hex");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Hash    : %s", value.littleHex().text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Correct : %s", hex.text());
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
             * Target Bits Encode 0x1b0404cb
             ***********************************************************************************************/
            testDifficulty.setDifficulty(0x1b0404cb);
            uint32_t checkTargetBits;
            testDifficulty.getDifficulty(checkTargetBits);

            if(checkTargetBits == 0x1b0404cb)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Encode 0x1b0404cb");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Encode 0x1b0404cb : 0x%08x", checkTargetBits);
                success = false;
            }

            /***********************************************************************************************
             * Target Bits Encode 0x1d00ffff
             ***********************************************************************************************/
            testDifficulty.setDifficulty(0x1d00ffff);
            testDifficulty.getDifficulty(checkTargetBits);

            if(checkTargetBits == 0x1d00ffff)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Encode 0x1d00ffff");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Encode 0x1d00ffff : 0x%08x", checkTargetBits);
                success = false;
            }

            /***********************************************************************************************
             * Target Bits Encode 0x181bc330
             ***********************************************************************************************/
            testDifficulty.setDifficulty(0x181bc330);
            testDifficulty.getDifficulty(checkTargetBits);

            if(checkTargetBits == 0x181bc330)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed Target Bits Encode 0x181bc330");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed Target Bits Encode 0x181bc330 : 0x%08x", checkTargetBits);
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

            /***********************************************************************************************
             * Test hash compare equal
             ***********************************************************************************************/
            Hash leftHash("0010");
            Hash rightHash("0010");

            if(leftHash.compare(rightHash) == 0)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed hash compare equal");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed hash compare equal");
                success = false;
            }

            /***********************************************************************************************
             * Test hash compare less than
             ***********************************************************************************************/
            leftHash.setHex("0010");
            rightHash.setHex("0020");

            if(leftHash.compare(rightHash) < 0)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed hash compare less than");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed hash compare less than");
                success = false;
            }

            /***********************************************************************************************
             * Test hash compare greater than
             ***********************************************************************************************/
            leftHash.setHex("0020");
            rightHash.setHex("0010");

            if(leftHash.compare(rightHash) > 0)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed hash compare greater than");
            else
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed hash compare greater than");
                success = false;
            }

            /***********************************************************************************************
             * Add Hash
             ***********************************************************************************************/
            Hash a(32, 5);
            Hash b(32, 1000);
            Hash answer(32, 1005);

            a += b;
            if(a == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed add assign hash 1005");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed add assign hash 1005 : %s",
                  a.hex().text());
                success = false;
            }

            a = 5;
            if(a + b == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed add hash 1005");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed add hash 1005 : %s",
                  (a + b).hex().text());
                success = false;
            }

            a = 1005;
            answer = 1010;
            if(a + 5 == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed add hash 1010");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed add hash 1010 : %s",
                  (a + 5).hex().text());
                success = false;
            }

            a = 16589;
            answer = 16590;
            ++a;
            if(a == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed increment");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed increment : %s",
                  a.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Subtract Hash
             ***********************************************************************************************/
            a = 1000;
            b = 5;
            a -= b;
            answer = 995;
            if(a == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed subtract assign hash 995");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed subtract assign hash 995 : %s",
                  a.hex().text());
                success = false;
            }

            a = 1000;
            if(a - b == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed subtract hash 995");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed subtract hash 995 : %s",
                  (a - b).hex().text());
                success = false;
            }

            a = 16589;
            answer = 16588;
            --a;
            if(a == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed decrement");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed decrement : %s",
                  a.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Assign negative Hash
             ***********************************************************************************************/
            a = -1;
            answer.setHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            if(a == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed assign negative");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed assign negative : %s",
                  a.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Multiply Hash
             ***********************************************************************************************/
            a = 100000;
            b = 1000;
            answer = 100000000;
            a *= b;
            if(a == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed multiply assign 100000000");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed multiply assign 100000000 : %s",
                  a.hex().text());
                success = false;
            }

            a = 100000;
            a *= 1000;
            if(a == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed multiply assign int 100000000");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed multiply assign int 100000000 : %s",
                  a.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Divide Hash
             ***********************************************************************************************/
            a = 100000;
            b = 1000;
            answer = 100;
            a /= b;
            if(a == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed divide assign 100");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed divide assign 100 : %s",
                  a.hex().text());
                success = false;
            }

            a = 100000;
            a /= 1000;
            if(a == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed divide assign int 100");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed divide assign int 100 : %s",
                  a.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Negate Hash
             ***********************************************************************************************/
            a.setHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            b = -a;
            answer = 1;
            if(b == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed negate -1 hash");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed negate -1 hash : %s",
                  b.hex().text());
                success = false;
            }

            a.setHex("0000000000000000000000000000000000000000000000000000000000000001");
            b = -a;
            answer.setHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            if(b == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed negate 1 hash");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed negate 1 hash : %s",
                  b.hex().text());
                success = false;
            }

            a = 1950;
            b = -a;
            answer.setHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff862");
            if(b == answer)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed negate 1950 hash");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed negate 1950 hash : %s",
                  b.hex().text());
                success = false;
            }

            /***********************************************************************************************
             * Hash work
             ***********************************************************************************************/
            Hash proofHash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            Hash workHash;
            Hash answerHash("0000000000000000000000000000000000000000000000000000000000000001");
            for(int i=0;i<8;++i)
            {
                proofHash.setByte(31, 0xff >> i);
                proofHash.getWork(workHash);
                if(workHash == answerHash)
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME,
                      "Passed hash work %d zeroes", i);
                else
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME,
                      "Failed hash work %d zeroes : %s", i, workHash.hex().text());
                    success = false;
                }
                answerHash <<= 1;
            }

            proofHash.setHex("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            answerHash.setHex("0000000000000000000000000000000000000000000000000000000000008000");
            proofHash.getWork(workHash);
            if(workHash == answerHash)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BASE_LOG_NAME, "Passed hash work 0001");
            else
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BASE_LOG_NAME, "Failed hash work 0001 : %s",
                  workHash.hex().text());
                success = false;
            }

            return success;
        }
    }
}
