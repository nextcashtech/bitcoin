/**************************************************************************
 * Copyright 2018 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "bloom_filter.hpp"

#include "base.hpp"
#include "interpreter.hpp"

#include <cmath>
#include <cstring>


#define BITCOIN_BLOOM_LOG_NAME "Bloom"
#define LN2SQUARED 0.48
#define LN2 0.7


namespace BitCoin
{
    const unsigned int BloomFilter::MAX_SIZE = 36000; // bytes
    const unsigned int BloomFilter::MAX_FUNCTIONS = 50;

    BloomFilter::BloomFilter(unsigned int pElementCount, unsigned int pFlags, double pFalsePositiveRate, unsigned int pTweak)
    {
        mDataSize = std::min((unsigned int)(-1 / LN2SQUARED * pElementCount * log(pFalsePositiveRate)), MAX_SIZE * 8) / 8;
        mData = new unsigned char[mDataSize];
        mHashFunctionCount = std::min((unsigned int)(mDataSize * 8 / pElementCount * LN2), MAX_FUNCTIONS);
        mTweak = pTweak;
        mFlags = pFlags;
        mIsFull = false;
        mIsEmpty = true;

        std::memset(mData, 0, mDataSize);
    }

    BloomFilter::~BloomFilter()
    {
        if(mData != NULL)
            delete[] mData;
    }

    void BloomFilter::updateStatus()
    {
        mIsFull = true;
        mIsEmpty = true;
        unsigned char *byte = mData;
        for(unsigned int i=0;i<mDataSize;++i,++byte)
        {
            if(*byte != 0xff)
                mIsFull = false;
            if(*byte != 0)
                mIsEmpty = false;
        }
    }

    void BloomFilter::add(const ArcMist::Hash &pHash)
    {
        if(mIsFull || mDataSize == 0)
            return;

        unsigned int offset;
        for(unsigned int i=0;i<mHashFunctionCount;i++)
        {
            offset = bitOffset(i, pHash);
            mData[offset >> 3] |= (1 << (7 & offset)); // Set bit at offset
        }

        mIsEmpty = false;
    }

    void BloomFilter::add(Outpoint &pOutpoint)
    {
        if(mIsFull || mDataSize == 0)
            return;

        ArcMist::Buffer data;
        pOutpoint.write(&data);

        unsigned int offset;
        for(unsigned int i=0;i<mHashFunctionCount;i++)
        {
            offset = bitOffset(i, data);
            mData[offset >> 3] |= (1 << (7 & offset)); // Set bit at offset
        }

        mIsEmpty = false;
    }

    void BloomFilter::addData(ArcMist::Buffer &pData)
    {
        if(mIsFull || mDataSize == 0)
            return;

        unsigned int offset;
        for(unsigned int i=0;i<mHashFunctionCount;i++)
        {
            offset = bitOffset(i, pData);
            mData[offset >> 3] |= (1 << (7 & offset)); // Set bit at offset
        }

        mIsEmpty = false;
    }

    void BloomFilter::addScript(ArcMist::Buffer &pScript)
    {
        if(mIsFull || mDataSize == 0)
            return;

        pScript.setReadOffset(0);

        unsigned int offset;
        ArcMist::Buffer data;
        uint8_t opCode;
        unsigned int byteCount, i;
        while(pScript.remaining())
        {
            opCode = pScript.readByte();

            if(opCode != 0 && opCode < MAX_SINGLE_BYTE_PUSH_DATA_CODE)
                byteCount = opCode;
            else if(opCode == OP_PUSHDATA1)
                byteCount = pScript.readByte();
            else if(opCode == OP_PUSHDATA2)
                byteCount = pScript.readUnsignedShort();
            else if(opCode == OP_PUSHDATA4)
                byteCount = pScript.readUnsignedInt();

            if(byteCount > 0)
            {
                data.copyBuffer(pScript, byteCount);

                for(i=0;i<mHashFunctionCount;i++)
                {
                    offset = bitOffset(i, data);
                    mData[offset >> 3] |= (1 << (7 & offset)); // Set bit at offset
                }

                mIsEmpty = false;
                data.clear();
                byteCount = 0;
            }
        }
    }

    bool BloomFilter::contains(const ArcMist::Hash &pHash)
    {
        if(mIsFull)
            return true;
        if(mIsEmpty || mDataSize == 0)
            return false;

        unsigned int offset;
        for(unsigned int i=0;i<mHashFunctionCount;i++)
        {
            offset = bitOffset(i, pHash);
            if(!(mData[offset >> 3] & (1 << (7 & offset)))) // Bit at offset is not set
                return false;
        }

        return true;
    }

    bool BloomFilter::contains(Outpoint &pOutpoint)
    {
        if(mIsFull)
            return true;
        if(mIsEmpty || mDataSize == 0)
            return false;

        ArcMist::Buffer data;
        pOutpoint.write(&data);

        unsigned int offset;
        for(unsigned int i=0;i<mHashFunctionCount;i++)
        {
            offset = bitOffset(i, data);
            if(!(mData[offset >> 3] & (1 << (7 & offset)))) // Bit at offset is not set
                return false;
        }

        return true;
    }

    bool BloomFilter::contains(Transaction &pTransaction)
    {
        if(mIsFull)
            return true;
        if(mIsEmpty || mDataSize == 0)
            return false;

        if(contains(pTransaction.hash))
            return true;

        for(std::vector<Input *>::iterator input=pTransaction.inputs.begin();input!=pTransaction.inputs.end();++input)
            if(contains((*input)->outpoint))
                return true;

        for(std::vector<Output *>::iterator output=pTransaction.outputs.begin();output!=pTransaction.outputs.end();++output)
            if(containsScript((*output)->script))
                return true;

        return false;
    }

    bool BloomFilter::containsScript(ArcMist::Buffer &pScript)
    {
        if(mIsFull)
            return true;
        if(mIsEmpty || mDataSize == 0)
            return false;

        pScript.setReadOffset(0);

        ArcMist::Buffer data;
        uint8_t opCode;
        unsigned int byteCount, i, offset;
        bool matches;
        while(pScript.remaining())
        {
            opCode = pScript.readByte();

            if(opCode != 0 && opCode < MAX_SINGLE_BYTE_PUSH_DATA_CODE)
                byteCount = opCode;
            else if(opCode == OP_PUSHDATA1)
                byteCount = pScript.readByte();
            else if(opCode == OP_PUSHDATA2)
                byteCount = pScript.readUnsignedShort();
            else if(opCode == OP_PUSHDATA4)
                byteCount = pScript.readUnsignedInt();

            if(byteCount > 0)
            {
                data.copyBuffer(pScript, byteCount);
                matches = true;

                for(i=0;i<mHashFunctionCount;i++)
                {
                    offset = bitOffset(i, data);
                    if(!(mData[offset >> 3] & (1 << (7 & offset)))) // Bit at offset is not set
                    {
                        matches = false;
                        break;
                    }
                }

                if(matches)
                    return true;

                data.clear();
                byteCount = 0;
            }
        }

        return false;
    }

    void BloomFilter::write(ArcMist::OutputStream *pStream) const
    {
        writeCompactInteger(pStream, mDataSize);
        pStream->write(mData, mDataSize);
        pStream->writeUnsignedInt(mHashFunctionCount);
        pStream->writeUnsignedInt(mTweak);
        pStream->writeByte(mFlags);
    }

    bool BloomFilter::read(ArcMist::InputStream *pStream)
    {
        if(mData != NULL)
        {
            // Delete any previous data
            delete[] mData;
            mDataSize = 0;
        }

        mDataSize = readCompactInteger(pStream);

        if(mDataSize == 0 || mDataSize > MAX_SIZE || mDataSize > pStream->remaining() - 9)
        {
            mDataSize = 0;
            return false;
        }

        mData = new unsigned char[mDataSize];
        pStream->read(mData, mDataSize);

        mHashFunctionCount = pStream->readUnsignedInt();
        mTweak = pStream->readUnsignedInt();
        mFlags = pStream->readByte();

        if(mHashFunctionCount > MAX_FUNCTIONS)
            return false;

        updateStatus();
        return true;
    }

    void BloomFilter::clear()
    {
        if(mData != NULL)
            delete[] mData; // Delete any data

        mDataSize = 0;
        mHashFunctionCount = 0;
        mTweak = 0;
        mFlags = 0;
        mIsFull = false;
        mIsEmpty = true;
    }

    void BloomFilter::assign(BloomFilter &pValue)
    {
        if(mData != NULL)
        {
            // Delete any previous data
            delete[] mData;
            mDataSize = 0;
        }

        mData = pValue.mData;
        pValue.mData = NULL;
        mDataSize = pValue.mDataSize;
        pValue.mDataSize = 0;

        mHashFunctionCount = pValue.mHashFunctionCount;
        mTweak = pValue.mTweak;
        mFlags = pValue.mFlags;
        mIsFull = pValue.mIsFull;
        mIsEmpty = pValue.mIsEmpty;
    }

    void BloomFilter::copy(BloomFilter &pValue)
    {
        if(mData != NULL)
        {
            // Delete any previous data
            delete[] mData;
            mDataSize = 0;
        }

        mData = new unsigned char[pValue.mDataSize];
        mDataSize = pValue.mDataSize;
        std::memcpy(mData, pValue.mData, mDataSize);

        mHashFunctionCount = pValue.mHashFunctionCount;
        mTweak = pValue.mTweak;
        mFlags = pValue.mFlags;
        mIsFull = pValue.mIsFull;
        mIsEmpty = pValue.mIsEmpty;
    }

    bool BloomFilter::test()
    {
        bool result = true;

        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOOM_LOG_NAME, "------------- Starting Bloom Filter Tests -------------");

        /***********************************************************************************************
         * Bloom Random Hash
         ***********************************************************************************************/
        BloomFilter filter(100);
        ArcMist::Hash randomHash(32);

        randomHash.randomize();

        filter.add(randomHash);

        if(filter.contains(randomHash))
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOOM_LOG_NAME, "Passed Bloom Filter Random Hash Contained");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOOM_LOG_NAME, "Failed Bloom Filter Random Hash Contained");
            result = false;
        }

        randomHash.randomize();

        if(!filter.contains(randomHash))
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_BLOOM_LOG_NAME, "Passed Bloom Filter Random Hash Not Contained");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_BLOOM_LOG_NAME, "Failed Bloom Filter Random Hash Not Contained");
            result = false;
        }

        /***********************************************************************************************
         * Bloom Random Hash Set
         ***********************************************************************************************/
        const unsigned int SET_CHECK_SIZE = 1000;
        ArcMist::Hash hashes[SET_CHECK_SIZE];
        BloomFilter setFilter(SET_CHECK_SIZE, 0.01);

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BLOOM_LOG_NAME,
          "Created bloom filter with %d bytes and %d functions", filter.size(), filter.functionCount());

        for(unsigned int i=0;i<SET_CHECK_SIZE;i++)
        {
            randomHash.randomize();
            hashes[i] = randomHash;
            setFilter.add(randomHash);
        }

        bool setCheckFailed = false;
        for(unsigned int i=0;i<SET_CHECK_SIZE;i++)
            if(!setFilter.contains(randomHash))
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOOM_LOG_NAME,
                  "Failed Bloom Filter Random Hash Set Contained : %d", SET_CHECK_SIZE);
                result = false;
                setCheckFailed = true;
                break;
            }

        if(!setCheckFailed)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BLOOM_LOG_NAME,
              "Passed Bloom Filter Random Hash Set Contained : %d", SET_CHECK_SIZE);

        unsigned int falsePositiveCount = 0;
        for(unsigned int i=0;i<SET_CHECK_SIZE;i++)
        {
            randomHash.randomize();
            if(setFilter.contains(randomHash))
                ++falsePositiveCount;
        }

        if(falsePositiveCount <= 15)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_BLOOM_LOG_NAME,
              "Passed Bloom Filter Random Hash Set False Positives : %d/%d", falsePositiveCount, SET_CHECK_SIZE);
        else
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_BLOOM_LOG_NAME,
              "Failed Bloom Filter Random Hash Set False Positives : %d/%d", falsePositiveCount, SET_CHECK_SIZE);
            result = false;
        }

        return result;
    }
}
