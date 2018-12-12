/**************************************************************************
 * Copyright 2018 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "bloom_lookup.hpp"

#include "base.hpp"
#include "digest.hpp"


namespace BitCoin
{
    bool BloomHashEntry::isPure() const
    {
        if(mCount != 1 && mCount != -1)
            return false;

        NextCash::Digest digest(NextCash::Digest::MURMUR3);
        digest.setOutputEndian(NextCash::Endian::LITTLE);
        digest.initialize(HASH_CHECK);
        digest.writeUnsignedLong(mKeySum);
        return mKeyCheck == digest.getResult();
    }

    bool BloomHashEntry::empty() const
    {
        return mCount == 0 && mKeySum == 0UL && mKeyCheck == 0;
    }

    void BloomHashEntry::addValue(NextCash::InputStream *pStream, NextCash::stream_size pSize)
    {
        if(pSize == 0)
            return;

        if(mValueSum.length() < pSize)
        {
            mValueSum.setSize(pSize);
            mValueSum.setWriteOffset(mValueSum.length());
            while(mValueSum.length() < pSize)
                mValueSum.writeByte(0);
        }

        mValueSum.setReadOffset(0);
        mValueSum.setWriteOffset(0);
        for(NextCash::stream_size i = 0; i < pSize; ++i)
            mValueSum.writeByte(mValueSum.readByte() ^ pStream->readByte());
    }

    void BloomHashEntry::addValue(uint64_t pValue)
    {
        if(mValueSum.length() < 8)
        {
            mValueSum.setSize(8);
            mValueSum.setWriteOffset(mValueSum.length());
            while(mValueSum.length() < 8)
                mValueSum.writeByte(0);
        }

        mValueSum.setReadOffset(0);
        mValueSum.setWriteOffset(0);
        uint8_t *byte = (uint8_t *)&pValue;
        if(NextCash::Endian::sSystemType != NextCash::Endian::LITTLE)
        {
            byte += 7;
            for(NextCash::stream_size i = 0; i < 8; ++i, --byte)
                mValueSum.writeByte(mValueSum.readByte() ^ *byte);
        }
        else
        {
            for(NextCash::stream_size i = 0; i < 8; ++i, ++byte)
                mValueSum.writeByte(mValueSum.readByte() ^ *byte);
        }
    }

    void BloomHashEntry::write(NextCash::OutputStream *pStream)
    {
        pStream->writeInt(mCount);
        pStream->writeUnsignedLong(mKeySum);
        pStream->writeUnsignedInt(mKeyCheck);

        writeCompactInteger(pStream, mValueSum.length());
        mValueSum.setReadOffset(0);
        pStream->writeStream(&mValueSum, mValueSum.length());
    }

    bool BloomHashEntry::read(NextCash::InputStream *pStream)
    {
        if(pStream->remaining() < 17)
            return false;
        mCount = pStream->readInt();
        mKeySum = pStream->readUnsignedLong();
        mKeyCheck = pStream->readUnsignedInt();

        mValueSum.clear();
        NextCash::stream_size valueSumLength = readCompactInteger(pStream);
        if(pStream->remaining() < valueSumLength)
            return false;
        pStream->readStream(&mValueSum, valueSumLength);
        return true;
    }
}
