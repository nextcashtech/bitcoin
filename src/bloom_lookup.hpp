/**************************************************************************
 * Copyright 2018 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_BLOOM_LOOKUP_HPP
#define BITCOIN_BLOOM_LOOKUP_HPP

#include "buffer.hpp"
#include "stream.hpp"

#include <cstdint>


namespace BitCoin
{
    class BloomHashEntry
    {
    public:

        BloomHashEntry()
        {
            mCount = 0;
            mKeySum = 0UL;
            mKeyCheck = 0;
        }
        BloomHashEntry(const BloomHashEntry &pCopy) : mValueSum(pCopy.mValueSum)
        {
            mCount = pCopy.mCount;
            mKeySum = pCopy.mKeySum;
            mKeyCheck = pCopy.mKeyCheck;
        }

        bool isPure() const;
        bool empty() const;
        void addValue(NextCash::InputStream *pStream, NextCash::stream_size pSize);
        void addValue(uint64_t pValue);

        void write(NextCash::OutputStream *pStream);
        bool read(NextCash::InputStream *pStream);

    private:

        static const uint32_t HASH_CHECK = 11;

        int32_t mCount;
        uint64_t mKeySum;
        uint32_t mKeyCheck;
        NextCash::Buffer mValueSum;

    };

    class BloomLookup
    {
    public:

        BloomLookup()
        {
            mVersion = 0UL;
            mHashCount = 0;
            mIsModified = false;
        }
        BloomLookup(const BloomLookup &pCopy) : mTable(pCopy.mTable)
        {
            mVersion = pCopy.mVersion;
            mHashCount = pCopy.mHashCount;
            mIsModified = pCopy.mIsModified;
        }
        BloomLookup(NextCash::stream_size pSize);

        void reset();
        NextCash::stream_size size() const;
        void resize(NextCash::stream_size pSize);

        // void insert(uint64_t pKey, )

        BloomLookup operator - (const BloomLookup &pRight) const;


    private:

        uint64_t mVersion;
        uint8_t mHashCount;
        bool mIsModified;

        std::vector<BloomHashEntry> mTable;

    };
}

#endif
