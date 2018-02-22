/**************************************************************************
 * Copyright 2018 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_BLOOM_HPP
#define BITCOIN_BLOOM_HPP

#include "arcmist/base/hash.hpp"
#include "arcmist/base/math.hpp"
#include "arcmist/io/buffer.hpp"
#include "arcmist/io/stream.hpp"
#include "arcmist/crypto/digest.hpp"
#include "transaction.hpp"


namespace BitCoin
{
    class BloomFilter
    {
    public:

        enum Flags
        {
            UPDATE_NONE = 0,
            UPDATE_ALL = 1,
            UPDATE_P2PUBKEY_ONLY = 2, // Only adds outpoints to the filter if the output is a pay-to-pubkey/pay-to-multisig script
            UPDATE_MASK = 3
        };

        static const unsigned int MAX_SIZE; // bytes
        static const unsigned int MAX_FUNCTIONS;

        BloomFilter()
        {
            mData = NULL;
            mDataSize = 0;
            mHashFunctionCount = 0;
            mTweak = 0;
            mFlags = 0;
            mIsFull = false;
            mIsEmpty = true;
        }
        BloomFilter(const BloomFilter &pCopy)
        {
            mData = NULL;
            mDataSize = pCopy.mDataSize;
            mHashFunctionCount = pCopy.mHashFunctionCount;
            mTweak = pCopy.mTweak;
            mFlags = pCopy.mFlags;
            mIsFull = pCopy.mIsFull;
            mIsEmpty = pCopy.mIsEmpty;

            if(mDataSize)
            {
                mData = new unsigned char[mDataSize];
                std::memcpy(mData, pCopy.mData, mDataSize);
            }
        }
        BloomFilter(unsigned int pElementCount, unsigned int pFlags = UPDATE_ALL,
          double pFalsePositiveRate = 0.0001, unsigned int pTweak = ArcMist::Math::randomInt());
        ~BloomFilter();

        const BloomFilter &operator = (const BloomFilter &pRight);

        void setup(unsigned int pElementCount, unsigned int pFlags = UPDATE_ALL,
          double pFalsePositiveRate = 0.0001, unsigned int pTweak = ArcMist::Math::randomInt());

        bool isEmpty() const { return mIsEmpty; }
        bool isFull() const { return mIsFull; }
        bool flags() const { return mFlags; }
        const unsigned char *data() const { return mData; }
        unsigned int size() const { return mDataSize; }
        unsigned int functionCount() const { return mHashFunctionCount; }
        unsigned int tweak() const { return mTweak; }
        void updateStatus();

        void add(const ArcMist::Hash &pHash);
        void add(Outpoint &pOutpoint);
        void addData(ArcMist::Buffer &pData);
        void addScript(ArcMist::Buffer &pScript);

        bool contains(const ArcMist::Hash &pHash) const;
        bool contains(Outpoint &pOutpoint) const;
        bool contains(Transaction &pTransaction) const;
        bool containsScript(ArcMist::Buffer &pScript) const;

        void write(ArcMist::OutputStream *pStream) const;
        bool read(ArcMist::InputStream *pStream);

        void clear();
        void assign(BloomFilter &pValue); // Removes data from pValue
        void copy(BloomFilter &pValue); // Makes equivalent to pValue

        static bool test();

    private:

        unsigned int bitOffset(unsigned int pHashNum, const ArcMist::Hash &pHash) const
        {
            ArcMist::Digest digest(ArcMist::Digest::MURMUR3);
            digest.initialize(pHashNum * 0xFBA4C795 + mTweak);
            pHash.write(&digest);
            return digest.getResult() % (mDataSize * 8);
        }

        unsigned int bitOffset(unsigned int pHashNum, ArcMist::Buffer &pData) const
        {
            ArcMist::Digest digest(ArcMist::Digest::MURMUR3);
            digest.initialize(pHashNum * 0xFBA4C795 + mTweak);
            pData.setReadOffset(0);
            digest.writeStream(&pData, pData.length());
            return digest.getResult() % (mDataSize * 8);
        }

        unsigned char *mData;
        unsigned int mDataSize;
        unsigned int mHashFunctionCount;
        unsigned int mTweak;
        unsigned char mFlags;

        bool mIsFull;
        bool mIsEmpty;

    };
}

#endif
