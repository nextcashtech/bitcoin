/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_ADDRESSES_HPP
#define BITCOIN_ADDRESSES_HPP

#include "arcmist/base/mutex.hpp"
#include "arcmist/base/hash.hpp"
#include "arcmist/base/hash_data_set.hpp"
#include "arcmist/base/distributed_vector.hpp"
#include "arcmist/base/log.hpp"
#include "base.hpp"
#include "transaction.hpp"
#include "info.hpp"

#include <vector>

#define BITCOIN_ADDRESSES_LOG_NAME "Address"


namespace BitCoin
{
    class FullOutputData
    {
    public:

        FullOutputData() {}
        FullOutputData(unsigned int pBlockHeight, const ArcMist::Hash &pTransactionID, unsigned int pIndex, Output &pOutput)
        {
            blockHeight = pBlockHeight;
            transactionID = pTransactionID;
            index = pIndex;
            output = pOutput;
        }

        void print();

        unsigned int blockHeight;
        ArcMist::Hash transactionID;
        unsigned int index;
        Output output;
    };

    class AddressOutputReference : public ArcMist::HashData
    {
    public:

        static const unsigned int SIZE = 12;

        AddressOutputReference() {}
        AddressOutputReference(uint32_t pBlockHeight, uint32_t pTransactionOffset, uint32_t pOutputIndex)
        {
            blockHeight = pBlockHeight;
            transactionOffset = pTransactionOffset;
            outputIndex = pOutputIndex;
        }

        bool getFullOutput(FullOutputData &pOutput) const;

        uint64_t size() { return 12; }

        // Evaluates the relative age of two objects.
        // Used to determine which objects to drop from cache
        // Negative means this object is older than pRight.
        // Zero means both objects are the same age.
        // Positive means this object is newer than pRight.
        int compareAge(ArcMist::HashData *pRight)
        {
            if(blockHeight < ((AddressOutputReference *)pRight)->blockHeight)
                return -1;
            else if(blockHeight > ((AddressOutputReference *)pRight)->blockHeight)
                return 1;
            else
                return 0;
        }

        // Returns true if the value of this object matches the value pRight references
        bool valuesMatch(const HashData *pRight) const
        {
            return blockHeight == ((AddressOutputReference *)pRight)->blockHeight &&
              transactionOffset == ((AddressOutputReference *)pRight)->transactionOffset &&
              outputIndex == ((AddressOutputReference *)pRight)->outputIndex;
        }

        // Reads object data from a stream
        bool read(ArcMist::InputStream *pStream)
        {
            if(pStream->remaining() < 12)
                return false;
            blockHeight = pStream->readUnsignedInt();
            transactionOffset = pStream->readUnsignedInt();
            outputIndex = pStream->readUnsignedInt();
            return true;
        }

        // Writes object data to a stream
        bool write(ArcMist::OutputStream *pStream)
        {
            pStream->writeUnsignedInt(blockHeight);
            pStream->writeUnsignedInt(transactionOffset);
            pStream->writeUnsignedInt(outputIndex);
            return true;
        }

        uint32_t blockHeight;
        uint32_t transactionOffset;
        uint32_t outputIndex;
    };

    /* Data set of address hashes and the transaction outputs associated with them
     */
    class Addresses : public ArcMist::HashDataSet<AddressOutputReference, 20, 1024, 1024>
    {
    public:

        unsigned int subSetOffset(const ArcMist::Hash &pLookupValue)
        {
            return pLookupValue.lookup16() >> 6;
        }

        Addresses() { mNextBlockHeight = 0; mMaxCacheSize = Info::instance().addressesThreshold; }
        ~Addresses() {}

        int height() { return mNextBlockHeight - 1; }

        bool add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);
        bool remove(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight);

        // Get transaction outputs associated with the specified public key address hash
        bool getOutputs(const ArcMist::Hash &pAddress, std::vector<FullOutputData> &pOutputs);

        bool needsPurge() { return cacheDataSize() > mMaxCacheSize; }

        bool load(const char *pFilePath, uint64_t pCacheDataTargetSize);
        bool save();

    private:

        unsigned int mNextBlockHeight;
        uint64_t mMaxCacheSize;

    };
}

#endif
