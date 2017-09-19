/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_KEY_HPP
#define BITCOIN_KEY_HPP

#include "arcmist/base/string.hpp"
#include "arcmist/io/stream.hpp"
#include "base.hpp"

#include "secp256k1.h"

#include <cstdint>
#include <cstring>


namespace BitCoin
{
    class Key
    {
    public:
        static secp256k1_context *context();
        static void destroyContext();
        static secp256k1_context *sContext;

        static bool test();
    };

    class PublicKey
    {
    public:

        PublicKey()
        {
            mContext = Key::context();
            std::memset(mData, 0, 64);
            mValid = false;
        }

        bool operator == (PublicKey &pRight) const { return std::memcmp(mData, pRight.mData, 64) == 0; }
        bool operator != (PublicKey &pRight) const { return std::memcmp(mData, pRight.mData, 64) != 0; }

        void set(void *pData) { std::memcpy(mData, pData, 64); mValid = true; }
        ArcMist::String hex() const;

        void write(ArcMist::OutputStream *pStream, bool pCompressed, bool pScriptFormat) const;
        bool read(ArcMist::InputStream *pStream);

        bool isValid() { return mValid; }
        void getHash(Hash &pHash);

        const uint8_t *value() const { return mData; }

    private:

        secp256k1_context *mContext;
        uint8_t mData[64];
        bool mValid;

    };

    class Signature
    {
    public:

        enum HashType { INVALID = 0x00, ALL = 0x01, NONE = 0x02, SINGLE = 0x03, ANYONECANPAY = 0x80 };

        Signature()
        {
            mContext = Key::context();
            std::memset(mData, 0, 64);
        }

        void set(void *pData) { std::memcpy(mData, pData, 64); }
        ArcMist::String hex() const;

        void write(ArcMist::OutputStream *pStream, bool pScriptFormat, HashType pHashType) const;
        bool read(ArcMist::InputStream *pStream, unsigned int pLength, bool pECDSA_DER_SigsOnly = false);

        bool verify(PublicKey &pPublicKey, Hash &pHash) const;

        void randomize()
        {
            unsigned int random;
            for(unsigned int i=0;i<64;i+=4)
            {
                random = ArcMist::Math::randomInt();
                std::memcpy(mData + i, &random, 4);
            }
        }

    private:

        void generateOutput();

        secp256k1_context *mContext;
        uint8_t mData[64];

    };

    class PrivateKey
    {
    public:

        PrivateKey();

        bool generate();
        bool generatePublicKey(PublicKey &pPublicKey) const;
        ArcMist::String hex() const;

        bool sign(Hash &pHash, Signature &pSignature) const;

        void write(ArcMist::OutputStream *pStream) const { pStream->write(mData, 32); }
        bool read(ArcMist::InputStream *pStream)
        {
            if(pStream->remaining() < 32)
                return false;
            pStream->read(mData, 32);
            return true;
        }

    private:

        secp256k1_context *mContext;
        uint8_t mData[32];

    };
}

#endif
