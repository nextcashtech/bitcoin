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
#include "arcmist/base/hash.hpp"
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

    enum AddressType
    {
        PUB_KEY_HASH = 0x00, // Public key hash
        SCRIPT_HASH  = 0x05, // Script hash
        PRIVATE_KEY  = 0x80, // Private key

        TEST_PUB_KEY_HASH = 0x6f, // Testnet Public key hash
        TEST_SCRIPT_HASH  = 0xc4, // Testnet Script hash
        TEST_PRIVATE_KEY  = 0xef, // Testnet Private key
    };

    ArcMist::String encodeAddress(const ArcMist::Hash &pHash, AddressType pType);
    bool decodeAddress(const char *pText, ArcMist::Hash &pHash, AddressType &pType);

    class PublicKey
    {
    public:

        PublicKey()
        {
            mContext = Key::context();
            std::memset(mData, 0, 64);
            mValid = false;
        }

        bool operator == (const PublicKey &pRight) const { return std::memcmp(mData, pRight.mData, 64) == 0; }
        bool operator != (const PublicKey &pRight) const { return std::memcmp(mData, pRight.mData, 64) != 0; }

        void set(const void *pData) { std::memcpy(mData, pData, 64); mValid = true; }
        ArcMist::String hex() const;

        void write(ArcMist::OutputStream *pStream, bool pCompressed, bool pScriptFormat) const;
        bool read(ArcMist::InputStream *pStream);

        bool isValid() const { return mValid; }
        void getHash(ArcMist::Hash &pHash) const;

        ArcMist::String address(bool pTest = false);

        const uint8_t *value() const { return mData; }

    private:

        secp256k1_context *mContext;
        uint8_t mData[64];
        bool mValid;

    };

    class Signature
    {
    public:

        enum HashType
        {
            INVALID      = 0x00, // Invalid value
            ALL          = 0x01, // Sign all outputs
            NONE         = 0x02, // Don't sign any outputs so anyone can modify them (i.e. miners)
            SINGLE       = 0x03, // Only sign one output so other outputs can be added later
            FORKID       = 0x40, // Flag for BitCoin Cash only transaction
            ANYONECANPAY = 0x80  // Only sign this input so that other inputs can be added later
        };

        Signature()
        {
            mContext = Key::context();
            std::memset(mData, 0, 64);
            mHashType = INVALID;
        }

        HashType hashType() const { return mHashType; }
        void setHashType(HashType pHashType) { mHashType = pHashType; }

        void set(void *pData) { std::memcpy(mData, pData, 64); }
        ArcMist::String hex() const;

        void write(ArcMist::OutputStream *pStream, bool pScriptFormat) const;
        bool read(ArcMist::InputStream *pStream, unsigned int pLength, bool pECDSA_DER_SigsOnly = false);

        bool verify(const PublicKey &pPublicKey, const ArcMist::Hash &pHash) const;

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
        HashType mHashType;

    };

    class PrivateKey
    {
    public:

        PrivateKey();
        ~PrivateKey();

        bool generate();
        bool generatePublicKey(PublicKey &pPublicKey) const;
        ArcMist::String hex() const;

        bool sign(ArcMist::Hash &pHash, Signature &pSignature) const;

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
