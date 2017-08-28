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
    class KeyContext
    {
    public:

        KeyContext();
        ~KeyContext();

        secp256k1_context *context;

    };

    class CompressedPublicKey
    {
    public:

        CompressedPublicKey() { std::memset(mData, 0, 33); }

        bool operator == (CompressedPublicKey &pRight) const { return std::memcmp(mData, pRight.mData, 33) == 0; }
        bool operator != (CompressedPublicKey &pRight) const { return std::memcmp(mData, pRight.mData, 33) != 0; }

        void set(void *pData) { std::memcpy(mData, pData, 33); }
        ArcMist::String hex() const;

        void write(ArcMist::OutputStream *pStream) const { pStream->write(mData, 33); }
        bool read(ArcMist::InputStream *pStream)
        {
            if(pStream->remaining() < 33)
                return false;

            pStream->read(mData, 33);
            return true;
        }

    private:

        uint8_t mData[33];

    };

    class PublicKeyData
    {
    public:

        PublicKeyData() { std::memset(mData, 0, 64); }

        bool operator == (PublicKeyData &pRight) const { return std::memcmp(mData, pRight.mData, 64) == 0; }
        bool operator != (PublicKeyData &pRight) const { return std::memcmp(mData, pRight.mData, 64) != 0; }

        void set(void *pData) { std::memcpy(mData, pData, 64); }
        ArcMist::String hex() const;

        void write(ArcMist::OutputStream *pStream, bool pScriptFormat) const;
        void writeRaw(void *pData) const { std::memcpy(pData, mData, 64); }
        bool read(ArcMist::InputStream *pStream)
        {
            if(pStream->remaining() < 64)
                return false;

            pStream->read(mData, 64);
            return true;
        }

    private:

        uint8_t mData[64];

    };

    class PublicKey
    {
    public:

        PublicKey(KeyContext *pContext) { mContext = pContext; std::memset(mData, 0, 64); }
        PublicKey(KeyContext *pContext, PublicKeyData &pData)
        {
            mContext = pContext;
            pData.writeRaw(mData);
        }
        
        KeyContext *context() const { return mContext; }

        bool operator == (PublicKey &pRight) const { return std::memcmp(mData, pRight.mData, 64) == 0; }
        bool operator != (PublicKey &pRight) const { return std::memcmp(mData, pRight.mData, 64) != 0; }

        void set(void *pData) { std::memcpy(mData, pData, 64); }
        ArcMist::String hex() const;

        bool compress(CompressedPublicKey &pResult) const;

        void write(ArcMist::OutputStream *pStream, bool pCompressed, bool pScriptFormat) const;
        bool read(ArcMist::InputStream *pStream);

        const Hash &hash();

        const uint8_t *value() const { return mData; }

    private:

        KeyContext *mContext;
        uint8_t mData[64];
        Hash mHash;

    };

    class Signature
    {
    public:

        Signature(KeyContext *pContext) { mContext = pContext; std::memset(mData, 0, 64); }
        
        KeyContext *context() const { return mContext; }

        void set(void *pData) { std::memcpy(mData, pData, 64); }
        ArcMist::String hex() const;

        void write(ArcMist::OutputStream *pStream, bool pScriptFormat) const;
        bool read(ArcMist::InputStream *pStream, unsigned int pLength);

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

        KeyContext *mContext;
        uint8_t mData[64];

    };

    class PrivateKey
    {
    public:

        PrivateKey(KeyContext *pContext);
        
        KeyContext *context() const { return mContext; }

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

        KeyContext *mContext;
        uint8_t mData[32];

    };

    namespace Key
    {
        bool test();
    }

}

#endif
