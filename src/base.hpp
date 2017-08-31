#ifndef BITCOIN_BASE_HPP
#define BITCOIN_BASE_HPP

#include "arcmist/io/stream.hpp"
#include "arcmist/io/network.hpp"

#include <cstdint>
#include <ctime>


namespace BitCoin
{
    enum Network { MAINNET, TESTNET };

    Network network();
    void setNetwork(Network pNetwork);

    // Seconds since epoch
    inline int64_t getTime()
    {
        return std::time(NULL);
    }

    const char *networkStartString();
    const uint8_t *networkStartBytes();
    const char *networkPortString();
    uint16_t networkPort();

    class IPAddress
    {
    public:

        IPAddress()
        {
            time = 0;
            services = 0;
            std::memset(ip, 0, 16);
            port = 0;
        }

        void write(ArcMist::OutputStream *pStream) const;
        bool read(ArcMist::InputStream *pStream);

        bool matches(IPAddress &pOther) { return std::memcmp(ip, pOther.ip, 16) == 0 && port == pOther.port; }
        void updateTime() { time = getTime(); }
        void operator = (ArcMist::Connection &pConnection)
        {
            if(pConnection.ipv6Bytes())
                std::memcpy(ip, pConnection.ipv6Bytes(), 16);
            port = pConnection.port();
        }
        bool isValid()
        {
            bool zeroes = true;
            for(int i=0;i<16;i++)
                if(ip[i] != 0)
                    zeroes = false;
            return !zeroes;
        }

        const IPAddress &operator = (const IPAddress &pRight)
        {
            time = pRight.time;
            services = pRight.services;
            port = pRight.port;
            std::memcpy(ip, pRight.ip, 16);
            return *this;
        }

        uint32_t time;
        uint64_t services;
        uint8_t ip[16];
        uint16_t port;
    };

    class Peer
    {
    public:

        Peer() { fails = 0; }

        void write(ArcMist::OutputStream *pStream) const;
        bool read(ArcMist::InputStream *pStream);

        ArcMist::String userAgent;
        uint32_t fails; // The number of failed attempts since the last success
        IPAddress address;

    };

    class Hash : public ArcMist::RawOutputStream // So ArcMist::Digest can write results to it
    {
    public:

        Hash() { mSize = 0; mData = NULL; }
        Hash(unsigned int pSize) { mSize = pSize; mData = new uint8_t[mSize]; zeroize(); }
        Hash(const Hash &pCopy) { mData = NULL; *this = pCopy; }
        ~Hash() { if(mData != NULL) delete[] mData; }

        unsigned int size() const { return mSize; }
        const uint8_t *value() const { return mData; }

        // Little endian (lease significant bytes first)
        ArcMist::String hex() const
        {
            ArcMist::String result;
            if(mSize == 0)
                return result;
            result.writeHex(mData, mSize);
            return result;
        }

        // Big endian (most significant bytes first, i.e. leading zeroes for block hashes)
        ArcMist::String bigHex() const
        {
            ArcMist::String result;
            if(mSize == 0)
                return result;
            uint8_t reverse[mSize];
            unsigned int i = mSize - 1;
            for(unsigned int j=0;j<mSize;j++)
                reverse[i--] = mData[j];
            result.writeHex(reverse, mSize);
            return result;
        }

        void setSize(unsigned int pSize)
        {
            if(mSize == pSize)
                return;
            if(mData != NULL)
                delete[] mData;
            mSize = pSize;
            if(mSize == 0)
                mData = NULL;
            else
            {
                mData = new uint8_t[mSize];
                zeroize();
            }
        }
        
        // Set to zero size. Makes hash "empty"
        void clear() { setSize(0); }

        bool isEmpty() const { return mSize == 0; }

        bool isZero() const
        {
            if(mSize == 0)
                return false; // Empty is not zero
            for(unsigned int i=0;i<mSize;i++)
                if(mData[i] != 0)
                    return false;
            return true;
        }

        uint16_t lookup() const;

        void zeroize()
        {
            if(mSize > 0)
                std::memset(mData, 0, mSize);
        }

        void randomize()
        {
            uint32_t random;
            for(unsigned int i=0;i<mSize;i+=4)
            {
                random = ArcMist::Math::randomInt();
                std::memcpy(mData + i, &random, 4);
            }
        }

        bool operator == (const Hash &pRight) const
        {
            if(mSize != pRight.mSize)
                return false;

            if(mSize == 0)
                return true;

            return std::memcmp(mData, pRight.mData, mSize) == 0;
        }

        bool operator != (const Hash &pRight) const
        {
            if(mSize != pRight.mSize)
                return true;

            if(mSize == 0)
                return false;

            return std::memcmp(mData, pRight.mData, mSize) != 0;
        }

        const Hash &operator = (const Hash &pRight)
        {
            if(mData != NULL)
                delete[] mData;
            mSize = pRight.mSize;
            if(mSize > 0)
            {
                mData = new uint8_t[mSize];
                std::memcpy(mData, pRight.mData, mSize);
            }
            else
                mData = NULL;

            return *this;
        }

        void write(ArcMist::OutputStream *pStream) const
        {
            if(mSize == 0)
                return;

            pStream->write(mData, mSize);
        }

        bool read(ArcMist::InputStream *pStream)
        {
            if(mSize == 0)
                return true;

            if(pStream->remaining() < mSize)
                return false;

            pStream->read(mData, mSize);
            return true;
        }

        bool read(ArcMist::InputStream *pStream, unsigned int pSize)
        {
            setSize(pSize);
            return read(pStream);
        }

        // ArcMist::RawOutputStream virtual
        void write(const void *pInput, unsigned int pSize)
        {
            setSize(pSize);
            std::memcpy(mData, pInput, pSize);
        }

    private:

        unsigned int mSize;
        uint8_t *mData;

    };

    class HashList : public std::vector<Hash *>
    {
    public:
        ~HashList()
        {
            for(unsigned int i=0;i<size();i++)
                delete at(i);
        }
    };

    enum Base58Type { PUBLIC_KEY_HASH, SCRIPT_HASH, PRIVATE_KEY, TEST_PUBLIC_KEY_HASH, TEST_SCRIPT_HASH };
    ArcMist::String base58Encode(Base58Type pType, ArcMist::InputStream *pStream, unsigned int pSize);
    //bool base58Decode(ArcMist::String pData, ArcMist::OutputStream *pStream);

    unsigned int compactIntegerSize(uint64_t pValue);
    unsigned int writeCompactInteger(ArcMist::OutputStream *pStream, uint64_t pValue);
    uint64_t readCompactInteger(ArcMist::InputStream *pStream);

    namespace Base
    {
        bool test();
    }
}

#endif
