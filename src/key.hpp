/**************************************************************************
 * Copyright 2017-2018 ArcMist, LLC                                       *
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
#include "arcmist/io/buffer.hpp"
#include "base.hpp"
#include "mnemonics.hpp"

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

        const uint8_t *data() const { return mData; }

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

        const uint8_t *data() const { return mData; }

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

        void set(void *pData) { std::memcpy(mData, pData, 32); }
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

    /**********************************************************************************************
     *                       BIP-0032 Hierarchal Deterministic Keys
     *
     * A private key with the chain code at each level can derive anything below it.
     * A "non-hardened" public key with the chain code at a specific level can derive only public
     *   keys below that level.
     * A "hardened" public key with the chain code at a specific level can't derive anything.
     *
     * Levels of Hierarchy
     *
     * Name                                    |     Count
     * --------------------------------------------------------------------
     * Seed    : 128 .. 512 bits of entropy    |       1
     * Level 1 : Master Key                    |       1
     * Level 2 : Accounts                      |    1 .. 2^32
     * Level 3 : Chains                        |    1 .. 2^32 per account
     * Level 4 : Payable Addresses             |    1 .. 2^32 per chain
     *
     *********************************************************************************************/
    class KeyTree
    {
    public:

        // Keys with indices greater than or equal to this are "hardened".
        static const uint32_t HARDENED_LIMIT = 0x80000000;

        enum Version { MAINNET_PRIVATE, MAINNET_PUBLIC, TESTNET_PRIVATE, TESTNET_PUBLIC };
        static const uint32_t sVersionValues[4];

        KeyTree();
        ~KeyTree();

        class KeyData
        {
        public:

            KeyData() { mPublicKey = NULL; clear(); }
            ~KeyData() { clear(); }

            // Encode key as base58 text
            ArcMist::String encode() const;

            // Decode key from base58 text
            bool decode(secp256k1_context *pContext, const char *pText);

            bool isPrivate() const { return mKey[0] == 0; }
            bool isHardened() const { return mIndex >= HARDENED_LIMIT; }
            const Version version() const { return (Version)mVersion; }
            uint8_t depth() const { return mDepth; }
            const uint8_t *fingerPrint() const { return mFingerPrint; }
            const uint8_t *parentFingerPrint() const { return mParentFingerPrint; }
            uint32_t index() const { return mIndex; }
            const uint8_t *key() const { return mKey; }
            const uint8_t *chainCode() const { return mChainCode; }
            KeyData *publicKey() { return mPublicKey; } // Null for public keys
            const ArcMist::Hash &hash();

            bool sign(secp256k1_context *pContext, ArcMist::Hash &pHash, Signature &pSignature) const;
            bool verify(secp256k1_context *pContext, Signature &pSignature, const ArcMist::Hash &pHash) const;

            void clear();

            // Serializes key data
            void write(ArcMist::OutputStream *pStream) const;
            bool read(ArcMist::InputStream *pStream);

            // Serializes key data and all children
            void writeTree(ArcMist::OutputStream *pStream) const;
            bool readTree(ArcMist::InputStream *pStream);

            // Find an already derived child key with the specified index
            KeyData *findChild(uint32_t pIndex);

            // If this is the address level then search for public address with matching hash
            KeyData *findAddress(const ArcMist::Hash &pHash);

            // For private key, creates child private/public key pair for specified index.
            // For public only key, creates child public key for specified index.
            KeyData *deriveChild(secp256k1_context *pContext, Network pNetwork, uint32_t pIndex);

            /*************************** Functions used to setup keys ****************************/
            void setInfo(Version pVersion, uint8_t pDepth, const uint8_t *pParentFingerPrint, uint32_t pIndex)
            {
                mVersion = pVersion;
                mDepth = pDepth;
                std::memcpy(mParentFingerPrint, pParentFingerPrint, 4);
                mIndex = pIndex;
            }

            void setKey(const uint8_t *pKey, uint8_t pType) { mKey[0] = pType; std::memcpy(mKey + 1, pKey, 32); }
            void writeKey(ArcMist::InputStream *pStream, uint8_t pType) { mKey[0] = pType; pStream->read(mKey + 1, 32); }
            void setChainCode(const uint8_t *pChainCode) { std::memcpy(mChainCode, pChainCode, 32); }
            void writeChainCode(ArcMist::InputStream *pStream) { pStream->read(mChainCode, 32); }

            // Used only by KeyTree
            // Calculates fingerprint
            // Creates associated public key if this is a private key
            bool finalize(secp256k1_context *pContext, Network pNetwork);
            /*************************************************************************************/

        private:

            uint8_t  mVersion;
            uint8_t  mDepth;
            uint8_t  mParentFingerPrint[4]; // First 4 bytes of parent's Hash160. Zeros for master.
            uint32_t mIndex;
            uint8_t  mChainCode[32];
            uint8_t  mKey[33]; // First byte zero for private

            uint8_t mFingerPrint[4];

            KeyData *mPublicKey;
            std::vector<KeyData *> mChildren;

            ArcMist::Hash mHash;

        };

        Network network() const { return mNetwork; }

        void clear(); // Clear all data and set master key to zero

        // Seed initialization
        void generate(Network pNetwork);
        bool setSeed(Network pNetwork, ArcMist::InputStream *pStream);
        void readSeed(ArcMist::OutputStream *pStream) { mSeed.setReadOffset(0); pStream->writeStream(&mSeed, mSeed.length()); }

        // Generate a master key from a mnemonic sentence and passphrase BIP-0039
        bool loadMnemonic(const char *pText, const char *pPassPhrase = "");

        // Generate a random mnemonic sentence
        static ArcMist::String generateMnemonic(Mnemonic::Language, unsigned int pBytesEntropy = 32);

        // Set top key in tree. Don't generate from seed.
        bool setTopKey(const char *pKeyText);

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        // TODO Add sub tree functions. i.e. Given an extended key, public or private, a sub tree can be created.
        // Public only can be used to verify incoming payments and balances.

        KeyData &top() { return mTopKey; }
        KeyData *getAccount(uint32_t pIndex); // Children of master key
        KeyData *findAddress(const ArcMist::Hash &pHash); // Find child of chain key with matching public key hash

        // Calls deriveChild function on parent key with appropriate tree values.
        KeyData *deriveChild(KeyData *pParent, uint32_t pIndex) { return pParent->deriveChild(mContext, mNetwork, pIndex); }

    private:

        void generateSeed(); // Generate entropy to create master key/code
        bool generateMaster(); // Generate master private key and chain code from entropy

        secp256k1_context *mContext;

        Network mNetwork;
        ArcMist::Buffer mSeed;
        KeyData mTopKey;

    };
}

#endif
