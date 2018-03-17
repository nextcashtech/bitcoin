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
#include "arcmist/base/mutex.hpp"
#include "arcmist/io/stream.hpp"
#include "arcmist/io/buffer.hpp"
#include "base.hpp"
#include "mnemonics.hpp"

#include "secp256k1.h"

#include <cstdint>
#include <cstring>


namespace BitCoin
{
    enum AddressType
    {
        PUB_KEY_HASH = 0x00, // Public key hash
        SCRIPT_HASH  = 0x05, // Script hash
        PRIVATE_KEY  = 0x80, // Private key

        TEST_PUB_KEY_HASH = 0x6f, // Testnet Public key hash
        TEST_SCRIPT_HASH  = 0xc4, // Testnet Script hash
        TEST_PRIVATE_KEY  = 0xef, // Testnet Private key
    };

    // Return Base58 address from hash and type.
    ArcMist::String encodeAddress(const ArcMist::Hash &pHash, AddressType pType);

    // Parse hash and type from Base58 encoded data.
    bool decodeAddress(const char *pText, ArcMist::Hash &pHash, AddressType &pType);

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
            std::memset(mData, 0, 64);
            mHashType = INVALID;
        }

        HashType hashType() const { return mHashType; }
        void setHashType(HashType pHashType) { mHashType = pHashType; }

        void set(void *pData) { std::memcpy(mData, pData, 64); }
        ArcMist::String hex() const;

        void write(ArcMist::OutputStream *pStream, bool pScriptFormat) const;
        bool read(ArcMist::InputStream *pStream, unsigned int pLength, bool pECDSA_DER_SigsOnly = false);

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

        uint8_t mData[64];
        HashType mHashType;

    };

    class Key
    {
    public:

        // Keys with indices greater than or equal to this are "hardened", meaning the private keys
        //   are required to derive children.
        static const uint32_t HARDENED_LIMIT = 0x80000000;

        enum Version { MAINNET_PRIVATE, MAINNET_PUBLIC, TESTNET_PRIVATE, TESTNET_PUBLIC };

        Key() { mPublicKey = NULL; clear(); }
        ~Key() { clear(); }

        // Encode key as base58 text
        ArcMist::String encode() const;

        // Decode key from base58 text
        bool decode(const char *pText);

        bool isPrivate() const { return mKey[0] == 0; }
        bool isHardened() const { return mIndex >= HARDENED_LIMIT; }
        const Version version() const { return (Version)mVersion; }
        uint8_t depth() const { return mDepth; }
        const uint8_t *fingerPrint() const { return mFingerPrint; }
        const uint8_t *parentFingerPrint() const { return mParentFingerPrint; }
        uint32_t index() const { return mIndex; }
        const uint8_t *key() const { return mKey; }
        const uint8_t *chainCode() const { return mChainCode; }
        unsigned int childCount() const { return mChildren.size(); }
        Key *publicKey() { return mPublicKey; } // Null for public keys
        bool used() const { return mUsed; } // Public key has received payment
        const ArcMist::Hash &hash() const; // SHA256 then RIPEMD160 of compressed key data
        ArcMist::String address() const; // Base58 encoded hash of compressed key data

        bool operator == (const Key &pRight)
        {
            if(mHash.isEmpty())
                return std::memcmp(mKey, pRight.mKey, 33) == 0;
            else
                return mHash == pRight.mHash;
        }
        bool operator != (const Key &pRight)
        {
            if(mHash.isEmpty())
                return std::memcmp(mKey, pRight.mKey, 33) != 0;
            else
                return mHash != pRight.mHash;
        }

        void clear();

        bool sign(const ArcMist::Hash &pHash, Signature &pSignature) const;
        bool verify(const Signature &pSignature, const ArcMist::Hash &pHash) const;

        // Read/Write public key in script format
        bool readPublic(ArcMist::InputStream *pStream);
        bool writePublic(ArcMist::OutputStream *pStream, bool pScriptFormat) const;

        // Read/Write private key raw key data only
        bool readPrivate(ArcMist::InputStream *pStream);
        bool writePrivate(ArcMist::OutputStream *pStream, bool pScriptFormat) const;

        // Serialize key data
        void write(ArcMist::OutputStream *pStream) const;
        bool read(ArcMist::InputStream *pStream);

        // Generate an individual private key (not a hierarchal key).
        void generatePrivate(Network pNetwork);

        // Setup a key with only a hash
        void loadHash(const ArcMist::Hash &pHash);

        /******************************************************************************************
         *                       BIP-0032 Hierarchal Deterministic Keys
         *
         * Each key with a chain code can generate 2^32 child keys.
         * 2^31 non-hardened and 2^31 hardened.
         *
         * A private key at each level can derive anything below it.
         * A "non-hardened" public key at a specific level can derive only public
         *   keys below that level.
         * A "hardened" public key at a specific level can't derive anything.
         *
         ******************************************************************************************
         *
         * BIP-0044 Derivation Paths
         *   Path : Master / Purpose / Coin / Account / Chain
         *
         * BIP-0044 Hierarchy levels are defined as such. (' after key index means hardened)
         *   Master  - Top level key generated from seed.
         *   Purpose - Separates different derivation path methods. Default 44'.
         *   Coin    - Separates different coins. Default 0'.
         *   Account - Separates different "identities". Like separate bank accounts. Default 0.
         *   Chain   - Parent of address keys. Default 0 for external "receiving" addresses and 1
         *     for internal "change" addresses.
         *
         * SIMPLE derivation uses first level extended key 0 (non hardened) as account key.
         *   Default account path m/0.
         * BIP0032 derivation uses first level extended key 0' (hardened) default account key.
         *   Default account path m/0'.
         * BIP0044 derivation uses first level extended key 44' (hardened) for "purpose" with levels
         *   for coin and account below that. Default account path m/44'/0'/0'.
         *
         * Chain is 0 for receiving (external) addresses and 1 for "change" (internal) addresses.
         * Coin and Account value of 0xffffffff means use default for derivation path
         *   method.
         ******************************************************************************************/
        enum DerivationPathMethod { SIMPLE, BIP0032, BIP0044 };
        enum CoinIndex
        {
            BITCOIN      = 0x80000000, // 0x00'
            BITCOIN_CASH = 0x80000091  // 0x91'
        };

        // Return "chain" key with which to generate/lookup address keys. Requires master key as
        //   top key to ensure correct full path.
        Key *chainKey(uint32_t pChain, DerivationPathMethod pMethod = BIP0044,
          uint32_t pAccount = 0xffffffff, uint32_t pCoin = 0xffffffff);

        // Updates gap (unused addresses)
        // Call only on "chain" key (parent of address keys).
        // Returns true if new addresses were generated.
        bool updateGap(unsigned int pGap);

        // Find an already derived child key with the specified index
        Key *findChild(uint32_t pIndex);

        // Find an address level key with a matching hash
        Key *findAddress(const ArcMist::Hash &pHash);

        // Return the next child key that is not used
        Key *getNextUnused();

        // Mark a key as "used" and generate new keys if necessary.
        // Keep a specified number of unused addresses ahead of any used address.
        // Sets pNewAddresses to true if new addresses are generated.
        // Returns the key matching the hash or NULL if none found.
        Key *markUsed(const ArcMist::Hash &pHash, unsigned int pGap, bool &pNewAddresses);

        // For private key, creates child private/public key pair for specified index.
        // For public only key, creates child public key for specified index.
        Key *deriveChild(uint32_t pIndex);

        // Seed initialization
        bool loadBinarySeed(Network pNetwork, ArcMist::InputStream *pStream);

        // Generate a master key from a mnemonic sentence and passphrase BIP-0039
        bool loadMnemonicSeed(Network pNetwork, const char *pText, const char *pPassPhrase = "", const char *pSalt = "mnemonic");

        // Generate a random mnemonic sentence
        static ArcMist::String generateMnemonicSeed(Mnemonic::Language, unsigned int pBytesEntropy = 32);

        // Serializes key data and all children
        void writeTree(ArcMist::OutputStream *pStream) const;
        bool readTree(ArcMist::InputStream *pStream);

        static secp256k1_context *context(unsigned int pFlags);
        static void destroyContext();
        static secp256k1_context *sContext;
        static unsigned int sContextFlags;
        static ArcMist::Mutex sMutex;
        static const uint32_t sVersionValues[4];

        static bool test();

    private:

        Key(const Key &pCopy);
        void operator = (const Key &pRight);

        bool finalize();

        uint8_t  mVersion;
        uint8_t  mDepth;
        uint8_t  mParentFingerPrint[4]; // First 4 bytes of parent's Hash160. Zeros for master.
        uint32_t mIndex;
        uint8_t  mChainCode[32];
        uint8_t  mKey[33]; // First byte zero for private

        uint8_t mFingerPrint[4];

        Key *mPublicKey;
        std::vector<Key *> mChildren;

        ArcMist::Hash mHash;
        bool mUsed;

    };

    class KeyStore : public std::vector<Key *>
    {
    public:

        ~KeyStore();

        void clear();

        // Find an address level key with a matching hash
        Key *findAddress(const ArcMist::Hash &pHash);

        // Mark a key as "used" and generate new keys if necessary.
        // Keep a specified number of unused addresses ahead of any used address.
        // Sets pNewAddresses to true if new addresses are generated.
        // Returns the key matching the hash or NULL if none found.
        Key *markUsed(const ArcMist::Hash &pHash, unsigned int pGap, bool &pNewAddresses);
    };
}

#endif
