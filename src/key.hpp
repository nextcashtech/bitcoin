/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_KEY_HPP
#define BITCOIN_KEY_HPP

#include "string.hpp"
#include "hash.hpp"
#include "mutex.hpp"
#include "stream.hpp"
#include "buffer.hpp"
#include "base.hpp"
#include "mnemonics.hpp"

#include "secp256k1.h"

#include <cstdint>
#include <cstring>


namespace BitCoin
{
    enum AddressType
    {
        MAIN_PUB_KEY_HASH = 0x00, // Mainnet Public key hash
        MAIN_SCRIPT_HASH  = 0x05, // Mainnet Script hash
        MAIN_PRIVATE_KEY  = 0x80, // Mainnet Private key

        TEST_PUB_KEY_HASH = 0x6f, // Testnet Public key hash
        TEST_SCRIPT_HASH  = 0xc4, // Testnet Script hash
        TEST_PRIVATE_KEY  = 0xef, // Testnet Private key

        BIP0070,
        UNKNOWN
    };

    // Decode payment code.
    class PaymentRequest
    {
    public:

        enum Format { INVALID, LEGACY, CASH };

        PaymentRequest()
        {
            format = Format::INVALID;
            type = AddressType::UNKNOWN;
            network = MAINNET;
            amount = 0;
            amountSpecified = false;
            secure = false;
        }
        PaymentRequest(const PaymentRequest &pCopy)
        {
            format = pCopy.format;
            type = pCopy.type;
            network = pCopy.network;
            pubKeyHash = pCopy.pubKeyHash;
            amount = pCopy.amount;
            amountSpecified = pCopy.amountSpecified;
            secure = pCopy.secure;
            label = pCopy.label;
            message = pCopy.message;
        }

        PaymentRequest &operator = (const PaymentRequest &pRight)
        {
            format = pRight.format;
            type = pRight.type;
            network = pRight.network;
            pubKeyHash = pRight.pubKeyHash;
            amount = pRight.amount;
            amountSpecified = pRight.amountSpecified;
            secure = pRight.secure;
            label = pRight.label;
            message = pRight.message;
            return *this;
        }

        Format format;
        AddressType type;
        Network network;
        NextCash::Hash pubKeyHash;
        uint64_t amount;
        bool amountSpecified;
        bool secure;
        NextCash::String label, message, secureURL;

    };

    // Return URI Payment code.
    //   pAmount is in satoshis
    NextCash::String encodePaymentCode(const NextCash::Hash &pHash,
      PaymentRequest::Format pFormat = PaymentRequest::Format::CASH,
      AddressType pType = MAIN_PUB_KEY_HASH, uint64_t pAmount = 0,
      NextCash::String pLabel = NextCash::String(), NextCash::String pMessage = NextCash::String());

    PaymentRequest decodePaymentCode(const char *pText);

    NextCash::String encodeLegacyAddress(const NextCash::Hash &pHash,
      AddressType pType = MAIN_PUB_KEY_HASH);

    // Parse hash and type from Base58 encoded data.
    bool decodeLegacyAddress(const char *pText, NextCash::Hash &pHash, AddressType &pType);

    NextCash::String encodeCashAddress(const NextCash::Hash &pHash,
      AddressType pType = MAIN_PUB_KEY_HASH);

    // Parse hash and type from cash address format.
    bool decodeCashAddress(const char *pText, NextCash::Hash &pHash, AddressType &pType);

    class Signature
    {
    public:

        enum HashType
        {
            INVALID      = 0x00, // Invalid value
            ALL          = 0x01, // Sign all outputs
            NONE         = 0x02, // Don't sign any outputs so anyone can modify them (i.e. miners)
            SINGLE       = 0x03, // Only sign one output so other outputs can be added later
            FORKID       = 0x40, // Signature contains a fork ID
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
        NextCash::String hex() const;

        void clear()
        {
            std::memset(mData, 0, 64);
            mHashType = INVALID;
        }

        void write(NextCash::OutputStream *pStream, bool pScriptFormat) const;
        bool read(NextCash::InputStream *pStream, unsigned int pLength, bool pECDSA_DER_SigsOnly = false);

        void randomize()
        {
            unsigned int random;
            for(unsigned int i=0;i<64;i+=4)
            {
                random = NextCash::Math::randomInt();
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

        // Depth when no hierarchy is present
        static const uint8_t NO_DEPTH = 0xff;
        static const unsigned int DEFAULT_GAP;

        enum Version { MAINNET_PRIVATE, MAINNET_PUBLIC, TESTNET_PRIVATE, TESTNET_PUBLIC,
          MAINNET_PUBKEY_HASH = 0xfe, EMPTY = 0xff };

        Key() : mChildLock("KeyChild") { mPublicKey = NULL; clear(); }
        Key(Key &pCopy);
        void operator = (Key &pRight);
        ~Key() { clear(); }

        // Encode key as base58 text
        NextCash::String encode() const;

        // Decode key from base58 text
        bool decode(const char *pText);

        bool decodePrivateKey(const char *pText);
        NextCash::String encodePrivateKey();

        bool isEmpty() const { return mVersion == EMPTY; }
        bool isPrivate() const { return !isEmpty() && mKey[0] == 0; }
        bool isHardened() const { return mIndex >= HARDENED; }
        const Version version() const { return mVersion; }
        uint8_t depth() const { return mDepth; }
        const uint8_t *fingerPrint() const { return mFingerPrint; }
        const uint8_t *parentFingerPrint() const { return mParentFingerPrint; }
        uint32_t index() const { return mIndex; }
        const uint8_t *key() const { return mKey; }
        const uint8_t *chainCode() const { return mChainCode; }
        unsigned int childCount() const { return mChildren.size(); }
        const Key *publicKey() const { return mPublicKey; } // Null for public keys
        Key *publicKey() { return mPublicKey; } // Null for public keys
        bool used() const { return mUsed; } // Public key has received payment
        const NextCash::Hash &hash() const; // SHA256 then RIPEMD160 of compressed key data

        // Encoded hash of compressed key data as specified text format.
        NextCash::String address(PaymentRequest::Format pFormat = PaymentRequest::Format::CASH) const;

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

        bool sign(const NextCash::Hash &pHash, Signature &pSignature) const;
        bool verify(const Signature &pSignature, const NextCash::Hash &pHash) const;

        // Read/Write public key in script format
        bool readPublic(NextCash::InputStream *pStream);
        bool writePublic(NextCash::OutputStream *pStream, bool pScriptFormat) const;

        // Read/Write private key raw key data only
        bool readPrivate(NextCash::InputStream *pStream);
        bool writePrivate(NextCash::OutputStream *pStream, bool pScriptFormat) const;

        // Serialize key data
        void write(NextCash::OutputStream *pStream) const;
        bool read(NextCash::InputStream *pStream);

        // Generate an individual private key (not a hierarchal key).
        void generatePrivate(Network pNetwork);

        // Setup a key with only a hash
        void loadHash(const NextCash::Hash &pHash);

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
         * Coin Values (all hardened)
         *   BTC : 0'
         *   BCH : 145'
         *   BSV : 236'
         *
         * BIP-0044 Hierarchy levels are defined as such. (' after key index means hardened)
         *   Master  - Top level key generated from seed.
         *   Purpose - Separates different derivation path methods. Default 44'.
         *   Coin    - Separates different coins. Default 0' (BTC).
         *   Account - Separates different "identities". Like separate bank accounts. Default 0.
         *   Chain   - Parent of address keys. Default 0 for external "receiving" addresses and 1
         *     for internal "change" addresses.
         *
         * SIMPLE derivation uses master as "account".
         *   Default receiving chain path m/0.
         *   Default change chain path m/1.
         * BIP0032 derivation uses first level extended key 0' (hardened) default account key.
         *   Default account path m/0'.
         * BIP0044 derivation uses first level extended key 44' (hardened) for "purpose" with levels
         *   for coin and account below that. Default account path m/44'/0'/0'.
         *
         * Chain is 0 for receiving (external) addresses and 1 for "change" (internal) addresses.
         * Coin and Account value of 0xffffffff means use default for derivation path
         *   method.
         ******************************************************************************************/
        enum DerivationPathMethod { DERIVE_UNKNOWN = 0, SIMPLE = 1, BIP0032 = 2, BIP0044 = 3,
          INDIVIDUAL = 4, DERIVE_CUSTOM = 5 };

        // Keys with indices greater than or equal to this are "hardened", meaning the private keys
        //   are required to derive children.
        static const uint32_t HARDENED;
        static const uint32_t PURPOSE_44;
        static const uint32_t COIN_BITCOIN;
        static const uint32_t COIN_BITCOIN_CASH;
        static const uint32_t COIN_BITCOIN_SV;

        const char *derivationPathMethodName(DerivationPathMethod pMethod)
        {
            switch(pMethod)
            {
            default:
            case DERIVE_UNKNOWN:
                return "Unknown";
            case SIMPLE:
                return "Simple";
            case BIP0032:
                return "BIP-0032";
            case BIP0044:
                return "BIP-0044";
            }
        }

        // Return "chain" key with which to generate/lookup address keys. Requires master key as
        //   top key to ensure correct full path.
        Key *chainKey(uint32_t pChain, DerivationPathMethod pMethod, uint32_t pAccount,
          uint32_t pCoin);

        // Updates gap (unused addresses)
        // Call only on "chain" key (parent of address keys).
        // Returns true if new addresses were generated.
        bool updateGap(unsigned int pGap);

        // Find an already derived child key with the specified index
        Key *findChild(uint32_t pIndex, bool pLocked = false);

        // Find an address level key with a matching hash
        Key *findAddress(const NextCash::Hash &pHash);

        // Return the next child key that is not used
        Key *getNextUnused();

        // Fill a vector with children
        void getChildren(std::vector<Key *> &pChildren);

        // Mark a key as "used" and generate new keys if necessary.
        // Keep a specified number of unused addresses ahead of any used address.
        // Sets pNewAddresses to true if new addresses are generated.
        // Returns the key matching the hash or NULL if none found.
        Key *markUsed(const NextCash::Hash &pHash, unsigned int pGap, bool &pNewAddresses);

        // Synchronize which keys are created and which addresses are "used".
        // pOther should be a public only version of one of the keys in the structure.
        // This allows monitoring for transactions in "public only" mode, then synchronizing
        //   data back to the private section when signing transactions.
        bool synchronize(Key *pOther);

        // For private key, creates child private/public key pair for specified index.
        // For public only key, creates child public key for specified index.
        Key *deriveChild(uint32_t pIndex, bool pLocked = false);

        Key *derivePath(const std::vector<uint32_t> &pPath);

        // Seed initialization
        bool loadBinarySeed(Network pNetwork, NextCash::InputStream *pStream);

        // Generate a master key from a mnemonic sentence and passphrase BIP-0039
        bool loadMnemonicSeed(Network pNetwork, const char *pText, const char *pPassPhrase = "",
          const char *pSalt = "mnemonic");

        // Generate a random mnemonic sentence
        static NextCash::String generateMnemonicSeed(Mnemonic::Language,
          unsigned int pBytesEntropy);

        // Validate check bits in mnemonic sentence
        bool static validateMnemonicSeed(const char *pText, const char *pPassPhrase = "",
          const char *pSalt = "mnemonic");

        // Serializes key data and all children
        void writeTree(NextCash::OutputStream *pStream);
        bool readTree(NextCash::InputStream *pStream);

        static secp256k1_context *context(unsigned int pFlags);
        static void destroyContext();
        static secp256k1_context *sContext;
        static unsigned int sContextFlags;
        static NextCash::MutexWithConstantName sMutex;

        static bool test();

    private:

        bool finalize();

        Version  mVersion;
        uint8_t  mDepth;
        uint8_t  mParentFingerPrint[4]; // First 4 bytes of parent's Hash160. Zeros for master.
        uint32_t mIndex;
        uint8_t  mChainCode[32];
        uint8_t  mKey[33]; // First byte zero for private

        uint8_t mFingerPrint[4];

        Key *mPublicKey;
        NextCash::MutexWithConstantName mChildLock;
        std::vector<Key *> mChildren;

        NextCash::Hash mHash;
        bool mUsed;

    };

    class PublicKeyData;
    class PrivateKeyData;

    class KeyStore
    {
    public:

        KeyStore();
        ~KeyStore();

        void markLoaded() { mLoaded = true; }
        void clear();

        unsigned int size() { return (unsigned int)mKeys.size(); }

        bool allAreSynchronized();
        void setAllSynchronized();

        // "Pass started" means that a monitor "pass" has been started to update transactions.
        bool allPassesStarted(); // All keys marked with "pass started".
        void setAllPassStarted(); // Mark all keys with "pass started".

        bool hasPrivate(unsigned int pOffset);
        NextCash::String name(unsigned int pOffset);
        bool isSynchronized(unsigned int pOffset);
        bool isBackedUp(unsigned int pOffset);
        Key::DerivationPathMethod derivationPathMethod(unsigned int pOffset);
        void getDerivationPath(unsigned int pOffset, unsigned int pChainOffset,
          std::vector<uint32_t> &pPath);
        Time createdDate(unsigned int pOffset);
        unsigned int gap(unsigned int pOffset);
        bool passStarted(unsigned int pOffset);
        std::vector<Key *> *chainKeys(unsigned int pOffset);
        Key *chainKey(unsigned int pOffset, uint32_t pIndex);

        void setName(unsigned int pOffset, const char *pName);
        void setBackedUp(unsigned int pOffset);
        void setGap(unsigned int pOffset, unsigned int pGap);

        // These functions require private keys to be loaded/decrypted.
        bool isPrivateLoaded() { return mPrivateLoaded; }
        NextCash::String seed(unsigned int pOffset);
        Key *fullKey(unsigned int pOffset);

        bool synchronize(unsigned int pOffset);

        // pPath is path to "account" key.
        //   Indices 0 and 1 under that will be used as receiving and change keys.
        int addSeed(const char *pSeed, Key::DerivationPathMethod pMethod,
          const std::vector<uint32_t> &pAccountPath, unsigned int pReceivingIndex,
          unsigned int pChangeIndex, int32_t pCreatedDate);

        int addEncodedKey(const char *pEncodedKey, Key::DerivationPathMethod pMethod,
          const std::vector<uint32_t> &pAccountPath, unsigned int pReceivingIndex,
          unsigned int pChangeIndex, int32_t pCreatedDate);

        int addIndividualKey(Key *pIndividualKey, int32_t pCreatedDate);

        // Load a key from text
        // Valid values are:
        //   Base58 encoded address key hashes.
        //   Base58 encoded BIP-0032 key data.
        //
        // Return values:
        //   0 = success
        //   1 = unknown failure
        //   2 = invalid format
        //   3 = already exists
        //   4 = invalid derivation
        //   5 = encryption key needed
        int addFromChainKeys(Key *pReceivingKey, Key *pChangeKey, int32_t pCreatedDate);

        // Load keys from a text stream
        // Valid lines of text are:
        //   Base58 encoded address key hashes.
        //   Base58 encoded BIP-0032 key data.
        bool loadKeys(NextCash::InputStream *pStream);

        bool remove(unsigned int pOffset);

        // Find an address level key with a matching hash
        Key *findAddress(const NextCash::Hash &pHash);
        Key *findAddress(unsigned int pKeyOffset, const NextCash::Hash &pHash);

        // Mark a key as "used" and generate new keys if necessary.
        // Keep a specified number of unused addresses ahead of any used address.
        // Sets pNewAddresses to true if new addresses are generated.
        // Returns the key matching the hash or NULL if none found.
        Key *markUsed(const NextCash::Hash &pHash, bool &pNewAddresses);

        void write(NextCash::OutputStream *pStream) const;
        bool read(NextCash::InputStream *pStream);

        bool writePrivate(NextCash::OutputStream *pStream, const uint8_t *pKey,
          unsigned int pKeyLength) const;
        bool readPrivate(NextCash::InputStream *pStream, const uint8_t *pKey,
          unsigned int pKeyLength);

        void unloadPrivate();

    private:

        int addKeyMethod(Key *pKey, Key::DerivationPathMethod pMethod, uint32_t pCoinIndex,
          int32_t pCreatedDate);

        int addKeyPath(Key *pKey, Key::DerivationPathMethod pMethod,
          const std::vector<uint32_t> &pAccountPath, unsigned int pReceivingIndex,
          unsigned int pChangeIndex, int32_t pCreatedDate);

        bool mLoaded;
        std::vector<PublicKeyData *> mKeys;
        bool mPrivateLoaded;
        std::vector<PrivateKeyData *> mPrivateKeys;

    };
}

#endif
