/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "key.hpp"

#ifdef PROFILER_ON
#include "arcmist/dev/profiler.hpp"
#endif

#include "arcmist/base/log.hpp"
#include "arcmist/base/math.hpp"
#include "arcmist/crypto/digest.hpp"
#include "interpreter.hpp"

#define BITCOIN_KEY_LOG_NAME "Key"


namespace BitCoin
{
    secp256k1_context *Key::sContext = NULL;

    secp256k1_context *Key::context()
    {
        if(sContext == NULL)
        {
            sContext = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
            std::atexit(destroyContext);
        }

        return sContext;
    }

    void Key::destroyContext()
    {
        secp256k1_context_destroy(sContext);
        sContext = NULL;
    }

    PrivateKey::PrivateKey()
    {
        // Create context with sign ability
        mContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        std::memset(mData, 0, 32);
    }

    PrivateKey::~PrivateKey()
    {
        secp256k1_context_destroy(mContext);
    }

    bool PrivateKey::generate()
    {
        bool valid;

        uint32_t random;
        for(unsigned int i=0;i<32;i+=4)
        {
            random = ArcMist::Math::randomInt();
            std::memcpy(mData + i, &random, 4);
        }

        valid = secp256k1_ec_seckey_verify(mContext, mData);

        if(!valid)
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to generate private key");

        return valid;
    }

    ArcMist::String PrivateKey::hex() const
    {
        ArcMist::String result;
        result.writeHex(mData, 32);
        return result;
    }

    bool PrivateKey::generatePublicKey(PublicKey &pPublicKey) const
    {
        secp256k1_pubkey pubkey;
        if(!secp256k1_ec_pubkey_create(mContext, &pubkey, mData))
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to generate public key");
            return false;
        }

        pPublicKey.set(pubkey.data);
        return true;
    }

    bool PrivateKey::sign(ArcMist::Hash &pHash, Signature &pSignature) const
    {
        if(pHash.size() != 32)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Wrong size hash to verify");
            return false;
        }

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Private Key Sign");
#endif
        secp256k1_ecdsa_signature signature;
        if(!secp256k1_ecdsa_sign(mContext, &signature, pHash.data(), mData,
          secp256k1_nonce_function_default, NULL))
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to sign hash");
            return false;
        }

        pSignature.set(signature.data);
        return true;
    }

    bool Signature::verify(const PublicKey &pPublicKey, const ArcMist::Hash &pHash) const
    {
        if(!pPublicKey.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Invalid public key. Can't verify.");
            return false;
        }

        if(pHash.size() != 32)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Wrong size hash to verify");
            return false;
        }

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Signature Verify");
#endif
        if(secp256k1_ecdsa_verify(mContext, (const secp256k1_ecdsa_signature *)mData,
          pHash.data(), (const secp256k1_pubkey *)pPublicKey.data()))
            return true;

        if(!secp256k1_ecdsa_signature_normalize(mContext, (secp256k1_ecdsa_signature *)mData,
          (const secp256k1_ecdsa_signature *)mData))
            return false; // Already normalized

        // Try it again with the normalized signature
        if(secp256k1_ecdsa_verify(mContext, (const secp256k1_ecdsa_signature *)mData,
          pHash.data(), (const secp256k1_pubkey *)pPublicKey.data()))
            return true;

        return false;
    }

    ArcMist::String Signature::hex() const
    {
        ArcMist::String result;
        result.writeHex(mData, 64);
        return result;
    }

    ArcMist::String PublicKey::hex() const
    {
        ArcMist::String result;
        result.writeHex(mData, 64);
        return result;
    }

    void PublicKey::write(ArcMist::OutputStream *pStream, bool pCompressed, bool pScriptFormat) const
    {
        if(pCompressed)
        {
            size_t compressedLength = 33;
            uint8_t compressedData[compressedLength];
            if(!secp256k1_ec_pubkey_serialize(mContext, compressedData, &compressedLength, (const secp256k1_pubkey *)mData, SECP256K1_EC_COMPRESSED))
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to write compressed public key");
            else
            {
                if(pScriptFormat)
                    ScriptInterpreter::writePushDataSize(compressedLength, pStream);
                pStream->write(compressedData, compressedLength);
            }
        }
        else
        {
            size_t length = 65;
            uint8_t data[length];
            if(!secp256k1_ec_pubkey_serialize(mContext, data, &length, (const secp256k1_pubkey *)mData, 0))
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to write public key");
            else
            {
                if(pScriptFormat)
                    ScriptInterpreter::writePushDataSize(length, pStream);
                pStream->write(data, length);
            }
        }
    }

    bool PublicKey::read(ArcMist::InputStream *pStream)
    {
        size_t length;
        uint8_t *data;
        mValid = false;

        if(pStream->remaining() < 1)
            return false;

        // Check first byte to determine length
        uint8_t type = pStream->readByte();
        if(type == 0x02 || type == 0x03) // Compressed
            length = 33;
        else if(type == 0x04) // Uncompressed
            length = 65;
        else // Unknown
        {
            length = pStream->remaining() + 1;
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
              "Public key type unknown. type %02x size %d", type, length);
        }

        if(pStream->remaining() < length - 1)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
              "Failed to read public key. type %02x size %d", type, pStream->remaining() + 1);
            return false;
        }

        data = new uint8_t[length];
        data[0] = type;
        pStream->read(data + 1, length - 1);

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Public Key Read");
#endif
        if(secp256k1_ec_pubkey_parse(mContext, (secp256k1_pubkey *)mData, data, length))
        {
            mValid = true;
            delete[] data;
            return true;
        }

        std::memset(mData, 0, 64);
        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to read public key");
        delete[] data;
        return false;
    }

    void PublicKey::getHash(ArcMist::Hash &pHash) const
    {
        // Calculate hash
        ArcMist::Digest digest(ArcMist::Digest::SHA256_RIPEMD160);
        write(&digest, true, false); // Compressed
        digest.getResult(&pHash);
    }

    ArcMist::String PublicKey::address(bool pTest)
    {
        ArcMist::Hash hash;
        getHash(hash);

        if(pTest)
            return encodeAddress(hash, TEST_PUB_KEY_HASH);
        else
            return encodeAddress(hash, PUB_KEY_HASH);
    }

    ArcMist::String encodeAddress(const ArcMist::Hash &pHash, AddressType pType)
    {
        ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
        ArcMist::Buffer data, check;

        // Calculate check
        digest.writeByte(static_cast<uint8_t>(pType));
        pHash.write(&digest);
        digest.getResult(&check);

        // Write data for address
        data.writeByte(static_cast<uint8_t>(pType));
        pHash.write(&data);
        data.writeUnsignedInt(check.readUnsignedInt());

        // Encode with base 58
        ArcMist::String result;
        result.writeBase58(data.startPointer(), data.length());
        return result;
    }

    bool decodeAddress(const char *pText, ArcMist::Hash &pHash, AddressType &pType)
    {
        ArcMist::Buffer data;

        // Parse address into public key hash
        data.writeBase58AsBinary(pText);

        if(data.length() < 24 || data.length() > 35)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
              "Invalid address length : %d not within (24, 35)", data.length());
            return false;
        }

        pType = static_cast<AddressType>(data.readByte());

        pHash.setSize(data.remaining() - 4);
        pHash.writeStream(&data, data.remaining() - 4);

        uint32_t check = data.readUnsignedInt();

        ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
        data.setReadOffset(0);
        data.readStream(&digest, data.length() - 4);
        ArcMist::Buffer checkHash;
        digest.getResult(&checkHash);

        uint32_t checkValue = checkHash.readUnsignedInt();
        if(checkValue != check)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
              "Invalid address check : %08x != %08x", checkValue, check);
            return false;
        }

        return true;
    }

    void Signature::write(ArcMist::OutputStream *pStream, bool pScriptFormat) const
    {
        size_t length = 73;
        uint8_t output[length];
        if(!secp256k1_ecdsa_signature_serialize_der(mContext, output, &length, (secp256k1_ecdsa_signature*)mData))
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to write signature");
        if(pScriptFormat)
            ScriptInterpreter::writePushDataSize(length + 1, pStream);
        pStream->write(output, length);
        pStream->writeByte(mHashType);
    }

    bool Signature::read(ArcMist::InputStream *pStream, unsigned int pLength, bool pStrictECDSA_DER_Sigs)
    {
        uint8_t input[pLength + 2];
        unsigned int totalLength = pLength - 1;

        pStream->read(input, totalLength);
        mHashType = static_cast<Signature::HashType>(pStream->readByte());

#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Signature Read");
#endif

        if(!pStrictECDSA_DER_Sigs)
        {
            // Hack badly formatted DER signatures
            uint8_t offset = 0;
            uint8_t subLength;
            if(input[offset++] != 0x30) // Compound header byte
            {
                ArcMist::String hex;
                hex.writeHex(input, totalLength);
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Invalid compound header byte in signature (%d bytes) : %s", totalLength, hex.text());
                return false;
            }

            // Full length
            unsigned int fullLengthOffset = offset;
            if(input[offset] != totalLength - 2)
            {
                if(input[offset] < totalLength - 2)
                {
                    // ArcMist::String hex;
                    // hex.writeHex(input, totalLength);
                    // ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_KEY_LOG_NAME,
                      // "Adjusting parse length %d to match total length in signature %d + 2 (header byte and length byte) : %s",
                      // totalLength, input[offset], hex.text());
                    totalLength = input[offset] + 2;
                }
                else
                {
                    ArcMist::String hex;
                    hex.writeHex(input, totalLength);
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                      "Invalid total length byte in signature (%d bytes) : %s", totalLength, hex.text());
                    return false;
                }
            }

            ++offset;

            // Integer header byte
            if(input[offset++] != 0x02)
            {
                ArcMist::String hex;
                hex.writeHex(input, totalLength);
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Invalid R integer header byte in signature (%d bytes) : %s", totalLength, hex.text());
                return false;
            }

            // R length
            subLength = input[offset++];
            if(subLength + offset > totalLength)
            {
                ArcMist::String hex;
                hex.writeHex(input, totalLength);
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "R integer length byte too high in signature (%d bytes) : %s", totalLength, hex.text());
                return false;
            }

            while(input[offset] == 0x00 && !(input[offset+1] & 0x80))
            {
                // ArcMist::String hex;
                // hex.writeHex(input, totalLength);
                // ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_KEY_LOG_NAME,
                  // "Removing extra leading zero byte in R value from signature (%d bytes) : %s", totalLength, hex.text());

                // Adjust lengths
                input[offset-1]--;
                input[fullLengthOffset]--;

                // Extra padding. Remove this
                std::memmove(input + offset, input + offset + 1, totalLength - offset - 1);

                --totalLength;
                --subLength;
            }

            if(input[offset] & 0x80)
            {
                // ArcMist::String hex;
                // hex.writeHex(input, totalLength);
                // ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_KEY_LOG_NAME,
                  // "Adding required leading zero byte in R value to signature (%d bytes) : %s", totalLength, hex.text());

                // Adjust lengths
                input[offset-1]++;
                input[fullLengthOffset]++;

                // Add a zero byte
                std::memmove(input + offset + 1, input + offset, totalLength - offset);
                input[offset] = 0x00;

                ++totalLength;
                ++subLength;
            }

            offset += subLength;

            // Integer header byte
            if(input[offset++] != 0x02)
            {
                ArcMist::String hex;
                hex.writeHex(input, totalLength);
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Invalid S integer header byte in signature (%d bytes) : %s", totalLength, hex.text());
                return false;
            }

            // S length
            subLength = input[offset++];
            if(subLength + offset > totalLength)
            {
                ArcMist::String hex;
                hex.writeHex(input, totalLength);
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "S integer length byte too high in signature (%d bytes) : %s", totalLength, hex.text());
                return false;
            }

            while(input[offset] == 0x00 && !(input[offset+1] & 0x80))
            {
                // ArcMist::String hex;
                // hex.writeHex(input, totalLength);
                // ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_KEY_LOG_NAME,
                  // "Removing extra leading zero byte in S value to signature (%d bytes) : %s", totalLength, hex.text());

                // Adjust lengths
                input[offset-1]--;
                input[fullLengthOffset]--;

                // Extra padding. Remove this
                std::memmove(input + offset, input + offset + 1, totalLength - offset - 1);

                --totalLength;
                --subLength;
            }

            if(input[offset] & 0x80)
            {
                // ArcMist::String hex;
                // hex.writeHex(input, totalLength);
                // ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_KEY_LOG_NAME,
                  // "Adding required leading zero byte in S value from signature (%d bytes) : %s", totalLength, hex.text());

                // Adjust lengths
                input[offset-1]++;
                input[fullLengthOffset]++;

                // Add a zero byte
                std::memmove(input + offset + 1, input + offset, totalLength - offset);
                input[offset] = 0x00;

                ++totalLength;
                ++subLength;
            }

            offset += subLength;
        }

        if(secp256k1_ecdsa_signature_parse_der(mContext, (secp256k1_ecdsa_signature*)mData, input, totalLength))
            return true;

        if(totalLength == 64 && !pStrictECDSA_DER_Sigs)
        {
            if(secp256k1_ecdsa_signature_parse_compact(mContext, (secp256k1_ecdsa_signature*)mData, input))
                return true;
            else
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to parse compact signature (64 bytes)");
                return false;
            }
        }

        ArcMist::String hex;
        hex.writeHex(input, totalLength);
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
          "Failed to parse signature (%d bytes) : %s", totalLength, hex.text());
        return false;
    }

    const uint32_t KeyTree::sVersionValues[4] = { 0x0488ADE4, 0x0488B21E, 0x04358394, 0x043587CF };

    const ArcMist::Hash &KeyTree::KeyData::hash()
    {
        if(isPrivate() || !mHash.isEmpty())
            return mHash;

        ArcMist::Digest digest(ArcMist::Digest::SHA256_RIPEMD160);
        digest.write(mKey, 33);
        digest.getResult(&mHash);
        return mHash;
    }

    void KeyTree::KeyData::clear()
    {
        std::memset(this, 0, sizeof(Key));
        std::memset(this, 0, sizeof(Key));
        std::memset(mParentFingerPrint, 0, 4);
        std::memset(mChainCode, 0, 32);
        std::memset(mKey, 0, 33);

        if(mPublicKey != NULL)
            delete mPublicKey;
        mPublicKey = NULL;

        for(std::vector<KeyData *>::iterator child=mChildren.begin();child!=mChildren.end();++child)
            delete *child;
        mChildren.clear();
    }

    void KeyTree::KeyData::write(ArcMist::OutputStream *pStream) const
    {
        pStream->setOutputEndian(ArcMist::Endian::BIG);
        pStream->writeUnsignedInt(sVersionValues[mVersion]);
        pStream->writeByte(mDepth);
        pStream->write(mParentFingerPrint, 4);
        pStream->writeUnsignedInt(mIndex);
        pStream->write(mChainCode, 32);
        pStream->write(mKey, 33);
    }

    bool KeyTree::KeyData::read(ArcMist::InputStream *pStream)
    {
        clear();

        if(pStream->remaining() < 78)
            return false;

        pStream->setInputEndian(ArcMist::Endian::BIG);
        uint32_t versionValue = pStream->readUnsignedInt();
        switch(versionValue)
        {
        case 0x0488ADE4:
            mVersion = MAINNET_PRIVATE;
            break;
        case 0x0488B21E:
            mVersion = MAINNET_PUBLIC;
            break;
        case 0x04358394:
            mVersion = TESTNET_PRIVATE;
            break;
        case 0x043587CF:
            mVersion = TESTNET_PUBLIC;
            break;
        default:
            return false;
        }
        mDepth = pStream->readByte();
        pStream->read(mParentFingerPrint, 4);
        mIndex = pStream->readUnsignedInt();
        pStream->read(mChainCode, 32);
        pStream->read(mKey, 33);
        return true;
    }

    void KeyTree::KeyData::writeTree(ArcMist::OutputStream *pStream) const
    {
        write(pStream);
        if(isPrivate())
            mPublicKey->writeTree(pStream);

        if(mDepth < 3)
        {
            pStream->writeUnsignedInt(mChildren.size());
            for(std::vector<KeyData *>::const_iterator child=mChildren.begin();child!=mChildren.end();++child)
                (*child)->writeTree(pStream);
        }
    }

    bool KeyTree::KeyData::readTree(ArcMist::InputStream *pStream)
    {
        if(!read(pStream))
            return false;
        if(isPrivate())
        {
            mPublicKey = new KeyData();
            if(!mPublicKey->readTree(pStream))
                return false;
        }

        if(mDepth < 3)
        {
            unsigned int childCount = pStream->readUnsignedInt();
            KeyData *newChild;
            for(unsigned int i=0;i<childCount;++i)
            {
                newChild = new KeyData();
                if(!newChild->readTree(pStream))
                {
                    delete newChild;
                    return false;
                }
                mChildren.push_back(newChild);
            }
        }

        return true;
    }

    ArcMist::String KeyTree::KeyData::encode() const
    {
        ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
        ArcMist::Buffer data, checkSum;
        ArcMist::String result;

        // Calculate check sum
        write(&digest);
        digest.getResult(&checkSum);

        // Write data and check sum to buffer
        write(&data);
        data.writeStream(&checkSum, 4);

        // Convert to base58
        result.writeBase58(data.startPointer(), data.length());

        return result;
    }

    bool KeyTree::KeyData::finalize(secp256k1_context *pContext, Network pNetwork)
    {
        ArcMist::Digest digest(ArcMist::Digest::SHA256_RIPEMD160);
        ArcMist::Buffer result;

        if(mPublicKey != NULL)
            delete mPublicKey;

        if(isPrivate())
        {
            mPublicKey = new KeyData();

            // Create public key
            switch(pNetwork)
            {
            case MAINNET:
                mPublicKey->setInfo(MAINNET_PUBLIC, mDepth, mParentFingerPrint, mIndex);
                break;
            case TESTNET:
                mPublicKey->setInfo(TESTNET_PUBLIC, mDepth, mParentFingerPrint, mIndex);
                break;
            }

            secp256k1_pubkey publicKey;
            if(!secp256k1_ec_pubkey_create(pContext, &publicKey, mKey + 1))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to generate public key for private child key");
                return false;
            }

            size_t compressedLength = 33;
            uint8_t compressedData[33];
            if(!secp256k1_ec_pubkey_serialize(pContext, compressedData, &compressedLength, &publicKey, SECP256K1_EC_COMPRESSED))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to write compressed public key for private child key");
                return false;
            }

            if(compressedLength != 33)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to write compressed public key for private child key. Invalid return length : %d", compressedLength);
                return false;
            }

            mPublicKey->setKey(compressedData + 1, compressedData[0]);
            mPublicKey->setChainCode(chainCode());

            digest.write(compressedData, 33);
        }
        else
        {
            mPublicKey = NULL;
            digest.write(mKey, 33);
        }

        digest.getResult(&result);
        result.read(mFingerPrint, 4); // Fingerprint is first 4 bytes of HASH160
        if(mPublicKey != NULL)
            std::memcpy(mPublicKey->mFingerPrint, mFingerPrint, 4);
        return true;
    }

    KeyTree::KeyData *KeyTree::KeyData::findAddress(const ArcMist::Hash &pHash)
    {
        if(mDepth < 2)
        {
            KeyData *result;
            for(std::vector<KeyData *>::iterator child=mChildren.begin();child!=mChildren.end();++child)
            {
                result = (*child)->findAddress(pHash);
                if(result != NULL)
                    return result;
            }
        }
        else if(mDepth == 2)
        {
            for(std::vector<KeyData *>::iterator child=mChildren.begin();child!=mChildren.end();++child)
                if((*child)->hash() == pHash)
                    return *child;
        }
        else if(pHash == hash())
            return this;

        return NULL;
    }

    KeyTree::KeyData *KeyTree::getAccount(uint32_t pIndex)
    {
        KeyData *result = mMasterKey.findChild(pIndex);
        if(result == NULL)
            result = mMasterKey.deriveChild(mContext, mNetwork, pIndex);
        return result;
    }

    KeyTree::KeyData *KeyTree::getChain(uint32_t pAccountIndex, uint32_t pIndex)
    {
        KeyData *account = getAccount(pAccountIndex);
        if(account == NULL)
            return NULL;
        KeyData *result = account->findChild(pIndex);
        if(result == NULL)
            result = account->deriveChild(mContext, mNetwork, pIndex);
        return result;
    }

    KeyTree::KeyData *KeyTree::getAddress(uint32_t pAccountIndex, uint32_t pChainIndex, uint32_t pIndex)
    {
        KeyData *chain = getChain(pAccountIndex, pChainIndex);
        if(chain == NULL)
            return NULL;
        KeyData *result = chain->findChild(pIndex);
        if(result == NULL)
            result = chain->deriveChild(mContext, mNetwork, pIndex);
        return result;
    }

    KeyTree::KeyData *KeyTree::findAddress(const ArcMist::Hash &pHash)
    {
        return mMasterKey.findAddress(pHash);
    }

    KeyTree::KeyData *KeyTree::KeyData::findChild(uint32_t pIndex)
    {
        for(std::vector<KeyData *>::iterator child=mChildren.begin();child!=mChildren.end();++child)
            if((*child)->index() == pIndex)
                return *child;

        return NULL;
    }

    bool KeyTree::KeyData::sign(secp256k1_context *pContext, ArcMist::Hash &pHash, Signature &pSignature) const
    {
        if(!isPrivate())
            return false;

        if(pHash.size() != 32)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Wrong size hash to sign");
            return false;
        }

        secp256k1_ecdsa_signature signature;
        if(!secp256k1_ecdsa_sign(pContext, &signature, pHash.data(), mKey + 1,
          secp256k1_nonce_function_default, NULL))
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to sign hash");
            return false;
        }

        pSignature.set(signature.data);
        return true;
    }

    bool KeyTree::KeyData::verify(secp256k1_context *pContext, Signature &pSignature, const ArcMist::Hash &pHash) const
    {
        if(isPrivate())
            return mPublicKey->verify(pContext, pSignature, pHash);

        if(pHash.size() != 32)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Wrong size hash to verify");
            return false;
        }

        secp256k1_pubkey publicKey;
        if(!secp256k1_ec_pubkey_parse(pContext, &publicKey, mKey, 33))
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
              "Failed to parse KeyTree Key public key");
            return false;
        }

        if(secp256k1_ecdsa_verify(pContext, (const secp256k1_ecdsa_signature *)pSignature.data(),
          pHash.data(), &publicKey))
            return true;

        // if(!secp256k1_ecdsa_signature_normalize(pContext, (secp256k1_ecdsa_signature *)pSignature.data(),
          // (const secp256k1_ecdsa_signature *)pSignature.data()))
            // return false; // Already normalized

        // // Try it again with the normalized signature
        // if(secp256k1_ecdsa_verify(pContext, (const secp256k1_ecdsa_signature *)pSignature.data(),
          // pHash.data(), publicKey))
            // return true;

        return false;
    }

    KeyTree::KeyData *KeyTree::KeyData::deriveChild(secp256k1_context *pContext, Network pNetwork, uint32_t pIndex)
    {
        KeyData *result = findChild(pIndex);

        if(result != NULL)
            return result; // Already created

        ArcMist::HMACDigest hmac(ArcMist::Digest::SHA512);
        ArcMist::Buffer hmacKey, hmacResult;
        uint8_t newKey[32];

        if(isPrivate())
        {
            result = new KeyData();

            switch(pNetwork)
            {
            case MAINNET:
                result->setInfo(MAINNET_PRIVATE, depth() + 1, fingerPrint(), pIndex);
                break;
            case TESTNET:
                result->setInfo(TESTNET_PRIVATE, depth() + 1, fingerPrint(), pIndex);
                break;
            }

            hmacKey.write(chainCode(), 32);
            hmac.setOutputEndian(ArcMist::Endian::BIG);
            hmac.initialize(&hmacKey);

            if(pIndex >= HARDENED_LIMIT)
            {
                // Index >= 2^31 - Hardened child
                // I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i))
                // Leading zero byte already in private key data
                hmac.write(mKey, 33); // 0x00 || ser256(kpar)
            }
            else
            {
                // Index < 2^31
                // I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i))
                hmac.write(mPublicKey->mKey, 33); // serP(point(kpar))
            }

            hmac.writeUnsignedInt(pIndex); // ser32(i)
            hmac.getResult(&hmacResult);

            // Split I into two 32-byte sequences, IL and IR.

            // The returned child key ki is parse256(IL) + kpar (mod n).
            uint8_t tweak[32];
            hmacResult.read(tweak, 32);
            std::memcpy(newKey, key() + 1, 32);

            if(!secp256k1_ec_privkey_tweak_add(pContext, newKey, tweak))
            {
                delete result;
                return NULL;
            }

            // In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one should proceed
            //   with the next value for i. (Note: this has probability lower than 1 in 2127.)
            if(!secp256k1_ec_seckey_verify(pContext, newKey))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to generate valid private child key");
                delete result;
                return NULL;
            }

            result->setKey(newKey, 0); // Zero for private
        }
        else // Public
        {
            if(pIndex >= HARDENED_LIMIT)
                return NULL;

            result = new KeyData();

            switch(pNetwork)
            {
            case MAINNET:
                result->setInfo(MAINNET_PUBLIC, depth() + 1, fingerPrint(), pIndex);
                break;
            case TESTNET:
                result->setInfo(TESTNET_PUBLIC, depth() + 1, fingerPrint(), pIndex);
                break;
            }

            // I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i))
            hmacKey.write(chainCode(), 32); // Key = cpar
            hmac.setOutputEndian(ArcMist::Endian::BIG);
            hmac.initialize(&hmacKey);

            hmac.write(mKey, 33);
            hmac.writeUnsignedInt(pIndex);
            hmac.getResult(&hmacResult);

            // Split I into two 32-byte sequences, IL and IR.

            // The returned child key Ki is point(parse256(IL)) + Kpar.

            hmacResult.read(newKey, 32);

            // In case parse256(IL) ≥ n or Ki is the point at infinity, the resulting key is invalid,
            //   and one should proceed with the next value for i.
            if(!secp256k1_ec_seckey_verify(pContext, newKey))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to generate valid private key for public child key");
                delete result;
                return NULL;
            }

            // Create public key for new private key
            secp256k1_pubkey *publicKeys[2];
            publicKeys[0] = new secp256k1_pubkey();
            if(!secp256k1_ec_pubkey_create(pContext, publicKeys[0], newKey))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to generate public key for public child key");
                delete publicKeys[0];
                delete result;
                return NULL;
            }

            // Parse parent public key to uncompressed format
            publicKeys[1] = new secp256k1_pubkey();
            if(!secp256k1_ec_pubkey_parse(pContext, publicKeys[1], mKey, 33))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to parse KeyTree Key public key");
                delete publicKeys[0];
                delete publicKeys[1];
                delete result;
                return NULL;
            }

            // Combine generated public key and parent public key into new child key
            secp256k1_pubkey newPublicKey;
            if(!secp256k1_ec_pubkey_combine(pContext, &newPublicKey, publicKeys, 2))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to combine public keys");
                delete result;
                return NULL;
            }

            delete publicKeys[0];
            delete publicKeys[1];

            size_t compressedLength = 33;
            uint8_t compressedData[compressedLength];
            if(!secp256k1_ec_pubkey_serialize(pContext, compressedData, &compressedLength,
              &newPublicKey, SECP256K1_EC_COMPRESSED))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to write compressed public key for public child key");
                delete result;
                return NULL;
            }

            result->setKey(compressedData + 1, compressedData[0]);
        }

        // The returned chain code ci is IR.
        result->writeChainCode(&hmacResult);

        if(result->finalize(pContext, pNetwork))
        {
            mChildren.push_back(result);
            return result;
        }
        else
        {
            delete result;
            return NULL;
        }
    }

    KeyTree::KeyTree()
    {
        mContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

        // Randomize context
        bool finished = false;
        while(!finished)
        {
            generateSeed();
            finished = secp256k1_context_randomize(mContext, mSeed.startPointer());
            mSeed.clear();
        }
    }

    KeyTree::~KeyTree()
    {
        secp256k1_context_destroy(mContext);
    }

    void KeyTree::clear()
    {
        mSeed.clear();
        mMasterKey.clear();
    }

    void KeyTree::generateSeed()
    {
        // Generate 32 bytes of entropy
        mSeed.clear();
        for(unsigned int i=0;i<32;i+=4)
            mSeed.writeUnsignedInt(ArcMist::Math::randomInt());
    }

    bool KeyTree::generateMaster()
    {
        if(mSeed.length() == 0)
            return false;

        switch(mNetwork)
        {
        case MAINNET:
            mMasterKey.setInfo(MAINNET_PRIVATE, 0, (uint8_t *)"\0\0\0\0", 0);
            break;
        case TESTNET:
            mMasterKey.setInfo(TESTNET_PRIVATE, 0, (uint8_t *)"\0\0\0\0", 0);
            break;
        }

        ArcMist::HMACDigest hmac(ArcMist::Digest::SHA512);
        ArcMist::Buffer hmacKey, hmacResult;

        // Calculate HMAC SHA512
        hmacKey.writeString("Bitcoin seed");
        hmac.initialize(&hmacKey);
        mSeed.setReadOffset(0);
        hmac.writeStream(&mSeed, mSeed.length());
        hmac.getResult(&hmacResult);

        // Split HMAC SHA512 into halves for key and chain code
        mMasterKey.writeKey(&hmacResult, 0); // Zero for private key
        mMasterKey.writeChainCode(&hmacResult);

        return secp256k1_ec_seckey_verify(mContext, mMasterKey.key() + 1) && mMasterKey.finalize(mContext, mNetwork);
    }

    void KeyTree::generate(Network pNetwork)
    {
        clear();

        mNetwork = pNetwork;

        // Generate valid seed and master key/code
        generateSeed();
        while(!generateMaster())
            generateSeed(); // Generate a new seed
    }

    bool KeyTree::setSeed(Network pNetwork, ArcMist::InputStream *pStream)
    {
        clear();

        mNetwork = pNetwork;
        mSeed.writeStream(pStream, pStream->length());
        return generateMaster();
    }

    ArcMist::String KeyTree::createMnemonic(Mnemonic::Language pLanguage)
    {
        if(mSeed.length() == 0 || // No seed
          mSeed.length() % 4 != 0) // Seed not multiple of 32 bits
            return ArcMist::String();

        ArcMist::String result;
        ArcMist::Digest digest(ArcMist::Digest::SHA256);
        ArcMist::Buffer checkSum;
        std::vector<bool> bits;
        uint8_t nextByte;

        // Calculate checksum
        mSeed.setReadOffset(0);
        digest.writeStream(&mSeed, mSeed.length());
        digest.getResult(&checkSum);

        int checkSumBits = mSeed.length() / 4; // Entropy bit count / 32

        // Copy seed to bit vector
        mSeed.setReadOffset(0);
        while(mSeed.remaining())
        {
            nextByte = mSeed.readByte();
            for(unsigned int bit=0;bit<8;++bit)
                bits.push_back(ArcMist::Math::bit(nextByte, bit));
        }

        // Append check sum
        while(checkSumBits > 0)
        {
            nextByte = checkSum.readByte();
            for(unsigned int bit=0;bit<8&&checkSumBits>0;++bit,--checkSumBits)
                bits.push_back(ArcMist::Math::bit(nextByte, bit));
        }

        // Parse 11 bits at a time and add words to the sentence
        uint16_t value = 0;
        uint8_t valueBits = 0;
        for(std::vector<bool>::iterator bit=bits.begin();bit!=bits.end();++bit)
        {
            ++valueBits;
            value <<= 1;
            if(*bit)
                value |= 0x01;

            if(valueBits == 11)
            {
                // Add word
                if(result.length() > 0)
                    result += ' ';
                result += Mnemonic::WORDS[pLanguage][value];

                valueBits = 0;
                value = 0;
            }
        }

        if(valueBits > 0)
        {
            // Add word
            if(result.length() > 0)
                result += ' ';
            result += Mnemonic::WORDS[pLanguage][value];

            valueBits = 0;
            value = 0;
        }

        return result;
    }

    bool KeyTree::loadMnemonic(const char *pText)
    {
        std::vector<bool> bits;
        uint16_t value;
        uint8_t valueBits;
        ArcMist::String word;
        bool found;
        const char *ptr;
        int seedBits, checkSumBits;
        ArcMist::Buffer checkSum, mnemonicCheckSum;

        // Loop through languages
        for(unsigned int languageIndex=0;languageIndex<Mnemonic::LANGUAGE_COUNT;++languageIndex)
        {
            // Parse words from text
            bits.clear();
            ptr = pText;
            while(*ptr)
            {
                if(*ptr == ' ' && word.length())
                {
                    // Lookup word in mnemonics and add value to list
                    // TODO Implement binary search
                    found = false;
                    for(value=0;value<Mnemonic::WORD_COUNT;++value)
                        if(word == Mnemonic::WORDS[languageIndex][value])
                        {
                            for(int bit=5;bit<16;++bit)
                            {
                                if(bit >= 8)
                                    bits.push_back(ArcMist::Math::bit(value & 0xff, bit - 8));
                                else
                                    bits.push_back(ArcMist::Math::bit(value >> 8, bit));
                            }
                            found = true;
                            break;
                        }

                    word.clear();

                    if(!found)
                        break;
                }
                else
                    word += ArcMist::lower(*ptr);

                ++ptr;
            }

            if(!found)
                continue; // Next language

            if(word.length())
            {
                found = false;
                for(value=0;value<Mnemonic::WORD_COUNT;++value)
                    if(word == Mnemonic::WORDS[languageIndex][value])
                    {
                        for(int bit=5;bit<16;++bit)
                        {
                            if(bit >= 8)
                                bits.push_back(ArcMist::Math::bit(value & 0xff, bit - 8));
                            else
                                bits.push_back(ArcMist::Math::bit(value >> 8, bit));
                        }
                        found = true;
                        break;
                    }

                if(!found)
                    continue; // Next language
            }

            // Check if values is a valid seed
            if(bits.size() > 128)
            {
                checkSumBits = 0;
                for(unsigned int i=128;i<=256;i+=32)
                    if(bits.size() == i + (i / 32))
                    {
                        seedBits = i;
                        checkSumBits = i / 32;
                        break;
                    }

                if(checkSumBits == 0)
                    continue;

                // Parse bits
                mSeed.clear();
                mnemonicCheckSum.clear();
                value = 0;
                valueBits = 0;
                for(std::vector<bool>::iterator bit=bits.begin();bit!=bits.end();++bit)
                {
                    --seedBits;
                    ++valueBits;
                    value <<= 1;
                    if(*bit)
                        value |= 0x01;

                    if(valueBits == 8)
                    {
                        if(seedBits >= 0)
                            mSeed.writeByte(value);
                        else
                            mnemonicCheckSum.writeByte(value);
                        value = 0;
                        valueBits = 0;
                    }
                }

                if(valueBits > 0)
                {
                    if(valueBits < 8)
                        value <<= (8 - valueBits);
                    if(seedBits >= 0)
                        mSeed.writeByte(value);
                    else
                        mnemonicCheckSum.writeByte(value);
                }

                ArcMist::Digest digest(ArcMist::Digest::SHA256);

                // Calculate checksum
                mSeed.setReadOffset(0);
                digest.writeStream(&mSeed, mSeed.length());
                checkSum.clear();
                digest.getResult(&checkSum);

                // Verify checksum
                bool matches = true;
                for(int bit=checkSumBits;bit>0;bit-=8)
                {
                    if(bit >= 8)
                    {
                        if(checkSum.readByte() != mnemonicCheckSum.readByte())
                        {
                            matches = false;
                            break;
                        }
                    }
                    else if((checkSum.readByte() >> bit) != (mnemonicCheckSum.readByte() >> bit))
                    {
                        matches = false;
                        break;
                    }
                }

                if(matches)
                    return true;
            }
        }

        return false;
    }

    void KeyTree::write(ArcMist::OutputStream *pStream)
    {
        pStream->writeByte(1); // Version
        pStream->writeByte(mNetwork);
        mSeed.setReadOffset(0);
        pStream->writeUnsignedInt(mSeed.length());
        pStream->writeStream(&mSeed, mSeed.length());
        mMasterKey.writeTree(pStream);
    }

    bool KeyTree::read(ArcMist::InputStream *pStream)
    {
        if(pStream->remaining() < 6)
            return false;

        if(pStream->readByte() != 1) // Version
            return false;

        mNetwork = (Network)pStream->readByte();

        mSeed.clear();
        unsigned int seedLength = pStream->readUnsignedInt();
        if(seedLength == 0)
            return true;

        if(pStream->remaining() < seedLength)
            return false;

        pStream->readStream(&mSeed, seedLength);

        return mMasterKey.readTree(pStream);
    }

    bool Key::test()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "------------- Starting Key Tests -------------");

        bool success = true;
        PrivateKey privateKey;
        PublicKey publicKey;

        /***********************************************************************************************
         * Private Key Generate
         ***********************************************************************************************/
        if(privateKey.generate())
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed Private Key Generate : %s", privateKey.hex().text());
        else
        {
            success = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed Private Key Generate : %s", privateKey.hex().text());
        }

        /***********************************************************************************************
         * Public Key Generate
         ***********************************************************************************************/
        if(privateKey.generatePublicKey(publicKey))
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed Public Key Generate : %s", publicKey.hex().text());
        else
        {
            success = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed Public Key Generate : %s", publicKey.hex().text());
        }

        /***********************************************************************************************
         * Read Public Key
         ***********************************************************************************************/
        ArcMist::Buffer buffer;
        PublicKey readPublicKey;
        publicKey.write(&buffer, true, false);

        if(readPublicKey.read(&buffer))
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed Read Public Key : %s", readPublicKey.hex().text());
        else
        {
            success = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed Read Public Key : %s", readPublicKey.hex().text());
        }

        /***********************************************************************************************
         * Read Public Key Compare
         ***********************************************************************************************/
        if(readPublicKey == publicKey)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed Read Public Key Compare : %s", readPublicKey.hex().text());
        else
        {
            success = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed Read Public Key Compare : %s", readPublicKey.hex().text());
        }

        /***********************************************************************************************
         * Sign Hash
         ***********************************************************************************************/
        ArcMist::Hash hash(32);
        Signature signature;
        hash.randomize(); // Generate random hash

        if(privateKey.sign(hash, signature))
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed Sign Hash : %s", signature.hex().text());
        else
        {
            success = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed Sign Hash : %s", signature.hex().text());
        }

        /***********************************************************************************************
         * Verify signature
         ***********************************************************************************************/
        if(signature.verify(publicKey, hash))
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed Verify Signature");
        else
        {
            success = false;
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed Verify Signature");
        }

        /***********************************************************************************************
         * Verify Signature Incorrect
         ***********************************************************************************************/
        hash.zeroize();
        if(!signature.verify(publicKey, hash))
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed Verify Sign Incorrect");
        else
        {
            success = false;
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed Verify Sign Incorrect");
        }

        /***********************************************************************************************
         * Encode address
         ***********************************************************************************************/
        ArcMist::Buffer data;
        AddressType addressType;
        ArcMist::Hash checkHash;

        // for(unsigned int i=0;i<64;i+=4)
            // data.writeUnsignedInt(ArcMist::Math::randomInt());

        data.writeHex("d7e09f05ef4e2a311b95877749f64a4b4c27576a4b5bea423116d0057825583ea5f6e606a981e223f0d5e55b65cd4a6dfae5241de08dee4c13d9ad67cc1bd224");
        publicKey.set(data.startPointer());
        publicKey.getHash(hash);

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Key : %s", publicKey.hex().text());
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Hash : %s", hash.hex().text());

        ArcMist::String address = publicKey.address();
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Address : %s", address.text());

        if(address == "162pwaq8Q269SexzQFQEWmhzRNW3TWFC3J")
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed encode public key hash address");
        else
        {
            success = false;
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed encode public key hash address");
        }

        if(decodeAddress(address, checkHash, addressType))
        {
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed decode address");

            if(addressType == PUB_KEY_HASH)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed decode address type");
            else
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed decode address type : %d",
                  addressType);
            }

            if(hash == checkHash)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed decode address hash");
            else
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed decode address hash : %s",
                  checkHash.hex().text());
            }
        }
        else
        {
            success = false;
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed decode address");
        }

        /***********************************************************************************************
         * Decode address
         ***********************************************************************************************/
        if(decodeAddress("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem", hash, addressType))
        {
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed decode address");

            if(addressType == PUB_KEY_HASH)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed decode address type");
            else
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed decode address type : %d",
                  addressType);
            }
        }
        else
        {
            success = false;
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed decode address");
        }

        /***********************************************************************************************
         * BIP-0032 Test Vector 1
         ***********************************************************************************************/
        KeyTree keyTree;
        ArcMist::Buffer keyTreeSeed;
        ArcMist::String correctEncoding, resultEncoding;

        /***********************************************************************************************
         * Chain m
         * ext pub: xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8
         * ext prv: xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
         ***********************************************************************************************/
        if(success)
        {
            keyTreeSeed.clear();
            keyTreeSeed.writeHex("000102030405060708090a0b0c0d0e0f");
            keyTree.setSeed(MAINNET, &keyTreeSeed);

            resultEncoding = keyTree.master().encode();
            correctEncoding = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
            if(correctEncoding == resultEncoding)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                  "Passed BIP-0032 Test Vector 1 Master Key Private");
            else
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 Master Key Private");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultEncoding.text());
            }

            resultEncoding = keyTree.master().publicKey()->encode();
            correctEncoding = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
            if(correctEncoding == resultEncoding)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                  "Passed BIP-0032 Test Vector 1 Master Key Public");
            else
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 Master Key Public");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultEncoding.text());
            }
        }

        /***********************************************************************************************
         * Chain m/0H
         * ext pub: xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw
         * ext prv: xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7
         ***********************************************************************************************/
        KeyTree::KeyData *m0hKey;
        if(success)
        {
            m0hKey = keyTree.deriveChild(&keyTree.master(), KeyTree::HARDENED_LIMIT + 0);
            if(m0hKey == NULL)
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H Private : Derive Failed");
            }
            else
            {
                resultEncoding = m0hKey->encode();
                correctEncoding = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
                if(correctEncoding == resultEncoding)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                      "Passed BIP-0032 Test Vector 1 m/0H Private");
                else
                {
                    success = false;
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H Private");
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Correct : %s", correctEncoding.text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Result  : %s", resultEncoding.text());
                }

            }
        }

        if(success)
        {
            resultEncoding = m0hKey->publicKey()->encode();
            correctEncoding = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";
            if(correctEncoding == resultEncoding)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                  "Passed BIP-0032 Test Vector 1 m/0H Public");
            else
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H Public");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultEncoding.text());
            }
        }

        /***********************************************************************************************
         * Chain m/0H/1
         * ext pub: xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ
         * ext prv: xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs
         ***********************************************************************************************/
        KeyTree::KeyData *m0h1Key;
        if(success)
        {
            m0h1Key = keyTree.deriveChild(m0hKey, 1);
            if(m0h1Key == NULL)
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1 Private : Derive Failed");
            }
            else
            {
                resultEncoding = m0h1Key->encode();
                correctEncoding = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
                if(correctEncoding == resultEncoding)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                      "Passed BIP-0032 Test Vector 1 m/0H/1 Private");
                else
                {
                    success = false;
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1 Private");
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Correct : %s", correctEncoding.text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Result  : %s", resultEncoding.text());
                }

            }
        }

        if(success)
        {
            resultEncoding = m0h1Key->publicKey()->encode();
            correctEncoding = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";
            if(correctEncoding == resultEncoding)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                  "Passed BIP-0032 Test Vector 1 m/0H/1 Public");
            else
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1 Public");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultEncoding.text());
            }
        }

        /***********************************************************************************************
         * Chain m/0H/1 Public Only Derivation
         * ext pub: xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ
         ***********************************************************************************************/
        KeyTree::KeyData *m0h1PublicKey;
        if(success)
        {
            m0h1PublicKey = keyTree.deriveChild(m0hKey->publicKey(), 1);
            if(m0h1PublicKey == NULL)
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1 Public Only : Derive Failed");
            }
            else
            {
                resultEncoding = m0h1PublicKey->encode();
                correctEncoding = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";
                if(correctEncoding == resultEncoding)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                      "Passed BIP-0032 Test Vector 1 m/0H/1 Public Only");
                else
                {
                    success = false;
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1 Public Only");
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Correct : %s", correctEncoding.text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Result  : %s", resultEncoding.text());
                }

            }
        }

        /***********************************************************************************************
         * Chain m/0H/1/2H
         * ext pub: xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5
         * ext prv: xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM
         ***********************************************************************************************/
        KeyTree::KeyData *m0h12hKey;
        if(success)
        {
            m0h12hKey = keyTree.deriveChild(m0h1Key, KeyTree::HARDENED_LIMIT + 2);
            if(m0h12hKey == NULL)
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1/2h Private : Derive Failed");
            }
            else
            {
                resultEncoding = m0h12hKey->encode();
                correctEncoding = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM";
                if(correctEncoding == resultEncoding)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                      "Passed BIP-0032 Test Vector 1 m/0H/1/2h Private");
                else
                {
                    success = false;
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1/2h Private");
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Correct : %s", correctEncoding.text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Result  : %s", resultEncoding.text());
                }

            }
        }

        if(success)
        {
            resultEncoding = m0h12hKey->publicKey()->encode();
            correctEncoding = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
            if(correctEncoding == resultEncoding)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                  "Passed BIP-0032 Test Vector 1 m/0H/1/2h Public");
            else
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1/2h Public");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultEncoding.text());
            }
        }

        /***********************************************************************************************
         * Chain m/0H/1/2H/2
         * ext pub: xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV
         * ext prv: xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334
         ***********************************************************************************************/
        KeyTree::KeyData *m0h12h2Key;
        if(success)
        {
            m0h12h2Key = keyTree.deriveChild(m0h12hKey, 2);
            if(m0h12h2Key == NULL)
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1/2h/2 Private : Derive Failed");
            }
            else
            {
                resultEncoding = m0h12h2Key->encode();
                correctEncoding = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334";
                if(correctEncoding == resultEncoding)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                      "Passed BIP-0032 Test Vector 1 m/0H/1/2h/2 Private");
                else
                {
                    success = false;
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1/2h/2 Private");
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Correct : %s", correctEncoding.text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Result  : %s", resultEncoding.text());
                }

            }
        }

        if(success)
        {
            resultEncoding = m0h12h2Key->publicKey()->encode();
            correctEncoding = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV";
            if(correctEncoding == resultEncoding)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                  "Passed BIP-0032 Test Vector 1 m/0H/1/2h/2 Public");
            else
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1/2h/2 Public");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultEncoding.text());
            }
        }

        /***********************************************************************************************
         * Chain m/0H/1/2H/2/1000000000
         * ext pub: xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy
         * ext prv: xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76
         ***********************************************************************************************/
        KeyTree::KeyData *m0h12h21000000000Key;
        if(success)
        {
            m0h12h21000000000Key = keyTree.deriveChild(m0h12h2Key, 1000000000);
            if(m0h12h21000000000Key == NULL)
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1/2h/2/1000000000 Private : Derive Failed");
            }
            else
            {
                resultEncoding = m0h12h21000000000Key->encode();
                correctEncoding = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76";
                if(correctEncoding == resultEncoding)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                      "Passed BIP-0032 Test Vector 1 m/0H/1/2h/2/1000000000 Private");
                else
                {
                    success = false;
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1/2h/2/1000000000 Private");
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Correct : %s", correctEncoding.text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Result  : %s", resultEncoding.text());
                }

            }
        }

        if(success)
        {
            resultEncoding = m0h12h21000000000Key->publicKey()->encode();
            correctEncoding = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy";
            if(correctEncoding == resultEncoding)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                  "Passed BIP-0032 Test Vector 1 m/0H/1/2h/2/1000000000 Public");
            else
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 1 m/0H/1/2h/2/1000000000 Public");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultEncoding.text());
            }
        }

        /***********************************************************************************************
         * BIP-0032 Test Vector 3
         ***********************************************************************************************/

        /***********************************************************************************************
         * Chain m
         * ext pub: xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13
         * ext prv: xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6
         ***********************************************************************************************/
        if(success)
        {
            keyTreeSeed.clear();
            keyTreeSeed.writeHex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");
            keyTree.setSeed(MAINNET, &keyTreeSeed);

            resultEncoding = keyTree.master().encode();
            correctEncoding = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6";
            if(correctEncoding == resultEncoding)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                  "Passed BIP-0032 Test Vector 3 Master Key Private");
            else
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 3 Master Key Private");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultEncoding.text());
            }

            resultEncoding = keyTree.master().publicKey()->encode();
            correctEncoding = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";
            if(correctEncoding == resultEncoding)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                  "Passed BIP-0032 Test Vector 3 Master Key Public");
            else
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 3 Master Key Public");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultEncoding.text());
            }
        }

        /***********************************************************************************************
         * Chain m/0H
         * ext pub: xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y
         * ext prv: xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L
         ***********************************************************************************************/
        if(success)
        {
            m0hKey = keyTree.deriveChild(&keyTree.master(), KeyTree::HARDENED_LIMIT + 0);
            if(m0hKey == NULL)
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 3 m/0H Private : Derive Failed");
            }
            else
            {
                resultEncoding = m0hKey->encode();
                correctEncoding = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L";
                if(correctEncoding == resultEncoding)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                      "Passed BIP-0032 Test Vector 3 m/0H Private");
                else
                {
                    success = false;
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 3 m/0H Private");
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Correct : %s", correctEncoding.text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Result  : %s", resultEncoding.text());
                }

            }
        }

        if(success)
        {
            resultEncoding = m0hKey->publicKey()->encode();
            correctEncoding = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y";
            if(correctEncoding == resultEncoding)
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                  "Passed BIP-0032 Test Vector 3 m/0H Public");
            else
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed BIP-0032 Test Vector 3 m/0H Public");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultEncoding.text());
            }
        }

        /***********************************************************************************************
         * BIP-0039 Trezor Test Vectors
         ***********************************************************************************************/
        ArcMist::Buffer resultSeed, correctSeed;
        ArcMist::String resultMnemonic, correctMnemonic;
        unsigned int trezorCount = 24;

        const char *trezorSeedHex[] =
        {
            "00000000000000000000000000000000",
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "80808080808080808080808080808080",
            "ffffffffffffffffffffffffffffffff",
            "000000000000000000000000000000000000000000000000",
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "808080808080808080808080808080808080808080808080",
            "ffffffffffffffffffffffffffffffffffffffffffffffff",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "8080808080808080808080808080808080808080808080808080808080808080",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "9e885d952ad362caeb4efe34a8e91bd2",
            "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "c0ba5a8e914111210f2bd131f3d5e08d",
            "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
            "23db8160a31d3e0dca3688ed941adbf3",
            "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
            "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
            "f30f8c1da665478f49b001d94c5fc452",
            "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f"
        };

        const char *trezorSeedMnemonic[] =
        {
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            "scheme spot photo card baby mountain device kick cradle pact join borrow",
            "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            "cat swing flag economy stadium alone churn speed unique patch report train",
            "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            "vessel ladder alter error federal sibling chat ability sun glass valve picture",
            "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"
        };

        const char *trezorKeyEncoding[] =
        {
            "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF",
            "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq",
            "xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq",
            "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd",
            "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU",
            "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7",
            "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae",
            "xprv9s21ZrQH143K36Ao5jHRVhFGDbLP6FCx8BEEmpru77ef3bmA928BxsqvVM27WnvvyfWywiFN8K6yToqMaGYfzS6Db1EHAXT5TuyCLBXUfdm",
            "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM",
            "xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU",
            "xprv9s21ZrQH143K3CSnQNYC3MqAAqHwxeTLhDbhF43A4ss4ciWNmCY9zQGvAKUSqVUf2vPHBTSE1rB2pg4avopqSiLVzXEU8KziNnVPauTqLRo",
            "xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB",
            "xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH",
            "xprv9s21ZrQH143K3uT8eQowUjsxrmsA9YUuQQK1RLqFufzybxD6DH6gPY7NjJ5G3EPHjsWDrs9iivSbmvjc9DQJbJGatfa9pv4MZ3wjr8qWPAK",
            "xprv9s21ZrQH143K2XTAhys3pMNcGn261Fi5Ta2Pw8PwaVPhg3D8DWkzWQwjTJfskj8ofb81i9NP2cUNKxwjueJHHMQAnxtivTA75uUFqPFeWzk",
            "xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6",
            "xprv9s21ZrQH143K3R1SfVZZLtVbXEB9ryVxmVtVMsMwmEyEvgXN6Q84LKkLRmf4ST6QrLeBm3jQsb9gx1uo23TS7vo3vAkZGZz71uuLCcywUkt",
            "xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems",
            "xprv9s21ZrQH143K4G28omGMogEoYgDQuigBo8AFHAGDaJdqQ99QKMQ5J6fYTMfANTJy6xBmhvsNZ1CJzRZ64PWbnTFUn6CDV2FxoMDLXdk95DQ",
            "xprv9s21ZrQH143K3wtsvY8L2aZyxkiWULZH4vyQE5XkHTXkmx8gHo6RUEfH3Jyr6NwkJhvano7Xb2o6UqFKWHVo5scE31SGDCAUsgVhiUuUDyh",
            "xprv9s21ZrQH143K3rEfqSM4QZRVmiMuSWY9wugscmaCjYja3SbUD3KPEB1a7QXJoajyR2T1SiXU7rFVRXMV9XdYVSZe7JoUXdP4SRHTxsT1nzm",
            "xprv9s21ZrQH143K2QWV9Wn8Vvs6jbqfF1YbTCdURQW9dLFKDovpKaKrqS3SEWsXCu6ZNky9PSAENg6c9AQYHcg4PjopRGGKmdD313ZHszymnps",
            "xprv9s21ZrQH143K4aERa2bq7559eMCCEs2QmmqVjUuzfy5eAeDX4mqZffkYwpzGQRE2YEEeLVRoH4CSHxianrFaVnMN2RYaPUZJhJx8S5j6puX",
            "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS",
        };

        /***********************************************************************************************
         * BIP-0039 Trezor Test 1
         ***********************************************************************************************/
        bool trezorPassed = true;
        for(unsigned int i=0;i<trezorCount;++i)
        {
            correctSeed.clear();
            correctSeed.writeHex(trezorSeedHex[i]);
            correctMnemonic = trezorSeedMnemonic[i];
            correctEncoding = trezorKeyEncoding[i];

            keyTree.setSeed(MAINNET, &correctSeed);
            resultMnemonic = keyTree.createMnemonic(Mnemonic::English);

            if(resultMnemonic != correctMnemonic)
            {
                trezorPassed = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed BIP-0039 Trezor Test %d Create Mnemonic", i + 1);
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctMnemonic.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultMnemonic.text());
            }

            if(!keyTree.loadMnemonic(correctMnemonic))
            {
                trezorPassed = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed BIP-0039 Trezor Test %d Load Mnemonic : Failed to load", i + 1);
            }
            else
            {
                correctSeed.setReadOffset(0);
                resultSeed.clear();
                keyTree.readSeed(&resultSeed);

                if(resultSeed != correctSeed)
                {
                    trezorPassed = false;
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Failed BIP-0039 Trezor Test %d Load Mnemonic", i + 1);
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Correct : %s", correctSeed.readHexString(correctSeed.length()).text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Result  : %s", resultSeed.readHexString(resultSeed.length()).text());
                }
            }
        }

        if(trezorPassed)
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed BIP-0039 Trezor Test Vector");

        return success;
    }
}
