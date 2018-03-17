/**************************************************************************
 * Copyright 2017-2018 ArcMist, LLC                                       *
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
    unsigned int Key::sContextFlags = 0;
    ArcMist::Mutex Key::sMutex("SECP256K1");

    void randomizeContext(secp256k1_context *pContext)
    {
        bool finished = false;
        uint8_t entropy[32];
        uint32_t random;
        while(!finished)
        {
            // Generate entropy
            for(unsigned int i=0;i<32;i+=4)
            {
                random = ArcMist::Math::randomInt();
                std::memcpy(entropy + i, &random, 4);
            }
            finished = secp256k1_context_randomize(pContext, entropy);
        }
    }

    secp256k1_context *Key::context(unsigned int pFlags)
    {
        sMutex.lock();
        if(sContext == NULL)
        {
            // Create context
            sContext = secp256k1_context_create(pFlags);
            sContextFlags = pFlags;
            if(pFlags & SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
                randomizeContext(sContext);
            std::atexit(destroyContext);
        }
        else if((sContextFlags & pFlags) != pFlags)
        {
            // Recreate context with new flags
            secp256k1_context_destroy(sContext);
            sContext = secp256k1_context_create(pFlags);
            sContextFlags = pFlags;
            if(pFlags & SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
                randomizeContext(sContext);
        }
        sMutex.unlock();

        return sContext;
    }

    void Key::destroyContext()
    {
        secp256k1_context_destroy(sContext);
        sContext = NULL;
    }

    // PrivateKey::PrivateKey()
    // {
        // // Create context with sign ability
        // mContext = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        // std::memset(mData, 0, 32);
    // }

    // PrivateKey::~PrivateKey()
    // {
        // secp256k1_context_destroy(mContext);
    // }

    // bool PrivateKey::generate()
    // {
        // bool valid;

        // uint32_t random;
        // for(unsigned int i=0;i<32;i+=4)
        // {
            // random = ArcMist::Math::randomInt();
            // std::memcpy(mData + i, &random, 4);
        // }

        // valid = secp256k1_ec_seckey_verify(mContext, mData);

        // if(!valid)
            // ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to generate private key");

        // return valid;
    // }

    // ArcMist::String PrivateKey::hex() const
    // {
        // ArcMist::String result;
        // result.writeHex(mData, 32);
        // return result;
    // }

    // bool PrivateKey::generatePublicKey(PublicKey &pPublicKey) const
    // {
        // secp256k1_pubkey pubkey;
        // if(!secp256k1_ec_pubkey_create(mContext, &pubkey, mData))
        // {
            // ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to generate public key");
            // return false;
        // }

        // pPublicKey.set(pubkey.data);
        // return true;
    // }

    // bool PrivateKey::sign(ArcMist::Hash &pHash, Signature &pSignature) const
    // {
        // if(pHash.size() != 32)
        // {
            // ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Wrong size hash to verify");
            // return false;
        // }

// #ifdef PROFILER_ON
        // ArcMist::Profiler profiler("Private Key Sign");
// #endif
        // secp256k1_ecdsa_signature signature;
        // if(!secp256k1_ecdsa_sign(mContext, &signature, pHash.data(), mData,
          // secp256k1_nonce_function_default, NULL))
        // {
            // ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to sign hash");
            // return false;
        // }

        // pSignature.set(signature.data);
        // return true;
    // }

    // bool Signature::verify(const PublicKey &pPublicKey, const ArcMist::Hash &pHash) const
    // {
        // if(!pPublicKey.isValid())
        // {
            // ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Invalid public key. Can't verify.");
            // return false;
        // }

        // if(pHash.size() != 32)
        // {
            // ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Wrong size hash to verify");
            // return false;
        // }

// #ifdef PROFILER_ON
        // ArcMist::Profiler profiler("Signature Verify");
// #endif
        // if(secp256k1_ecdsa_verify(mContext, (const secp256k1_ecdsa_signature *)mData,
          // pHash.data(), (const secp256k1_pubkey *)pPublicKey.data()))
            // return true;

        // if(!secp256k1_ecdsa_signature_normalize(mContext, (secp256k1_ecdsa_signature *)mData,
          // (const secp256k1_ecdsa_signature *)mData))
            // return false; // Already normalized

        // // Try it again with the normalized signature
        // if(secp256k1_ecdsa_verify(mContext, (const secp256k1_ecdsa_signature *)mData,
          // pHash.data(), (const secp256k1_pubkey *)pPublicKey.data()))
            // return true;

        // return false;
    // }

    ArcMist::String Signature::hex() const
    {
        ArcMist::String result;
        result.writeHex(mData, 64);
        return result;
    }

    // ArcMist::String PublicKey::hex() const
    // {
        // ArcMist::String result;
        // result.writeHex(mData, 64);
        // return result;
    // }

    // void PublicKey::write(ArcMist::OutputStream *pStream, bool pCompressed, bool pScriptFormat) const
    // {
        // if(pCompressed)
        // {
            // size_t compressedLength = 33;
            // uint8_t compressedData[compressedLength];
            // if(!secp256k1_ec_pubkey_serialize(mContext, compressedData, &compressedLength, (const secp256k1_pubkey *)mData, SECP256K1_EC_COMPRESSED))
                // ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to write compressed public key");
            // else
            // {
                // if(pScriptFormat)
                    // ScriptInterpreter::writePushDataSize(compressedLength, pStream);
                // pStream->write(compressedData, compressedLength);
            // }
        // }
        // else
        // {
            // size_t length = 65;
            // uint8_t data[length];
            // if(!secp256k1_ec_pubkey_serialize(mContext, data, &length, (const secp256k1_pubkey *)mData, 0))
                // ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to write public key");
            // else
            // {
                // if(pScriptFormat)
                    // ScriptInterpreter::writePushDataSize(length, pStream);
                // pStream->write(data, length);
            // }
        // }
    // }

    // bool PublicKey::read(ArcMist::InputStream *pStream)
    // {
        // size_t length;
        // uint8_t *data;
        // mValid = false;

        // if(pStream->remaining() < 1)
            // return false;

        // // Check first byte to determine length
        // uint8_t type = pStream->readByte();
        // if(type == 0x02 || type == 0x03) // Compressed
            // length = 33;
        // else if(type == 0x04) // Uncompressed
            // length = 65;
        // else // Unknown
        // {
            // length = pStream->remaining() + 1;
            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
              // "Public key type unknown. type %02x size %d", type, length);
        // }

        // if(pStream->remaining() < length - 1)
        // {
            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
              // "Failed to read public key. type %02x size %d", type, pStream->remaining() + 1);
            // return false;
        // }

        // data = new uint8_t[length];
        // data[0] = type;
        // pStream->read(data + 1, length - 1);

// #ifdef PROFILER_ON
        // ArcMist::Profiler profiler("Public Key Read");
// #endif
        // if(secp256k1_ec_pubkey_parse(mContext, (secp256k1_pubkey *)mData, data, length))
        // {
            // mValid = true;
            // delete[] data;
            // return true;
        // }

        // std::memset(mData, 0, 64);
        // ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to read public key");
        // delete[] data;
        // return false;
    // }

    // void PublicKey::getHash(ArcMist::Hash &pHash) const
    // {
        // // Calculate hash
        // ArcMist::Digest digest(ArcMist::Digest::SHA256_RIPEMD160);
        // write(&digest, true, false); // Compressed
        // digest.getResult(&pHash);
    // }

    // ArcMist::String PublicKey::address(bool pTest)
    // {
        // ArcMist::Hash hash;
        // getHash(hash);

        // if(pTest)
            // return encodeAddress(hash, TEST_PUB_KEY_HASH);
        // else
            // return encodeAddress(hash, PUB_KEY_HASH);
    // }

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
        if(!secp256k1_ecdsa_signature_serialize_der(Key::context(SECP256K1_CONTEXT_NONE), output,
          &length, (secp256k1_ecdsa_signature*)mData))
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

        secp256k1_context *thisContext = Key::context(SECP256K1_CONTEXT_NONE);
        if(secp256k1_ecdsa_signature_parse_der(thisContext, (secp256k1_ecdsa_signature*)mData, input, totalLength))
            return true;

        if(totalLength == 64 && !pStrictECDSA_DER_Sigs)
        {
            if(secp256k1_ecdsa_signature_parse_compact(thisContext, (secp256k1_ecdsa_signature*)mData, input))
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

    const ArcMist::Hash &Key::hash() const
    {
        if(isPrivate() && mPublicKey != NULL)
            return mPublicKey->hash();
        else
            return mHash;
    }

    ArcMist::String Key::address() const
    {
        if(isPrivate())
        {
            if(mPublicKey != NULL)
                return mPublicKey->address();
            else
                return NULL;
        }

        switch(mVersion)
        {
        case MAINNET_PRIVATE:
        case MAINNET_PUBLIC:
            return encodeAddress(hash(), PUB_KEY_HASH);
        case TESTNET_PRIVATE:
        case TESTNET_PUBLIC:
            return encodeAddress(hash(), TEST_PUB_KEY_HASH);
        default:
            return ArcMist::String();
        }
    }

    void Key::clear()
    {
        mVersion = 0;
        mDepth = 0;
        std::memset(mParentFingerPrint, 0, 4);
        mIndex = 0;
        std::memset(mChainCode, 0, 32);
        std::memset(mKey, 0, 33);

        if(mPublicKey != NULL)
            delete mPublicKey;
        mPublicKey = NULL;

        for(std::vector<Key *>::iterator child=mChildren.begin();child!=mChildren.end();++child)
            delete *child;
        mChildren.clear();

        mHash.clear();
        mUsed = false;
    }

    bool Key::readPublic(ArcMist::InputStream *pStream)
    {
        clear();

        mDepth = -1;
        mIndex = -1;

        if(pStream->remaining() < 33)
            return false;

        mKey[0] = pStream->readByte();

        if(mKey[0] == 0x04) // Uncompressed
        {
            if(pStream->remaining() < 64)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to read public key. type %02x size %d", mKey[0], pStream->remaining() + 1);
                return false;
            }

            uint8_t data[65];
            data[0] = mKey[0];
            pStream->read(data + 1, 64);

            // Convert to compressed public key
            secp256k1_context *thisContext = context(SECP256K1_CONTEXT_NONE);
            secp256k1_pubkey pubkey;

            if(!secp256k1_ec_pubkey_parse(thisContext, &pubkey, data, 65))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to parse public key");
                return false;
            }

            size_t length = 33;
            if(!secp256k1_ec_pubkey_serialize(context(SECP256K1_CONTEXT_VERIFY), mKey, &length,
              &pubkey, SECP256K1_EC_COMPRESSED) || length != 33)
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to compress public key");
                return false;
            }

            // Calculate hash
            ArcMist::Digest hash(ArcMist::Digest::SHA256_RIPEMD160);
            hash.write(mKey, 33);
            hash.getResult(&mHash);

            return true;
        }
        else if(mKey[0] == 0x02 || mKey[0] == 0x03) // Compressed
        {
            if(pStream->remaining() < 32)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to read public key. type %02x size %d", mKey[0], pStream->remaining() + 1);
                return false;
            }

            pStream->read(mKey + 1, 32);

            // Calculate hash
            ArcMist::Digest hash(ArcMist::Digest::SHA256_RIPEMD160);
            hash.write(mKey, 33);
            hash.getResult(&mHash);

            return true;
        }
        else // Unknown type
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
              "Public key type unknown. type %02x", mKey[0]);
            return false;
        }
    }

    bool Key::writePublic(ArcMist::OutputStream *pStream, bool pScriptFormat) const
    {
        if(isPrivate()) // Private or key missing
            return false;

        if(pScriptFormat)
            ScriptInterpreter::writePushDataSize(33, pStream);
        pStream->write(mKey, 33);
        return true;
    }

    bool Key::readPrivate(ArcMist::InputStream *pStream)
    {
        clear();

        mDepth = -1;
        mIndex = -1;

        if(pStream->remaining() < 32)
            return false;

        mKey[0] = 0; // Private
        pStream->read(mKey + 1, 32);
        return true;
    }

    bool Key::writePrivate(ArcMist::OutputStream *pStream, bool pScriptFormat) const
    {
        if(!isPrivate()) // Not private
            return false;

        pStream->write(mKey + 1, 32);
        return true;
    }

    void Key::generatePrivate(Network pNetwork)
    {
        clear();

        secp256k1_context *thisContext = context(SECP256K1_CONTEXT_NONE);

        mDepth = -1;
        mIndex = -1;

        while(true)
        {
            // Generate entropy
            unsigned int random;
            for(unsigned int i=0;i<32;i+=4)
            {
                random = ArcMist::Math::randomInt();
                std::memcpy(mKey + 1 + i, &random, 4);
            }

            // Check validity
            if(secp256k1_ec_seckey_verify(thisContext, mKey + 1))
            {
                // Create public key
                finalize();
                return;
            }
        }
    }

    void Key::loadHash(const ArcMist::Hash &pHash)
    {
        clear();

        mDepth = -1;
        mIndex = -1;
        mHash = pHash;
    }

    const uint32_t Key::sVersionValues[4] = { 0x0488ADE4, 0x0488B21E, 0x04358394, 0x043587CF };

    void Key::write(ArcMist::OutputStream *pStream) const
    {
        pStream->setOutputEndian(ArcMist::Endian::BIG);
        pStream->writeUnsignedInt(sVersionValues[mVersion]);
        pStream->writeByte(mDepth);
        pStream->write(mParentFingerPrint, 4);
        pStream->writeUnsignedInt(mIndex);
        pStream->write(mChainCode, 32);
        pStream->write(mKey, 33);
    }

    bool Key::read(ArcMist::InputStream *pStream)
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

    void Key::writeTree(ArcMist::OutputStream *pStream) const
    {
        write(pStream);
        pStream->writeByte(mUsed);
        if(isPrivate())
            mPublicKey->writeTree(pStream);

        pStream->writeUnsignedInt(mChildren.size());
        for(std::vector<Key *>::const_iterator child=mChildren.begin();child!=mChildren.end();++child)
            (*child)->writeTree(pStream);
    }

    bool Key::readTree(ArcMist::InputStream *pStream)
    {
        if(!read(pStream))
            return false;
        mUsed = pStream->readByte();
        if(isPrivate())
        {
            mPublicKey = new Key();
            if(!mPublicKey->readTree(pStream))
                return false;
        }

        unsigned int childCount = pStream->readUnsignedInt();
        Key *newChild;
        for(unsigned int i=0;i<childCount;++i)
        {
            newChild = new Key();
            if(!newChild->readTree(pStream))
            {
                delete newChild;
                return false;
            }
            mChildren.push_back(newChild);
        }

        return true;
    }

    ArcMist::String Key::encode() const
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

    bool Key::decode(const char *pText)
    {
        ArcMist::Buffer data;

        // Decode base58
        if(data.writeBase58AsBinary(pText) == 0)
            return false;

        // Read into key
        if(!read(&data) || data.remaining() != 4)
        {
            clear();
            return false;
        }

        ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
        ArcMist::Buffer checkSum;

        write(&digest);
        digest.getResult(&checkSum);

        checkSum.setInputEndian(ArcMist::Endian::BIG);
        if(checkSum.readUnsignedInt() != data.readUnsignedInt())
        {
            clear();
            return false;
        }

        return finalize();
    }

    bool Key::finalize()
    {
        unsigned int contextFlags = SECP256K1_CONTEXT_VERIFY;
        if(isPrivate())
            contextFlags = SECP256K1_CONTEXT_SIGN;
        secp256k1_context *thisContext = context(contextFlags);
        ArcMist::Digest digest(ArcMist::Digest::SHA256_RIPEMD160);
        ArcMist::Buffer result;

        if(mPublicKey != NULL)
            delete mPublicKey;

        if(isPrivate())
        {
            mPublicKey = new Key();

            // Create public key
            switch(mVersion)
            {
            case MAINNET_PRIVATE:
                mPublicKey->mVersion = MAINNET_PUBLIC;
                break;
            case TESTNET_PRIVATE:
                mPublicKey->mVersion = TESTNET_PUBLIC;
                break;
            default:
                delete mPublicKey;
                return false;
            }

            mPublicKey->mDepth = mDepth;
            std::memcpy(mPublicKey->mParentFingerPrint, mParentFingerPrint, 4);
            mPublicKey->mIndex = mIndex;
            std::memcpy(mPublicKey->mChainCode, mChainCode, 32);

            secp256k1_pubkey publicKey;
            if(!secp256k1_ec_pubkey_create(thisContext, &publicKey, mKey + 1))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to generate public key for private child key");
                return false;
            }

            size_t compressedLength = 33;
            if(!secp256k1_ec_pubkey_serialize(thisContext, mPublicKey->mKey, &compressedLength,
              &publicKey, SECP256K1_EC_COMPRESSED))
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

            // Calculate hash
            ArcMist::Digest hash(ArcMist::Digest::SHA256_RIPEMD160);
            hash.write(mPublicKey->mKey, 33);
            hash.getResult(&mPublicKey->mHash);

            digest.write(mPublicKey->mKey, 33);
        }
        else
        {
            mPublicKey = NULL;
            digest.write(mKey, 33);

            // Calculate hash
            ArcMist::Digest hash(ArcMist::Digest::SHA256_RIPEMD160);
            hash.write(mKey, 33);
            hash.getResult(&mHash);
        }

        digest.getResult(&result);
        result.read(mFingerPrint, 4); // Fingerprint is first 4 bytes of HASH160
        if(mPublicKey != NULL)
            std::memcpy(mPublicKey->mFingerPrint, mFingerPrint, 4);
        return true;
    }

    Key *Key::findAddress(const ArcMist::Hash &pHash)
    {
        if(pHash == hash())
            return this;

        Key *result;
        for(std::vector<Key *>::iterator child=mChildren.begin();child!=mChildren.end();++child)
        {
            result = (*child)->findAddress(pHash);
            if(result != NULL)
                return result;
        }

        return NULL;
    }

    Key *Key::chainKey(uint32_t pChain, DerivationPathMethod pMethod,
      uint32_t pAccount, uint32_t pCoin)
    {
        switch(pMethod)
        {
        case SIMPLE: // m/account/chain
        {
            if(pAccount == 0xffffffff)
                pAccount = 0; // Default

            Key *account = NULL;
            if(mDepth == 0) // Master key
                account = deriveChild(pAccount);
            if(account == NULL)
                return NULL;

            return account->deriveChild(pChain);
        }
        case BIP0032: // m/account/chain
        {
            if(pAccount == 0xffffffff)
                pAccount = Key::HARDENED_LIMIT; // Default

            Key *account = NULL;
            if(mDepth == 0) // Master key
                account = deriveChild(pAccount);
            if(account == NULL)
                return NULL;

            return account->deriveChild(pChain);
        }
        case BIP0044: // m/44'/coin/account/chain
        {
            // Purpose
            Key *purpose = NULL;
            if(mDepth == 0) // Master key
                purpose = deriveChild(Key::HARDENED_LIMIT + 44);
            if(purpose == NULL)
                return NULL;

            // Coin
            if(pCoin == 0xffffffff)
                pCoin = BITCOIN; // Default
            Key *coin = purpose->deriveChild(pCoin);
            if(coin == NULL)
                return NULL;

            // Account
            if(pAccount == 0xffffffff)
                pAccount = Key::HARDENED_LIMIT; // Default
            Key *account = NULL;
            account = coin->deriveChild(pAccount);
            if(account == NULL)
                return NULL;

            return account->deriveChild(pChain);
        }
        default:
            return NULL;
        }
    }

    bool Key::updateGap(unsigned int pGap)
    {
        unsigned int gap = 0;
        unsigned int lastIndex = 0;
        for(std::vector<Key *>::iterator child=mChildren.begin();child!=mChildren.end();++child)
        {
            lastIndex = (*child)->mIndex;
            if((*child)->mUsed)
                gap = 0;
            else
                ++gap;
        }

        if(gap < pGap)
        {
            ++lastIndex; // Go to next index
            while(gap < pGap)
                if(deriveChild(lastIndex) != NULL)
                {
                    ++gap;
                    ++lastIndex;
                }
            return true;
        }
        else
            return false;
    }

    Key *Key::markUsed(const ArcMist::Hash &pHash, unsigned int pGap, bool &pNewAddresses)
    {
        if(hash() == pHash)
        {
            if(mUsed)
            {
                // Already used
                pNewAddresses = false;
                return this;
            }

            // Mark as used
            // The parent is apparently not available, so no new addresses will be generated.
            pNewAddresses = false;
            mUsed = true;
            if(mPublicKey != NULL)
                mPublicKey->mUsed = true;
            return this;
        }

        pNewAddresses = false;
        Key *result = NULL;
        unsigned int gap = 0;
        unsigned int lastIndex = 0;
        for(std::vector<Key *>::iterator child=mChildren.begin();child!=mChildren.end();++child)
        {
            if(result != NULL)
            {
                lastIndex = (*child)->mIndex;
                if((*child)->mUsed)
                    gap = 0;
                else
                    ++gap;
            }
            else if((*child)->hash() == pHash)
            {
                lastIndex = (*child)->mIndex;
                result = *child;

                if(result->mUsed)
                    return result; // Already used so no new addresses will be needed

                result->mUsed = true;
                if(result->mPublicKey != NULL)
                    result->mPublicKey->mUsed = true;
            }
            else
            {
                result = (*child)->markUsed(pHash, pGap, pNewAddresses);
                if(result != NULL)
                    return result;
            }
        }

        // Check if more addresses need to be generated
        if(result != NULL && gap < pGap)
        {
            // TODO Add support for after 2^31 indices are used up
            pNewAddresses = true;
            ++lastIndex; // Go to next index
            while(gap < pGap)
                if(deriveChild(lastIndex) != NULL)
                {
                    ++gap;
                    ++lastIndex;
                }
        }

        return result;
    }

    Key *Key::getNextUnused()
    {
        for(std::vector<Key *>::iterator child=mChildren.begin();child!=mChildren.end();++child)
            if(!(*child)->mUsed)
                return *child;

        return NULL;
    }

    Key *Key::findChild(uint32_t pIndex)
    {
        for(std::vector<Key *>::iterator child=mChildren.begin();child!=mChildren.end();++child)
            if((*child)->index() == pIndex)
                return *child;

        return NULL;
    }

    bool Key::sign(const ArcMist::Hash &pHash, Signature &pSignature) const
    {
        if(!isPrivate())
            return false;

        if(pHash.size() != 32)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Wrong size hash to sign");
            return false;
        }

        secp256k1_ecdsa_signature signature;
        if(!secp256k1_ecdsa_sign(context(SECP256K1_CONTEXT_SIGN), &signature, pHash.data(), mKey + 1,
          secp256k1_nonce_function_default, NULL))
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Failed to sign hash");
            return false;
        }

        pSignature.set(signature.data);
        return true;
    }

    bool Key::verify(const Signature &pSignature, const ArcMist::Hash &pHash) const
    {
        if(isPrivate())
            return mPublicKey->verify(pSignature, pHash);

        secp256k1_context *thisContext = context(SECP256K1_CONTEXT_VERIFY);

        if(pHash.size() != 32)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME, "Wrong size hash to verify");
            return false;
        }

        secp256k1_pubkey publicKey;
        if(!secp256k1_ec_pubkey_parse(thisContext, &publicKey, mKey, 33))
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
              "Failed to parse KeyTree Key public key");
            return false;
        }

        if(secp256k1_ecdsa_verify(thisContext, (const secp256k1_ecdsa_signature *)pSignature.data(),
          pHash.data(), &publicKey))
            return true;

        if(!secp256k1_ecdsa_signature_normalize(thisContext, (secp256k1_ecdsa_signature *)pSignature.data(),
          (const secp256k1_ecdsa_signature *)pSignature.data()))
            return false; // Already normalized

        // Try it again with the normalized signature
        if(secp256k1_ecdsa_verify(thisContext, (const secp256k1_ecdsa_signature *)pSignature.data(),
          pHash.data(), &publicKey))
            return true;

        return false;
    }

    Key *Key::deriveChild(uint32_t pIndex)
    {
        Key *result = findChild(pIndex);

        if(result != NULL)
            return result; // Already created

        secp256k1_context *thisContext = context(SECP256K1_CONTEXT_NONE);
        ArcMist::HMACDigest hmac(ArcMist::Digest::SHA512);
        ArcMist::Buffer hmacKey, hmacResult;

        if(isPrivate())
        {
            result = new Key();

            switch(mVersion)
            {
            case MAINNET_PRIVATE:
                result->mVersion = MAINNET_PRIVATE;
                break;
            case TESTNET_PRIVATE:
                result->mVersion = TESTNET_PRIVATE;
                break;
            default:
                delete result;
                return NULL;
            }

            result->mDepth = mDepth + 1;
            std::memcpy(result->mParentFingerPrint, mFingerPrint, 4);
            result->mIndex = pIndex;

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
            result->mKey[0] = 0;
            std::memcpy(result->mKey + 1, key() + 1, 32);

            if(!secp256k1_ec_privkey_tweak_add(thisContext, result->mKey + 1, tweak))
            {
                delete result;
                return NULL;
            }

            // In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one should proceed
            //   with the next value for i. (Note: this has probability lower than 1 in 2127.)
            if(!secp256k1_ec_seckey_verify(thisContext, result->mKey + 1))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to generate valid private child key");
                delete result;
                return NULL;
            }
        }
        else // Public
        {
            if(pIndex >= HARDENED_LIMIT)
                return NULL;

            result = new Key();

            switch(mVersion)
            {
            case MAINNET_PRIVATE:
            case MAINNET_PUBLIC:
                result->mVersion = MAINNET_PUBLIC;
                break;
            case TESTNET_PRIVATE:
            case TESTNET_PUBLIC:
                result->mVersion = TESTNET_PUBLIC;
                break;
            }

            result->mDepth = mDepth + 1;
            std::memcpy(result->mParentFingerPrint, mFingerPrint, 4);
            result->mIndex = pIndex;

            // I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i))
            hmacKey.write(chainCode(), 32); // Key = cpar
            hmac.setOutputEndian(ArcMist::Endian::BIG);
            hmac.initialize(&hmacKey);

            hmac.write(mKey, 33);
            hmac.writeUnsignedInt(pIndex);
            hmac.getResult(&hmacResult);

            // Split I into two 32-byte sequences, IL and IR.

            // The returned child key Ki is point(parse256(IL)) + Kpar.

            hmacResult.read(result->mKey + 1, 32);

            // In case parse256(IL) ≥ n or Ki is the point at infinity, the resulting key is invalid,
            //   and one should proceed with the next value for i.
            if(!secp256k1_ec_seckey_verify(thisContext, result->mKey + 1))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to generate valid private key for public child key");
                delete result;
                return NULL;
            }

            // Create public key for new private key
            secp256k1_pubkey *publicKeys[2];
            publicKeys[0] = new secp256k1_pubkey();
            if(!secp256k1_ec_pubkey_create(thisContext, publicKeys[0], result->mKey + 1))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to generate public key for public child key");
                delete publicKeys[0];
                delete result;
                return NULL;
            }

            // Parse parent public key to uncompressed format
            publicKeys[1] = new secp256k1_pubkey();
            if(!secp256k1_ec_pubkey_parse(thisContext, publicKeys[1], mKey, 33))
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
            if(!secp256k1_ec_pubkey_combine(thisContext, &newPublicKey, publicKeys, 2))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to combine public keys");
                delete result;
                return NULL;
            }

            delete publicKeys[0];
            delete publicKeys[1];

            size_t compressedLength = 33;
            if(!secp256k1_ec_pubkey_serialize(thisContext, result->mKey, &compressedLength,
              &newPublicKey, SECP256K1_EC_COMPRESSED))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_KEY_LOG_NAME,
                  "Failed to write compressed public key for public child key");
                delete result;
                return NULL;
            }
        }

        // The returned chain code ci is IR.
        hmacResult.read(result->mChainCode, 32);

        if(result->finalize())
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

    bool Key::loadBinarySeed(Network pNetwork, ArcMist::InputStream *pStream)
    {
        clear();

        switch(pNetwork)
        {
        case MAINNET:
            mVersion = MAINNET_PRIVATE;
            break;
        case TESTNET:
            mVersion = TESTNET_PRIVATE;
            break;
        default:
            return false;
        }

        mDepth = 0;
        std::memset(mParentFingerPrint, 0, 4);
        mIndex = 0;

        ArcMist::HMACDigest hmac(ArcMist::Digest::SHA512);
        ArcMist::Buffer hmacKey, hmacResult;

        // Calculate HMAC SHA512
        hmacKey.writeString("Bitcoin seed");
        hmac.initialize(&hmacKey);
        hmac.writeStream(pStream, pStream->length());
        hmac.getResult(&hmacResult);

        // Split HMAC SHA512 into halves for key and chain code
        mKey[0] = 0;
        hmacResult.read(mKey + 1, 32); // Zero for private key
        hmacResult.read(mChainCode, 32);

        return secp256k1_ec_seckey_verify(context(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN),
          mKey + 1) && finalize();
    }

    ArcMist::String createMnemonicFromSeed(Mnemonic::Language pLanguage, ArcMist::InputStream *pSeed)
    {
        ArcMist::String result;
        ArcMist::Digest digest(ArcMist::Digest::SHA256);
        ArcMist::Buffer checkSum;
        std::vector<bool> bits;
        uint8_t nextByte;

        // Calculate checksum
        pSeed->setReadOffset(0);
        digest.writeStream(pSeed, pSeed->length());
        digest.getResult(&checkSum);

        int checkSumBits = pSeed->length() / 4; // Entropy bit count / 32

        // Copy seed to bit vector
        pSeed->setReadOffset(0);
        while(pSeed->remaining())
        {
            nextByte = pSeed->readByte();
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

    ArcMist::String Key::generateMnemonicSeed(Mnemonic::Language pLanguage, unsigned int pBytesEntropy)
    {
        // Generate specified number of bytes of entropy
        ArcMist::Buffer seed;
        for(unsigned int i=0;i<pBytesEntropy;i+=4)
            seed.writeUnsignedInt(ArcMist::Math::randomInt());
        return createMnemonicFromSeed(pLanguage, &seed);
    }

    // PBKDF2 with HMAC SHA512, 2048 iterations, and output length of 512 bits.
    bool processMnemonicSeed(ArcMist::InputStream *pMnemonicSentence,
      ArcMist::InputStream *pSaltPlusPassPhrase, ArcMist::OutputStream *pResult)
    {
        ArcMist::HMACDigest digest(ArcMist::Digest::SHA512);
        ArcMist::Buffer dataList[2], *data, *round, result;

        data = dataList;
        round = dataList + 1;

        // Write salt, passphrase, and iteration index into data for first round
        data->setOutputEndian(ArcMist::Endian::BIG);
        pSaltPlusPassPhrase->setReadOffset(0);
        data->writeStream(pSaltPlusPassPhrase, pSaltPlusPassPhrase->length());
        data->writeUnsignedInt(1); // Iteration index (only 1 iteration since output length is 512)

        // Initialize result to zeros
        for(unsigned int i=0;i<64;++i)
            result.writeByte(0);

        for(unsigned int i=0;i<2048;++i)
        {
            // Calculate HMAC SHA512
            pMnemonicSentence->setReadOffset(0);
            digest.initialize(pMnemonicSentence);

            data->setReadOffset(0);
            digest.writeStream(data, data->length());

            round->setWriteOffset(0);
            digest.getResult(round);

            // Xor round into result
            round->setReadOffset(0);
            result.setReadOffset(0);
            result.setWriteOffset(0);
            while(result.remaining())
                result.writeByte(result.readByte() ^ round->readByte());

            // Swap data and round
            if(data == dataList)
            {
                data = dataList + 1;
                round = dataList;
            }
            else
            {
                data = dataList;
                round = dataList + 1;
            }
        }

        result.setReadOffset(0);
        pResult->writeStream(&result, result.length());

        // Zeroize before releasing memory since a password might have been in here
        data->zeroize();
        round->zeroize();
        result.zeroize();
        return true;
    }

    bool Key::loadMnemonicSeed(Network pNetwork, const char *pMnemonicSentence,
      const char *pPassPhrase, const char *pSalt)
    {
        clear();

        //TODO Validate Mnemonic Sentence
        // // Loop through languages
        // for(unsigned int languageIndex=0;languageIndex<Mnemonic::LANGUAGE_COUNT;++languageIndex)
        // {
            // // Parse words from text
            // bits.clear();
            // ptr = pText;
            // while(*ptr)
            // {
                // if(*ptr == ' ' && word.length())
                // {
                    // // Lookup word in mnemonics and add value to list
                    // // TODO Implement binary search
                    // found = false;
                    // for(value=0;value<Mnemonic::WORD_COUNT;++value)
                        // if(word == Mnemonic::WORDS[languageIndex][value])
                        // {
                            // for(int bit=5;bit<16;++bit)
                            // {
                                // if(bit >= 8)
                                    // bits.push_back(ArcMist::Math::bit(value & 0xff, bit - 8));
                                // else
                                    // bits.push_back(ArcMist::Math::bit(value >> 8, bit));
                            // }
                            // found = true;
                            // break;
                        // }

                    // word.clear();

                    // if(!found)
                        // break;
                // }
                // else
                    // word += ArcMist::lower(*ptr);

                // ++ptr;
            // }

            // if(!found)
                // continue; // Next language

            // if(word.length())
            // {
                // found = false;
                // for(value=0;value<Mnemonic::WORD_COUNT;++value)
                    // if(word == Mnemonic::WORDS[languageIndex][value])
                    // {
                        // for(int bit=5;bit<16;++bit)
                        // {
                            // if(bit >= 8)
                                // bits.push_back(ArcMist::Math::bit(value & 0xff, bit - 8));
                            // else
                                // bits.push_back(ArcMist::Math::bit(value >> 8, bit));
                        // }
                        // found = true;
                        // break;
                    // }

                // if(!found)
                    // continue; // Next language
            // }

            // // Check if values is a valid seed
            // if(bits.size() > 128)
            // {
                // checkSumBits = 0;
                // if(pIncludesCheckSum)
                // {
                    // for(unsigned int i=128;i<=256;i+=32)
                        // if(bits.size() == i + (i / 32))
                        // {
                            // seedBits = i;
                            // checkSumBits = i / 32;
                            // break;
                        // }

                    // if(checkSumBits == 0)
                        // continue;
                // }
                // else
                    // seedBits = bits.size();

                // // Parse bits
                // mSeed.clear();
                // mnemonicCheckSum.clear();
                // value = 0;
                // valueBits = 0;
                // for(std::vector<bool>::iterator bit=bits.begin();bit!=bits.end();++bit)
                // {
                    // --seedBits;
                    // ++valueBits;
                    // value <<= 1;
                    // if(*bit)
                        // value |= 0x01;

                    // if(valueBits == 8)
                    // {
                        // if(seedBits >= 0)
                            // mSeed.writeByte(value);
                        // else
                            // mnemonicCheckSum.writeByte(value);
                        // value = 0;
                        // valueBits = 0;
                    // }
                // }

                // if(valueBits > 0)
                // {
                    // if(valueBits < 8)
                        // value <<= (8 - valueBits);
                    // if(seedBits >= 0)
                        // mSeed.writeByte(value);
                    // else
                        // mnemonicCheckSum.writeByte(value);
                // }

                // if(pIncludesCheckSum)
                // {
                    // // Calculate checksum
                    // ArcMist::Digest digest(ArcMist::Digest::SHA256);
                    // mSeed.setReadOffset(0);
                    // digest.writeStream(&mSeed, mSeed.length());
                    // checkSum.clear();
                    // digest.getResult(&checkSum);

                    // // Verify checksum
                    // bool matches = true;
                    // for(int bit=checkSumBits;bit>0;bit-=8)
                    // {
                        // if(bit >= 8)
                        // {
                            // if(checkSum.readByte() != mnemonicCheckSum.readByte())
                            // {
                                // matches = false;
                                // break;
                            // }
                        // }
                        // else if((checkSum.readByte() >> bit) != (mnemonicCheckSum.readByte() >> bit))
                        // {
                            // matches = false;
                            // break;
                        // }
                    // }

                    // if(matches)
                        // return generateMnemonicMaster();
                // }
                // else
                    // return generateMnemonicMaster();
            // }
        // }

        // return false;

        ArcMist::Buffer sentence, salt, seed;
        sentence.writeString(pMnemonicSentence);
        salt.writeString(pSalt);
        salt.writeString(pPassPhrase);
        if(!processMnemonicSeed(&sentence, &salt, &seed))
            return false;

        return loadBinarySeed(pNetwork, &seed);
    }

    KeyStore::~KeyStore()
    {
        for(std::vector<Key *>::iterator key=begin();key!=end();++key)
            delete *key;
    }

    void KeyStore::clear()
    {
        for(std::vector<Key *>::iterator key=begin();key!=end();++key)
            delete *key;
        std::vector<Key *>::clear();
    }

    // If this is the address level then search for public address with matching hash
    Key *KeyStore::findAddress(const ArcMist::Hash &pHash)
    {
        Key *result = NULL;
        for(std::vector<Key *>::iterator key=begin();key!=end();++key)
        {
            result = (*key)->findAddress(pHash);
            if(result != NULL)
                return result;
        }

        return NULL;
    }

    Key *KeyStore::markUsed(const ArcMist::Hash &pHash, unsigned int pGap, bool &pNewAddresses)
    {
        pNewAddresses = false;
        Key *result = NULL;
        for(std::vector<Key *>::iterator key=begin();key!=end();++key)
        {
            result = (*key)->markUsed(pHash, pGap, pNewAddresses);
            if(result != NULL)
                return result;
        }

        return NULL;
    }

    bool Key::test()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "------------- Starting Key Tests -------------");

        bool success = true;
        AddressType addressType;
        ArcMist::Hash hash;

        /***********************************************************************************************
         * BIP-0032 Test Vector 1
         ***********************************************************************************************/
        Key keyTree;
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
            keyTree.loadBinarySeed(MAINNET, &keyTreeSeed);

            resultEncoding = keyTree.encode();
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

            resultEncoding = keyTree.publicKey()->encode();
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
        Key *m0hKey;
        if(success)
        {
            m0hKey = keyTree.deriveChild(Key::HARDENED_LIMIT + 0);
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
        Key *m0h1Key;
        if(success)
        {
            m0h1Key = m0hKey->deriveChild(1);
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
        Key *m0h1PublicKey;
        if(success)
        {
            m0h1PublicKey = m0hKey->publicKey()->deriveChild(1);
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
        Key *m0h12hKey;
        if(success)
        {
            m0h12hKey = m0h1Key->deriveChild(Key::HARDENED_LIMIT + 2);
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
        Key *m0h12h2Key;
        if(success)
        {
            m0h12h2Key = m0h12hKey->deriveChild(2);
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
        Key *m0h12h21000000000Key;
        if(success)
        {
            m0h12h21000000000Key = m0h12h2Key->deriveChild(1000000000);
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
            keyTree.loadBinarySeed(MAINNET, &keyTreeSeed);

            resultEncoding = keyTree.encode();
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

            resultEncoding = keyTree.publicKey()->encode();
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
            m0hKey = keyTree.deriveChild(Key::HARDENED_LIMIT + 0);
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
        ArcMist::Buffer resultSeed, correctSeed, mnemonicStream;
        ArcMist::Buffer resultProcessedSeed, correctProcessedSeed;
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

        const char *trezorProcessedSeed[] =
        {
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
            "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
            "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
            "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
            "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
            "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
            "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
            "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
            "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
            "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
            "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
            "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
            "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
            "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
            "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
            "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
            "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
            "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
            "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"
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
         * BIP-0039 Trezor Test Vector
         ***********************************************************************************************/
        bool trezorPassed = true;
        ArcMist::Buffer salt;

        salt.writeString("mnemonicTREZOR");

        for(unsigned int i=0;i<trezorCount;++i)
        {
            correctSeed.clear();
            correctSeed.writeHex(trezorSeedHex[i]);
            correctProcessedSeed.clear();
            correctProcessedSeed.writeHex(trezorProcessedSeed[i]);
            correctMnemonic = trezorSeedMnemonic[i];
            correctEncoding = trezorKeyEncoding[i];

            resultMnemonic = createMnemonicFromSeed(Mnemonic::English, &correctSeed);

            if(resultMnemonic != correctMnemonic)
            {
                trezorPassed = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed BIP-0039 Trezor Test %d Create Mnemonic", i + 1);
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctMnemonic.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultMnemonic.text());
                continue;
            }

            resultProcessedSeed.clear();
            mnemonicStream.clear();
            mnemonicStream.writeString(correctMnemonic);
            processMnemonicSeed(&mnemonicStream, &salt, &resultProcessedSeed);
            if(resultProcessedSeed != correctProcessedSeed)
            {
                trezorPassed = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed BIP-0039 Trezor Test %d Load Mnemonic : Incorrect Processed Seed", i + 1);
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctProcessedSeed.readHexString(correctProcessedSeed.length()).text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", resultProcessedSeed.readHexString(resultProcessedSeed.length()).text());
                continue;
            }

            if(!keyTree.loadMnemonicSeed(MAINNET, correctMnemonic, "TREZOR"))
            {
                trezorPassed = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed BIP-0039 Trezor Test %d Load Mnemonic : Failed to load", i + 1);
                continue;
            }

            if(keyTree.encode() != correctEncoding)
            {
                trezorPassed = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed BIP-0039 Trezor Test %d Load Mnemonic : Incorrect Key", i + 1);
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", keyTree.encode().text());
                continue;
            }
        }

        if(trezorPassed)
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed BIP-0039 Trezor Test Vector");

        /***********************************************************************************************
         * Decode Key Text 1
         ***********************************************************************************************/
        if(success)
        {
            correctEncoding = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

            if(!keyTree.decode(correctEncoding))
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 1 : Failed to decode");
            }
            else if(keyTree.encode() != correctEncoding)
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 1 : Encode doesn't match");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", keyTree.encode().text());
            }
            else if(!keyTree.isPrivate())
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 1 : Key not private");
            }
            else if(keyTree.depth() != 0)
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 1 : Depth not zero : %d", keyTree.depth());
            }
        }

        if(success)
        {
            correctEncoding = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
            if(keyTree.publicKey()->encode() != correctEncoding)
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 1 : Public encode doesn't match");
            }
        }

        if(success)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
              "Passed Decode Key Text 1");

        /***********************************************************************************************
         * Decode Key Text 2
         ***********************************************************************************************/
        if(success)
        {
            correctEncoding = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

            if(!keyTree.decode(correctEncoding))
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 2 : Failed to decode");
            }
            else if(keyTree.encode() != correctEncoding)
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 2 : Encode doesn't match");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", keyTree.encode().text());
            }
            else if(keyTree.isPrivate())
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 2 : Key not public");
            }
            else if(keyTree.depth() != 0)
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 2 : Depth not zero : %d", keyTree.depth());
            }
        }

        if(success)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
              "Passed Decode Key Text 2");

        /***********************************************************************************************
         * Decode Key Text 3
         ***********************************************************************************************/
        if(success)
        {
            correctEncoding = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76";

            if(!keyTree.decode(correctEncoding))
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 3 : Failed to decode");
            }
            else if(keyTree.encode() != correctEncoding)
            {
                success = false;
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 3 : Encode doesn't match");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", keyTree.encode().text());
            }
            else if(!keyTree.isPrivate())
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 3 : Key not private");
            }
            else if(keyTree.depth() != 5)
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 3 : Depth not 5 : %d", keyTree.depth());
            }
        }

        if(success)
        {
            correctEncoding = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy";
            if(keyTree.publicKey()->encode() != correctEncoding)
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Decode Key Text 3 : Public encode doesn't match");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", keyTree.publicKey()->encode().text());
            }
        }

        if(success)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
              "Passed Decode Key Text 3");

        /***********************************************************************************************
         * Wallet Test vs Electron Cash
         * /0 For receiving addresses
         * /1 For change addresses
         ***********************************************************************************************/
        Key *account0, *account1, *addressKey;
        ArcMist::String encodedAddress;
        bool walletSuccess = true;

        if(!keyTree.loadMnemonicSeed(MAINNET,
          "advice cushion arrange charge update kit gloom elbow delay message swap bulk", "",
          "electrum"))
        {
            walletSuccess = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
              "Failed Wallet Test : Failed to load mnemonic");
        }

        if(walletSuccess)
        {
            correctEncoding = "xpub661MyMwAqRbcGujPLVW3q6UQQGetTsUcM7EYwUTDFGif17McpzNmGu5P1kzwxvCNGnjtDPM5MDbRTD8QZQSpktu7f9CcYydG7PNc3tqCKZi";
            if(keyTree.publicKey()->encode() != correctEncoding)
            {
                walletSuccess = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Wallet Test : Public encode doesn't match");
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Correct : %s", correctEncoding.text());
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Result  : %s", keyTree.publicKey()->encode().text());
            }
        }

        account0 = keyTree.deriveChild(0);
        if(account0 == NULL)
        {
            walletSuccess = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
              "Failed Wallet Test : Failed create account 0");
        }

        if(walletSuccess)
        {
            account1 = keyTree.deriveChild(1);
            if(account1 == NULL)
            {
                walletSuccess = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed Wallet Test : Failed create account 1");
            }
        }

        if(walletSuccess)
        {
            const char *receivingAddresses[5] =
            {
                "1Jvfk1qMhnZ6i6eWSSkgihwacaTjwABBsr",
                "1JinwuSo1JoUPnxQs3hM4sisyJeNZo3Zvv",
                "1LYZtXwzSHhhFoDyJccjpMWLVZpzgkaZsV",
                "1JK5MMpiTYv8wSZgPZ5oyYZgyVQP6h8prQ",
                "1K2eD9iWqBunMBGWcJBZUSQQmNYHRpk5Ne"
            };

            for(unsigned int i=0;i<5 && walletSuccess;++i)
            {
                addressKey = account0->deriveChild(i);

                if(addressKey != NULL)
                {
                    encodedAddress = encodeAddress(addressKey->hash(), PUB_KEY_HASH);
                    if(encodedAddress != receivingAddresses[i])
                    {
                        walletSuccess = false;
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                          "Failed to generate receiving address key : %d : Non Matching Address", i);
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                          "Correct : %s", receivingAddresses[i]);
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                          "Result  : %s", encodedAddress.text());
                    }

                    if(!decodeAddress(receivingAddresses[i], hash, addressType))
                    {
                        walletSuccess = false;
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                          "Failed decode address %d", i);
                    }
                    else
                    {
                        if(addressType != PUB_KEY_HASH)
                        {
                            walletSuccess = false;
                            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                              "Failed decode address type %d : type %d", i, addressType);
                        }
                        else if(hash != addressKey->hash())
                        {
                            walletSuccess = false;
                            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                              "Failed decode address hash %d", i);
                            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                              "Correct : %s", addressKey->hash().hex().text());
                            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                              "Result  : %s", hash.hex().text());
                        }
                    }
                }
                else
                {
                    walletSuccess = false;
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Failed to generate address key : %d", i);
                }
            }

            const char *changeAddresses[5] =
            {
                "1N89DzxGHj9gfg2uA53QYKuoNX4hhvYwrZ",
                "16xur1hethAuELqR2t5LDAUeUdvUqjgqxW",
                "1BXQQWVzUC6GtutPPvEKnLdXKsFLcGGB9u",
                "1JTxMVtTVJPR1L1WLpH7W3he46Mjatrbk8",
                "1NZbMv8qneXKkexBnjm5BpHMC5teG9BgpS"
            };

            for(unsigned int i=0;i<5 && walletSuccess;++i)
            {
                addressKey = account1->deriveChild(i);

                if(addressKey != NULL)
                {
                    encodedAddress = encodeAddress(addressKey->hash(), PUB_KEY_HASH);
                    if(encodedAddress != changeAddresses[i])
                    {
                        walletSuccess = false;
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                          "Failed to generate change address key : %d : Non Matching Address", i);
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                          "Correct : %s", receivingAddresses[i]);
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                          "Result  : %s", encodedAddress.text());
                    }
                }
                else
                {
                    walletSuccess = false;
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Failed to generate address key : %d", i);
                }
            }
        }

        if(walletSuccess)
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed Wallet Test vs Electron Cash");
        else
            success = false;

        /***********************************************************************************************
         * Key Derivation Path Test Vector
         ***********************************************************************************************/
        Key *purpose, *coin, *account, *chain, *checkChain;

        /***********************************************************************************************
         * SIMPLE m/0
         ***********************************************************************************************/
        account = keyTree.deriveChild(0);
        if(account == NULL)
        {
            success = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
              "Failed SIMPLE : Failed to derive account key.");
        }
        else
        {
            // Receiving
            chain = account->deriveChild(0);
            if(chain == NULL)
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed SIMPLE Receiving Chain Key : Failed to derive chain key.");
            }
            else
            {
                checkChain = keyTree.chainKey(0, Key::SIMPLE);
                if(checkChain == NULL)
                {
                    success = false;
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Failed SIMPLE Receiving Chain Key : Failed to request chain key.");
                }
                else if(chain->encode() != checkChain->encode())
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Failed SIMPLE Receiving Chain Key : Non Matching Chain Keys");
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Correct : %s", chain->encode().text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Result  : %s", checkChain->encode().text());
                }
                else
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                      "Passed SIMPLE Receiving Chain Key.");
            }

            // Change
            chain = account->deriveChild(1);
            if(chain == NULL)
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed SIMPLE Change Chain Key : Failed to derive chain key.");
            }
            else
            {
                checkChain = keyTree.chainKey(1, Key::SIMPLE);
                if(checkChain == NULL)
                {
                    success = false;
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Failed SIMPLE Change Chain Key : Failed to request chain key.");
                }
                else if(chain->encode() != checkChain->encode())
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Failed SIMPLE Change Chain Key : Non Matching Chain Keys");
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Correct : %s", chain->encode().text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Result  : %s", checkChain->encode().text());
                }
                else
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                      "Passed SIMPLE Change Chain Key.");
            }
        }

        /***********************************************************************************************
         * BIP-0032 m/0'
         ***********************************************************************************************/
        account = keyTree.deriveChild(Key::HARDENED_LIMIT);
        if(account == NULL)
        {
            success = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
              "Failed BIP-0032 : Failed to derive account key.");
        }
        else
        {
            // Receiving
            chain = account->deriveChild(0);
            if(chain == NULL)
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed BIP-0032 Receiving Chain Key : Failed to derive chain key.");
            }
            else
            {
                checkChain = keyTree.chainKey(0, Key::BIP0032);
                if(checkChain == NULL)
                {
                    success = false;
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Failed BIP-0032 Receiving Chain Key : Failed to request chain key.");
                }
                else if(chain->encode() != checkChain->encode())
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Failed BIP-0032 Receiving Chain Key : Non Matching Chain Keys");
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Correct : %s", chain->encode().text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Result  : %s", checkChain->encode().text());
                }
                else
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                      "Passed BIP-0032 Receiving Chain Key.");
            }

            // Change
            chain = account->deriveChild(1);
            if(chain == NULL)
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed BIP-0032 Change Chain Key : Failed to derive chain key.");
            }
            else
            {
                checkChain = keyTree.chainKey(1, Key::BIP0032);
                if(checkChain == NULL)
                {
                    success = false;
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Failed BIP-0032 Change Chain Key : Failed to request chain key.");
                }
                else if(chain->encode() != checkChain->encode())
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Failed BIP-0032 Change Chain Key : Non Matching Chain Keys");
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Correct : %s", chain->encode().text());
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Result  : %s", checkChain->encode().text());
                }
                else
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                      "Passed BIP-0032 Change Chain Key.");
            }
        }

        /***********************************************************************************************
         * BIP-0044 m/44'/0'/0'
         ***********************************************************************************************/
        purpose = keyTree.deriveChild(Key::HARDENED_LIMIT + 44);
        if(purpose == NULL)
        {
            success = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
              "Failed BIP-0044 : Failed to derive purpose key.");
        }
        else
        {
            coin = purpose->deriveChild(Key::HARDENED_LIMIT);
            if(coin == NULL)
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                  "Failed BIP-0044 : Failed to derive coin key.");
            }
            else
            {
                account = coin->deriveChild(Key::HARDENED_LIMIT);
                if(account == NULL)
                {
                    success = false;
                    ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                      "Failed BIP-0044 : Failed to derive account key.");
                }
                else
                {
                    // Receiving
                    chain = account->deriveChild(0);
                    if(chain == NULL)
                    {
                        success = false;
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                          "Failed BIP-0044 Receiving Chain Key : Failed to derive chain key.");
                    }
                    else
                    {
                        checkChain = keyTree.chainKey(0);
                        if(checkChain == NULL)
                        {
                            success = false;
                            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                              "Failed BIP-0044 Receiving Chain Key : Failed to request chain key.");
                        }
                        else if(chain->encode() != checkChain->encode())
                        {
                            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                              "Failed BIP-0044 Receiving Chain Key : Non Matching Chain Keys");
                            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                              "Correct : %s", chain->encode().text());
                            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                              "Result  : %s", checkChain->encode().text());
                        }
                        else
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                              "Passed BIP-0044 Receiving Chain Key.");
                    }

                    // Change
                    chain = account->deriveChild(1);
                    if(chain == NULL)
                    {
                        success = false;
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                          "Failed BIP-0044 Change Chain Key : Failed to derive chain key.");
                    }
                    else
                    {
                        checkChain = keyTree.chainKey(1);
                        if(checkChain == NULL)
                        {
                            success = false;
                            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                              "Failed BIP-0044 Change Chain Key : Failed to request chain key.");
                        }
                        else if(chain->encode() != checkChain->encode())
                        {
                            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                              "Failed BIP-0044 Change Chain Key : Non Matching Chain Keys");
                            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                              "Correct : %s", chain->encode().text());
                            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
                              "Result  : %s", checkChain->encode().text());
                        }
                        else
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
                              "Passed BIP-0044 Change Chain Key.");
                    }
                }
            }
        }

        /***********************************************************************************************
         * Address Gap
         ***********************************************************************************************/
        bool addressGapSuccess = true;
        chain = keyTree.chainKey(0);
        chain->updateGap(20);

        if(chain->childCount() != 20)
        {
            addressGapSuccess = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
              "Failed Address Gap : Update address gap : %d != 20", chain->childCount());
        }

        addressKey = chain->getNextUnused();
        if(addressKey == NULL)
        {
            addressGapSuccess = false;
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
              "Failed Address Gap : Get next unused");
        }

        bool updated = false;
        chain->markUsed(addressKey->hash(), 20, updated);

        if(!updated)
        {
            addressGapSuccess = false;
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
              "Failed Address Gap : Get next unused");
        }

        if(chain->childCount() != 21)
        {
            addressGapSuccess = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
              "Failed Address Gap : Increment address gap : %d != 21", chain->childCount());
        }

        addressKey = chain->findChild(11);
        chain->markUsed(addressKey->hash(), 20, updated);

        if(chain->childCount() != 31)
        {
            addressGapSuccess = false;
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME,
              "Failed Address Gap : Increase address gap : %d != 31", chain->childCount());
        }

        if(addressGapSuccess)
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME,
              "Passed Address Gap");
        else
            success = false;

        return success;
    }
}
