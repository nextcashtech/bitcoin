#include "key.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/base/math.hpp"
#include "arcmist/io/buffer.hpp"
#include "arcmist/crypto/digest.hpp"
#include "interpreter.hpp"

#define BITCOIN_KEY_LOG_NAME "BitCoin Key"


namespace BitCoin
{
    KeyContext::KeyContext()
    {
        context = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    }

    KeyContext::~KeyContext()
    {
        secp256k1_context_destroy(context);
    }

    PrivateKey::PrivateKey(KeyContext *pContext)
    {
        mContext = pContext;
        std::memset(mData, 0, 32);
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

        valid = secp256k1_ec_seckey_verify(mContext->context, mData);

        if(!valid)
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed to generate private key");

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
        if(!secp256k1_ec_pubkey_create(mContext->context, &pubkey, mData))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed to generate public key");
            return false;
        }

        pPublicKey.set(pubkey.data);
        return true;
    }

    bool PrivateKey::sign(Hash &pHash, Signature &pSignature) const
    {
        if(pHash.size() != 32)
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME, "Wrong size hash to verify");
            return false;
        }

        secp256k1_ecdsa_signature signature;
        if(!secp256k1_ecdsa_sign(mContext->context, &signature, pHash.value(), mData,
          secp256k1_nonce_function_default, NULL))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed to sign hash");
            return false;
        }

        pSignature.set(signature.data);
        return true;
    }

    bool Signature::verify(PublicKey &pPublicKey, Hash &pHash) const
    {
        if(pHash.size() != 32)
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME, "Wrong size hash to verify");
            return false;
        }

        if(secp256k1_ecdsa_verify(mContext->context, (const secp256k1_ecdsa_signature *)mData,
          pHash.value(), (const secp256k1_pubkey *)pPublicKey.value()))
            return true;

        if(!secp256k1_ecdsa_signature_normalize(mContext->context, (secp256k1_ecdsa_signature *)mData,
          (const secp256k1_ecdsa_signature *)mData))
        {
            ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_KEY_LOG_NAME, "Signature already normalized");
            return false; // Already normalized
        }

        // Try it again with the normalized signature
        if(secp256k1_ecdsa_verify(mContext->context, (const secp256k1_ecdsa_signature *)mData,
          pHash.value(), (const secp256k1_pubkey *)pPublicKey.value()))
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

    bool PublicKey::compress(CompressedPublicKey &pResult) const
    {
        size_t length = 33;
        uint8_t data[length];
        if(!secp256k1_ec_pubkey_serialize(mContext->context, data, &length, (const secp256k1_pubkey *)mData, SECP256K1_EC_COMPRESSED))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed to compress public key");
            return false;
        }

        pResult.set(data);
        return true;
    }

    void PublicKey::write(ArcMist::OutputStream *pStream, bool pCompressed, bool pScriptFormat) const
    {
        if(pCompressed)
        {
            size_t compressedLength = 33;
            uint8_t compressedData[compressedLength];
            if(!secp256k1_ec_pubkey_serialize(mContext->context, compressedData, &compressedLength, (const secp256k1_pubkey *)mData, SECP256K1_EC_COMPRESSED))
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed to write compressed public key");
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
            if(!secp256k1_ec_pubkey_serialize(mContext->context, data, &length, (const secp256k1_pubkey *)mData, 0))
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed to write public key");
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
        size_t length = 65;
        uint8_t data[length];

        if(pStream->remaining() < 1)
            return false;

        // Check first byte to determine length
        data[0] = pStream->readByte();
        if(data[0] == 0x02 || data[0] == 0x03)
        {
            length = 33;
            if(pStream->remaining() < length - 1)
                return false;
            pStream->read(data + 1, 32); // Compressed
        }
        else
        {
            if(pStream->remaining() < length - 1)
                return false;
            pStream->read(data + 1, 64); // Uncompressed
        }

        if(!secp256k1_ec_pubkey_parse(mContext->context, (secp256k1_pubkey *)mData, data, length))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed to read public key");
            return false;
        }

        return true;
    }

    const Hash &PublicKey::hash()
    {
        if(mHash.size() != 0)
            return mHash;

        // Calculate hash
        ArcMist::Digest digest(ArcMist::Digest::SHA256_RIPEMD160);
        write(&digest, true, false); // Compressed
        digest.getResult(&mHash);
        return mHash;
    }

    void PublicKeyData::write(ArcMist::OutputStream *pStream, bool pScriptFormat) const
    {
        if(pScriptFormat)
            ScriptInterpreter::writePushDataSize(64, pStream);
        pStream->write(mData, 64);
    }

    void Signature::write(ArcMist::OutputStream *pStream, bool pScriptFormat, HashType pHashType) const
    {
        size_t length = 73;
        uint8_t output[length];
        if(!secp256k1_ecdsa_signature_serialize_der(mContext->context, output, &length, (secp256k1_ecdsa_signature*)mData))
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed to write signature");
        if(pScriptFormat)
            ScriptInterpreter::writePushDataSize(length + 1, pStream);
        pStream->write(output, length);
        pStream->writeByte(pHashType);
    }

    bool Signature::read(ArcMist::InputStream *pStream, unsigned int pLength, bool pECDSA_DER_SigsOnly)
    {
        uint8_t input[pLength];
        pStream->read(input, pLength);

        if(pLength == 64)
        {
            if(pECDSA_DER_SigsOnly)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME,
                  "BIP-0066 requires ECDSA DER signatures only. Signature length %d", pLength);
                return false;
            }

            if(!secp256k1_ecdsa_signature_parse_compact(mContext->context, (secp256k1_ecdsa_signature*)mData, input))
            {
                ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME, "Failed to parse compact signature (64 bytes)");
                return false;
            }
            else
                return true;
        }
        else if(pLength < 64)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME,
              "Failed to parse signature. Too short : %d bytes", pLength);
            return false;
        }

        if(secp256k1_ecdsa_signature_parse_der(mContext->context, (secp256k1_ecdsa_signature*)mData, input, pLength))
            return true;
        else
        {
            // Try to hack it to work
            bool tryAgain = false;
            unsigned int totalLength = pLength;
            uint8_t offset = 0;
            uint8_t subLength;
            if(input[offset++] != 0x30) // Compound header byte
            {
                ArcMist::String hex;
                hex.writeHex(input, pLength);
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME,
                  "Invalid compound header byte in signature (%d bytes) : %s", pLength, hex.text());
                return false;
            }

            // Full length
            unsigned int fullLengthOffset = offset;
            if(input[offset++] != pLength - 2)
            {
                ArcMist::String hex;
                hex.writeHex(input, pLength);
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME,
                  "Invalid total length byte in signature (%d bytes) : %s", pLength, hex.text());
                return false;
            }

            // Integer header byte
            if(input[offset++] != 0x02)
            {
                ArcMist::String hex;
                hex.writeHex(input, pLength);
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME,
                  "Invalid R integer header byte in signature (%d bytes) : %s", pLength, hex.text());
                return false;
            }

            // R length
            subLength = input[offset++];
            if(subLength + offset > totalLength)
            {
                ArcMist::String hex;
                hex.writeHex(input, pLength);
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME,
                  "R integer length byte too high in signature (%d bytes) : %s", pLength, hex.text());
                return false;
            }

            if(input[offset] == 0x00 && !(input[offset+1] & 0x80))
            {
                ArcMist::String hex;
                hex.writeHex(input, pLength);
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME,
                  "Removing extra leading zero in R value from signature (%d bytes) : %s", pLength, hex.text());

                // Adjust lengths
                input[offset-1]--;
                input[fullLengthOffset]--;

                // Extra padding. Remove this
                std::memmove(input + offset, input + offset + 1, totalLength - offset - 1);
                --offset;
                tryAgain = true;
                --totalLength;
            }

            offset += subLength;

            // Integer header byte
            if(input[offset++] != 0x02)
            {
                ArcMist::String hex;
                hex.writeHex(input, pLength);
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME,
                  "Invalid S integer header byte in signature (%d bytes) : %s", pLength, hex.text());
                return false;
            }

            // S length
            subLength = input[offset++];
            if(subLength + offset > totalLength)
            {
                ArcMist::String hex;
                hex.writeHex(input, pLength);
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME,
                  "S integer length byte too high in signature (%d bytes) : %s", pLength, hex.text());
                return false;
            }

            if(input[offset] == 0x00 && !(input[offset+1] & 0x80))
            {
                ArcMist::String hex;
                hex.writeHex(input, pLength);
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME,
                  "Removing extra leading zero in S value from signature (%d bytes) : %s", pLength, hex.text());

                // Adjust lengths
                input[offset-1]--;
                input[fullLengthOffset]--;

                // Extra padding. Remove this
                std::memmove(input + offset, input + offset + 1, totalLength - offset - 1);
                --offset;
                tryAgain = true;
                --totalLength;
            }

            offset += subLength;

            if(tryAgain && secp256k1_ecdsa_signature_parse_der(mContext->context,
              (secp256k1_ecdsa_signature*)mData, input, totalLength))
                return true;
        }

        ArcMist::String hex;
        hex.writeHex(input, pLength);
        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_KEY_LOG_NAME,
          "Failed to parse signature (%d bytes) : %s", pLength, hex.text());
        return false;
    }

    ArcMist::String CompressedPublicKey::hex() const
    {
        ArcMist::String result;
        result.writeHex(mData, 33);
        return result;
    }

    namespace Key
    {
        bool test()
        {
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "------------- Starting Key Tests -------------");

            bool success = true;
            KeyContext context;
            PrivateKey privateKey(&context);
            PublicKey publicKey(&context);
            CompressedPublicKey compressedPublicKey;

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
             * Compress Public Key
             ***********************************************************************************************/
            if(publicKey.compress(compressedPublicKey))
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_KEY_LOG_NAME, "Passed Compress Public Key : %s", compressedPublicKey.hex().text());
            else
            {
                success = false;
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_KEY_LOG_NAME, "Failed Compress Public Key : %s", compressedPublicKey.hex().text());
            }

            /***********************************************************************************************
             * Read Public Key
             ***********************************************************************************************/
            ArcMist::Buffer buffer;
            PublicKey readPublicKey(&context);
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
            Hash hash(32);
            Signature signature(&context);
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

            return success;
        }
    }
}
