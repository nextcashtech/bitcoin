/**************************************************************************
 * Copyright 2017-2019 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "interpreter.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#include "profiler_setup.hpp"
#endif

#include "digest.hpp"
#include "key.hpp"


namespace BitCoin
{
    bool ScriptInterpreter::bufferIsZero(NextCash::Buffer *pBuffer)
    {
        pBuffer->setReadOffset(0);
        while(pBuffer->remaining() > 0)
            if(pBuffer->readByte() != 0)
                return false;
        return true;
    }

    bool ScriptInterpreter::isPushOnly(NextCash::Buffer &pScript)
    {
        uint8_t opCode;

        while(pScript.remaining() > 0)
        {
            opCode = pScript.readByte();
            if(opCode != OP_0 && pullDataSize(opCode, pScript, true) == 0xffffffff)
                return false;
        }

        return true;
    }

    bool ScriptInterpreter::isSmallInteger(uint8_t pOpCode)
    {
        return pOpCode == OP_0 || (pOpCode >= OP_1 && pOpCode <= OP_16);
    }

    unsigned int ScriptInterpreter::smallIntegerValue(uint8_t pOpCode)
    {
        if(pOpCode != OP_0 && (pOpCode < OP_1 || pOpCode > OP_16))
            return 0;
        return (pOpCode - OP_1) + 1;
    }

    bool ScriptInterpreter::writeSmallInteger(unsigned int pValue, NextCash::Buffer &pScript)
    {
        if(pValue > 16)
            return false;

        if(pValue == 0)
            pScript.writeByte(OP_0);
        else
            pScript.writeByte((OP_1 + pValue) - 1);
        return true;
    }

    void ScriptInterpreter::writeArithmeticInteger(NextCash::Buffer &pScript, int64_t pValue)
    {
        NextCash::Buffer value;
        arithmeticWrite(&value, pValue);
        ScriptInterpreter::writePushDataSize(value.length(), &pScript);
        pScript.writeStream(&value, value.length());
    }

    // Parse output script for standard type and hash
    ScriptInterpreter::ScriptType ScriptInterpreter::parseOutputScript(NextCash::Buffer &pScript,
      NextCash::HashList &pHashes)
    {
        uint8_t opCode;
        NextCash::Hash tempHash;
        NextCash::Buffer data;
        NextCash::Digest digest(NextCash::Digest::SHA256_RIPEMD160);

        pHashes.clear();
        pScript.setReadOffset(0);
        opCode = pScript.readByte();

        if(opCode == OP_RETURN)
        {
            if(isPushOnly(pScript))
                return NULL_DATA;
            else
            {
                NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
                  "OP_RETURN script is not push only");
                return NON_STANDARD;
            }
        }
        else if(opCode == OP_DUP)
        {
            if(pScript.readByte() != OP_HASH160)
                return NON_STANDARD;
            if(pScript.readByte() != 20) // Push of HASH160
                return NON_STANDARD;
            tempHash.read(&pScript, 20); // Read public key hash
            if(pScript.readByte() != OP_EQUALVERIFY)
                return NON_STANDARD;
            if(pScript.readByte() != OP_CHECKSIG)
                return NON_STANDARD;
            pHashes.push_back(tempHash);
            return P2PKH;
        }
        else if(opCode == OP_HASH160)
        {
            if(pScript.readByte() != 20) // Push of HASH160
                return NON_STANDARD;
            tempHash.read(&pScript, 20); // Read redeem script hash
            if(pScript.readByte() != OP_EQUAL)
                return NON_STANDARD;
            pHashes.push_back(tempHash);
            return P2SH;
        }
        else if(isSmallInteger(opCode))
        {
            if(smallIntegerValue(opCode) == 0) // Zero required signatures is not valid
                return NON_STANDARD;

            unsigned int publicKeyCount = 0;
            while(true)
            {
                opCode = pScript.readByte();
                if(isSmallInteger(opCode))
                {
                    // After public keys the next value must be the count of the public keys
                    unsigned int scriptKeyCount = smallIntegerValue(opCode);

                    // At least one public key is provided and the count matches the count specified
                    if(scriptKeyCount == 0 || scriptKeyCount != publicKeyCount)
                        return NON_STANDARD;

                    // Script must end with OP_CHECKMULTISIG
                    if(pScript.readByte() == OP_CHECKMULTISIG && pScript.remaining() == 0)
                        return MULTI_SIG;
                    else
                        return NON_STANDARD;
                }
                else
                {
                    // Public keys
                    if(!pullData(opCode, pScript, data))
                        return NON_STANDARD;
                    else if(data.length() >= 33 || data.length() <= 65) // Valid size for public key
                    {
                        digest.initialize();
                        data.readStream(&digest, data.length());
                        digest.getResult(&tempHash);
                        pHashes.push_back(tempHash);
                        ++publicKeyCount;
                    }
                    else
                        return NON_STANDARD;
                }
            }
        }
        else if(pullData(opCode, pScript, data)) // Check for P2PK (starting with data push of public key)
        {
            if((data.length() >= 33 || data.length() <= 65) && // Valid size for public key
              pScript.readByte() == OP_CHECKSIG)
            {
                digest.initialize();
                data.readStream(&digest, data.length());
                digest.getResult(&tempHash);
                pHashes.push_back(tempHash);
                return P2PK;
            }
            else
                return NON_STANDARD;
        }

        return NON_STANDARD;
    }

    unsigned int ScriptInterpreter::pullDataSize(uint8_t pOpCode, NextCash::Buffer &pScript,
      bool pSkipData)
    {
        if(pOpCode <= MAX_SINGLE_BYTE_PUSH_DATA_CODE)
        {
            if(pOpCode > pScript.remaining())
                return 0xffffffff;
            else if(pSkipData)
                pScript.setReadOffset(pScript.readOffset() + pOpCode);
            return pOpCode;
        }

        switch(pOpCode)
        {
        // case OP_0: //                  = 0x00, // An empty array of bytes is pushed to the stack
        case OP_FALSE: //               = 0x00, // An empty array of bytes is pushed to the stack
        case OP_1NEGATE: //             = 0x4f, // The number -1 is pushed
        // case OP_1: //                   = 0x51, // The number 1 is pushed
        case OP_TRUE: //                = 0x51, // The number 1 is pushed
        case OP_2: //                   = 0x52, // The number 2 is pushed
        case OP_3: //                   = 0x53, // The number 3 is pushed
        case OP_4: //                   = 0x54, // The number 4 is pushed
        case OP_5: //                   = 0x55, // The number 5 is pushed
        case OP_6: //                   = 0x56, // The number 6 is pushed
        case OP_7: //                   = 0x57, // The number 7 is pushed
        case OP_8: //                   = 0x58, // The number 8 is pushed
        case OP_9: //                   = 0x59, // The number 9 is pushed
        case OP_10: //                  = 0x5a, // The number 10 is pushed
        case OP_11: //                  = 0x5b, // The number 11 is pushed
        case OP_12: //                  = 0x5c, // The number 12 is pushed
        case OP_13: //                  = 0x5d, // The number 13 is pushed
        case OP_14: //                  = 0x5e, // The number 14 is pushed
        case OP_15: //                  = 0x5f, // The number 15 is pushed
        case OP_16: //                  = 0x60, // The number 16 is pushed
            return 1;

        case OP_PUSHDATA1: // The next byte contains the number of bytes to be pushed
        {
            uint8_t length = pScript.readByte();
            if(length > pScript.remaining())
                return 0xffffffff;
            else if(pSkipData)
                pScript.setReadOffset(pScript.readOffset() + length);
            return length;
        }
        case OP_PUSHDATA2: // The next 2 bytes contains the number of bytes to be pushed
        {
            uint16_t length = pScript.readUnsignedShort();
            if(length > pScript.remaining())
                return 0xffffffff;
            else if(pSkipData)
                pScript.setReadOffset(pScript.readOffset() + length);
            return length;
        }
        case OP_PUSHDATA4: // The next 4 bytes contains the number of bytes to be pushed
        {
            uint32_t length = pScript.readUnsignedInt();
            if(length > pScript.remaining())
                return 0xffffffff;
            else if(pSkipData)
                pScript.setReadOffset(pScript.readOffset() + length);
            return length;
        }

        default:
            return 0xffffffff;
        }
    }

    bool ScriptInterpreter::pullData(uint8_t pOpCode, NextCash::Buffer &pScript, NextCash::Buffer &pData)
    {
        pData.clear();

        if(pOpCode <= MAX_SINGLE_BYTE_PUSH_DATA_CODE)
        {
            if(pOpCode > pScript.remaining())
                return false;
            else
                pData.copyBuffer(pScript, pOpCode);
            return true;
        }

        switch(pOpCode)
        {
        // case OP_0: //                  = 0x00, // An empty array of bytes is pushed to the stack
        case OP_FALSE: //               = 0x00, // An empty array of bytes is pushed to the stack
        case OP_1NEGATE: //             = 0x4f, // The number -1 is pushed
        // case OP_1: //                   = 0x51, // The number 1 is pushed
        case OP_TRUE: //                = 0x51, // The number 1 is pushed
        case OP_2: //                   = 0x52, // The number 2 is pushed
        case OP_3: //                   = 0x53, // The number 3 is pushed
        case OP_4: //                   = 0x54, // The number 4 is pushed
        case OP_5: //                   = 0x55, // The number 5 is pushed
        case OP_6: //                   = 0x56, // The number 6 is pushed
        case OP_7: //                   = 0x57, // The number 7 is pushed
        case OP_8: //                   = 0x58, // The number 8 is pushed
        case OP_9: //                   = 0x59, // The number 9 is pushed
        case OP_10: //                  = 0x5a, // The number 10 is pushed
        case OP_11: //                  = 0x5b, // The number 11 is pushed
        case OP_12: //                  = 0x5c, // The number 12 is pushed
        case OP_13: //                  = 0x5d, // The number 13 is pushed
        case OP_14: //                  = 0x5e, // The number 14 is pushed
        case OP_15: //                  = 0x5f, // The number 15 is pushed
        case OP_16: //                  = 0x60, // The number 16 is pushed
            pData.writeByte(smallIntegerValue(pOpCode));
            return true;

        case OP_PUSHDATA1: // The next byte contains the number of bytes to be pushed
        {
            uint8_t length = pScript.readByte();
            if(length > pScript.remaining())
                return false;
            else
                pData.copyBuffer(pScript, length);
            return true;
        }
        case OP_PUSHDATA2: // The next 2 bytes contains the number of bytes to be pushed
        {
            uint16_t length = pScript.readUnsignedShort();
            if(length > pScript.remaining())
                return false;
            else
                pData.copyBuffer(pScript, length);
            return true;
        }
        case OP_PUSHDATA4: // The next 4 bytes contains the number of bytes to be pushed
        {
            uint32_t length = pScript.readUnsignedInt();
            if(length > pScript.remaining())
                return false;
            else
                pData.copyBuffer(pScript, length);
            return true;
        }

        default:
            return false;
        }
    }

    void ScriptInterpreter::writePushDataSize(unsigned int pSize, NextCash::OutputStream *pOutput)
    {
        if(pSize <= MAX_SINGLE_BYTE_PUSH_DATA_CODE)
            pOutput->writeByte(pSize);
        else if(pSize < 0xff)
        {
            pOutput->writeByte(OP_PUSHDATA1);
            pOutput->writeByte(pSize);
        }
        else if(pSize < 0xffff)
        {
            pOutput->writeByte(OP_PUSHDATA2);
            pOutput->writeUnsignedShort(pSize);
        }
        else
        {
            pOutput->writeByte(OP_PUSHDATA4);
            pOutput->writeUnsignedInt(pSize);
        }
    }

    bool ScriptInterpreter::writeP2PKHOutputScript(NextCash::Buffer &pOutputScript,
      const NextCash::Hash &pPubKeyHash)
    {
        pOutputScript.clear();

        if(pPubKeyHash.size() != PUB_KEY_HASH_SIZE)
            return false;

        // Copy the public key from the signature script and push it onto the stack
        pOutputScript.writeByte(OP_DUP);

        // Pop the public key from the signature script, hash it, and push the hash onto the stack
        pOutputScript.writeByte(OP_HASH160);

        // Push the provided public key hash onto the stack
        ScriptInterpreter::writePushDataSize(pPubKeyHash.size(), &pOutputScript);
        pPubKeyHash.write(&pOutputScript);

        // Pop both the hashes from the stack, check that they match, and verify the transaction if they do
        pOutputScript.writeByte(OP_EQUALVERIFY);

        // Pop the signature from the signature script and verify it against the transaction data
        pOutputScript.writeByte(OP_CHECKSIG);

        pOutputScript.compact();
        return true;
    }

    NextCash::String ScriptInterpreter::coinBaseText(NextCash::Buffer &pScript,
      unsigned int pBlockVersion)
    {
        if(pBlockVersion >= 2)
        {
            unsigned int length = pullDataSize(pScript.readByte(), pScript, false);
            if(length != 0xffffffff)
            {
                for(unsigned int i = 0; i < length; ++i)
                    pScript.readByte();
            }
        }

        NextCash::String result;
        char byte;
        while(pScript.remaining())
        {
            byte = pScript.readByte();
            if(NextCash::isWhiteSpace(byte))
                result += ' ';
            else if(NextCash::isASCII(byte))
                result += byte;
        }

        return result;
    }

    NextCash::String ScriptInterpreter::scriptText(NextCash::Buffer &pScript, const Forks &pForks,
      unsigned int pBlockHeight)
    {
        NextCash::String result;

        if(pScript.remaining() == 0)
            return result;

        uint8_t opCode;

        while(pScript.remaining())
        {
            opCode = pScript.readByte();

            if(opCode > 0x00 && opCode <= MAX_SINGLE_BYTE_PUSH_DATA_CODE)
            {
                result += "<OP_PUSH=0x";
                if(opCode > pScript.remaining())
                    result += "too long";
                else
                    result += pScript.readHexString(opCode);
                result += ">";
                continue;
            }

            switch(opCode)
            {
            default:
                result += sOpCodeNames[opCode];
                break;
            case OP_PUSHDATA1: // The next byte contains the number of bytes to be pushed
            {
                uint8_t length = pScript.readByte();
                result += "<OP_PUSHDATA1=0x";
                if(length > pScript.remaining())
                    result += "too long";
                else
                    result += pScript.readHexString(length);
                result += ">";
                break;
            }
            case OP_PUSHDATA2: // The next 2 bytes contains the number of bytes to be pushed
            {
                uint16_t length = pScript.readUnsignedShort();
                result += "<OP_PUSHDATA2=0x";
                if(length > pScript.remaining())
                    result += "too long";
                else
                    result += pScript.readHexString(length);
                result += ">";
                break;
            }
            case OP_PUSHDATA4: // The next 4 bytes contains the number of bytes to be pushed
            {
                uint32_t length = pScript.readUnsignedInt();
                result += "<OP_PUSHDATA4=0x";
                if(length > pScript.remaining())
                    result += "too long";
                else
                    result += pScript.readHexString(length);
                result += ">";
                break;
            }
            }
        }

        return result;
    }

    void ScriptInterpreter::printScript(NextCash::Buffer &pScript, const Forks &pForks,
      unsigned int pBlockHeight, NextCash::Log::Level pLevel)
    {
        NextCash::String text = scriptText(pScript, pForks, pBlockHeight);
        NextCash::Log::addFormatted(pLevel, BITCOIN_INTERPRETER_LOG_NAME, text);
    }

    void ScriptInterpreter::printStack(const char *pText)
    {
        unsigned int index;

        if(mStack.size())
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack : %s", pText);
            index = 1;
            for(std::list<NextCash::Buffer *>::reverse_iterator i = mStack.rbegin();
              i != mStack.rend(); ++i, ++index)
            {
                (*i)->setReadOffset(0);
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
                  "  %d (%d bytes) : %s", index, (*i)->length(),
                  (*i)->readHexString((*i)->length()).text());
            }
        }
        else
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack empty - %s", pText);

        if(mAltStack.size())
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
              "Alt Stack :");
            index = 1;
            for(std::list<NextCash::Buffer *>::reverse_iterator i = mAltStack.rbegin();
              i != mAltStack.rend(); ++i, ++index)
            {
                (*i)->setReadOffset(0);
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
                  "  %d (%d bytes) : %s", index, (*i)->length(),
                  (*i)->readHexString((*i)->length()).text());
            }
        }
        else
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
              "Alt Stack empty - %s", pText);

        if(mAltStack.size())
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME, "If Stack :");
            index = 1;
            for(std::list<bool>::reverse_iterator i = mIfStack.rbegin();
              i != mIfStack.rend(); ++i, ++index)
            {
                if(*i)
                    NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
                      "  true");
                else
                    NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
                      "  false");
            }
        }
        else
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
              "If Stack empty - %s", pText);
    }

    void ScriptInterpreter::printFailure(const char *pScriptName, NextCash::Buffer &pScript)
    {
        if(isValid() && isVerified())
            return;

        const char *reason;
        if(!isValid())
            reason = "is invalid";
        else
            reason = "failed verify";

        if(pScript.remaining())
        {
            if(pScript.readOffset() > 0)
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
                  "Script (%s) %s at offset %d after %s", pScriptName, reason,
                  pScript.readOffset() - 1,
                  sOpCodeNames[*(pScript.begin() + (pScript.readOffset() - 1))]);
            else
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
                  "Script (%s) %s before start", pScriptName, reason);
        }
        else
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
              "Script (%s) %s after completion", pScriptName, reason);

        printStack("After Failure");
    }

    bool ScriptInterpreter::readArithmeticInteger(NextCash::Buffer &pScript, int64_t &pValue)
    {
        unsigned int length = pullDataSize(pScript.readByte(), pScript, false);

        if(length == 0xffffffff)
            return false;

        NextCash::Buffer value;

        value.copyBuffer(pScript, length);

        return arithmeticRead(&value, pValue);
    }

    bool ScriptInterpreter::readDataPush(NextCash::Buffer &pScript, NextCash::Buffer &pData)
    {
        uint8_t opCode = pScript.readByte();

        pData.clear();

        if(opCode == 0x00)
            return false;
        else if(opCode <= MAX_SINGLE_BYTE_PUSH_DATA_CODE)
        {
            if(opCode > pScript.remaining())
                return false;
            pData.writeStream(&pScript, opCode);
        }
        else
            return false;

        return true;
    }

    void ScriptInterpreter::removeCodeSeparators(NextCash::Buffer &pInputScript, NextCash::Buffer &pOutputScript)
    {
        uint8_t opCode;
        while(pInputScript.remaining())
        {
            opCode = pInputScript.readByte();
            if(opCode != OP_CODESEPARATOR)
                pOutputScript.writeByte(opCode);

            if(opCode == 0x00)
                continue;

            if(opCode <= MAX_SINGLE_BYTE_PUSH_DATA_CODE)
            {
                if(opCode > pInputScript.remaining())
                    break;
                pOutputScript.writeStream(&pInputScript, opCode);
                continue;
            }

            switch(opCode)
            {
            case OP_PUSHDATA1: // The next byte contains the number of bytes to be pushed
            {
                uint8_t size = pInputScript.readByte();
                if(size > pInputScript.remaining())
                    break;
                pOutputScript.writeByte(size);
                pOutputScript.writeStream(&pInputScript, size);
                break;
            }
            case OP_PUSHDATA2: // The next 2 bytes contains the number of bytes to be pushed
            {
                uint16_t size = pInputScript.readUnsignedShort();
                if(size > pInputScript.remaining())
                    break;
                pOutputScript.writeUnsignedShort(size);
                pOutputScript.writeStream(&pInputScript, size);
                break;
            }
            case OP_PUSHDATA4: // The next 4 bytes contains the number of bytes to be pushed
            {
                uint32_t size = pInputScript.readUnsignedInt();
                if(size > pInputScript.remaining())
                    break;
                pOutputScript.writeUnsignedInt(size);
                pOutputScript.writeStream(&pInputScript, size);
                break;
            }
            default:
                break;
            }
        }
    }

    bool ScriptInterpreter::checkSignature(Transaction &pTransaction, unsigned int pInputOffset,
      int64_t pOutputAmount, const uint8_t *pPublicKeyData, unsigned int pPublicKeyDataSize,
      const uint8_t *pSignatureData, unsigned int pSignatureDataSize, bool pStrictSignatures,
      NextCash::Buffer &pCurrentOutputScript, unsigned int pSignatureStartOffset,
      const Forks &pForks, unsigned int pBlockHeight)
    {
        if(pSignatureDataSize < 2)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Signature too short : %d", pSignatureDataSize);
            return false;
        }

        if(pForks.cashActive(pBlockHeight) &&
          !(pSignatureData[pSignatureDataSize-1] & Signature::FORKID))
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Signature hash type missing required fork ID flag : 0x%02x",
              pSignatureData[pSignatureDataSize-1]);
            return false;
        }

        // Get signature hash
        NextCash::Hash signatureHash(32);
        NextCash::stream_size previousOffset = pCurrentOutputScript.readOffset();
        pCurrentOutputScript.setReadOffset(pSignatureStartOffset);
        pTransaction.getSignatureHash(pForks, pBlockHeight, signatureHash, pInputOffset,
          pCurrentOutputScript, pOutputAmount, pSignatureData[pSignatureDataSize-1]);
        pCurrentOutputScript.setReadOffset(previousOffset);

        if(Key::verify(pPublicKeyData, pPublicKeyDataSize, pSignatureData, pSignatureDataSize - 1,
          pStrictSignatures, signatureHash))
            return true;
        else
            return false;
    }

    bool ScriptInterpreter::arithmeticRead(NextCash::Buffer *pBuffer, int64_t &pValue)
    {
        //TODO This is a still messy and should be cleaned up. Unit test below should cover it.
        pBuffer->setReadOffset(0);
        if(pBuffer->length() > 8)
        {
            pBuffer->setReadOffset(0);
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Arithmetic read has too many bytes : %s",
              pBuffer->readHexString(pBuffer->length()).text());
            return false;
        }
        else if(pBuffer->length() == 0)
        {
            pValue = 0;
            return true;
        }

        // Read value
        int startOffset = 8 - pBuffer->length();
        uint8_t bytes[8];
        pBuffer->setReadOffset(0);
        std::memset(bytes, 0, 8);
        if(NextCash::Endian::sSystemType == NextCash::Endian::LITTLE)
        {
            for(unsigned int i=7;pBuffer->remaining();i--)
                bytes[i] = pBuffer->readByte();
        }
        else
        {
            for(unsigned int i=startOffset;pBuffer->remaining();i++)
                bytes[i] = pBuffer->readByte();
        }

        // Zeroize any previous bytes
        std::memset(bytes, 0x00, startOffset);

        bool negative = bytes[startOffset] & 0x80;
        bool dropFirstByte = false;
        if(negative)
        {
            if(bytes[startOffset] == 0x80)
            {
                bytes[startOffset] = 0x00;
                startOffset++;
                dropFirstByte = true;
            }
            else
                bytes[startOffset] ^= 0x80; // Flip highest bit
        }
        else
        {
            if(bytes[startOffset] == 0x00)
            {
                startOffset++;
                dropFirstByte = true;
            }
        }

        if(dropFirstByte)
        {
            if(pBuffer->length() > 5)
            {
                pBuffer->setReadOffset(0);
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Arithmetic read has too many bytes (negative with 0x80) : %s",
                  pBuffer->readHexString(pBuffer->length()).text());
                return false;
            }
        }
        else if(pBuffer->length() > 4)
        {
            pBuffer->setReadOffset(0);
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Arithmetic read has too many bytes : %s",
              pBuffer->readHexString(pBuffer->length()).text());
            return false;
        }

        // Adjust for system endian
        if(NextCash::Endian::sSystemType == NextCash::Endian::LITTLE)
            NextCash::Endian::reverse(bytes, 8);
        std::memcpy(&pValue, bytes, 8);

        if(negative)
        {
            pValue = -pValue;
            std::memset((uint8_t *)&pValue + startOffset, 0xff, 8 - startOffset);
        }

        pBuffer->setReadOffset(0);
        //NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
        //  "Arithmetic read : %s -> %08x%08x (%d)", pBuffer->readHexString(pBuffer->length()).text(),
        //  pValue >> 32, pValue, pValue & 0xffffffff);
        return true;
    }

    void ScriptInterpreter::arithmeticWrite(NextCash::Buffer *pBuffer, int64_t pValue)
    {
        //TODO This is a still messy and should be cleaned up. Unit test below should cover it.
        uint8_t bytes[8];
        int startOffset = 0;
        bool negative = false;
        int64_t value;
        if(pValue < 0)
        {
            negative = true;
            value = -pValue;
        }
        else
            value = pValue;

        pBuffer->clear();

        std::memcpy(bytes, &value, 8);
        if(NextCash::Endian::sSystemType == NextCash::Endian::LITTLE)
            NextCash::Endian::reverse(bytes, 8);

        // Skip zero bytes
        for(int i=startOffset;i<8;i++)
            if(bytes[i] == 0x00)
                startOffset++;
            else
                break;

        if(startOffset == 8)
        {
            // All zeros
            if(negative) // was all 0xff
                pBuffer->writeByte(0x80);
            return;
        }

        if(negative)
        {
            if(bytes[startOffset] & 0x80) // Top bit already set
            {
                if(startOffset == 0)
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "Arithmetic write (too many bytes) : %08x%08x -> %s", pValue >> 32, pValue);
                    return;
                }

                // Prepend 0x80 byte
                bytes[--startOffset] = 0x80;
            }
            else // Set top bit
                bytes[startOffset] |= 0x80;
        }
        else if(bytes[startOffset] & 0x80)
        {
            if(startOffset == 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Arithmetic write (too many bytes) : %08x%08x -> %s", pValue >> 32, pValue);
                return;
            }

            // Prepend 0x00 byte
            bytes[--startOffset] = 0x00;
        }

        if(NextCash::Endian::sSystemType == NextCash::Endian::LITTLE)
        {
            NextCash::Endian::reverse(bytes, 8);
            pBuffer->write(bytes, 8 - startOffset);
        }
        else
            pBuffer->write(bytes + startOffset, 8 - startOffset);
        pBuffer->setReadOffset(0);
        //NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
        //  "Arithmetic write : %08x%08x (%d) -> %s", pValue >> 32, pValue, pValue & 0xffffffff,
        //  pBuffer->readHexString(pBuffer->length()).text());
    }

    void leftShift(NextCash::Buffer &pValue, int pShiftBits)
    {
        static uint8_t sShiftMask[] = {0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01};

        uint8_t original[pValue.length()];
        uint8_t *result = pValue.begin();
        int bitShift = pShiftBits % 8;
        int byteShift = pShiftBits / 8;
        uint8_t mask = sShiftMask[bitShift];
        uint8_t overflowMask = ~mask;

        std::memcpy(original, result, pValue.length());
        std::memset(result, 0x00, pValue.length());

        for(int i = 0; i < (int)pValue.length(); ++i)
        {
            int k = i + byteShift;

            if(k < (int)pValue.length())
                result[k] |= ((original[i] & mask) << bitShift);

            if(k + 1 < (int)pValue.length())
                result[k + 1] |= ((original[i] & overflowMask) >> (8 - bitShift));
        }
    }

    void rightShift(NextCash::Buffer &pValue, int pShiftBits)
    {
        static uint8_t sShiftMask[] = {0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80};

        uint8_t original[pValue.length()];
        uint8_t *result = pValue.begin();
        int bitShift = pShiftBits % 8;
        int byteShift = pShiftBits / 8;
        uint8_t mask = sShiftMask[bitShift];
        uint8_t overflowMask = ~mask;

        std::memcpy(original, result, pValue.length());
        std::memset(result, 0x00, pValue.length());

        for(int i = 0; i < (int)pValue.length(); ++i)
        {
            int k = i + byteShift;

            if(k < (int)pValue.length())
                result[k] |= ((original[i] & mask)  << bitShift);

            if (k + 1 < (int)pValue.length())
                result[k + 1] |= ((original[i] & overflowMask) >> (8 - bitShift));
        }
    }

    bool ScriptInterpreter::process(NextCash::Buffer &pScript, int32_t pBlockVersion, Forks &pForks,
      unsigned int pBlockHeight)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_INTERP_PROCESS_ID, PROFILER_INTERP_PROCESS_NAME), true);
#endif
        uint8_t opCode;

        mSigStartOffset = pScript.readOffset();
        mScript = &pScript;
        mBlockVersion = pBlockVersion;
        mForks = &pForks;
        mBlockHeight = pBlockHeight;

        while(pScript.remaining())
        {
            if(mStack.size() > 1000)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack overflow %d items", mStack.size());
                mValid = false;
                return false;
            }

            if(mIfStack.size() > 20)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "If Stack overflow %d items", mIfStack.size());
                mValid = false;
                return false;
            }

            opCode = pScript.readByte();

            if(!(this->*sExecuteOpCode[opCode])(opCode))
                break;
        }

        return mValid;
    }

    bool ScriptInterpreter::opCodePushFalse(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        // Push an empty value onto the stack (OP_0, OP_FALSE)
        push();
        return true;
    }

    bool ScriptInterpreter::opCodeSingleBytePush(uint8_t pOpCode)
    {
        if(pOpCode > mScript->remaining())
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Push data size more than remaining script : %d/%d", pOpCode, mScript->remaining());
            mValid = false;
            return false;
        }

        // Push opCode value bytes onto stack from input
        if(!ifStackTrue())
            mScript->setReadOffset(mScript->readOffset() + pOpCode);
        else
            push()->copyBuffer(*mScript, pOpCode);

        return true;
    }

    bool ScriptInterpreter::opCodeIf(uint8_t pOpCode)
    {
        // If the top stack value is not OP_FALSE the statements are executed. The top stack value
        //   is removed
        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_IF");
            mValid = false;
            return false;
        }

        if(ifStackTrue())
        {
            mIfStack.push_back(!bufferIsZero(top()));
            pop();
        }
        else
            mIfStack.push_back(true);

        return true;
    }

    bool ScriptInterpreter::opCodeNotIf(uint8_t pOpCode)
    {
        // If the top stack value is OP_FALSE the statements are executed. The top stack value is
        //   removed
        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_NOTIF");
            mValid = false;
            return false;
        }

        if(ifStackTrue())
        {
            mIfStack.push_back(bufferIsZero(top()));
            pop();
        }
        else
            mIfStack.push_back(true);

        return true;
    }

    bool ScriptInterpreter::opCodeElse(uint8_t pOpCode)
    {
        // If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then these statements are
        //   and if the preceding OP_IF or OP_NOTIF or OP_ELSE was executed then these statements
        //   are not.
        if(mIfStack.size() > 0)
            mIfStack.back() = !mIfStack.back();
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "No if before else");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeEndIf(uint8_t pOpCode)
    {
        // Ends an if/else block. All blocks must end, or the transaction is invalid. An OP_ENDIF
        //   without OP_IF earlier is also invalid.
        if(mIfStack.size() > 0)
            mIfStack.pop_back();
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "No if before endif");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeVerify(uint8_t pOpCode)
    {
        // Marks transaction as invalid if top stack value is not true.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_VERIFY");
            mValid = false;
            return false;
        }

        if(bufferIsZero(top()))
        {
            mVerified = false;
            return false;
        }
        else
            pop();

        return true;
    }

    bool ScriptInterpreter::opCodeReturn(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        // Marks transaction as invalid
        mVerified = false;
        return false;
    }

    bool ScriptInterpreter::opCodeEqual(uint8_t pOpCode)
    {
        // OP_EQUAL Returns 1 if the the top two stack items are exactly equal, 0 otherwise.
        // OP_EQUALVERIFY Same as OP_EQUAL, but runs OP_VERIFY afterward.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_EQUALVERIFY");
            mValid = false;
            return false;
        }

        // Compare top 2 stack entries
        std::list<NextCash::Buffer *>::iterator secondToLast = mStack.end();
        --secondToLast;
        --secondToLast;
        mStack.back()->setReadOffset(0);
        (*secondToLast)->setReadOffset(0);
        bool matching = *mStack.back() == **secondToLast;
        pop();
        pop();

        if(matching)
        {
            if(pOpCode == OP_EQUAL)
                push()->writeByte(1); // Push true
        }
        else
        {
            if(pOpCode == OP_EQUAL)
                push(); // Push false
            else
            {
                // OP_EQUALVERIFY
                mVerified = false;
                return false;
            }
        }

        return true;
    }

    bool ScriptInterpreter::opCodeHash(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for %s", sOpCodeNames[pOpCode]);
            mValid = false;
            return false;
        }

        NextCash::Buffer *data = top();
        data->setReadOffset(0);

        switch(pOpCode)
        {
        case OP_RIPEMD160:
        {
            // Hash top stack item and pop it
            NextCash::Digest digest(NextCash::Digest::RIPEMD160);
            digest.writeStream(data, data->length());
            digest.getResult(&mHash);
            break;
        }
        case OP_SHA1:
        {
            // Hash top stack item and pop it
            NextCash::Digest digest(NextCash::Digest::SHA1);
            digest.writeStream(data, data->length());
            digest.getResult(&mHash);
            break;
        }
        case OP_SHA256:
        {
            // Hash top stack item and pop it
            NextCash::Digest digest(NextCash::Digest::SHA256);
            digest.writeStream(data, data->length());
            digest.getResult(&mHash);
            break;
        }
        case OP_HASH160: // The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
        {
            // Hash top stack item and pop it
            NextCash::Digest digest(NextCash::Digest::SHA256_RIPEMD160);
            digest.writeStream(data, data->length());
            digest.getResult(&mHash);
            break;
        }
        case OP_HASH256: // The input is hashed two times with SHA-256.
        {
            // Hash top stack item and pop it
            NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
            digest.writeStream(data, data->length());
            digest.getResult(&mHash);
            break;
        }
        }

        // Pop the hashed value.
        pop();

        // Push the hash
        mHash.write(push());

        return true;
    }


    bool ScriptInterpreter::opCodeSeparator(uint8_t pOpCode)
    {
        // All of the signature checking words will only match signatures to the data after the
        //   most recently-executed OP_CODESEPARATOR.
        if(!ifStackTrue())
            return true;
        mSigStartOffset = mScript->readOffset();
        return true;
    }


    bool ScriptInterpreter::opCodeCheckSig(uint8_t pOpCode)
    {
        // Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_CHECKSIG");
            mValid = false;
            return false;
        }

        bool failed = false;

        // Pop the public key
        NextCash::Buffer *publicKeyData = top();
        pop(false);

        // Pop the signature
        bool strictSigs = mBlockVersion >= 3 && mForks->enabledBlockVersion(mBlockHeight) >= 3;
        NextCash::Buffer *signatureData = top();
        signatureData->setReadOffset(0);
        pop(false);

        // Check the signature with the public key
        if(!failed && checkSignature(*mTransaction, mInputOffset, mOutputAmount,
          publicKeyData->begin(), publicKeyData->length(), signatureData->begin(),
          signatureData->length(), strictSigs, *mScript, mSigStartOffset, *mForks,
          mBlockHeight))
        {
            delete publicKeyData;
            delete signatureData;
            if(pOpCode == OP_CHECKSIG)
                push()->writeByte(1); // Push true onto the stack
        }
        else
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
              "Signature check failed");
            delete publicKeyData;
            delete signatureData;
            if(pOpCode == OP_CHECKSIG)
                push(); // Push false onto the stack
            else
            {
                mVerified = false;
                return false;
            }
        }

        return true;
    }

    bool ScriptInterpreter::opCodeCheckMultiSig(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(4))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_CHECKMULTISIG");
            mValid = false;
            return false;
        }

        // Pop count of public keys
        unsigned int publicKeyCount = popInteger();
        if(!checkStackSize(publicKeyCount))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_CHECKMULTISIG public keys");
            mValid = false;
            return false;
        }

        // Pop public keys
        NextCash::Buffer *publicKeys[publicKeyCount];
        for(unsigned int i = 0; i < publicKeyCount; ++i)
        {
            publicKeys[i] = top();
            pop(false);
        }

        // Pop count of signatures
        unsigned int signatureCount = popInteger();
        if(!checkStackSize(signatureCount + 1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_CHECKMULTISIG signatures");
            mValid = false;
            for(unsigned int i = 0; i < publicKeyCount; ++i)
                delete publicKeys[i];
            return false;
        }

        // Pop signatures
        bool strictECDSA_DER_Sigs = mBlockVersion >= 3 &&
          mForks->enabledBlockVersion(mBlockHeight) >= 3;
        NextCash::Buffer *signatures[signatureCount];
        for(unsigned int i = 0; i < signatureCount; ++i)
        {
            signatures[i] = top();
            signatures[i]->setReadOffset(0);
            pop(false);
        }

        // Pop extra item because of bug
        pop();

        // Check the signatures with the public keys to make sure all the signatures
        //  are valid
        unsigned int publicKeyOffset = 0;
        bool signatureVerified;
        bool failed = false;
        NextCash::Buffer *publicKey, *signature;
        for(unsigned int i = 0; i < signatureCount; ++i)
        {
            signatureVerified = false;
            while(publicKeyOffset < publicKeyCount)
            {
                publicKey = publicKeys[publicKeyOffset++];
                signature = signatures[i];
                if(checkSignature(*mTransaction, mInputOffset, mOutputAmount,
                  publicKey->begin(), publicKey->length(), signature->begin(),
                  signature->length(), strictECDSA_DER_Sigs, *mScript, mSigStartOffset,
                  *mForks, mBlockHeight))
                {
                    signatureVerified = true;
                    break;
                }
            }

            if(!signatureVerified)
            {
                failed = true;
                break;
            }
        }

        // Destroy public key and signature buffers.
        for(unsigned int i = 0; i < publicKeyCount; ++i)
            delete publicKeys[i];
        for(unsigned int i = 0; i < signatureCount; ++i)
            delete signatures[i];

        if(failed)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
              "Multiple Signature check failed");
            if(pOpCode == OP_CHECKMULTISIG)
                push(); // Push false onto the stack
            else
            {
                mVerified = false;
                return false;
            }
        }
        else
        {
            if(pOpCode == OP_CHECKMULTISIG)
                push()->writeByte(1); // Push true onto the stack
        }

        return true;
    }

    bool ScriptInterpreter::opCodeCheckDataSig(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!mForks->cashFork201811IsActive(mBlockHeight))
            return true;

        if(!checkStackSize(3))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_CHECKDATASIG");
            mValid = false;
            return false;
        }

        bool failed = false;

        // Pop the public key
        NextCash::Buffer *publicKey = top();
        pop(false);

        // Pop the message
        NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
        NextCash::Hash messageHash;
        digest.setOutputEndian(NextCash::Endian::LITTLE);
        top()->setReadOffset(0);
        digest.writeStream(top(), (unsigned int)top()->length());
        digest.getResult(&messageHash);
        pop();

        // Pop the signature
        NextCash::Buffer *signature = top();
        signature->setReadOffset(0);
        pop(false);

        // Check the signature with the public key
        if(!failed && Key::verify(publicKey->begin(), publicKey->length(),
          signature->begin(), signature->length(), true, messageHash))
        {
            delete publicKey;
            delete signature;
            if(pOpCode == OP_CHECKDATASIG)
                push()->writeByte(1); // Push true onto the stack
        }
        else
        {
            delete publicKey;
            delete signature;
            if(pOpCode == OP_CHECKDATASIG)
                push(); // Push false onto the stack
            else
            {
                mVerified = false;
                return true;
            }
        }

        return true;
    }

    bool ScriptInterpreter::opCodeCheckLockTimeVerify(uint8_t pOpCode)
    {
        if(mBlockVersion < 4 || mForks->enabledBlockVersion(mBlockHeight) < 4)
            return true;

        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_CHECKLOCKTIMEVERIFY");
            mValid = false;
            return false;
        }

        int64_t value;
        if(!arithmeticRead(top(), value))
        {
            mValid = false;
            return false;
        }

        if(value < 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_CHECKLOCKTIMEVERIFY top stack value can't be negative : %d", (int)value);
            mValid = false;
            return false;
        }

        if(mInputSequence == 0xffffffff)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_CHECKLOCKTIMEVERIFY input sequence not 0xffffffff : %08x", mInputSequence);
            mVerified = false;
            return false;
        }

        if(mTransaction == NULL)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_CHECKLOCKTIMEVERIFY Transaction not set");
            mVerified = false;
            return false;
        }

        // Check that the lock time and time in the stack are both the same type (block height or timestamp)
        if(((uint32_t)value < Transaction::LOCKTIME_THRESHOLD &&
          mTransaction->lockTime > Transaction::LOCKTIME_THRESHOLD) ||
          ((uint32_t)value > Transaction::LOCKTIME_THRESHOLD &&
            mTransaction->lockTime < Transaction::LOCKTIME_THRESHOLD))
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_CHECKLOCKTIMEVERIFY value and lock time are different \"types\" : value %d > lock time %d",
              (uint32_t)value, mTransaction->lockTime);
            mVerified = false;
            return false;
        }

        // Check that the lock time has passed
        if(mTransaction == NULL || (uint32_t)value > mTransaction->lockTime)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_CHECKLOCKTIMEVERIFY value greater than lock time : value %d > lock time %d",
              (uint32_t)value, mTransaction->lockTime);
            mVerified = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeCheckSequenceVerify(uint8_t pOpCode)
    {
        if(!mForks->softForkIsActive(mBlockHeight, SoftFork::BIP0112))
            return true;

        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_CHECKSEQUENCEVERIFY");
            mValid = false;
            return false;
        }

        int64_t value;
        if(!arithmeticRead(top(), value))
        {
            mValid = false;
            return false;
        }

        if(value < 0)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Negative script sequence : OP_CHECKSEQUENCEVERIFY");
            mValid = false;
            return false;
        }

        if(!(value & Input::SEQUENCE_DISABLE)) // Script sequence disable bit set
        {
            // Transaction version doesn't support OP_CHECKSEQUENCEVERIFY
            if(mTransaction->version < 2)
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Transaction version less than 2 : OP_CHECKSEQUENCEVERIFY");
                mVerified = false;
                return false;
            }

            if(mInputSequence & Input::SEQUENCE_DISABLE) // Input sequence disable bit set
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Input sequence disable bit set : OP_CHECKSEQUENCEVERIFY");
                mVerified = false;
                return false;
            }

            if((value & Input::SEQUENCE_TYPE) != (mInputSequence & Input::SEQUENCE_TYPE))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Script sequence type doesn't match input sequence type %d != %d : OP_CHECKSEQUENCEVERIFY",
                  (value & Input::SEQUENCE_TYPE) >> 22, (mInputSequence & Input::SEQUENCE_TYPE) >> 22);
                mVerified = false;
                return false;
            }

            if((value & Input::SEQUENCE_LOCKTIME_MASK) > (mInputSequence & Input::SEQUENCE_LOCKTIME_MASK))
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Script sequence greater than input sequence %d > %d : OP_CHECKSEQUENCEVERIFY",
                  value & Input::SEQUENCE_LOCKTIME_MASK, mInputSequence & Input::SEQUENCE_LOCKTIME_MASK);
                mVerified = false;
                return false;
            }
        }

        return true;
    }

    bool ScriptInterpreter::opCodePushData(uint8_t pOpCode)
    {
        NextCash::stream_size count;
        switch(pOpCode)
        {
        case OP_PUSHDATA1: // The next byte contains the number of bytes to be pushed
            count = mScript->readByte();
            if(count > mScript->remaining())
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Push data size more than remaining script : %d/%d", count, mScript->remaining());
                mValid = false;
                return false;
            }

            if(!ifStackTrue())
                mScript->setReadOffset(mScript->readOffset() + count);
            else
                push()->copyBuffer(*mScript, count);
            break;

        case OP_PUSHDATA2: // The next 2 bytes contains the number of bytes to be pushed
            count = mScript->readUnsignedShort();
            if(count > mScript->remaining())
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Push data size more than remaining script : %d/%d", count, mScript->remaining());
                mValid = false;
                return false;
            }

            if(!ifStackTrue())
                mScript->setReadOffset(mScript->readOffset() + count);
            else
                push()->copyBuffer(*mScript, count);
            break;

        case OP_PUSHDATA4: // The next 4 bytes contains the number of bytes to be pushed
            count = mScript->readUnsignedInt();
            if(count > mScript->remaining())
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Push data size more than remaining script : %d/%d", count, mScript->remaining());
                mValid = false;
                return false;
            }

            if(!ifStackTrue())
                mScript->setReadOffset(mScript->readOffset() + count);
            else
                push()->copyBuffer(*mScript, count);
            break;

        default:
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Invalid push data op code %02x", pOpCode);
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodePushNumber(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        switch(pOpCode)
        {
        case OP_1NEGATE: // The number -1 is pushed
            push();
            arithmeticWrite(top(), -1);
            break;
        case OP_1: // The number 1 is pushed
        //case OP_TRUE: // The number 1 is pushed
            push()->writeByte(1);
            break;
        case OP_2: // The number 2 is pushed
            push()->writeByte(2);
            break;
        case OP_3: // The number 3 is pushed
            push()->writeByte(3);
            break;
        case OP_4: // The number 4 is pushed
            push()->writeByte(4);
            break;
        case OP_5: // The number 5 is pushed
            push()->writeByte(5);
            break;
        case OP_6: // The number 6 is pushed
            push()->writeByte(6);
            break;
        case OP_7: // The number 7 is pushed
            push()->writeByte(7);
            break;
        case OP_8: // The number 8 is pushed
            push()->writeByte(8);
            break;
        case OP_9: // The number 9 is pushed
            push()->writeByte(9);
            break;
        case OP_10: // The number 10 is pushed
            push()->writeByte(10);
            break;
        case OP_11: // The number 11 is pushed
            push()->writeByte(11);
            break;
        case OP_12: // The number 12 is pushed
            push()->writeByte(12);
            break;
        case OP_13: // The number 13 is pushed
            push()->writeByte(13);
            break;
        case OP_14: // The number 14 is pushed
            push()->writeByte(14);
            break;
        case OP_15: // The number 15 is pushed
            push()->writeByte(15);
            break;
        case OP_16: // The number 16 is pushed
            push()->writeByte(16);
            break;
        default:
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Invalid push number op code %02x", pOpCode);
            mValid = false;
            return false;
        }

        return true;
    }

    // Arithmetic
    bool ScriptInterpreter::opCodeAdd1(uint8_t pOpCode)
    {
        // Add 1 to the top item on the stack.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_1ADD");
            mValid = false;
            return false;
        }

        int64_t value;
        if(!arithmeticRead(top(), value))
        {
            mValid = false;
            return false;
        }

        arithmeticWrite(top(), value + 1);
        return true;
    }

    bool ScriptInterpreter::opCodeSubtract1(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_1SUB");
            mValid = false;
            return false;
        }

        int64_t value;
        if(!arithmeticRead(top(), value))
        {
            mValid = false;
            return false;
        }

        arithmeticWrite(top(), value - 1);
        return true;
    }

    bool ScriptInterpreter::opCodeNegate(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_NEGATE");
            mValid = false;
            return false;
        }

        int64_t value;
        if(!arithmeticRead(top(), value))
        {
            mValid = false;
            return false;
        }

        arithmeticWrite(top(), -value);
        return true;
    }

    bool ScriptInterpreter::opCodeAbs(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_ABS");
            mValid = false;
            return false;
        }

        int64_t value;
        if(!arithmeticRead(top(), value))
        {
            mValid = false;
            return false;
        }

        if(value < 0)
            arithmeticWrite(top(), -value);
        return true;
    }

    bool ScriptInterpreter::opCodeNot(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_NOT");
            mValid = false;
            return false;
        }

        int64_t value;
        if(!arithmeticRead(top(), value))
        {
            mValid = false;
            return false;
        }

        top()->clear();
        if(value == 0)
            top()->writeByte(1);
        return true;
    }

    bool ScriptInterpreter::opCodeZeroNotEqual(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_0NOTEQUAL");
            mValid = false;
            return false;
        }

        int64_t value;
        if(!arithmeticRead(top(), value))
        {
            mValid = false;
            return false;
        }

        top()->clear();
        if(value != 0)
            top()->writeByte(1);
        return true;
    }

    bool ScriptInterpreter::opCodeAdd(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_ADD");
            mValid = false;
            return false;
        }

        int64_t b;
        if(!arithmeticRead(top(), b))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t a;
        if(!arithmeticRead(top(), a))
        {
            mValid = false;
            return false;
        }

        arithmeticWrite(top(), a + b);
        return true;
    }

    bool ScriptInterpreter::opCodeSubtract(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_SUB");
            mValid = false;
            return false;
        }

        int64_t b;
        if(!arithmeticRead(top(), b))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t a;
        if(!arithmeticRead(top(), a))
        {
            mValid = false;
            return false;
        }

        arithmeticWrite(top(), a - b);
        return true;
    }

    bool ScriptInterpreter::opCodeMultiply(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201811IsActive(mBlockHeight))
        {
            if(!checkStackSize(2))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_MUL");
                mValid = false;
                return false;
            }

            if(top()->length() > mForks->elementMaxSize(mBlockHeight))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Value element longer than max element size for OP_MUL");
                mValid = false;
                return false;
            }

            int64_t b;
            if(!arithmeticRead(top(), b))
            {
                mValid = false;
                return false;
            }
            pop();

            int64_t a;
            if(!arithmeticRead(top(), a))
            {
                mValid = false;
                return false;
            }

            arithmeticWrite(top(), a * b);
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_MUL is a disabled op code");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeDivide(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201805IsActive(mBlockHeight))
        {
            if(!checkStackSize(2))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_DIV");
                mValid = false;
                return false;
            }

            int64_t b;
            if(!arithmeticRead(top(), b))
            {
                mValid = false;
                return false;
            }
            pop();

            int64_t a;
            if(!arithmeticRead(top(), a))
            {
                mValid = false;
                return false;
            }

            if(b == 0)
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Divide by zero for OP_DIV");
                mValid = false;
                return false;
            }

            arithmeticWrite(top(), a / b);
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_DIV is a disabled op code");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeMod(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201805IsActive(mBlockHeight))
        {
            if(!checkStackSize(2))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_MOD");
                mValid = false;
                return false;
            }

            int64_t b;
            if(!arithmeticRead(top(), b))
            {
                mValid = false;
                return false;
            }
            pop();

            int64_t a;
            if(!arithmeticRead(top(), a))
            {
                mValid = false;
                return false;
            }

            if(b == 0)
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Divide by zero for OP_MOD");
                mValid = false;
                return false;
            }

            arithmeticWrite(top(), a % b);
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_MOD is a disabled op code");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeLeftShift(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201811IsActive(mBlockHeight))
        {
            if(!checkStackSize(2))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_LSHIFT");
                mValid = false;
                return false;
            }

            if(top()->length() > mForks->elementMaxSize(mBlockHeight))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Value element longer than max element size for OP_LSHIFT");
                mValid = false;
                return false;
            }

            int64_t n;
            if(!arithmeticRead(top(), n))
            {
                mValid = false;
                return false;
            }
            pop();

            if(top()->length() > mForks->elementMaxSize(mBlockHeight))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Value element longer than max element size for OP_LSHIFT");
                mValid = false;
                return false;
            }

            leftShift(*top(), n);
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_LSHIFT is a disabled op code");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeRightShift(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201811IsActive(mBlockHeight))
        {
            if(!checkStackSize(2))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_RSHIFT");
                mValid = false;
                return false;
            }

            if(top()->length() > mForks->elementMaxSize(mBlockHeight))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Value element longer than max element size for OP_RSHIFT");
                mValid = false;
                return false;
            }

            int64_t n;
            if(!arithmeticRead(top(), n))
            {
                mValid = false;
                return false;
            }
            pop();

            if(top()->length() > mForks->elementMaxSize(mBlockHeight))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Value element longer than max element size for OP_RSHIFT");
                mValid = false;
                return false;
            }

            rightShift(*top(), n);
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_RSHIFT is a disabled op code");
            mValid = false;
            return false;
        }
        return true;
    }

    bool ScriptInterpreter::opCodeBoolAnd(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_BOOLAND");
            mValid = false;
            return false;
        }

        int64_t a;
        if(!arithmeticRead(top(), a))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t b;
        if(!arithmeticRead(top(), b))
        {
            mValid = false;
            return false;
        }

        top()->clear();
        if(a != 0 && b != 0)
            top()->writeByte(1);
        return true;
    }

    bool ScriptInterpreter::opCodeBoolOr(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_BOOLOR");
            mValid = false;
            return false;
        }

        int64_t a;
        if(!arithmeticRead(top(), a))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t b;
        if(!arithmeticRead(top(), b))
        {
            mValid = false;
            return false;
        }

        top()->clear();
        if(a != 0 || b != 0)
            top()->writeByte(1);
        return true;
    }

    bool ScriptInterpreter::opCodeNumEqual(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_NUMEQUAL");
            mValid = false;
            return false;
        }

        int64_t a;
        if(!arithmeticRead(top(), a))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t b;
        if(!arithmeticRead(top(), b))
        {
            mValid = false;
            return false;
        }

        top()->clear();
        if(pOpCode == OP_NUMEQUALVERIFY)
        {
            if(a != b)
            {
                mVerified = false;
                return false;
            }
        }
        else
        {
            if(a == b)
                top()->writeByte(1);
        }
        return true;
    }

    bool ScriptInterpreter::opCodeNumNotEqual(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_NUMNOTEQUAL");
            mValid = false;
            return false;
        }

        int64_t a;
        if(!arithmeticRead(top(), a))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t b;
        if(!arithmeticRead(top(), b))
        {
            mValid = false;
            return false;
        }

        top()->clear();
        if(a != b)
            top()->writeByte(1);
        return true;
    }

    bool ScriptInterpreter::opCodeLessThan(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_LESSTHAN");
            mValid = false;
            return false;
        }

        int64_t b;
        if(!arithmeticRead(top(), b))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t a;
        if(!arithmeticRead(top(), a))
        {
            mValid = false;
            return false;
        }

        top()->clear();
        if(a < b)
            top()->writeByte(1);
        return true;
    }

    bool ScriptInterpreter::opCodeGreaterThan(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_GREATERTHAN");
            mValid = false;
            return false;
        }

        int64_t b;
        if(!arithmeticRead(top(), b))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t a;
        if(!arithmeticRead(top(), a))
        {
            mValid = false;
            return false;
        }

        top()->clear();
        if(a > b)
            top()->writeByte(1);
        return true;
    }

    bool ScriptInterpreter::opCodeLessThanOrEqual(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_LESSTHANOREQUAL");
            mValid = false;
            return false;
        }

        int64_t b;
        if(!arithmeticRead(top(), b))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t a;
        if(!arithmeticRead(top(), a))
        {
            mValid = false;
            return false;
        }

        top()->clear();
        if(a <= b)
            top()->writeByte(1);
        return true;
    }

    bool ScriptInterpreter::opCodeGreaterThanOrEqual(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_GREATERTHANOREQUAL");
            mValid = false;
            return false;
        }

        int64_t b;
        if(!arithmeticRead(top(), b))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t a;
        if(!arithmeticRead(top(), a))
        {
            mValid = false;
            return false;
        }

        top()->clear();
        if(a >= b)
            top()->writeByte(1);
        return true;
    }

    bool ScriptInterpreter::opCodeMin(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_MIN");
            mValid = false;
            return false;
        }

        int64_t a;
        if(!arithmeticRead(top(), a))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t b;
        if(!arithmeticRead(top(), b))
        {
            mValid = false;
            return false;
        }

        top()->setWriteOffset(0);
        if(a < b)
            arithmeticWrite(top(), a);
        else
            arithmeticWrite(top(), b);
        return true;
    }

    bool ScriptInterpreter::opCodeMax(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_MAX");
            mValid = false;
            return false;
        }

        int64_t a;
        if(!arithmeticRead(top(), a))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t b;
        if(!arithmeticRead(top(), b))
        {
            mValid = false;
            return false;
        }

        top()->setWriteOffset(0);
        if(a > b)
            arithmeticWrite(top(), a);
        else
            arithmeticWrite(top(), b);
        return true;
    }

    bool ScriptInterpreter::opCodeWithin(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(3))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_WITHIN");
            mValid = false;
            return false;
        }

        int64_t max;
        if(!arithmeticRead(top(), max))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t min;
        if(!arithmeticRead(top(), min))
        {
            mValid = false;
            return false;
        }
        pop();

        int64_t x;
        if(!arithmeticRead(top(), x))
        {
            mValid = false;
            return false;
        }

        top()->clear();
        if(x >= min && x < max)
            top()->writeByte(1);
        return true;
    }

    // Stack
    bool ScriptInterpreter::opCodeToAltStack(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_TOALTSTACK");
            mValid = false;
            return false;
        }

        pushAlt(top());
        pop(false);
        return true;
    }

    bool ScriptInterpreter::opCodeFromAltStack(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkAltStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Alt Stack not large enough for OP_FROMALTSTACK");
            mValid = false;
            return false;
        }

        push(topAlt());
        popAlt(false);
        return true;
    }

    bool ScriptInterpreter::opCodeDup(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_DUP");
            mValid = false;
            return false;
        }

        top()->setReadOffset(0);
        push(new NextCash::Buffer(*top()));
        return true;
    }

    bool ScriptInterpreter::opCodeIfDup(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_IFDUP");
            mValid = false;
            return false;
        }

        if(!bufferIsZero(top()))
        {
            top()->setReadOffset(0);
            push(new NextCash::Buffer(*top(), true));
        }
        return true;
    }

    bool ScriptInterpreter::opCodeDepth(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;
        arithmeticWrite(push(), mStack.size());
        return true;
    }

    bool ScriptInterpreter::opCodeDrop(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_DROP");
            mValid = false;
            return false;
        }

        pop();
        return true;
    }

    bool ScriptInterpreter::opCodeNip(uint8_t pOpCode)
    {
        // Removes the second-to-top stack item.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_NIP");
            mValid = false;
            return false;
        }

        std::list<NextCash::Buffer *>::iterator secondToLast = mStack.end();
        --secondToLast;
        --secondToLast;
        delete *secondToLast;
        mStack.erase(secondToLast);
        return true;
    }

    bool ScriptInterpreter::opCodeOver(uint8_t pOpCode)
    {
        // Copies the second-to-top stack item to the top.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_OVER");
            mValid = false;
            return false;
        }

        std::list<NextCash::Buffer *>::iterator secondToLast = mStack.end();
        --secondToLast;
        --secondToLast;

        push(new NextCash::Buffer(**secondToLast));
        return true;
    }

    bool ScriptInterpreter::opCodePick(uint8_t pOpCode)
    {
        // The item n back in the stack is copied to the top.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_PICK");
            mValid = false;
            return false;
        }

        int64_t n;
        if(!arithmeticRead(top(), n))
        {
            mValid = false;
            return false;
        }
        pop();

        if(!checkStackSize(n))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_ROLL");
            mValid = false;
            return false;
        }

        std::list<NextCash::Buffer *>::iterator item = mStack.end();
        --item; // get last item

        for(unsigned int i=0;i<n;i++)
            --item;

        push(new NextCash::Buffer(**item));
        return true;
    }

    bool ScriptInterpreter::opCodeRoll(uint8_t pOpCode)
    {
        // The item n back in the stack is moved to the top.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_ROLL");
            mValid = false;
            return false;
        }

        int64_t n;
        if(!arithmeticRead(top(), n))
        {
            mValid = false;
            return false;
        }
        pop();

        if(!checkStackSize(n))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_ROLL");
            mValid = false;
            return false;
        }

        std::list<NextCash::Buffer *>::iterator item = mStack.end();
        --item; // get last item

        for(unsigned int i = 0; i < n; ++i)
            --item;

        push(*item);
        mStack.erase(item);
        return true;
    }

    bool ScriptInterpreter::opCodeRotate(uint8_t pOpCode)
    {
        // The top three items on the stack are rotated to the left.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(3))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_ROT");
            mValid = false;
            return false;
        }

        NextCash::Buffer *three = top();
        pop(false);
        NextCash::Buffer *two = top();
        pop(false);
        NextCash::Buffer *one = top();
        pop(false);

        push(two);
        push(three);
        push(one);
        return true;
    }

    bool ScriptInterpreter::opCodeSwap(uint8_t pOpCode)
    {
        // The top two items on the stack are swapped.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_SWAP");
            mValid = false;
            return false;
        }

        NextCash::Buffer *two = top();
        pop(false);
        NextCash::Buffer *one = top();
        pop(false);

        push(two);
        push(one);
        return true;
    }

    bool ScriptInterpreter::opCodeTuck(uint8_t pOpCode)
    {
        // The item at the top of the stack is copied and inserted before the second-to-top item.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_TUCK");
            mValid = false;
            return false;
        }

        NextCash::Buffer *two = top();
        pop(false);
        NextCash::Buffer *one = top();
        pop(false);

        push(new NextCash::Buffer(*two));
        push(one);
        push(two);
        return true;
    }

    bool ScriptInterpreter::opCodeDrop2(uint8_t pOpCode)
    {
        // Removes the top two stack items.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_2DROP");
            mValid = false;
            return false;
        }

        pop();
        pop();
        return true;
    }

    bool ScriptInterpreter::opCodeDup2(uint8_t pOpCode)
    {
        // Duplicates the top two stack items.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_ROLL");
            mValid = false;
            return false;
        }

        std::list<NextCash::Buffer *>::iterator two = mStack.end();
        --two; // get last item
        std::list<NextCash::Buffer *>::iterator one = two;
        --one; // get the second to last item

        push(new NextCash::Buffer(**one));
        push(new NextCash::Buffer(**two));
        return true;
    }

    bool ScriptInterpreter::opCodeDup3(uint8_t pOpCode)
    {
        // Duplicates the top three stack items.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_3DUP");
            mValid = false;
            return false;
        }

        std::list<NextCash::Buffer *>::iterator three = mStack.end();
        --three; // get last item
        std::list<NextCash::Buffer *>::iterator two = three;
        --two; // get second to last item
        std::list<NextCash::Buffer *>::iterator one = two;
        --one; // get the third to last item

        push(new NextCash::Buffer(**one));
        push(new NextCash::Buffer(**two));
        push(new NextCash::Buffer(**three));
        return true;
    }

    bool ScriptInterpreter::opCodeOver2(uint8_t pOpCode)
    {
        // Copies the pair of items two spaces back in the stack to the front.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(4))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_2OVER");
            mValid = false;
            return false;
        }

        std::list<NextCash::Buffer *>::iterator two = mStack.end();
        --two; // 4
        --two; // 3
        --two; // 2
        std::list<NextCash::Buffer *>::iterator one = two;
        --one; // 1

        push(new NextCash::Buffer(**one));
        push(new NextCash::Buffer(**two));
        return true;
    }

    bool ScriptInterpreter::opCodeRotate2(uint8_t pOpCode)
    {
        // The fifth and sixth items back are moved to the top of the stack.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(6))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_ROLL");
            mValid = false;
            return false;
        }

        std::list<NextCash::Buffer *>::iterator two = mStack.end();
        --two; // 6
        --two; // 5
        --two; // 4
        --two; // 3
        --two; // 2
        std::list<NextCash::Buffer *>::iterator one = two;
        --one; // 1

        NextCash::Buffer *itemTwo = *two;
        NextCash::Buffer *itemOne = *one;

        mStack.erase(one);
        mStack.erase(two);

        push(itemOne);
        push(itemTwo);
        return true;
    }

    bool ScriptInterpreter::opCodeSwap2(uint8_t pOpCode)
    {
        // Swaps the top two pairs of items.
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(2))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_ROLL");
            mValid = false;
            return false;
        }

        std::list<NextCash::Buffer *>::iterator two = mStack.end();
        --two; // 4
        --two; // 3
        --two; // 2
        std::list<NextCash::Buffer *>::iterator one = two;
        --one; // 1

        NextCash::Buffer *itemTwo = *two;
        NextCash::Buffer *itemOne = *one;

        mStack.erase(one);
        mStack.erase(two);

        push(itemOne);
        push(itemTwo);
        return true;
    }

    // Splice
    bool ScriptInterpreter::opCodeConcat(uint8_t pOpCode)
    {
        // Concatenates two strings.
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201805IsActive(mBlockHeight))
        {
            if(!checkStackSize(2))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_CAT");
                mValid = false;
                return false;
            }

            NextCash::Buffer *two = top();
            pop(false);
            NextCash::Buffer *one = top();

            if(one->length() + two->length() > mForks->elementMaxSize(mBlockHeight))
            {
                // Put two back one stack since it hasn't been deleted yet.
                push(two);

                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack elements too large for OP_CAT");
                mValid = false;
                return false;
            }

            // Append two to the end of one
            one->setWriteOffset(one->length());
            two->setReadOffset(0);
            one->writeStream(two, two->length());

            // Delete two
            delete two;
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_CAT is a disabled op code");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeSplit(uint8_t pOpCode)
    {
        // Split byte sequence x at position n
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201805IsActive(mBlockHeight))
        {
            if(!checkStackSize(2))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_SPLIT");
                mValid = false;
                return false;
            }

            // Pull n off the stack
            int64_t n;
            if(!arithmeticRead(top(), n))
            {
                mValid = false;
                return false;
            }
            pop();

            if(n < 0)
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack element negative for OP_SPLIT length");
                mValid = false;
                return false;
            }

            // Get x from stack
            NextCash::Buffer *x = top();

            if(x->length() > mForks->elementMaxSize(mBlockHeight))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack element too large for OP_SPLIT");
                mValid = false;
                return false;
            }

            if((unsigned int)n > x->length())
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "OP_SPLIT byte count is past end of data element to be split");
                mValid = false;
                return false;
            }

            // Split x after n bytes leaving first part in x and putting second part in two.
            NextCash::Buffer *two = new NextCash::Buffer();

            if(n == 0)
            {
                // Put an empty value in front of x
                pop(false); // pop x
                push(two);
                push(x);
            }
            else
            {
                x->setReadOffset(n);
                two->writeStream(x, x->remaining());
                x->setReadOffset(0);
                x->setEnd(n);
                push(two);
            }
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_SUBSTR is a disabled op code");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeNum2Bin(uint8_t pOpCode)
    {
        // Convert numeric value a into byte sequence of length b
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201805IsActive(mBlockHeight))
        {
            if(!checkStackSize(2))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_NUM2BIN");
                mValid = false;
                return false;
            }

            int64_t length;
            if(!arithmeticRead(top(), length))
            {
                mValid = false;
                return false;
            }
            pop();

            int64_t n;
            unsigned int nLength = top()->length();
            if(!arithmeticRead(top(), n))
            {
                mValid = false;
                return false;
            }

            if(length < nLength)
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Length element too short for OP_NUM2BIN");
                mValid = false;
                return false;
            }

            if(length > mForks->elementMaxSize(mBlockHeight))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Length element more than max element size for OP_NUM2BIN");
                mValid = false;
                return false;
            }

            NextCash::Buffer *out = top();
            bool nIsNegative = n < 0;

            if(nIsNegative)
                n = -n;
            out->clear();

            for(int i=0;i<length;++i)
            {
                if(i < 8)
                    out->writeByte((n >> (i * 8)) & 0xff);
                else
                    out->writeByte(0);
            }

            if(nIsNegative)
            {
                // Add negative bit to last byte
                out->setWriteOffset(out->writeOffset() - 1);
                out->setReadOffset(out->writeOffset());
                out->writeByte(out->readByte() | 0x80);
            }
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_LEFT is a disabled op code");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeBin2Num(uint8_t pOpCode)
    {
        // Convert byte sequence x into a numeric value
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201805IsActive(mBlockHeight))
        {
            if(!checkStackSize(1))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_BIN2NUM");
                mValid = false;
                return false;
            }

            int64_t n = 0;
            int offset = 0;
            NextCash::Buffer *x = top();

            if(x->length() > mForks->elementMaxSize(mBlockHeight))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Value element longer than max element size for OP_BIN2NUM");
                mValid = false;
                return false;
            }

            x->setReadOffset(0);
            while(x->remaining() > 1)
            {
                if(offset >= 8)
                {
                    if(x->readByte() != 0)
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Value element larger than max numeric for OP_BIN2NUM");
                        mValid = false;
                        return false;
                    }
                }
                else
                {
                    n |= x->readByte() << (offset * 8);
                    ++offset;
                }
            }

            if(x->remaining())
            {
                if(offset >= 8)
                {
                    uint8_t byte = x->readByte();

                    // Bytes past end of numeric can only have negative bit
                    if(byte == 0x80)
                        n = -n;
                    else if(byte != 0)
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Value element larger than max numeric for OP_BIN2NUM");
                        mValid = false;
                        return false;
                    }
                }
                else
                {
                    // Check for negative bit
                    uint8_t byte = x->readByte();
                    n |= (byte & 0x7f) << (offset * 8);
                    if(byte & 0x80)
                        n = -n;
                }
            }

            arithmeticWrite(x, n);
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_RIGHT is a disabled op code");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeSize(uint8_t pOpCode)
    {
        // Pushes the string length of the top element of the stack (without popping it).
        if(!ifStackTrue())
            return true;

        if(!checkStackSize(1))
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Stack not large enough for OP_SIZE");
            mValid = false;
            return false;
        }

        int64_t itemSize = top()->length();
        push();
        arithmeticWrite(top(), itemSize);
        return true;
    }


    // Bitwise logic
    bool ScriptInterpreter::opCodeInvert(uint8_t pOpCode)
    {
        // Flips all of the bits in the input.
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201811IsActive(mBlockHeight))
        {
            if(!checkStackSize(1))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_INVERT");
                mValid = false;
                return false;
            }

            if(top()->length() > mForks->elementMaxSize(mBlockHeight))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Value element longer than max element size for OP_INVERT");
                mValid = false;
                return false;
            }

            // Invert each byte.
            uint8_t *byte = top()->begin();
            for(unsigned int i = 0; i < top()->length(); ++i, ++byte)
                *byte = ~*byte;
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_INVERT is a disabled op code");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeAnd(uint8_t pOpCode)
    {
        // Bitwise and between each bit in the inputs.
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201805IsActive(mBlockHeight))
        {
            if(!checkStackSize(2))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_AND");
                mValid = false;
                return false;
            }

            NextCash::Buffer *two = top();
            pop(false);
            NextCash::Buffer *one = top();

            if(two->length() != one->length())
            {
                push(two);

                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack item lengths don't match for OP_AND");
                mValid = false;
                return false;
            }
            else if(one->length() > 0)
            {
                one->setReadOffset(0);
                two->setReadOffset(0);
                one->setWriteOffset(0);

                while(two->remaining())
                    one->writeByte(one->readByte() & two->readByte());

                delete two;
            }
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_RIGHT is a disabled op code");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeOr(uint8_t pOpCode)
    {
        // Bitwise or between each bit in the inputs.
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201805IsActive(mBlockHeight))
        {
            if(!checkStackSize(2))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_OR");
                mValid = false;
                return false;
            }

            NextCash::Buffer *two = top();
            pop(false);
            NextCash::Buffer *one = top();

            if(two->length() != one->length())
            {
                push(two);

                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack item lengths don't match for OP_OR");
                mValid = false;
                return false;
            }
            else if(one->length() > 0)
            {
                one->setReadOffset(0);
                two->setReadOffset(0);
                one->setWriteOffset(0);

                while(two->remaining())
                    one->writeByte(one->readByte() | two->readByte());

                delete two;
            }
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_RIGHT is a disabled op code");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeXor(uint8_t pOpCode)
    {
        // Boolean exclusive or between each bit in the inputs.
        if(!ifStackTrue())
            return true;

        if(mForks->cashFork201805IsActive(mBlockHeight))
        {
            if(!checkStackSize(2))
            {
                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack not large enough for OP_XOR");
                mValid = false;
                return false;
            }

            NextCash::Buffer *two = top();
            pop(false);
            NextCash::Buffer *one = top();

            if(two->length() != one->length())
            {
                push(two);

                NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack item lengths don't match for OP_XOR");
                mValid = false;
                return false;
            }
            else if(one->length() > 0)
            {
                one->setReadOffset(0);
                two->setReadOffset(0);
                one->setWriteOffset(0);

                while(two->remaining())
                    one->writeByte(one->readByte() ^ two->readByte());

                delete two;
            }
        }
        else
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "OP_RIGHT is a disabled op code");
            mValid = false;
            return false;
        }

        return true;
    }

    bool ScriptInterpreter::opCodeDisabled(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
          "Op code is disabled : %02x", pOpCode);
        mValid = false;
        return false;
    }

    bool ScriptInterpreter::opCodeReserved(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        mValid = false;
        return false;
    }

    bool ScriptInterpreter::opCodeNoOp(uint8_t pOpCode)
    {
        return true;
    }

    bool ScriptInterpreter::opCodeUndefined(uint8_t pOpCode)
    {
        if(!ifStackTrue())
            return true;

        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
          "Undefined op code : %02x", pOpCode);
        mValid = false;
        return false;
    }

    const char *ScriptInterpreter::sOpCodeNames[256];
    bool (ScriptInterpreter::*ScriptInterpreter::sExecuteOpCode[256])(uint8_t pOpCode);

    void ScriptInterpreter::initializeStatic()
    {
        // Initialize all to unknown.
        for(unsigned int i = 0; i < 256; ++i)
        {
            sExecuteOpCode[i] = &ScriptInterpreter::opCodeUndefined;
            sOpCodeNames[i] = "<UNDEFINED>";
        }

        // False
        sExecuteOpCode[OP_0] = &ScriptInterpreter::opCodePushFalse;

        // Push single byte length data
        for(unsigned int i = 1; i <= MAX_SINGLE_BYTE_PUSH_DATA_CODE; ++i)
        {
            sExecuteOpCode[i] = &ScriptInterpreter::opCodeSingleBytePush;
            sOpCodeNames[i] = "<OP_PUSH_BYTE>";
        }

        // Push data
        sExecuteOpCode[OP_PUSHDATA1] = &ScriptInterpreter::opCodePushData;
        sOpCodeNames[OP_PUSHDATA1] = "<OP_PUSHDATA1>";
        sExecuteOpCode[OP_PUSHDATA2] = &ScriptInterpreter::opCodePushData;
        sOpCodeNames[OP_PUSHDATA2] = "<OP_PUSHDATA2>";
        sExecuteOpCode[OP_PUSHDATA4] = &ScriptInterpreter::opCodePushData;
        sOpCodeNames[OP_PUSHDATA4] = "<OP_PUSHDATA4>";

        // Small integers
        sExecuteOpCode[OP_1NEGATE] = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_1NEGATE]   = "<-1>";
        sExecuteOpCode[OP_1]       = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_1]         = "<1>";
        sExecuteOpCode[OP_2]       = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_2]         = "<2>";
        sExecuteOpCode[OP_3]       = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_3]         = "<3>";
        sExecuteOpCode[OP_4]       = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_4]         = "<4>";
        sExecuteOpCode[OP_5]       = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_5]         = "<5>";
        sExecuteOpCode[OP_6]       = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_6]         = "<6>";
        sExecuteOpCode[OP_7]       = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_7]         = "<7>";
        sExecuteOpCode[OP_8]       = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_8]         = "<8>";
        sExecuteOpCode[OP_9]       = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_9]         = "<9>";
        sExecuteOpCode[OP_10]      = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_10]        = "<10>";
        sExecuteOpCode[OP_11]      = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_11]        = "<11>";
        sExecuteOpCode[OP_12]      = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_12]        = "<12>";
        sExecuteOpCode[OP_13]      = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_13]        = "<13>";
        sExecuteOpCode[OP_14]      = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_14]        = "<14>";
        sExecuteOpCode[OP_15]      = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_15]        = "<15>";
        sExecuteOpCode[OP_16]      = &ScriptInterpreter::opCodePushNumber;
        sOpCodeNames[OP_16]        = "<16>";

        // Conditional
        sExecuteOpCode[OP_IF]         = &ScriptInterpreter::opCodeIf;
        sOpCodeNames[OP_IF]           = "<OP_IF>";
        sExecuteOpCode[OP_NOTIF]      = &ScriptInterpreter::opCodeNotIf;
        sOpCodeNames[OP_NOTIF]        = "<OP_NOTIF>";
        sExecuteOpCode[OP_ELSE]       = &ScriptInterpreter::opCodeElse;
        sOpCodeNames[OP_ELSE]         = "<OP_ELSE>";
        sExecuteOpCode[OP_ENDIF]      = &ScriptInterpreter::opCodeEndIf;
        sOpCodeNames[OP_ENDIF]        = "<OP_ENDIF>";

        // Control
        sExecuteOpCode[OP_VERIFY]      = &ScriptInterpreter::opCodeVerify;
        sOpCodeNames[OP_VERIFY]        = "<OP_VERIFY>";
        sExecuteOpCode[OP_RETURN]      = &ScriptInterpreter::opCodeReturn;
        sOpCodeNames[OP_RETURN]        = "<OP_RETURN>";

        // Compare
        sExecuteOpCode[OP_EQUAL]       = &ScriptInterpreter::opCodeEqual;
        sOpCodeNames[OP_EQUAL]         = "<OP_EQUAL>";
        sExecuteOpCode[OP_EQUALVERIFY] = &ScriptInterpreter::opCodeEqual;
        sOpCodeNames[OP_EQUALVERIFY]   = "<OP_EQUALVERIFY>";

        // Hashes
        sExecuteOpCode[OP_RIPEMD160] = &ScriptInterpreter::opCodeHash;
        sOpCodeNames[OP_RIPEMD160] = "<OP_RIPEMD160>";
        sExecuteOpCode[OP_SHA1]      = &ScriptInterpreter::opCodeHash;
        sOpCodeNames[OP_SHA1] = "<OP_SHA1>";
        sExecuteOpCode[OP_SHA256]    = &ScriptInterpreter::opCodeHash;
        sOpCodeNames[OP_SHA256] = "<OP_SHA256>";
        sExecuteOpCode[OP_HASH160]   = &ScriptInterpreter::opCodeHash;
        sOpCodeNames[OP_HASH160] = "<OP_HASH160>";
        sExecuteOpCode[OP_HASH256]   = &ScriptInterpreter::opCodeHash;
        sOpCodeNames[OP_HASH256] = "<OP_HASH256>";

        sExecuteOpCode[OP_CODESEPARATOR] = &ScriptInterpreter::opCodeSeparator;
        sOpCodeNames[OP_CODESEPARATOR]   = "<OP_CODESEPARATOR>";

        // Signatures
        sExecuteOpCode[OP_CHECKSIG]            = &ScriptInterpreter::opCodeCheckSig;
        sOpCodeNames[OP_CHECKSIG]              = "<OP_CHECKSIG>";
        sExecuteOpCode[OP_CHECKSIGVERIFY]      = &ScriptInterpreter::opCodeCheckSig;
        sOpCodeNames[OP_CHECKSIGVERIFY]        = "<OP_CHECKSIGVERIFY>";
        sExecuteOpCode[OP_CHECKMULTISIG]       = &ScriptInterpreter::opCodeCheckMultiSig;
        sOpCodeNames[OP_CHECKMULTISIG]         = "<OP_CHECKMULTISIG>";
        sExecuteOpCode[OP_CHECKMULTISIGVERIFY] = &ScriptInterpreter::opCodeCheckMultiSig;
        sOpCodeNames[OP_CHECKMULTISIGVERIFY]   = "<OP_CHECKMULTISIGVERIFY>";
        sExecuteOpCode[OP_CHECKDATASIG]        = &ScriptInterpreter::opCodeCheckDataSig;
        sOpCodeNames[OP_CHECKDATASIG]          = "<OP_CHECKDATASIG>";
        sExecuteOpCode[OP_CHECKDATASIGVERIFY]  = &ScriptInterpreter::opCodeCheckDataSig;
        sOpCodeNames[OP_CHECKDATASIGVERIFY]    = "<OP_CHECKDATASIGVERIFY>";

        // Time locks
        sExecuteOpCode[OP_CHECKLOCKTIMEVERIFY]  = &ScriptInterpreter::opCodeCheckLockTimeVerify;
        sOpCodeNames[OP_CHECKLOCKTIMEVERIFY]    = "<OP_CHECKLOCKTIMEVERIFY>";
        sExecuteOpCode[OP_CHECKSEQUENCEVERIFY]  = &ScriptInterpreter::opCodeCheckSequenceVerify;
        sOpCodeNames[OP_CHECKSEQUENCEVERIFY]    = "<OP_CHECKSEQUENCEVERIFY>";

        // Math
        sExecuteOpCode[OP_1ADD]      = &ScriptInterpreter::opCodeAdd1;
        sOpCodeNames[OP_1ADD]        = "<OP_1ADD>";
        sExecuteOpCode[OP_1SUB]      = &ScriptInterpreter::opCodeSubtract1;
        sOpCodeNames[OP_1SUB]        = "<OP_1SUB>";
        sExecuteOpCode[OP_NEGATE]    = &ScriptInterpreter::opCodeNegate;
        sOpCodeNames[OP_NEGATE]      = "<OP_NEGATE>";
        sExecuteOpCode[OP_ABS]       = &ScriptInterpreter::opCodeAbs;
        sOpCodeNames[OP_ABS]         = "<OP_ABS>";
        sExecuteOpCode[OP_NOT]       = &ScriptInterpreter::opCodeNot;
        sOpCodeNames[OP_NOT]         = "<OP_NOT>";
        sExecuteOpCode[OP_0NOTEQUAL] = &ScriptInterpreter::opCodeZeroNotEqual;
        sOpCodeNames[OP_0NOTEQUAL]   = "<OP_0NOTEQUAL>";
        sExecuteOpCode[OP_ADD]       = &ScriptInterpreter::opCodeAdd;
        sOpCodeNames[OP_ADD]         = "<OP_ADD>";
        sExecuteOpCode[OP_SUB]       = &ScriptInterpreter::opCodeSubtract;
        sOpCodeNames[OP_SUB]         = "<OP_SUB>";
        sExecuteOpCode[OP_MUL]       = &ScriptInterpreter::opCodeMultiply;
        sOpCodeNames[OP_MUL]         = "<OP_MUL>";
        sExecuteOpCode[OP_DIV]       = &ScriptInterpreter::opCodeDivide;
        sOpCodeNames[OP_DIV]         = "<OP_DIV>";
        sExecuteOpCode[OP_MOD]       = &ScriptInterpreter::opCodeMod;
        sOpCodeNames[OP_MOD]         = "<OP_MOD>";
        sExecuteOpCode[OP_2MUL]      = &ScriptInterpreter::opCodeDisabled;
        sOpCodeNames[OP_2MUL]        = "<OP_2MUL>";
        sExecuteOpCode[OP_2DIV]      = &ScriptInterpreter::opCodeDisabled;
        sOpCodeNames[OP_2DIV]        = "<OP_2DIV>";

        // Bitwise
        sExecuteOpCode[OP_LSHIFT]  = &ScriptInterpreter::opCodeLeftShift;
        sOpCodeNames[OP_LSHIFT]    = "<OP_LSHIFT>";
        sExecuteOpCode[OP_RSHIFT]  = &ScriptInterpreter::opCodeRightShift;
        sOpCodeNames[OP_RSHIFT]    = "<OP_RSHIFT>";
        sExecuteOpCode[OP_BOOLAND] = &ScriptInterpreter::opCodeBoolAnd;
        sOpCodeNames[OP_BOOLAND]   = "<OP_BOOLAND>";
        sExecuteOpCode[OP_BOOLOR]  = &ScriptInterpreter::opCodeBoolOr;
        sOpCodeNames[OP_BOOLOR]    = "<OP_BOOLOR>";

        // Comparison
        sExecuteOpCode[OP_NUMEQUAL]           = &ScriptInterpreter::opCodeNumEqual;
        sOpCodeNames[OP_NUMEQUAL]             = "<OP_NUMEQUAL>";
        sExecuteOpCode[OP_NUMEQUALVERIFY]     = &ScriptInterpreter::opCodeNumEqual;
        sOpCodeNames[OP_NUMEQUALVERIFY]       = "<OP_NUMEQUALVERIFY>";
        sExecuteOpCode[OP_NUMNOTEQUAL]        = &ScriptInterpreter::opCodeNumNotEqual;
        sOpCodeNames[OP_NUMNOTEQUAL]          = "<OP_NUMNOTEQUAL>";
        sExecuteOpCode[OP_LESSTHAN]           = &ScriptInterpreter::opCodeLessThan;
        sOpCodeNames[OP_LESSTHAN]             = "<OP_LESSTHAN>";
        sExecuteOpCode[OP_GREATERTHAN]        = &ScriptInterpreter::opCodeGreaterThan;
        sOpCodeNames[OP_GREATERTHAN]          = "<OP_GREATERTHAN>";
        sExecuteOpCode[OP_LESSTHANOREQUAL]    = &ScriptInterpreter::opCodeLessThanOrEqual;
        sOpCodeNames[OP_LESSTHANOREQUAL]      = "<OP_LESSTHANOREQUAL>";
        sExecuteOpCode[OP_GREATERTHANOREQUAL] = &ScriptInterpreter::opCodeGreaterThanOrEqual;
        sOpCodeNames[OP_GREATERTHANOREQUAL]   = "<OP_GREATERTHANOREQUAL>";
        sExecuteOpCode[OP_MIN]                = &ScriptInterpreter::opCodeMin;
        sOpCodeNames[OP_MIN]                  = "<OP_MIN>";
        sExecuteOpCode[OP_MAX]                = &ScriptInterpreter::opCodeMax;
        sOpCodeNames[OP_MAX]                  = "<OP_MAX>";
        sExecuteOpCode[OP_WITHIN]             = &ScriptInterpreter::opCodeWithin;
        sOpCodeNames[OP_WITHIN]               = "<OP_WITHIN>";

        // Stack manipulation
        sExecuteOpCode[OP_TOALTSTACK]   = &ScriptInterpreter::opCodeToAltStack;
        sOpCodeNames[OP_TOALTSTACK]     = "<OP_TOALTSTACK>";
        sExecuteOpCode[OP_FROMALTSTACK] = &ScriptInterpreter::opCodeFromAltStack;
        sOpCodeNames[OP_FROMALTSTACK]   = "<OP_FROMALTSTACK>";
        sExecuteOpCode[OP_DUP]          = &ScriptInterpreter::opCodeDup;
        sOpCodeNames[OP_DUP]            = "<OP_DUP>";
        sExecuteOpCode[OP_IFDUP]        = &ScriptInterpreter::opCodeIfDup;
        sOpCodeNames[OP_IFDUP]          = "<OP_IFDUP>";
        sExecuteOpCode[OP_DEPTH]        = &ScriptInterpreter::opCodeDepth;
        sOpCodeNames[OP_DEPTH]          = "<OP_DEPTH>";
        sExecuteOpCode[OP_DROP]         = &ScriptInterpreter::opCodeDrop;
        sOpCodeNames[OP_DROP]           = "<OP_DROP>";
        sExecuteOpCode[OP_NIP]          = &ScriptInterpreter::opCodeNip;
        sOpCodeNames[OP_NIP]            = "<OP_NIP>";
        sExecuteOpCode[OP_OVER]         = &ScriptInterpreter::opCodeOver;
        sOpCodeNames[OP_OVER]           = "<OP_OVER>";
        sExecuteOpCode[OP_PICK]         = &ScriptInterpreter::opCodePick;
        sOpCodeNames[OP_PICK]           = "<OP_PICK>";
        sExecuteOpCode[OP_ROLL]         = &ScriptInterpreter::opCodeRoll;
        sOpCodeNames[OP_ROLL]           = "<OP_ROLL>";
        sExecuteOpCode[OP_ROT]          = &ScriptInterpreter::opCodeRotate;
        sOpCodeNames[OP_ROT]            = "<OP_ROT>";
        sExecuteOpCode[OP_SWAP]         = &ScriptInterpreter::opCodeSwap;
        sOpCodeNames[OP_SWAP]           = "<OP_SWAP>";
        sExecuteOpCode[OP_TUCK]         = &ScriptInterpreter::opCodeTuck;
        sOpCodeNames[OP_TUCK]           = "<OP_TUCK>";
        sExecuteOpCode[OP_2DROP]        = &ScriptInterpreter::opCodeDrop2;
        sOpCodeNames[OP_2DROP]          = "<OP_2DROP>";
        sExecuteOpCode[OP_2DUP]         = &ScriptInterpreter::opCodeDup2;
        sOpCodeNames[OP_2DUP]           = "<OP_2DUP>";
        sExecuteOpCode[OP_3DUP]         = &ScriptInterpreter::opCodeDup3;
        sOpCodeNames[OP_3DUP]           = "<OP_3DUP>";
        sExecuteOpCode[OP_2OVER]        = &ScriptInterpreter::opCodeOver2;
        sOpCodeNames[OP_2OVER]          = "<OP_2OVER>";
        sExecuteOpCode[OP_2ROT]         = &ScriptInterpreter::opCodeRotate2;
        sOpCodeNames[OP_2ROT]           = "<OP_2ROT>";
        sExecuteOpCode[OP_2SWAP]        = &ScriptInterpreter::opCodeSwap2;
        sOpCodeNames[OP_2SWAP]          = "<OP_2SWAP>";

        // Value manipulation
        sExecuteOpCode[OP_CAT]     = &ScriptInterpreter::opCodeConcat;
        sOpCodeNames[OP_CAT]       = "<OP_CAT>";
        sExecuteOpCode[OP_SPLIT]   = &ScriptInterpreter::opCodeSplit;
        sOpCodeNames[OP_SPLIT]     = "<OP_SPLIT>";
        sExecuteOpCode[OP_NUM2BIN] = &ScriptInterpreter::opCodeNum2Bin;
        sOpCodeNames[OP_NUM2BIN]   = "<OP_NUM2BIN>";
        sExecuteOpCode[OP_BIN2NUM] = &ScriptInterpreter::opCodeBin2Num;
        sOpCodeNames[OP_BIN2NUM]   = "<OP_BIN2NUM>";
        sExecuteOpCode[OP_SIZE]    = &ScriptInterpreter::opCodeSize;
        sOpCodeNames[OP_SIZE]      = "<OP_SIZE>";
        sExecuteOpCode[OP_INVERT]  = &ScriptInterpreter::opCodeInvert;
        sOpCodeNames[OP_INVERT]    = "<OP_INVERT>";

        // Logic
        sExecuteOpCode[OP_AND] = &ScriptInterpreter::opCodeAnd;
        sOpCodeNames[OP_AND]   = "<OP_AND>";
        sExecuteOpCode[OP_OR]  = &ScriptInterpreter::opCodeOr;
        sOpCodeNames[OP_OR]    = "<OP_OR>";
        sExecuteOpCode[OP_XOR] = &ScriptInterpreter::opCodeXor;
        sOpCodeNames[OP_XOR]   = "<OP_XOR>";

        // Reserved
        sExecuteOpCode[OP_RESERVED]  = &ScriptInterpreter::opCodeReserved;
        sOpCodeNames[OP_RESERVED]    = "<OP_RESERVED>";
        sExecuteOpCode[OP_VER]       = &ScriptInterpreter::opCodeReserved;
        sOpCodeNames[OP_VER]         = "<OP_VER>";
        sExecuteOpCode[OP_VERIF]     = &ScriptInterpreter::opCodeReserved;
        sOpCodeNames[OP_VERIF]       = "<OP_VERIF>";
        sExecuteOpCode[OP_VERNOTIF]  = &ScriptInterpreter::opCodeReserved;
        sOpCodeNames[OP_VERNOTIF]    = "<OP_VERNOTIF>";
        sExecuteOpCode[OP_RESERVED1] = &ScriptInterpreter::opCodeReserved;
        sOpCodeNames[OP_RESERVED1]   = "<OP_RESERVED1>";
        sExecuteOpCode[OP_RESERVED2] = &ScriptInterpreter::opCodeReserved;
        sOpCodeNames[OP_RESERVED2]   = "<OP_RESERVED2>";

        // No Op
        sExecuteOpCode[OP_NOP]   = &ScriptInterpreter::opCodeNoOp;
        sOpCodeNames[OP_NOP]     = "<OP_NOP>";
        sExecuteOpCode[OP_NOP1]  = &ScriptInterpreter::opCodeNoOp;
        sOpCodeNames[OP_NOP1]    = "<OP_NOP1>";
        // OP_NOP2 changed to OP_CHECKLOCKTIMEVERIFY
        // OP_NOP3 changed to OP_CHECKSEQUENCEVERIFY
        sExecuteOpCode[OP_NOP4]  = &ScriptInterpreter::opCodeNoOp;
        sOpCodeNames[OP_NOP4]    = "<OP_NOP4>";
        sExecuteOpCode[OP_NOP5]  = &ScriptInterpreter::opCodeNoOp;
        sOpCodeNames[OP_NOP5]    = "<OP_NOP5>";
        sExecuteOpCode[OP_NOP6]  = &ScriptInterpreter::opCodeNoOp;
        sOpCodeNames[OP_NOP6]    = "<OP_NOP6>";
        sExecuteOpCode[OP_NOP7]  = &ScriptInterpreter::opCodeNoOp;
        sOpCodeNames[OP_NOP7]    = "<OP_NOP7>";
        sExecuteOpCode[OP_NOP8]  = &ScriptInterpreter::opCodeNoOp;
        sOpCodeNames[OP_NOP8]    = "<OP_NOP8>";
        sExecuteOpCode[OP_NOP9]  = &ScriptInterpreter::opCodeNoOp;
        sOpCodeNames[OP_NOP9]    = "<OP_NOP9>";
        sExecuteOpCode[OP_NOP10] = &ScriptInterpreter::opCodeNoOp;
        sOpCodeNames[OP_NOP10]   = "<OP_NOP10>";
    }

    bool ScriptInterpreter::test()
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
          "------------- Starting Script Interpreter Tests -------------");

        bool success = true;
        NextCash::Buffer data, testData;
        int64_t value, testValue;

        /***********************************************************************************************
         * Arithmetic read 0x7fffffff - Highest 32 bit positive number (highest bit 0)
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("ffffff7f");
        value = 0x7fffffff;

        if(arithmeticRead(&testData, testValue) && value == testValue)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0x7fffffff");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0x7fffffff");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Read    : %08x%08x", testValue >> 32, testValue);
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic write 0x7fffffff - Highest 32 bit positive number (highest bit 0)
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("ffffff7f");
        value = 0x7fffffff;
        arithmeticWrite(&data, value);

        data.setReadOffset(0);
        if(data == testData)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0x7fffffff");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0x7fffffff");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %s", testData.readHexString(testData.length()).text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Written : %s", data.readHexString(data.length()).text());
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic read 0xffffffff - Highest 32 bit negative number (all bits 1) == -1
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("ffffffff");
        value = 0xffffffff80000001; //0xffffffffffffffff;

        if(arithmeticRead(&testData, testValue) && value == testValue)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0xffffffff");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0xffffffff");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Read    : %08x%08x", testValue >> 32, testValue);
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic write 0xffffffff - Highest 32 bit negative number (all bits 1) == -1
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("ffffffff");
        value = 0xffffffff80000001; //0xffffffffffffffff;
        arithmeticWrite(&data, value);

        data.setReadOffset(0);
        if(data == testData)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0xffffffff");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0xffffffff");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %s", testData.readHexString(testData.length()).text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Written : %s", data.readHexString(data.length()).text());
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic write 0xffffffff80
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("ffffffff80");
        value = 0xffffffff00000001; // 64 bit form of ‭-4,294,967,295‬
        arithmeticWrite(&data, value);

        data.setReadOffset(0);
        if(data == testData)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0xffffffff80");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0xffffffff80");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %s", testData.readHexString(testData.length()).text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Written : %s", data.readHexString(data.length()).text());
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic read 0xffffffff80
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("ffffffff80");
        value = 0xffffffff00000001;

        if(arithmeticRead(&testData, testValue) && value == testValue)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0xffffffff80");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0xffffffff80");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Read    : %08x%08x", testValue >> 32, testValue);
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic read 0xfeffffff80
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("feffffff80");
        value = 0xffffffff00000002;

        if(arithmeticRead(&testData, testValue) && value == testValue)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0xfeffffff80");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0xfeffffff80");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Read    : %08x%08x", testValue >> 32, testValue);
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic write 0xfeffffff80
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("feffffff80");
        value = 0xffffffff00000002;
        arithmeticWrite(&data, value);

        data.setReadOffset(0);
        if(data == testData)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0xfeffffff80");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0xfeffffff80");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %s", testData.readHexString(testData.length()).text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Written : %s", data.readHexString(data.length()).text());
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic read 0x6e
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("6e");
        value = 0x000000000000006e;

        if(arithmeticRead(&testData, testValue) && value == testValue)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0x6e");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0x6e");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Read    : %08x%08x", testValue >> 32, testValue);
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic write 0x6e
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("6e");
        value = 0x000000000000006e;
        arithmeticWrite(&data, value);

        data.setReadOffset(0);
        if(data == testData)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0x6e");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0x6e");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %s", testData.readHexString(testData.length()).text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Written : %s", data.readHexString(data.length()).text());
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic read 0xfeffffff00
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("feffffff00");
        value = 0x00000000fffffffe;

        if(arithmeticRead(&testData, testValue) && value == testValue)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0xfeffffff00");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0xfeffffff00");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Read    : %08x%08x", testValue >> 32, testValue);
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic write 0xfeffffff00
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("feffffff00");
        value = 0x00000000fffffffe;
        arithmeticWrite(&data, value);

        data.setReadOffset(0);
        if(data == testData)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0xfeffffff00");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0xfeffffff00");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct   : %s", testData.readHexString(testData.length()).text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Written : %s", data.readHexString(data.length()).text());
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic read 0x82
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("82");
        value = -2;

        if(arithmeticRead(&testData, testValue) && value == testValue)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0x82");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0x82");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Read    : %08x%08x", testValue >> 32, testValue);
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic write 0x82
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("82");
        value = -2;
        arithmeticWrite(&data, value);

        data.setReadOffset(0);
        if(data == testData)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0x82");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0x82");
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct   : %s", testData.readHexString(testData.length()).text());
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Written : %s", data.readHexString(data.length()).text());
            success = false;
        }

        /***********************************************************************************************
         * OP_CAT
         ***********************************************************************************************/
        Forks forks;
        NextCash::Buffer testScript;
        ScriptInterpreter interpreter;

        forks.setFork201805Active(1);

        interpreter.clear();
        testScript.clear();

        // Add element of max size
        ScriptInterpreter::writePushDataSize(forks.elementMaxSize(0), &testScript);
        for(unsigned int i=0;i<forks.elementMaxSize(0);++i)
            testScript.writeByte(0);

        // Add element with size of 1
        ScriptInterpreter::writePushDataSize(1, &testScript);
        testScript.writeByte(0);

        // Add OP_CAT
        testScript.writeByte(OP_CAT);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed OP_CAT max element size");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_CAT max element size");

        interpreter.clear();
        testScript.clear();

        // Add element of half max size
        ScriptInterpreter::writePushDataSize(forks.elementMaxSize(0) / 2, &testScript);
        for(unsigned int i=0;i<forks.elementMaxSize(0) / 2;++i)
            testScript.writeByte(0);

        // Add element of half max size + 1
        ScriptInterpreter::writePushDataSize((forks.elementMaxSize(0) / 2) + 1, &testScript);
        for(unsigned int i=0;i<(forks.elementMaxSize(0) / 2) + 1;++i)
            testScript.writeByte(0);

        // Add OP_CAT
        testScript.writeByte(OP_CAT);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed OP_CAT combined max element size + 1");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_CAT combined max element size + 1");

        interpreter.clear();
        testScript.clear();

        // Add two empty elements
        ScriptInterpreter::writePushDataSize(0, &testScript);
        ScriptInterpreter::writePushDataSize(0, &testScript);

        // Add OP_CAT
        testScript.writeByte(OP_CAT);

        // Add check that OP_0 is at the top
        testScript.writeByte(OP_0);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_CAT two empties");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed OP_CAT two empties");
            interpreter.printStack("Should be one empty");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        // Add one empty element and one not empty
        testScript.writeByte(OP_5);
        ScriptInterpreter::writePushDataSize(0, &testScript);

        // Add OP_CAT
        testScript.writeByte(OP_CAT);

        // Add check that OP_5 is at the top
        testScript.writeByte(OP_5);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_CAT one empty");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed OP_CAT one empty");
            interpreter.printStack("Should be a 5");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        // Add one empty element and one not empty
        ScriptInterpreter::writePushDataSize(0, &testScript);
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(4);
        testScript.writeByte(6);

        // Add OP_CAT
        testScript.writeByte(OP_CAT);

        // Add check that OP_5 is at the top
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(4);
        testScript.writeByte(6);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_CAT 4 and 6");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed OP_CAT 4 and 6");
            interpreter.printStack("Should be a 4 and 6");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        // Add two elements
        testScript.writeByte(OP_5);
        testScript.writeByte(OP_7);

        // Add OP_CAT
        testScript.writeByte(OP_CAT);

        // Add check that OP_0 is at the top
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(5);
        testScript.writeByte(7);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_CAT 5 and 7");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed OP_CAT 5 and 7");
            interpreter.printStack("Should be a 5 and 7");
            success = false;
        }

        /***********************************************************************************************
         * OP_SPLIT
         ***********************************************************************************************/
        interpreter.clear();
        testScript.clear();

        // Add empty element
        testScript.writeByte(OP_0);

        // Add number zero
        ScriptInterpreter::writeArithmeticInteger(testScript, 0);

        // Add OP_SPLIT
        testScript.writeByte(OP_SPLIT);

        if(!interpreter.process(testScript, 4, forks, 2))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_SPLIT empty at zero");
            interpreter.printStack("Should be two empties");
            success = false;
        }
        else
        {
            NextCash::Buffer *first = interpreter.testElement(0);
            NextCash::Buffer *second = interpreter.testElement(1);

            if(first != NULL && first->length() == 0 && second != NULL && second->length() == 0)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
                  "Passed OP_SPLIT empty at zero");
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
                  "Failed to OP_SPLIT empty at zero");
                interpreter.printStack("Should be two empties");
                success = false;
            }
        }

        interpreter.clear();
        testScript.clear();

        // Add element with 1 byte
        testScript.writeByte(OP_5);

        // Add number zero
        ScriptInterpreter::writeArithmeticInteger(testScript, 0);

        // Add OP_SPLIT
        testScript.writeByte(OP_SPLIT);

        if(!interpreter.process(testScript, 4, forks, 2))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_SPLIT non-empty at zero");
            interpreter.printStack("Should be empty then non-empty");
            success = false;
        }
        else
        {
            NextCash::Buffer *first = interpreter.testElement(0);
            NextCash::Buffer *second = interpreter.testElement(1);

            if(first != NULL && first->length() == 1 && first->readByte() == 5 &&
              second != NULL && second->length() == 0)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
                  "Passed OP_SPLIT non-empty at zero");
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
                  "Failed to OP_SPLIT non-empty at zero");
                interpreter.printStack("Should be empty then non-empty");
                success = false;
            }
        }

        interpreter.clear();
        testScript.clear();

        // Add element with 1 byte
        testScript.writeByte(OP_5);

        // Add number 1
        ScriptInterpreter::writeArithmeticInteger(testScript, 1);

        // Add OP_SPLIT
        testScript.writeByte(OP_SPLIT);

        if(!interpreter.process(testScript, 4, forks, 2))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_SPLIT non-empty at end");
            interpreter.printStack("Should be empty then non-empty");
            success = false;
        }
        else
        {
            NextCash::Buffer *first = interpreter.testElement(0);
            NextCash::Buffer *second = interpreter.testElement(1);

            if(first != NULL && first->length() == 0 && second != NULL && second->length() == 1 && second->readByte() == 5)
                NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
                  "Passed OP_SPLIT non-empty at end");
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
                  "Failed to OP_SPLIT non-empty at end");
                interpreter.printStack("Should be empty then non-empty");
                success = false;
            }
        }

        interpreter.clear();
        testScript.clear();

        // Add element with 1 byte
        testScript.writeByte(OP_5);

        // Add number 1
        ScriptInterpreter::writeArithmeticInteger(testScript, 2);

        // Add OP_SPLIT
        testScript.writeByte(OP_SPLIT);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_SPLIT non-empty past end");
            interpreter.printStack("Should be empty then non-empty");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_SPLIT non-empty past end");

        interpreter.clear();
        testScript.clear();

        // Add element with 5 bytes
        ScriptInterpreter::writePushDataSize(5, &testScript);
        testScript.writeByte(1);
        testScript.writeByte(2);
        testScript.writeByte(3);
        testScript.writeByte(4);
        testScript.writeByte(5);

        // Add number 3
        ScriptInterpreter::writeArithmeticInteger(testScript, 3);

        // Add OP_SPLIT
        testScript.writeByte(OP_SPLIT);

        if(!interpreter.process(testScript, 4, forks, 2))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_SPLIT middle");
            interpreter.printStack("Should be x010203 and x0405");
            success = false;
        }
        else
        {
            NextCash::Buffer *first = interpreter.testElement(0);
            NextCash::Buffer *second = interpreter.testElement(1);

            if(first != NULL && first->length() == 2 && second != NULL && second->length() == 3)
            {
                if(first->readByte() != 0x04 || first->readByte() != 0x05 ||
                  second->readByte() != 0x01 || second->readByte() != 0x02 ||
                  second->readByte() != 0x03)
                {
                    NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
                      "Failed to OP_SPLIT middle");
                    interpreter.printStack("Should be x010203 and x0405");
                }
                else
                    NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
                      "Passed OP_SPLIT middle");
            }
            else
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
                  "Failed to OP_SPLIT middle");
                interpreter.printStack("Should be x010203 and x0405");
                success = false;
            }
        }

        /***********************************************************************************************
         * OP_AND
         ***********************************************************************************************/
        interpreter.clear();
        testScript.clear();

        // Add element with 1 byte
        testScript.writeByte(OP_5);

        // Add element with 2 bytes
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(1);
        testScript.writeByte(2);

        // Add OP_AND
        testScript.writeByte(OP_AND);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_AND non-matching lengths");
            interpreter.printStack("Should be fail");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_AND non-matching lengths");

        interpreter.clear();
        testScript.clear();

        // Add element with 2 bytes
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(0x01);
        testScript.writeByte(0x02);

        // Add element with 2 bytes
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(0x05);
        testScript.writeByte(0x04);

        // Add OP_AND
        testScript.writeByte(OP_AND);

        // Add element with 2 bytes
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(0x01);
        testScript.writeByte(0x00);

        // Add OP_EQUAL
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() && interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_AND value check");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_AND value check");
            interpreter.printStack("Should be x0100");
            success = false;
        }

        /***********************************************************************************************
         * OP_OR
         ***********************************************************************************************/
        interpreter.clear();
        testScript.clear();

        // Add element with 1 byte
        testScript.writeByte(OP_5);

        // Add element with 2 bytes
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(1);
        testScript.writeByte(2);

        // Add OP_OR
        testScript.writeByte(OP_OR);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_OR non-matching lengths");
            interpreter.printStack("Should be fail");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_OR non-matching lengths");

        interpreter.clear();
        testScript.clear();

        // Add element with 2 bytes
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(0x01);
        testScript.writeByte(0x02);

        // Add element with 2 bytes
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(0x05);
        testScript.writeByte(0x04);

        // Add OP_OR
        testScript.writeByte(OP_OR);

        // Add element with 2 bytes
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(0x05);
        testScript.writeByte(0x06);

        // Add OP_EQUAL
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_OR value check");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_OR value check");
            interpreter.printStack("Should be x0506");
            success = false;
        }

        /***********************************************************************************************
         * OP_XOR
         ***********************************************************************************************/
        interpreter.clear();
        testScript.clear();

        // Add element with 1 byte
        testScript.writeByte(OP_5);

        // Add element with 2 bytes
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(1);
        testScript.writeByte(2);

        // Add OP_XOR
        testScript.writeByte(OP_XOR);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_XOR non-matching lengths");
            interpreter.printStack("Should be fail");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_XOR non-matching lengths");

        interpreter.clear();
        testScript.clear();

        // Add element with 2 bytes
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(0x01);
        testScript.writeByte(0x02);

        // Add element with 2 bytes
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(0x05);
        testScript.writeByte(0x04);

        // Add OP_XOR
        testScript.writeByte(OP_XOR);

        // Add element with 2 bytes
        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(0x04);
        testScript.writeByte(0x06);

        // Add OP_EQUAL
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_XOR value check");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_XOR value check");
            interpreter.printStack("Should be x0406");
            success = false;
        }

        /***********************************************************************************************
         * OP_DIV
         ***********************************************************************************************/
        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writePushDataSize(9, &testScript);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);

        testScript.writeByte(OP_2);

        // Add OP_DIV
        testScript.writeByte(OP_DIV);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_DIV first non-numeric");
            interpreter.printStack("Should be fail");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_DIV first non-numeric");

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writeArithmeticInteger(testScript, 2);
        ScriptInterpreter::writeArithmeticInteger(testScript, 0);

        // Add OP_DIV
        testScript.writeByte(OP_DIV);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_DIV divide by zero");
            interpreter.printStack("Should be fail");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_DIV divide by zero");

        interpreter.clear();
        testScript.clear();

        testScript.writeByte(OP_5);
        testScript.writeByte(OP_2);

        // Add OP_DIV
        testScript.writeByte(OP_DIV);

        testScript.writeByte(OP_2);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_DIV value check");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_DIV value check");
            interpreter.printStack("Should be x02");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writeArithmeticInteger(testScript, -5);
        ScriptInterpreter::writeArithmeticInteger(testScript, 2);

        // Add OP_DIV
        testScript.writeByte(OP_DIV);

        ScriptInterpreter::writeArithmeticInteger(testScript, -2);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_DIV negative value check");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_DIV negative value check");
            interpreter.printStack("Should be -2");
            success = false;
        }

        /***********************************************************************************************
         * OP_MOD
         ***********************************************************************************************/
        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writePushDataSize(9, &testScript);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);

        testScript.writeByte(OP_2);

        // Add OP_MOD
        testScript.writeByte(OP_MOD);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_MOD first non-numeric");
            interpreter.printStack("Should be fail");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_MOD first non-numeric");

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writeArithmeticInteger(testScript, 2);
        ScriptInterpreter::writeArithmeticInteger(testScript, 0);

        // Add OP_MOD
        testScript.writeByte(OP_MOD);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_MOD divide by zero");
            interpreter.printStack("Should be fail");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_MOD divide by zero");

        interpreter.clear();
        testScript.clear();

        testScript.writeByte(OP_5);
        testScript.writeByte(OP_2);

        // Add OP_MOD
        testScript.writeByte(OP_MOD);

        testScript.writeByte(OP_1);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_MOD value check");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_MOD value check");
            interpreter.printStack("Should be x01");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writeArithmeticInteger(testScript, -5);
        ScriptInterpreter::writeArithmeticInteger(testScript, 2);

        // Add OP_MOD
        testScript.writeByte(OP_MOD);

        ScriptInterpreter::writeArithmeticInteger(testScript, -1);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_MOD negative value check");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_MOD negative value check");
            interpreter.printStack("Should be -1");
            success = false;
        }

        /***********************************************************************************************
         * OP_NUM2BIN
         ***********************************************************************************************/
        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writePushDataSize(9, &testScript);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);

        testScript.writeByte(OP_2);

        // Add OP_NUM2BIN
        testScript.writeByte(OP_NUM2BIN);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_NUM2BIN first non-numeric");
            interpreter.printStack("Should be fail");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_NUM2BIN first non-numeric");

        interpreter.clear();
        testScript.clear();

        testScript.writeByte(OP_2);

        ScriptInterpreter::writePushDataSize(9, &testScript);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);

        // Add OP_NUM2BIN
        testScript.writeByte(OP_NUM2BIN);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_NUM2BIN second non-numeric");
            interpreter.printStack("Should be fail");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_NUM2BIN second non-numeric");

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writeArithmeticInteger(testScript, 256);
        ScriptInterpreter::writeArithmeticInteger(testScript, 1);

        // Add OP_NUM2BIN
        testScript.writeByte(OP_NUM2BIN);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_NUM2BIN sequence too small");
            interpreter.printStack("Should be fail");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_NUM2BIN sequence too small");

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writeArithmeticInteger(testScript, 1);
        ScriptInterpreter::writeArithmeticInteger(testScript, forks.elementMaxSize(0) + 1);

        // Add OP_NUM2BIN
        testScript.writeByte(OP_NUM2BIN);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_NUM2BIN sequence too long");
            interpreter.printStack("Should be fail");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_NUM2BIN sequence too long");

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writeArithmeticInteger(testScript, 1);
        ScriptInterpreter::writeArithmeticInteger(testScript, 4);

        // Add OP_NUM2BIN
        testScript.writeByte(OP_NUM2BIN);

        ScriptInterpreter::writePushDataSize(4, &testScript);
        testScript.writeByte(1);
        testScript.writeByte(0);
        testScript.writeByte(0);
        testScript.writeByte(0);

        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_NUM2BIN value check");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_NUM2BIN value check");
            interpreter.printStack("Should be 0x01000000");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writeArithmeticInteger(testScript, -2);
        ScriptInterpreter::writeArithmeticInteger(testScript, 4);

        // Add OP_NUM2BIN
        testScript.writeByte(OP_NUM2BIN);

        ScriptInterpreter::writePushDataSize(4, &testScript);
        testScript.writeByte(2);
        testScript.writeByte(0);
        testScript.writeByte(0);
        testScript.writeByte(0x80);

        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_NUM2BIN negative value check");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_NUM2BIN negative value check");
            interpreter.printStack("Should be 0x02000080");
            success = false;
        }

        /***********************************************************************************************
         * OP_BIN2NUM
         ***********************************************************************************************/
        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writePushDataSize(9, &testScript);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);
        testScript.writeByte(0x04);

        // Add OP_BIN2NUM
        testScript.writeByte(OP_BIN2NUM);

        if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_BIN2NUM sequence too large");
            interpreter.printStack("Should be fail");
            success = false;
        }
        else
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_BIN2NUM sequence too large");

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writePushDataSize(9, &testScript);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);

        // Add OP_BIN2NUM
        testScript.writeByte(OP_BIN2NUM);

        testScript.writeByte(OP_0);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_BIN2NUM zeroes");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_BIN2NUM zeroes");
            interpreter.printStack("Should be empty");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writePushDataSize(9, &testScript);
        testScript.writeByte(0x02);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);

        // Add OP_BIN2NUM
        testScript.writeByte(OP_BIN2NUM);

        testScript.writeByte(OP_2);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_BIN2NUM long two");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_BIN2NUM long two");
            interpreter.printStack("Should be 2");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writePushDataSize(forks.elementMaxSize(0), &testScript);
        testScript.writeByte(0x02);
        for(unsigned int i=0;i<forks.elementMaxSize(0)-1;++i)
            testScript.writeByte(0x00);

        // Add OP_BIN2NUM
        testScript.writeByte(OP_BIN2NUM);

        testScript.writeByte(OP_2);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_BIN2NUM max length two");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_BIN2NUM max length two");
            interpreter.printStack("Should be 2");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writePushDataSize(9, &testScript);
        testScript.writeByte(0x02);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x00);
        testScript.writeByte(0x80);

        // Add OP_BIN2NUM
        testScript.writeByte(OP_BIN2NUM);

        ScriptInterpreter::writeArithmeticInteger(testScript, -2);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_BIN2NUM long negative two");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_BIN2NUM long negative two");
            interpreter.printStack("Should be -2");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writePushDataSize(forks.elementMaxSize(0), &testScript);
        testScript.writeByte(0x02);
        for(unsigned int i=0;i<forks.elementMaxSize(0)-2;++i)
            testScript.writeByte(0x00);
        testScript.writeByte(0x80);

        // Add OP_BIN2NUM
        testScript.writeByte(OP_BIN2NUM);

        ScriptInterpreter::writeArithmeticInteger(testScript, -2);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_BIN2NUM max length negative two");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_BIN2NUM max length negative two");
            interpreter.printStack("Should be -2");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writePushDataSize(2, &testScript);
        testScript.writeByte(0x00);
        testScript.writeByte(0x80);

        // Add OP_BIN2NUM
        testScript.writeByte(OP_BIN2NUM);

        ScriptInterpreter::writeArithmeticInteger(testScript, 0);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_BIN2NUM negative zero");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_BIN2NUM negative zero");
            interpreter.printStack("Should be 0");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writePushDataSize(forks.elementMaxSize(0), &testScript);
        for(unsigned int i=0;i<forks.elementMaxSize(0)-1;++i)
            testScript.writeByte(0x00);
        testScript.writeByte(0x80);

        // Add OP_BIN2NUM
        testScript.writeByte(OP_BIN2NUM);

        ScriptInterpreter::writeArithmeticInteger(testScript, 0);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_BIN2NUM max length negative zero");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_BIN2NUM max length negative zero");
            interpreter.printStack("Should be -2");
            success = false;
        }

        interpreter.clear();
        testScript.clear();

        ScriptInterpreter::writePushDataSize(4, &testScript);
        testScript.writeByte(0xd4);
        testScript.writeByte(0x04);
        testScript.writeByte(0x00);
        testScript.writeByte(0x80);

        // Add OP_BIN2NUM
        testScript.writeByte(OP_BIN2NUM);

        ScriptInterpreter::writeArithmeticInteger(testScript, -1236);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks, 2) && interpreter.isValid() &&
          interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_BIN2NUM negative 1236");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_BIN2NUM negative 1236");
            interpreter.printStack("Should be -1236");
            success = false;
        }

        /***********************************************************************************************
         * TODO OP_CHECKDATASIG
         ***********************************************************************************************/
        // interpreter.clear();
        // testScript.clear();

        // ScriptInterpreter::writePushDataSize(9, &testScript);
        // testScript.writeByte(0x04);
        // //TODO Write valid and invalid check data sig.

        // // Add OP_CHECKDATASIG
        // testScript.writeByte(OP_CHECKDATASIG);

        // if(interpreter.process(testScript, 4, forks, 2) || interpreter.isValid())
        // {
            // NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              // "Failed to process OP_CHECKDATASIG");
            // interpreter.printStack("Should be fail");
            // success = false;
        // }
        // else
            // NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              // "Passed OP_CHECKDATASIG");

        /***********************************************************************************************
         * TODO OP_MUL
         ***********************************************************************************************/

        /***********************************************************************************************
         * TODO OP_LSHIFT
         ***********************************************************************************************/

        /***********************************************************************************************
         * TODO OP_RSHIFT
         ***********************************************************************************************/

        /***********************************************************************************************
         * TODO OP_INVERT
         ***********************************************************************************************/

        return success;
    }
}
