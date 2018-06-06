/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                       *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "interpreter.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
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
            if(opCode != OP_0 && pullDataSize(opCode, pScript) == 0)
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
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Interpreter Parse Output");
#endif
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
            {
                if(pScript.length() < 224)
                    return NULL_DATA;
                else
                    return NON_STANDARD;
            }
            else
                return NON_STANDARD;
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

    unsigned int ScriptInterpreter::pullDataSize(uint8_t pOpCode, NextCash::Buffer &pScript, bool pSkipData)
    {
        if(pOpCode <= MAX_SINGLE_BYTE_PUSH_DATA_CODE)
        {
            if(pOpCode > pScript.remaining())
                return 0;
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
                    return 0;
                else if(pSkipData)
                    pScript.setReadOffset(pScript.readOffset() + length);
                return length;
            }
            case OP_PUSHDATA2: // The next 2 bytes contains the number of bytes to be pushed
            {
                uint16_t length = pScript.readUnsignedShort();
                if(length > pScript.remaining())
                    return 0;
                else if(pSkipData)
                    pScript.setReadOffset(pScript.readOffset() + length);
                return length;
            }
            case OP_PUSHDATA4: // The next 4 bytes contains the number of bytes to be pushed
            {
                uint32_t length = pScript.readUnsignedInt();
                if(length > pScript.remaining())
                    return 0;
                else if(pSkipData)
                    pScript.setReadOffset(pScript.readOffset() + length);
                return length;
            }

            default:
                return 0;
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

    NextCash::String ScriptInterpreter::scriptText(NextCash::Buffer &pScript, Forks &pForks)
    {
        NextCash::String result;

        if(pScript.remaining() == 0)
            return result;

        uint8_t opCode;

        while(pScript.remaining())
        {
            opCode = pScript.readByte();

            if(opCode == 0x00)
            {
                result += "<OP_0>";
                continue;
            }

            if(opCode <= MAX_SINGLE_BYTE_PUSH_DATA_CODE)
            {
                result += "<PUSH_OP=";
                if(opCode > pScript.remaining())
                    result += "too long";
                else
                    result += pScript.readHexString(opCode);
                result += ">";
                continue;
            }

            switch(opCode)
            {
                case OP_NOP: // Does nothing
                    result += "<OP_NOP>";
                    break;
                case OP_IF: // If the top stack value is not OP_FALSE the statements are executed. The top stack value is removed
                    result += "<OP_IF>";
                    break;
                case OP_NOTIF: // If the top stack value is OP_FALSE the statements are executed. The top stack value is removed
                    result += "<OP_NOTIF>";
                    break;
                case OP_ELSE:
                    result += "<OP_ELSE>";
                    break;
                case OP_ENDIF:
                    result += "<OP_ENDIF>";
                    break;
                case OP_VERIFY:
                    result += "<OP_VERIFY>";
                    break;
                case OP_RETURN:
                    result += "<OP_RETURN>";
                    break;
                case OP_EQUAL:
                    result += "<OP_EQUAL>";
                    break;
                case OP_EQUALVERIFY:
                    result += "<OP_EQUALVERIFY>";
                    break;
                case OP_RIPEMD160:
                    result += "<OP_RIPEMD160>";
                    break;
                case OP_SHA1:
                    result += "<OP_SHA1>";
                    break;
                case OP_SHA256:
                    result += "<OP_SHA256>";
                    break;
                case OP_HASH160:
                    result += "<OP_HASH160>";
                    break;
                case OP_HASH256:
                    result += "<OP_HASH256>";
                    break;
                case OP_CODESEPARATOR:
                    result += "<OP_CODESEPARATOR>";
                    break;
                case OP_CHECKSIG:
                    result += "<OP_CHECKSIG>";
                    break;
                case OP_CHECKSIGVERIFY:
                    result += "<OP_CHECKSIGVERIFY>";
                    break;
                case OP_CHECKMULTISIG:
                    result += "<OP_CHECKMULTISIG>";
                    break;
                case OP_CHECKMULTISIGVERIFY:
                    result += "<OP_CHECKMULTISIGVERIFY>";
                    break;
                case OP_CHECKLOCKTIMEVERIFY:
                    result += "<OP_CHECKLOCKTIMEVERIFY>";
                    break;
                case OP_CHECKSEQUENCEVERIFY:
                    result += "<OP_CHECKSEQUENCEVERIFY>";
                    break;
                case OP_PUSHDATA1: // The next byte contains the number of bytes to be pushed
                {
                    uint8_t length = pScript.readByte();
                    result += "<OP_PUSHDATA1=";
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
                    result += "<OP_PUSHDATA2=";
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
                    result += "<OP_PUSHDATA4=";
                    if(length > pScript.remaining())
                        result += "too long";
                    else
                        result += pScript.readHexString(length);
                    result += ">";
                    break;
                }
                case OP_0: // An empty array of bytes is pushed to the stack
                    //case OP_FALSE:
                    result += "<OP_0>";
                    break;
                case OP_1NEGATE: // The number -1 is pushed
                    result += "<OP_1NEGATE>";
                    break;
                case OP_1: // The number 1 is pushed
                    result += "<OP_1>";
                    break;
                case OP_2: // The number 2 is pushed
                    result += "<OP_2>";
                    break;
                case OP_3: // The number 3 is pushed
                    result += "<OP_3>";
                    break;
                case OP_4: // The number 4 is pushed
                    result += "<OP_4>";
                    break;
                case OP_5: // The number 5 is pushed
                    result += "<OP_5>";
                    break;
                case OP_6: // The number 6 is pushed
                    result += "<OP_6>";
                    break;
                case OP_7: // The number 7 is pushed
                    result += "<OP_7>";
                    break;
                case OP_8: // The number 8 is pushed
                    result += "<OP_8>";
                    break;
                case OP_9: // The number 9 is pushed
                    result += "<OP_9>";
                    break;
                case OP_10: // The number 10 is pushed
                    result += "<OP_10>";
                    break;
                case OP_11: // The number 11 is pushed
                    result += "<OP_11>";
                    break;
                case OP_12: // The number 12 is pushed
                    result += "<OP_12>";
                    break;
                case OP_13: // The number 13 is pushed
                    result += "<OP_13>";
                    break;
                case OP_14: // The number 14 is pushed
                    result += "<OP_14>";
                    break;
                case OP_15: // The number 15 is pushed
                    result += "<OP_15>";
                    break;
                case OP_16: // The number 16 is pushed
                    result += "<OP_16>";
                    break;


                case OP_1ADD: //    in    out    1 is added to the input.
                    result += "<OP_1ADD>";
                    break;
                case OP_1SUB: //    in    out    1 is subtracted from the input.
                    result += "<OP_1SUB>";
                    break;
                case OP_2MUL: //    in    out    The input is multiplied by 2. disabled.
                    result += "<OP_2MUL disabled>";
                    break;
                case OP_2DIV: //    in    out    The input is divided by 2. disabled.
                    result += "<OP_2DIV disabled>";
                    break;
                case OP_NEGATE: //    in    out    The sign of the input is flipped.
                    result += "<OP_NEGATE>";
                    break;
                case OP_ABS: //    in    out    The input is made positive.
                    result += "<OP_ABS>";
                    break;
                case OP_NOT: //    in    out    If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
                    result += "<OP_NOT>";
                    break;
                case OP_0NOTEQUAL: //    in    out    Returns 0 if the input is 0. 1 otherwise.
                    result += "<OP_0NOTEQUAL>";
                    break;
                case OP_ADD: //    a b   out    a is added to b.
                    result += "<OP_ADD>";
                    break;
                case OP_SUB: //    a b   out    b is subtracted from a.
                    result += "<OP_SUB>";
                    break;
                case OP_MUL: //    a b   out    a is multiplied by b. disabled.
                    result += "<OP_MUL disabled>";
                    break;
                case OP_DIV: //    a b   out    a is divided by b.
                    if(pForks.fork201805Active())
                        result += "<OP_DIV>";
                    else
                        result += "<OP_DIV disabled>";
                    break;
                case OP_MOD: //    a b   out    Returns the remainder after dividing a by b.
                    if(pForks.fork201805Active())
                        result += "<OP_MOD>";
                    else
                        result += "<OP_MOD disabled>";
                    break;
                case OP_LSHIFT: //    a b   out    Shifts a left b bits, preserving sign. disabled.
                    result += "<OP_LSHIFT disabled>";
                    break;
                case OP_RSHIFT: //    a b   out    Shifts a right b bits, preserving sign. disabled.
                    result += "<OP_RSHIFT disabled>";
                    break;
                case OP_BOOLAND: //    a b   out    If both a and b are not 0, the output is 1. Otherwise 0.
                    result += "<OP_BOOLAND>";
                    break;
                case OP_BOOLOR: //    a b   out    If a or b is not 0, the output is 1. Otherwise 0.
                    result += "<OP_BOOLOR>";
                    break;
                case OP_NUMEQUAL: //    a b   out    Returns 1 if the numbers are equal, 0 otherwise.
                    result += "<OP_NUMEQUAL>";
                    break;
                case OP_NUMEQUALVERIFY: //    a b   Nothing / fail    Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
                    result += "<OP_NUMEQUALVERIFY>";
                    break;
                case OP_NUMNOTEQUAL: //    a b   out    Returns 1 if the numbers are not equal, 0 otherwise.
                    result += "<OP_NUMNOTEQUAL>";
                    break;
                case OP_LESSTHAN: //    a b   out    Returns 1 if a is less than b, 0 otherwise.
                    result += "<OP_LESSTHAN>";
                    break;
                case OP_GREATERTHAN: //    a b   out    Returns 1 if a is greater than b, 0 otherwise.
                    result += "<OP_GREATERTHAN>";
                    break;
                case OP_LESSTHANOREQUAL: //    a b   out    Returns 1 if a is less than or equal to b, 0 otherwise.
                    result += "<OP_LESSTHANOREQUAL>";
                    break;
                case OP_GREATERTHANOREQUAL: //    a b   out    Returns 1 if a is greater than or equal to b, 0 otherwise.
                    result += "<OP_GREATERTHANOREQUAL>";
                    break;
                case OP_MIN: //    a b   out    Returns the smaller of a and b.
                    result += "<OP_MIN>";
                    break;
                case OP_MAX: //    a b   out    Returns the larger of a and b.
                    result += "<OP_MAX>";
                    break;
                case OP_WITHIN: //    x min max    out    Returns 1 if x is within the specified range (left-inclusive), 0 otherwise
                    result += "<OP_WITHIN>";
                    break;


                    // Stack
                case OP_TOALTSTACK:
                    result += "<OP_TOALTSTACK>";
                    break;
                case OP_FROMALTSTACK:
                    result += "<OP_FROMALTSTACK>";
                    break;
                case OP_DUP:
                    result += "<OP_DUP>";
                    break;
                case OP_IFDUP: // 0x73//     x    x / x x    If the top stack value is not 0, duplicate it.
                    result += "<OP_IFDUP>";
                    break;
                case OP_DEPTH: // 0x74//     Nothing    <Stack size>    Puts the number of stack items onto the stack.
                    result += "<OP_DEPTH>";
                    break;
                case OP_DROP: // 0x75//     x    Nothing    Removes the top stack item.
                    result += "<OP_DROP>";
                    break;
                case OP_NIP: // 0x77//     x1 x2    x2    Removes the second-to-top stack item.
                    result += "<OP_NIP>";
                    break;
                case OP_OVER: // 0x78//     x1 x2    x1 x2 x1    Copies the second-to-top stack item to the top.
                    result += "<OP_OVER>";
                    break;
                case OP_PICK: // 0x79//     xn ... x2 x1 x0 <n>    xn ... x2 x1 x0 xn    The item n back in the stack is copied to the top.
                    result += "<OP_PICK>";
                    break;
                case OP_ROLL: // 0x7a//     xn ... x2 x1 x0 <n>    ... x2 x1 x0 xn    The item n back in the stack is moved to the top.
                    result += "<OP_ROLL>";
                    break;
                case OP_ROT: // 0x7b//     x1 x2 x3    x2 x3 x1    The top three items on the stack are rotated to the left.
                    result += "<OP_ROT>";
                    break;
                case OP_SWAP: // 0x7c//     x1 x2    x2 x1    The top two items on the stack are swapped.
                    result += "<OP_SWAP>";
                    break;
                case OP_TUCK: // 0x7d//     x1 x2    x2 x1 x2    The item at the top of the stack is copied and inserted before the second-to-top item.
                    result += "<OP_TUCK>";
                    break;
                case OP_2DROP: // 0x6d//     x1 x2    Nothing    Removes the top two stack items.
                    result += "<OP_2DROP>";
                    break;
                case OP_2DUP: // 0x6e//     x1 x2    x1 x2 x1 x2    Duplicates the top two stack items.
                    result += "<OP_2DUP>";
                    break;
                case OP_3DUP: // 0x6f//     x1 x2 x3    x1 x2 x3 x1 x2 x3    Duplicates the top three stack items.
                    result += "<OP_3DUP>";
                    break;
                case OP_2OVER: // 0x70//     x1 x2 x3 x4    x1 x2 x3 x4 x1 x2    Copies the pair of items two spaces back in the stack to the front.
                    result += "<OP_2OVER>";
                    break;
                case OP_2ROT: // 0x71//     x1 x2 x3 x4 x5 x6    x3 x4 x5 x6 x1 x2    The fifth and sixth items back are moved to the top of the stack.
                    result += "<OP_2ROT>";
                    break;
                case OP_2SWAP: // 0x72 //     x1 x2 x3 x4    x3 x4 x1 x2	Swaps the top two pairs of items.
                    result += "<OP_2SWAP>";
                    break;


                    // Splice
                case OP_CAT: //  x1 x2  out  Concatenates two strings.
                    if(pForks.fork201805Active())
                        result += "<OP_CAT>";
                    else
                        result += "<OP_CAT disabled>";
                    break;
                case OP_SPLIT: // Split byte sequence x at position n
                    if(pForks.fork201805Active())
                        result += "<OP_SPLIT>";
                    else
                        result += "<OP_SUBSTR disabled>";
                    break;
                case OP_NUM2BIN: // Convert numeric value a into byte sequence of length b
                    if(pForks.fork201805Active())
                        result += "<OP_NUM2BIN>";
                    else
                        result += "<OP_LEFT disabled>";
                    break;
                case OP_BIN2NUM: // Convert byte sequence x into a numeric value
                    if(pForks.fork201805Active())
                        result += "<OP_BIN2NUM>";
                    else
                        result += "<OP_RIGHT disabled>";
                    break;
                case OP_SIZE: //  in  in size  Pushes the string length of the top element of the stack (without popping it).
                    result += "<OP_SIZE>";
                    break;


                    // Bitwise logic
                case OP_INVERT: //  in  out  Flips all of the bits in the input. disabled.
                    result += "<OP_INVERT disabled>";
                    break;
                case OP_AND: //  x1 x2  out  Boolean and between each bit in the inputs.
                    if(pForks.fork201805Active())
                        result += "<OP_AND>";
                    else
                        result += "<OP_AND disabled>";
                    break;
                case OP_OR: //  x1 x2  out  Boolean or between each bit in the inputs.
                    if(pForks.fork201805Active())
                        result += "<OP_OR>";
                    else
                        result += "<OP_OR disabled>";
                    break;
                case OP_XOR: //  x1 x2  out  Boolean exclusive or between each bit in the inputs.
                    if(pForks.fork201805Active())
                        result += "<OP_XOR>";
                    else
                        result += "<OP_XOR disabled>";
                    break;


                    // Reserved
                case OP_RESERVED: //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
                    result += "<OP_RESERVED>";
                    break;
                case OP_VER: //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
                    result += "<OP_VER>";
                    break;
                case OP_VERIF: //  Transaction is invalid even when occuring in an unexecuted OP_IF branch
                    result += "<OP_VERIF>";
                    break;
                case OP_VERNOTIF: //  Transaction is invalid even when occuring in an unexecuted OP_IF branch
                    result += "<OP_VERNOTIF>";
                    break;
                case OP_RESERVED1: //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
                    result += "<OP_RESERVED1>";
                    break;
                case OP_RESERVED2: //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
                    result += "<OP_RESERVED2>";
                    break;

                case OP_NOP1: // The word is ignored. Does not mark transaction as invalid.
                    result += "<OP_NOP1>";
                    break;
                    //OP_NOP2              = 0xb1, // Changed to OP_CHECKLOCKTIMEVERIFY
                    //OP_NOP3              = 0xb2, // Changed to OP_CHECKSEQUENCEVERIFY
                case OP_NOP4:  // The word is ignored. Does not mark transaction as invalid.
                    result += "<OP_NOP4>";
                    break;
                case OP_NOP5:  // The word is ignored. Does not mark transaction as invalid.
                    result += "<OP_NOP5>";
                    break;
                case OP_NOP6:  // The word is ignored. Does not mark transaction as invalid.
                    result += "<OP_NOP6>";
                    break;
                case OP_NOP7:  // The word is ignored. Does not mark transaction as invalid.
                    result += "<OP_NOP7>";
                    break;
                case OP_NOP8:  // The word is ignored. Does not mark transaction as invalid.
                    result += "<OP_NOP8>";
                    break;
                case OP_NOP9:  // The word is ignored. Does not mark transaction as invalid.
                    result += "<OP_NOP9>";
                    break;
                case OP_NOP10: // The word is ignored. Does not mark transaction as invalid.
                    result += "<OP_NOP10>";
                    break;


                default:
                {
                    NextCash::String undefinedText;
                    undefinedText.writeFormatted("<!!!UNDEFINED 0x%02x!!!>", opCode);
                    result += undefinedText;
                    break;
                }
            }
        }

        return result;
    }

    void ScriptInterpreter::printScript(NextCash::Buffer &pScript, Forks &pForks, NextCash::Log::Level pLevel)
    {
        NextCash::String text = scriptText(pScript, pForks);
        NextCash::Log::addFormatted(pLevel, BITCOIN_INTERPRETER_LOG_NAME, text);
    }


    bool ScriptInterpreter::readArithmeticInteger(NextCash::Buffer &pScript, int64_t &pValue)
    {
        unsigned int length = pullDataSize(pScript.readByte(), pScript, false);

        if(length == 0)
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
      int64_t pOutputAmount, const Key &pPublicKey, const Signature &pSignature,
      NextCash::Buffer &pCurrentOutputScript, unsigned int pSignatureStartOffset, const Forks &pForks)
    {
        if(pForks.cashActive() && !(pSignature.hashType() & Signature::FORKID))
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Signature hash type missing required fork ID flag : %02x", pSignature.hashType());
            return false;
        }
        else if(!pForks.cashActive() && pSignature.hashType() & Signature::FORKID)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Signature hash type has disabled fork ID flag : %02x", pSignature.hashType());
            return false;
        }

        // Get signature hash
        NextCash::Hash signatureHash(32);
        NextCash::stream_size previousOffset = pCurrentOutputScript.readOffset();
        pCurrentOutputScript.setReadOffset(pSignatureStartOffset);
        if(!pTransaction.getSignatureHash(signatureHash, pInputOffset, pCurrentOutputScript,
          pOutputAmount, pSignature.hashType(), pForks.forkID()))
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to get signature hash : 0x%02x - %s", (int)pSignature.hashType(), pSignature.hex().text());
            pCurrentOutputScript.setReadOffset(previousOffset);
            return false;
        }

        pCurrentOutputScript.setReadOffset(previousOffset);
        if(pPublicKey.verify(pSignature, signatureHash))
            return true;
        else
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Signature check failed : 0x%02x - %s", (int)pSignature.hashType(), pSignature.hex().text());
            return false;
        }
    }

    void ScriptInterpreter::printStack(const char *pText)
    {
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME, "Stack : %s", pText);

        unsigned int index = 1;
        for(std::list<NextCash::Buffer *>::reverse_iterator i = mStack.rbegin();i!=mStack.rend();++i,index++)
        {
            (*i)->setReadOffset(0);
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
              "    %d (%d bytes) : %s", index, (*i)->length(), (*i)->readHexString((*i)->length()).text());
        }
    }

    bool ScriptInterpreter::arithmeticRead(NextCash::Buffer *pBuffer, int64_t &pValue)
    {
        //TODO This is a still messy and should be cleaned up. Unit test below should cover it.
        pBuffer->setReadOffset(0);
        if(pBuffer->length() > 8)
        {
            pBuffer->setReadOffset(0);
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Arithmetic read to many bytes : %s", pBuffer->readHexString(pBuffer->length()).text());
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
                  "Arithmetic read to many bytes (negative with 0x80) : %s",
                  pBuffer->readHexString(pBuffer->length()).text());
                return false;
            }
        }
        else if(pBuffer->length() > 4)
        {
            pBuffer->setReadOffset(0);
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Arithmetic read to many bytes : %s", pBuffer->readHexString(pBuffer->length()).text());
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

    bool ScriptInterpreter::process(NextCash::Buffer &pScript, int32_t pBlockVersion, Forks &pForks)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Interpreter Process");
#endif
        unsigned int sigStartOffset = pScript.readOffset();
        uint8_t opCode;
        uint64_t count;
        bool strictECDSA_DER_Sigs = pBlockVersion >= 3 && pForks.enabledVersion() >= 3;

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

            if(opCode == OP_0) // or OP_FALSE
            {
                if(!ifStackTrue())
                    continue;

                // Push an empty value onto the stack (OP_0, OP_FALSE)
                push();
                continue;
            }

            if(opCode <= MAX_SINGLE_BYTE_PUSH_DATA_CODE)
            {
                if(opCode > pScript.remaining())
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "Push data size more than remaining script : %d/%d", opCode, pScript.remaining());
                    mValid = false;
                    return false;
                }

#ifdef PROFILER_ON
                NextCash::Profiler profiler("Interpreter Push");
#endif
                // Push opCode value bytes onto stack from input
                if(!ifStackTrue())
                    pScript.setReadOffset(pScript.readOffset() + opCode);
                else
                    push()->copyBuffer(pScript, opCode);
                continue;
            }

            switch(opCode)
            {
                case OP_NOP: // Does nothing
                    break;

                case OP_IF: // If the top stack value is not OP_FALSE the statements are executed. The top stack value is removed
                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_IF");
                        mValid = false;
                        return false;
                    }

                    // if(!bufferIsZero(top()))
                        // NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          // "OP_IF pushing to on");
                    // else
                        // NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          // "OP_IF pushing to off");
                    if(ifStackTrue())
                    {
                        mIfStack.push_back(!bufferIsZero(top()));
                        pop();
                    }
                    else
                        mIfStack.push_back(true);
                    break;
                case OP_NOTIF: // If the top stack value is OP_FALSE the statements are executed. The top stack value is removed
                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_NOTIF");
                        mValid = false;
                        return false;
                    }

                    // if(bufferIsZero(top()))
                        // NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          // "OP_NOTIF pushing to on");
                    // else
                        // NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          // "OP_NOTIF pushing to off");
                    if(ifStackTrue())
                    {
                        mIfStack.push_back(bufferIsZero(top()));
                        pop();
                    }
                    else
                        mIfStack.push_back(true);
                    break;
                case OP_ELSE: // If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then these statements are and if the preceding OP_IF or OP_NOTIF or OP_ELSE was executed then these statements are not.
                    if(mIfStack.size() > 0)
                    {
                        // if(mIfStack.back())
                            // NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                              // "OP_ELSE switching to off");
                        // else
                            // NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                              // "OP_ELSE switching to on");
                        mIfStack.back() = !mIfStack.back();
                    }
                    else
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "No if before else");
                        mValid = false;
                        return false;
                    }
                    break;
                case OP_ENDIF: // Ends an if/else block. All blocks must end, or the transaction is invalid. An OP_ENDIF without OP_IF earlier is also invalid.
                    //NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "OP_ENDIF");
                    if(mIfStack.size() > 0)
                        mIfStack.pop_back();
                    else
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "No if before endif");
                        mValid = false;
                        return false;
                    }
                    break;

                case OP_VERIFY: // Marks transaction as invalid if top stack value is not true.
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_VERIFY");
                        mValid = false;
                        return false;
                    }

                    if(bufferIsZero(top()))
                    {
                        mVerified = false;
                        return true;
                    }
                    else
                        pop();
                    break;
                case OP_RETURN: // Marks transaction as invalid
                    if(!ifStackTrue())
                        break;
                    NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Return. Marking not verified");
                    mVerified = false;
                    return true;
                case OP_EQUAL: // Returns 1 if the the top two stack items are exactly equal, 0 otherwise
                case OP_EQUALVERIFY: // Same as OP_EQUAL, but runs OP_VERIFY afterward.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_EQUALVERIFY");
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
                    if(!matching)
                        printStack("OP_EQUAL failed");
                    pop();
                    pop();

                    if(matching)
                    {
                        if(opCode == OP_EQUAL)
                            push()->writeByte(1); // Push true
                    }
                    else
                    {
                        if(opCode == OP_EQUAL)
                            push(); // Push false
                        else
                        {
                            mVerified = false;
                            return true;
                        }
                    }

                    break;
                }
                case OP_RIPEMD160:
                {
#ifdef PROFILER_ON
                    NextCash::Profiler profiler("Interpreter RipeMD160");
#endif
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_SHA1");
                        mValid = false;
                        return false;
                    }

                    // Hash top stack item and pop it
                    top()->setReadOffset(0);
                    NextCash::Digest digest(NextCash::Digest::RIPEMD160);
                    digest.writeStream(top(), top()->length());
                    digest.getResult(&mHash);
                    pop();

                    // Push the hash
                    mHash.write(push());
                    break;
                }
                case OP_SHA1:
                {
#ifdef PROFILER_ON
                    NextCash::Profiler profiler("Interpreter SHA1");
#endif
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_SHA1");
                        mValid = false;
                        return false;
                    }

                    // Hash top stack item and pop it
                    top()->setReadOffset(0);
                    NextCash::Digest digest(NextCash::Digest::SHA1);
                    digest.writeStream(top(), top()->length());
                    digest.getResult(&mHash);
                    pop();

                    // Push the hash
                    mHash.write(push());
                    break;
                }
                case OP_SHA256:
                {
#ifdef PROFILER_ON
                    NextCash::Profiler profiler("Interpreter SHA256");
#endif
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_SHA256");
                        mValid = false;
                        return false;
                    }

                    // Hash top stack item and pop it
                    top()->setReadOffset(0);
                    NextCash::Digest digest(NextCash::Digest::SHA256);
                    digest.writeStream(top(), top()->length());
                    digest.getResult(&mHash);
                    pop();

                    // Push the hash
                    mHash.write(push());
                    break;
                }
                case OP_HASH160: // The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
                {
#ifdef PROFILER_ON
                    NextCash::Profiler profiler("Interpreter Hash160");
#endif
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_HASH160");
                        mValid = false;
                        return false;
                    }

                    // Hash top stack item and pop it
                    top()->setReadOffset(0);
                    NextCash::Digest digest(NextCash::Digest::SHA256_RIPEMD160);
                    digest.writeStream(top(), top()->length());
                    digest.getResult(&mHash);
                    pop();

                    // Push the hash
                    mHash.write(push());
                    break;
                }
                case OP_HASH256: // The input is hashed two times with SHA-256.
                {
#ifdef PROFILER_ON
                    NextCash::Profiler profiler("Interpreter Hash256");
#endif
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_HASH256");
                        mValid = false;
                        return false;
                    }

                    // Hash top stack item and pop it
                    top()->setReadOffset(0);
                    NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
                    digest.writeStream(top(), top()->length());
                    digest.getResult(&mHash);
                    pop();

                    // Push the hash
                    mHash.write(push());
                    break;
                }

                case OP_CODESEPARATOR: // All of the signature checking words will only match signatures to the data after the most recently-executed OP_CODESEPARATOR.
                    if(!ifStackTrue())
                        break;
                    sigStartOffset = (unsigned int)pScript.readOffset();
                    break;

                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY: // Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
                {
#ifdef PROFILER_ON
                    NextCash::Profiler profiler("Interpreter CheckSig");
#endif
                    /* The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR
                     *   to the end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this hash and
                     *   public key. If it is, 1 is returned, 0 otherwise. */
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_CHECKSIG");
                        mValid = false;
                        return false;
                    }

                    // Pop the public key
                    Key publicKey;
                    top()->setReadOffset(0);
                    publicKey.readPublic(top());
                    pop();

                    // Pop the signature
                    Signature signature;
                    top()->setReadOffset(0);
                    signature.read(top(), (unsigned int)top()->length(), strictECDSA_DER_Sigs);
                    pop();

                    // Check the signature with the public key
                    if(checkSignature(*mTransaction, mInputOffset, mOutputAmount, publicKey,
                      signature, pScript, sigStartOffset, pForks))
                    {
                        if(opCode == OP_CHECKSIG)
                            push()->writeByte(1); // Push true onto the stack
                    }
                    else
                    {
                        if(opCode == OP_CHECKSIG)
                            push(); // Push false onto the stack
                        else
                        {
                            mVerified = false;
                            return true;
                        }
                    }

                    break;
                }
                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
#ifdef PROFILER_ON
                    NextCash::Profiler profiler("Interpreter CheckMultiSig");
#endif
                    /* Compares the first signature against each public key until it finds an ECDSA match. Starting with the
                     *   subsequent public key, it compares the second signature against each remaining public key until it
                     *   finds an ECDSA match. The process is repeated until all signatures have been checked or not enough
                     *   public keys remain to produce a successful result. All signatures need to match a public key. Because
                     *   public keys are not checked again if they fail any signature comparison, signatures must be placed in
                     *   the scriptSig using the same order as their corresponding public keys were placed in the scriptPubKey
                     *   or redeemScript. If all signatures are valid, 1 is returned, 0 otherwise. Due to a bug, one extra
                     *   unused value is removed from the stack.
                     *
                     * Preceding data
                     *   <extra value to be removed by bug> sig1 sig2 ... <number of signatures> pub1 pub2 <number of public keys>
                     */
                    if(!ifStackTrue())
                        break;

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
                    Key *publicKeys[publicKeyCount];
                    for(unsigned int i=0;i<publicKeyCount;i++)
                    {
                        publicKeys[i] = new Key();
                        top()->setReadOffset(0);
                        publicKeys[i]->readPublic(top());
                        pop();
                    }

                    // Pop count of signatures
                    unsigned int signatureCount = popInteger();
                    if(!checkStackSize(signatureCount + 1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_CHECKMULTISIG signatures");
                        mValid = false;
                        return false;
                    }

                    // Pop signatures
                    Signature signatures[signatureCount];
                    for(unsigned int i=0;i<signatureCount;i++)
                    {
                        top()->setReadOffset(0);
                        signatures[i].read(top(), top()->length(), strictECDSA_DER_Sigs);
                        pop();
                    }

                    // Pop extra item because of bug
                    pop();

                    // Check the signatures with the public keys to make sure all the signatures are valid
                    unsigned int publicKeyOffset = 0;
                    bool signatureVerified;
                    bool failed = false;
                    for(unsigned int i=0;i<signatureCount;i++)
                    {
                        signatureVerified = false;
                        while(publicKeyOffset < publicKeyCount)
                            if(checkSignature(*mTransaction, mInputOffset, mOutputAmount,
                              *publicKeys[publicKeyOffset++], signatures[i], pScript, sigStartOffset,
                              pForks))
                            {
                                signatureVerified = true;
                                break;
                            }

                        if(!signatureVerified)
                        {
                            failed = true;
                            break;
                        }
                    }

                    // Destroy public keys and signatures
                    for(unsigned int i=0;i<publicKeyCount;i++)
                        delete publicKeys[i];

                    if(failed)
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Multiple Signature check failed");
                        if(opCode == OP_CHECKMULTISIG)
                            push(); // Push false onto the stack
                        else
                        {
                            mVerified = false;
                            return true;
                        }
                    }
                    else
                    {
                        if(opCode == OP_CHECKMULTISIG)
                            push()->writeByte(1); // Push true onto the stack
                    }

                    break;
                }
                case OP_CHECKLOCKTIMEVERIFY: // BIP-0065
                {
                    if(pBlockVersion < 4 || pForks.enabledVersion() < 4)
                        break;

                    if(!ifStackTrue())
                        break;

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
                        return true;
                    }

                    if(mTransaction == NULL)
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "OP_CHECKLOCKTIMEVERIFY Transaction not set");
                        mVerified = false;
                        return true;
                    }

                    // Check that the lock time and time in the stack are both the same type (block height or timestamp)
                    if(((uint32_t)value < Transaction::LOCKTIME_THRESHOLD && mTransaction->lockTime > Transaction::LOCKTIME_THRESHOLD) ||
                      ((uint32_t)value > Transaction::LOCKTIME_THRESHOLD && mTransaction->lockTime < Transaction::LOCKTIME_THRESHOLD))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "OP_CHECKLOCKTIMEVERIFY value and lock time are different \"types\" : value %d > lock time %d",
                          (uint32_t)value, mTransaction->lockTime);
                        mVerified = false;
                        return true;
                    }

                    // Check that the lock time has passed
                    if(mTransaction == NULL || (uint32_t)value > mTransaction->lockTime)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "OP_CHECKLOCKTIMEVERIFY value greater than lock time : value %d > lock time %d", (uint32_t)value,
                          mTransaction->lockTime);
                        mVerified = false;
                        return true;
                    }

                    break;
                }
                case OP_CHECKSEQUENCEVERIFY: // BIP-0112
                {
                    if(pForks.softForkState(SoftFork::BIP0112) != SoftFork::ACTIVE)
                        break;

                    if(!ifStackTrue())
                        break;

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
                            return true;
                        }

                        if(mInputSequence & Input::SEQUENCE_DISABLE) // Input sequence disable bit set
                        {
                            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                              "Input sequence disable bit set : OP_CHECKSEQUENCEVERIFY");
                            mVerified = false;
                            return true;
                        }

                        if((value & Input::SEQUENCE_TYPE) != (mInputSequence & Input::SEQUENCE_TYPE))
                        {
                            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                              "Script sequence type doesn't match input sequence type %d != %d : OP_CHECKSEQUENCEVERIFY",
                              (value & Input::SEQUENCE_TYPE) >> 22, (mInputSequence & Input::SEQUENCE_TYPE) >> 22);
                            mVerified = false;
                            return true;
                        }

                        if((value & Input::SEQUENCE_LOCKTIME_MASK) > (mInputSequence & Input::SEQUENCE_LOCKTIME_MASK))
                        {
                            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                              "Script sequence greater than input sequence %d > %d : OP_CHECKSEQUENCEVERIFY",
                              value & Input::SEQUENCE_LOCKTIME_MASK, mInputSequence & Input::SEQUENCE_LOCKTIME_MASK);
                            mVerified = false;
                            return true;
                        }
                    }

                    break;
                }
                case OP_PUSHDATA1: // The next byte contains the number of bytes to be pushed
                {
                    count = pScript.readByte();
                    if(count > pScript.remaining())
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Push data size more than remaining script : %d/%d", count, pScript.remaining());
                        mValid = false;
                        return false;
                    }
#ifdef PROFILER_ON
                    NextCash::Profiler profiler("Interpreter Push");
#endif
                    if(!ifStackTrue())
                        pScript.setReadOffset(pScript.readOffset() + count);
                    else
                        push()->copyBuffer(pScript, count);
                    break;
                }
                case OP_PUSHDATA2: // The next 2 bytes contains the number of bytes to be pushed
                {
                    count = pScript.readUnsignedShort();
                    if(count > pScript.remaining())
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Push data size more than remaining script : %d/%d", count, pScript.remaining());
                        mValid = false;
                        return false;
                    }
#ifdef PROFILER_ON
                    NextCash::Profiler profiler("Interpreter Push");
#endif
                    if(!ifStackTrue())
                        pScript.setReadOffset(pScript.readOffset() + count);
                    else
                        push()->copyBuffer(pScript, count);
                    break;
                }
                case OP_PUSHDATA4: // The next 4 bytes contains the number of bytes to be pushed
                {
                    count = pScript.readUnsignedInt();
                    if(count > pScript.remaining())
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Push data size more than remaining script : %d/%d", count, pScript.remaining());
                        mValid = false;
                        return false;
                    }
#ifdef PROFILER_ON
                    NextCash::Profiler profiler("Interpreter Push");
#endif
                    if(!ifStackTrue())
                        pScript.setReadOffset(pScript.readOffset() + count);
                    else
                        push()->copyBuffer(pScript, count);
                    break;
                }
                case OP_1NEGATE: // The number -1 is pushed
                    if(!ifStackTrue())
                        break;
                    push();
                    arithmeticWrite(top(), -1);
                    break;
                case OP_1: // The number 1 is pushed
                //case OP_TRUE: // The number 1 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(1);
                    break;
                case OP_2: // The number 2 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(2);
                    break;
                case OP_3: // The number 3 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(3);
                    break;
                case OP_4: // The number 4 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(4);
                    break;
                case OP_5: // The number 5 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(5);
                    break;
                case OP_6: // The number 6 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(6);
                    break;
                case OP_7: // The number 7 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(7);
                    break;
                case OP_8: // The number 8 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(8);
                    break;
                case OP_9: // The number 9 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(9);
                    break;
                case OP_10: // The number 10 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(10);
                    break;
                case OP_11: // The number 11 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(11);
                    break;
                case OP_12: // The number 12 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(12);
                    break;
                case OP_13: // The number 13 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(13);
                    break;
                case OP_14: // The number 14 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(14);
                    break;
                case OP_15: // The number 15 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(15);
                    break;
                case OP_16: // The number 16 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(16);
                    break;


                // Arithmetic
                case OP_1ADD: //    in    out    1 is added to the input.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_1SUB: //    in    out    1 is subtracted from the input.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_2MUL: //    in    out    The input is multiplied by 2. disabled.
                    NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_2MUL is a disabled op code");
                    mValid = false;
                    return false;
                case OP_2DIV: //    in    out    The input is divided by 2. disabled.
                    NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_2DIV is a disabled op code");
                    mValid = false;
                    return false;
                case OP_NEGATE: //    in    out    The sign of the input is flipped.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_ABS: //    in    out    The input is made positive.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_NOT: //    in    out    If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_0NOTEQUAL: //    in    out    Returns 0 if the input is 0. 1 otherwise.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_ADD: //    a b   out    a is added to b.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_SUB: //    a b   out    b is subtracted from a.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_MUL: //    a b   out    a is multiplied by b. disabled.
                    NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_MUL is a disabled op code");
                    mValid = false;
                    return false;
                case OP_DIV: //    a b   out    a is divided by b.
                    if(pForks.fork201805Active())
                    {
                        if(!ifStackTrue())
                            break;

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
                    break;
                case OP_MOD: //    a b   out    Returns the remainder after dividing a by b.
                    if(pForks.fork201805Active())
                    {
                        if(!ifStackTrue())
                            break;

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
                    break;
                case OP_LSHIFT: //    a b   out    Shifts a left b bits, preserving sign. disabled.
                    NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_LSHIFT is a disabled op code");
                    mValid = false;
                    return false;
                case OP_RSHIFT: //    a b   out    Shifts a right b bits, preserving sign. disabled.
                    NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_RSHIFT is a disabled op code");
                    mValid = false;
                    return false;
                case OP_BOOLAND: //    a b   out    If both a and b are not 0, the output is 1. Otherwise 0.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_BOOLOR: //    a b   out    If a or b is not 0, the output is 1. Otherwise 0.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_NUMEQUAL: //    a b   out    Returns 1 if the numbers are equal, 0 otherwise.
                {
                    if(!ifStackTrue())
                        break;

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
                    if(a == b)
                        top()->writeByte(1);
                    break;
                }
                case OP_NUMEQUALVERIFY: //    a b   Nothing / fail    Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_NUMEQUALVERIFY");
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
                    pop();

                    if(a != b)
                    {
                        mVerified = false;
                        return true;
                    }
                    break;
                }
                case OP_NUMNOTEQUAL: //    a b   out    Returns 1 if the numbers are not equal, 0 otherwise.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_LESSTHAN: //    a b   out    Returns 1 if a is less than b, 0 otherwise.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_GREATERTHAN: //    a b   out    Returns 1 if a is greater than b, 0 otherwise.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_LESSTHANOREQUAL: //    a b   out    Returns 1 if a is less than or equal to b, 0 otherwise.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_GREATERTHANOREQUAL: //    a b   out    Returns 1 if a is greater than or equal to b, 0 otherwise
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_MIN: //    a b   out    Returns the smaller of a and b.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_MAX: //    a b   out    Returns the larger of a and b.
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }
                case OP_WITHIN: //    x min max    out    Returns 1 if x is within the specified range (left-inclusive), 0 otherwise
                {
                    if(!ifStackTrue())
                        break;

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
                    break;
                }


                // Stack
                case OP_TOALTSTACK: // Puts the input onto the top of the alt stack. Removes it from the main stack.
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_TOALTSTACK");
                        mValid = false;
                        return false;
                    }

                    pushAlt(top());
                    pop(false);
                    break;
                case OP_FROMALTSTACK: // Puts the input onto the top of the main stack. Removes it from the alt stack.
                    if(!ifStackTrue())
                        break;

                    if(!checkAltStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Alt Stack not large enough for OP_FROMALTSTACK");
                        mValid = false;
                        return false;
                    }

                    push(topAlt());
                    popAlt(false);
                    break;
                case OP_DUP: // Duplicates the top stack item.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_DUP");
                        mValid = false;
                        return false;
                    }

                    push(new NextCash::Buffer(*top()));
                    break;
                }
                case OP_IFDUP: // 0x73//     x    x / x x    If the top stack value is not 0, duplicate it.
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_IFDUP");
                        mValid = false;
                        return false;
                    }

                    if(!bufferIsZero(top()))
                        push(new NextCash::Buffer(*top()));
                    break;
                case OP_DEPTH: // 0x74//     Nothing    <Stack size>    Puts the number of stack items onto the stack.
                {
                    if(!ifStackTrue())
                        break;
                    int64_t stackSize = mStack.size();
                    push();
                    arithmeticWrite(top(), stackSize);
                    break;
                }
                case OP_DROP: // 0x75//     x    Nothing    Removes the top stack item.
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_DROP");
                        mValid = false;
                        return false;
                    }

                    pop();
                    break;
                case OP_NIP: // 0x77//     x1 x2    x2    Removes the second-to-top stack item.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_NIP");
                        mValid = false;
                        return false;
                    }

                    std::list<NextCash::Buffer *>::iterator secondToLast = mStack.end();
                    --secondToLast;
                    --secondToLast;
                    delete *secondToLast;
                    mStack.erase(secondToLast);
                    break;
                }
                case OP_OVER: // 0x78//     x1 x2    x1 x2 x1    Copies the second-to-top stack item to the top.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_OVER");
                        mValid = false;
                        return false;
                    }

                    std::list<NextCash::Buffer *>::iterator secondToLast = mStack.end();
                    --secondToLast;
                    --secondToLast;

                    push(new NextCash::Buffer(**secondToLast));
                    break;
                }
                case OP_PICK: // 0x79//     xn ... x2 x1 x0 <n>    xn ... x2 x1 x0 xn    The item n back in the stack is copied to the top.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_PICK");
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
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROLL");
                        mValid = false;
                        return false;
                    }

                    std::list<NextCash::Buffer *>::iterator item = mStack.end();
                    --item; // get last item

                    for(unsigned int i=0;i<n;i++)
                        --item;

                    push(new NextCash::Buffer(**item));
                    break;
                }
                case OP_ROLL: // 0x7a//     xn ... x2 x1 x0 <n>    ... x2 x1 x0 xn    The item n back in the stack is moved to the top.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROLL");
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
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROLL");
                        mValid = false;
                        return false;
                    }

                    std::list<NextCash::Buffer *>::iterator item = mStack.end();
                    --item; // get last item

                    for(unsigned int i=0;i<n;i++)
                        --item;

                    push(*item);
                    mStack.erase(item);
                    break;
                }
                case OP_ROT: // 0x7b//     x1 x2 x3    x2 x3 x1    The top three items on the stack are rotated to the left.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(3))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROT");
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
                    break;
                }
                case OP_SWAP: // 0x7c//     x1 x2    x2 x1    The top two items on the stack are swapped.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_SWAP");
                        mValid = false;
                        return false;
                    }

                    NextCash::Buffer *two = top();
                    pop(false);
                    NextCash::Buffer *one = top();
                    pop(false);

                    push(two);
                    push(one);
                    break;
                }
                case OP_TUCK: // 0x7d//     x1 x2    x2 x1 x2    The item at the top of the stack is copied and inserted before the second-to-top item.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_TUCK");
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
                    break;
                }
                case OP_2DROP: // 0x6d//     x1 x2    Nothing    Removes the top two stack items.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_2DROP");
                        mValid = false;
                        return false;
                    }

                    pop();
                    pop();
                    break;
                }
                case OP_2DUP: // 0x6e//     x1 x2    x1 x2 x1 x2    Duplicates the top two stack items.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROLL");
                        mValid = false;
                        return false;
                    }

                    std::list<NextCash::Buffer *>::iterator two = mStack.end();
                    --two; // get last item
                    std::list<NextCash::Buffer *>::iterator one = two;
                    --one; // get the second to last item

                    push(new NextCash::Buffer(**one));
                    push(new NextCash::Buffer(**two));
                    break;
                }
                case OP_3DUP: // 0x6f//     x1 x2 x3    x1 x2 x3 x1 x2 x3    Duplicates the top three stack items.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_3DUP");
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
                    break;
                }
                case OP_2OVER: // 0x70//     x1 x2 x3 x4    x1 x2 x3 x4 x1 x2    Copies the pair of items two spaces back in the stack to the front.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(4))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_2OVER");
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
                    break;
                }
                case OP_2ROT: // 0x71//     x1 x2 x3 x4 x5 x6    x3 x4 x5 x6 x1 x2    The fifth and sixth items back are moved to the top of the stack.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(6))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROLL");
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
                    break;
                }
                case OP_2SWAP: // 0x72 //     x1 x2 x3 x4    x3 x4 x1 x2	Swaps the top two pairs of items.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROLL");
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
                    break;
                }


                // Splice
                case OP_CAT: //  x1 x2  out  Concatenates two strings.
                    if(pForks.fork201805Active())
                    {
                        if(!ifStackTrue())
                            break;

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

                        if(one->length() + two->length() > pForks.elementMaxSize())
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
                    break;
                case OP_SPLIT: //  in x n  out x1 x2  Split byte sequence x at position n
                    if(pForks.fork201805Active())
                    {
                        if(!ifStackTrue())
                            break;

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

                        if(x->length() > pForks.elementMaxSize())
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
                    break;
                case OP_NUM2BIN: // in x1 x2 out  Convert numeric value a into byte sequence of length b
                    if(pForks.fork201805Active())
                    {
                        if(!ifStackTrue())
                            break;

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

                        if(length > pForks.elementMaxSize())
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
                    break;
                case OP_BIN2NUM: // in x out Convert byte sequence x into a numeric value
                    if(pForks.fork201805Active())
                    {
                        if(!ifStackTrue())
                            break;

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

                        if(x->length() > pForks.elementMaxSize())
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
                    break;
                case OP_SIZE: //  in x out size  Pushes the string length of the top element of the stack (without popping it).
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_SIZE");
                        mValid = false;
                        return false;
                    }

                    int64_t itemSize = top()->length();
                    push();
                    arithmeticWrite(top(), itemSize);
                    break;
                }


                // Bitwise logic
                case OP_INVERT: //  in  out  Flips all of the bits in the input. disabled.
                    NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_RIGHT is a disabled op code");
                    mValid = false;
                    return false;
                case OP_AND: //  x1 x2  out  Bitwise and between each bit in the inputs.
                    if(pForks.fork201805Active())
                    {
                        if(!ifStackTrue())
                            break;

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
                    break;
                case OP_OR: //  x1 x2  out  Bitwise or between each bit in the inputs.
                    if(pForks.fork201805Active())
                    {
                        if(!ifStackTrue())
                            break;

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
                    break;
                case OP_XOR: //  x1 x2  out  Boolean exclusive or between each bit in the inputs. disabled.
                    if(pForks.fork201805Active())
                    {
                        if(!ifStackTrue())
                            break;

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
                    break;


                // Reserved
                case OP_RESERVED: //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
                case OP_VER: //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
                case OP_VERIF: //  Transaction is invalid even when occuring in an unexecuted OP_IF branch
                case OP_VERNOTIF: //  Transaction is invalid even when occuring in an unexecuted OP_IF branch
                case OP_RESERVED1: //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
                case OP_RESERVED2: //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
                    if(!ifStackTrue())
                        break;
                    NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_RESERVED op code executed");
                    mValid = false;
                    return false;

                case OP_NOP1: // The word is ignored. Does not mark transaction as invalid.
                //OP_NOP2              = 0xb1, // Changed to OP_CHECKLOCKTIMEVERIFY
                //OP_NOP3              = 0xb2, // Changed to OP_CHECKSEQUENCEVERIFY
                case OP_NOP4:  // The word is ignored. Does not mark transaction as invalid.
                case OP_NOP5:  // The word is ignored. Does not mark transaction as invalid.
                case OP_NOP6:  // The word is ignored. Does not mark transaction as invalid.
                case OP_NOP7:  // The word is ignored. Does not mark transaction as invalid.
                case OP_NOP8:  // The word is ignored. Does not mark transaction as invalid.
                case OP_NOP9:  // The word is ignored. Does not mark transaction as invalid.
                case OP_NOP10: // The word is ignored. Does not mark transaction as invalid.
                    break;
            }
        }

        return mValid;
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

        forks.setFork201805Active();

        interpreter.clear();
        testScript.clear();

        // Add element of max size
        ScriptInterpreter::writePushDataSize(forks.elementMaxSize(), &testScript);
        for(unsigned int i=0;i<forks.elementMaxSize();++i)
            testScript.writeByte(0);

        // Add element with size of 1
        ScriptInterpreter::writePushDataSize(1, &testScript);
        testScript.writeByte(0);

        // Add OP_CAT
        testScript.writeByte(OP_CAT);

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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
        ScriptInterpreter::writePushDataSize(forks.elementMaxSize() / 2, &testScript);
        for(unsigned int i=0;i<forks.elementMaxSize() / 2;++i)
            testScript.writeByte(0);

        // Add element of half max size + 1
        ScriptInterpreter::writePushDataSize((forks.elementMaxSize() / 2) + 1, &testScript);
        for(unsigned int i=0;i<(forks.elementMaxSize() / 2) + 1;++i)
            testScript.writeByte(0);

        // Add OP_CAT
        testScript.writeByte(OP_CAT);

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(!interpreter.process(testScript, 4, forks))
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

        if(!interpreter.process(testScript, 4, forks))
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

            if(first != NULL && first->length() == 1 && first->readByte() == 5 && second != NULL && second->length() == 0)
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

        if(!interpreter.process(testScript, 4, forks))
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

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(!interpreter.process(testScript, 4, forks))
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

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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
        ScriptInterpreter::writeArithmeticInteger(testScript, forks.elementMaxSize() + 1);

        // Add OP_NUM2BIN
        testScript.writeByte(OP_NUM2BIN);

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) || interpreter.isValid())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        ScriptInterpreter::writePushDataSize(forks.elementMaxSize(), &testScript);
        testScript.writeByte(0x02);
        for(unsigned int i=0;i<forks.elementMaxSize()-1;++i)
            testScript.writeByte(0x00);

        // Add OP_BIN2NUM
        testScript.writeByte(OP_BIN2NUM);

        testScript.writeByte(OP_2);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        ScriptInterpreter::writePushDataSize(forks.elementMaxSize(), &testScript);
        testScript.writeByte(0x02);
        for(unsigned int i=0;i<forks.elementMaxSize()-2;++i)
            testScript.writeByte(0x00);
        testScript.writeByte(0x80);

        // Add OP_BIN2NUM
        testScript.writeByte(OP_BIN2NUM);

        ScriptInterpreter::writeArithmeticInteger(testScript, -2);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        ScriptInterpreter::writePushDataSize(forks.elementMaxSize(), &testScript);
        for(unsigned int i=0;i<forks.elementMaxSize()-1;++i)
            testScript.writeByte(0x00);
        testScript.writeByte(0x80);

        // Add OP_BIN2NUM
        testScript.writeByte(OP_BIN2NUM);

        ScriptInterpreter::writeArithmeticInteger(testScript, 0);
        testScript.writeByte(OP_EQUAL);

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
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

        if(interpreter.process(testScript, 4, forks) && interpreter.isValid() && interpreter.isVerified())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
              "Passed OP_BIN2NUM negative 1236");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Failed to process OP_BIN2NUM negative 1236");
            interpreter.printStack("Should be -1236");
            success = false;
        }

        return success;
    }
}
