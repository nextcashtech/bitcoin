/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "interpreter.hpp"

#ifdef PROFILER_ON
#include "arcmist/dev/profiler.hpp"
#endif

#include "arcmist/crypto/digest.hpp"
#include "key.hpp"

#define MAX_SINGLE_BYTE_PUSH_DATA_CODE 0x4b


namespace BitCoin
{
    enum OperationCodes
    {
        OP_0                   = 0x00, // An empty array of bytes is pushed to the stack
        OP_FALSE               = 0x00, // An empty array of bytes is pushed to the stack

        OP_PUSHDATA1           = 0x4c, // The next byte contains the number of bytes to be pushed
        OP_PUSHDATA2           = 0x4d, // The next 2 bytes contains the number of bytes to be pushed
        OP_PUSHDATA4           = 0x4e, // The next 4 bytes contains the number of bytes to be pushed

        OP_1NEGATE             = 0x4f, // The number -1 is pushed
        OP_1                   = 0x51, // The number 1 is pushed
        OP_TRUE                = 0x51, // The number 1 is pushed
        OP_2                   = 0x52, // The number 2 is pushed
        OP_3                   = 0x53, // The number 3 is pushed
        OP_4                   = 0x54, // The number 4 is pushed
        OP_5                   = 0x55, // The number 5 is pushed
        OP_6                   = 0x56, // The number 6 is pushed
        OP_7                   = 0x57, // The number 7 is pushed
        OP_8                   = 0x58, // The number 8 is pushed
        OP_9                   = 0x59, // The number 9 is pushed
        OP_10                  = 0x5a, // The number 10 is pushed
        OP_11                  = 0x5b, // The number 11 is pushed
        OP_12                  = 0x5c, // The number 12 is pushed
        OP_13                  = 0x5d, // The number 13 is pushed
        OP_14                  = 0x5e, // The number 14 is pushed
        OP_15                  = 0x5f, // The number 15 is pushed
        OP_16                  = 0x60, // The number 16 is pushed

        OP_NOP                 = 0x61, // Does nothing
        OP_IF                  = 0x63, // If the top stack value is not OP_FALSE the statements are executed. The top stack value is removed
        OP_NOTIF               = 0x64, // If the top stack value is OP_FALSE the statements are executed. The top stack value is removed
        OP_ELSE                = 0x67, // If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then these statements are and if the preceding OP_IF or OP_NOTIF or OP_ELSE was executed then these statements are not.
        OP_ENDIF               = 0x68, // Ends an if/else block. All blocks must end, or the transaction is invalid. An OP_ENDIF without OP_IF earlier is also invalid.

        OP_VERIFY              = 0x69, // Marks transaction as invalid if top stack value is not true.
        OP_RETURN              = 0x6a, // Marks transaction as invalid

        OP_EQUAL               = 0x87, // Returns 1 if the inputs are exactly equal, 0 otherwise
        OP_EQUALVERIFY         = 0x88, // Same as OP_EQUAL, but runs OP_VERIFY afterward.


        // Hashes
        OP_RIPEMD160           = 0xa6, // in   hash   The input is hashed using RIPEMD-160.
        OP_SHA1                = 0xa7, // in  hash  The input is hashed using SHA-1.
        OP_SHA256              = 0xa8, // in  hash  The input is hashed using SHA-256.
        OP_HASH160             = 0xa9, // The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
        OP_HASH256             = 0xaa, // The input is hashed two times with SHA-256.


        // Signatures
        OP_CODESEPARATOR       = 0xab, // All of the signature checking words will only match signatures to the data after the most recently-executed OP_CODESEPARATOR.

        OP_CHECKSIG            = 0xac,
        /* The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR
         *   to the end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this hash and
         *   public key. If it is, 1 is returned, 0 otherwise. */
        OP_CHECKSIGVERIFY      = 0xad, // Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.

        OP_CHECKMULTISIG       = 0xae,
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
        OP_CHECKMULTISIGVERIFY = 0xaf, // Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.

        OP_CHECKLOCKTIMEVERIFY = 0xb1,
        /* Marks transaction as invalid if the top stack item is greater than the transaction's nLockTime field,
         *   otherwise script evaluation continues as though an OP_NOP was executed. Transaction is also invalid
         *   if 1. the stack is empty; or 2. the top stack item is negative; or 3. the top stack item is greater
         *   than or equal to 500000000 while the transaction's nLockTime field is less than 500000000, or vice
         *   versa; or 4. the input's nSequence field is equal to 0xffffffff. The precise semantics are described
         *   in BIP 0065 */
        OP_CHECKSEQUENCEVERIFY  = 0xb2,
        /* Marks transaction as invalid if the relative lock time of the input (enforced by BIP 0068 with nSequence)
         * is not equal to or longer than the value of the top stack item. The precise semantics are described in BIP 0112. */

        OP_1ADD                = 0x8b, //    in    out    1 is added to the input.
        OP_1SUB                = 0x8c, //    in    out    1 is subtracted from the input.
        OP_2MUL                = 0x8d, //    in    out    The input is multiplied by 2. disabled.
        OP_2DIV                = 0x8e, //    in    out    The input is divided by 2. disabled.
        OP_NEGATE              = 0x8f, //    in    out    The sign of the input is flipped.
        OP_ABS                 = 0x90, //    in    out    The input is made positive.
        OP_NOT                 = 0x91, //    in    out    If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
        OP_0NOTEQUAL           = 0x92, //    in    out    Returns 0 if the input is 0. 1 otherwise.
        OP_ADD                 = 0x93, //    a b   out    a is added to b.
        OP_SUB                 = 0x94, //    a b   out    b is subtracted from a.
        OP_MUL                 = 0x95, //    a b   out    a is multiplied by b. disabled.
        OP_DIV                 = 0x96, //    a b   out    a is divided by b. disabled.
        OP_MOD                 = 0x97, //    a b   out    Returns the remainder after dividing a by b. disabled.
        OP_LSHIFT              = 0x98, //    a b   out    Shifts a left b bits, preserving sign. disabled.
        OP_RSHIFT              = 0x99, //    a b   out    Shifts a right b bits, preserving sign. disabled.
        OP_BOOLAND             = 0x9a, //    a b   out    If both a and b are not 0, the output is 1. Otherwise 0.
        OP_BOOLOR              = 0x9b, //    a b   out    If a or b is not 0, the output is 1. Otherwise 0.
        OP_NUMEQUAL            = 0x9c, //    a b   out    Returns 1 if the numbers are equal, 0 otherwise.
        OP_NUMEQUALVERIFY      = 0x9d, //    a b   Nothing / fail    Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
        OP_NUMNOTEQUAL         = 0x9e, //    a b   out    Returns 1 if the numbers are not equal, 0 otherwise.
        OP_LESSTHAN            = 0x9f, //    a b   out    Returns 1 if a is less than b, 0 otherwise.
        OP_GREATERTHAN         = 0xa0, //    a b   out    Returns 1 if a is greater than b, 0 otherwise.
        OP_LESSTHANOREQUAL     = 0xa1, //    a b   out    Returns 1 if a is less than or equal to b, 0 otherwise.
        OP_GREATERTHANOREQUAL  = 0xa2, //    a b   out    Returns 1 if a is greater than or equal to b, 0 otherwise.
        OP_MIN                 = 0xa3, //    a b   out    Returns the smaller of a and b.
        OP_MAX                 = 0xa4, //    a b   out    Returns the larger of a and b.
        OP_WITHIN              = 0xa5, //    x min max    out    Returns 1 if x is within the specified range (left-inclusive), 0 otherwise

        // Stack
        OP_TOALTSTACK          = 0x6b, // Puts the input onto the top of the alt stack. Removes it from the main stack.
        OP_FROMALTSTACK        = 0x6c, // Puts the input onto the top of the main stack. Removes it from the alt stack.
        OP_IFDUP               = 0x73, //     x    x / x x    If the top stack value is not 0, duplicate it.
        OP_DEPTH               = 0x74, //     Nothing    <Stack size>    Puts the number of stack items onto the stack.
        OP_DROP                = 0x75, //     x    Nothing    Removes the top stack item.
        OP_DUP                 = 0x76, //     x    x x    Duplicates the top stack item.
        OP_NIP                 = 0x77, //     x1 x2    x2    Removes the second-to-top stack item.
        OP_OVER                = 0x78, //     x1 x2    x1 x2 x1    Copies the second-to-top stack item to the top.
        OP_PICK                = 0x79, //     xn ... x2 x1 x0 <n>    xn ... x2 x1 x0 xn    The item n back in the stack is copied to the top.
        OP_ROLL                = 0x7a, //     xn ... x2 x1 x0 <n>    ... x2 x1 x0 xn    The item n back in the stack is moved to the top.
        OP_ROT                 = 0x7b, //     x1 x2 x3    x2 x3 x1    The top three items on the stack are rotated to the left.
        OP_SWAP                = 0x7c, //     x1 x2    x2 x1    The top two items on the stack are swapped.
        OP_TUCK                = 0x7d, //     x1 x2    x2 x1 x2    The item at the top of the stack is copied and inserted before the second-to-top item.
        OP_2DROP               = 0x6d, //     x1 x2    Nothing    Removes the top two stack items.
        OP_2DUP                = 0x6e, //     x1 x2    x1 x2 x1 x2    Duplicates the top two stack items.
        OP_3DUP                = 0x6f, //     x1 x2 x3    x1 x2 x3 x1 x2 x3    Duplicates the top three stack items.
        OP_2OVER               = 0x70, //     x1 x2 x3 x4    x1 x2 x3 x4 x1 x2    Copies the pair of items two spaces back in the stack to the front.
        OP_2ROT                = 0x71, //     x1 x2 x3 x4 x5 x6    x3 x4 x5 x6 x1 x2    The fifth and sixth items back are moved to the top of the stack.
        OP_2SWAP               = 0x72, //     x1 x2 x3 x4    x3 x4 x1 x2	Swaps the top two pairs of items.


        // Splice
        OP_CAT                 = 0x7e, //  x1 x2  out  Concatenates two strings. disabled.
        OP_SUBSTR              = 0x7f, //  in begin size  out  Returns a section of a string. disabled.
        OP_LEFT                = 0x80, //  in size  out  Keeps only characters left of the specified point in a string. disabled.
        OP_RIGHT               = 0x81, //  in size  out  Keeps only characters right of the specified point in a string. disabled.
        OP_SIZE                = 0x82, //  in  in size  Pushes the string length of the top element of the stack (without popping it).


        // Bitwise logic
        OP_INVERT              = 0x83, //  in  out  Flips all of the bits in the input. disabled.
        OP_AND                 = 0x84, //  x1 x2  out  Boolean and between each bit in the inputs. disabled.
        OP_OR                  = 0x85, //  x1 x2  out  Boolean or between each bit in the inputs. disabled.
        OP_XOR                 = 0x86, //  x1 x2  out  Boolean exclusive or between each bit in the inputs. disabled.


        // Reserved
        OP_RESERVED            = 0x50, //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
        OP_VER                 = 0x62, //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
        OP_VERIF               = 0x65, //  Transaction is invalid even when occuring in an unexecuted OP_IF branch
        OP_VERNOTIF            = 0x66, //  Transaction is invalid even when occuring in an unexecuted OP_IF branch
        OP_RESERVED1           = 0x89, //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
        OP_RESERVED2           = 0x8a, //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
        OP_NOP1                = 0xb0, // The word is ignored. Does not mark transaction as invalid.
        //OP_NOP2              = 0xb1, // Changed to OP_CHECKLOCKTIMEVERIFY
        //OP_NOP3              = 0xb2, // Changed to OP_CHECKSEQUENCEVERIFY
        OP_NOP4                = 0xb3, // The word is ignored. Does not mark transaction as invalid.
        OP_NOP5                = 0xb4, // The word is ignored. Does not mark transaction as invalid.
        OP_NOP6                = 0xb5, // The word is ignored. Does not mark transaction as invalid.
        OP_NOP7                = 0xb6, // The word is ignored. Does not mark transaction as invalid.
        OP_NOP8                = 0xb7, // The word is ignored. Does not mark transaction as invalid.
        OP_NOP9                = 0xb8, // The word is ignored. Does not mark transaction as invalid.
        OP_NOP10               = 0xb9  // The word is ignored. Does not mark transaction as invalid.
        //TODO More operation codes
    };

    // Parse output script for standard type and hash
    ScriptInterpreter::ScriptType ScriptInterpreter::parseOutputScript(ArcMist::Buffer &pScript, Hash &pHash)
    {
        /* Supports
         *   P2PKH - OP_DUP, OP_HASH160, <PubKeyHash>, OP_EQUALVERIFY, OP_CHECKSIG
         *   P2SH  - OP_HASH160, <Hash160(redeemScript)> OP_EQUAL
         */
        uint8_t opCode;
        Hash tempHash;

        pHash.clear();
        pScript.setReadOffset(0);
        opCode = pScript.readByte();

        if(opCode == OP_DUP)
        {
            if(pScript.readByte() != OP_HASH160)
                return UNKNOWN;
            if(pScript.readByte() != 20) // Push of 20 bytes to stack
                return UNKNOWN;
            tempHash.read(&pScript, 20); // Read public key hash
            if(pScript.readByte() != OP_EQUALVERIFY)
                return UNKNOWN;
            if(pScript.readByte() != OP_CHECKSIG)
                return UNKNOWN;
            pHash = tempHash;
            return P2PKH;
        }
        else if(opCode == OP_HASH160)
        {
            if(pScript.readByte() != 20) // Push of 20 bytes to stack
                return UNKNOWN;
            tempHash.read(&pScript, 20); // Read redeem script hash
            if(pScript.readByte() != OP_EQUAL)
                return UNKNOWN;
            pHash = tempHash;
            return P2SH;
        }

        return UNKNOWN;
    }

    // Create a Pay to Public Key Hash signature script
    bool ScriptInterpreter::writeP2PKHSignatureScript(const PrivateKey &pPrivateKey,
                                                      const PublicKey &pPublicKey,
                                                      Transaction &pTransaction,
                                                      unsigned int pInputOffset,
                                                      ArcMist::Buffer &pUnspentScript,
                                                      Signature::HashType pType,
                                                      ArcMist::OutputStream *pOutput,
                                                      const Forks &pForks)
    {
        Signature signature;

        // Write appropriate data to a SHA256_SHA256 digest
        ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
        unsigned int previousReadOffset = pUnspentScript.readOffset();
        pUnspentScript.setReadOffset(0);
        digest.setOutputEndian(ArcMist::Endian::LITTLE);
        pTransaction.writeSignatureData(&digest, pInputOffset, pUnspentScript, pType, pForks);
        pUnspentScript.setReadOffset(previousReadOffset);

        // Get digest result
        Hash signatureHash(32);
        digest.getResult(&signatureHash);

        // Sign Hash
        if(!pPrivateKey.sign(signatureHash, signature))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed to sign script hash");
            return false;
        }

        // Push the signature onto the stack
        signature.write(pOutput, true, pType);

        // Push the public key onto the stack
        pPublicKey.write(pOutput, true, true);

        return true;
    }

    // Create a Pay to Public Key Hash public key script
    void ScriptInterpreter::writeP2PKHPublicKeyScript(const Hash &pPublicKeyHash, ArcMist::OutputStream *pOutput)
    {
        // Copy the public key from the signature script and push it onto the stack
        pOutput->writeByte(OP_DUP);

        // Pop the public key from the signature script, hash it, and push the hash onto the stack
        pOutput->writeByte(OP_HASH160);

        // Push the provided public key hash onto the stack
        writePushDataSize(pPublicKeyHash.size(), pOutput);
        pPublicKeyHash.write(pOutput);

        // Pop both the hashes from the stack, check that they match, and verify the transaction if they do
        pOutput->writeByte(OP_EQUALVERIFY);

        // Pop the signature from the signature script and verify it against the transaction data
        pOutput->writeByte(OP_CHECKSIG);
    }

    // Create a P2SH (Pay to Script Hash) signature script
    void ScriptInterpreter::writeP2SHSignatureScript(ArcMist::Buffer &pRedeemScript, ArcMist::OutputStream *pOutput)
    {
        // Push the redeem script onto the stack
        writePushDataSize(pRedeemScript.length(), pOutput);
        pRedeemScript.setReadOffset(0);
        pOutput->writeStream(&pRedeemScript, pRedeemScript.length());
    }

    // Create a P2SH (Pay to Script Hash) public key/output script
    void ScriptInterpreter::writeP2SHPublicKeyScript(const Hash &pScriptHash, ArcMist::OutputStream *pOutput)
    {
        // Pop the public key from the signature script, hash it, and push the hash onto the stack
        pOutput->writeByte(OP_HASH160);

        // Push the provided script hash onto the stack
        writePushDataSize(pScriptHash.size(), pOutput);
        pScriptHash.write(pOutput);

        // Pop the hash from the previous step and the redeem script from the signature script
        //   from the stack and check that they match
        pOutput->writeByte(OP_EQUAL);
    }

    Transaction *ScriptInterpreter::createCoinbaseTransaction(int pBlockHeight, const Hash &pPublicKeyHash)
    {
        Transaction *result = new Transaction();
        result->version = 2;

        Input *input = new Input();
        ArcMist::Buffer blockHeight;
        arithmeticWrite(&blockHeight, pBlockHeight); // Write block height into coinbase input
        input->script.writeByte(blockHeight.length());
        blockHeight.readStream(&input->script, blockHeight.length());
        input->script.compact();
        result->inputs.push_back(input);

        Output *output = new Output();
        output->amount = coinBaseAmount(pBlockHeight);
        writeP2PKHPublicKeyScript(pPublicKeyHash, &output->script);
        output->script.compact();
        result->outputs.push_back(output);

        result->lockTime = 0;
        result->calculateHash();
        return result;
    }

    void ScriptInterpreter::writePushDataSize(unsigned int pSize, ArcMist::OutputStream *pOutput)
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

    void ScriptInterpreter::printScript(ArcMist::Buffer &pScript, ArcMist::Log::Level pLevel)
    {
        if(pScript.remaining() == 0)
        {
            ArcMist::Log::addFormatted(pLevel, BITCOIN_INTERPRETER_LOG_NAME, "EMPTY SCRIPT");
            return;
        }

        uint8_t opCode;
        ArcMist::String result;

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
                        result += pScript.readHexString(pScript.readByte());
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
                        result += pScript.readHexString(pScript.readUnsignedInt());
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
                case OP_DIV: //    a b   out    a is divided by b. disabled.
                    result += "<OP_DIV disabled>";
                    break;
                case OP_MOD: //    a b   out    Returns the remainder after dividing a by b. disabled.
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
                case OP_CAT: //  x1 x2  out  Concatenates two strings. disabled.
                    result += "<OP_CAT disabled>";
                    break;
                case OP_SUBSTR: //  in begin size  out  Returns a section of a string. disabled.
                    result += "<OP_SUBSTR disabled>";
                    break;
                case OP_LEFT: //  in size  out  Keeps only characters left of the specified point in a string. disabled.
                    result += "<OP_LEFT disabled>";
                    break;
                case OP_RIGHT: //  in size  out  Keeps only characters right of the specified point in a string. disabled.
                    result += "<OP_RIGHT disabled>";
                    break;
                case OP_SIZE: //  in  in size  Pushes the string length of the top element of the stack (without popping it).
                    result += "<OP_SIZE>";
                    break;


                // Bitwise logic
                case OP_INVERT: //  in  out  Flips all of the bits in the input. disabled.
                    result += "<OP_INVERT disabled>";
                    break;
                case OP_AND: //  x1 x2  out  Boolean and between each bit in the inputs. disabled.
                    result += "<OP_AND disabled>";
                    break;
                case OP_OR: //  x1 x2  out  Boolean or between each bit in the inputs. disabled.
                    result += "<OP_OR disabled>";
                    break;
                case OP_XOR: //  x1 x2  out  Boolean exclusive or between each bit in the inputs. disabled.
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
                    result += "<!!!UNDEFINED!!!>";
                    ArcMist::Log::addFormatted(pLevel, BITCOIN_INTERPRETER_LOG_NAME, "Undefined : %x", opCode);
                    break;
            }
        }

        ArcMist::Log::addFormatted(pLevel, BITCOIN_INTERPRETER_LOG_NAME, result);
    }

    int64_t ScriptInterpreter::readFirstPushOpValue(ArcMist::Buffer &pScript)
    {
        uint8_t opCode = pScript.readByte();
        ArcMist::Buffer data;

        if(opCode == 0x00)
            return 0;
        else if(opCode <= MAX_SINGLE_BYTE_PUSH_DATA_CODE)
        {
            if(opCode > pScript.remaining())
                return 0;
            data.writeStream(&pScript, opCode);
        }
        else
            return 0;

        int64_t value = 0;
        arithmeticRead(&data, value);
        return value;
    }

    void ScriptInterpreter::removeCodeSeparators(ArcMist::Buffer &pInputScript, ArcMist::Buffer &pOutputScript)
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

    bool ScriptInterpreter::checkSignature(PublicKey &pPublicKey, ArcMist::Buffer *pSignature, bool pStrictECDSA_DER_Sigs,
      ArcMist::Buffer &pCurrentOutputScript, unsigned int pSignatureStartOffset, const Forks &pForks)
    {
        // Read the signature from the stack item
        Signature signature;
        pSignature->setReadOffset(0);
        if(pSignature->length() == 0)
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Zero length signature");
            return false;
        }

        if(!signature.read(pSignature, pSignature->length()-1, pStrictECDSA_DER_Sigs))
            return false;

        // Read the hash type from the stack item
        Signature::HashType hashType = static_cast<Signature::HashType>(pSignature->readByte());
        if(pForks.cashRequired() && !(hashType & Signature::FORKID))
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Signature hash type missing required fork ID flag : %02x", hashType);
            return false;
        }

        // Write appropriate data to a SHA256_SHA256 digest
        ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
        unsigned int previousReadOffset = pCurrentOutputScript.readOffset();
        pCurrentOutputScript.setReadOffset(pSignatureStartOffset);
        digest.setOutputEndian(ArcMist::Endian::LITTLE);
        Hash signatureHash(32);
        if(mTransaction->writeSignatureData(&digest, mInputOffset, pCurrentOutputScript, hashType, pForks))
            digest.getResult(&signatureHash); // Get digest result
        else if(hashType & Signature::FORKID)
            signatureHash.zeroize();
        else
            signatureHash.setByte(0, 1); // Use signature hash of 1 (probably sig hash single with not enough outputs)

        pCurrentOutputScript.setReadOffset(previousReadOffset);

        // Push a true or false depending on if the signature is valid
        return signature.verify(pPublicKey, signatureHash);
    }

    void ScriptInterpreter::printStack(const char *pText)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME, "Stack : %s", pText);

        unsigned int index = 1;
        for(std::list<ArcMist::Buffer *>::reverse_iterator i = mStack.rbegin();i!=mStack.rend();++i,index++)
        {
            (*i)->setReadOffset(0);
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_INTERPRETER_LOG_NAME,
              "    %d (%d bytes) : %s", index, (*i)->length(), (*i)->readHexString((*i)->length()).text());
        }
    }

    void ScriptInterpreter::setTransaction(Transaction *pTransaction)
    {
        mTransaction = pTransaction;
    }

    bool ScriptInterpreter::arithmeticRead(ArcMist::Buffer *pBuffer, int64_t &pValue)
    {
        //TODO This is a still messy and should be cleaned up. Unit test below should cover it.
        pBuffer->setReadOffset(0);
        if(pBuffer->length() > 8)
        {
            pBuffer->setReadOffset(0);
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
        if(ArcMist::Endian::sSystemType == ArcMist::Endian::LITTLE)
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
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Arithmetic read to many bytes (negative with 0x80) : %s",
                  pBuffer->readHexString(pBuffer->length()).text());
                return false;
            }
        }
        else if(pBuffer->length() > 4)
        {
            pBuffer->setReadOffset(0);
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
              "Arithmetic read to many bytes : %s", pBuffer->readHexString(pBuffer->length()).text());
            return false;
        }

        // Adjust for system endian
        if(ArcMist::Endian::sSystemType == ArcMist::Endian::LITTLE)
            ArcMist::Endian::reverse(bytes, 8);
        std::memcpy(&pValue, bytes, 8);

        if(negative)
        {
            pValue = -pValue;
            std::memset((uint8_t *)&pValue + startOffset, 0xff, 8 - startOffset);
        }

        pBuffer->setReadOffset(0);
        //ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
        //  "Arithmetic read : %s -> %08x%08x (%d)", pBuffer->readHexString(pBuffer->length()).text(),
        //  pValue >> 32, pValue, pValue & 0xffffffff);
        return true;
    }

    void ScriptInterpreter::arithmeticWrite(ArcMist::Buffer *pBuffer, int64_t pValue)
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
        if(ArcMist::Endian::sSystemType == ArcMist::Endian::LITTLE)
            ArcMist::Endian::reverse(bytes, 8);

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
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Arithmetic write (too many bytes) : %08x%08x -> %s", pValue >> 32, pValue);
                return;
            }

            // Prepend 0x00 byte
            bytes[--startOffset] = 0x00;
        }

        if(ArcMist::Endian::sSystemType == ArcMist::Endian::LITTLE)
        {
            ArcMist::Endian::reverse(bytes, 8);
            pBuffer->write(bytes, 8 - startOffset);
        }
        else
            pBuffer->write(bytes + startOffset, 8 - startOffset);
        pBuffer->setReadOffset(0);
        //ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
        //  "Arithmetic write : %08x%08x (%d) -> %s", pValue >> 32, pValue, pValue & 0xffffffff,
        //  pBuffer->readHexString(pBuffer->length()).text());
    }

    bool ScriptInterpreter::process(ArcMist::Buffer &pScript, bool pIsSignatureScript,
      int32_t pBlockVersion, const Forks &pForks)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Interpreter Process");
#endif
        unsigned int sigStartOffset = pScript.readOffset();
        uint8_t opCode;
        uint64_t count;
        bool strictECDSA_DER_Sigs = pBlockVersion >= 3 && pForks.enabledVersion() >= 3;

        while(pScript.remaining())
        {
            if(mStack.size() > 1000)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                  "Stack overflow %d items", mStack.size());
                mValid = false;
                return false;
            }

            if(mIfStack.size() > 20)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "Push data size more than remaining script : %d/%d", opCode, pScript.remaining());
                    mValid = false;
                    return false;
                }

#ifdef PROFILER_ON
                ArcMist::Profiler profiler("Interpreter Push");
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_IF");
                        mValid = false;
                        return false;
                    }

                    // if(!bufferIsZero(top()))
                        // ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          // "OP_IF pushing to on");
                    // else
                        // ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_NOTIF");
                        mValid = false;
                        return false;
                    }

                    // if(bufferIsZero(top()))
                        // ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          // "OP_NOTIF pushing to on");
                    // else
                        // ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                            // ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                              // "OP_ELSE switching to off");
                        // else
                            // ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                              // "OP_ELSE switching to on");
                        mIfStack.back() = !mIfStack.back();
                    }
                    else
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "No if before else");
                        mValid = false;
                        return false;
                    }
                    break;
                case OP_ENDIF: // Ends an if/else block. All blocks must end, or the transaction is invalid. An OP_ENDIF without OP_IF earlier is also invalid.
                    //ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "OP_ENDIF");
                    if(mIfStack.size() > 0)
                        mIfStack.pop_back();
                    else
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "No if before endif");
                        mValid = false;
                        return false;
                    }
                    break;

                case OP_VERIFY: // Marks transaction as invalid if top stack value is not true.
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Invalid op code for signature script : OP_VERIFY");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_VERIFY");
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
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Return. Marking not verified");
                    mVerified = false;
                    return true;
                case OP_EQUAL: // Returns 1 if the the top two stack items are exactly equal, 0 otherwise
                case OP_EQUALVERIFY: // Same as OP_EQUAL, but runs OP_VERIFY afterward.
                {
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Invalid op code for signature script : OP_EQUAL or OP_EQUALVERIFY");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_EQUALVERIFY");
                        mValid = false;
                        return false;
                    }

                    // Compare top 2 stack entries
                    std::list<ArcMist::Buffer *>::iterator secondToLast = mStack.end();
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
                    ArcMist::Profiler profiler("Interpreter RipeMD160");
#endif
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Invalid op code for signature script : OP_SHA1");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_SHA1");
                        mValid = false;
                        return false;
                    }

                    // Hash top stack item and pop it
                    top()->setReadOffset(0);
                    ArcMist::Digest digest(ArcMist::Digest::RIPEMD160);
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
                    ArcMist::Profiler profiler("Interpreter SHA1");
#endif
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Invalid op code for signature script : OP_SHA1");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_SHA1");
                        mValid = false;
                        return false;
                    }

                    // Hash top stack item and pop it
                    top()->setReadOffset(0);
                    ArcMist::Digest digest(ArcMist::Digest::SHA1);
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
                    ArcMist::Profiler profiler("Interpreter SHA256");
#endif
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Invalid op code for signature script : OP_SHA256");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_SHA256");
                        mValid = false;
                        return false;
                    }

                    // Hash top stack item and pop it
                    top()->setReadOffset(0);
                    ArcMist::Digest digest(ArcMist::Digest::SHA256);
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
                    ArcMist::Profiler profiler("Interpreter Hash160");
#endif
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Invalid op code for signature script : OP_HASH160");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_HASH160");
                        mValid = false;
                        return false;
                    }

                    // Hash top stack item and pop it
                    top()->setReadOffset(0);
                    ArcMist::Digest digest(ArcMist::Digest::SHA256_RIPEMD160);
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
                    ArcMist::Profiler profiler("Interpreter Hash256");
#endif
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Invalid op code for signature script : OP_HASH256");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_HASH256");
                        mValid = false;
                        return false;
                    }

                    // Hash top stack item and pop it
                    top()->setReadOffset(0);
                    ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
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
                    sigStartOffset = pScript.readOffset();
                    break;

                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY: // Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
                {
#ifdef PROFILER_ON
                    ArcMist::Profiler profiler("Interpreter CheckSig");
#endif
                    /* The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR
                     *   to the end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this hash and
                     *   public key. If it is, 1 is returned, 0 otherwise. */
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_CHECKSIG");
                        mValid = false;
                        return false;
                    }

                    // Pop the public key
                    PublicKey publicKey;
                    top()->setReadOffset(0);
                    publicKey.read(top());
                    pop();

                    // Check the signature (at the top of the stack) with the public key we just popped from the stack
                    if(checkSignature(publicKey, top(), strictECDSA_DER_Sigs, pScript, sigStartOffset, pForks))
                    {
                        pop();
                        if(opCode == OP_CHECKSIG)
                            push()->writeByte(1); // Push true onto the stack
                    }
                    else
                    {
                        pop();
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Signature check failed");
                        //ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                        //  "Public key : %s", publicKey.hex().text());
                        //ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                        //  "Signature : %s", scriptSignature.hex().text());
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
                    ArcMist::Profiler profiler("Interpreter CheckMultiSig");
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_CHECKMULTISIG");
                        mValid = false;
                        return false;
                    }

                    // Pop count of public keys
                    unsigned int publicKeyCount = popInteger();
                    if(!checkStackSize(publicKeyCount))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_CHECKMULTISIG public keys");
                        mValid = false;
                        return false;
                    }

                    // Pop public keys
                    PublicKey *publicKeys[publicKeyCount];
                    for(unsigned int i=0;i<publicKeyCount;i++)
                    {
                        publicKeys[i] = new PublicKey();
                        top()->setReadOffset(0);
                        publicKeys[i]->read(top());
                        pop();
                    }

                    // Pop count of signatures
                    unsigned int signatureCount = popInteger();
                    if(!checkStackSize(signatureCount + 1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_CHECKMULTISIG signatures");
                        mValid = false;
                        return false;
                    }

                    // Pop signatures
                    ArcMist::Buffer *signatures[signatureCount];
                    for(unsigned int i=0;i<signatureCount;i++)
                    {
                        signatures[i] = top();
                        pop(false);
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
                            if(checkSignature(*publicKeys[publicKeyOffset++], signatures[i],
                              strictECDSA_DER_Sigs, pScript, sigStartOffset, pForks))
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
                    for(unsigned int i=0;i<signatureCount;i++)
                        delete signatures[i];
                    for(unsigned int i=0;i<publicKeyCount;i++)
                        delete publicKeys[i];

                    if(failed)
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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

                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Invalid op code for signature script : OP_CHECKLOCKTIMEVERIFY");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "OP_CHECKLOCKTIMEVERIFY top stack value can't be negative : %d", (int)value);
                        mValid = false;
                        return false;
                    }

                    if(mInputSequence == 0xffffffff)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "OP_CHECKLOCKTIMEVERIFY input sequence not 0xffffffff : %08x", mInputSequence);
                        mVerified = false;
                        return true;
                    }

                    if(mTransaction == NULL)
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "OP_CHECKLOCKTIMEVERIFY Transaction not set");
                        mVerified = false;
                        return true;
                    }

                    // Check that the lock time and time in the stack are both the same type (block height or timestamp)
                    if(((uint32_t)value < Transaction::LOCKTIME_THRESHOLD && mTransaction->lockTime > Transaction::LOCKTIME_THRESHOLD) ||
                      ((uint32_t)value > Transaction::LOCKTIME_THRESHOLD && mTransaction->lockTime < Transaction::LOCKTIME_THRESHOLD))
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "OP_CHECKLOCKTIMEVERIFY value and lock time are different \"types\" : value %d > lock time %d",
                          (uint32_t)value, mTransaction->lockTime);
                        mVerified = false;
                        return true;
                    }

                    // Check that the lock time has passed
                    if(mTransaction == NULL || (uint32_t)value > mTransaction->lockTime)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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

                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Invalid op code for signature script : OP_CHECKSEQUENCEVERIFY");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Negative script sequence : OP_CHECKSEQUENCEVERIFY");
                        mValid = false;
                        return false;
                    }

                    if(!(value & Input::SEQUENCE_DISABLE)) // Script sequence disable bit set
                    {
                        // Transaction version doesn't support OP_CHECKSEQUENCEVERIFY
                        if(mTransaction->version < 2)
                        {
                            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                              "Transaction version less than 2 : OP_CHECKSEQUENCEVERIFY");
                            mVerified = false;
                            return true;
                        }

                        if(mInputSequence & Input::SEQUENCE_DISABLE) // Input sequence disable bit set
                        {
                            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                              "Input sequence disable bit set : OP_CHECKSEQUENCEVERIFY");
                            mVerified = false;
                            return true;
                        }

                        if((value & Input::SEQUENCE_TYPE) != (mInputSequence & Input::SEQUENCE_TYPE))
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                              "Script sequence type doesn't match input sequence type %d != %d : OP_CHECKSEQUENCEVERIFY",
                              (value & Input::SEQUENCE_TYPE) >> 22, (mInputSequence & Input::SEQUENCE_TYPE) >> 22);
                            mVerified = false;
                            return true;
                        }

                        if((value & Input::SEQUENCE_LOCKTIME_MASK) > (mInputSequence & Input::SEQUENCE_LOCKTIME_MASK))
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Push data size more than remaining script : %d/%d", count, pScript.remaining());
                        mValid = false;
                        return false;
                    }
#ifdef PROFILER_ON
                    ArcMist::Profiler profiler("Interpreter Push");
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
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Push data size more than remaining script : %d/%d", count, pScript.remaining());
                        mValid = false;
                        return false;
                    }
#ifdef PROFILER_ON
                    ArcMist::Profiler profiler("Interpreter Push");
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
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Push data size more than remaining script : %d/%d", count, pScript.remaining());
                        mValid = false;
                        return false;
                    }
#ifdef PROFILER_ON
                    ArcMist::Profiler profiler("Interpreter Push");
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_2MUL is a disabled op code");
                    mValid = false;
                    return false;
                case OP_2DIV: //    in    out    The input is divided by 2. disabled.
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_2DIV is a disabled op code");
                    mValid = false;
                    return false;
                case OP_NEGATE: //    in    out    The sign of the input is flipped.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_MUL is a disabled op code");
                    mValid = false;
                    return false;
                case OP_DIV: //    a b   out    a is divided by b. disabled.
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_DIV is a disabled op code");
                    mValid = false;
                    return false;
                case OP_MOD: //    a b   out    Returns the remainder after dividing a by b. disabled.
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_MOD is a disabled op code");
                    mValid = false;
                    return false;
                case OP_LSHIFT: //    a b   out    Shifts a left b bits, preserving sign. disabled.
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_LSHIFT is a disabled op code");
                    mValid = false;
                    return false;
                case OP_RSHIFT: //    a b   out    Shifts a right b bits, preserving sign. disabled.
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_RSHIFT is a disabled op code");
                    mValid = false;
                    return false;
                case OP_BOOLAND: //    a b   out    If both a and b are not 0, the output is 1. Otherwise 0.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_TOALTSTACK");
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Alt Stack not large enough for OP_FROMALTSTACK");
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_DUP");
                        mValid = false;
                        return false;
                    }

                    push(new ArcMist::Buffer(*top()));
                    break;
                }
                case OP_IFDUP: // 0x73//     x    x / x x    If the top stack value is not 0, duplicate it.
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_IFDUP");
                        mValid = false;
                        return false;
                    }

                    if(!bufferIsZero(top()))
                        push(new ArcMist::Buffer(*top()));
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_DROP");
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_NIP");
                        mValid = false;
                        return false;
                    }

                    std::list<ArcMist::Buffer *>::iterator secondToLast = mStack.end();
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_OVER");
                        mValid = false;
                        return false;
                    }

                    std::list<ArcMist::Buffer *>::iterator secondToLast = mStack.end();
                    --secondToLast;
                    --secondToLast;

                    push(new ArcMist::Buffer(**secondToLast));
                    break;
                }
                case OP_PICK: // 0x79//     xn ... x2 x1 x0 <n>    xn ... x2 x1 x0 xn    The item n back in the stack is copied to the top.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_PICK");
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROLL");
                        mValid = false;
                        return false;
                    }

                    std::list<ArcMist::Buffer *>::iterator item = mStack.end();
                    --item; // get last item

                    for(unsigned int i=0;i<n;i++)
                        --item;

                    push(new ArcMist::Buffer(**item));
                    break;
                }
                case OP_ROLL: // 0x7a//     xn ... x2 x1 x0 <n>    ... x2 x1 x0 xn    The item n back in the stack is moved to the top.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROLL");
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROLL");
                        mValid = false;
                        return false;
                    }

                    std::list<ArcMist::Buffer *>::iterator item = mStack.end();
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROT");
                        mValid = false;
                        return false;
                    }

                    ArcMist::Buffer *three = top();
                    pop(false);
                    ArcMist::Buffer *two = top();
                    pop(false);
                    ArcMist::Buffer *one = top();
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_SWAP");
                        mValid = false;
                        return false;
                    }

                    ArcMist::Buffer *two = top();
                    pop(false);
                    ArcMist::Buffer *one = top();
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_TUCK");
                        mValid = false;
                        return false;
                    }

                    ArcMist::Buffer *two = top();
                    pop(false);
                    ArcMist::Buffer *one = top();
                    pop(false);

                    push(new ArcMist::Buffer(*two));
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_2DROP");
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROLL");
                        mValid = false;
                        return false;
                    }

                    std::list<ArcMist::Buffer *>::iterator two = mStack.end();
                    --two; // get last item
                    std::list<ArcMist::Buffer *>::iterator one = two;
                    --one; // get the second to last item

                    push(new ArcMist::Buffer(**one));
                    push(new ArcMist::Buffer(**two));
                    break;
                }
                case OP_3DUP: // 0x6f//     x1 x2 x3    x1 x2 x3 x1 x2 x3    Duplicates the top three stack items.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_3DUP");
                        mValid = false;
                        return false;
                    }

                    std::list<ArcMist::Buffer *>::iterator three = mStack.end();
                    --three; // get last item
                    std::list<ArcMist::Buffer *>::iterator two = three;
                    --two; // get second to last item
                    std::list<ArcMist::Buffer *>::iterator one = two;
                    --one; // get the third to last item

                    push(new ArcMist::Buffer(**one));
                    push(new ArcMist::Buffer(**two));
                    push(new ArcMist::Buffer(**three));
                    break;
                }
                case OP_2OVER: // 0x70//     x1 x2 x3 x4    x1 x2 x3 x4 x1 x2    Copies the pair of items two spaces back in the stack to the front.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(4))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_2OVER");
                        mValid = false;
                        return false;
                    }

                    std::list<ArcMist::Buffer *>::iterator two = mStack.end();
                    --two; // 4
                    --two; // 3
                    --two; // 2
                    std::list<ArcMist::Buffer *>::iterator one = two;
                    --one; // 1

                    push(new ArcMist::Buffer(**one));
                    push(new ArcMist::Buffer(**two));
                    break;
                }
                case OP_2ROT: // 0x71//     x1 x2 x3 x4 x5 x6    x3 x4 x5 x6 x1 x2    The fifth and sixth items back are moved to the top of the stack.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(6))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROLL");
                        mValid = false;
                        return false;
                    }

                    std::list<ArcMist::Buffer *>::iterator two = mStack.end();
                    --two; // 6
                    --two; // 5
                    --two; // 4
                    --two; // 3
                    --two; // 2
                    std::list<ArcMist::Buffer *>::iterator one = two;
                    --one; // 1

                    ArcMist::Buffer *itemTwo = *two;
                    ArcMist::Buffer *itemOne = *one;

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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_ROLL");
                        mValid = false;
                        return false;
                    }

                    std::list<ArcMist::Buffer *>::iterator two = mStack.end();
                    --two; // 4
                    --two; // 3
                    --two; // 2
                    std::list<ArcMist::Buffer *>::iterator one = two;
                    --one; // 1

                    ArcMist::Buffer *itemTwo = *two;
                    ArcMist::Buffer *itemOne = *one;

                    mStack.erase(one);
                    mStack.erase(two);

                    push(itemOne);
                    push(itemTwo);
                    break;
                }


                // Splice
                case OP_CAT: //  x1 x2  out  Concatenates two strings. disabled.
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_CAT is a disabled op code");
                    mValid = false;
                    return false;
                case OP_SUBSTR: //  in begin size  out  Returns a section of a string. disabled.
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_SUBSTR is a disabled op code");
                    mValid = false;
                    return false;
                case OP_LEFT: //  in size  out  Keeps only characters left of the specified point in a string. disabled.
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_LEFT is a disabled op code");
                    mValid = false;
                    return false;
                case OP_RIGHT: //  in size  out  Keeps only characters right of the specified point in a string. disabled.
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_RIGHT is a disabled op code");
                    mValid = false;
                    return false;
                case OP_SIZE: //  in  in size  Pushes the string length of the top element of the stack (without popping it).
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_SIZE");
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
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_RIGHT is a disabled op code");
                    mValid = false;
                    return false;
                case OP_AND: //  x1 x2  out  Boolean and between each bit in the inputs. disabled.
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_RIGHT is a disabled op code");
                    mValid = false;
                    return false;
                case OP_OR: //  x1 x2  out  Boolean or between each bit in the inputs. disabled.
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_RIGHT is a disabled op code");
                    mValid = false;
                    return false;
                case OP_XOR: //  x1 x2  out  Boolean exclusive or between each bit in the inputs. disabled.
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_RIGHT is a disabled op code");
                    mValid = false;
                    return false;


                // Reserved
                case OP_RESERVED: //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
                case OP_VER: //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
                case OP_VERIF: //  Transaction is invalid even when occuring in an unexecuted OP_IF branch
                case OP_VERNOTIF: //  Transaction is invalid even when occuring in an unexecuted OP_IF branch
                case OP_RESERVED1: //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
                case OP_RESERVED2: //  Transaction is invalid unless occuring in an unexecuted OP_IF branch
                    if(!ifStackTrue())
                        break;
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
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
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME,
          "------------- Starting Script Interpreter Tests -------------");

        bool success = true;
        ArcMist::Buffer data, testData;
        int64_t value, testValue;

        /***********************************************************************************************
         * Arithmetic read 0x7fffffff - Highest 32 bit positive number (highest bit 0)
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("ffffff7f");
        value = 0x7fffffff;

        if(arithmeticRead(&testData, testValue) && value == testValue)
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0x7fffffff");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0x7fffffff");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0x7fffffff");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0x7fffffff");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %s", testData.readHexString(testData.length()).text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0xffffffff");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0xffffffff");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0xffffffff");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0xffffffff");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %s", testData.readHexString(testData.length()).text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0xffffffff80");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0xffffffff80");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %s", testData.readHexString(testData.length()).text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0xffffffff80");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0xffffffff80");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0xfeffffff80");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0xfeffffff80");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0xfeffffff80");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0xfeffffff80");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %s", testData.readHexString(testData.length()).text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0x6e");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0x6e");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0x6e");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0x6e");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %s", testData.readHexString(testData.length()).text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0xfeffffff00");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0xfeffffff00");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0xfeffffff00");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0xfeffffff00");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct   : %s", testData.readHexString(testData.length()).text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0x82");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0x82");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %08x%08x", value >> 32, value);
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
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
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0x82");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0x82");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct   : %s", testData.readHexString(testData.length()).text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Written : %s", data.readHexString(data.length()).text());
            success = false;
        }

        return success;
    }
}
