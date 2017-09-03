#include "interpreter.hpp"

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

        OP_TOALTSTACK          = 0x6b, // Puts the input onto the top of the alt stack. Removes it from the main stack.
        OP_FROMALTSTACK        = 0x6c, // Puts the input onto the top of the main stack. Removes it from the alt stack.
        OP_DUP                 = 0x76, // Duplicates the top stack item.
        
        OP_EQUAL               = 0x87, // Returns 1 if the inputs are exactly equal, 0 otherwise
        OP_EQUALVERIFY         = 0x88, // Same as OP_EQUAL, but runs OP_VERIFY afterward.

        OP_HASH160             = 0xa9, // The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
        OP_HASH256             = 0xaa, // The input is hashed two times with SHA-256.
        
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
                                                      ArcMist::OutputStream *pOutput)
    {
        Signature signature(pPrivateKey.context());

        // Write appropriate data to a SHA256_SHA256 digest
        ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
        unsigned int previousReadOffset = pUnspentScript.readOffset();
        pUnspentScript.setReadOffset(0);
        digest.setOutputEndian(ArcMist::Endian::LITTLE);
        pTransaction.writeSignatureData(&digest, pInputOffset, pUnspentScript, pType);
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
    
    void ScriptInterpreter::writePushDataSize(unsigned int pSize, ArcMist::OutputStream *pOutput)
    {
        if(pSize < MAX_SINGLE_BYTE_PUSH_DATA_CODE)
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

            if(opCode < MAX_SINGLE_BYTE_PUSH_DATA_CODE)
            {
                result += "<PUSH=";
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
                case OP_TOALTSTACK:
                    result += "<OP_TOALTSTACK>";
                    break;
                case OP_FROMALTSTACK:
                    result += "<OP_FROMALTSTACK>";
                    break;
                case OP_DUP:
                    result += "<OP_DUP>";
                    break;
                case OP_EQUAL:
                    result += "<OP_EQUAL>";
                    break;
                case OP_EQUALVERIFY:
                    result += "<OP_EQUALVERIFY>";
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
                case OP_PUSHDATA1: // The next byte contains the number of bytes to be pushed
                    result += "<OP_PUSHDATA1=";
                    result += pScript.readHexString(pScript.readByte());
                    result += ">";
                    break;
                case OP_PUSHDATA2: // The next 2 bytes contains the number of bytes to be pushed
                    result += "<OP_PUSHDATA2=";
                    result += pScript.readHexString(pScript.readUnsignedShort());
                    result += ">";
                    break;
                case OP_PUSHDATA4: // The next 4 bytes contains the number of bytes to be pushed
                    result += "<OP_PUSHDATA4=";
                    result += pScript.readHexString(pScript.readUnsignedInt());
                    result += ">";
                    break;
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
                    result += "<OP_2MUL>";
                    break;
                case OP_2DIV: //    in    out    The input is divided by 2. disabled.
                    result += "<OP_2DIV>";
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
                    result += "<OP_MUL>";
                    break;
                case OP_DIV: //    a b   out    a is divided by b. disabled.
                    result += "<OP_DIV>";
                    break;
                case OP_MOD: //    a b   out    Returns the remainder after dividing a by b. disabled.
                    result += "<OP_MOD>";
                    break;
                case OP_LSHIFT: //    a b   out    Shifts a left b bits, preserving sign. disabled.
                    result += "<OP_LSHIFT>";
                    break;
                case OP_RSHIFT: //    a b   out    Shifts a right b bits, preserving sign. disabled.
                    result += "<OP_RSHIFT>";
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

                default:
                    result += "<!!!UNDEFINED!!!>";
                    ArcMist::Log::addFormatted(pLevel, BITCOIN_INTERPRETER_LOG_NAME, "Undefined : %x", opCode);
                    break;
            }
        }

        ArcMist::Log::addFormatted(pLevel, BITCOIN_INTERPRETER_LOG_NAME, result);
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

            if(opCode < MAX_SINGLE_BYTE_PUSH_DATA_CODE)
            {
                pOutputScript.writeStream(&pInputScript, opCode);
                continue;
            }

            switch(opCode)
            {
                case OP_PUSHDATA1: // The next byte contains the number of bytes to be pushed
                {
                    uint8_t size = pInputScript.readByte();
                    pOutputScript.writeByte(size);
                    pOutputScript.writeStream(&pInputScript, size);
                    break;
                }
                case OP_PUSHDATA2: // The next 2 bytes contains the number of bytes to be pushed
                {
                    uint16_t size = pInputScript.readUnsignedShort();
                    pOutputScript.writeUnsignedShort(size);
                    pOutputScript.writeStream(&pInputScript, size);
                    break;
                }
                case OP_PUSHDATA4: // The next 4 bytes contains the number of bytes to be pushed
                {
                    uint32_t size = pInputScript.readUnsignedInt();
                    pOutputScript.writeUnsignedInt(size);
                    pOutputScript.writeStream(&pInputScript, size);
                    break;
                }
                default:
                    break;
            }
        }
    }

    bool ScriptInterpreter::checkSignature(PublicKey &pPublicKey, ArcMist::Buffer *pSignature, bool pECDSA_DER_SigsOnly,
      ArcMist::Buffer &pCurrentOutputScript, unsigned int pSignatureStartOffset)
    {
        // Read the signature from the stack item
        Signature signature(pPublicKey.context());
        pSignature->setReadOffset(0);
        if(!signature.read(pSignature, pSignature->length()-1, pECDSA_DER_SigsOnly))
        {
            mValid = false;
            return false;
        }

        // Read the hash type from the stack item
        Signature::HashType hashType = static_cast<Signature::HashType>(pSignature->readByte());

        // Write appropriate data to a SHA256_SHA256 digest
        ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
        unsigned int previousReadOffset = pCurrentOutputScript.readOffset();
        pCurrentOutputScript.setReadOffset(pSignatureStartOffset);
        digest.setOutputEndian(ArcMist::Endian::LITTLE);
        mTransaction.writeSignatureData(&digest, mInputOffset, pCurrentOutputScript, hashType);
        pCurrentOutputScript.setReadOffset(previousReadOffset);

        // Get digest result
        Hash signatureHash(32);
        digest.getResult(&signatureHash);

        // Push a true or false depending on if the signature is valid
        return signature.verify(pPublicKey, signatureHash);
    }

    void ScriptInterpreter::setTransaction(Transaction &pTransaction)
    {
        mTransaction = pTransaction;
    }

    bool arithmeticRead(ArcMist::Buffer *pBuffer, int64_t &pValue)
    {
        //TODO This is a mess and needs to be cleaned up. Unit test below should cover it.
        // For logging
        pBuffer->setReadOffset(0);
        ArcMist::String inputValue = pBuffer->readHexString(pBuffer->length());

        if(pBuffer->length() > 8)
        {
            pBuffer->setReadOffset(0);
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
              "Arithmetic read to many bytes : %s", inputValue.text());
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
        //pBuffer->read(bytes + (8 - pBuffer->length()), pBuffer->length());
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

        bool negative = false;

        // Skip 0xff (all bits true) bytes
        for(int i=startOffset;i<8;i++)
            if(bytes[i] == 0xff)
            {
                negative = true;
                startOffset++;
            }
            else
                break;

        if(startOffset == 8) // all 0xff
        {
            pValue = -1;
            return true;
        }

        negative = negative || bytes[startOffset] & 0x80;

        if(negative)
        {
            if(bytes[startOffset] == 0x80)
                startOffset++; // Skip 0x80 byte
            else
                bytes[startOffset] ^= 0x80; // Flip highest bit

            // Set any previous bytes to 0xff
            std::memset(bytes, 0xff, startOffset);
        }
        else
        {
            // Zeroize any previous bytes
            std::memset(bytes, 0, startOffset);

            // Skip zero bytes
            for(int i=startOffset;i<8;i++)
                if(bytes[i] == 0x00)
                    startOffset++;
                else
                    break;
        }

        if(startOffset == 8)
        {
            if(negative) // All 0xff
                pValue = -1; // this might not get hit
            else // All 0x00
                pValue = 0;
        }
        else
        {
            if(negative && bytes[startOffset] == 0x80)
            {
                if(startOffset < 3)
                {
                    pBuffer->setReadOffset(0);
                    ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                      "Arithmetic read to many bytes (negative) : %s", inputValue.text());
                    return false;
                }
            }
            else if(pBuffer->length() > 5)
            {
                pBuffer->setReadOffset(0);
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                  "Arithmetic read to many bytes (positive) : %s", inputValue.text());
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
        }

        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
          "Arithmetic read : %s -> %08x%08x", inputValue.text(), pValue >> 32, pValue);
        return true;
    }

    void arithmeticWrite(ArcMist::Buffer *pBuffer, int64_t pValue)
    {
        //TODO This is a mess and needs to be cleaned up. Unit test below should cover it.
        uint8_t bytes[8];
        int startOffset = 0;
        bool negative = pValue < 0;

        std::memcpy(bytes, &pValue, 8);
        if(ArcMist::Endian::sSystemType == ArcMist::Endian::LITTLE)
            ArcMist::Endian::reverse(bytes, 8);

        // Minimal encoding. Remove leading 0xff bytes
        if(negative)
        {
            // Skip 0xff bytes
            for(int i=startOffset;i<5;i++)
                if(bytes[i] == 0xff)
                    startOffset++;
                else
                    break;
        }
        else
        {
            // Skip zero bytes
            for(int i=startOffset;i<8;i++)
                if(bytes[i] == 0x00)
                    startOffset++;
                else
                    break;
        }

        if(startOffset == 4 && (negative || bytes[startOffset] & 0x80))
        {
            // Needs compacting
            int64_t value = pValue;
            if(negative)
                value = -value;

            std::memcpy(bytes, &value, 8);
            if(ArcMist::Endian::sSystemType == ArcMist::Endian::LITTLE)
                ArcMist::Endian::reverse(bytes, 8);

            startOffset = 0;
            // Skip zero bytes
            for(int i=startOffset;i<4;i++)
                if(bytes[i] == 0x00)
                    startOffset++;
                else
                    break;

            if(bytes[startOffset] & 0x80) // Highest bit set
            {
                if(negative)
                {
                    //    - If the most significant byte is >= 0x80 and the value is negative, push a
                    //    new 0x80 byte that will be popped off when converting to an integral.
                    bytes[--startOffset] = 0x80; // Add a new 0x80 byte
                }
                else
                {
                    //    - If the most significant byte is >= 0x80 and the value is positive, push a
                    //    new zero-byte to make the significant byte < 0x80 again.
                    bytes[--startOffset] = 0x00; // Add a new 0x00 byte
                }
            }
            else if(negative)
            {
                //    - If the most significant byte is < 0x80 and the value is negative, add
                //    0x80 to it, since it will be subtracted and interpreted as a negative when
                //    converting to an integral.
                bytes[--startOffset] = 0x80;
            }
        }
        else if(negative && bytes[startOffset] == 0xff)
            startOffset--;
        else if(!negative && bytes[startOffset] == 0x00)
            startOffset--;

        pBuffer->clear();
        if(ArcMist::Endian::sSystemType == ArcMist::Endian::LITTLE)
        {
            ArcMist::Endian::reverse(bytes, 8);
            pBuffer->write(bytes, 8 - startOffset);
        }
        else
            pBuffer->write(bytes + startOffset, 8 - startOffset);
        pBuffer->setReadOffset(0);
        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
          "Arithmetic write : %08x%08x -> %s", pValue >> 32, pValue, pBuffer->readHexString(pBuffer->length()).text());
    }

    bool ScriptInterpreter::process(ArcMist::Buffer &pScript, bool pIsSignatureScript, bool pECDSA_DER_SigsOnly)
    {
        unsigned int sigStartOffset = pScript.readOffset();
        uint8_t opCode;
        uint64_t count;

        while(pScript.remaining())
        {
            opCode = pScript.readByte();

            if(opCode == 0x00)
            {
                if(!ifStackTrue())
                    continue;

                // Push an empty value onto the stack (OP_FALSE)
                push()->writeByte(0);
                continue;
            }

            if(opCode < MAX_SINGLE_BYTE_PUSH_DATA_CODE)
            {
                if(!ifStackTrue())
                    continue;

                // Push opCode value bytes onto stack from input
                push()->writeStream(&pScript, opCode);
                continue;
            }

            switch(opCode)
            {
                case OP_NOP: // Does nothing
                    break;

                case OP_IF: // If the top stack value is not OP_FALSE the statements are executed. The top stack value is removed
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Invalid op code for signature script : OP_IF");
                        mValid = false;
                        return false;
                    }

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_IF");
                        mValid = false;
                        return false;
                    }

                    top()->setReadOffset(0);
                    mIfStack.push_back(top()->length() > 0);
                    pop();
                    break;
                case OP_NOTIF: // If the top stack value is OP_FALSE the statements are executed. The top stack value is removed
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Invalid op code for signature script : OP_NOTIF");
                        mValid = false;
                        return false;
                    }

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_NOTIF");
                        mValid = false;
                        return false;
                    }

                    top()->setReadOffset(0);
                    mIfStack.push_back(top()->length() > 0);
                    pop();
                    break;
                case OP_ELSE: // If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then these statements are and if the preceding OP_IF or OP_NOTIF or OP_ELSE was executed then these statements are not.
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Invalid op code for signature script : OP_ELSE");
                        mValid = false;
                        return false;
                    }

                    if(mIfStack.size() > 0)
                        mIfStack.back() = !mIfStack.back();
                    else
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "No if before else");
                        mValid = false;
                        return false;
                    }
                    break;
                case OP_ENDIF: // Ends an if/else block. All blocks must end, or the transaction is invalid. An OP_ENDIF without OP_IF earlier is also invalid.
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Invalid op code for signature script : OP_ENDIF");
                        mValid = false;
                        return false;
                    }

                    if(mIfStack.size() > 0)
                        mIfStack.pop_back();
                    else
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "No if before endif");
                        mValid = false;
                        return false;
                    }
                    break;

                case OP_VERIFY: // Marks transaction as invalid if top stack value is not true.
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Invalid op code for signature script : OP_VERIFY");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_VERIFY");
                        mValid = false;
                        return false;
                    }

                    if(bufferIsZero(*top()))
                        mVerified = false;
                    break;
                case OP_RETURN: // Marks transaction as invalid
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Invalid op code for signature script : OP_RETURN");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;
                    ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Return. Marking not verified");
                    mVerified = false;
                    return true;

                case OP_TOALTSTACK: // Puts the input onto the top of the alt stack. Removes it from the main stack.
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_TOALTSTACK");
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
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Alt Stack not large enough for OP_FROMALTSTACK");
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
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_DUP");
                        mValid = false;
                        return false;
                    }

                    ArcMist::Buffer *dupBuffer = new ArcMist::Buffer();
                    top()->setReadOffset(0);
                    dupBuffer->writeStream(top(), top()->length());
                    push(dupBuffer);
                    printStack("OP_DUP");
                    break;
                }
                case OP_EQUAL: // Returns 1 if the the top two stack items are exactly equal, 0 otherwise
                case OP_EQUALVERIFY: // Same as OP_EQUAL, but runs OP_VERIFY afterward.
                {
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Invalid op code for signature script : OP_EQUAL or OP_EQUALVERIFY");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;
                    
                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_EQUALVERIFY");
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
                        else
                            mVerified = true;
                    }
                    else
                    {
                        if(opCode == OP_EQUAL)
                            push(); // Push false
                        else
                            mVerified = false;
                    }

                    break;
                }
                case OP_HASH160: // The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
                {
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Invalid op code for signature script : OP_HASH160");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;
                    
                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_HASH160");
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
                    ArcMist::Buffer *hash160Buffer = new ArcMist::Buffer();
                    mHash.write(hash160Buffer);
                    push(hash160Buffer);

                    break;
                }
                case OP_HASH256: // The input is hashed two times with SHA-256.
                {
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                          "Invalid op code for signature script : OP_HASH256");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;
                    
                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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
                    ArcMist::Buffer *hash256Buffer = new ArcMist::Buffer();
                    mHash.write(hash256Buffer);
                    push(hash256Buffer);
                    break;
                }

                case OP_CODESEPARATOR: // All of the signature checking words will only match signatures to the data after the most recently-executed OP_CODESEPARATOR.
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                          "Invalid op code for signature script : OP_CODESEPARATOR");
                        mValid = false;
                        return false;
                    }

                    if(!ifStackTrue())
                        break;
                    sigStartOffset = pScript.readOffset();
                    break;

                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY: // Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
                {
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                          "Invalid op code for signature script : OP_CHECKSIG or OP_CHECKSIGVERIFY");
                        mValid = false;
                        return false;
                    }

                    /* The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR
                     *   to the end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this hash and
                     *   public key. If it is, 1 is returned, 0 otherwise. */
                    if(!ifStackTrue())
                        break;
                    
                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_CHECKSIG");
                        mValid = false;
                        return false;
                    }

                    KeyContext keyContext;

                    // Pop the public key
                    PublicKey publicKey(&keyContext);
                    top()->setReadOffset(0);
                    if(!publicKey.read(top()))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Failed to read public key");
                        mValid = false;
                        return false;
                    }
                    pop();

                    // Check the signature with the public key
                    if(checkSignature(publicKey, top(), pECDSA_DER_SigsOnly, pScript, sigStartOffset))
                    {
                        pop();
                        if(opCode == OP_CHECKSIG)
                            push()->writeByte(1); // Push true onto the stack
                        else
                            mVerified = true;
                    }
                    else
                    {
                        pop();
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Signature check failed");
                        //ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                        //  "Public key : %s", publicKey.hex().text());
                        //ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                        //  "Signature : %s", scriptSignature.hex().text());
                        if(opCode == OP_CHECKSIG)
                            push(); // Push false onto the stack
                        else
                            mVerified = false;
                    }

                    break;
                }
                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                          "Invalid op code for signature script : OP_CHECKMULTISIG or OP_CHECKMULTISIGVERIFY");
                        mValid = false;
                        return false;
                    }

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

                    if(!checkStackSize(5))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_CHECKMULTISIG");
                        mValid = false;
                        return false;
                    }

                    KeyContext keyContext;

                    // Pop count of public keys
                    unsigned int publicKeyCount = popInteger();
                    if(!checkStackSize(publicKeyCount))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                          "Stack not large enough for OP_CHECKMULTISIG public keys");
                        mValid = false;
                        return false;
                    }

                    // Pop public keys
                    PublicKey *publicKeys[publicKeyCount];
                    for(unsigned int i=0;i<publicKeyCount;i++)
                    {
                        publicKeys[i] = new PublicKey(&keyContext);
                        top()->setReadOffset(0);
                        if(!publicKeys[i]->read(top()))
                        {
                            ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME, "Failed to read public key");
                            mValid = false;
                            return false;
                        }
                        pop();
                    }

                    // Pop count of signatures
                    unsigned int signatureCount = popInteger();
                    if(!checkStackSize(signatureCount + 1))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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
                            if(checkSignature(*publicKeys[publicKeyOffset], signatures[i],
                              pECDSA_DER_SigsOnly, pScript, sigStartOffset))
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
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                          "Multiple Signature check failed");
                        if(opCode == OP_CHECKMULTISIG)
                            push(); // Push false onto the stack
                        else
                            mVerified = false;
                    }
                    else
                    {
                        if(opCode == OP_CHECKMULTISIG)
                            push()->writeByte(1); // Push true onto the stack
                        else
                            mVerified = true;
                    }

                    break;
                }
                case OP_CHECKLOCKTIMEVERIFY:
                    if(pIsSignatureScript)
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                          "Invalid op code for signature script : OP_CHECKLOCKTIMEVERIFY");
                        mValid = false;
                        return false;
                    }

                    /* Marks transaction as invalid if the top stack item is greater than the transaction's nLockTime field,
                     *   otherwise script evaluation continues as though an OP_NOP was executed. Transaction is also invalid
                     *   if 1. the stack is empty; or 2. the top stack item is negative; or 3. the top stack item is greater
                     *   than or equal to 500000000 while the transaction's nLockTime field is less than 500000000, or vice
                     *   versa; or 4. the input's nSequence field is equal to 0xffffffff. The precise semantics are described
                     *   in BIP 0065 */
                    if(!ifStackTrue())
                        break;
                    
                    //TODO execute OP_CHECKLOCKTIMEVERIFY
                    break;

                case OP_PUSHDATA1: // The next byte contains the number of bytes to be pushed
                    if(!ifStackTrue())
                        break;
                    count = pScript.readByte();
                    push()->writeStream(&pScript, count);
                    break;
                case OP_PUSHDATA2: // The next 2 bytes contains the number of bytes to be pushed
                    if(!ifStackTrue())
                        break;
                    count = pScript.readUnsignedShort();
                    push()->writeStream(&pScript, count);
                    break;
                case OP_PUSHDATA4: // The next 4 bytes contains the number of bytes to be pushed
                    if(!ifStackTrue())
                        break;
                    count = pScript.readUnsignedInt();
                    push()->writeStream(&pScript, count);
                    break;

                case OP_0: // An empty array of bytes is pushed to the stack
                //case OP_FALSE: // An empty array of bytes is pushed to the stack
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(0);
                    break;
                case OP_1NEGATE: // The number -1 is pushed
                    if(!ifStackTrue())
                        break;
                    push()->writeByte(-1);
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
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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
                    ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_2MUL is a disabled op code");
                    mValid = false;
                    break;
                case OP_2DIV: //    in    out    The input is divided by 2. disabled.
                    ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_2DIV is a disabled op code");
                    mValid = false;
                    break;
                case OP_NEGATE: //    in    out    The sign of the input is flipped.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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

                    top()->setWriteOffset(0);
                    if(value == 0)
                        top()->writeByte(1);
                    else
                        top()->writeByte(0);
                    break;
                }
                case OP_0NOTEQUAL: //    in    out    Returns 0 if the input is 0. 1 otherwise.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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

                    top()->setWriteOffset(0);
                    if(value == 0)
                        top()->writeByte(0);
                    else
                        top()->writeByte(1);
                    break;
                }
                case OP_ADD: //    a b   out    a is added to b.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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
                    ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_MUL is a disabled op code");
                    mValid = false;
                    break;
                case OP_DIV: //    a b   out    a is divided by b. disabled.
                    ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_DIV is a disabled op code");
                    mValid = false;
                    break;
                case OP_MOD: //    a b   out    Returns the remainder after dividing a by b. disabled.
                    ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_MOD is a disabled op code");
                    mValid = false;
                    break;
                case OP_LSHIFT: //    a b   out    Shifts a left b bits, preserving sign. disabled.
                    ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_LSHIFT is a disabled op code");
                    mValid = false;
                    break;
                case OP_RSHIFT: //    a b   out    Shifts a right b bits, preserving sign. disabled.
                    ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
                      "OP_RSHIFT is a disabled op code");
                    mValid = false;
                    break;
                case OP_BOOLAND: //    a b   out    If both a and b are not 0, the output is 1. Otherwise 0.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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

                    top()->setWriteOffset(0);
                    if(a != 0 && b != 0)
                        top()->writeByte(1);
                    else
                        top()->writeByte(0);
                    break;
                }
                case OP_BOOLOR: //    a b   out    If a or b is not 0, the output is 1. Otherwise 0.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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

                    top()->setWriteOffset(0);
                    if(a != 0 || b != 0)
                        top()->writeByte(1);
                    else
                        top()->writeByte(0);
                    break;
                }
                case OP_NUMEQUAL: //    a b   out    Returns 1 if the numbers are equal, 0 otherwise.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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

                    top()->setWriteOffset(0);
                    if(a == b)
                        top()->writeByte(1);
                    else
                        top()->writeByte(0);
                    break;
                }
                case OP_NUMEQUALVERIFY: //    a b   Nothing / fail    Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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

                    top()->setWriteOffset(0);
                    if(a == b)
                        top()->writeByte(1);
                    else
                    {
                        top()->writeByte(0);
                        mVerified = false;
                    }
                    break;
                }
                case OP_NUMNOTEQUAL: //    a b   out    Returns 1 if the numbers are not equal, 0 otherwise.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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

                    top()->setWriteOffset(0);
                    if(a != b)
                        top()->writeByte(1);
                    else
                        top()->writeByte(0);
                    break;
                }
                case OP_LESSTHAN: //    a b   out    Returns 1 if a is less than b, 0 otherwise.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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

                    top()->setWriteOffset(0);
                    if(a < b)
                        top()->writeByte(1);
                    else
                        top()->writeByte(0);
                    break;
                }
                case OP_GREATERTHAN: //    a b   out    Returns 1 if a is greater than b, 0 otherwise.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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

                    top()->setWriteOffset(0);
                    if(a > b)
                        top()->writeByte(1);
                    else
                        top()->writeByte(0);
                    break;
                }
                case OP_LESSTHANOREQUAL: //    a b   out    Returns 1 if a is less than or equal to b, 0 otherwise.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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

                    top()->setWriteOffset(0);
                    if(a <= b)
                        top()->writeByte(1);
                    else
                        top()->writeByte(0);
                    break;
                }
                case OP_GREATERTHANOREQUAL: //    a b   out    Returns 1 if a is greater than or equal to b, 0 otherwise
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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

                    top()->setWriteOffset(0);
                    if(a >= b)
                        top()->writeByte(1);
                    else
                        top()->writeByte(0);
                    break;
                }
                case OP_MIN: //    a b   out    Returns the smaller of a and b.
                {
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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
                        ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_INTERPRETER_LOG_NAME,
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

                    top()->setWriteOffset(0);
                    if(x >= min && x < max)
                        top()->writeByte(1);
                    else
                        top()->writeByte(0);
                    break;
                }
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
        value = 0xffffffffffffffff;

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
        value = 0xffffffffffffffff;
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
         * Arithmetic write 0xffffff7f80 - Lowest 32 bit negative number (first and last bits 1) == ‭-2,147,483,647‬
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("ffffff7f80");
        value = 0xffffffff80000001; // 64 bit form of ‭-2,147,483,647‬
        arithmeticWrite(&data, value); // Compress to as few bytes as possible (which is 5 : 0xfeffffff80)

        data.setReadOffset(0);
        if(data == testData)
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic write 0xffffff7f80");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic write 0xffffff7f80");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Correct : %s", testData.readHexString(testData.length()).text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME,
              "Written : %s", data.readHexString(data.length()).text());
            success = false;
        }

        /***********************************************************************************************
         * Arithmetic read 0xffffff7f80 - Lowest 32 bit negative number (first and last bits 1) == ‭-2,147,483,647‬
         ***********************************************************************************************/
        testData.clear();
        testData.writeHex("ffffff7f80");
        value = 0xffffffff80000001;

        if(arithmeticRead(&testData, testValue) && value == testValue)
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_INTERPRETER_LOG_NAME, "Passed Arithmetic read 0xffffff7f80");
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed Arithmetic read 0xffffff7f80");
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

        return success;
    }
}
