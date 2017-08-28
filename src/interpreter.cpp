#include "interpreter.hpp"

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

        OP_CHECKLOCKTIMEVERIFY = 0xb1 
        /* Marks transaction as invalid if the top stack item is greater than the transaction's nLockTime field,
         *   otherwise script evaluation continues as though an OP_NOP was executed. Transaction is also invalid
         *   if 1. the stack is empty; or 2. the top stack item is negative; or 3. the top stack item is greater
         *   than or equal to 500000000 while the transaction's nLockTime field is less than 500000000, or vice
         *   versa; or 4. the input's nSequence field is equal to 0xffffffff. The precise semantics are described
         *   in BIP 0065 */

        //TODO More operation codes
    };

    // Parse output script for standard type and hash
    ScriptType parseOutputScript(ArcMist::Buffer &pScript, Hash &pHash)
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
    bool writeP2PKHSignatureScript(const PrivateKey &pPrivateKey,
                                   const PublicKey &pPublicKey,
                                   ArcMist::Buffer &pScript,
                                   ArcMist::OutputStream *pOutput)
    {
        Hash signatureHash(32);
        Signature signature(pPrivateKey.context());

        // Calculate Hash
        pScript.setReadOffset(0);
        doubleSHA256(&pScript, pScript.length(), signatureHash);

        // Sign Hash
        if(!pPrivateKey.sign(signatureHash, signature))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_INTERPRETER_LOG_NAME, "Failed to sign script hash");
            return false;
        }

        // Push the signature onto the stack
        signature.write(pOutput, true);

        // Push the public key onto the stack
        pPublicKey.write(pOutput, true, true);

        return true;
    }

    // Create a Pay to Public Key Hash public key script
    void writeP2PKHPublicKeyScript(const Hash &pPublicKeyHash, ArcMist::OutputStream *pOutput)
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
    void writeP2SHSignatureScript(ArcMist::Buffer &pRedeemScript, ArcMist::OutputStream *pOutput)
    {
        // Push the redeem script onto the stack
        writePushDataSize(pRedeemScript.length(), pOutput);
        pRedeemScript.setReadOffset(0);
        pOutput->writeStream(&pRedeemScript, pRedeemScript.length());
    }

    // Create a P2SH (Pay to Script Hash) public key/output script
    void writeP2SHPublicKeyScript(const Hash &pScriptHash, ArcMist::OutputStream *pOutput)
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
    
    void writePushDataSize(unsigned int pSize, ArcMist::OutputStream *pOutput)
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

    void writeScriptToText(ArcMist::InputStream *pScript, ArcMist::OutputStream *pText)
    {
        //TODO
    }

    bool checkSignature(PublicKey &pPublicKey, Signature &pSignature, ArcMist::Buffer &pScript, unsigned int pSignatureStartOffset)
    {
        // Get offset of end of signature
        unsigned int previousReadOffset = pScript.readOffset();

        // Set read offset to the beginning of the data for the signature
        pScript.setReadOffset(pSignatureStartOffset);

        // Calculate the signature hash
        Hash signatureHash(32);
        doubleSHA256(&pScript, pScript.length() - pSignatureStartOffset, signatureHash);

        // Set offset back to the previous
        pScript.setReadOffset(previousReadOffset);

        // Push a true or false depending on if the signature is valid
        return pSignature.verify(pPublicKey, signatureHash);
    }

    bool ScriptInterpreter::process(ArcMist::Buffer &pScript)
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
                push();
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
                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_IF");
                        mValid = false;
                        return false;
                    }

                    top()->setReadOffset(0);
                    mIfStack.push_back(top()->length() > 0);
                    pop();
                    break;
                case OP_NOTIF: // If the top stack value is OP_FALSE the statements are executed. The top stack value is removed
                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_NOTIF");
                        mValid = false;
                        return false;
                    }

                    top()->setReadOffset(0);
                    mIfStack.push_back(top()->length() > 0);
                    pop();
                    break;
                case OP_ELSE: // If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then these statements are and if the preceding OP_IF or OP_NOTIF or OP_ELSE was executed then these statements are not.
                    if(mIfStack.size() > 0)
                        mIfStack.back() = !mIfStack.back();
                    else
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "No if before else");
                        mValid = false;
                        return false;
                    }
                    break;
                case OP_ENDIF: // Ends an if/else block. All blocks must end, or the transaction is invalid. An OP_ENDIF without OP_IF earlier is also invalid.
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
                    if(!ifStackTrue())
                        break;

                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_VERIFY");
                        mValid = false;
                        return false;
                    }

                    if(top()->length() == 0)
                        mVerified = false;
                    else if(top()->length() == 1)
                        mVerified = top()->readByte() != 0;
                    else if(top()->length() == 2)
                        mVerified = top()->readUnsignedShort() != 0;
                    else if(top()->length() == 4)
                        mVerified = top()->readUnsignedInt() != 0;
                    else
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME,
                          "Verify stack when top is longer than 4 : %d", top()->length());
                        mValid = false;
                        return false;
                    }
                    break;
                case OP_RETURN: // Marks transaction as invalid
                    if(!ifStackTrue())
                        break;
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Return. Marking not verified");
                    mVerified = false;
                    return false;

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

                    ArcMist::Buffer *dupBuffer = new ArcMist::Buffer();
                    top()->setReadOffset(0);
                    dupBuffer->writeStream(top(), top()->length());
                    push(dupBuffer);
                    break;
                }
                case OP_EQUAL: // Returns 1 if the the top two stack items are exactly equal, 0 otherwise
                case OP_EQUALVERIFY: // Same as OP_EQUAL, but runs OP_VERIFY afterward.
                {
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
                    bool matching = *mStack.back() == **secondToLast;
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
                    mHash.setSize(20);
                    sha256RIPEMD160(top(), top()->length(), mHash);
                    pop();

                    // Push the hash
                    ArcMist::Buffer *hash160Buffer = new ArcMist::Buffer();
                    mHash.write(hash160Buffer);
                    push(hash160Buffer);

                    break;
                }
                case OP_HASH256: // The input is hashed two times with SHA-256.
                {
                    if(!ifStackTrue())
                        break;
                    
                    if(!checkStackSize(1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_HASH256");
                        mValid = false;
                        return false;
                    }

                    // Hash top stack item and pop it
                    top()->setReadOffset(0);
                    mHash.setSize(32);
                    doubleSHA256(top(), top()->length(), mHash);
                    pop();

                    // Push the hash
                    ArcMist::Buffer *hash256Buffer = new ArcMist::Buffer();
                    mHash.write(hash256Buffer);
                    push(hash256Buffer);
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
                    /* The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR
                     *   to the end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this hash and
                     *   public key. If it is, 1 is returned, 0 otherwise. */
                    if(!ifStackTrue())
                        break;
                    
                    if(!checkStackSize(2))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_CHECKSIG");
                        mValid = false;
                        return false;
                    }

                    KeyContext keyContext;

                    // Pop the public key
                    PublicKey publicKey(&keyContext);
                    top()->setReadOffset(0);
                    if(!publicKey.read(top()))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Failed to read public key");
                        mValid = false;
                        return false;
                    }
                    pop();

                    // Pop the signature
                    Signature scriptSignature(&keyContext);
                    top()->setReadOffset(0);
                    if(!scriptSignature.read(top(), top()->length()))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Failed to read signature");
                        mValid = false;
                        return false;
                    }
                    pop();

                    // Check the signature with the public key
                    if(checkSignature(publicKey, scriptSignature, pScript, sigStartOffset))
                    {
                        if(opCode == OP_CHECKSIG)
                            push()->writeByte(1); // Push true onto the stack
                        else
                            mVerified = true;
                    }
                    else
                    {
                        if(opCode == OP_CHECKSIG)
                            push(); // Push false onto the stack
                        else
                        {
                            mVerified = false;
                            return false;
                        }
                    }

                    break;
                }
                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
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
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_CHECKMULTISIG");
                        mValid = false;
                        return false;
                    }

                    KeyContext keyContext;

                    // Pop count of public keys
                    unsigned int publicKeyCount = popInteger();

                    if(!checkStackSize(publicKeyCount))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_CHECKMULTISIG public keys");
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
                            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Failed to read public key");
                            mValid = false;
                            return false;
                        }
                        pop();
                    }

                    // Pop count of signatures
                    unsigned int signatureCount = popInteger();

                    if(!checkStackSize(signatureCount + 1))
                    {
                        ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Stack not large enough for OP_CHECKMULTISIG signatures");
                        mValid = false;
                        return false;
                    }

                    // Pop signatures
                    Signature *signatures[signatureCount];
                    for(unsigned int i=0;i<signatureCount;i++)
                    {
                        signatures[i] = new Signature(&keyContext);
                        top()->setReadOffset(0);
                        if(!signatures[i]->read(top(), top()->length()))
                        {
                            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_INTERPRETER_LOG_NAME, "Failed to read signature");
                            mValid = false;
                            return false;
                        }
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
                        {
                            if(checkSignature(*publicKeys[publicKeyOffset], *signatures[i], pScript, sigStartOffset))
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
                    
                    // Destroy public keys and signatures
                    for(unsigned int i=0;i<signatureCount;i++)
                        delete signatures[i];
                    for(unsigned int i=0;i<publicKeyCount;i++)
                        delete publicKeys[i];

                    if(failed)
                    {
                        if(opCode == OP_CHECKMULTISIG)
                            push(); // Push false onto the stack
                        else
                        {
                            mVerified = false;
                            return false;
                        }
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
                    push();
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
            }
        }

        return mValid;
    }
}
