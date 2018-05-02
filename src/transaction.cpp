/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                       *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "transaction.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#endif

#include "endian.hpp"
#include "math.hpp"
#include "log.hpp"
#include "digest.hpp"
#include "interpreter.hpp"
#include "block.hpp"

#define BITCOIN_TRANSACTION_LOG_NAME "Transaction"


namespace BitCoin
{
    Transaction::Transaction(const Transaction &pCopy)
    {
        hash = pCopy.hash;
        version = pCopy.version;
        lockTime = pCopy.lockTime;

        mOutpointHash = pCopy.mOutpointHash;
        mSequenceHash = pCopy.mSequenceHash;
        mOutputHash = pCopy.mOutputHash;
        mTime = pCopy.mTime;
        mFee = pCopy.mFee;
        mStatus = pCopy.mStatus;
        mSize = pCopy.mSize;

        inputs.reserve(pCopy.inputs.size());
        for(std::vector<Input>::const_iterator copyInput=pCopy.inputs.begin();copyInput!=pCopy.inputs.end();++copyInput)
            inputs.emplace_back(*copyInput);

        outputs.resize(pCopy.outputs.size());
        for(std::vector<Output>::const_iterator copyOutput=pCopy.outputs.begin();copyOutput!=pCopy.outputs.end();++copyOutput)
            outputs.emplace_back(*copyOutput);
    }

    Transaction::~Transaction()
    {
    }

    void Transaction::clear()
    {
        hash.clear();
        mOutpointHash.clear();
        mSequenceHash.clear();
        mOutputHash.clear();
        version = 2;
        mFee = 0;
        lockTime = 0xffffffff;

        inputs.clear();
        outputs.clear();
    }

    void Transaction::clearCache()
    {
        mOutpointHash.clear();
        mSequenceHash.clear();
        mOutputHash.clear();
    }

    void Transaction::print(Forks &pForks, NextCash::Log::Level pLevel)
    {
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Hash      : %s", hash.hex().text());
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Version   : %d", version);
        if(lockTime > LOCKTIME_THRESHOLD)
        {
            NextCash::String lockTimeText;
            lockTimeText.writeFormattedTime(lockTime);
            NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME,
              "Lock Time : time stamp %d - %s", lockTime, lockTimeText.text());
        }
        else
            NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME,
              "Lock Time : block height %d", lockTime);
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Fee       : %f", bitcoins(-mFee));

        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "%d Inputs", inputs.size());
        unsigned int index = 1;
        for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Input %d", index++);
            input->print(pForks, pLevel);
        }

        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "%d Outputs", outputs.size());
        index = 1;
        for(std::vector<Output>::iterator output=outputs.begin();output!=outputs.end();++output)
        {
            NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Output %d", index++);
            output->print(pForks, pLevel);
        }
    }

    void Input::print(Forks &pForks, NextCash::Log::Level pLevel)
    {
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Outpoint Trans : %s", outpoint.transactionID.hex().text());
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Outpoint Index : %d", outpoint.index);
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Sequence       : 0x%08x", sequence);
        script.setReadOffset(0);
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Script         : (%d bytes)",script.length());
        ScriptInterpreter::printScript(script, pForks, pLevel);
    }

    bool Transaction::addInput(const NextCash::Hash &pTransactionID, unsigned int pIndex, uint32_t pSequence)
    {
        // Add input
        inputs.emplace_back();
        Input &newInput = inputs.back();

        // Link input to unspent
        newInput.outpoint.transactionID = pTransactionID;
        newInput.outpoint.index = pIndex;
        newInput.sequence = pSequence;
        return true;
    }

    bool Transaction::addCoinbaseInput(int pBlockHeight)
    {
        // Add input
        inputs.emplace_back();
        Input &newInput = inputs.back();

        ScriptInterpreter::writeArithmeticInteger(newInput.script, pBlockHeight);
        newInput.script.compact();
        return true;
    }

    bool Transaction::signP2PKHInput(Output &pOutput, unsigned int pInputOffset, const Key &pPrivateKey,
      const Key &pPublicKey, Signature::HashType pHashType)
    {
        NextCash::HashList outputHashes;
        if(ScriptInterpreter::parseOutputScript(pOutput.script, outputHashes) != ScriptInterpreter::P2PKH)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Output script is not P2PKH");
            return false;
        }

        if(outputHashes.size() != 1 || pPublicKey.hash() != outputHashes.front())
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Output script public key hash doesn't match");
            return false;
        }

        if(inputs.size() <= pInputOffset)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Invalid input offset");
            return false;
        }
        Input &thisInput = inputs[pInputOffset];

        // Create input script
        // Get signature hash
        NextCash::Hash signatureHash;
        pOutput.script.setReadOffset(0);
        if(!getSignatureHash(signatureHash, pInputOffset, pOutput.script, pOutput.amount, pHashType))
            return false;

        // Sign Hash
        Signature signature;
        if(!pPrivateKey.sign(signatureHash, signature))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to sign script hash");
            return false;
        }
        signature.setHashType(pHashType);

        thisInput.script.clear();

        // Push the signature onto the stack
        signature.write(&thisInput.script, true);

        // Push the public key onto the stack
        pPublicKey.writePublic(&thisInput.script, true);
        return true;
    }

    bool Transaction::addP2PKHOutput(const NextCash::Hash &pPublicKeyHash, uint64_t pAmount)
    {
        outputs.emplace_back();
        Output &newOutput = outputs.back();
        newOutput.amount = pAmount;

        // Copy the public key from the signature script and push it onto the stack
        newOutput.script.writeByte(OP_DUP);

        // Pop the public key from the signature script, hash it, and push the hash onto the stack
        newOutput.script.writeByte(OP_HASH160);

        // Push the provided public key hash onto the stack
        ScriptInterpreter::writePushDataSize(pPublicKeyHash.size(), &newOutput.script);
        pPublicKeyHash.write(&newOutput.script);

        // Pop both the hashes from the stack, check that they match, and verify the transaction if they do
        newOutput.script.writeByte(OP_EQUALVERIFY);

        // Pop the signature from the signature script and verify it against the transaction data
        newOutput.script.writeByte(OP_CHECKSIG);
        newOutput.script.compact();

        return true;
    }

    bool Transaction::signP2PKInput(Output &pOutput, unsigned int pInputOffset, const Key &pPrivateKey,
      const Key &pPublicKey, Signature::HashType pHashType)
    {
        NextCash::HashList outputHashes;
        pOutput.script.setReadOffset(0);
        if(ScriptInterpreter::parseOutputScript(pOutput.script, outputHashes) != ScriptInterpreter::P2PK)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Output script is not P2PK");
            return false;
        }

        if(outputHashes.size() != 1)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Output script public keys don't match");
            return false;
        }

        if(pPublicKey.hash() != outputHashes.front())
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Output script public key doesn't match");
            return false;
        }

        // Check Public Key in output
        NextCash::Buffer publicKeyData;
        pOutput.script.setReadOffset(0);
        if(ScriptInterpreter::readDataPush(pOutput.script, publicKeyData) == 0)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Failed to read public key");
            return false;
        }

        Key checkPublicKey;
        if(!checkPublicKey.readPublic(&publicKeyData))
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Failed to parse public key");
            return false;
        }

        if(checkPublicKey != pPublicKey)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Non matching public key");
            return false;
        }

        if(inputs.size() <= pInputOffset)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Invalid input offset");
            return false;
        }
        Input &thisInput = inputs[pInputOffset];

        // Create input script
        // Get signature hash
        NextCash::Hash signatureHash;
        pOutput.script.setReadOffset(0);
        if(!getSignatureHash(signatureHash, pInputOffset, pOutput.script, pOutput.amount, pHashType))
            return false;

        // Sign Hash
        Signature signature;
        if(!pPrivateKey.sign(signatureHash, signature))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to sign script hash");
            return false;
        }
        signature.setHashType(pHashType);

        // Push the signature onto the stack
        thisInput.script.clear();
        signature.write(&thisInput.script, true);
        return true;
    }

    bool Transaction::addP2PKOutput(const Key &pPublicKey, uint64_t pAmount)
    {
        outputs.emplace_back();
        Output &newOutput = outputs.back();
        newOutput.amount = pAmount;

        // Push the provided public key onto the stack
        pPublicKey.writePublic(&newOutput.script, true);

        // Pop the signature from the signature script and verify it against the transaction data
        newOutput.script.writeByte(OP_CHECKSIG);
        newOutput.script.compact();

        return true;
    }

    bool Transaction::authorizeP2SHInput(Output &pOutput, unsigned int pInputOffset, NextCash::Buffer &pRedeemScript)
    {
        NextCash::HashList outputHashes;
        pOutput.script.setReadOffset(0);
        if(ScriptInterpreter::parseOutputScript(pOutput.script, outputHashes) != ScriptInterpreter::P2SH)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Output script is not P2SH");
            return false;
        }

        // Check redeem script hash
        NextCash::Digest scriptDigest(NextCash::Digest::SHA256_RIPEMD160);
        pRedeemScript.setReadOffset(0);
        scriptDigest.writeStream(&pRedeemScript, pRedeemScript.length());
        NextCash::Hash scriptHash;
        scriptDigest.getResult(&scriptHash);
        if(outputHashes.size() != 1 || scriptHash != outputHashes.front())
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Non matching script hash");
            return false;
        }

        if(inputs.size() <= pInputOffset)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Invalid input offset");
            return false;
        }
        Input &thisInput = inputs[pInputOffset];
        thisInput.script.clear();

        // Push the redeem script onto the stack
        ScriptInterpreter::writePushDataSize(pRedeemScript.length(), &thisInput.script);
        pRedeemScript.setReadOffset(0);
        thisInput.script.writeStream(&pRedeemScript, pRedeemScript.length());
        thisInput.script.compact();
        return true;
    }

    bool Transaction::addP2SHOutput(const NextCash::Hash &pScriptHash, uint64_t pAmount)
    {
        outputs.emplace_back();
        Output &newOutput = outputs.back();
        newOutput.amount = pAmount;

        // Pop the public key from the signature script, hash it, and push the hash onto the stack
        newOutput.script.writeByte(OP_HASH160);

        // Push the provided script hash onto the stack
        ScriptInterpreter::writePushDataSize(pScriptHash.size(), &newOutput.script);
        pScriptHash.write(&newOutput.script);

        // Pop the hash from the previous step and the redeem script from the signature script
        //   from the stack and check that they match
        newOutput.script.writeByte(OP_EQUAL);
        newOutput.script.compact();

        return true;
    }

    bool Transaction::addMultiSigInputSignature(Output &pOutput, unsigned int pInputOffset,
      const Key &pPrivateKey, const Key &pPublicKey, Signature::HashType pHashType,
      const Forks &pForks, bool &pSignatureAdded, bool &pTransactionComplete)
    {
        pSignatureAdded = false;
        pTransactionComplete = false;

        if(pInputOffset >= inputs.size())
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "MultiSig input offset too high");
            return false;
        }

        // Parse output script
        uint8_t opCode;
        unsigned int requiredSignatures;

        pOutput.script.setReadOffset(0);

        // Parse required signature count
        opCode = pOutput.script.readByte();
        if(!ScriptInterpreter::isSmallInteger(opCode))
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "MultiSig doesn't start with a small integer");
            return false;
        }

        requiredSignatures = ScriptInterpreter::smallIntegerValue(opCode);
        if(requiredSignatures == 0)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "MultiSig has zero required signatures");
            return false;
        }

        // Parse public keys
        NextCash::Buffer data;
        Key *publicKey;
        std::vector<Key *> publicKeys;
        bool success = true;
        while(success)
        {
            opCode = pOutput.script.readByte();
            if(ScriptInterpreter::isSmallInteger(opCode))
            {
                // After public keys the next value must be the count of the public keys
                unsigned int scriptKeyCount = ScriptInterpreter::smallIntegerValue(opCode);

                // At least one public key is provided and the count matches the count specified
                if(scriptKeyCount == 0 || scriptKeyCount != publicKeys.size())
                {
                    NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "MultiSig has invalid public key count");
                    success = false;
                    break;
                }

                // Script must end with OP_CHECKMULTISIG
                if(pOutput.script.readByte() != OP_CHECKMULTISIG && pOutput.script.remaining() == 0)
                {
                    NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "MultiSig doesn't end with OP_CHECKMULTISIG");
                    success = false;
                }
                break;
            }
            else
            {
                // Public keys
                if(ScriptInterpreter::pullData(opCode, pOutput.script, data) &&
                  (data.length() >= 33 && data.length() <= 65)) // Valid size for public key
                {
                    publicKey = new Key();
                    if(publicKey->readPublic(&data))
                        publicKeys.push_back(publicKey);
                    else
                    {
                        delete publicKey;
                        NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                          "MultiSig failed to read public key");
                        success = false;
                        break;
                    }
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "MultiSig public key with invalid length : %d", data.length());
                    success = false;
                    break;
                }
            }
        }

        if(!success)
        {
            for(std::vector<Key *>::iterator key=publicKeys.begin();key!=publicKeys.end();++key)
                delete *key;
            return false;
        }

        // Parse current input script
        Input &input = inputs[pInputOffset];
        std::vector<Signature *> signatures;
        Signature *signature = NULL;

        input.script.setReadOffset(0);

        // Parse dummy small int (OP_CHECKMULTISIG bug)
        opCode = input.script.readByte();
        if(!ScriptInterpreter::isSmallInteger(opCode))
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "MultiSig doesn't start with a small integer");
            success = false;
        }

        // Parse already existing signatures
        while(success && input.script.remaining())
        {
            if(ScriptInterpreter::pullData(input.script.readByte(), input.script, data) &&
              (data.length() >= 9 && data.length() <= 73)) // Valid size for signature
            {
                signature = new Signature();
                if(!signature->read(&data, data.length(), pForks.enabledVersion() >= 3))
                {
                    delete signature;
                    signature = NULL;
                    NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "MultiSig failed to read signature");
                    success = false;
                    break;
                }
                signatures.push_back(signature);
                signature = NULL;
            }
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "MultiSig public key with invalid length : %d", data.length());
                success = false;
                break;
            }
        }

        std::vector<Signature *> verifiedSignatures;

        if(success)
        {
            // Check signatures against public keys to find  where the new signature belongs
            std::vector<Key *>::iterator publicKeyIter = publicKeys.begin();
            std::vector<Signature *>::iterator signatureIter = signatures.begin();
            bool signatureVerified;
            bool publicKeyFound = false;
            int signatureOffset = 0;
            NextCash::Hash signatureHash;

            while(publicKeyIter!=publicKeys.end())
            {
                signatureVerified = false;
                while(publicKeyIter != publicKeys.end())
                {
                    if(signatureIter != signatures.end() &&
                      ScriptInterpreter::checkSignature(*this, pInputOffset, pOutput.amount, **publicKeyIter,
                        **signatureIter, pOutput.script, 0, pForks))
                    {
                        if(**publicKeyIter == pPublicKey)
                        {
                            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME, "Public key already signed");
                            publicKeyFound = true;
                        }

                        // Put signature in ordered list
                        verifiedSignatures.push_back(*signatureIter);
                        ++signatureIter;
                        ++signatureOffset;
                        ++publicKeyIter;
                        signatureVerified = true;
                        break;
                    }
                    else if(!publicKeyFound && **publicKeyIter == pPublicKey)
                    {
                        // Match found
                        signature = new Signature();

                        // Create new signature
                        // Get signature hash
                        pOutput.script.setReadOffset(0);
                        if(!getSignatureHash(signatureHash, pInputOffset, pOutput.script, pOutput.amount, pHashType))
                        {
                            success = false;
                            signatureVerified = true; // To avoid signature verfied message below
                            break;
                        }

                        // Sign Hash
                        if(!pPrivateKey.sign(signatureHash, *signature))
                        {
                            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to sign signature hash");
                            success = false;
                            signatureVerified = true; // To avoid signature verfied message below
                            break;
                        }
                        else
                        {
                            signature->setHashType(pHashType);
                            verifiedSignatures.push_back(signature);
                            pSignatureAdded = true;
                            signatureVerified = true;
                            ++publicKeyIter;
                        }
                        break;
                    }

                    // Check signature against next public key
                    ++publicKeyIter;
                }

                if(!signatureVerified)
                {
                    if(signatureIter != signatures.end())
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                          "MultiSig signature %d didn't verify : %s", signatureOffset, (*signatureIter)->hex().text());
                    else
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                          "MultiSig public key not found in output script : %s", pPublicKey.hash().hex().text());
                    success = false;
                    break;
                }

                // Break when signature is added and there are no more signatures to check
                if((pSignatureAdded || publicKeyFound) && signatureIter == signatures.end())
                    break;
            }

            if(success && verifiedSignatures.size() >= requiredSignatures)
                pTransactionComplete = true;
        }

        if(success)
        {
            // Rewrite input script
            input.script.clear();
            input.script.writeByte(OP_0); // Dummy small int (OP_CHECKMULTISIG bug)

            for(std::vector<Signature *>::iterator verifiedSig=verifiedSignatures.begin();verifiedSig!=verifiedSignatures.end();++verifiedSig)
                (*verifiedSig)->write(&input.script, true);
        }

        if(signature != NULL)
            delete signature;
        for(std::vector<Key *>::iterator key=publicKeys.begin();key!=publicKeys.end();++key)
            delete *key;
        for(std::vector<Signature *>::iterator sig=signatures.begin();sig!=signatures.end();++sig)
            delete *sig;

        return success;
    }

    bool Transaction::addMultiSigOutput(unsigned int pRequiredSignatureCount, std::vector<Key *> pPublicKeys,
      uint64_t pAmount)
    {
        outputs.emplace_back();
        Output &newOutput = outputs.back();
        newOutput.amount = pAmount;

        if(pPublicKeys.size() == 0 || pRequiredSignatureCount == 0)
            return false;

        // Required signatures count
        ScriptInterpreter::writeSmallInteger(pRequiredSignatureCount, newOutput.script);

        // Public keys
        for(std::vector<Key *>::iterator key=pPublicKeys.begin();key!=pPublicKeys.end();++key)
            (*key)->writePublic(&newOutput.script, true);

        // Public key count
        ScriptInterpreter::writeSmallInteger(pPublicKeys.size(), newOutput.script);

        newOutput.script.writeByte(OP_CHECKMULTISIG);
        newOutput.script.compact();

        return true;
    }

    Transaction *Transaction::createCoinbaseTransaction(int pBlockHeight, int64_t pFees,
      const NextCash::Hash &pPublicKeyHash)
    {
        Transaction *result = new Transaction();
        result->addCoinbaseInput(pBlockHeight);
        result->addP2PKHOutput(pPublicKeyHash, coinBaseAmount(pBlockHeight) + pFees);
        result->lockTime = 0;
        result->calculateHash();
        return result;
    }

    bool Transaction::updateOutputs(TransactionOutputPool &pOutputs, const std::vector<Transaction *> &pBlockTransactions,
      uint64_t pBlockHeight, std::vector<unsigned int> &pSpentAges)
    {
        if(inputs.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Zero inputs");
            return false;
        }

        if(outputs.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Zero outputs");
            return false;
        }

        // Process Inputs
        TransactionReference *reference;
        unsigned int index = 0;
        for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            if(input->outpoint.index != 0xffffffff)
            {
                // Find unspent transaction for input
                reference = pOutputs.findUnspent(input->outpoint.transactionID, input->outpoint.index);

                if(reference == NULL)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d outpoint transaction not found : trans %s index %d", index + 1,
                      input->outpoint.transactionID.hex().text(), input->outpoint.index);
                    return false;
                }

                pSpentAges.push_back(pBlockHeight - reference->blockHeight);

                pOutputs.spend(reference, input->outpoint.index, pBlockHeight);
            }

            ++index;
        }

        return true;
    }

    uint8_t Transaction::checkOutpoints(TransactionOutputPool &pOutputs, TransactionList &pMemPoolTransactions)
    {
        TransactionReference *reference;
        OutputReference *outputReference;
        Transaction *outpointTransaction;
        unsigned int index = 0;
        bool outpointsFound = true;
        for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            // Find unspent transaction for input
            reference = pOutputs.findUnspent(input->outpoint.transactionID, input->outpoint.index);
            if(reference != NULL)
                outputReference = reference->outputAt(input->outpoint.index);
            if(reference == NULL || outputReference == NULL || outputReference->blockFileOffset == 0)
            {
                // Search mempool
                outpointTransaction = pMemPoolTransactions.getSorted(input->outpoint.transactionID);
                if(outpointTransaction != NULL)
                {
                    if(outpointTransaction->outputs.size() <= input->outpoint.index)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d outpoint index too high : index %d trans %s", index,
                          input->outpoint.index, input->outpoint.transactionID.hex().text());
                        return mStatus;
                    }

                    if(input->outpoint.output == NULL)
                        input->outpoint.output = new Output();
                    *input->outpoint.output = outpointTransaction->outputs[input->outpoint.index];
                }
                else
                {
                    if(input->outpoint.output != NULL)
                    {
                        delete input->outpoint.output;
                        input->outpoint.output = NULL;
                    }
                    input->outpoint.signatureStatus = 0;
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d outpoint not found : index %d trans %s", index,
                      input->outpoint.index, input->outpoint.transactionID.hex().text());
                    outpointsFound = false;
                    continue;
                }
            }
            else
            {
                if(input->outpoint.output == NULL)
                    input->outpoint.output = new Output();
                if(!BlockFile::readOutput(reference->blockHeight, outputReference,
                  input->outpoint.index, *input->outpoint.output))
                {
                    //TODO This should be a system failure, not an invalid transaction
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d outpoint transaction failed to read : index %d trans %s", index,
                      input->outpoint.index, input->outpoint.transactionID.hex().text());
                    reference->print(NextCash::Log::WARNING);
                    if(input->outpoint.output != NULL)
                    {
                        delete input->outpoint.output;
                        input->outpoint.output = NULL;
                    }
                    input->outpoint.signatureStatus = 0;
                    outpointsFound = false;
                    return mStatus;
                }
            }
            ++index;
        }

        if(!outpointsFound) // Turn off outpoints found and sigs verified flags
            mStatus &= ~(OUTPOINTS_FOUND | SIGS_VERIFIED);

        return mStatus;
    }

    bool Transaction::check(TransactionOutputPool &pOutputs, TransactionList &pMemPoolTransactions,
      NextCash::HashList &pOutpointsNeeded, int32_t pBlockVersion, BlockStats &pBlockStats, Forks &pForks)
    {
        pOutpointsNeeded.clear();
        mStatus = IS_VALID | IS_STANDARD | WAS_CHECKED;
        mFee = 0;

        if(size() > 100000)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Transaction over standard size of 100000 : trans %s", hash.hex().text());
            if(mStatus & IS_STANDARD)
                mStatus ^= IS_STANDARD;
        }

        if(inputs.size() == 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Zero inputs : trans %s", hash.hex().text());
            mStatus ^= IS_VALID;
            return true;
        }

        if(outputs.size() == 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Zero outputs : trans %s", hash.hex().text());
            mStatus ^= IS_VALID;
            return true;
        }

        // Check inputs
        unsigned int index = 0;
        for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            if(input->outpoint.index == 0xffffffff)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d has no outpoint transaction : trans %s", index, hash.hex().text());
                mStatus ^= IS_VALID;
                return true; // Coinbase transactions not allowed in mempool
            }

            if(input->script.length() > 1650)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d script over standard size of 1650 : trans %s", index, hash.hex().text());
                if(mStatus & IS_STANDARD)
                    mStatus ^= IS_STANDARD;
            }

            // Input script only contains data pushes, including hard coded value pushes
            input->script.setReadOffset(0);
            if(!ScriptInterpreter::isPushOnly(input->script))
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d script is not push only : trans %s", index, hash.hex().text());
                if(mStatus & IS_STANDARD)
                    mStatus ^= IS_STANDARD;
            }
            ++index;
        }

        // Check Outputs
        index = 0;
        ScriptInterpreter::ScriptType scriptType;
        NextCash::HashList hashes;
        for(std::vector<Output>::iterator output=outputs.begin();output!=outputs.end();++output)
        {
            if(output->amount < 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Output %d amount is less than zero (%d) : trans %s", index, output->amount, hash.hex().text());
                output->print(pForks, NextCash::Log::VERBOSE);
                print(pForks, NextCash::Log::VERBOSE);
                mStatus ^= IS_VALID;
                return true;
            }

            // Output script matches allowed patterns
            scriptType = ScriptInterpreter::parseOutputScript(output->script, hashes);
            if(scriptType == ScriptInterpreter::NON_STANDARD)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Output %d is non standard : trans %s", index, hash.hex().text());
                print(pForks, NextCash::Log::VERBOSE);
                if(mStatus & IS_STANDARD)
                    mStatus ^= IS_STANDARD;
            }
            //TODO Find out why NULL DATA transactions are allowed and what to do with them
            // else if(scriptType == ScriptInterpreter::NULL_DATA)
            // {
                // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  // "Output %d is null data", index);
                // print(pForks, NextCash::Log::VERBOSE);
                // isStandard = false;
            // }
            else if(scriptType == ScriptInterpreter::INVALID)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Output %d is invalid : trans %s", index, hash.hex().text());
                print(pForks, NextCash::Log::VERBOSE);
                mStatus ^= IS_VALID;
                return true;
            }

            mFee -= output->amount;
            ++index;
        }

        if(!(mStatus & IS_STANDARD))
            return true; // Only standard transactions currently supported so don't check signatures

        // Find outpoints and check signatures
        ScriptInterpreter interpreter;
        TransactionReference *reference = NULL;
        OutputReference *outputReference = NULL;
        Transaction *outpointTransaction;
        bool sigsVerified = true;
        index = 0;
        for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            if(input->outpoint.output == NULL)
            {
                input->outpoint.signatureStatus = 0;

                // Find unspent transaction for input
                reference = pOutputs.find(input->outpoint.transactionID, input->outpoint.index);
                if(reference != NULL)
                    outputReference = reference->outputAt(input->outpoint.index);
                if(outputReference != NULL && outputReference->spentBlockHeight != 0)
                {
                    // Already spent
                    mStatus |= OUTPOINTS_SPENT;
                    mStatus ^= IS_VALID;
                    return true;
                }
                if(reference == NULL || outputReference == NULL || outputReference->blockFileOffset == 0)
                {
                    // Search mempool
                    outpointTransaction = pMemPoolTransactions.getSorted(input->outpoint.transactionID);
                    if(outpointTransaction != NULL)
                    {
                        if(outpointTransaction->outputs.size() <= input->outpoint.index)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                              "Input %d outpoint index too high : index %d trans %s", index,
                              input->outpoint.index, input->outpoint.transactionID.hex().text());
                            mStatus ^= IS_VALID;
                            return true;
                        }

                        if(input->outpoint.output == NULL)
                            input->outpoint.output = new Output();
                        *input->outpoint.output = outpointTransaction->outputs[input->outpoint.index];
                    }
                    else
                    {
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d outpoint not found : index %d trans %s", index,
                          input->outpoint.index, input->outpoint.transactionID.hex().text());
                        pOutpointsNeeded.push_back(input->outpoint.transactionID);
                        continue;
                    }
                }
                else
                {
                    if(input->outpoint.output == NULL)
                        input->outpoint.output = new Output();
                    if(!BlockFile::readOutput(reference->blockHeight, outputReference,
                      input->outpoint.index, *input->outpoint.output))
                    {
                        delete input->outpoint.output;
                        input->outpoint.output = NULL;

                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d outpoint transaction failed to read : index %d trans %s", index,
                          input->outpoint.index, input->outpoint.transactionID.hex().text());
                        reference->print(NextCash::Log::VERBOSE);
                        return false;
                    }
                }
            }

            interpreter.clear();
            interpreter.initialize(this, index, input->sequence, input->outpoint.output->amount);

            input->outpoint.signatureStatus = Outpoint::CHECKED;

            // Process signature script
            input->script.setReadOffset(0);
            if(!interpreter.process(input->script, pBlockVersion, pForks))
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d signature script is invalid : trans %s", index, hash.hex().text());
                input->print(pForks, NextCash::Log::VERBOSE);
                mStatus ^= IS_VALID;
                return true;
            }

            // Check outpoint script
            input->outpoint.output->script.setReadOffset(0);
            if(!interpreter.process(input->outpoint.output->script, pBlockVersion, pForks) ||
              !interpreter.isValid())
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d outpoint script is not valid : trans %s", index, hash.hex().text());
                input->print(pForks, NextCash::Log::VERBOSE);
                if(reference != NULL)
                {
                    NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "UTXO :");
                    reference->print(NextCash::Log::VERBOSE);
                }
                input->outpoint.output->print(pForks, NextCash::Log::VERBOSE);
                mStatus ^= IS_VALID;
                return true;
            }
            else if(!interpreter.isVerified())
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d script did not verify : trans %s", index, hash.hex().text());
                input->print(pForks, NextCash::Log::VERBOSE);
                interpreter.printStack("After fail verify");
                if(reference != NULL)
                {
                    NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "UTXO :");
                    reference->print(NextCash::Log::VERBOSE);
                }
                input->outpoint.output->print(pForks, NextCash::Log::VERBOSE);
                sigsVerified = false;
            }
            else
                input->outpoint.signatureStatus |= Outpoint::VERIFIED;

            mFee += input->outpoint.output->amount;
            ++index;
        }

        if(pOutpointsNeeded.size() == 0)
        {
            if(mFee < 0)
            {
                NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Outputs amounts are more than inputs amounts");
                print(pForks, NextCash::Log::VERBOSE);
                mStatus ^= IS_VALID;
                return true;
            }
            if((mStatus & IS_VALID) && sigsVerified)
                mStatus |= SIGS_VERIFIED;
            mStatus |= OUTPOINTS_FOUND;
        }

        if(pOutpointsNeeded.size() == 0)
            clearCache();
        return true;
    }

    bool Transaction::process(TransactionOutputPool &pOutputs, const std::vector<Transaction *> &pBlockTransactions,
      unsigned int pBlockHeight, bool pCoinBase, int32_t pBlockVersion, BlockStats &pBlockStats,
      Forks &pForks, std::vector<unsigned int> &pSpentAges)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Transaction Process");
        NextCash::Profiler verifyProfiler("Transaction Inputs", false);
#endif
        mFee = 0;

        if(inputs.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME, "Zero inputs");
            return false;
        }
        else if(pCoinBase && inputs.size() != 1)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
              "Coinbase has more than one input : %d", inputs.size());
            return false;
        }

        if(outputs.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME, "Zero outputs");
            return false;
        }

        // Process Inputs
        ScriptInterpreter interpreter;
        TransactionReference *reference;
        OutputReference *outputReference = NULL;
        Output output;
        unsigned int index = 0;
        bool sequenceFound = false;
        for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            if(pCoinBase)
            {
                if(input->outpoint.index != 0xffffffff)
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Coinbase Input %d outpoint index is not 0xffffffff : %08x", index, input->outpoint.index);
                    return false;
                }

                // BIP-0034
                if(pBlockVersion >= 2 && pForks.enabledVersion() >= 2)
                {
                    // Read block height
                    int64_t blockHeight = 0;
                    input->script.setReadOffset(0);
                    if(!ScriptInterpreter::readArithmeticInteger(input->script, blockHeight))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Coinbase input doesn't start with data push");
                        return false;
                    }

                    if(blockHeight < 0 || (uint64_t)blockHeight != pBlockHeight)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Non matching coinbase block height : actual %d, coinbase %d",
                          pBlockHeight, blockHeight);
                        return false;
                    }
                }
            }
            else
            {
                // NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME,
                  // "Processing input %d", index);

                // Find unspent transaction for input
                reference = pOutputs.findUnspent(input->outpoint.transactionID, input->outpoint.index);
                if(reference == NULL)
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d outpoint not found : index %d trans %s", index,
                      input->outpoint.index, input->outpoint.transactionID.hex().text());
                    return false;
                }
                else
                    outputReference = reference->outputAt(input->outpoint.index);

                if(outputReference == NULL)
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d outpoint output index not found : index %d trans %s", index,
                      input->outpoint.index, input->outpoint.transactionID.hex().text());
                    return false;
                }

                pSpentAges.push_back(pBlockHeight - reference->blockHeight);

                if(reference->blockHeight == pBlockHeight)
                {
                    // Get output from this block since it hasn't been written to a block file yet
                    bool found = false;
                    for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
                        if(*transaction == this)
                            break; // Only use transactions before this one
                        else if((*transaction)->hash == input->outpoint.transactionID)
                        {
                            found = true;
                            output = (*transaction)->outputs.at(input->outpoint.index);
                            break;
                        }

                    if(!found)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d outpoint transaction not found in current block : index %d trans %s", index,
                          input->outpoint.index, input->outpoint.transactionID.hex().text());
                        reference->print(NextCash::Log::WARNING);
                        return false;
                    }
                }
                else if(!BlockFile::readOutput(reference->blockHeight, outputReference, input->outpoint.index, output))
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d outpoint transaction failed to read : index %d trans %s", index,
                      input->outpoint.index, input->outpoint.transactionID.hex().text());
                    reference->print(NextCash::Log::WARNING);
                    return false;
                }

#ifdef PROFILER_ON
                verifyProfiler.start();
#endif
                // BIP-0068 Relative time lock sequence
                if(version >= 2 && !input->sequenceDisabled() &&
                  pForks.softForkState(SoftFork::BIP0068) == SoftFork::ACTIVE)
                {
                    // Sequence is an encoded relative time lock
                    int32_t lock = input->sequence & Input::SEQUENCE_LOCKTIME_MASK;
                    if(input->sequence & Input::SEQUENCE_TYPE)
                    {
                        // Seconds since outpoint median past time in units of 512 seconds granularity
                        lock <<= 9;
                        int32_t currentBlockMedianTime = pBlockStats.getMedianPastTime(pBlockHeight, 11);
                        int32_t spentBlockMedianTime = pBlockStats.getMedianPastTime(reference->blockHeight, 11);
                        if(currentBlockMedianTime < spentBlockMedianTime + lock)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                              "Input %d sequence not valid. Required spent block time age %d, actual %d : index %d trans %s",
                              index, lock, currentBlockMedianTime - spentBlockMedianTime,
                              input->outpoint.index, input->outpoint.transactionID.hex().text());
                            NextCash::String timeText;
                            timeText.writeFormattedTime(spentBlockMedianTime + lock);
                            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                              "Not valid until median block time %s", timeText.text());
                            reference->print(NextCash::Log::WARNING);
#ifdef PROFILER_ON
                            verifyProfiler.stop();
#endif
                            return false;
                        }
                    }
                    else if(pBlockHeight < reference->blockHeight + lock) // Number of blocks since outpoint
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d sequence not valid. Required block height age %d. actual %d : index %d trans %s",
                          index, lock, pBlockHeight - reference->blockHeight,
                          input->outpoint.index, input->outpoint.transactionID.hex().text());
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Not valid until block %d", reference->blockHeight + lock);
                        reference->print(NextCash::Log::WARNING);
#ifdef PROFILER_ON
                        verifyProfiler.stop();
#endif
                        return false;
                    }
                }

                if(input->sequence != 0xffffffff)
                    sequenceFound = true;

                pOutputs.spend(reference, input->outpoint.index, pBlockHeight);
                // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  // "Transaction %s Input %d spent transaction output %s index %d", hash.hex().text(), index + 1,
                  // input->outpoint.transactionID.hex().text(), input->outpoint.index);

                interpreter.clear();
                interpreter.initialize(this, index, input->sequence, output.amount);

                // Process signature script
                //NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME, "Input %d script : ", index);
                //input->script.setReadOffset(0);
                //ScriptInterpreter::printScript(input->script, NextCash::Log::DEBUG);
                input->script.setReadOffset(0);
                if(!interpreter.process(input->script, pBlockVersion, pForks))
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d signature script failed : ", index);
                    input->print(pForks, NextCash::Log::WARNING);
                    reference->print(NextCash::Log::WARNING);
#ifdef PROFILER_ON
                    verifyProfiler.stop();
#endif
                    return false;
                }

                // Process unspent transaction output script
                //NextCash::Log::add(NextCash::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME, "UTXO script : ");
                //output.script.setReadOffset(0);
                //ScriptInterpreter::printScript(output.script, NextCash::Log::DEBUG);
                output.script.setReadOffset(0);
                if(!interpreter.process(output.script, pBlockVersion, pForks))
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d unspent transaction output script failed : ", index);
                    input->print(pForks, NextCash::Log::WARNING);
                    NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME, "UTXO :");
                    reference->print(NextCash::Log::WARNING);
                    output.print(pForks, NextCash::Log::WARNING);
#ifdef PROFILER_ON
                    verifyProfiler.stop();
#endif
                    return false;
                }

                if(!interpreter.isValid())
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d script is not valid : ", index);
                    input->print(pForks, NextCash::Log::WARNING);
                    interpreter.printStack("After fail validate");
                    NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME, "UTXO :");
                    reference->print(NextCash::Log::WARNING);
                    output.print(pForks, NextCash::Log::WARNING);
#ifdef PROFILER_ON
                    verifyProfiler.stop();
#endif
                    return false;
                }

                if(!interpreter.isVerified())
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d script did not verify : ", index);
                    input->print(pForks, NextCash::Log::WARNING);
                    interpreter.printStack("After fail verify");
                    NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME, "UTXO :");
                    reference->print(NextCash::Log::WARNING);
                    output.print(pForks, NextCash::Log::WARNING);
#ifdef PROFILER_ON
                    verifyProfiler.stop();
#endif
                    return false;
                }

                mFee += output.amount;
            }

#ifdef PROFILER_ON
            verifyProfiler.stop();
#endif
            ++index;
        }

        if(!pCoinBase && sequenceFound)
        {
            if(lockTime > LOCKTIME_THRESHOLD)
            {
                // Lock time is a timestamp
                if(pForks.softForkState(SoftFork::BIP0113) == SoftFork::ACTIVE)
                {
                    if((int32_t)lockTime > pBlockStats.getMedianPastTime(pBlockHeight, 11))
                    {
                        NextCash::String lockTimeText, blockTimeText;
                        lockTimeText.writeFormattedTime(lockTime);
                        blockTimeText.writeFormattedTime(pBlockStats.getMedianPastTime(pBlockHeight, 11));
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Lock time stamp is not valid. Lock time %s > block median time %s",
                          lockTimeText.text(), blockTimeText.text());
                        print(pForks, NextCash::Log::VERBOSE);
                        return false;
                    }
                }
                else
                {
                    // Add 600 to fake having a "peer time offset" for older blocks
                    //   Block 357903 transaction 98 has a lock time about 3 minutes after the block time
                    if((int32_t)lockTime > pBlockStats.time(pBlockHeight) + 600)
                    {
                        NextCash::String lockTimeText, blockTimeText;
                        lockTimeText.writeFormattedTime(lockTime);
                        blockTimeText.writeFormattedTime(pBlockStats.time(pBlockHeight));
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Lock time stamp is not valid. Lock time %s > block time %s",
                          lockTimeText.text(), blockTimeText.text());
                        print(pForks, NextCash::Log::VERBOSE);
                        return false;
                    }
                }
            }
            else
            {
                // Lock time is a block height
                if(lockTime > pBlockHeight)
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Lock time block height is not valid. Lock height %d > block height %d",
                      lockTime, pBlockHeight);
                    print(pForks, NextCash::Log::VERBOSE);
                    return false;
                }
            }
        }

#ifdef PROFILER_ON
        NextCash::Profiler outputsProfiler("Transaction Outputs");
#endif
        // Process Outputs
        index = 0;
        for(std::vector<Output>::iterator output=outputs.begin();output!=outputs.end();++output)
        {
            if(output->amount < 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                  "Output %d amount is negative %d : ", index + 1, output->amount);
                output->print(pForks, NextCash::Log::WARNING);
                print(pForks, NextCash::Log::VERBOSE);
                return false;
            }

            if(!pCoinBase && output->amount > 0 && output->amount > mFee)
            {
                NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Outputs are more than inputs");
                print(pForks, NextCash::Log::VERBOSE);
                return false;
            }

            mFee -= output->amount;
            ++index;
        }

        clearCache();
        return true;
    }

    NextCash::stream_size Transaction::calculatedSize()
    {
        unsigned int result = 4; // Version

        // Input Count
        result += compactIntegerSize(inputs.size());

        // Inputs
        for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
            result += input->size();

        // Output Count
        result += compactIntegerSize(outputs.size());

        // Outputs
        for(std::vector<Output>::iterator output=outputs.begin();output!=outputs.end();++output)
            result += output->size();

        // Lock Time
        result += 4;

        return 4;
    }

    uint64_t Transaction::feeRate()
    {
        uint64_t currentSize = mSize;
        if(currentSize == 0)
            currentSize = calculatedSize();
        if(mFee == 0)
            return 0;
        return (mFee * 1000) / currentSize; // Satoshis per KB
    }

    void Outpoint::write(NextCash::OutputStream *pStream)
    {
        transactionID.write(pStream);
        pStream->writeUnsignedInt(index);
    }

    bool Outpoint::read(NextCash::InputStream *pStream)
    {
        if(!transactionID.read(pStream))
            return false;

        if(pStream->remaining() < 4)
            return false;
        index = pStream->readUnsignedInt();
        return true;
    }

    bool Outpoint::skip(NextCash::InputStream *pInputStream, NextCash::OutputStream *pOutputStream)
    {
        if(pInputStream->remaining() < 36)
            return false;
        if(pOutputStream == NULL)
            pInputStream->setReadOffset(pInputStream->readOffset() + 36);
        else
            pInputStream->readStream(pOutputStream, 36);
        return true;
    }

    void Input::write(NextCash::OutputStream *pStream)
    {
        outpoint.write(pStream);
        writeCompactInteger(pStream, script.length());
        script.setReadOffset(0);
        pStream->writeStream(&script, script.length());
        pStream->writeUnsignedInt(sequence);
    }

    bool Input::read(NextCash::InputStream *pStream)
    {
        // Outpoint
        if(!outpoint.read(pStream))
            return false;

        // Script
        uint64_t bytes = readCompactInteger(pStream);
        if(pStream->remaining() < bytes)
            return false;
        script.clear();
        script.setSize(bytes);
        script.writeStreamCompact(*pStream, bytes);

        // Sequence
        if(pStream->remaining() < 4)
            return false;
        sequence = pStream->readUnsignedInt();

        return true;
    }

    bool Input::skip(NextCash::InputStream *pInputStream, NextCash::OutputStream *pOutputStream)
    {
        // Outpoint
        if(!Outpoint::skip(pInputStream, pOutputStream))
            return false;

        // Script
        uint64_t bytes = readCompactInteger(pInputStream);
        if(pOutputStream != NULL)
            writeCompactInteger(pOutputStream, bytes);
        if(pInputStream->remaining() < bytes)
            return false;
        if(pOutputStream == NULL)
            pInputStream->setReadOffset(pInputStream->readOffset() + bytes);
        else
            pInputStream->readStream(pOutputStream, bytes);

        // Sequence
        if(pInputStream->remaining() < 4)
            return false;
        if(pOutputStream == NULL)
            pInputStream->setReadOffset(pInputStream->readOffset() + 4);
        else
            pOutputStream->writeUnsignedInt(pInputStream->readUnsignedInt());

        return true;
    }

    void Transaction::write(NextCash::OutputStream *pStream, bool pBlockFile)
    {
        NextCash::stream_size startOffset = pStream->writeOffset();
        mSize = 0;

        // Version
        pStream->writeUnsignedInt(version);

        // Input Count
        writeCompactInteger(pStream, inputs.size());

        // Inputs
        for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
            input->write(pStream);

        // Output Count
        writeCompactInteger(pStream, outputs.size());

        // Outputs
        for(std::vector<Output>::iterator output=outputs.begin();output!=outputs.end();++output)
            output->write(pStream, pBlockFile);

        // Lock Time
        pStream->writeUnsignedInt(lockTime);

        mSize = pStream->writeOffset() - startOffset;
    }

    bool Input::writeSignatureData(NextCash::OutputStream *pStream, NextCash::Buffer *pSubScript, bool pZeroSequence)
    {
        outpoint.write(pStream);
        if(pSubScript == NULL)
            writeCompactInteger(pStream, 0);
        else
        {
            writeCompactInteger(pStream, pSubScript->length());
            pSubScript->setReadOffset(0);
            pStream->writeStream(pSubScript, pSubScript->length());
        }

        if(pZeroSequence)
            pStream->writeUnsignedInt(0);
        else
            pStream->writeUnsignedInt(sequence);
        return true;
    }

    bool Transaction::writeSignatureData(NextCash::OutputStream *pStream, unsigned int pInputOffset,
      NextCash::Buffer &pOutputScript, int64_t pOutputAmount, Signature::HashType pHashType)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Transaction Sign Data");
#endif
        Signature::HashType hashType = pHashType;
        // Extract FORKID (0x40) flag from hash type
        bool forkID = hashType & Signature::FORKID;
        if(forkID)
            hashType = static_cast<Signature::HashType >(hashType ^ Signature::FORKID);
        // Extract ANYONECANPAY (0x80) flag from hash type
        bool anyoneCanPay = hashType & Signature::ANYONECANPAY;
        if(anyoneCanPay)
            hashType = static_cast<Signature::HashType >(hashType ^ Signature::ANYONECANPAY);

        if(forkID)
        {
            // BIP-0143 Signature Hash Algorithm
            NextCash::Hash hash(32);
            NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
            digest.setOutputEndian(NextCash::Endian::LITTLE);

            // Version
            pStream->writeUnsignedInt(version);

            // Hash Prev Outs
            if(anyoneCanPay)
                hash.zeroize();
            else
            {
                if(!mOutpointHash.isEmpty())
                    hash = mOutpointHash;
                else
                {
                    // All input outpoints
                    digest.initialize();
                    for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
                        input->outpoint.write(&digest);
                    digest.getResult(&hash);
                    mOutpointHash = hash; // Save for next input
                }
            }
            hash.write(pStream);

            // Hash Sequence
            if(anyoneCanPay || hashType == Signature::SINGLE || hashType == Signature::NONE)
                hash.zeroize();
            else
            {
                if(!mSequenceHash.isEmpty())
                    hash = mSequenceHash;
                else
                {
                    // All input sequences
                    digest.initialize();
                    for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
                        digest.writeUnsignedInt(input->sequence);
                    digest.getResult(&hash);
                    mSequenceHash = hash; // Save for next input
                }
            }
            hash.write(pStream);

            // Outpoint
            if(pInputOffset < inputs.size())
                inputs[pInputOffset].outpoint.write(pStream);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                  "Failed to write transaction signature data. Input offset out of range %d/%d",
                  pInputOffset, inputs.size());
                return false;
            }

            // Script Code
            writeCompactInteger(pStream, pOutputScript.remaining());
            pStream->writeStream(&pOutputScript, pOutputScript.remaining());

            // Value of Output
            pStream->writeLong(pOutputAmount);

            // Sequence
            if(pInputOffset < inputs.size())
                pStream->writeUnsignedInt(inputs[pInputOffset].sequence);
            else
                return false;

            // Hash Outputs
            if(hashType == Signature::SINGLE)
            {
                if(pInputOffset < outputs.size())
                {
                    // Only output corresponding to this input
                    digest.initialize();
                    outputs[pInputOffset].write(&digest);
                    digest.getResult(&hash);
                }
                else
                    hash.zeroize();
            }
            else if(hashType == Signature::NONE)
                hash.zeroize();
            else
            {
                if(!mOutputHash.isEmpty())
                    hash = mOutputHash;
                else
                {
                    // All outputs
                    digest.initialize();
                    for(std::vector<Output>::iterator output=outputs.begin();output!=outputs.end();++output)
                        output->write(&digest);
                    digest.getResult(&hash);
                    mOutputHash = hash; // Save for next input
                }
            }
            hash.write(pStream);
        }
        else
        {
            // Build subscript from unspent/output script
            unsigned int offset;
            NextCash::Buffer subScript;
            ScriptInterpreter::removeCodeSeparators(pOutputScript, subScript);

            // Version
            pStream->writeUnsignedInt(version);

            switch(hashType)
            {
            default:
            case Signature::INVALID:
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Unsupported signature hash type : 0x%02x", pHashType);
            case Signature::ALL:
            {
                // Input Count
                if(anyoneCanPay)
                    writeCompactInteger(pStream, 1);
                else
                    writeCompactInteger(pStream, inputs.size());

                // Inputs
                offset = 0;
                for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
                {
                    if(pInputOffset == offset++)
                        input->writeSignatureData(pStream, &subScript, false);
                    else if(!anyoneCanPay)
                        input->writeSignatureData(pStream, NULL, false);
                }

                // Output Count
                writeCompactInteger(pStream, outputs.size());

                // Outputs
                for(std::vector<Output>::iterator output=outputs.begin();output!=outputs.end();++output)
                    output->write(pStream);

                break;
            }
            case Signature::NONE:
            {
                // Input Count
                if(anyoneCanPay)
                    writeCompactInteger(pStream, 1);
                else
                    writeCompactInteger(pStream, inputs.size());

                // Inputs
                offset = 0;
                for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
                {
                    if(pInputOffset == offset++)
                        input->writeSignatureData(pStream, &subScript, false);
                    else if(!anyoneCanPay)
                        input->writeSignatureData(pStream, NULL, true);
                }

                // Output Count
                writeCompactInteger(pStream, 0);
                break;
            }
            case Signature::SINGLE:
            {
                // Input Count
                if(anyoneCanPay)
                    writeCompactInteger(pStream, 1);
                else
                    writeCompactInteger(pStream, inputs.size());

                // Inputs
                offset = 0;
                for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
                {
                    if(pInputOffset == offset++)
                        input->writeSignatureData(pStream, &subScript, false);
                    else if(!anyoneCanPay)
                        input->writeSignatureData(pStream, NULL, true);
                }

                // Output Count (number of inputs)
                writeCompactInteger(pStream, pInputOffset + 1);

                // Outputs
                std::vector<Output>::iterator output=outputs.begin();
                for(offset=0;offset<pInputOffset+1;offset++)
                    if(output!=outputs.end())
                    {
                        if(offset == pInputOffset)
                            output->write(pStream);
                        else
                        {
                            // Write -1 amount output
                            pStream->writeLong(-1);
                            writeCompactInteger(pStream, 0);
                        }
                        ++output;
                    }
                    else
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Failed to write transaction signature data. Invalid number of outputs %d/%d",
                          pInputOffset+1, outputs.size());
                        return false;
                    }

                break;
            }
            }
        }

        // Lock Time
        pStream->writeUnsignedInt(lockTime);

        // Sig Hash Type
        pStream->writeUnsignedInt(pHashType);

        return true;
    }

    bool Transaction::getSignatureHash(NextCash::Hash &pHash, unsigned int pInputOffset,
      NextCash::Buffer &pOutputScript, int64_t pOutputAmount, Signature::HashType pHashType)
    {
        // Write appropriate data to a digest
        NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
        NextCash::stream_size previousReadOffset = pOutputScript.readOffset();
        digest.setOutputEndian(NextCash::Endian::LITTLE);
        if(writeSignatureData(&digest, pInputOffset, pOutputScript, pOutputAmount, pHashType))
        {
            digest.getResult(&pHash); // Get digest result
            pOutputScript.setReadOffset(previousReadOffset);
            return true;
        }
        else
        {
            if(pHashType & Signature::FORKID)
                pHash.zeroize();
            else
                pHash.setByte(0, 1); // Use signature hash of 1 (probably sig hash single with not enough outputs)
            pOutputScript.setReadOffset(previousReadOffset);
            return false;
        }
    }

    bool Transaction::skip(NextCash::InputStream *pStream)
    {
        // Version
        if(pStream->remaining() < 4)
            return false;
        pStream->setReadOffset(pStream->readOffset() + 4);

        // Input Count
        if(!pStream->remaining())
            return false;
        uint64_t count = readCompactInteger(pStream);

        // Inputs
        for(unsigned int i=0;i<count;++i)
            if(!Input::skip(pStream))
                return false;

        // Output Count
        if(!pStream->remaining())
            return false;
        count = readCompactInteger(pStream);

        // Outputs
        for(unsigned int i=0;i<count;++i)
            if(!Output::skip(pStream))
                return false;

        if(pStream->remaining() < 4)
            return false;

        // Lock Time
        pStream->setReadOffset(pStream->readOffset() + 4);
        return true;
    }

    bool Transaction::readOutput(NextCash::InputStream *pStream, unsigned int pOutputIndex,
      NextCash::Hash &pTransactionID, Output &pOutput, bool pBlockFile)
    {
        NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
        digest.setOutputEndian(NextCash::Endian::LITTLE);

        // Version
        if(pStream->remaining() < 5)
            return false;
        digest.writeUnsignedInt(pStream->readUnsignedInt());

        // Input Count
        uint64_t count = readCompactInteger(pStream);
        writeCompactInteger(&digest, count);

        // Inputs
        for(unsigned int i=0;i<count;++i)
            if(!Input::skip(pStream, &digest))
                return false;

        // Output Count
        if(!pStream->remaining())
            return false;
        count = readCompactInteger(pStream);
        writeCompactInteger(&digest, count);

        // Outputs
        for(unsigned int i=0;i<count;++i)
        {
            if(pOutputIndex == i)
            {
                if(!pOutput.read(pStream, pBlockFile))
                    return false;
                pOutput.write(&digest);
            }
            else if(!Output::skip(pStream, &digest))
                return false;
        }

        // Lock Time
        if(pStream->remaining() < 4)
            return false;
        digest.writeUnsignedInt(pStream->readUnsignedInt());

        digest.getResult(&pTransactionID);
        return true;
    }

    bool Transaction::read(NextCash::InputStream *pStream, bool pCalculateHash, bool pBlockFile)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Transaction Read");
#endif
        clear();

        NextCash::stream_size startOffset = pStream->readOffset();
        mSize = 0;

        // Create hash
        NextCash::Digest *digest = NULL;
        if(pCalculateHash)
        {
            digest = new NextCash::Digest(NextCash::Digest::SHA256_SHA256);
            digest->setOutputEndian(NextCash::Endian::LITTLE);
        }
        hash.clear();

        if(pStream->remaining() < 5)
        {
            if(digest != NULL)
                delete digest;
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Transaction read failed : stream remaining less than 5");
            return false;
        }

        // Version
        version = pStream->readUnsignedInt();
        if(pCalculateHash)
            digest->writeUnsignedInt(version);

        // Input Count
        uint64_t count = readCompactInteger(pStream);
        if(pCalculateHash)
            writeCompactInteger(digest, count);
        if(pStream->remaining() < count)
        {
            if(digest != NULL)
                delete digest;
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Transaction read failed : stream remaining less than input count %d", count);
            return false;
        }

        // Inputs
        inputs.reserve(count);
        for(unsigned int i=0;i<count;++i)
        {
            inputs.emplace_back();
            if(!inputs.back().read(pStream))
            {
                if(digest != NULL)
                    delete digest;
                NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Transaction read failed : input read failed");
                return false;
            }
            else if(pCalculateHash)
                inputs.back().write(digest);
        }

        // Output Count
        count = readCompactInteger(pStream);
        if(pCalculateHash)
            writeCompactInteger(digest, count);

        // Outputs
        outputs.reserve(count);
        for(unsigned int i=0;i<count;++i)
        {
            outputs.emplace_back();
            if(!outputs.back().read(pStream, pBlockFile))
            {
                if(digest != NULL)
                    delete digest;
                NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Transaction read failed : output read failed");
                return false;
            }
            else if(pCalculateHash)
                outputs.back().write(digest);
        }

        if(pStream->remaining() < 4)
        {
            if(digest != NULL)
                delete digest;
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Transaction read failed : stream remaining less than 4");
            return false;
        }

        // Lock Time
        lockTime = pStream->readUnsignedInt();
        if(pCalculateHash)
            digest->writeUnsignedInt(lockTime);

        if(pCalculateHash)
            digest->getResult(&hash);

        if(digest != NULL)
            delete digest;

        mSize = pStream->readOffset() - startOffset;
        return true;
    }

    void Transaction::calculateHash()
    {
        hash.clear();

        // Write into digest
        NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
        digest.setOutputEndian(NextCash::Endian::LITTLE);
        write(&digest);

        digest.getResult(&hash);
    }

    TransactionList::~TransactionList()
    {
        for(std::vector<Transaction *>::iterator item=begin();item!=end();++item)
            delete *item;
    }

    Transaction *TransactionList::getSorted(const NextCash::Hash &pHash)
    {
        // Search sorted
        if(size() == 0 || back()->hash < pHash)
            return NULL; // Item would be after end

        if(front()->hash > pHash)
            return NULL; // Item would be before beginning

        int compare;
        Transaction **bottom = data();
        Transaction **top    = data() + size() - 1;
        Transaction **current;

        while(true)
        {
            // Break the set in two halves
            current = bottom + ((top - bottom) / 2);
            compare = pHash.compare((*current)->hash);

            if(compare == 0) // Item found
                break;

            if(current == bottom)
            {
                if(current != top && (*top)->hash == pHash)
                {
                    current = top; // Item found
                    break;
                }

                return NULL;
            }

            // Determine which half the desired item is in
            if(compare > 0)
                bottom = current;
            else //if(compare < 0)
                top = current;
        }

        // Current is the matching item
        return *current;
    }

    bool TransactionList::insertSorted(Transaction *pTransaction)
    {
        // Insert sorted
        if(size() == 0)
        {
            // Append as last item
            push_back(pTransaction);
            return true;
        }

        int compare = back()->hash.compare(pTransaction->hash);
        if(compare == 0)
            return false; // Already last item
        else if(compare < 0)
        {
            // Append as last item
            push_back(pTransaction);
            return true;
        }

        compare = front()->hash.compare(pTransaction->hash);
        if(compare == 0)
            return false; // Already first item
        else if(compare > 0)
        {
            // Insert as first item
            insert(begin(), pTransaction);
            return true;
        }

        Transaction **bottom = data();
        Transaction **top    = data() + size() - 1;
        Transaction **current;

        while(true)
        {
            // Break the set in two halves
            current = bottom + ((top - bottom) / 2);
            compare = pTransaction->hash.compare((*current)->hash);

            if(compare == 0) // Item found
                return false;

            if(current == bottom)
            {
                if(current != top && (*top)->hash > pTransaction->hash)
                    current = top; // Insert before top
                else
                    current = top + 1; // Insert after top

                if(*current != NULL && (*current)->hash == pTransaction->hash)
                    return false;

                break;
            }

            // Determine which half the desired item is in
            if(compare > 0)
                bottom = current;
            else //if(compare < 0)
                top = current;
        }

        // Current is the item to insert before
        iterator after = begin();
        after += (current - data());
        insert(after, pTransaction);
        return true;
    }

    bool TransactionList::removeSorted(const NextCash::Hash &pHash)
    {
        // Remove sorted
        if(size() == 0 || back()->hash < pHash)
            return false; // Item would be after end

        if(front()->hash > pHash)
            return false; // Item would be before beginning

        int compare;
        Transaction **bottom = data();
        Transaction **top    = data() + size() - 1;
        Transaction **current;

        while(true)
        {
            // Break the set in two halves
            current = bottom + ((top - bottom) / 2);
            compare = pHash.compare((*current)->hash);

            if(compare == 0) // Item found
                break;

            if(current == bottom)
            {
                if(current != top && (*top)->hash == pHash)
                {
                    current = top; // Item found
                    break;
                }

                return false;
            }

            // Determine which half the desired item is in
            if(compare > 0)
                bottom = current;
            else //if(compare < 0)
                top = current;
        }

        // Current is the matching item
        std::vector<Transaction *>::iterator item = begin();
        item += (current - data());
        delete *item;
        erase(item);
        return true;
    }

    void TransactionList::clear()
    {
        for(std::vector<Transaction *>::iterator item=begin();item!=end();++item)
            delete *item;
        std::vector<Transaction *>::clear();
    }

    void TransactionList::clearNoDelete()
    {
        std::vector<Transaction *>::clear();
    }

    bool Transaction::test()
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME,
          "------------- Starting Transaction Tests -------------");

        bool success = true;
        Key privateKey1;
        Key publicKey1;
        Signature signature;
        Key privateKey2;
        Key publicKey2;
        NextCash::Buffer data;
        Forks forks;

        // Initialize private key
        data.writeHex("d68e0869df44615cc57f196208a896653e969f69960c6435f38ae47f6b6d082d");
        privateKey1.readPrivate(&data);

        // Initialize public key
        data.clear();
        data.writeHex("03077b2a0406db4b4e2cddbe9aca5e9f1a3cf039feb843992d05cc0b7a75046635");
        publicKey1.readPublic(&data);

        // Initialize private key
        data.writeHex("4fd0a873dba1d74801f182013c5ae17c17213d333657047a6e6c5865f388a60a");
        privateKey2.readPrivate(&data);

        // Initialize public key
        data.clear();
        data.writeHex("03362365326bd230642290787f3ba93d6299392ac5d26cd66e300f140184521e9c");
        publicKey2.readPublic(&data);

        // Create unspent transaction output (so we can spend it)
        Transaction spendable, transaction;

        spendable.addP2PKHOutput(publicKey1.hash(), 51000);

        spendable.calculateHash();

        /***********************************************************************************************
         * Process Valid P2PKH Transaction
         ***********************************************************************************************/
        // Create public key script to pay the third public key

        // Create Transaction to spend it
        // Add input
        transaction.addInput(spendable.hash, 0);

        // Add output
        transaction.addP2PKHOutput(publicKey2.hash(), 50000);

        // Sign the input
        transaction.signP2PKHInput(spendable.outputs[0], 0, privateKey1, publicKey1, Signature::ALL);

        transaction.calculateHash();

        NextCash::HashList checkHashes;
        if(ScriptInterpreter::parseOutputScript(spendable.outputs[0].script, checkHashes) == ScriptInterpreter::P2PKH)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed check P2PKH script");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed check P2PKH script");
            success = false;
        }

        if(checkHashes.size() != 1 || publicKey1.hash() == checkHashes.front())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed check P2PKH script hash");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed check P2PKH script hash");
            success = false;
        }

        // Process the script
        ScriptInterpreter interpreter;

        //NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0].script.setReadOffset(0);
        interpreter.initialize(&transaction, 0, transaction.inputs[0].sequence, spendable.outputs[0].amount);
        if(!interpreter.process(transaction.inputs[0].script, 4, forks))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            spendable.outputs[0].script.setReadOffset(0);
            if(!interpreter.process(spendable.outputs[0].script, 4, forks))
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process UTXO script");
                success = false;
            }
            else
            {
                if(interpreter.isValid() && interpreter.isVerified())
                    NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed process valid P2PKH transaction");
                else
                {
                    NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed process valid P2PKH transaction");
                    success = false;
                }
            }
        }

        /***********************************************************************************************
         * Process P2PKH Transaction with Bad PK
         ***********************************************************************************************/
        interpreter.clear();
        transaction.clear();

        // Add input
        transaction.addInput(spendable.hash, 0);

        // Add output
        transaction.addP2PKHOutput(publicKey2.hash(), 50000);

        // Sign the input
        if(!transaction.signP2PKHInput(spendable.outputs[0], 0, privateKey1, publicKey2, Signature::ALL))
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed P2PKH sign with wrong public key");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed P2PKH sign with wrong public key");
            success = false;
        }

        transaction.calculateHash();

        if(ScriptInterpreter::parseOutputScript(spendable.outputs[0].script, checkHashes) == ScriptInterpreter::P2PKH)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed check P2PKH script bad PK");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed check P2PKH script bad PK");
            success = false;
        }

        if(checkHashes.size() != 1 || publicKey1.hash() == checkHashes.front())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed check P2PKH script bad PK hash");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed check P2PKH script bad PK hash");
            success = false;
        }

        // transaction.inputs[0]->script.setReadOffset(0);
        // transaction.calculateHash();
        // //NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        // transaction.inputs[0]->script.setReadOffset(0);
        // interpreter.setTransaction(&transaction);
        // interpreter.setInputSequence(transaction.inputs[0]->sequence);
        // if(!interpreter.process(transaction.inputs[0]->script, 4, forks))
        // {
            // NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            // success = false;
        // }
        // else
        // {
            // spendable.outputs[0]->script.setReadOffset(0);
            // if(!interpreter.process(spendable.outputs[0]->script, 4, forks))
            // {
                // NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process UTXO script");
                // success = false;
            // }
            // else
            // {
                // if(interpreter.isValid() && !interpreter.isVerified())
                    // NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed process P2PKH transaction with bad PK");
                // else
                // {
                    // NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed process P2PKH transaction with bad PK ");
                    // success = false;
                // }
            // }
        // }

        /***********************************************************************************************
         * Process P2PKH Transaction with Bad Sig
         ***********************************************************************************************/
        interpreter.clear();
        transaction.clear();

        // Add input
        transaction.addInput(spendable.hash, 0);

        // Add output
        transaction.addP2PKHOutput(publicKey2.hash(), 50000);

        // Sign the input
        if(transaction.signP2PKHInput(spendable.outputs[0], 0, privateKey2, publicKey1, Signature::ALL))
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed P2PKH sign with wrong private key");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed P2PKH sign with wrong private key");
            success = false;
        }

        transaction.inputs[0].script.setReadOffset(0);
        transaction.calculateHash();
        //NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0].script.setReadOffset(0);
        interpreter.initialize(&transaction, 0, transaction.inputs[0].sequence, spendable.outputs[0].amount);
        if(!interpreter.process(transaction.inputs[0].script, 4, forks))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            spendable.outputs[0].script.setReadOffset(0);
            if(!interpreter.process(spendable.outputs[0].script, 4, forks))
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process UTXO script");
                success = false;
            }
            else
            {
                if(interpreter.isValid() && !interpreter.isVerified())
                    NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed process P2PKH transaction bad sig");
                else
                {
                    NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed process P2PKH transaction bad sig");
                    success = false;
                }
            }
        }

        /***********************************************************************************************
         * Process Valid P2SH Transaction
         ***********************************************************************************************/
        // Create random redeemScript
        NextCash::Buffer redeemScript;
        for(unsigned int i=0;i<100;i+=4)
            redeemScript.writeUnsignedInt(NextCash::Math::randomInt());

        // Create hash of redeemScript
        NextCash::Hash redeemHash(20);
        NextCash::Digest digest(NextCash::Digest::SHA256_RIPEMD160);
        digest.writeStream(&redeemScript, redeemScript.length());
        digest.getResult(&redeemHash);

        spendable.clear();
        spendable.addP2SHOutput(redeemHash, 51000);
        spendable.calculateHash();

        transaction.clear();

        // Add input
        transaction.addInput(spendable.hash, 0);

        // Add output
        transaction.addP2PKHOutput(publicKey2.hash(), 50000);

        // Create signature script
        redeemScript.setReadOffset(0);
        if(transaction.authorizeP2SHInput(spendable.outputs[0], 0, redeemScript))
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed sign P2SH script");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed sign P2SH script");
            success = false;
        }

        if(ScriptInterpreter::parseOutputScript(spendable.outputs[0].script, checkHashes) == ScriptInterpreter::P2SH)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed check P2SH script");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed check P2SH script");
            success = false;
        }

        if(checkHashes.size() != 1 || redeemHash == checkHashes.front())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed check P2SH script hash");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed check P2SH script hash");
            success = false;
        }

        transaction.inputs[0].script.setReadOffset(0);
        transaction.calculateHash();
        //NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0].script.setReadOffset(0);
        interpreter.initialize(&transaction, 0, transaction.inputs[0].sequence, spendable.outputs[0].amount);
        if(!interpreter.process(transaction.inputs[0].script, 4, forks))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            spendable.outputs[0].script.setReadOffset(0);
            if(!interpreter.process(spendable.outputs[0].script, 4, forks))
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process UTXO script");
                success = false;
            }
            else
            {
                if(interpreter.isValid() && interpreter.isVerified())
                    NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed process valid P2SH transaction");
                else
                {
                    NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed process valid P2SH transaction");
                    success = false;
                }
            }
        }

        /***********************************************************************************************
         * Process Valid MULTISIG 1 of 2 Transaction
         ***********************************************************************************************/
        interpreter.clear();
        transaction.clear();
        spendable.clear();

        NextCash::Hash testOutHash(20);
        std::vector<Key *> publicKeys;

        publicKeys.push_back(&publicKey1);
        publicKeys.push_back(&publicKey2);
        testOutHash.randomize();

        spendable.addMultiSigOutput(1, publicKeys, 51000);
        spendable.calculateHash();

        transaction.addInput(spendable.hash, 0);
        transaction.addP2PKHOutput(testOutHash, 50000);

        bool signatureAdded, transactionComplete;

        if(transaction.addMultiSigInputSignature(spendable.outputs[0], 0, privateKey1,
          publicKey1, Signature::ALL, forks, signatureAdded, transactionComplete))
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed add multisig sign");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed add multisig sign");
            success = false;
        }

        if(signatureAdded)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed add multisig sign added");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed add multisig sign added");
            success = false;
        }

        if(transactionComplete)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed add multisig sign complete");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed add multisig sign complete");
            success = false;
        }

        if(ScriptInterpreter::parseOutputScript(spendable.outputs[0].script, checkHashes) == ScriptInterpreter::MULTI_SIG)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed check MULTISIG 1 of 2 script");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed check MULTISIG 1 of 2 script");
            success = false;
        }

        if(checkHashes.size() == 2)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed check MULTISIG 1 of 2 script hash count");
        else
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed check MULTISIG 1 of 2 script hash count : %d", checkHashes.size());
            success = false;
        }

        transaction.inputs[0].script.setReadOffset(0);
        transaction.calculateHash();
        //NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0].script.setReadOffset(0);
        interpreter.initialize(&transaction, 0, transaction.inputs[0].sequence, spendable.outputs[0].amount);
        if(!interpreter.process(transaction.inputs[0].script, 4, forks))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process MULTISIG 1 of 2 input script");
            success = false;
        }
        else
        {
            spendable.outputs[0].script.setReadOffset(0);
            if(!interpreter.process(spendable.outputs[0].script, 4, forks))
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process MULTISIG 1 of 2 output script");
                success = false;
            }
            else
            {
                if(interpreter.isValid() && interpreter.isVerified())
                    NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed process valid MULTISIG 1 of 2 transaction");
                else
                {
                    NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed process valid MULTISIG 1 of 2 transaction");
                    success = false;
                }
            }
        }

        /***********************************************************************************************
         * Process Valid MULTISIG 2 of 3 Transaction
         ***********************************************************************************************/
        interpreter.clear();
        transaction.clear();
        spendable.clear();

        Key privateKey3;

        privateKey3.generatePrivate(MAINNET);

        publicKeys.clear();
        publicKeys.push_back(&publicKey1);
        publicKeys.push_back(&publicKey2);
        publicKeys.push_back(privateKey3.publicKey());

        spendable.addMultiSigOutput(2, publicKeys, 51000);
        spendable.calculateHash();

        transaction.addInput(spendable.hash, 0);
        transaction.addP2PKHOutput(testOutHash, 50000);

        if(transaction.addMultiSigInputSignature(spendable.outputs[0], 0, privateKey2,
          publicKey2, Signature::ALL, forks, signatureAdded, transactionComplete))
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed add multisig sign 2");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed add multisig sign 2");
            success = false;
        }

        if(signatureAdded)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed add multisig sign 2 added");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed add multisig sign 2 added");
            success = false;
        }

        if(!transactionComplete)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed add multisig sign 2 not complete");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed add multisig sign 2 not complete");
            success = false;
        }

        if(transaction.addMultiSigInputSignature(spendable.outputs[0], 0, privateKey2,
          publicKey2, Signature::ALL, forks, signatureAdded, transactionComplete))
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed add multisig sign 2 again");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed add multisig sign 2 again");
            success = false;
        }

        if(!signatureAdded)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed add multisig sign 2 added again");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed add multisig sign 2 added again");
            success = false;
        }

        if(!transactionComplete)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed add multisig sign 2 again not complete");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed add multisig sign 2 again not complete");
            success = false;
        }

        if(transaction.addMultiSigInputSignature(spendable.outputs[0], 0, privateKey1,
          publicKey1, Signature::ALL, forks, signatureAdded, transactionComplete))
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed add multisig sign 1");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed add multisig sign 1");
            success = false;
        }

        if(signatureAdded)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed add multisig sign added 1");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed add multisig sign added 1");
            success = false;
        }

        if(transactionComplete)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed add multisig sign complete 1");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed add multisig sign complete 1");
            success = false;
        }

        if(ScriptInterpreter::parseOutputScript(spendable.outputs[0].script, checkHashes) == ScriptInterpreter::MULTI_SIG)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed check MULTISIG 2 of 3 script");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed check MULTISIG 2 of 3 script");
            success = false;
        }

        if(checkHashes.size() == 3)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed check MULTISIG 2 of 3 script hash count");
        else
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed check MULTISIG 2 of 3 script hash count : %d", checkHashes.size());
            success = false;
        }

        transaction.inputs[0].script.setReadOffset(0);
        transaction.calculateHash();
        //NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0].script.setReadOffset(0);
        interpreter.initialize(&transaction, 0, transaction.inputs[0].sequence, spendable.outputs[0].amount);
        if(!interpreter.process(transaction.inputs[0].script, 4, forks))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process MULTISIG 2 of 3 input script");
            success = false;
        }
        else
        {
            spendable.outputs[0].script.setReadOffset(0);
            if(!interpreter.process(spendable.outputs[0].script, 4, forks))
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process MULTISIG 2 of 3 output script");
                success = false;
            }
            else
            {
                if(interpreter.isValid() && interpreter.isVerified())
                    NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed process valid MULTISIG 2 of 3 transaction");
                else
                {
                    NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed process valid MULTISIG 2 of 3 transaction");
                    success = false;
                }
            }
        }

        return success;
    }
}
