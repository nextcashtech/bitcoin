/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "transaction.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#include "profiler_setup.hpp"
#endif

#include "endian.hpp"
#include "math.hpp"
#include "log.hpp"
#include "digest.hpp"
#include "interpreter.hpp"
#include "block.hpp"
#include "chain.hpp"

#define BITCOIN_TRANSACTION_LOG_NAME "Transaction"


namespace BitCoin
{
    Transaction::Transaction(const Transaction &pCopy)
    {
        mHash = pCopy.mHash;
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
        for(std::vector<Input>::const_iterator copyInput = pCopy.inputs.begin();
          copyInput != pCopy.inputs.end(); ++copyInput)
            inputs.emplace_back(*copyInput);

        outputs.reserve(pCopy.outputs.size());
        for(std::vector<Output>::const_iterator copyOutput = pCopy.outputs.begin();
          copyOutput != pCopy.outputs.end(); ++copyOutput)
            outputs.emplace_back(*copyOutput);
    }

    Transaction &Transaction::operator = (const Transaction &pRight)
    {
        mHash = pRight.mHash;
        version = pRight.version;
        lockTime = pRight.lockTime;

        mOutpointHash = pRight.mOutpointHash;
        mSequenceHash = pRight.mSequenceHash;
        mOutputHash = pRight.mOutputHash;
        mTime = pRight.mTime;
        mFee = pRight.mFee;
        mStatus = pRight.mStatus;
        mSize = pRight.mSize;

        inputs.clear();
        inputs.reserve(pRight.inputs.size());
        for(std::vector<Input>::const_iterator copyInput = pRight.inputs.begin();
          copyInput != pRight.inputs.end(); ++copyInput)
            inputs.emplace_back(*copyInput);

        outputs.clear();
        outputs.reserve(pRight.outputs.size());
        for(std::vector<Output>::const_iterator copyOutput = pRight.outputs.begin();
          copyOutput != pRight.outputs.end(); ++copyOutput)
            outputs.emplace_back(*copyOutput);

        return *this;
    }

    void Transaction::clear()
    {
        version = 1;
        lockTime = 0;

        mHash.clear();
        mOutpointHash.clear();
        mSequenceHash.clear();
        mOutputHash.clear();
        mFee = INVALID_FEE;

        inputs.clear();
        outputs.clear();
    }

    void Transaction::clearCache()
    {
        mOutpointHash.clear();
        mSequenceHash.clear();
        mOutputHash.clear();
    }

    void Transaction::print(const Forks &pForks, NextCash::Log::Level pLevel)
    {
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Hash      : %s",
          hash().hex().text());
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Version   : %d",
          version);
        if(lockTime >= LOCKTIME_THRESHOLD)
        {
            NextCash::String lockTimeText;
            lockTimeText.writeFormattedTime(lockTime);
            NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME,
              "Lock Time : time stamp %d - %s", lockTime, lockTimeText.text());
        }
        else
            NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME,
              "Lock Time : block height %d", lockTime);
        if(mFee != INVALID_FEE)
            NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Fee       : %f",
              bitcoins(-mFee));

        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "%d Inputs",
          inputs.size());
        unsigned int index = 0;
        for(std::vector<Input>::iterator input = inputs.begin(); input != inputs.end(); ++input)
        {
            NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Input %d", index++);
            input->print(pForks, pLevel);
        }

        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "%d Outputs",
          outputs.size());
        index = 0;
        for(std::vector<Output>::iterator output = outputs.begin(); output != outputs.end();
          ++output)
        {
            NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Output %d",
              index++);
            output->print(pForks, BITCOIN_TRANSACTION_LOG_NAME, pLevel);
        }
    }

    void Input::print(const Forks &pForks, NextCash::Log::Level pLevel)
    {
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Outpoint Trans : %s",
          outpoint.transactionID.hex().text());
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Outpoint Index : %d",
          outpoint.index);
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME,
          "  Sequence       : 0x%08x", sequence);
        NextCash::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME,
          "  Script         : (%d bytes)",script.length());
        script.setReadOffset(0);
        ScriptInterpreter::printScript(script, pForks, pLevel);
    }

    bool Transaction::addInput(const NextCash::Hash &pTransactionID, unsigned int pIndex,
      uint32_t pSequence)
    {
        // Add input
        inputs.emplace_back();
        Input &newInput = inputs.back();

        // Link input to unspent
        newInput.outpoint.transactionID = pTransactionID;
        newInput.outpoint.index = pIndex;
        newInput.sequence = pSequence;

        mOutpointHash.clear();
        mSequenceHash.clear();
        return true;
    }

    bool Transaction::addCoinbaseInput(int pHeight)
    {
        // Add input
        inputs.emplace_back();
        Input &newInput = inputs.back();

        ScriptInterpreter::writeArithmeticInteger(newInput.script, pHeight);
        newInput.script.compact();

        mOutpointHash.clear();
        mSequenceHash.clear();
        return true;
    }

    bool Transaction::signP2PKHInput(const Forks &pForks, Output &pOutput,
      unsigned int pInputOffset, const Key &pPrivateKey, Signature::HashType pHashType)
    {
        if(pPrivateKey.publicKey() == NULL)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed to sign P2PKH Input : Private key doesn't have public key");
            return false;
        }

        NextCash::HashList outputHashes;
        if(ScriptInterpreter::parseOutputScript(pOutput.script, outputHashes) !=
          ScriptInterpreter::P2PKH)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed to sign P2PKH Input : Output script is not P2PKH");
            return false;
        }

        if(outputHashes.size() != 1 || pPrivateKey.publicKey()->hash() != outputHashes.front())
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed to sign P2PKH Input : Output script public key hash doesn't match");
            return false;
        }

        if(inputs.size() <= pInputOffset)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed to sign P2PKH Input : Invalid input offset");
            return false;
        }

        // Create input script
        // Get signature hash
        Input &thisInput = inputs[pInputOffset];
        NextCash::Hash signatureHash;
        pOutput.script.setReadOffset(0);
        getSignatureHash(pForks, pForks.height(), signatureHash, pInputOffset,
          pOutput.script, pOutput.amount, pHashType);

        // Sign Hash
        Signature signature;
        if(!pPrivateKey.sign(signatureHash, signature))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed to sign P2PKH Input : Failed to sign script hash");
            return false;
        }
        signature.setHashType(pHashType);

        thisInput.script.clear();

        // Push the signature onto the stack
        signature.write(&thisInput.script, true);

        // Push the public key onto the stack
        pPrivateKey.publicKey()->writePublic(&thisInput.script, true);
        return true;
    }

    bool Transaction::addOutput(NextCash::Buffer pOutputScript, uint64_t pAmount)
    {
        if(pOutputScript.length() == 0)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
              "Empty output script");
            return false;
        }

        outputs.emplace_back();
        Output &newOutput = outputs.back();
        newOutput.amount = pAmount;

        newOutput.script = pOutputScript;
        newOutput.script.compact();

        mOutputHash.clear();
        return true;
    }

    bool Transaction::addOutput(const Output &pOutput)
    {
        if(pOutput.amount < DUST || pOutput.script.length() == 0)
            return false;

        outputs.emplace_back(pOutput);
        mOutputHash.clear();
        return true;
    }

    bool Transaction::addP2PKHOutput(const NextCash::Hash &pPublicKeyHash, uint64_t pAmount)
    {
        if(pPublicKeyHash.size() != PUB_KEY_HASH_SIZE)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
              "Public key hash is not the correct size");
            return false;
        }

        outputs.emplace_back();
        Output &newOutput = outputs.back();
        newOutput.amount = pAmount;

        if(!ScriptInterpreter::writeP2PKHOutputScript(newOutput.script, pPublicKeyHash))
            return false;

        mOutputHash.clear();
        return true;
    }

    bool Transaction::signP2PKInput(const Forks &pForks, Output &pOutput,
      unsigned int pInputOffset, const Key &pPrivateKey, const Key &pPublicKey,
      Signature::HashType pHashType)
    {
        NextCash::HashList outputHashes;
        pOutput.script.setReadOffset(0);
        if(ScriptInterpreter::parseOutputScript(pOutput.script, outputHashes) !=
          ScriptInterpreter::P2PK)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Output script is not P2PK");
            return false;
        }

        if(outputHashes.size() != 1)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Output script public keys don't match");
            return false;
        }

        if(pPublicKey.hash() != outputHashes.front())
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Output script public key doesn't match");
            return false;
        }

        // Check Public Key in output
        NextCash::Buffer publicKeyData;
        pOutput.script.setReadOffset(0);
        if(ScriptInterpreter::readDataPush(pOutput.script, publicKeyData) == 0)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed to read public key");
            return false;
        }

        Key checkPublicKey;
        if(!checkPublicKey.readPublic(&publicKeyData))
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed to parse public key");
            return false;
        }

        if(checkPublicKey != pPublicKey)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Non matching public key");
            return false;
        }

        if(inputs.size() <= pInputOffset)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Invalid input offset");
            return false;
        }
        Input &thisInput = inputs[pInputOffset];

        // Create input script
        // Get signature hash
        NextCash::Hash signatureHash;
        pOutput.script.setReadOffset(0);
        getSignatureHash(pForks, pForks.height(), signatureHash, pInputOffset, pOutput.script,
          pOutput.amount, pHashType);

        // Sign Hash
        Signature signature;
        if(!pPrivateKey.sign(signatureHash, signature))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed to sign script hash");
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

        mOutputHash.clear();
        return true;
    }

    bool Transaction::authorizeP2SHInput(Output &pOutput, unsigned int pInputOffset,
      NextCash::Buffer &pRedeemScript)
    {
        NextCash::HashList outputHashes;
        pOutput.script.setReadOffset(0);
        if(ScriptInterpreter::parseOutputScript(pOutput.script, outputHashes) !=
          ScriptInterpreter::P2SH)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Output script is not P2SH");
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
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Non matching script hash");
            return false;
        }

        if(inputs.size() <= pInputOffset)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Invalid input offset");
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

        mOutputHash.clear();
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
        std::vector<NextCash::Buffer> publicKeys;
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
                    publicKeys.emplace_back(data);
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
            return false;

        // Parse current input script
        Input &input = inputs[pInputOffset];
        std::vector<NextCash::Buffer> signatures;

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
                signatures.push_back(data);
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "MultiSig public key with invalid length : %d", data.length());
                success = false;
                break;
            }
        }

        std::vector<NextCash::Buffer> verifiedSignatures;

        if(success)
        {
            // Check signatures against public keys to find  where the new signature belongs
            std::vector<NextCash::Buffer>::iterator publicKeyIter = publicKeys.begin();
            std::vector<NextCash::Buffer>::iterator signatureIter = signatures.begin();
            bool signatureVerified;
            bool publicKeyFound = false;
            int signatureOffset = 0;
            NextCash::Hash signatureHash;
            NextCash::Buffer publicKeyBuffer;

            pPublicKey.writePublic(&publicKeyBuffer, false);

            while(publicKeyIter != publicKeys.end())
            {
                signatureVerified = false;
                while(publicKeyIter != publicKeys.end())
                {
                    if(signatureIter != signatures.end() &&
                      ScriptInterpreter::checkSignature(*this, pInputOffset, pOutput.amount,
                        publicKeyIter->begin(), publicKeyIter->length(), signatureIter->begin(),
                        signatureIter->length(), true, pOutput.script, 0, pForks, pForks.height()))
                    {
                        if(*publicKeyIter == publicKeyBuffer)
                        {
                            NextCash::Log::add(NextCash::Log::WARNING,
                              BITCOIN_TRANSACTION_LOG_NAME, "Public key already signed");
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
                    else if(!publicKeyFound && *publicKeyIter == publicKeyBuffer)
                    {
                        // Match found
                        Signature signature;

                        // Create new signature
                        // Get signature hash
                        pOutput.script.setReadOffset(0);
                        getSignatureHash(pForks, pForks.height(), signatureHash, pInputOffset,
                          pOutput.script, pOutput.amount, pHashType);

                        // Sign Hash
                        if(!pPrivateKey.sign(signatureHash, signature))
                        {
                            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
                              "Failed to sign signature hash");
                            success = false;
                            signatureVerified = true; // To avoid signature verfied message below
                            break;
                        }
                        else
                        {
                            signature.setHashType(pHashType);
                            data.clear();
                            signature.write(&data, false);
                            verifiedSignatures.push_back(data);
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
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                          BITCOIN_TRANSACTION_LOG_NAME, "MultiSig signature %d didn't verify",
                          signatureOffset);
                    else
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                          BITCOIN_TRANSACTION_LOG_NAME,
                          "MultiSig public key not found in output script : %s",
                          pPublicKey.hash().hex().text());
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

            for(std::vector<NextCash::Buffer>::iterator verifiedSig = verifiedSignatures.begin();
              verifiedSig != verifiedSignatures.end(); ++verifiedSig)
            {
                verifiedSig->setReadOffset(0);
                ScriptInterpreter::writePushDataSize(verifiedSig->length(), &input.script);
                input.script.writeStream(&*verifiedSig, verifiedSig->length());
            }
        }

        return success;
    }

    bool Transaction::addMultiSigOutput(unsigned int pRequiredSignatureCount,
      std::vector<Key *> pPublicKeys, uint64_t pAmount)
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

        mOutputHash.clear();
        return true;
    }

    Transaction *Transaction::createCoinbaseTransaction(int pHeight, int64_t pFees,
      const NextCash::Hash &pPublicKeyHash)
    {
        Transaction *result = new Transaction();
        result->addCoinbaseInput(pHeight);
        result->addP2PKHOutput(pPublicKeyHash, coinBaseAmount(pHeight) + pFees);
        result->lockTime = 0;
        result->calculateHash();
        return result;
    }

    bool Transaction::updateOutputs(Chain *pChain, uint64_t pHeight, bool pCoinBase,
      NextCash::Mutex &pSpentAgeLock, std::vector<unsigned int> &pSpentAges)
    {
        if(inputs.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
              "Zero inputs");
            return false;
        }

        if(outputs.size() == 0)
        {
            NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
              "Zero outputs");
            return false;
        }

        // Process Inputs
        uint32_t previousHeight;
        unsigned int index = 0;
        for(std::vector<Input>::iterator input = inputs.begin(); input != inputs.end();
          ++input, ++index)
        {
            if(input->outpoint.index != 0xffffffff)
            {
                if(pChain->outputs().spend(input->outpoint.transactionID, input->outpoint.index,
                  pHeight, previousHeight, false))
                {
                    pSpentAgeLock.lock();
                    pSpentAges.push_back(pHeight - previousHeight);
                    pSpentAgeLock.unlock();
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::WARNING,
                      BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d outpoint transaction not found : trans %s index %d", index,
                      input->outpoint.transactionID.hex().text(), input->outpoint.index);
                    print(pChain->forks(), NextCash::Log::WARNING);
                    return false;
                }
            }
        }

        return true;
    }

    bool Transaction::checkOutpoints(Chain *pChain, bool pMemPoolIsLocked)
    {
        // Verify outpoints are still unspent
        Output output;
        for(std::vector<Input>::iterator input = inputs.begin(); input != inputs.end();
          ++input)
            if(!pChain->memPool().getOutput(input->outpoint.transactionID, input->outpoint.index,
              output, pMemPoolIsLocked) &&
              !pChain->outputs().isUnspent(input->outpoint.transactionID, input->outpoint.index))
            {
                if(mStatus & OUTPOINTS_FOUND)
                    mStatus ^= OUTPOINTS_FOUND;
                return false;
            }

        return true;
    }

    void Transaction::check(Chain *pChain, const NextCash::Hash &pBlockHash, unsigned int pHeight,
      bool pCoinBase, int32_t pBlockVersion, NextCash::Mutex &pSpentAgeLock,
      std::vector<unsigned int> &pSpentAges, NextCash::Timer &pCheckDupTime,
      NextCash::Timer &pOutputLookupTime, NextCash::Timer &pScriptTime)
    {
        mStatus |= WAS_CHECKED;

        bool setIsStandard = true;

        if(!(mStatus & IS_VALID))
        {
            if(size() > 100000)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Transaction over max size of 100000 (%d bytes) : trans %s", size(),
                  hash().hex().text());
                return;
            }

            // if(pChain->forks().cashFork201811IsActive(pHeight) && size() < 100)
            // { // Not SV Compatible
                // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  // "Transaction below min size of 100 (%d bytes) : trans %s", size(),
                  // hash().hex().text());
                // return;
            // }

            if(inputs.size() == 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Zero inputs : trans %s", hash().hex().text());
                return;
            }

            if(outputs.size() == 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Zero outputs : trans %s", hash().hex().text());
                return;
            }
        }

#ifdef TRANS_ID_DUP_CHECK
        if(!(mStatus & DUP_CHECKED))
        {
            pCheckDupTime.start();
            if(!pChain->outputs().checkDuplicate(hash, pHeight, pBlockHash))
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Zero outputs : trans %s", hash().hex().text());
                return;
            }
            pCheckDupTime.stop();
        }

        mStatus |= DUP_CHECKED;
#endif

        // Check inputs
        unsigned int index = 0;
        for(std::vector<Input>::iterator input = inputs.begin(); input != inputs.end(); ++input)
        {
            if(pCoinBase)
            {
                if(input->outpoint.index != 0xffffffff)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Coinbase input %d has outpoint transaction : trans %s", index, hash().hex().text());
                    return;
                }
            }
            else
            {
                if(input->outpoint.index == 0xffffffff)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d has no outpoint transaction : trans %s", index, hash().hex().text());
                    return;
                }

                // Input script only contains data pushes, including hard coded value pushes
                input->script.setReadOffset(0);
                if(pChain->forks().cashFork201811IsActive(pHeight) &&
                  !ScriptInterpreter::isPushOnly(input->script))
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d script is not push only : trans %s", index, hash().hex().text());
                    input->script.setReadOffset(0);
                    ScriptInterpreter::printScript(input->script, pChain->forks(), pHeight,
                      NextCash::Log::VERBOSE);
                    return;
                }
            }

            if(input->script.length() > 1650)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d script over standard size of 1650 (%d bytes) : trans %s", index,
                  input->script.length(), hash().hex().text());
                setIsStandard = false;
            }

            ++index;
        }

        // Check Outputs
        index = 0;
        ScriptInterpreter::ScriptType scriptType;
        NextCash::HashList hashes;
        int64_t newFee = 0;
        for(std::vector<Output>::iterator output = outputs.begin(); output != outputs.end();
          ++output)
        {
            if(output->amount < 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                  "Output %d amount is less than zero (%d) : trans %s", index, output->amount,
                  hash().hex().text());
                output->print(pChain->forks(), BITCOIN_TRANSACTION_LOG_NAME,
                  NextCash::Log::WARNING);
                print(pChain->forks(), NextCash::Log::VERBOSE);
                mFee = INVALID_FEE;
                return;
            }

            // Output script matches allowed patterns
            scriptType = ScriptInterpreter::parseOutputScript(output->script, hashes);
            if(scriptType == ScriptInterpreter::NON_STANDARD)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Output %d is non standard : trans %s", index, hash().hex().text());
                output->script.setReadOffset(0);
                ScriptInterpreter::printScript(output->script, pChain->forks(), pHeight,
                  NextCash::Log::VERBOSE);
                print(pChain->forks(), NextCash::Log::VERBOSE);
                setIsStandard = false;
            }
            else if(scriptType == ScriptInterpreter::INVALID)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Output %d is invalid : trans %s", index, hash().hex().text());
                print(pChain->forks(), NextCash::Log::VERBOSE);
                mFee = INVALID_FEE;
                return;
            }

            newFee -= output->amount;
            ++index;
        }

        if(setIsStandard)
            mStatus |= IS_STANDARD;
        else if(pHeight == Chain::INVALID_HEIGHT)
        {
            if(mStatus & IS_STANDARD)
                mStatus ^= IS_STANDARD;
            mFee = INVALID_FEE;
            return; // Only standard currently supported so don't check signatures
        }

        if(pCoinBase)
        {
            // BIP-0034 Check coinbase input script
            if(pBlockVersion >= 2 && pChain->forks().enabledBlockVersion(pHeight) >= 2)
                for(std::vector<Input>::iterator input = inputs.begin(); input != inputs.end(); ++input)
                {
                    // Read block height
                    int64_t blockHeight = 0;
                    input->script.setReadOffset(0);
                    if(!ScriptInterpreter::readArithmeticInteger(input->script, blockHeight))
                    {
                        NextCash::Log::add(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Coinbase input doesn't start with data push");
                        mFee = INVALID_FEE;
                        return;
                    }

                    if(blockHeight < 0 || (uint64_t)blockHeight != pHeight)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING,
                          BITCOIN_TRANSACTION_LOG_NAME,
                          "Non matching coinbase block height : actual %d, coinbase %d",
                          pHeight, blockHeight);
                        mFee = INVALID_FEE;
                        return;
                    }
                }

            mStatus |= OUTPOINTS_FOUND;
            mStatus |= SIGS_VERIFIED;
            mFee = newFee;
        }
        else
        {
            // Find outpoints and check signatures
            ScriptInterpreter interpreter;
            uint32_t previousHeight;
            bool sequenceFound = false;
            Output output;
            index = 0;
            if(mStatus & OUTPOINTS_FOUND)
            {
                // Verify outpoints are still unspent
                for(std::vector<Input>::iterator input = inputs.begin(); input != inputs.end();
                  ++input)
                {
                    pOutputLookupTime.start();
                    if(pHeight == Chain::INVALID_HEIGHT)
                    {
                        // Search mempool
                        if(!pChain->memPool().getOutput(input->outpoint.transactionID,
                          input->outpoint.index, output, false))
                        {
                            if(!pChain->outputs().isUnspent(input->outpoint.transactionID,
                              input->outpoint.index))
                            {
                                NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                                  BITCOIN_TRANSACTION_LOG_NAME,
                                  "Input %d outpoint transaction not found : index %d trans %s",
                                  index, input->outpoint.index,
                                  input->outpoint.transactionID.hex().text());
                                if(mStatus & OUTPOINTS_FOUND)
                                    mStatus ^= OUTPOINTS_FOUND;
                                pOutputLookupTime.stop();
                                break;
                            }
                        }
                    }
#ifdef TEST
                    else if(!pChain->outputs().spend(input->outpoint.transactionID,
                      input->outpoint.index, pHeight, previousHeight, false)) // Don't require unspent
                    {
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                          BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d outpoint transaction not found : index %d trans %s",
                          index, input->outpoint.index,
                          input->outpoint.transactionID.hex().text());
                        if(mStatus & OUTPOINTS_FOUND)
                            mStatus ^= OUTPOINTS_FOUND;
                        pOutputLookupTime.stop();
                        break;
                    }
#else
                    else if(!pChain->outputs().spend(input->outpoint.transactionID,
                      input->outpoint.index, pHeight, previousHeight, true))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                          BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d outpoint transaction not found : index %d trans %s",
                          index, input->outpoint.index,
                          input->outpoint.transactionID.hex().text());
                        if(mStatus & OUTPOINTS_FOUND)
                            mStatus ^= OUTPOINTS_FOUND;
                        pOutputLookupTime.stop();
                        break;
                    }
#endif
                    pOutputLookupTime.stop();
                }
            }
            else
            {
                Output output;
                bool allOutpointsFound = true;
                bool sigFailed = false;
                uint8_t outputFlag;
                for(std::vector<Input>::iterator input = inputs.begin();
                  input != inputs.end() && !sigFailed; ++input, ++index)
                {
#ifdef TEST
                    outputFlag = 0;
#else
                    if(pHeight == Chain::INVALID_HEIGHT)
                        outputFlag = Outputs::REQUIRE_UNSPENT;
                    else
                        outputFlag = Outputs::REQUIRE_UNSPENT |
                          Outputs::MARK_SPENT;
#endif

                    pOutputLookupTime.start();
                    if(pHeight == Chain::INVALID_HEIGHT)
                    {
                        // Search for outpoint.
                        if(!pChain->memPool().getOutput(input->outpoint.transactionID,
                          input->outpoint.index, output, false) &&
                          !pChain->outputs().getOutput(input->outpoint.transactionID,
                          input->outpoint.index, outputFlag, pHeight, output, previousHeight))
                        {
                            pOutputLookupTime.stop();
                            if(mStatus & OUTPOINTS_FOUND)
                                mStatus ^= OUTPOINTS_FOUND;
                            NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                              BITCOIN_TRANSACTION_LOG_NAME,
                              "Input %d outpoint transaction not found : index %d trans %s",
                              index, input->outpoint.index,
                              input->outpoint.transactionID.hex().text());
                            allOutpointsFound = false;
                            continue;
                        }
                    }
                    else if(pChain->outputs().getOutput(input->outpoint.transactionID,
                      input->outpoint.index, outputFlag, pHeight, output, previousHeight))
                    {
                        pSpentAgeLock.lock();
                        pSpentAges.push_back(pHeight - previousHeight);
                        pSpentAgeLock.unlock();
                    }
                    else
                    {
                        pOutputLookupTime.stop();
                        if(mStatus & OUTPOINTS_FOUND)
                            mStatus ^= OUTPOINTS_FOUND;
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                          BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d outpoint transaction not found : index %d trans %s", index,
                          input->outpoint.index, input->outpoint.transactionID.hex().text());
                        allOutpointsFound = false;
                        continue;
                    }
                    pOutputLookupTime.stop();

                    // BIP-0068 Relative time lock sequence
                    if(version >= 2 && !input->sequenceDisabled() &&
                      pChain->forks().softForkIsActive(pHeight, SoftFork::BIP0068))
                    {
                        // Sequence is an encoded relative time lock
                        uint32_t lock = input->sequence & Input::SEQUENCE_LOCKTIME_MASK;
                        if(input->sequence & Input::SEQUENCE_TYPE)
                        {
                            // Seconds since outpoint median past time in units of 512 seconds granularity
                            lock <<= 9;
                            Time currentBlockMedianTime = pChain->getMedianPastTime(pHeight - 1, 11);
                            Time spentBlockMedianTime = pChain->getMedianPastTime(previousHeight - 1, 11);
                            if(currentBlockMedianTime < spentBlockMedianTime + lock)
                            {
                                NextCash::Log::addFormatted(NextCash::Log::WARNING,
                                  BITCOIN_TRANSACTION_LOG_NAME,
                                  "Input %d sequence 0x%08x not valid. Required spent block time age %d, actual %d : index %d trans %s",
                                  index, input->sequence, lock,
                                  currentBlockMedianTime - spentBlockMedianTime, input->outpoint.index,
                                  input->outpoint.transactionID.hex().text());
                                NextCash::String timeText;
                                timeText.writeFormattedTime(spentBlockMedianTime + lock);
                                NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                                  "Not valid until median block time %s", timeText.text());
                                mFee = INVALID_FEE;
                                return;
                            }
                        }
                        else if(pHeight < previousHeight + lock) // Number of blocks since outpoint
                        {
                            NextCash::Log::addFormatted(NextCash::Log::WARNING,
                              BITCOIN_TRANSACTION_LOG_NAME,
                              "Input %d sequence 0x%08x not valid. Required block height age %d. actual %d : index %d trans %s",
                              index, input->sequence, lock, pHeight - previousHeight,
                              input->outpoint.index, input->outpoint.transactionID.hex().text());
                            NextCash::Log::addFormatted(NextCash::Log::WARNING,
                              BITCOIN_TRANSACTION_LOG_NAME, "Not valid until block %d",
                              previousHeight + lock);
                            mFee = INVALID_FEE;
                            return;
                        }
                    }

                    if(input->sequence != Input::SEQUENCE_NONE)
                        sequenceFound = true;

                    newFee += output.amount;

                    if(input->signatureStatus & Input::VERIFIED)
                        continue;

                    interpreter.clear();
                    interpreter.initialize(this, index, input->sequence, output.amount);

                    input->signatureStatus = Input::CHECKED;

                    // Process signature script
                    pScriptTime.start();
                    input->script.setReadOffset(0);
                    if(!interpreter.process(input->script, pBlockVersion, pChain->forks(),
                      pHeight))
                    {
                        pScriptTime.stop();
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                          BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d signature script is not valid : trans %s", index,
                          hash().hex().text());
                        input->print(pChain->forks(), NextCash::Log::VERBOSE);
                        sigFailed = true;
                        continue;
                    }

                    // Check outpoint script
                    output.script.setReadOffset(0);
                    if(!interpreter.process(output.script, pBlockVersion,
                      pChain->forks(), pHeight) || !interpreter.isValid())
                    {
                        pScriptTime.stop();
                        NextCash::Log::addFormatted(NextCash::Log::WARNING,
                          BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d outpoint script is not valid : trans %s", index,
                          hash().hex().text());
                        input->print(pChain->forks(), NextCash::Log::WARNING);
                        output.print(pChain->forks(), BITCOIN_TRANSACTION_LOG_NAME,
                          NextCash::Log::WARNING);
                        sigFailed = true;
                        continue;
                    }
                    else
                    {
                        pScriptTime.stop();
                        if(!interpreter.isVerified())
                        {
                            NextCash::Log::addFormatted(NextCash::Log::WARNING,
                              BITCOIN_TRANSACTION_LOG_NAME,
                              "Input %d script did not verify : trans %s", index,
                              hash().hex().text());
                            input->print(pChain->forks(), NextCash::Log::WARNING);
                            interpreter.printStack("After fail verify");
                            output.print(pChain->forks(), BITCOIN_TRANSACTION_LOG_NAME,
                              NextCash::Log::WARNING);
                            sigFailed = true;
                            continue;
                        }
                        // else if(pChain->forks().cashFork201811IsActive(pHeight) &&
                          // !interpreter.stackIsClean())
                        // {
                            // NextCash::Log::addFormatted(NextCash::Log::WARNING,
                              // BITCOIN_TRANSACTION_LOG_NAME,
                              // "Input %d script did not leave the stack clean : trans %s", index,
                              // hash().hex().text());
                            // input->print(pChain->forks(), NextCash::Log::WARNING);
                            // interpreter.printStack("After fail clean stack");
                            // output.print(pChain->forks(), BITCOIN_TRANSACTION_LOG_NAME,
                              // NextCash::Log::WARNING);
                            // sigFailed = true;
                            // continue;
                        // }
                        else
                            input->signatureStatus |= Input::VERIFIED;
                    }
                }

                if(sigFailed)
                {
                    if(mStatus & SIGS_VERIFIED)
                        mStatus ^= SIGS_VERIFIED;
                    mFee = INVALID_FEE;
                    return;
                }
                else if(allOutpointsFound)
                {
                    mStatus |= OUTPOINTS_FOUND;
                    mStatus |= SIGS_VERIFIED;

                    mFee = newFee;
                    if(mFee < 0)
                    {
                        NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                          "Outputs amounts are more than inputs amounts");
                        index = 0;
                        for(std::vector<Input>::iterator input = inputs.begin(); input != inputs.end();
                          ++input)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                              BITCOIN_TRANSACTION_LOG_NAME, "    Input %d : %.08f", index,
                              bitcoins(output.amount));
                            ++index;
                        }
                        index = 0;
                        for(std::vector<Output>::iterator outputIter = outputs.begin();
                          outputIter != outputs.end(); ++outputIter)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                              BITCOIN_TRANSACTION_LOG_NAME, "    Output %d : %.08f", index,
                              bitcoins(outputIter->amount));
                            ++index;
                        }
                        print(pChain->forks(), NextCash::Log::VERBOSE);
                        mFee = INVALID_FEE;
                        return;
                    }

                    clearCache();
                }
                else
                    mFee = INVALID_FEE;
            }

            if(sequenceFound)
            {
                if(lockTime >= LOCKTIME_THRESHOLD)
                {
                    // Lock time is a timestamp
                    if(pChain->forks().softForkIsActive(pHeight, SoftFork::BIP0113))
                    {
                        if(lockTime > pChain->getMedianPastTime(pHeight, 11))
                        {
                            NextCash::String lockTimeText, blockTimeText;
                            lockTimeText.writeFormattedTime(lockTime);
                            blockTimeText.writeFormattedTime(
                              pChain->getMedianPastTime(pHeight, 11));
                            NextCash::Log::addFormatted(NextCash::Log::WARNING,
                              BITCOIN_TRANSACTION_LOG_NAME,
                              "Lock time 0x%08x time stamp is not valid. Lock time %s > block median time %s",
                              lockTime, lockTimeText.text(), blockTimeText.text());
                            print(pChain->forks(), NextCash::Log::VERBOSE);
                            mFee = INVALID_FEE;
                            return;
                        }
                    }
                    else
                    {
                        // Add 600 to fake having a "peer time offset" for older blocks
                        //   Block 357903 transaction 98 has a lock time about 3 minutes after the
                        //   block time.
                        if(lockTime > pChain->time(pHeight) + 600)
                        {
                            NextCash::String lockTimeText, blockTimeText;
                            lockTimeText.writeFormattedTime(lockTime);
                            blockTimeText.writeFormattedTime(pChain->time(pHeight));
                            NextCash::Log::addFormatted(NextCash::Log::WARNING,
                              BITCOIN_TRANSACTION_LOG_NAME,
                              "Lock time 0x%08x time stamp is not valid. Lock time %s > block time %s",
                              lockTime, lockTimeText.text(), blockTimeText.text());
                            print(pChain->forks(), NextCash::Log::VERBOSE);
                            mFee = INVALID_FEE;
                            return;
                        }
                    }
                }
                else
                {
                    // Lock time is a block height
                    if(lockTime > pHeight)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::WARNING,
                          BITCOIN_TRANSACTION_LOG_NAME,
                          "Lock time block height is not valid. Lock height %d > block height %d",
                          lockTime, pHeight);
                        print(pChain->forks(), NextCash::Log::VERBOSE);
                        mFee = INVALID_FEE;
                        return;
                    }
                }
            }
        }

        mStatus |= IS_VALID;
        return;
    }

    void Transaction::calculateSize()
    {
        mSize = 4; // Version

        // Input Count
        mSize += compactIntegerSize(inputs.size());

        // Inputs
        for(std::vector<Input>::iterator input = inputs.begin(); input != inputs.end(); ++input)
            mSize += input->size();

        // Output Count
        mSize += compactIntegerSize(outputs.size());

        // Outputs
        for(std::vector<Output>::iterator output = outputs.begin();
          output != outputs.end(); ++output)
            mSize += output->size();

        // Lock Time
        mSize += 4;
    }

    uint64_t Transaction::feeRate()
    {
        if(mFee == INVALID_FEE)
            return 0;
        uint64_t currentSize = mSize;
        if(currentSize == 0)
        {
            calculateSize();
            currentSize = mSize;
        }
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
        if(bytes > MAX_SCRIPT_SIZE)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed to read input. Script too long : %d", bytes);
            return false;
        }
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

    void Transaction::write(NextCash::OutputStream *pStream)
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
            output->write(pStream);

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

    bool Transaction::writeSignatureData(const Forks &pForks, unsigned int pHeight,
      NextCash::OutputStream *pStream, unsigned int pInputOffset, NextCash::Buffer &pOutputScript,
      int64_t pOutputAmount, uint8_t pHashType)
    {
#ifdef PROFILER_ON
        NextCash::ProfilerReference profiler(NextCash::getProfiler(PROFILER_SET,
          PROFILER_TRANS_WRITE_SIG_ID, PROFILER_TRANS_WRITE_SIG_NAME), true);
#endif
        Signature::HashType hashType = static_cast<Signature::HashType>(pHashType);
        // Extract FORKID (0x40) flag from hash type
        bool containsForkID = pForks.cashActive(pHeight) && hashType & Signature::FORKID;
        if(containsForkID)
            hashType = static_cast<Signature::HashType>(hashType ^ Signature::FORKID);
        // Extract ANYONECANPAY (0x80) flag from hash type
        bool anyoneCanPay = hashType & Signature::ANYONECANPAY;
        if(anyoneCanPay)
            hashType = static_cast<Signature::HashType>(hashType ^ Signature::ANYONECANPAY);

        if(containsForkID)
        {
            // BIP-0143 Signature Hash Algorithm
            NextCash::Hash sigHash(32);
            NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
            digest.setOutputEndian(NextCash::Endian::LITTLE);

            // Version
            pStream->writeUnsignedInt(version);

            // Hash Prev Outs
            if(anyoneCanPay)
                sigHash.zeroize();
            else
            {
                if(!mOutpointHash.isEmpty())
                    sigHash = mOutpointHash;
                else
                {
                    // All input outpoints
                    digest.initialize();
                    for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
                        input->outpoint.write(&digest);
                    digest.getResult(&sigHash);
                    mOutpointHash = sigHash; // Save for next input
                }
            }
            sigHash.write(pStream);

            // Hash Sequence
            if(anyoneCanPay || hashType == Signature::SINGLE || hashType == Signature::NONE)
                sigHash.zeroize();
            else
            {
                if(!mSequenceHash.isEmpty())
                    sigHash = mSequenceHash;
                else
                {
                    // All input sequences
                    digest.initialize();
                    for(std::vector<Input>::iterator input=inputs.begin();input!=inputs.end();++input)
                        digest.writeUnsignedInt(input->sequence);
                    digest.getResult(&sigHash);
                    mSequenceHash = sigHash; // Save for next input
                }
            }
            sigHash.write(pStream);

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
                    digest.getResult(&sigHash);
                }
                else
                    sigHash.zeroize();
            }
            else if(hashType == Signature::NONE)
                sigHash.zeroize();
            else
            {
                if(!mOutputHash.isEmpty())
                    sigHash = mOutputHash;
                else
                {
                    // All outputs
                    digest.initialize();
                    for(std::vector<Output>::iterator output=outputs.begin();output!=outputs.end();++output)
                        output->write(&digest);
                    digest.getResult(&sigHash);
                    mOutputHash = sigHash; // Save for next input
                }
            }
            sigHash.write(pStream);

            // Lock Time
            pStream->writeUnsignedInt(lockTime);

            // Sig Hash Type
            pStream->writeUnsignedInt((pForks.cashForkID(pHeight) << 8) | pHashType);
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
                std::vector<Output>::iterator output = outputs.begin();
                for(offset = 0; offset < pInputOffset + 1; offset++)
                    if(output != outputs.end())
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
                          pInputOffset + 1, outputs.size());
                        return false;
                    }

                break;
            }
            }

            // Lock Time
            pStream->writeUnsignedInt(lockTime);

            // Sig Hash Type
            pStream->writeUnsignedInt(pHashType);
        }

        return true;
    }

    void Transaction::getSignatureHash(const Forks &pForks, unsigned int pHeight,
      NextCash::Hash &pHash, unsigned int pInputOffset, NextCash::Buffer &pOutputScript,
      int64_t pOutputAmount, uint8_t pHashType)
    {
        // Write appropriate data to a digest
        NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
        NextCash::stream_size previousReadOffset = pOutputScript.readOffset();
        digest.setOutputEndian(NextCash::Endian::LITTLE);
        if(writeSignatureData(pForks, pHeight, &digest, pInputOffset, pOutputScript,
          pOutputAmount, pHashType))
        {
            digest.getResult(&pHash); // Get digest result
            pOutputScript.setReadOffset(previousReadOffset);
        }
        else
        {
            // Use signature hash of 0 or 1 (probably sig hash single with not enough outputs)
            pHash.zeroize();
            if(!(pHashType & Signature::FORKID))
                pHash.setByte(0, 1);
            pOutputScript.setReadOffset(previousReadOffset);
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
      NextCash::Hash &pTransactionID, Output &pOutput)
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
                if(!pOutput.read(pStream))
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

    bool Transaction::read(NextCash::InputStream *pStream)
    {
#ifdef PROFILER_ON
        NextCash::Profiler &profiler = NextCash::getProfiler(PROFILER_SET,
          PROFILER_TRANS_READ_ID, PROFILER_TRANS_READ_NAME);
        NextCash::ProfilerReference profilerRef(profiler, true);
#endif

        clear();

        NextCash::stream_size startOffset = pStream->readOffset();
        mSize = 0;

        if(pStream->remaining() < 5)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Transaction read failed : stream remaining less than 5");
            return false;
        }

        // Version
        version = pStream->readUnsignedInt();

        // Input Count
        uint64_t count = readCompactInteger(pStream);
        if(count > MAX_TRANSACTION_INPUTS)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Transaction read failed. Too many inputs : %d", count);
            return false;
        }

        if(pStream->remaining() < count)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Transaction read failed : stream remaining less than input count %d", count);
            return false;
        }

        // Inputs
        inputs.reserve(count);
        for(unsigned int i = 0; i < count; ++i)
        {
            inputs.emplace_back();
            if(!inputs.back().read(pStream))
            {
                NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Transaction read failed : input read failed");
                return false;
            }
        }

        // Output Count
        count = readCompactInteger(pStream);
        if(count > MAX_TRANSACTION_OUTPUTS)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Transaction read failed. Too many outputs : %d", count);
            return false;
        }

        // Outputs
        outputs.reserve(count);
        for(unsigned int i = 0; i < count; ++i)
        {
            outputs.emplace_back();
            if(!outputs.back().read(pStream))
            {
                NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Transaction read failed : output read failed");
                return false;
            }
        }

        if(pStream->remaining() < 4)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Transaction read failed : stream remaining less than 4");
            return false;
        }

        // Lock Time
        lockTime = pStream->readUnsignedInt();

        mSize = pStream->readOffset() - startOffset;
#ifdef PROFILER_ON
        profiler.addHits(size() - 1); // One hit (byte) will be added by reference.
#endif
        return true;
    }

    void Transaction::calculateHash()
    {
        // Write into digest
        NextCash::Digest digest(NextCash::Digest::SHA256_SHA256);
        digest.setOutputEndian(NextCash::Endian::LITTLE);
        write(&digest);

        digest.getResult(&mHash);
    }

    int signTransaction(Transaction &pTransaction, Key *pKey, Signature::HashType pHashType,
      const Forks &pForks)
    {
        Key *key;
        ScriptInterpreter::ScriptType scriptType;
        NextCash::HashList payAddresses;
        uint32_t inputOffset = 0;

        pTransaction.clearCache();

        for(std::vector<Input>::iterator input = pTransaction.inputs.begin();
            input != pTransaction.inputs.end(); ++input, ++inputOffset)
        {
            // Parse the output for addresses
            scriptType = ScriptInterpreter::parseOutputScript(input->outpoint.output->script,
              payAddresses);
            if(scriptType != ScriptInterpreter::P2PKH || payAddresses.size() != 1)
            {
                payAddresses.clear();
                return 1;
            }

            // Find private key for public key hash
            key = pKey->findAddress(payAddresses.front());
            if(key == NULL)
                return 1;

            // Sign input with private key
            if(!pTransaction.signP2PKHInput(pForks, *input->outpoint.output, inputOffset, *key,
              pHashType))
                return 5; // Issue with signing
        }

        return 0;
    }

    int Transaction::sign(uint64_t pInputAmount, double pFeeRate, uint64_t pSendAmount,
      int pChangeOutputOffset, Key *pKey, Signature::HashType pHashType, const Forks &pForks)
    {
        uint64_t actualFee = 0, fee = 0;
        int result = 0;
        do
        {
            if(fee == 0)
                fee = (uint64_t)((double)size() * pFeeRate);
            else if(pFeeRate >= 1.0)
                fee += (uint64_t)pFeeRate;
            else
                ++fee;

            if(pSendAmount == 0xffffffffffffffffL) // Send all. Adjust send amount to make fee correct
                outputs.back().amount = pInputAmount - fee; // Expects only one output
            else if(pChangeOutputOffset > 0) // Adjust change amount to make fee correct
                outputs[pChangeOutputOffset].amount = pInputAmount - pSendAmount - fee;
            // else // Leave all remaining balance in the fee

            // Sign transaction
            mOutputHash.clear(); // Clear output sig hash because an output has been modified
            result = signTransaction(*this, pKey, pHashType, pForks);
            if(result != 0)
                return result;

            calculateSize();
            actualFee = pInputAmount - outputAmount();
        }
        while(actualFee < (uint64_t)((double)size() * pFeeRate));

        return result;
    }

    TransactionReference TransactionList::getSorted(const NextCash::Hash &pHash)
    {
        // Search sorted
        if(size() == 0 || back()->hash() < pHash)
            return NULL; // Item would be after end

        if(front()->hash() > pHash)
            return NULL; // Item would be before beginning

        int compare;
        TransactionReference *bottom = data();
        TransactionReference *top    = data() + size() - 1;
        TransactionReference *current;

        while(true)
        {
            // Break the set in two halves
            current = bottom + ((top - bottom) / 2);
            compare = pHash.compare((*current)->hash());

            if(compare == 0) // Item found
                break;

            if(current == bottom)
            {
                if(current != top && (*top)->hash() == pHash)
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

    bool TransactionList::insertSorted(TransactionReference pTransaction)
    {
        // Insert sorted
        if(size() == 0)
        {
            // Append as last item
            push_back(pTransaction);
            return true;
        }

        int compare = back()->hash().compare(pTransaction->hash());
        if(compare == 0)
            return false; // Already last item
        else if(compare < 0)
        {
            // Append as last item
            push_back(pTransaction);
            return true;
        }

        compare = front()->hash().compare(pTransaction->hash());
        if(compare == 0)
            return false; // Already first item
        else if(compare > 0)
        {
            // Insert as first item
            insert(begin(), pTransaction);
            return true;
        }

        TransactionReference *bottom = data();
        TransactionReference *top    = data() + size() - 1;
        TransactionReference *current;

        while(true)
        {
            // Break the set in two halves
            current = bottom + ((top - bottom) / 2);
            compare = pTransaction->hash().compare((*current)->hash());

            if(compare == 0) // Item found
                return false;

            if(current == bottom)
            {
                if(current != top && (*top)->hash() > pTransaction->hash())
                    current = top; // Insert before top
                else
                    current = top + 1; // Insert after top

                if(*current && (*current)->hash() == pTransaction->hash())
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
        if(size() == 0 || back()->hash() < pHash)
            return false; // Item would be after end

        if(front()->hash() > pHash)
            return false; // Item would be before beginning

        int compare;
        TransactionReference *bottom = data();
        TransactionReference *top    = data() + size() - 1;
        TransactionReference *current;

        while(true)
        {
            // Break the set in two halves
            current = bottom + ((top - bottom) / 2);
            compare = pHash.compare((*current)->hash());

            if(compare == 0) // Item found
                break;

            if(current == bottom)
            {
                if(current != top && (*top)->hash() == pHash)
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
        iterator item = begin();
        item += (current - data());
        erase(item);
        return true;
    }

    TransactionReference TransactionList::getAndRemoveSorted(const NextCash::Hash &pHash)
    {
        // Remove sorted
        if(size() == 0 || back()->hash() < pHash)
            return NULL; // Item would be after end

        if(front()->hash() > pHash)
            return NULL; // Item would be before beginning

        int compare;
        TransactionReference *bottom = data();
        TransactionReference *top    = data() + size() - 1;
        TransactionReference *current;

        while(true)
        {
            // Break the set in two halves
            current = bottom + ((top - bottom) / 2);
            compare = pHash.compare((*current)->hash());

            if(compare == 0) // Item found
                break;

            if(current == bottom)
            {
                if(current != top && (*top)->hash() == pHash)
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
        iterator item = begin();
        item += (current - data());
        TransactionReference result = *item;
        erase(item);
        return result;
    }

    TransactionReference TransactionList::getAndRemoveAt(unsigned int pOffset)
    {
        if(pOffset >= size())
            return NULL;

        iterator iter = begin() + pOffset;
        TransactionReference result = *iter;
        erase(iter);
        return result;
    }

    bool Transaction::test()
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME,
          "------------- Starting Transaction Tests -------------");

        bool success = true;
        Key privateKey1, privateKey2, privateKey3;
        //Key publicKey1, publicKey2;
        Signature signature;
        NextCash::Buffer data;
        Forks forks;

        privateKey3.generatePrivate(MAINNET);

        // Initialize private key
        data.writeHex("d68e0869df44615cc57f196208a896653e969f69960c6435f38ae47f6b6d082d");
        privateKey1.readPrivate(&data);

        // Initialize public key
//        data.clear();
//        data.writeHex("03077b2a0406db4b4e2cddbe9aca5e9f1a3cf039feb843992d05cc0b7a75046635");
//        publicKey1.readPublic(&data);

        // Initialize private key
        data.writeHex("4fd0a873dba1d74801f182013c5ae17c17213d333657047a6e6c5865f388a60a");
        privateKey2.readPrivate(&data);

        // Initialize public key
//        data.clear();
//        data.writeHex("03362365326bd230642290787f3ba93d6299392ac5d26cd66e300f140184521e9c");
//        publicKey2.readPublic(&data);

        // Create unspent transaction output (so we can spend it)
        Transaction spendable, spendable3, transaction;

        spendable.addP2PKHOutput(privateKey1.hash(), 51000);
        spendable.calculateHash();

        spendable3.addP2PKHOutput(privateKey3.hash(), 51000);
        spendable3.calculateHash();

        /***********************************************************************************************
         * Process Valid P2PKH Transaction
         ***********************************************************************************************/
        // Create public key script to pay the third public key

        // Create Transaction to spend it
        // Add input
        transaction.addInput(spendable.hash(), 0);

        // Add output
        transaction.addP2PKHOutput(privateKey2.hash(), 50000);

        // Sign the input
        transaction.signP2PKHInput(forks, spendable.outputs[0], 0, privateKey1, Signature::ALL);

        NextCash::Buffer inputScript;
        transaction.inputs[0].script.setReadOffset(0);
        inputScript.writeHex("48304502210086f3bd9b0b0020cba317ee197e71cfcabed272c3d096f256d8f238febc65464402205c88f0059425bc774f4269b08895af62936d720da3c324be70979de800d392be012103077b2a0406db4b4e2cddbe9aca5e9f1a3cf039feb843992d05cc0b7a75046635");
        if(inputScript == transaction.inputs[0].script)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed check P2PKH script matching");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed check P2PKH input script matching");
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Result : %s",
              transaction.inputs[0].script.readHexString(transaction.inputs[0].script.length()).text());
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Correct : %s",
              inputScript.readHexString(inputScript.length()).text());
            success = false;
        }

        transaction.calculateHash();

        NextCash::HashList checkHashes;
        if(ScriptInterpreter::parseOutputScript(spendable.outputs[0].script, checkHashes) == ScriptInterpreter::P2PKH)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed check P2PKH script");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed check P2PKH script");
            success = false;
        }

        if(checkHashes.size() != 1 || privateKey1.hash() == checkHashes.front())
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
        if(!interpreter.process(transaction.inputs[0].script, 4, forks, 0))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            spendable.outputs[0].script.setReadOffset(0);
            if(!interpreter.process(spendable.outputs[0].script, 4, forks, 0))
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
        transaction.addInput(spendable.hash(), 0);

        // Add output
        transaction.addP2PKHOutput(privateKey2.hash(), 50000);

        // Sign the input
        if(!transaction.signP2PKHInput(forks, spendable.outputs[0], 0, privateKey2,
          Signature::ALL))
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

        if(checkHashes.size() != 1 || privateKey1.hash() == checkHashes.front())
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
        // if(!interpreter.process(transaction.inputs[0]->script, 4, forks, 0))
        // {
            // NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            // success = false;
        // }
        // else
        // {
            // spendable.outputs[0]->script.setReadOffset(0);
            // if(!interpreter.process(spendable.outputs[0]->script, 4, forks, 0))
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
        transaction.addInput(spendable3.hash(), 0);

        // Add output
        transaction.addP2PKHOutput(privateKey2.hash(), 50000);

        // Sign the input with the wrong output
        if(transaction.signP2PKHInput(forks, spendable3.outputs[0], 0, privateKey3,
          Signature::ALL))
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME,
              "Passed P2PKH sign with wrong private key");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed P2PKH sign with wrong private key");
            success = false;
        }

        transaction.inputs[0].script.setReadOffset(0);
        transaction.calculateHash();
        //NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
        //  "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0].script.setReadOffset(0);
        interpreter.initialize(&transaction, 0, transaction.inputs[0].sequence, spendable.outputs[0].amount);
        if(!interpreter.process(transaction.inputs[0].script, 4, forks, 0))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed to process signature script");
            success = false;
        }
        else
        {
            spendable.outputs[0].script.setReadOffset(0);
            if(!interpreter.process(spendable.outputs[0].script, 4, forks, 0))
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
                  "Failed to process UTXO script");
                success = false;
            }
            else
            {
                if(interpreter.isValid() && !interpreter.isVerified())
                    NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME,
                      "Passed process P2PKH transaction bad sig");
                else
                {
                    NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
                      "Failed process P2PKH transaction bad sig");
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

        interpreter.clear();
        transaction.clear();

        // Add input
        transaction.addInput(spendable.hash(), 0);

        // Add output
        transaction.addP2PKHOutput(privateKey2.hash(), 50000);

        // Create signature script
        redeemScript.setReadOffset(0);
        if(transaction.authorizeP2SHInput(spendable.outputs[0], 0, redeemScript))
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME,
              "Passed sign P2SH script");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed sign P2SH script");
            success = false;
        }

        if(ScriptInterpreter::parseOutputScript(spendable.outputs[0].script, checkHashes) ==
          ScriptInterpreter::P2SH)
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME,
              "Passed check P2SH script");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed check P2SH script");
            success = false;
        }

        if(checkHashes.size() != 1 || redeemHash == checkHashes.front())
            NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME,
              "Passed check P2SH script hash");
        else
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed check P2SH script hash");
            success = false;
        }

        transaction.inputs[0].script.setReadOffset(0);
        transaction.calculateHash();
        //NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
        //  "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0].script.setReadOffset(0);
        interpreter.initialize(&transaction, 0, transaction.inputs[0].sequence,
          spendable.outputs[0].amount);
        if(!interpreter.process(transaction.inputs[0].script, 4, forks, 0))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
              "Failed to process signature script");
            success = false;
        }
        else
        {
            spendable.outputs[0].script.setReadOffset(0);
            if(!interpreter.process(spendable.outputs[0].script, 4, forks, 0))
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
                  "Failed to process UTXO script");
                success = false;
            }
            else
            {
                if(interpreter.isValid() && interpreter.isVerified())
                    NextCash::Log::add(NextCash::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME,
                      "Passed process valid P2SH transaction");
                else
                {
                    NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
                      "Failed process valid P2SH transaction");
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

        publicKeys.push_back(privateKey1.publicKey());
        publicKeys.push_back(privateKey2.publicKey());
        testOutHash.randomize();

        spendable.addMultiSigOutput(1, publicKeys, 51000);
        spendable.calculateHash();

        transaction.addInput(spendable.hash(), 0);
        transaction.addP2PKHOutput(testOutHash, 50000);

        bool signatureAdded, transactionComplete;

        if(transaction.addMultiSigInputSignature(spendable.outputs[0], 0, privateKey1,
          *privateKey1.publicKey(), Signature::ALL, forks, signatureAdded, transactionComplete))
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
        if(!interpreter.process(transaction.inputs[0].script, 4, forks, 0))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process MULTISIG 1 of 2 input script");
            success = false;
        }
        else
        {
            spendable.outputs[0].script.setReadOffset(0);
            if(!interpreter.process(spendable.outputs[0].script, 4, forks, 0))
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

        publicKeys.clear();
        publicKeys.push_back(privateKey1.publicKey());
        publicKeys.push_back(privateKey2.publicKey());
        publicKeys.push_back(privateKey3.publicKey());

        spendable.addMultiSigOutput(2, publicKeys, 51000);
        spendable.calculateHash();

        transaction.addInput(spendable.hash(), 0);
        transaction.addP2PKHOutput(testOutHash, 50000);

        if(transaction.addMultiSigInputSignature(spendable.outputs[0], 0, privateKey2,
          *privateKey2.publicKey(), Signature::ALL, forks, signatureAdded, transactionComplete))
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
          *privateKey2.publicKey(), Signature::ALL, forks, signatureAdded, transactionComplete))
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
          *privateKey1.publicKey(), Signature::ALL, forks, signatureAdded, transactionComplete))
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
        if(!interpreter.process(transaction.inputs[0].script, 4, forks, 0))
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process MULTISIG 2 of 3 input script");
            success = false;
        }
        else
        {
            spendable.outputs[0].script.setReadOffset(0);
            if(!interpreter.process(spendable.outputs[0].script, 4, forks, 0))
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
