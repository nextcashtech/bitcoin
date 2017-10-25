/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "transaction.hpp"

#ifdef PROFILER_ON
#include "arcmist/dev/profiler.hpp"
#endif

#include "arcmist/base/endian.hpp"
#include "arcmist/base/math.hpp"
#include "arcmist/base/log.hpp"
#include "arcmist/crypto/digest.hpp"
#include "interpreter.hpp"
#include "block.hpp"

#define BITCOIN_TRANSACTION_LOG_NAME "BitCoin Transaction"


namespace BitCoin
{
    Transaction::~Transaction()
    {
        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
            if((*input) != NULL)
                delete (*input);
        for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
            if((*output) != NULL)
                delete (*output);
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

        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
            delete (*input);
        inputs.clear();
        for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
            delete (*output);
        outputs.clear();
    }

    void Transaction::clearCache()
    {
        mOutpointHash.clear();
        mSequenceHash.clear();
        mOutputHash.clear();
    }

    void Transaction::print(ArcMist::Log::Level pLevel)
    {
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Hash      : %s", hash.hex().text());
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Version   : %d", version);
        if(lockTime > LOCKTIME_THRESHOLD)
        {
            ArcMist::String lockTimeText;
            lockTimeText.writeFormattedTime(lockTime);
            ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME,
              "Lock Time : time stamp %d - %s", lockTime, lockTimeText.text());
        }
        else
            ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME,
              "Lock Time : block height %d", lockTime);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Fee       : %f", bitcoins(mFee));

        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "%d Inputs", inputs.size());
        unsigned int index = 1;
        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Input %d", index++);
            (*input)->print(pLevel);
        }

        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "%d Outputs", outputs.size());
        index = 1;
        for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
        {
            ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Output %d", index++);
            (*output)->print(pLevel);
        }
    }

    void Input::print(ArcMist::Log::Level pLevel)
    {
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Outpoint Trans : %s", outpoint.transactionID.hex().text());
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Outpoint Index : 0x%08x", outpoint.index);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Sequence       : 0x%08x", sequence);
        script.setReadOffset(0);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Script         : (%d bytes)",script.length());
        ScriptInterpreter::printScript(script, pLevel);
    }

    // P2PKH only
    bool Transaction::addP2PKHInput(const Hash &pTransactionID, unsigned int pIndex, Output &pOutput, PrivateKey &pPrivateKey,
      PublicKey &pPublicKey, const Forks &pForks)
    {
        // Test unspent transaction output script type
        Hash test;
        if(ScriptInterpreter::parseOutputScript(pOutput.script, test) != ScriptInterpreter::P2PKH)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Unspent script is not P2PKH");
            return false;
        }

        Input *newInput = new Input();
        inputs.push_back(newInput);

        // Link input to unspent
        newInput->outpoint.transactionID = pTransactionID;
        newInput->outpoint.index = pIndex;

        // Create signature script for unspent
        if(!ScriptInterpreter::writeP2PKHSignatureScript(pPrivateKey, pPublicKey, *this, inputs.size() - 1, pOutput.amount,
          pOutput.script, Signature::ALL, &newInput->script, pForks))
        {
            delete newInput;
            return false;
        }

        return true;
    }

    // P2PKH only
    bool Transaction::addP2PKHOutput(Hash pPublicKeyHash, uint64_t pAmount)
    {
        Output *newOutput = new Output();
        newOutput->amount = pAmount;
        ScriptInterpreter::writeP2PKHPublicKeyScript(pPublicKeyHash, &newOutput->script);
        outputs.push_back(newOutput);
        return true;
    }

    // P2SH only
    bool Transaction::addP2SHInput(const Hash &pTransactionID, unsigned int pIndex, Output &pOutput, ArcMist::Buffer &pRedeemScript)
    {
        // Test unspent transaction output script type
        Hash test;
        if(ScriptInterpreter::parseOutputScript(pOutput.script, test) != ScriptInterpreter::P2SH)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Unspent script is not P2SH");
            return false;
        }

        Input *newInput = new Input();

        // Create signature script for unspent transaction output
        ScriptInterpreter::writeP2SHSignatureScript(pRedeemScript, &newInput->script);

        // Link input to unspent transaction output
        newInput->outpoint.transactionID = pTransactionID;
        newInput->outpoint.index = pIndex;

        inputs.push_back(newInput);
        return true;
    }

    bool Transaction::updateOutputs(TransactionOutputPool &pOutputs, const std::vector<Transaction *> &pBlockTransactions,
      uint64_t pBlockHeight, std::vector<unsigned int> &pSpentAges)
    {
        if(inputs.size() == 0)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Zero inputs");
            return false;
        }

        if(outputs.size() == 0)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Zero outputs");
            return false;
        }

        // Process Inputs
        TransactionReference *reference;
        unsigned int index = 0;
        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            if((*input)->outpoint.index != 0xffffffff)
            {
                // Find unspent transaction for input
                reference = pOutputs.findUnspent((*input)->outpoint.transactionID, (*input)->outpoint.index);

                if(reference == NULL)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d outpoint transaction not found : trans %s index %d", index + 1,
                      (*input)->outpoint.transactionID.hex().text(), (*input)->outpoint.index);
                    return false;
                }

                pSpentAges.push_back(pBlockHeight - reference->blockHeight);

                pOutputs.spend(reference, (*input)->outpoint.index, pBlockHeight);
            }

            ++index;
        }

        return true;
    }

    bool Transaction::process(TransactionOutputPool &pOutputs, const std::vector<Transaction *> &pBlockTransactions,
      uint64_t pBlockHeight, bool pCoinBase, int32_t pBlockVersion, const BlockStats &pBlockStats,
      const Forks &pForks, std::vector<unsigned int> &pSpentAges)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Transaction Process");
        ArcMist::Profiler verifyProfiler("Transaction Inputs", false);
#endif
        mFee = 0;

        if(inputs.size() == 0)
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME, "Zero inputs");
            return false;
        }
        else if(pCoinBase && inputs.size() != 1)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
              "Coinbase has more than one input : %d", inputs.size());
            return false;
        }

        if(outputs.size() == 0)
        {
            ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME, "Zero outputs");
            return false;
        }

        // Process Inputs
        ScriptInterpreter interpreter;
        TransactionReference *reference;
        Output output;
        unsigned int index = 0;
        bool sequenceFound = false;
        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            if(pCoinBase)
            {
                if((*input)->outpoint.index != 0xffffffff)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Coinbase Input %d outpoint index is not 0xffffffff : %08x", index+1, (*input)->outpoint.index);
                    return false;
                }

                // BIP-0034
                if(pBlockVersion >= 2 && pForks.enabledVersion() >= 2)
                {
                    interpreter.clear();
                    interpreter.setTransaction(this);
                    interpreter.setInputOffset(index);

                    // Read block height
                    (*input)->script.setReadOffset(0);
                    int64_t blockHeight = interpreter.readFirstPushOpValue((*input)->script);
                    if(blockHeight < 0 || (uint64_t)blockHeight != pBlockHeight)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Non matching coinbase block height : actual %d, coinbase %d",
                          pBlockHeight, blockHeight);
                        return false;
                    }
                }
            }
            else
            {
                // Find unspent transaction for input
                reference = pOutputs.findUnspent((*input)->outpoint.transactionID, (*input)->outpoint.index);
                if(reference == NULL)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d outpoint not found : index %d trans %s", index + 1,
                      (*input)->outpoint.index, (*input)->outpoint.transactionID.hex().text());
                    return false;
                }

                pSpentAges.push_back(pBlockHeight - reference->blockHeight);

                if(reference->blockHeight == pBlockHeight)
                {
                    // Get output from this block
                    bool found = false;
                    for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
                        if(*transaction == this)
                            break; // Only use transactions before this one
                        else if((*transaction)->hash == reference->id)
                        {
                            found = true;
                            output = *(*transaction)->outputs.at((*input)->outpoint.index);
                            break;
                        }

                    if(!found)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d outpoint transaction not found in current block : index %d trans %s", index + 1,
                          (*input)->outpoint.index, (*input)->outpoint.transactionID.hex().text());
                        reference->print(ArcMist::Log::WARNING);
                        return false;
                    }
                }
                else if(!BlockFile::readOutput(reference, (*input)->outpoint.index, output))
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d outpoint transaction failed to read : index %d trans %s", index + 1,
                      (*input)->outpoint.index, (*input)->outpoint.transactionID.hex().text());
                    reference->print(ArcMist::Log::WARNING);
                    return false;
                }

#ifdef PROFILER_ON
                verifyProfiler.start();
#endif
                // BIP-0068 Relative time lock sequence
                if(version >= 2 && !(*input)->sequenceDisabled() &&
                  pForks.softForkState(SoftFork::BIP0068) == SoftFork::ACTIVE)
                {
                    // Sequence is an encoded relative time lock
                    uint32_t lock = (*input)->sequence & Input::SEQUENCE_LOCKTIME_MASK;
                    if((*input)->sequence & Input::SEQUENCE_TYPE)
                    {
                        // Seconds since outpoint median past time in units of 512 seconds granularity
                        lock <<= 9;
                        uint32_t currentBlockMedianTime = pBlockStats.getMedianPastTime(pBlockHeight, 11);
                        uint32_t spentBlockMedianTime = pBlockStats.getMedianPastTime(reference->blockHeight, 11);
                        if(currentBlockMedianTime < spentBlockMedianTime + lock)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                              "Input %d sequence not valid. Required spent block time age %d, actual %d : index %d trans %s",
                              index + 1, lock, currentBlockMedianTime - spentBlockMedianTime,
                              (*input)->outpoint.index, (*input)->outpoint.transactionID.hex().text());
                            ArcMist::String timeText;
                            timeText.writeFormattedTime(spentBlockMedianTime + lock);
                            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                              "Not valid until median block time %s", timeText.text());
                            reference->print(ArcMist::Log::WARNING);
#ifdef PROFILER_ON
                            verifyProfiler.stop();
#endif
                            return false;
                        }
                    }
                    else if(pBlockHeight < reference->blockHeight + lock) // Number of blocks since outpoint
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d sequence not valid. Required block height age %d. actual %d : index %d trans %s",
                          index + 1, lock, pBlockHeight - reference->blockHeight,
                          (*input)->outpoint.index, (*input)->outpoint.transactionID.hex().text());
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Not valid until block %d", reference->blockHeight + lock);
                        reference->print(ArcMist::Log::WARNING);
#ifdef PROFILER_ON
                        verifyProfiler.stop();
#endif
                        return false;
                    }
                }

                if((*input)->sequence != 0xffffffff)
                    sequenceFound = true;

                pOutputs.spend(reference, (*input)->outpoint.index, pBlockHeight);
                // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  // "Transaction %s Input %d spent transaction output %s index %d", hash.hex().text(), index + 1,
                  // (*input)->outpoint.transactionID.hex().text(), (*input)->outpoint.index);

                //TODO If transaction output is in this block then it won't be available through the previous function

                interpreter.clear();
                interpreter.setTransaction(this);
                interpreter.setInputOffset(index);
                interpreter.setInputSequence((*input)->sequence);
                interpreter.setOutputAmount(output.amount);

                // Process signature script
                //ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME, "Input %d script : ", index+1);
                //(*input)->script.setReadOffset(0);
                //ScriptInterpreter::printScript((*input)->script, ArcMist::Log::DEBUG);
                (*input)->script.setReadOffset(0);
                if(!interpreter.process((*input)->script, true, pBlockVersion, pForks))
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d signature script failed : ", index+1);
                    (*input)->print(ArcMist::Log::WARNING);
                    reference->print(ArcMist::Log::WARNING);
#ifdef PROFILER_ON
                    verifyProfiler.stop();
#endif
                    return false;
                }

                // Process unspent transaction output script
                //ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME, "UTXO script : ");
                //output.script.setReadOffset(0);
                //ScriptInterpreter::printScript(output.script, ArcMist::Log::DEBUG);
                output.script.setReadOffset(0);
                if(!interpreter.process(output.script, false, pBlockVersion, pForks))
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d unspent transaction output script failed : ", index + 1);
                    (*input)->print(ArcMist::Log::WARNING);
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME, "UTXO :");
                    reference->print(ArcMist::Log::WARNING);
                    output.print(ArcMist::Log::WARNING);
#ifdef PROFILER_ON
                    verifyProfiler.stop();
#endif
                    return false;
                }

                if(!interpreter.isValid())
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d script is not valid : ", index+1);
                    (*input)->print(ArcMist::Log::WARNING);
                    interpreter.printStack("After fail validate");
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME, "UTXO :");
                    reference->print(ArcMist::Log::WARNING);
                    output.print(ArcMist::Log::WARNING);
#ifdef PROFILER_ON
                    verifyProfiler.stop();
#endif
                    return false;
                }

                if(!interpreter.isVerified())
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d script did not verify : ", index+1);
                    (*input)->print(ArcMist::Log::WARNING);
                    interpreter.printStack("After fail verify");
                    ArcMist::Log::add(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME, "UTXO :");
                    reference->print(ArcMist::Log::WARNING);
                    output.print(ArcMist::Log::WARNING);
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
                    if(lockTime > pBlockStats.getMedianPastTime(pBlockHeight, 11))
                    {
                        ArcMist::String lockTimeText, blockTimeText;
                        lockTimeText.writeFormattedTime(lockTime);
                        blockTimeText.writeFormattedTime(pBlockStats.getMedianPastTime(pBlockHeight, 11));
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Lock time stamp is not valid. Lock time %s > block median time %s",
                          lockTimeText.text(), blockTimeText.text());
                        print(ArcMist::Log::VERBOSE);
                        return false;
                    }
                }
                else
                {
                    // Add 600 to fake having a "peer time offset" for older blocks
                    //   Block 357903 transaction 98 has a lock time about 3 minutes after the block time
                    if(lockTime > pBlockStats.time(pBlockHeight) + 600)
                    {
                        ArcMist::String lockTimeText, blockTimeText;
                        lockTimeText.writeFormattedTime(lockTime);
                        blockTimeText.writeFormattedTime(pBlockStats.time(pBlockHeight));
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Lock time stamp is not valid. Lock time %s > block time %s",
                          lockTimeText.text(), blockTimeText.text());
                        print(ArcMist::Log::VERBOSE);
                        return false;
                    }
                }
            }
            else
            {
                // Lock time is a block height
                if(lockTime > pBlockHeight)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                      "Lock time block height is not valid. Lock height %d > block height %d",
                      lockTime, pBlockHeight);
                    print(ArcMist::Log::VERBOSE);
                    return false;
                }
            }
        }

#ifdef PROFILER_ON
        ArcMist::Profiler outputsProfiler("Transaction Outputs");
#endif
        // Process Outputs
        index = 0;
        for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
        {
            if((*output)->amount < 0)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                  "Output %d amount is negative %d : ", index + 1, (*output)->amount);
                (*output)->print(ArcMist::Log::WARNING);
                print(ArcMist::Log::VERBOSE);
                return false;
            }

            if(!pCoinBase && (*output)->amount > 0 && (*output)->amount > mFee)
            {
                ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME, "Outputs are more than inputs");
                print(ArcMist::Log::VERBOSE);
                return false;
            }

            mFee -= (*output)->amount;
            ++index;
        }

        clearCache();
        return true;
    }

    unsigned int Transaction::calculatedSize()
    {
        unsigned int result = 4; // Version

        // Input Count
        result += compactIntegerSize(inputs.size());

        // Inputs
        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
            result += (*input)->size();

        // Output Count
        result += compactIntegerSize(outputs.size());

        // Outputs
        for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
            result += (*output)->size();

        // Lock Time
        result += 4;

        return 4;
    }

    uint64_t Transaction::feeRate()
    {
        unsigned int currentSize = mSize;
        if(currentSize == 0)
            currentSize = calculatedSize();
        if(mFee < currentSize)
            return 0;
        else
            return currentSize / mFee;
    }

    void Outpoint::write(ArcMist::OutputStream *pStream)
    {
        transactionID.write(pStream);
        pStream->writeUnsignedInt(index);
    }

    bool Outpoint::read(ArcMist::InputStream *pStream)
    {
        if(!transactionID.read(pStream))
            return false;

        if(pStream->remaining() < 4)
            return false;
        index = pStream->readUnsignedInt();
        return true;
    }

    void Input::write(ArcMist::OutputStream *pStream)
    {
        outpoint.write(pStream);
        writeCompactInteger(pStream, script.length());
        script.setReadOffset(0);
        pStream->writeStream(&script, script.length());
        pStream->writeUnsignedInt(sequence);
    }

    bool Input::read(ArcMist::InputStream *pStream)
    {
        if(!outpoint.read(pStream))
            return false;

        uint64_t bytes = readCompactInteger(pStream);
        if(pStream->remaining() < bytes)
            return false;
        script.clear();
        script.setSize(bytes);
        script.writeStreamCompact(*pStream, bytes);

        if(pStream->remaining() < 4)
            return false;
        sequence = pStream->readUnsignedInt();

        return true;
    }

    void Transaction::write(ArcMist::OutputStream *pStream, bool pBlockFile)
    {
        unsigned int startOffset = pStream->writeOffset();
        mSize = 0;

        // Version
        pStream->writeUnsignedInt(version);

        // Input Count
        writeCompactInteger(pStream, inputs.size());

        // Inputs
        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
            (*input)->write(pStream);

        // Output Count
        writeCompactInteger(pStream, outputs.size());

        // Outputs
        for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
            (*output)->write(pStream, pBlockFile);

        // Lock Time
        pStream->writeUnsignedInt(lockTime);

        mSize = pStream->writeOffset() - startOffset;
    }

    bool Input::writeSignatureData(ArcMist::OutputStream *pStream, ArcMist::Buffer *pSubScript, bool pZeroSequence)
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

    bool Transaction::writeSignatureData(ArcMist::OutputStream *pStream, unsigned int pInputOffset,
      int64_t pOutputAmount, ArcMist::Buffer &pOutputScript, Signature::HashType pHashType, const Forks &pForks)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Transaction Sign Data");
#endif
        Signature::HashType hashType = pHashType;
        // Extract FORKID (0x40) flag from hash type
        bool forkID = hashType & Signature::FORKID;
        if(forkID)
            hashType = static_cast<Signature::HashType>(hashType ^ Signature::FORKID);
        // Extract ANYONECANPAY (0x80) flag from hash type
        bool anyoneCanPay = hashType & Signature::ANYONECANPAY;
        if(anyoneCanPay)
            hashType = static_cast<Signature::HashType>(hashType ^ Signature::ANYONECANPAY);

        // Verify bitcoin cash fork ID
        if(pForks.cashActive())
        {
            if(!forkID)
                return false;
        }
        else if(forkID)
            return false;

        if(forkID)
        {
            // BIP-0143 Signature Hash Algorithm
            Hash hash(32);
            ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
            digest.setOutputEndian(ArcMist::Endian::LITTLE);

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
                    for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
                        (*input)->outpoint.write(&digest);
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
                    for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
                        digest.writeUnsignedInt((*input)->sequence);
                    digest.getResult(&hash);
                    mSequenceHash = hash; // Save for next input
                }
            }
            hash.write(pStream);

            // Outpoint
            if(pInputOffset < inputs.size())
                inputs[pInputOffset]->outpoint.write(pStream);
            else
                return false;

            // Script Code
            writeCompactInteger(pStream, pOutputScript.remaining());
            pStream->writeStream(&pOutputScript, pOutputScript.remaining());

            // Value of Output
            pStream->writeLong(pOutputAmount);

            // Sequence
            if(pInputOffset < inputs.size())
                pStream->writeUnsignedInt(inputs[pInputOffset]->sequence);
            else
                return false;

            // Hash Outputs
            if(hashType == Signature::SINGLE)
            {
                if(pInputOffset < outputs.size())
                {
                    // Only output corresponding to this input
                    digest.initialize();
                    outputs[pInputOffset]->write(&digest);
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
                    for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
                        (*output)->write(&digest);
                    digest.getResult(&hash);
                    mOutputHash = hash; // Save for next input
                }
            }
            hash.write(pStream);

            // Lock Time
            pStream->writeUnsignedInt(lockTime);

            // Sig Hash Type
            pStream->writeUnsignedInt(pHashType);

            return true;
        }
        else
        {
            // Build subscript from unspent/output script
            unsigned int offset;
            ArcMist::Buffer subScript;
            ScriptInterpreter::removeCodeSeparators(pOutputScript, subScript);

            // Version
            pStream->writeUnsignedInt(version);

            switch(hashType)
            {
            default:
            case Signature::INVALID:
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME,
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
                for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
                {
                    if(pInputOffset == offset++)
                        (*input)->writeSignatureData(pStream, &subScript, false);
                    else if(!anyoneCanPay)
                        (*input)->writeSignatureData(pStream, NULL, false);
                }

                // Output Count
                writeCompactInteger(pStream, outputs.size());

                // Outputs
                for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
                    (*output)->write(pStream);

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
                for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
                {
                    if(pInputOffset == offset++)
                        (*input)->writeSignatureData(pStream, &subScript, false);
                    else if(!anyoneCanPay)
                        (*input)->writeSignatureData(pStream, NULL, true);
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
                for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
                {
                    if(pInputOffset == offset++)
                        (*input)->writeSignatureData(pStream, &subScript, false);
                    else if(!anyoneCanPay)
                        (*input)->writeSignatureData(pStream, NULL, true);
                }

                // Output Count (number of inputs)
                writeCompactInteger(pStream, pInputOffset + 1);

                // Outputs
                std::vector<Output *>::iterator output=outputs.begin();
                for(offset=0;offset<pInputOffset+1;offset++)
                    if(output!=outputs.end())
                    {
                        if(offset == pInputOffset)
                            (*output)->write(pStream);
                        else
                        {
                            // Write -1 amount output
                            pStream->writeLong(-1);
                            writeCompactInteger(pStream, 0);
                        }
                        ++output;
                    }
                    else
                        return false; // Invalid number of outputs

                break;
            }
            }

            // Lock Time
            pStream->writeUnsignedInt(lockTime);

            // Sig Hash Type
            pStream->writeUnsignedInt(pHashType);

            return true;
        }
    }

    bool Transaction::read(ArcMist::InputStream *pStream, bool pCalculateHash, bool pBlockFile)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Transaction Read");
#endif
        unsigned int startOffset = pStream->readOffset();
        mSize = 0;

        // Create hash
        ArcMist::Digest *digest = NULL;
        if(pCalculateHash)
        {
            digest = new ArcMist::Digest(ArcMist::Digest::SHA256_SHA256);
            digest->setOutputEndian(ArcMist::Endian::LITTLE);
        }
        hash.clear();

        if(pStream->remaining() < 5)
        {
            if(digest != NULL)
                delete digest;
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
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
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
              "Transaction read failed : stream remaining less than input count %d", count);
            return false;
        }

        // Inputs
        inputs.resize(count);
        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
            (*input) = NULL;
        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            (*input) = new Input();
            if(!(*input)->read(pStream))
            {
                if(digest != NULL)
                    delete digest;
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Transaction read failed : input read failed");
                return false;
            }
            else if(pCalculateHash)
                (*input)->write(digest);
        }

        // Output Count
        count = readCompactInteger(pStream);
        if(pCalculateHash)
            writeCompactInteger(digest, count);

        // Outputs
        outputs.resize(count);
        for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
            (*output) = NULL;
        for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
        {
            (*output) = new Output();
            if(!(*output)->read(pStream, pBlockFile))
            {
                if(digest != NULL)
                    delete digest;
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Transaction read failed : output read failed");
                return false;
            }
            else if(pCalculateHash)
                (*output)->write(digest);
        }

        if(pStream->remaining() < 4)
        {
            if(digest != NULL)
                delete digest;
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
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
        ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
        digest.setOutputEndian(ArcMist::Endian::LITTLE);
        write(&digest);

        digest.getResult(&hash);
    }

    bool Transaction::test()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME,
          "------------- Starting Transaction Tests -------------");

        bool success = true;
        PrivateKey privateKey1;
        PublicKey publicKey1;
        Hash transactionHash(20);
        Signature signature;
        PrivateKey privateKey2;
        PublicKey publicKey2;
        ArcMist::Buffer data;

        // Initialize private key
        data.writeHex("d68e0869df44615cc57f196208a896653e969f69960c6435f38ae47f6b6d082d");
        privateKey1.read(&data);

        // Initialize public key
        data.clear();
        data.writeHex("03077b2a0406db4b4e2cddbe9aca5e9f1a3cf039feb843992d05cc0b7a75046635");
        publicKey1.read(&data);

        // Initialize private key
        data.writeHex("4fd0a873dba1d74801f182013c5ae17c17213d333657047a6e6c5865f388a60a");
        privateKey2.read(&data);

        // Initialize public key
        data.clear();
        data.writeHex("03362365326bd230642290787f3ba93d6299392ac5d26cd66e300f140184521e9c");
        publicKey2.read(&data);

        // Create unspent transaction output (so we can spend it)
        Output output;
        Hash outputHash;

        output.amount = 51000;
        Hash publicKey1Hash;
        publicKey1.getHash(publicKey1Hash);
        ScriptInterpreter::writeP2PKHPublicKeyScript(publicKey1Hash, &output.script);
        outputHash.setSize(32);
        outputHash.randomize();

        // Create Transaction
        Transaction transaction;

        // Add input
        transaction.inputs.push_back(new Input());

        // Setup outpoint of input
        transaction.inputs[0]->outpoint.transactionID = outputHash;
        transaction.inputs[0]->outpoint.index = 0; // First output of transaction

        // Add output
        transaction.outputs.push_back(new Output());
        transaction.outputs[0]->amount = 50000;

        /***********************************************************************************************
         * Process Valid P2PKH Transaction
         ***********************************************************************************************/
        // Create public key script to pay the third public key
        Forks forks;
        Hash publicKey2Hash;
        publicKey2.getHash(publicKey2Hash);
        ScriptInterpreter::writeP2PKHPublicKeyScript(publicKey2Hash, &transaction.outputs[0]->script);

        // Create signature script
        ScriptInterpreter::writeP2PKHSignatureScript(privateKey1, publicKey1, transaction, 0, output.amount, output.script,
          Signature::ALL, &transaction.inputs[0]->script, forks);

        transaction.calculateHash();

        // Process the script
        ScriptInterpreter interpreter;

        //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0]->script.setReadOffset(0);
        interpreter.setTransaction(&transaction);
        interpreter.setInputOffset(0);
        interpreter.setInputSequence(transaction.inputs[0]->sequence);
        if(!interpreter.process(transaction.inputs[0]->script, true, 4, forks))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            output.script.setReadOffset(0);
            if(!interpreter.process(output.script, false, 4, forks))
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process UTXO script");
                success = false;
            }
            else
            {
                if(interpreter.isValid() && interpreter.isVerified())
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed process valid P2PKH transaction");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed process valid P2PKH transaction");
                    success = false;
                }
            }
        }

        /***********************************************************************************************
         * Process P2PKH Transaction with Bad PK
         ***********************************************************************************************/
        interpreter.clear();

        // Create signature script
        transaction.inputs[0]->script.clear();
        ScriptInterpreter::writeP2PKHSignatureScript(privateKey1, publicKey2, transaction, 0, output.amount, output.script,
          Signature::ALL, &transaction.inputs[0]->script, forks);

        transaction.inputs[0]->script.setReadOffset(0);
        transaction.calculateHash();
        //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0]->script.setReadOffset(0);
        interpreter.setTransaction(&transaction);
        interpreter.setInputSequence(transaction.inputs[0]->sequence);
        if(!interpreter.process(transaction.inputs[0]->script, true, 4, forks))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            output.script.setReadOffset(0);
            if(!interpreter.process(output.script, false, 4, forks))
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process UTXO script");
                success = false;
            }
            else
            {
                if(interpreter.isValid() && !interpreter.isVerified())
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed process P2PKH transaction with bad PK");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed process P2PKH transaction with bad PK ");
                    success = false;
                }
            }
        }

        /***********************************************************************************************
         * Process P2PKH Transaction with Bad Sig
         ***********************************************************************************************/
        interpreter.clear();

        // Create signature script
        transaction.inputs[0]->script.clear();
        ScriptInterpreter::writeP2PKHSignatureScript(privateKey2, publicKey1, transaction, 0, output.amount, output.script,
          Signature::ALL, &transaction.inputs[0]->script, forks);

        transaction.inputs[0]->script.setReadOffset(0);
        transaction.calculateHash();
        //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0]->script.setReadOffset(0);
        interpreter.setTransaction(&transaction);
        interpreter.setInputSequence(transaction.inputs[0]->sequence);
        if(!interpreter.process(transaction.inputs[0]->script, true, 4, forks))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            output.script.setReadOffset(0);
            if(!interpreter.process(output.script, false, 4, forks))
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process UTXO script");
                success = false;
            }
            else
            {
                if(interpreter.isValid() && !interpreter.isVerified())
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed process P2PKH transaction bad sig");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed process P2PKH transaction bad sig");
                    success = false;
                }
            }
        }

        /***********************************************************************************************
         * Process Valid P2SH Transaction
         ***********************************************************************************************/
        // Create random redeemScript
        ArcMist::Buffer redeemScript;
        for(unsigned int i=0;i<100;i+=4)
            redeemScript.writeUnsignedInt(ArcMist::Math::randomInt());

        // Create hash of redeemScript
        Hash redeemHash(20);
        ArcMist::Digest digest(ArcMist::Digest::SHA256_RIPEMD160);
        digest.writeStream(&redeemScript, redeemScript.length());
        digest.getResult(&redeemHash);

        output.amount = 51000;
        output.script.clear();
        ScriptInterpreter::writeP2SHPublicKeyScript(redeemHash, &output.script);
        outputHash.setSize(32);
        outputHash.randomize();

        // Create signature script
        transaction.inputs[0]->script.clear();
        redeemScript.setReadOffset(0);
        ScriptInterpreter::writeP2SHSignatureScript(redeemScript, &transaction.inputs[0]->script);

        transaction.inputs[0]->script.setReadOffset(0);
        transaction.calculateHash();
        //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0]->script.setReadOffset(0);
        interpreter.setTransaction(&transaction);
        interpreter.setInputSequence(transaction.inputs[0]->sequence);
        if(!interpreter.process(transaction.inputs[0]->script, true, 4, forks))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            output.script.setReadOffset(0);
            if(!interpreter.process(output.script, false, 4, forks))
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process UTXO script");
                success = false;
            }
            else
            {
                if(interpreter.isValid() && interpreter.isVerified())
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "Passed process valid P2SH transaction");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed process valid P2SH transaction");
                    success = false;
                }
            }
        }

        return success;
    }
}
