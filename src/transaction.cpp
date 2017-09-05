#include "transaction.hpp"

#include "arcmist/base/endian.hpp"
#include "arcmist/base/math.hpp"
#include "arcmist/base/log.hpp"
#include "arcmist/crypto/digest.hpp"
#include "interpreter.hpp"

#define BITCOIN_TRANSACTION_LOG_NAME "BitCoin Transaction"


namespace BitCoin
{
    // Transaction &Transaction::operator = (const Transaction &pRight)
    // {
        // hash = pRight.hash;
        // version = pRight.version;
        // lockTime = pRight.lockTime;

        // for(std::vector<Input *>::const_iterator i=pRight.inputs.begin();i!=pRight.inputs.end();++i)
            // inputs.push_back(new Input(**i));
        // for(std::vector<Output *>::const_iterator i=pRight.outputs.begin();i!=pRight.outputs.end();++i)
            // outputs.push_back(new Output(**i));

        // return *this;
    // }

    Transaction::~Transaction()
    {
        for(unsigned int i=0;i<mUnspents.size();i++)
            if(mUnspents[i] != NULL)
                delete mUnspents[i];
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
        version = 1;
        mFee = 0;
        lockTime = 0xffffffff;

        for(unsigned int i=0;i<mUnspents.size();i++)
            delete mUnspents[i];
        mUnspents.clear();
        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
            delete (*input);
        inputs.clear();
        for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
            delete (*output);
        outputs.clear();
    }

    void Transaction::print(ArcMist::Log::Level pLevel)
    {
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Hash      : %s", hash.hex().text());
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Version   : %d", version);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "Lock Time : %08x", lockTime);

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
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Outpoint Index : %08x", outpoint.index);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Sequence       : %08x", sequence);
        script.setReadOffset(0);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Script         : (%d bytes)",script.length());
        ScriptInterpreter::printScript(script, pLevel);
    }

    void Output::print(ArcMist::Log::Level pLevel)
    {
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Amount : %.08f", bitcoins(amount));
        script.setReadOffset(0);
        ArcMist::Log::addFormatted(pLevel, BITCOIN_TRANSACTION_LOG_NAME, "  Script : (%d bytes)", script.length());
        ScriptInterpreter::printScript(script, pLevel);
    }

    // P2PKH only
    bool Transaction::addP2PKHInput(Unspent *pUnspent, PrivateKey &pPrivateKey, PublicKey &pPublicKey)
    {
        // Test unspent script type
        Hash test;
        if(ScriptInterpreter::parseOutputScript(pUnspent->script, test) != ScriptInterpreter::P2PKH)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Unspent script is not P2PKH");
            return false;
        }

        Input *newInput = new Input();
        inputs.push_back(newInput);

        // Link input to unspent
        newInput->outpoint.transactionID = pUnspent->transactionID;
        newInput->outpoint.index = pUnspent->index;

        // Create signature script for unspent
        if(!ScriptInterpreter::writeP2PKHSignatureScript(pPrivateKey, pPublicKey, *this, inputs.size() - 1, pUnspent->script,
          Signature::ALL, &newInput->script))
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
    bool Transaction::addP2SHInput(Unspent *pUnspent, ArcMist::Buffer &pRedeemScript)
    {
        // Test unspent script type
        Hash test;
        if(ScriptInterpreter::parseOutputScript(pUnspent->script, test) != ScriptInterpreter::P2SH)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Unspent script is not P2SH");
            return false;
        }

        Input *newInput = new Input();

        // Create signature script for unspent
        ScriptInterpreter::writeP2SHSignatureScript(pRedeemScript, &newInput->script);

        // Link input to unspent
        newInput->outpoint.transactionID = pUnspent->transactionID;
        newInput->outpoint.index = pUnspent->index;

        inputs.push_back(newInput);
        return true;
    }

    bool Transaction::process(UnspentPool &pUnspentPool, uint64_t pBlockHeight, bool pCoinBase, uint32_t pBlockVersion)
    {
        ScriptInterpreter interpreter;
        Unspent *unspent = NULL;
        std::vector<Unspent *> spents;

        mUnspents.clear();
        mFee = 0;

        // Process Inputs
        unsigned int index = 0;
        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            if(pCoinBase)
            {
                if((*input)->outpoint.index != 0xffffffff)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Coinbase Input %d outpoint index is not 0xffffff : %08x", index+1, (*input)->outpoint.index);
                    return false;
                }

                /* BIP34 Block version 2 - Requires block height in coinbase input script
                 *   Reject version 2 blocks without block height at block 224,412
                 *   Reject version 1 blocks at block 227,930
                 */
                if((pBlockVersion == 2 && pBlockHeight >= 224412) || pBlockVersion > 2)
                {
                    interpreter.clear();
                    interpreter.setTransaction(this);
                    interpreter.setInputOffset(index);

                    // Process signature script
                    (*input)->script.setReadOffset(0);
                    if(!interpreter.process((*input)->script, true, pBlockVersion >= 3))
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d signature script failed", index+1);
                        return false;
                    }

                    int blockHeight = interpreter.readStackUnsignedInt();
                    if(blockHeight != (int)pBlockHeight)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                          "Version 2 block with non matching block height after 224,412 : actual %d, specified %d",
                          pBlockHeight, blockHeight);
                        return false;
                    }
                }
            }
            else
            {
                // Find unspent transaction for input
                unspent = pUnspentPool.find((*input)->outpoint.transactionID, (*input)->outpoint.index);
                if(unspent == NULL)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d outpoint transaction not found : trans %s output %d", index+1,
                      (*input)->outpoint.transactionID.hex().text(), (*input)->outpoint.index + 1);
                    return false;
                }

                spents.push_back(unspent);

                interpreter.clear();
                interpreter.setTransaction(this);
                interpreter.setInputOffset(index);

                // Process signature script
                //ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME, "Input %d script : ", index+1);
                //(*input)->script.setReadOffset(0);
                //ScriptInterpreter::printScript((*input)->script, ArcMist::Log::DEBUG);
                (*input)->script.setReadOffset(0);
                if(!interpreter.process((*input)->script, true, pBlockVersion >= 3))
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d signature script failed : ", index+1);
                    (*input)->print(ArcMist::Log::VERBOSE);
                    return false;
                }

                // Add unspent transaction script
                if(unspent != NULL)
                {
                    //ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME, "Unspent script : ");
                    //unspent->script.setReadOffset(0);
                    //ScriptInterpreter::printScript(unspent->script, ArcMist::Log::DEBUG);
                    unspent->script.setReadOffset(0);
                    if(!interpreter.process(unspent->script, false, pBlockVersion >= 3))
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                          "Input %d unspent script failed : ", index+1);
                        (*input)->print(ArcMist::Log::VERBOSE);
                        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Unspent :");
                        unspent->print(ArcMist::Log::VERBOSE);
                        return false;
                    }
                }

                if(!interpreter.isValid())
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d script is not valid : ", index+1);
                    (*input)->print(ArcMist::Log::VERBOSE);
                    if(unspent != NULL)
                    {
                        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Unspent :");
                        unspent->print(ArcMist::Log::VERBOSE);
                    }
                    return false;
                }

                if(!interpreter.isVerified())
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d script did not verify : ", index+1);
                    (*input)->print(ArcMist::Log::VERBOSE);
                    interpreter.printStack("After fail verify");
                    if(unspent != NULL)
                    {
                        ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Unspent :");
                        unspent->print(ArcMist::Log::VERBOSE);

                        unspent->script.setReadOffset(0);
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Unspent Script Raw : %s", unspent->script.readHexString(unspent->script.length()).text());

                    }
                    return false;
                }

                mFee += unspent->amount;
            }

            ++index;
        }

        // Process Outputs
        index = 0;
        for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
        {
            if((*output)->amount < 0)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                  "Output %d amount is negative %d : ", index+1, (*output)->amount);
                (*output)->print(ArcMist::Log::VERBOSE);
                return false;
            }

            unspent = new Unspent();
            unspent->amount = (*output)->amount;
            unspent->script = (*output)->script;
            unspent->script.compact();
            unspent->transactionID = hash;
            unspent->index = index;
            unspent->height = pBlockHeight;
            ScriptInterpreter::parseOutputScript(unspent->script, unspent->hash);
            mUnspents.push_back(unspent);

            if(!pCoinBase && (*output)->amount > 0 && (*output)->amount > mFee)
            {
                ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME, "Outputs are more than inputs");
                return false;
            }

            mFee -= (*output)->amount;
            ++index;
        }

        for(std::vector<Unspent *>::iterator unspent=mUnspents.begin();unspent!=mUnspents.end();++unspent)
            pUnspentPool.add(**unspent);

        for(std::vector<Unspent *>::iterator unspent=spents.begin();unspent!=spents.end();++unspent)
            pUnspentPool.spend(*unspent);

        return true;
    }

    unsigned int Transaction::size()
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
        unsigned int currentSize = size();
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
        script.writeStream(pStream, bytes);

        if(pStream->remaining() < 4)
            return false;
        sequence = pStream->readUnsignedInt();

        return true;
    }

    void Output::write(ArcMist::OutputStream *pStream)
    {
        pStream->writeLong(amount);
        writeCompactInteger(pStream, script.length());
        script.setReadOffset(0);
        pStream->writeStream(&script, script.length());
    }

    bool Output::read(ArcMist::InputStream *pStream)
    {
        if(pStream->remaining() < 8)
            return false;

        amount = pStream->readUnsignedLong();

        uint64_t bytes = readCompactInteger(pStream);
        if(pStream->remaining() < bytes)
            return false;
        script.clear();
        script.setSize(bytes);
        script.writeStream(pStream, bytes);

        return true;
    }

    void Transaction::write(ArcMist::OutputStream *pStream)
    {
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
            (*output)->write(pStream);

        // Lock Time
        pStream->writeUnsignedInt(lockTime);
    }

    bool Input::writeSignatureData(ArcMist::OutputStream *pStream, ArcMist::Buffer *pSubScript)
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
        pStream->writeUnsignedInt(sequence);
        return true;
    }

    bool Transaction::writeSignatureData(ArcMist::OutputStream *pStream, unsigned int pInputOffset,
      ArcMist::Buffer &pOutputScript, Signature::HashType pHashType)
    {
        if(pHashType != Signature::ALL)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME,
              "Unsupported signature hash type : %d", pHashType);
            return false;
        }

        // Build subscript from unspent/output script
        ArcMist::Buffer subScript;
        ScriptInterpreter::removeCodeSeparators(pOutputScript, subScript);

        // Version
        pStream->writeUnsignedInt(version);

        // Input Count
        writeCompactInteger(pStream, inputs.size());

        // Inputs
        unsigned int offset = 0;
        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            if(pInputOffset == offset++)
                (*input)->writeSignatureData(pStream, &subScript);
            else
                (*input)->writeSignatureData(pStream, NULL);
        }

        // Output Count
        writeCompactInteger(pStream, outputs.size());

        // Outputs
        for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
            (*output)->write(pStream);

        // Lock Time
        pStream->writeUnsignedInt(lockTime);

        // Add signature hash type to the end as a 32 bit value
        pStream->writeUnsignedInt(pHashType);

        return true;
    }

    bool Transaction::read(ArcMist::InputStream *pStream, bool pCalculateHash)
    {
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
            if(!(*output)->read(pStream))
            {
                if(digest != NULL)
                    delete digest;
                return false;
            }
            else if(pCalculateHash)
                (*output)->write(digest);
        }

        if(pStream->remaining() < 4)
        {
            if(digest != NULL)
                delete digest;
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
        KeyContext context;
        PrivateKey privateKey1(&context);
        PublicKey publicKey1(&context);
        Hash transactionHash(20);
        Signature signature(&context);
        PrivateKey privateKey2(&context);
        PublicKey publicKey2(&context);
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

        // Create unspent (so we can spend it)
        Unspent *unspent = new Unspent();

        unspent->amount = 51000;
        ScriptInterpreter::writeP2PKHPublicKeyScript(publicKey1.hash(), &unspent->script);
        unspent->transactionID.setSize(32);
        unspent->transactionID.randomize();
        unspent->index = 0;
        unspent->hash = publicKey1.hash();

        //UnspentPool::instance().add(&unspent);

        // Create Transaction
        Transaction transaction;

        // Add input
        transaction.inputs.push_back(new Input());

        // Setup outpoint of input
        transaction.inputs[0]->outpoint.transactionID = unspent->transactionID;
        transaction.inputs[0]->outpoint.index = unspent->index; // First output of transaction

        // Add output
        transaction.outputs.push_back(new Output());
        transaction.outputs[0]->amount = 50000;

        /***********************************************************************************************
         * Process Valid P2PKH Transaction
         ***********************************************************************************************/
        // Create public key script to pay the third public key
        ScriptInterpreter::writeP2PKHPublicKeyScript(publicKey2.hash(), &transaction.outputs[0]->script);

        // Create signature script
        ScriptInterpreter::writeP2PKHSignatureScript(privateKey1, publicKey1, transaction, 0, unspent->script,
          Signature::ALL, &transaction.inputs[0]->script);

        transaction.calculateHash();

        // Process the script
        ScriptInterpreter interpreter;

        //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0]->script.setReadOffset(0);
        interpreter.setTransaction(&transaction);
        interpreter.setInputOffset(0);
        if(!interpreter.process(transaction.inputs[0]->script, true))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            unspent->script.setReadOffset(0);
            if(!interpreter.process(unspent->script, false))
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process unspent script");
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
        ScriptInterpreter::writeP2PKHSignatureScript(privateKey1, publicKey2, transaction, 0, unspent->script,
          Signature::ALL, &transaction.inputs[0]->script);

        transaction.inputs[0]->script.setReadOffset(0);
        transaction.calculateHash();
        //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0]->script.setReadOffset(0);
        interpreter.setTransaction(&transaction);
        if(!interpreter.process(transaction.inputs[0]->script, true))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            unspent->script.setReadOffset(0);
            if(!interpreter.process(unspent->script, false))
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process unspent script");
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
        ScriptInterpreter::writeP2PKHSignatureScript(privateKey2, publicKey1, transaction, 0, unspent->script,
          Signature::ALL, &transaction.inputs[0]->script);

        transaction.inputs[0]->script.setReadOffset(0);
        transaction.calculateHash();
        //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0]->script.setReadOffset(0);
        interpreter.setTransaction(&transaction);
        if(!interpreter.process(transaction.inputs[0]->script, true))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            unspent->script.setReadOffset(0);
            if(!interpreter.process(unspent->script, false))
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process unspent script");
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

        unspent->amount = 51000;
        unspent->script.clear();
        ScriptInterpreter::writeP2SHPublicKeyScript(redeemHash, &unspent->script);
        unspent->transactionID.setSize(32);
        unspent->transactionID.randomize();
        unspent->index = 0;
        unspent->hash = publicKey1.hash();

        // Create signature script
        transaction.inputs[0]->script.clear();
        redeemScript.setReadOffset(0);
        ScriptInterpreter::writeP2SHSignatureScript(redeemScript, &transaction.inputs[0]->script);

        transaction.inputs[0]->script.setReadOffset(0);
        transaction.calculateHash();
        //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0]->script.setReadOffset(0);
        interpreter.setTransaction(&transaction);
        if(!interpreter.process(transaction.inputs[0]->script, true))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            unspent->script.setReadOffset(0);
            if(!interpreter.process(unspent->script, false))
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process unspent script");
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
