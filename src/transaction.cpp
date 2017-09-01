#include "transaction.hpp"

#include "arcmist/base/endian.hpp"
#include "arcmist/base/math.hpp"
#include "arcmist/base/log.hpp"
#include "arcmist/crypto/digest.hpp"
#include "interpreter.hpp"

#define BITCOIN_TRANSACTION_LOG_NAME "BitCoin Transaction"


namespace BitCoin
{
    Transaction::Transaction(const Transaction &pCopy)
    {
        version = pCopy.version;
        lockTime = pCopy.lockTime;
        hash = pCopy.hash;
        hash = pCopy.hash;

        for(std::vector<Input *>::const_iterator i=pCopy.inputs.begin();i!=pCopy.inputs.end();++i)
            inputs.push_back(new Input(**i));
        for(std::vector<Output *>::const_iterator i=pCopy.outputs.begin();i!=pCopy.outputs.end();++i)
            outputs.push_back(new Output(**i));
    }

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

    // P2PKH only
    bool Transaction::addP2PKHInput(Unspent *pUnspent, PrivateKey &pPrivateKey, PublicKey &pPublicKey)
    {
        // Test unspent script type
        Hash test;
        if(parseOutputScript(pUnspent->script, test) != P2PKH)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Unspent script is not P2PKH");
            return false;
        }

        Input *newInput = new Input();

        // Create signature script for unspent
        if(!writeP2PKHSignatureScript(pPrivateKey, pPublicKey, pUnspent->script, &newInput->script))
        {
            delete newInput;
            return false;
        }

        // Link input to unspent
        newInput->outpoint.transactionID = pUnspent->transactionID;
        newInput->outpoint.index = pUnspent->index;

        inputs.push_back(newInput);
        return true;
    }

    // P2PKH only
    bool Transaction::addP2PKHOutput(Hash pPublicKeyHash, uint64_t pAmount)
    {
        Output *newOutput = new Output();
        newOutput->amount = pAmount;
        writeP2PKHPublicKeyScript(pPublicKeyHash, &newOutput->script);
        outputs.push_back(newOutput);
        return true;
    }

    // P2SH only
    bool Transaction::addP2SHInput(Unspent *pUnspent, ArcMist::Buffer &pRedeemScript)
    {
        // Test unspent script type
        Hash test;
        if(parseOutputScript(pUnspent->script, test) != P2SH)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Unspent script is not P2SH");
            return false;
        }

        Input *newInput = new Input();

        // Create signature script for unspent
        writeP2SHSignatureScript(pRedeemScript, &newInput->script);

        // Link input to unspent
        newInput->outpoint.transactionID = pUnspent->transactionID;
        newInput->outpoint.index = pUnspent->index;

        inputs.push_back(newInput);
        return true;
    }

    bool Transaction::process(UnspentPool &pUnspentPool, uint64_t pBlockHeight, bool pCoinBase)
    {
        ScriptInterpreter interpreter;
        Unspent *unspent = NULL;
        std::vector<Unspent *> spents;

        mUnspents.clear();
        mFee = 0;

        // Process Inputs
        unsigned int index = 1;
        for(std::vector<Input *>::iterator input=inputs.begin();input!=inputs.end();++input)
        {
            // Check if this is a coinbase
            if(pCoinBase)
            {
                if((*input)->outpoint.index != 0xffffffff)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Coinbase Input %d outpoint index is not 0xffffff : %08x", index, (*input)->outpoint.index);
                    return false;
                }
            }
            else
            {
                // Find unspent transaction for input
                unspent = pUnspentPool.find((*input)->outpoint.transactionID, (*input)->outpoint.index);
                if(unspent == NULL)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d outpoint transaction not found : trans %s output %d", index,
                      (*input)->outpoint.transactionID.hex().text(), (*input)->outpoint.index + 1);
                    return false;
                }

                spents.push_back(unspent);
            }

            interpreter.clear();

            // Process signature script
            (*input)->script.setReadOffset(0);
            if(!interpreter.process((*input)->script))
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d signature script failed", index);
                return false;
            }

            // Add unspent transaction script
            if(unspent != NULL)
            {
                unspent->script.setReadOffset(0);
                if(!interpreter.process(unspent->script));
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d output script failed", index);
                    return false;
                }
            }

            if(!interpreter.isValid())
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d script is not valid", index);
                return false;
            }

            if(!pCoinBase)
            {
                if(!interpreter.isVerified())
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME,
                      "Input %d script did not verify", index);
                    return false;
                }

                mFee += unspent->amount;
            }

            ++index;
        }

        // Process Outputs
        index = 1;
        for(std::vector<Output *>::iterator output=outputs.begin();output!=outputs.end();++output)
        {
            if((*output)->amount < 0)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_TRANSACTION_LOG_NAME,
                  "Output %d amount is negative %d", index, (*output)->amount);
                  return false;
            }

            unspent = new Unspent();
            unspent->amount = (*output)->amount;
            unspent->script = (*output)->script;
            unspent->script.compact();
            unspent->transactionID = hash;
            unspent->index = index - 1;
            unspent->height = pBlockHeight;
            parseOutputScript(unspent->script, unspent->hash);
            mUnspents.push_back(unspent);

            if(!pCoinBase && (*output)->amount > 0 && (uint64_t)(*output)->amount > mFee)
            {
                ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME,
                  "Outputs are more than inputs");
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

    /*unsigned int Script::blockHeight()
    {
        if(data.length () < 2) // Minimum of 2 bytes to specify block height
            return 0;

        data.setReadOffset(0);

        // Block height specification in "coinbase" block is a "push data" op code followed by the block height
        switch(data.readByte())
        {
            case 1:
                return data.readByte();
            case 2:
                return data.readUnsignedShort();
            case 3:
                if(data.inputEndian() == ArcMist::Endian::BIG)
                    return (data.readUnsignedShort() << 8) + data.readByte();
                else
                    return data.readUnsignedShort() + (data.readByte() << 16);
            case 4:
                return data.readUnsignedInt();
            default:
                return 0;
        }
    }*/

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

    /*void CoinBaseInput::write(ArcMist::OutputStream *pStream) const
    {
        outpoint.write(pStream);
        writeCompactInteger(pStream, signatureScript.length());
        signatureScript->write(pStream);
        pStream->writeUnsignedInt(sequence);
        
        
        Hash256 hash;
        uint32_t index; // always 0xffffffff, because there is no previous outpoint
        uint64_t blockHeight;
        
    }

    bool CoinBaseInput::read(ArcMist::InputStream *pStream)
    {
        
    }*/

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
        ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_TRANSACTION_LOG_NAME, "------------- Starting Transaction Tests -------------");

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
        writeP2PKHPublicKeyScript(publicKey1.hash(), &unspent->script);
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
        //transaction.inputs[0]->outpoint.transactionID = ;
        transaction.inputs[0]->outpoint.index = 0; // First output of transaction

        // Add output
        transaction.outputs.push_back(new Output());
        transaction.outputs[0]->amount = 50000;

        /***********************************************************************************************
         * Process Valid P2PKH Transaction
         ***********************************************************************************************/
        // Create public key script to pay the third public key
        writeP2PKHPublicKeyScript(publicKey2.hash(), &transaction.outputs[0]->script);

        // Create signature script
        writeP2PKHSignatureScript(privateKey1, publicKey1, unspent->script, &transaction.inputs[0]->script);

        // Process the script
        ScriptInterpreter interpreter;

        transaction.inputs[0]->script.setReadOffset(0);
        transaction.calculateHash();
        //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0]->script.setReadOffset(0);
        if(!interpreter.process(transaction.inputs[0]->script))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            unspent->script.setReadOffset(0);
            if(!interpreter.process(unspent->script))
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
        writeP2PKHSignatureScript(privateKey1, publicKey2, unspent->script, &transaction.inputs[0]->script);

        transaction.inputs[0]->script.setReadOffset(0);
        transaction.calculateHash();
        //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0]->script.setReadOffset(0);
        if(!interpreter.process(transaction.inputs[0]->script))
        {
            interpreter.printStack("After signature script");
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            unspent->script.setReadOffset(0);
            if(!interpreter.process(unspent->script))
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
        writeP2PKHSignatureScript(privateKey2, publicKey1, unspent->script, &transaction.inputs[0]->script);

        transaction.inputs[0]->script.setReadOffset(0);
        transaction.calculateHash();
        //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0]->script.setReadOffset(0);
        if(!interpreter.process(transaction.inputs[0]->script))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            unspent->script.setReadOffset(0);
            if(!interpreter.process(unspent->script))
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
        writeP2SHPublicKeyScript(redeemHash, &unspent->script);
        unspent->transactionID.setSize(32);
        unspent->transactionID.randomize();
        unspent->index = 0;
        unspent->hash = publicKey1.hash();

        // Create signature script
        transaction.inputs[0]->script.clear();
        redeemScript.setReadOffset(0);
        writeP2SHSignatureScript(redeemScript, &transaction.inputs[0]->script);

        transaction.inputs[0]->script.setReadOffset(0);
        transaction.calculateHash();
        //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME, "Transaction ID : %s", transaction.hash.hex().text());
        transaction.inputs[0]->script.setReadOffset(0);
        if(!interpreter.process(transaction.inputs[0]->script))
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_TRANSACTION_LOG_NAME, "Failed to process signature script");
            success = false;
        }
        else
        {
            unspent->script.setReadOffset(0);
            if(!interpreter.process(unspent->script))
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
