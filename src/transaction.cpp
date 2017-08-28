#include "transaction.hpp"

#include "arcmist/base/endian.hpp"
#include "arcmist/base/math.hpp"
#include "arcmist/base/log.hpp"
#include "interpreter.hpp"

#define BITCOIN_TRANSACTION_LOG_NAME "BitCoin Transaction"


namespace BitCoin
{
    Transaction::~Transaction()
    {
        for(unsigned int i=0;i<mUnspents.size();i++)
            delete mUnspents[i];
        for(unsigned int i=0;i<inputs.size();i++)
            delete inputs[i];
        for(unsigned int i=0;i<outputs.size();i++)
            delete outputs[i];
    }

    void Transaction::clear()
    {
        version = 1;
        mFee = 0;
        lockTime = 0xffffffff;

        for(unsigned int i=0;i<mUnspents.size();i++)
            delete mUnspents[i];
        mUnspents.clear();
        for(unsigned int i=0;i<inputs.size();i++)
            delete inputs[i];
        inputs.clear();
        for(unsigned int i=0;i<outputs.size();i++)
            delete outputs[i];
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

    bool Transaction::process(bool pTest)
    {
        UnspentPool &unspentPool = UnspentPool::instance();
        ScriptInterpreter interpreter;
        Unspent *unspent;
        std::vector<Unspent *> spents;

        mUnspents.clear();
        mFee = 0;

        // Process Inputs
        for(unsigned int i=0;i<inputs.size();i++)
        {
            // Find unspent transaction for input
            unspent = unspentPool.find(inputs[i]->outpoint.transactionID, inputs[i]->outpoint.index);
            if(unspent)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d outpoint transaction not found : trans %s output %d", i + 1,
                  inputs[i]->outpoint.transactionID.hex().text(), inputs[i]->outpoint.index + 1);
                  return false;
            }

            spents.push_back(unspent);
            interpreter.clear();

            // Process signature script
            inputs[i]->script.setReadOffset(0);
            if(!interpreter.process(inputs[i]->script))
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d signature script failed", i + 1);
                return false;
            }

            // Add unspent transaction script
            unspent->script.setReadOffset(0);
            if(!interpreter.process(unspent->script));
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d output script failed", i + 1);
                return false;
            }

            if(!interpreter.isValid())
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d script is not valid", i + 1);
                return false;
            }

            if(!interpreter.isVerified())
            {
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME,
                  "Input %d script did not verify", i + 1);
                return false;
            }

            mFee += unspent->amount;
        }

        // Process Outputs
        for(unsigned int i=0;i<outputs.size();i++)
        {
            unspent = new Unspent();
            unspent->amount = outputs[i]->amount;
            unspent->script = outputs[i]->script;
            unspent->transactionID = id();
            unspent->index = i;
            parseOutputScript(unspent->script, unspent->hash);

            if(outputs[i]->amount > mFee)
            {
                ArcMist::Log::add(ArcMist::Log::DEBUG, BITCOIN_TRANSACTION_LOG_NAME,
                  "Outputs are more than inputs");
                return false;
            }

            mFee -= outputs[i]->amount;
        }

        if(!pTest)
        {
            for(unsigned int i=0;i<mUnspents.size();i++)
                unspentPool.add(*mUnspents[i]);

            for(unsigned int i=0;i<spents.size();i++)
                unspentPool.spend(spents[i]);
        }

        return true;
    }

    unsigned int Transaction::size()
    {
        unsigned int result = 4; // Version

        // Input Count
        result += compactIntegerSize(inputs.size());

        // Inputs
        for(unsigned int i=0;i<inputs.size();i++)
            result += inputs[i]->size();

        // Output Count
        result += compactIntegerSize(outputs.size());

        // Outputs
        for(unsigned int i=0;i<outputs.size();i++)
            result += outputs[i]->size();

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
        pStream->write(&script, script.length());
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
        script.read(pStream, bytes);

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
        pStream->writeUnsignedLong(amount);
        writeCompactInteger(pStream, script.length());
        script.setReadOffset(0);
        pStream->write(&script, script.length());
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
        script.read(pStream, bytes);

        return true;
    }

    void Transaction::write(ArcMist::OutputStream *pStream)
    {
        // Version
        pStream->writeUnsignedInt(version);

        // Input Count
        writeCompactInteger(pStream, inputs.size());

        // Inputs
        for(unsigned int i=0;i<inputs.size();i++)
            inputs[i]->write(pStream);

        // Output Count
        writeCompactInteger(pStream, outputs.size());

        // Outputs
        for(unsigned int i=0;i<outputs.size();i++)
            outputs[i]->write(pStream);

        // Lock Time
        pStream->writeUnsignedInt(lockTime);
    }

    bool Transaction::read(ArcMist::InputStream *pStream)
    {
        if(pStream->remaining() < 5)
            return false;

        // Version
        version = pStream->readUnsignedInt();

        // Input Count
        uint64_t count = readCompactInteger(pStream);
        if(pStream->remaining() < count)
            return false;

        // Inputs
        inputs.resize(count);
        for(unsigned int i=0;i<count;i++)
        {
            inputs[i] = new Input();
            if(!inputs[i]->read(pStream))
                return false;
        }

        // Output Count
        count = readCompactInteger(pStream);

        // Outputs
        outputs.resize(count);
        for(unsigned int i=0;i<count;i++)
        {
            outputs[i] = new Output();
            if(!outputs[i]->read(pStream))
                return false;
        }

        if(pStream->remaining() < 4)
            return false;

        // Lock Time
        lockTime = pStream->readUnsignedInt();

        return true;
    }

    bool Transaction::test()
    {
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
        data.writeHexAsBinary("d68e0869df44615cc57f196208a896653e969f69960c6435f38ae47f6b6d082d");
        privateKey1.read(&data);

        // Initialize public key
        data.clear();
        data.writeHexAsBinary("03077b2a0406db4b4e2cddbe9aca5e9f1a3cf039feb843992d05cc0b7a75046635");
        publicKey1.read(&data);

        // Initialize private key
        data.writeHexAsBinary("4fd0a873dba1d74801f182013c5ae17c17213d333657047a6e6c5865f388a60a");
        privateKey2.read(&data);

        // Initialize public key
        data.clear();
        data.writeHexAsBinary("03362365326bd230642290787f3ba93d6299392ac5d26cd66e300f140184521e9c");
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
        sha256RIPEMD160(&redeemScript, redeemScript.length(), redeemHash);

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
