/**************************************************************************
 * Copyright 2017-2018 ArcMist, LLC                                       *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "requests.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/base/hash.hpp"
#include "arcmist/crypto/digest.hpp"

#include "key.hpp"
#include "info.hpp"

#define BITCOIN_REQUEST_LOG_NAME "Request"


namespace BitCoin
{
    RequestChannel::RequestChannel(ArcMist::Network::Connection *pConnection, Chain *pChain) : mConnectionMutex("Request Connection")
    {
        mThread = NULL;
        mConnection = NULL;
        mStop = false;
        mStopped = false;
        mAuthenticated = false;
        mChain = pChain;

        mLastReceiveTime = getTime();
        mConnectedTime = getTime();

        // Verify connection
        mConnectionMutex.lock();
        mConnection = pConnection;
        mConnectionMutex.unlock();
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_REQUEST_LOG_NAME, "Requests Connection %s : %d",
          mConnection->ipv6Address(), mConnection->port());

        // Start thread
        mThread = new ArcMist::Thread("Request", run, this);
        ArcMist::Thread::sleep(100); // Give the thread a chance to initialize
    }

    RequestChannel::~RequestChannel()
    {
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
          "Disconnecting %s", mConnection->ipv6Address());

        requestStop();
        if(mThread != NULL)
            delete mThread;
        mConnectionMutex.lock();
        if(mConnection != NULL)
            delete mConnection;
        mConnectionMutex.unlock();
    }

    void RequestChannel::run()
    {
        RequestChannel *requestChannel = (RequestChannel *)ArcMist::Thread::getParameter();
        if(requestChannel == NULL)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_REQUEST_LOG_NAME, "Thread parameter is null. Stopping");
            return;
        }

        if(requestChannel->mStop)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
              "Request channel stopped before thread started");
            requestChannel->mStopped = true;
            return;
        }

        while(!requestChannel->mStop)
        {
            requestChannel->process();
            if(requestChannel->mStop)
                break;
            ArcMist::Thread::sleep(100);
        }

        requestChannel->mStopped = true;
    }

    void RequestChannel::requestStop()
    {
        if(mThread == NULL)
            return;
        mConnectionMutex.lock();
        if(mConnection != NULL && mConnection->isOpen())
        {
            ArcMist::Buffer closeBuffer;
            closeBuffer.writeString("clse:");
            mConnection->send(&closeBuffer);
        }
        mConnectionMutex.unlock();
        mStop = true;
    }

    void RequestChannel::process()
    {
        mConnectionMutex.lock();
        if(mConnection == NULL)
        {
            mConnectionMutex.unlock();
            return;
        }

        if(!mConnection->isOpen())
        {
            requestStop();
            mConnectionMutex.unlock();
            return;
        }
        if(mConnection->receive(&mReceiveBuffer))
            mLastReceiveTime = getTime();
        mConnectionMutex.unlock();

        if(mLastReceiveTime - getTime() > 120)
        {
            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
              "Timed out waiting for message");
            requestStop();
            return;
        }

        if(!mAuthenticated)
        {
            if(getTime() - mConnectedTime > 60)
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
                  "Timed out waiting for authentication");
                requestStop();
                return;
            }

            // Check for auth command
            mReceiveBuffer.setReadOffset(0);
            if(mReceiveBuffer.remaining() < 5)
                return;

            ArcMist::String authString = mReceiveBuffer.readString(5);
            if(authString != "auth:")
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
                  "Invalid authentication command : %s", authString.text());
                requestStop();
                return;
            }

            // Read signature
            if(!mReceiveBuffer.remaining())
                return;

            if(mReceiveBuffer.readByte() != 0x30)
            {
                mReceiveBuffer.setReadOffset(mReceiveBuffer.readOffset() - 1);
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
                  "Signature doesn't start with compound header byte : %02x", mReceiveBuffer.readByte());
                requestStop();
                return;
            }

            unsigned int sigLength = mReceiveBuffer.readByte() + 3; // Plus header byte, length byte, hash type byte
            mReceiveBuffer.setReadOffset(mReceiveBuffer.readOffset() - 2);
            Signature signature;
            if(!signature.read(&mReceiveBuffer, sigLength, true))
                return;

            // Generate hashes to check
            uint32_t value = getTime();
            value -= value % 10;
            value -= 30;
            ArcMist::Hash hashes[5];
            ArcMist::Digest digest(ArcMist::Digest::SHA256);
            for(int i=0;i<5;++i)
            {
                digest.initialize();
                digest.writeUnsignedInt(value);
                digest.getResult(&hashes[i]);
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_REQUEST_LOG_NAME,
                  "Auth hash %d : %s", value, hashes[i].hex().text());
                value += 10;
            }

            // Open public keys file
            ArcMist::String keysFilePathName = Info::instance().path();
            keysFilePathName.pathAppend("keys");
            ArcMist::FileInputStream keysFile(keysFilePathName);

            if(!keysFile.isValid())
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
                  "Failed to open keys file : %s", keysFilePathName.text());
                requestStop();
                return;
            }

            // Check signature against authorized public keys
            PublicKey publicKey;
            ArcMist::String keyText;
            ArcMist::Buffer keyBuffer;
            uint8_t keyData[64];
            char nextChar;
            unsigned int authorizedCount = 0;
            ArcMist::Hash validHash;
            while(keysFile.remaining())
            {
                keyText.clear();
                while(keysFile.remaining())
                {
                    nextChar = keysFile.readByte();
                    if(nextChar == '\r' || nextChar == '\n')
                    {
                        keysFile.setReadOffset(keysFile.readOffset() - 1);
                        break;
                    }

                    keyText += nextChar;
                }

                keyBuffer.clear();
                keyBuffer.writeHex(keyText);

                if(!publicKey.read(&keyBuffer))
                    break;
                keyBuffer.clear();
                publicKey.write(&keyBuffer, true, false);
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_REQUEST_LOG_NAME,
                  "Checking public key : %s", keyBuffer.readHexString(keyBuffer.remaining()).text());
                ++authorizedCount;

                for(int i=0;i<5;++i)
                    if(signature.verify(publicKey, hashes[i]))
                    {
                        validHash = hashes[i];
                        mAuthenticated = true;
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
                          "Connection authorized : %s", validHash.hex().text());
                        break;
                    }

                if(mAuthenticated)
                    break;

                if(!keysFile.remaining())
                    break;

                // Parse end of line character(s)
                nextChar = keysFile.readByte();
                if(nextChar == '\r')
                {
                    if(keysFile.readByte() != '\n')
                        break;
                }
                else if(nextChar != '\n')
                    break;
            }

            if(!mAuthenticated)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
                  "Failed to authenticate : %d authorized users", authorizedCount);
                requestStop();
                return;
            }

            // Send signature back to prove identity
            ArcMist::String privateKeyFilePathName = Info::instance().path();
            privateKeyFilePathName.pathAppend(".private_key");
            ArcMist::FileInputStream privateKeyFile(privateKeyFilePathName);

            if(!privateKeyFile.isValid())
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
                  "Failed to open private key file : %s", privateKeyFilePathName.text());
                requestStop();
                return;
            }

            keyText = privateKeyFile.readString(64);
            if(keyText.readHex(keyData) != 32)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
                  "Failed to read private key from file : %s", privateKeyFilePathName.text());
                requestStop();
                return;
            }

            PrivateKey privateKey;
            Signature returnSignature;
            privateKey.set(keyData);
            if(!privateKey.sign(validHash, returnSignature))
            {
                ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
                  "Failed to sign return value");
                requestStop();
                return;
            }

            mReceiveBuffer.flush();

            ArcMist::Buffer sendData;
            sendData.writeString("acpt:");
            returnSignature.write(&sendData, false);
            keyBuffer.clear();
            returnSignature.write(&keyBuffer, false);
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_REQUEST_LOG_NAME,
              "Sending accept signature : %s", keyBuffer.readHexString(keyBuffer.remaining()).text());

            mConnectionMutex.lock();
            mConnection->send(&sendData);
            mConnectionMutex.unlock();
            return;
        }

        // Parse message from receive buffer
        ArcMist::String command;
        while(mReceiveBuffer.remaining())
            if(mReceiveBuffer.readByte() == ':' && mReceiveBuffer.readOffset() >= 5)
            {
                mReceiveBuffer.setReadOffset(mReceiveBuffer.readOffset() - 5);
                command = mReceiveBuffer.readString(4);
                mReceiveBuffer.readByte(); // Read colon again
                break;
            }

        if(command.length() != 4)
            return;

        ArcMist::Buffer sendData;

        if(command == "clse")
        {
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_REQUEST_LOG_NAME, "Connection closed");
            requestStop();
            return;
        }
        else if(command == "stat")
        {
            mReceiveBuffer.flush();

            // Return block chain status message
            sendData.writeString("stat:");
            sendData.writeInt(mChain->height());
            if(mChain->isInSync())
                sendData.writeByte(-1);
            else
                sendData.writeByte(0);
            sendData.writeUnsignedInt(mChain->memPool().count());
            sendData.writeUnsignedInt(mChain->memPool().size());

            ArcMist::Log::add(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME, "Sending status");
        }
        else if(command == "addr")
        {
            // Return address data message (UTXOs, balances, spent/unspent)
            unsigned int addressLength = mReceiveBuffer.readByte();
            ArcMist::String address = mReceiveBuffer.readString(addressLength);
            ArcMist::Hash addressHash;
            AddressType addressType;

            if(!decodeAddress(address, addressHash, addressType))
            {
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_REQUEST_LOG_NAME,
                  "Invalid address (%d bytes) : %s", addressLength, address.text());
                sendData.writeString("fail:Invalid Address Format", true);
            }
            else
            {
                if(addressType != PUB_KEY_HASH)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_REQUEST_LOG_NAME,
                      "Wrong address type (%d bytes) : %s", addressLength, address.text());
                    sendData.writeString("fail:Not Public Key Hash", true);
                }
                else
                {
                    std::vector<FullOutputData> outputs;
                    if(!mChain->addresses().getOutputs(addressHash, outputs))
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_REQUEST_LOG_NAME,
                          "Failed to get outputs for address : %s", address.text());
                        sendData.writeString("fail:Output Lookup Failed", true);
                    }
                    else
                    {
                        TransactionOutputPool::Iterator reference;
                        OutputReference *outputReference;

                        sendData.writeString("outp:");
                        sendData.writeUnsignedInt(outputs.size());

                        for(std::vector<FullOutputData>::iterator output=outputs.begin();output!=outputs.end();++output)
                        {
                            output->transactionID.write(&sendData);
                            sendData.writeUnsignedInt(output->index);
                            sendData.writeLong(output->output.amount);

                            reference = mChain->outputs().get(output->transactionID);
                            if(reference)
                            {
                                outputReference = ((TransactionReference *)*reference)->outputAt(output->index);
                                if(outputReference != NULL)
                                    sendData.writeUnsignedInt(outputReference->spentBlockHeight);
                                else
                                    sendData.writeUnsignedInt(-1); // Not found
                            }
                            else
                                sendData.writeUnsignedInt(-1); // Not found
                        }
                    }

                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
                      "Sending %d outputs for address : %s", outputs.size(), address.text());
                }
            }
        }
        else if(command == "trxn")
        {
            // Return transaction

        }
        else if(command == "head")
        {
            // Return header

        }
        else if(command == "blok")
        {
            // Return block for specified hash

        }
        else if(command == "blkn")
        {
            // Return block hash at specified height

        }
        else
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_REQUEST_LOG_NAME,
              "Unknown command : %s", command.text());

        if(sendData.length())
        {
            mConnectionMutex.lock();
            mConnection->send(&sendData);
            mConnectionMutex.unlock();
        }
    }
}
