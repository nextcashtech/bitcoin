/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "requests.hpp"

#include "log.hpp"
#include "hash.hpp"
#include "digest.hpp"

#include "key.hpp"
#include "info.hpp"
#include "mem_pool.hpp"

#include <algorithm>


namespace BitCoin
{
    unsigned int RequestChannel::mNextID = 256;

    RequestChannel::RequestChannel(NextCash::Network::Connection *pConnection, Chain *pChain) :
      mID(mNextID++), mConnectionMutex("Request Connection")
    {
        mThread = NULL;
        mConnection = NULL;
        mStop = false;
        mStopped = false;
        mAuthenticated = false;
        mChain = pChain;
        mPreviousStatisticsHeight = 0;
        mPreviousStatisticsHours = 0;
        mName.writeFormatted("Request [%d]", mID);

        mLastReceiveTime = getTime();
        mConnectedTime = getTime();

        // Verify connection
        mConnectionMutex.lock();
        mConnection = pConnection;
        mConnectionMutex.unlock();
        NextCash::Log::addFormatted(NextCash::Log::INFO, mName, "Requests Connection %s : %d",
          mConnection->ipv6Address(), mConnection->port());

        // Start thread
        mThread = new NextCash::Thread("Request", run, this);
        NextCash::Thread::sleep(100); // Give the thread a chance to initialize
    }

    RequestChannel::~RequestChannel()
    {
        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
          "Disconnecting %s", mConnection->ipv6Address());

        requestStop();
        if(mThread != NULL)
            delete mThread;
        mConnectionMutex.lock();
        if(mConnection != NULL)
            delete mConnection;
        mConnectionMutex.unlock();
    }

    void RequestChannel::run(void *pParameter)
    {
        RequestChannel *requestChannel = (RequestChannel *)pParameter;
        if(requestChannel == NULL)
        {
            NextCash::Log::add(NextCash::Log::ERROR, "Request", "Thread parameter is null. Stopping");
            return;
        }

        if(requestChannel->mStop)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, requestChannel->mName,
              "Request channel stopped before thread started");
            requestChannel->mStopped = true;
            return;
        }

        while(!requestChannel->mStop)
        {
            requestChannel->process();
            if(requestChannel->mStop)
                break;
            NextCash::Thread::sleep(100);
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
            NextCash::Buffer closeBuffer;
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
            mConnectionMutex.unlock();
            requestStop();
            return;
        }
        mConnection->receive(&mReceiveBuffer);
        mConnectionMutex.unlock();

        if(getTime() - mLastReceiveTime > 120)
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, mName,
              "Timed out waiting for message");
            requestStop();
            return;
        }

        if(!mAuthenticated)
        {
            if(getTime() - mConnectedTime > 60)
            {
                NextCash::Log::add(NextCash::Log::VERBOSE, mName,
                  "Timed out waiting for authentication");
                requestStop();
                return;
            }

            // Check for auth command
            mReceiveBuffer.setReadOffset(0);
            if(mReceiveBuffer.remaining() < 5)
                return;

            NextCash::String authString = mReceiveBuffer.readString(5);
            if(authString != "auth:")
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
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
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
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
            Time value = getTime();
            value -= value % 10;
            value -= 30;
            NextCash::Hash hashes[5];
            NextCash::Digest digest(NextCash::Digest::SHA256);
            for(int i=0;i<5;++i)
            {
                digest.initialize();
                digest.writeUnsignedInt(value);
                digest.getResult(&hashes[i]);
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, mName,
                  "Auth hash %d : %s", value, hashes[i].hex().text());
                value += 10;
            }

            // Open public keys file
            NextCash::String keysFilePathName = Info::instance().path();
            keysFilePathName.pathAppend("request_keys");
            NextCash::FileInputStream keysFile(keysFilePathName);

            if(!keysFile.isValid())
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                  "Failed to open request keys file : %s", keysFilePathName.text());
                requestStop();
                return;
            }

            // Check signature against authorized public keys
            Key publicKey;
            NextCash::String keyText, keyName;
            NextCash::Buffer keyBuffer, keyData;
            char nextChar;
            unsigned int authorizedCount = 0;
            NextCash::Hash validHash;
            while(keysFile.remaining())
            {
                keyName.clear();
                keyText.clear();
                while(keysFile.remaining())
                {
                    nextChar = keysFile.readByte();
                    if(nextChar == '\r' || nextChar == '\n')
                    {
                        keysFile.setReadOffset(keysFile.readOffset() - 1);
                        break;
                    }
                    else if(nextChar == ' ')
                        break;

                    keyText += nextChar;
                }

                if(nextChar == ' ')
                    while(keysFile.remaining())
                    {
                        nextChar = keysFile.readByte();
                        if(nextChar == '\r' || nextChar == '\n')
                        {
                            keysFile.setReadOffset(keysFile.readOffset() - 1);
                            break;
                        }

                        keyName += nextChar;
                    }

                keyBuffer.clear();
                keyBuffer.writeHex(keyText);

                if(!publicKey.readPublic(&keyBuffer))
                    break;
                keyBuffer.clear();
                publicKey.writePublic(&keyBuffer, false);
                NextCash::Log::addFormatted(NextCash::Log::DEBUG, mName,
                  "Checking public key %s : %s", keyName.text(), keyBuffer.readHexString(keyBuffer.remaining()).text());
                ++authorizedCount;

                for(int i=0;i<5;++i)
                    if(publicKey.verify(signature, hashes[i]))
                    {
                        validHash = hashes[i];
                        mAuthenticated = true;
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                          "Connection authorized : %s", keyName.text());
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
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                  "Failed to authenticate : %d authorized users", authorizedCount);
                requestStop();
                return;
            }

            // Send signature back to prove identity
            NextCash::String privateKeyFilePathName = Info::instance().path();
            privateKeyFilePathName.pathAppend(".request_private_key");
            NextCash::FileInputStream privateKeyFile(privateKeyFilePathName);

            if(!privateKeyFile.isValid())
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                  "Failed to open private key file : %s", privateKeyFilePathName.text());
                requestStop();
                return;
            }

            keyText = privateKeyFile.readString(64);
            if(keyData.writeHex(keyText) != 32)
            {
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                  "Failed to read private key from file : %s", privateKeyFilePathName.text());
                requestStop();
                return;
            }

            Key privateKey;
            Signature returnSignature;
            privateKey.readPrivate(&keyData);
            if(!privateKey.sign(validHash, returnSignature))
            {
                NextCash::Log::add(NextCash::Log::VERBOSE, mName, "Failed to sign return value");
                requestStop();
                return;
            }

            mReceiveBuffer.flush();

            NextCash::Buffer sendData;
            sendData.writeString("acpt:");
            returnSignature.write(&sendData, false);
            keyBuffer.clear();
            returnSignature.write(&keyBuffer, false);
            NextCash::Log::addFormatted(NextCash::Log::DEBUG, mName,
              "Sending accept signature : %s", keyBuffer.readHexString(keyBuffer.remaining()).text());

            mConnectionMutex.lock();
            mConnection->send(&sendData);
            mConnectionMutex.unlock();
            return;
        }

        // Parse message from receive buffer
        NextCash::String command;
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

        NextCash::Buffer sendData;

        if(command == "clse")
        {
            NextCash::Log::add(NextCash::Log::INFO, mName, "Connection closed");
            requestStop();
            return;
        }
        else if(command == "stat")
        {
            mReceiveBuffer.flush();

            // Return block chain status message
            sendData.writeString("stat:");
            sendData.writeInt(mChain->headerHeight());
            sendData.writeInt(mChain->blockHeight());
            if(mChain->isInSync())
                sendData.writeByte(-1);
            else
                sendData.writeByte(0);
            if(Info::instance().initialBlockDownloadIsComplete())
                sendData.writeByte(-1);
            else
                sendData.writeByte(0);
            if(mChain->saveDataInProgress())
                sendData.writeByte(-1);
            else
                sendData.writeByte(0);
            sendData.writeUnsignedInt(mChain->memPool().count());
            sendData.writeUnsignedInt(mChain->memPool().size());
            sendData.writeUnsignedLong(currentSupply(mChain->headerHeight()));

            NextCash::Log::add(NextCash::Log::VERBOSE, mName, "Sending status");
        }
        else if(command == "addr")
        {
#ifndef DISABLE_ADDRESSES
            NextCash::Log::add(NextCash::Log::VERBOSE, mName, "Received address request");

            // Return address data message (UTXOs, balances, spent/unspent)
            unsigned int addressLength = mReceiveBuffer.readByte();
            NextCash::String address = mReceiveBuffer.readString(addressLength);
            PaymentRequest request;

            request = decodePaymentCode(address);

            if(request.format == PaymentRequest::Format::INVALID)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, mName,
                  "Invalid address (%d bytes) : %s", addressLength, address.text());
                sendData.writeString("fail:Invalid Address Format", true);
            }
            else
            {
                if(request.network != MAINNET)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, mName,
                      "Wrong address type (%d bytes) : %s", addressLength, address.text());
                    sendData.writeString("fail:Not Public Key Hash", true);
                }
                else
                {
                    std::vector<FullOutputData> outputs;
                    if(!mChain->addresses().getOutputs(request.pubKeyHash, outputs))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, mName,
                          "Failed to get outputs for address : %s", address.text());
                        sendData.writeString("fail:No transactions found", true);
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
                                    sendData.writeUnsignedInt(-1); // Not spent
                            }
                            else
                                sendData.writeUnsignedInt(-1); // Not spent
                        }
                    }

                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                      "Sending %d outputs for address : %s", outputs.size(), address.text());
                }
            }
#else
            sendData.writeString("fail:Addresses not enables", true);
#endif
        }
        else if(command == "blkd")
        {
            if(mReceiveBuffer.remaining() < 5)
                NextCash::Log::add(NextCash::Log::WARNING, mName,
                  "Received short block details request");
            else
            {
                NextCash::Log::add(NextCash::Log::VERBOSE, mName, "Received block details request");

                // Return block details
                unsigned int height = mReceiveBuffer.readUnsignedInt(); // Start height
                unsigned int count = mReceiveBuffer.readByte(); // Number of blocks to include
                Block block;
                unsigned int resultCount = 0, inputCount, outputCount;
                uint64_t amountSent;

                if(height < 0)
                    height = mChain->blockHeight();

                sendData.writeString("blkd:");
                sendData.writeByte(0);

                // Height, Hash, Size, Transaction Count, Input Count, Output Count
                for(unsigned int i = 0; i < count; ++i)
                {
                    // Get Block at height - i
                    if(!mChain->getBlock(height - i, block))
                        continue;

                    sendData.writeUnsignedInt(height - i); // Height
                    block.header.hash.write(&sendData); // Hash
                    sendData.writeUnsignedInt(block.header.time); // Time
                    sendData.writeUnsignedInt(block.size()); // Size
                    sendData.writeUnsignedLong(block.actualCoinbaseAmount() - coinBaseAmount(height - i)); // Fees
                    sendData.writeUnsignedInt(block.transactions.size()); // Transaction Count

                    inputCount = 0;
                    outputCount = 0;
                    amountSent = 0;
                    bool skip = true;
                    for(std::vector<Transaction *>::iterator trans = block.transactions.begin();
                      trans != block.transactions.end(); ++trans)
                    {
                        if(skip)
                        {
                            skip = false;
                            continue;
                        }
                        inputCount += (*trans)->inputs.size();
                        outputCount += (*trans)->outputs.size();
                        for(std::vector<Output>::iterator output = (*trans)->outputs.begin();
                          output != (*trans)->outputs.end(); ++output)
                            amountSent += output->amount;
                    }
                    sendData.writeUnsignedInt(inputCount); // Input Count
                    sendData.writeUnsignedInt(outputCount); // Output Count
                    sendData.writeUnsignedLong(amountSent); // Amount Sent

                    ++resultCount;
                }

                // Update result count
                sendData.setWriteOffset(5);
                sendData.writeByte(resultCount);

                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                  "Sending %d block details starting at height %d", resultCount, height);
            }
        }
        else if(command == "bkst")
        {
            if(mReceiveBuffer.remaining() < 8)
                NextCash::Log::add(NextCash::Log::WARNING, mName,
                  "Received short block statistics request");
            else
            {
                // Return statistics
                unsigned int height = mReceiveBuffer.readUnsignedInt(); // Start height
                unsigned int hours = mReceiveBuffer.readUnsignedInt(); // Number of hours back in time to include

                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                  "Received block statistics request for %d hours before height %d", hours, height);

                if(mPreviousStatisticsResult.length() > 0 && mPreviousStatisticsHeight == height &&
                  mPreviousStatisticsHours == hours)
                {
                    NextCash::Log::add(NextCash::Log::VERBOSE, mName,
                      "Resending previous block statistics result");
                    mPreviousStatisticsResult.setReadOffset(0);
                    sendData.writeStream(&mPreviousStatisticsResult,
                      mPreviousStatisticsResult.length());
                    mPreviousStatisticsResult.setReadOffset(0);
                }
                else
                {
                    Time stopTime = 0;
                    unsigned int blockCount = 0, totalTransactionCount = 0, totalInputCount = 0,
                      totalOutputCount = 0;
                    unsigned int inputCount, outputCount;
                    uint64_t totalBlockSize = 0, totalFees = 0, fee, totalAmountSent = 0,
                      amountSent, feeRate;
                    std::vector<uint64_t> blockSizes, fees, amountsSent, feeRates;
                    std::vector<unsigned int> transactionCounts, inputCounts, outputCounts;
                    Block block;

                    fees.reserve(256);
                    feeRates.reserve(256);
                    blockSizes.reserve(256);
                    transactionCounts.reserve(256);
                    inputCounts.reserve(256);
                    outputCounts.reserve(256);

                    if(hours <= 168) // Week max
                    {
                        if(height < 0)
                            height = mChain->blockHeight();

                        int currentHeight = height;

                        while(currentHeight > 0)
                        {
                            // Get Block at current height
                            if(!mChain->getBlock((unsigned int)currentHeight--, block))
                                continue;

                            if(stopTime == 0)
                                stopTime = block.header.time - (hours * 3600);
                            else if(block.header.time < stopTime)
                                break;

                            // Count inputs and outputs
                            inputCount = 0;
                            outputCount = 0;
                            amountSent = 0;
                            bool skip = true;
                            for(std::vector<Transaction *>::iterator trans =
                              block.transactions.begin(); trans != block.transactions.end();
                              ++trans)
                            {
                                if(skip)
                                {
                                    skip = false;
                                    continue;
                                }
                                inputCount += (*trans)->inputs.size();
                                outputCount += (*trans)->outputs.size();
                                for(std::vector<Output>::iterator output =
                                  (*trans)->outputs.begin(); output != (*trans)->outputs.end();
                                  ++output)
                                    amountSent += output->amount;
                            }

                            totalBlockSize += block.size();
                            blockSizes.push_back(block.size());

                            totalTransactionCount += block.transactions.size();
                            transactionCounts.push_back(block.transactions.size());

                            totalInputCount += inputCount;
                            inputCounts.push_back(inputCount);

                            totalOutputCount += outputCount;
                            outputCounts.push_back(outputCount);

                            totalAmountSent += amountSent;
                            amountsSent.push_back(amountSent);

                            fee = block.actualCoinbaseAmount() - coinBaseAmount(currentHeight + 1);
                            totalFees += fee;
                            fees.push_back(fee);

                            feeRate = (fee * 1000L) / block.size();
                            feeRates.push_back(feeRate);

                            ++blockCount;
                        }
                    }

                    uint64_t medianBlockSize = 0;
                    unsigned int medianTransactionCount = 0;
                    unsigned int medianInputCount = 0;
                    unsigned int medianOutputCount = 0;
                    uint64_t medianFees = 0;
                    uint64_t medianAmountSent = 0;
                    uint64_t medianFeeRate = 0;

                    if(blockCount > 1)
                    {
                        std::sort(blockSizes.begin(), blockSizes.end());
                        medianBlockSize = blockSizes[blockSizes.size()/2];

                        std::sort(transactionCounts.begin(), transactionCounts.end());
                        medianTransactionCount = transactionCounts[transactionCounts.size()/2];

                        std::sort(inputCounts.begin(), inputCounts.end());
                        medianInputCount = inputCounts[inputCounts.size()/2];

                        std::sort(outputCounts.begin(), outputCounts.end());
                        medianOutputCount = outputCounts[outputCounts.size()/2];

                        std::sort(amountsSent.begin(), amountsSent.end());
                        medianAmountSent = amountsSent[amountsSent.size()/2];

                        std::sort(fees.begin(), fees.end());
                        medianFees = fees[fees.size()/2];

                        std::sort(feeRates.begin(), feeRates.end());
                        medianFeeRate = feeRates[feeRates.size()/2];
                    }
                    else if(blockCount == 1)
                    {
                        medianBlockSize = totalBlockSize;
                        medianTransactionCount = totalTransactionCount;
                        medianInputCount = totalInputCount;
                        medianOutputCount = totalOutputCount;
                        medianAmountSent = totalAmountSent;
                        medianFees = totalFees;
                        medianFeeRate = (totalFees * 1000L) / totalBlockSize;
                    }

                    sendData.writeString("bkst:");
                    sendData.writeUnsignedInt(blockCount); // Total blocks

                    sendData.writeUnsignedLong(totalBlockSize); // Total block size
                    sendData.writeUnsignedLong(medianBlockSize); // Median block size

                    sendData.writeUnsignedInt(totalTransactionCount); // Total transactions
                    sendData.writeUnsignedInt(medianTransactionCount); // Median transactions

                    sendData.writeUnsignedInt(totalInputCount); // Total Input Count
                    sendData.writeUnsignedInt(medianInputCount); // Median Input Count

                    sendData.writeUnsignedInt(totalOutputCount); // Total Output Count
                    sendData.writeUnsignedInt(medianOutputCount); // Median Output Count

                    sendData.writeUnsignedLong(totalAmountSent); // Total Amount Sent
                    sendData.writeUnsignedLong(medianAmountSent); // Median Amount Sent

                    sendData.writeUnsignedLong(totalFees); // Total Fees
                    sendData.writeUnsignedLong(medianFees); // Median Fees

                    // Total Fee Rate
                    sendData.writeUnsignedLong((totalFees * 1000L) / totalBlockSize);
                    // Median Fee Rate
                    sendData.writeUnsignedLong(medianFeeRate);

                    // Save result
                    mPreviousStatisticsHeight = height;
                    mPreviousStatisticsHours = hours;
                    mPreviousStatisticsResult.clear();
                    sendData.setReadOffset(0);
                    mPreviousStatisticsResult.writeStream(&sendData, sendData.length());
                    sendData.setReadOffset(0);

                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                      "Sending block statistics for %d blocks starting at height %d going back %d hours",
                      blockCount, height, hours);
                }
            }
        }
        else if(command == "memp")
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, mName, "Received mempool request");

            MemPool::RequestData requestData;
            mChain->memPool().getRequestData(requestData, Info::instance().minFee);

            sendData.writeString("memp:");
            sendData.writeUnsignedInt(requestData.count); // Number of transactions
            sendData.writeUnsignedLong(requestData.size); // Size in bytes
            sendData.writeUnsignedLong(requestData.zero); // Zero fee
            sendData.writeUnsignedLong(requestData.one); // Below 1 sat/B
            sendData.writeUnsignedLong(requestData.two); // Below 2 sat/B
            sendData.writeUnsignedLong(requestData.five); // Below 5 sat/B
            sendData.writeUnsignedLong(requestData.ten); // Below 10 sat/B
            sendData.writeUnsignedLong(requestData.remainingSize); // Total size of remaining
            sendData.writeUnsignedLong(requestData.remainingFee); // Total fee of remaining
            sendData.writeUnsignedLong(requestData.minFee); // Minimum fee

            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
              "Sending mempool data : %d trans (%d KB)", requestData.count, requestData.size / 1000L);
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
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
              "Unknown command : %s", command.text());

        sendData.setReadOffset(0);
        if(sendData.length())
        {
            mLastReceiveTime = getTime();
            mConnectionMutex.lock();
            mConnection->send(&sendData);
            mConnectionMutex.unlock();
        }
    }
}
