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
#include "interpreter.hpp"

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

    bool sortBySize(BlockStat &pLeft, BlockStat &pRight) { return pLeft.size < pRight.size; }
    bool sortByTransactionCount(BlockStat &pLeft, BlockStat &pRight)
      { return pLeft.transactionCount < pRight.transactionCount; }
    bool sortByInputCount(BlockStat &pLeft, BlockStat &pRight)
      { return pLeft.inputCount < pRight.inputCount; }
    bool sortByOutputCount(BlockStat &pLeft, BlockStat &pRight)
      { return pLeft.outputCount < pRight.outputCount; }
    bool sortByAmount(BlockStat &pLeft, BlockStat &pRight) { return pLeft.amount < pRight.amount; }
    bool sortByFees(BlockStat &pLeft, BlockStat &pRight) { return pLeft.fees < pRight.fees; }
    bool sortByFeeRates(BlockStat &pLeft, BlockStat &pRight) { return pLeft.feeRate() < pRight.feeRate(); }

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
            sendData.writeUnsignedLong(currentSupply(mChain->headerHeight()));
            sendData.writeUnsignedInt(mChain->memPool().count());
            sendData.writeUnsignedLong(mChain->memPool().size());
            sendData.writeUnsignedInt(mChain->memPool().pendingCount());
            sendData.writeUnsignedLong(mChain->memPool().pendingSize());

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
                BlockStat stat;
                unsigned int resultCount = 0;

                if(height < 0)
                    height = mChain->blockHeight();

                sendData.writeString("blkd:");
                sendData.writeByte(0);

                // Height, Hash, Size, Transaction Count, Input Count, Output Count
                for(unsigned int i = 0; i < count; ++i)
                {
                    if(i > height)
                        break;

                    // Get Block at height - i
                    if(!mChain->getBlockStat(height - i, stat))
                        continue;

                    sendData.writeUnsignedInt(height - i); // Height
                    stat.hash.write(&sendData); // Hash
                    sendData.writeUnsignedInt(stat.time); // Time
                    sendData.writeUnsignedInt(stat.size); // Size
                    sendData.writeUnsignedLong(stat.fees); // Fees
                    sendData.writeUnsignedInt(stat.transactionCount); // Transaction Count

                    sendData.writeUnsignedInt(stat.inputCount); // Input Count
                    sendData.writeUnsignedInt(stat.outputCount); // Output Count
                    sendData.writeUnsignedLong(stat.amount); // Amount

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
                    unsigned int totalTransactionCount = 0, totalInputCount = 0,
                      totalOutputCount = 0;
                    NextCash::stream_size totalBlockSize = 0UL;
                    uint64_t totalFees = 0UL, totalAmount = 0UL;
                    std::vector<BlockStat> stats;
                    BlockStat stat;

                    stats.reserve(hours * 6);

                    if(hours <= 168) // Week max
                    {
                        if(height < 0)
                            height = mChain->blockHeight();

                        unsigned int currentHeight = height;

                        while(true)
                        {
                            // Get Block at current height
                            if(!mChain->getBlockStat(currentHeight--, stat))
                                continue;

                            if(stopTime == 0)
                                stopTime = stat.time - (hours * 3600);
                            else if(stat.time < stopTime)
                                break;

                            stats.emplace_back(stat);
                            totalBlockSize += stat.size;
                            totalTransactionCount += stat.transactionCount;
                            totalInputCount += stat.inputCount;
                            totalOutputCount += stat.outputCount;
                            totalAmount += stat.amount;
                            totalFees += stat.fees;

                            if(currentHeight == 0)
                                break;
                        }
                    }

                    NextCash::stream_size medianBlockSize = 0UL;
                    unsigned int medianTransactionCount = 0;
                    unsigned int medianInputCount = 0;
                    unsigned int medianOutputCount = 0;
                    uint64_t medianFees = 0UL;
                    uint64_t medianAmount = 0UL;
                    uint64_t medianFeeRate = 0UL;

                    if(stats.size() > 1)
                    {
                        std::sort(stats.begin(), stats.end(), sortBySize);
                        medianBlockSize = stats[stats.size()/2].size;

                        std::sort(stats.begin(), stats.end(), sortByTransactionCount);
                        medianTransactionCount = stats[stats.size()/2].transactionCount;

                        std::sort(stats.begin(), stats.end(), sortByInputCount);
                        medianInputCount = stats[stats.size()/2].inputCount;

                        std::sort(stats.begin(), stats.end(), sortByOutputCount);
                        medianOutputCount = stats[stats.size()/2].outputCount;

                        std::sort(stats.begin(), stats.end(), sortByAmount);
                        medianAmount = stats[stats.size()/2].amount;

                        std::sort(stats.begin(), stats.end(), sortByFees);
                        medianFees = stats[stats.size()/2].fees;

                        std::sort(stats.begin(), stats.end(), sortByFeeRates);
                        medianFeeRate = stats[stats.size()/2].feeRate();
                    }
                    else if(stats.size() == 1)
                    {
                        medianBlockSize = totalBlockSize;
                        medianTransactionCount = totalTransactionCount;
                        medianInputCount = totalInputCount;
                        medianOutputCount = totalOutputCount;
                        medianAmount = totalAmount;
                        medianFees = totalFees;
                        medianFeeRate = (totalFees * 1000L) / totalBlockSize;
                    }

                    sendData.writeString("bkst:");
                    sendData.writeUnsignedInt(stats.size()); // Total blocks

                    sendData.writeUnsignedLong(totalBlockSize); // Total block size
                    sendData.writeUnsignedLong(medianBlockSize); // Median block size

                    sendData.writeUnsignedInt(totalTransactionCount); // Total transactions
                    sendData.writeUnsignedInt(medianTransactionCount); // Median transactions

                    sendData.writeUnsignedInt(totalInputCount); // Total Input Count
                    sendData.writeUnsignedInt(medianInputCount); // Median Input Count

                    sendData.writeUnsignedInt(totalOutputCount); // Total Output Count
                    sendData.writeUnsignedInt(medianOutputCount); // Median Output Count

                    sendData.writeLong(totalAmount); // Total Amount
                    sendData.writeLong(medianAmount); // Median Amount

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
                      stats.size(), height, hours);
                }
            }
        }
        else if(command == "memp")
        {
            NextCash::Log::add(NextCash::Log::VERBOSE, mName, "Received mempool request");

            MemPool::RequestData requestData;
            mChain->memPool().getRequestData(requestData);

            sendData.writeString("memp:");
            sendData.writeUnsignedInt(requestData.count); // Number of transactions
            sendData.writeUnsignedLong(requestData.totalFee); // Total of fees
            sendData.writeUnsignedLong(requestData.size); // Size in bytes
            sendData.writeUnsignedLong(requestData.zero); // Zero fee
            sendData.writeUnsignedLong(requestData.low); // Low fee
            sendData.writeUnsignedLong(requestData.one); // 1 sat/B
            sendData.writeUnsignedLong(requestData.two); // 2 sat/B
            sendData.writeUnsignedLong(requestData.five); // 5 sat/B
            sendData.writeUnsignedLong(requestData.remainingSize); // Total size of remaining
            sendData.writeUnsignedLong(requestData.remainingFee); // Total fee of remaining
            sendData.writeUnsignedInt(requestData.pendingCount); // Number of pending transactions
            sendData.writeUnsignedLong(requestData.pendingSize); // Pending size in bytes

            Info &info = Info::instance();
            sendData.writeUnsignedLong(info.minFee); // Minimum fee
            sendData.writeUnsignedLong(info.lowFee); // Low fee
            sendData.writeUnsignedLong(info.memPoolLowFeeSize); // Low fee size

            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
              "Sending mempool data : %d trans (%d KB)", requestData.count, requestData.size / 1000L);
        }
        else if(command == "tran")
        {
            // Return transaction for specified hash
            if(mReceiveBuffer.remaining() < TRANSACTION_HASH_SIZE)
                NextCash::Log::add(NextCash::Log::WARNING, mName,
                  "Received short transaction request");
            else
            {
                NextCash::Hash hash(TRANSACTION_HASH_SIZE);
                hash.read(&mReceiveBuffer);
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                  "Received transaction request for hash %s", hash.hex().text());

                // Find block height
                unsigned int height = mChain->outputs().getBlockHeight(hash);

                if(height == 0xffffffff)
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                      "Block height not found for transaction %s", hash.hex().text());
                }
                else
                {
                    // Get Block at height
                    BlockReference block(mChain->getBlock(height));
                    if(block)
                    {
                        unsigned int offset = 0;
                        for(TransactionList::iterator trans = block->transactions.begin();
                          trans != block->transactions.end(); ++trans, ++offset)
                            if((*trans)->hash() == hash)
                            {
                                sendData.writeString("tran:");
                                sendData.writeUnsignedInt(0);

                                sendData.writeUnsignedInt(height); // Block height
                                (*trans)->hash().write(&sendData); // Hash
                                sendData.writeUnsignedInt((*trans)->size()); // Size
                                sendData.writeUnsignedInt((*trans)->lockTime); // Lock Time

                                // Inputs
                                sendData.writeUnsignedInt((*trans)->inputs.size());
                                for(std::vector<Input>::iterator input = (*trans)->inputs.begin();
                                  input != (*trans)->inputs.end(); ++input)
                                {
                                    input->outpoint.transactionID.write(&sendData);
                                    sendData.writeUnsignedInt(input->outpoint.index);
                                    input->script.setReadOffset(0);
                                    if(offset == 0)
                                        sendData.writeString(ScriptInterpreter::coinBaseText(
                                          input->script, block->header.version), true);
                                    else
                                        sendData.writeString(ScriptInterpreter::scriptText(
                                          input->script, mChain->forks(), height), true);
                                    sendData.writeUnsignedInt(input->sequence);
                                }

                                // Outputs
                                sendData.writeUnsignedInt((*trans)->outputs.size());
                                for(std::vector<Output>::iterator output =
                                  (*trans)->outputs.begin(); output != (*trans)->outputs.end();
                                  ++output)
                                {
                                    sendData.writeLong(output->amount);
                                    output->script.setReadOffset(0);
                                    sendData.writeString(ScriptInterpreter::scriptText(
                                      output->script, mChain->forks(), height), true);
                                }

                                // Update result size
                                sendData.setWriteOffset(5);
                                sendData.writeUnsignedInt(sendData.length() - 9);

                                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                                  "Sending transaction data : %d B", sendData.length());
                            }
                    }
                }
            }
        }
        else if(command == "head")
        {
            // Return header

        }
        else if(command == "blok")
        {
            // Return block for specified height
            if(mReceiveBuffer.remaining() < 4)
                NextCash::Log::add(NextCash::Log::WARNING, mName,
                  "Received short block request");
            else
            {
                unsigned int height = mReceiveBuffer.readUnsignedInt(); // Height
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                  "Received block request for height %d", height);

                // Get Block at height
                unsigned int inputCount, outputCount;
                int64_t amountSent;
                BlockReference block(mChain->getBlock(height));
                if(block)
                {
                    sendData.writeString("blok:");
                    sendData.writeUnsignedLong(0UL);

                    sendData.writeUnsignedInt(height); // Height
                    block->header.hash().write(&sendData); // Hash
                    sendData.writeUnsignedInt(block->header.time); // Time
                    sendData.writeUnsignedInt(block->size()); // Size
                    sendData.writeUnsignedLong(block->actualCoinbaseAmount() -
                      coinBaseAmount(height)); // Fees
                    sendData.writeUnsignedInt(block->transactions.size()); // Transaction Count

                    inputCount = 0;
                    outputCount = 0;
                    amountSent = 0L;
                    for(TransactionList::iterator trans = block->transactions.begin();
                      trans != block->transactions.end(); ++trans)
                    {
                        inputCount += (*trans)->inputs.size();
                        outputCount += (*trans)->outputs.size();
                        for(std::vector<Output>::iterator output = (*trans)->outputs.begin();
                          output != (*trans)->outputs.end(); ++output)
                            amountSent += output->amount;
                    }
                    sendData.writeUnsignedInt(inputCount); // Input Count
                    sendData.writeUnsignedInt(outputCount); // Output Count
                    sendData.writeLong(amountSent); // Amount Sent

                    for(TransactionList::iterator trans = block->transactions.begin();
                      trans != block->transactions.end(); ++trans)
                    {
                        (*trans)->hash().write(&sendData); // Hash
                        sendData.writeUnsignedInt((*trans)->size()); // Size
                        sendData.writeUnsignedInt((*trans)->inputs.size()); // Input Count
                        sendData.writeUnsignedInt((*trans)->outputs.size()); // Output Count
                        amountSent = 0L;
                        for(std::vector<Output>::iterator output = (*trans)->outputs.begin();
                          output != (*trans)->outputs.end(); ++output)
                            amountSent += output->amount;
                        sendData.writeLong(amountSent); // Amount Sent
                    }

                    // Update result size
                    sendData.setWriteOffset(5);
                    sendData.writeUnsignedLong(sendData.length() - 13);

                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, mName,
                      "Sending block data : %d KB", sendData.length() / 1000UL);
                }
            }
        }
        else if(command == "blkh")
        {
            // Return block hash at specified height

        }
        else if(command == "blkn")
        {
            // Return block height for specified hash

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
