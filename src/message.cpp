/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "message.hpp"

#include "arcmist/io/stream.hpp"
#include "arcmist/io/buffer.hpp"
#include "arcmist/base/log.hpp"
#include "arcmist/base/endian.hpp"
#include "arcmist/base/math.hpp"
#include "arcmist/crypto/digest.hpp"
#include "base.hpp"

#include <cstring>

#define BITCOIN_MESSAGE_LOG_NAME "BitCoin Message"


namespace BitCoin
{
    namespace Message
    {
        const char *nameFor(Type pType)
        {
            switch(pType)
            {
                case VERSION:
                    return "version";
                case VERACK:
                    return "verack";
                case PING:
                    return "ping";
                case PONG:
                    return "pong";
                case REJECT:
                    return "reject";
                case GET_ADDRESSES:
                    return "getaddr";
                case ADDRESSES:
                    return "addr";
                case ALERT:
                    return "alert";
                case FEE_FILTER:
                    return "feefilter";
                case FILTER_ADD:
                    return "filteradd";
                case FILTER_CLEAR:
                    return "filterclear";
                case FILTER_LOAD:
                    return "filterload";
                case SEND_HEADERS:
                    return "sendheaders";
                case GET_BLOCKS:
                    return "getblocks";
                case BLOCK:
                    return "block";
                case GET_DATA:
                    return "getdata";
                case GET_HEADERS:
                    return "getheaders";
                case HEADERS:
                    return "headers";
                case INVENTORY:
                    return "inv";
                case MEM_POOL:
                    return "mempool";
                case MERKLE_BLOCK:
                    return "merkleblock";
                case NOT_FOUND:
                    return "notfound";
                case TRANSACTION:
                    return "tx";
                case SEND_COMPACT:
                    return "sendcmpct";
                case COMPACT_BLOCK:
                    return "cmpctblock";
                case GET_BLOCK_TRANSACTIONS:
                    return "getblocktxn";
                case BLOCK_TRANSACTIONS:
                    return "blocktxn";
                default:
                case UNKNOWN:
                    return "";
            }
        }

        Type typeFor(const char *pCommand)
        {
            if(std::strcmp(pCommand, "version") == 0)
                return VERSION;
            else if(std::strcmp(pCommand, "verack") == 0)
                return VERACK;
            else if(std::strcmp(pCommand, "ping") == 0)
                return PING;
            else if(std::strcmp(pCommand, "pong") == 0)
                return PONG;
            else if(std::strcmp(pCommand, "reject") == 0)
                return REJECT;
            else if(std::strcmp(pCommand, "getaddr") == 0)
                return GET_ADDRESSES;
            else if(std::strcmp(pCommand, "addr") == 0)
                return ADDRESSES;
            else if(std::strcmp(pCommand, "alert") == 0)
                return ALERT;
            else if(std::strcmp(pCommand, "feefilter") == 0)
                return FEE_FILTER;
            else if(std::strcmp(pCommand, "filteradd") == 0)
                return FILTER_ADD;
            else if(std::strcmp(pCommand, "filterclear") == 0)
                return FILTER_CLEAR;
            else if(std::strcmp(pCommand, "filterload") == 0)
                return FILTER_LOAD;
            else if(std::strcmp(pCommand, "sendheaders") == 0)
                return SEND_HEADERS;
            else if(std::strcmp(pCommand, "getblocks") == 0)
                return GET_BLOCKS;
            else if(std::strcmp(pCommand, "block") == 0)
                return BLOCK;
            else if(std::strcmp(pCommand, "getdata") == 0)
                return GET_DATA;
            else if(std::strcmp(pCommand, "getheaders") == 0)
                return GET_HEADERS;
            else if(std::strcmp(pCommand, "headers") == 0)
                return HEADERS;
            else if(std::strcmp(pCommand, "inv") == 0)
                return INVENTORY;
            else if(std::strcmp(pCommand, "mempool") == 0)
                return MEM_POOL;
            else if(std::strcmp(pCommand, "merkleblock") == 0)
                return MERKLE_BLOCK;
            else if(std::strcmp(pCommand, "notfound") == 0)
                return NOT_FOUND;
            else if(std::strcmp(pCommand, "tx") == 0)
                return TRANSACTION;
            else if(std::strcmp(pCommand, "sendcmpct") == 0)
                return SEND_COMPACT;
            else if(std::strcmp(pCommand, "cmpctblock") == 0)
                return COMPACT_BLOCK;
            else if(std::strcmp(pCommand, "getblocktxn") == 0)
                return GET_BLOCK_TRANSACTIONS;
            else if(std::strcmp(pCommand, "blocktxn") == 0)
                return BLOCK_TRANSACTIONS;
            else
                return UNKNOWN;
        }

        Data *Interpreter::read(ArcMist::Buffer *pInput, const char *pName)
        {
            unsigned int startReadOffset = pInput->readOffset();
            pInput->setInputEndian(ArcMist::Endian::LITTLE);

            // Start String
            const uint8_t *startBytes = networkStartBytes();
            unsigned int matchOffset = 0;
            bool startStringFound = false;

            // Search for start string
            while(pInput->remaining())
            {
                if(pInput->readByte() == startBytes[matchOffset])
                {
                    matchOffset++;
                    if(matchOffset == 4)
                    {
                        startStringFound = true;
                        startReadOffset = pInput->readOffset() - 4;
                        break;
                    }
                }
                else
                    matchOffset = 0;
            }

            if(!startStringFound)
                return NULL;

            // Check if header is complete
            if(pInput->remaining() < 20)
            {
                //ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName, "Header not fully received : %d / %d",
                //  pInput->remaining() + 4, 24); // Add 4 for start string that is already read
                pInput->setReadOffset(startReadOffset);
                return NULL;
            }

            // Command Name (12 bytes padded with nulls)
            ArcMist::String command = pInput->readString(12);

            // Payload Size (4 bytes)
            uint32_t payloadSize = pInput->readUnsignedInt();

            // Check Sum (4 bytes) SHA256(SHA256(payload))
            uint8_t receivedCheckSum[4];
            pInput->read(receivedCheckSum, 4);

            // Check if payload is complete
            if(payloadSize > pInput->remaining())
            {
                if(strcmp(command, "block") == 0 && pInput->remaining() > 80)
                {
                    Block block;
                    block.read(pInput, false, false, true);

                    if(pendingBlockHash.isEmpty())
                    {
                        // Starting new block
                        pendingBlockStartTime = getTime();
                        pendingBlockLastReportTime = pendingBlockStartTime;
                        pendingBlockHash = block.hash;
                        lastPendingBlockSize = pInput->remaining();
                        pendingBlockUpdateTime = pendingBlockStartTime;
                    }
                    else if(pendingBlockHash == block.hash)
                    {
                        if(pInput->remaining() != lastPendingBlockSize)
                        {
                            lastPendingBlockSize = pInput->remaining();
                            pendingBlockUpdateTime = getTime();
                        }

                        // Continuing block
                        if(getTime() - pendingBlockLastReportTime >= 30)
                        {
                            pendingBlockLastReportTime = getTime();
                            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, pName,
                              "Block downloading %d / %d (%ds) : %s", pInput->remaining(), payloadSize,
                              pendingBlockUpdateTime - pendingBlockStartTime, block.hash.hex().text());
                        }
                    }
                    else
                    {
                        // New block started without finishing last block
                        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, pName,
                          "Failed block download : %s", pendingBlockHash.hex().text());

                        // Starting new block
                        pendingBlockStartTime = getTime();
                        pendingBlockLastReportTime = pendingBlockStartTime;
                        pendingBlockHash = block.hash;
                        lastPendingBlockSize = pInput->remaining();
                        pendingBlockUpdateTime = pendingBlockStartTime;
                    }
                }
                // else
                    // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, pName,
                      // "Payload not fully received <%s> : %d / %d", command, pInput->remaining(), payloadSize);

                // Set read offset back to beginning of message
                pInput->setReadOffset(startReadOffset);

                // Allocate enough memory in this buffer for the full message
                pInput->setSize(payloadSize + 24); // 24 for message header
                return NULL;
            }

            // Read payload
            unsigned int payloadOffset = pInput->readOffset();

            // Validate check sum
            uint8_t checkSum[4];
            ArcMist::Buffer checkSumData(32);
            ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
            digest.writeStream(pInput, payloadSize);
            digest.getResult(&checkSumData);
            checkSumData.read(checkSum, 4);
            if(std::memcmp(checkSum, receivedCheckSum, 4) != 0)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, pName,
                  "Invalid message check sum. rec %08x != comp %08x",
                  *((uint32_t *)receivedCheckSum), *((uint32_t *)checkSum));
                return NULL;
            }

            pInput->setReadOffset(payloadOffset);
            Data *result = NULL;
            switch(typeFor(command))
            {
                case VERSION:
                    result = new VersionData();
                    break;
                case VERACK:
                    result = new Data(VERACK);
                    break;
                case PING:
                    result = new PingData();
                    break;
                case PONG:
                    result = new PongData();
                    break;
                case REJECT:
                    result = new RejectData();
                    break;
                case GET_ADDRESSES:
                    result = new Data(GET_ADDRESSES);
                    break;
                case ADDRESSES:
                    result = new AddressesData();
                    break;
                case ALERT:
                    result = new Data(ALERT);
                    break;
                case FEE_FILTER:
                    result = new FeeFilterData();
                    break;
                case FILTER_ADD:
                    result = new FilterAddData();
                    break;
                case FILTER_CLEAR:
                    result = new Data(FILTER_CLEAR);
                    break;
                case FILTER_LOAD:
                    result = new FilterLoadData();
                    break;
                case SEND_HEADERS:
                    result = new Data(SEND_HEADERS);
                    break;
                case GET_BLOCKS:
                    result = new GetBlocksData();
                    break;
                case BLOCK:
                    result = new BlockData();
                    break;
                case GET_DATA:
                    result = new GetDataData();
                    break;
                case GET_HEADERS:
                    result = new GetHeadersData();
                    break;
                case HEADERS:
                    result = new HeadersData();
                    break;
                case INVENTORY:
                    result = new InventoryData();
                    break;
                case MEM_POOL:
                    result = new Data(MEM_POOL);
                    break;
                case MERKLE_BLOCK:
                    result = new MerkleBlockData();
                    break;
                case NOT_FOUND:
                    result = new NotFoundData();
                    break;
                case TRANSACTION:
                    result = new TransactionData();
                    break;
                case SEND_COMPACT:
                    result = new SendCompactData();
                    break;
                case COMPACT_BLOCK:
                    result = new CompactBlockData();
                    break;
                case GET_BLOCK_TRANSACTIONS:
                    result = new GetBlockTransactionsData();
                    break;
                case BLOCK_TRANSACTIONS:
                    result = new BlockTransactionsData();
                    break;
                default:
                case UNKNOWN:
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, pName,
                      "Unknown command name (%s). Discarding.", command.text());
                    result = NULL;
                    break;
            }

            if(result != NULL && !result->read(pInput, payloadSize, version))
            {
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_MESSAGE_LOG_NAME,
                  "Failed to read <%s> message", command.text());
                delete result;
                result = NULL;
            }

            if(result != NULL && result->type == BLOCK)
            {
                // Block downloaded completely before first parsing of incoming data
                if(pendingBlockHash != ((BlockData *)result)->block->hash)
                    pendingBlockStartTime = getTime();
                pendingBlockUpdateTime = 0;
                pendingBlockHash.clear();
            }

            pInput->flush();
            return result;
        }

        void Interpreter::write(Data *pData, ArcMist::Buffer *pOutput)
        {
            pOutput->setOutputEndian(ArcMist::Endian::LITTLE);

            // Write header
            // Start String (4 bytes)
            pOutput->writeHex(networkStartString());

            // Command Name (12 bytes padded with nulls)
            const char *name = nameFor(pData->type);
            pOutput->writeString(name);

            // Pad with nulls
            for(int i=std::strlen(name);i<12;i++)
                pOutput->writeByte(0);

            // Write payload to buffer
            ArcMist::Buffer payload;
            payload.setOutputEndian(ArcMist::Endian::LITTLE);
            pData->write(&payload);

            // Payload Size (4 bytes)
            pOutput->writeUnsignedInt(payload.length());

            // Check Sum (4 bytes) SHA256(SHA256(payload))
            ArcMist::Buffer checkSum(32);
            ArcMist::Digest digest(ArcMist::Digest::SHA256_SHA256);
            digest.writeStream(&payload, payload.length());
            digest.getResult(&checkSum);
            pOutput->writeStream(&checkSum, 4);

            // Write payload
            payload.setReadOffset(0);
            pOutput->writeStream(&payload, payload.length());
        }

        void InventoryHash::write(ArcMist::OutputStream *pStream) const
        {
            // Type
            pStream->writeUnsignedInt(type);

            // Hash
            hash.write(pStream);
        }

        bool InventoryHash::read(ArcMist::InputStream *pStream)
        {
            // Type
            type = static_cast<InventoryHash::Type>(pStream->readUnsignedInt());

            // Hash
            return hash.read(pStream);
        }

        Inventory::~Inventory()
        {
            for(iterator item=begin();item!=end();++item)
                delete *item;
        }

        void Inventory::write(ArcMist::OutputStream *pStream) const
        {
            // Inventory Hash Count
            writeCompactInteger(pStream, size());

            // Inventory
            for(const_iterator item=begin();item!=end();++item)
                (*item)->write(pStream);
        }

        bool Inventory::read(ArcMist::InputStream *pStream, unsigned int pSize)
        {
            // Inventory Hash Count
            unsigned int startReadOffset = pStream->readOffset();
            uint64_t count = readCompactInteger(pStream);
            if(pSize - pStream->readOffset() - startReadOffset < count)
                return false;

            // Inventory
            resize(count);
            unsigned int readCount = 0;
            for(iterator item=begin();item!=end();++item)
            {
                *item = new InventoryHash();
                readCount++;
                if(!(*item)->read(pStream))
                {
                    delete *item;
                    resize(readCount-1);
                    return false;
                }
            }

            return true;
        }

        VersionData::VersionData(const uint8_t *pReceivingIP, uint16_t pReceivingPort,
                                 const uint8_t *pTransmittingIP, uint16_t pTransmittingPort,
                                 bool pFullNode, uint32_t pStartBlockHeight, bool pRelay) : Data(VERSION)
        {
            version = PROTOCOL_VERSION;
            services = 0x00;

            if(pFullNode)
                services |= FULL_NODE_BIT;

            //services |= FILTER_NODE_BIT; //TODO BIP-0111 Add 0x02 (1 << 2) bit to services to support filter messages

            time = getTime();

            // Receiving
            receivingServices = 0x01;
            std::memcpy(receivingIPv6, pReceivingIP, 16);
            receivingPort = pReceivingPort;

            // Transmitting
            transmittingServices = services; // Same as services
            std::memcpy(transmittingIPv6, pTransmittingIP, 16);
            transmittingPort = pTransmittingPort;

            // Nonce
            nonce = ArcMist::Math::randomLong();

            // User Agent
            userAgent = BITCOIN_USER_AGENT;

            // Status
            startBlockHeight = pStartBlockHeight;
            relay = pRelay;
        }

        void VersionData::write(ArcMist::OutputStream *pStream)
        {
            // Version
            pStream->writeInt(version);

            // Services Supported
            pStream->writeUnsignedLong(services);

            // Timestamp
            pStream->writeLong(time);

            // Receiving Services Supported
            pStream->writeUnsignedLong(receivingServices);

            // Receiving IPv6 (16 bytes)
            pStream->write(receivingIPv6, 16);

            // Receiving Port
            pStream->setOutputEndian(ArcMist::Endian::BIG);
            pStream->writeUnsignedShort(receivingPort);
            pStream->setOutputEndian(ArcMist::Endian::LITTLE);

            // Transmitting Services (Same as Services Supported above)
            pStream->writeUnsignedLong(transmittingServices);

            // Transmitting IPv6 (16 bytes)
            pStream->write(transmittingIPv6, 16);

            // Transmitting Port
            pStream->setOutputEndian(ArcMist::Endian::BIG);
            pStream->writeUnsignedShort(transmittingPort);
            pStream->setOutputEndian(ArcMist::Endian::LITTLE);

            // Nonce (Random)
            pStream->writeUnsignedLong(nonce);

            // User Agent Bytes
            writeCompactInteger(pStream, userAgent.length());

            // User Agent
            pStream->writeString(userAgent);

            // Start Block Height
            pStream->writeUnsignedInt(startBlockHeight);

            // Relay Transactions and Inventory Messages
            pStream->writeByte(relay);
        }

        bool VersionData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            unsigned int startReadOffset = pStream->readOffset();

            if(pSize < 81)
                return false;

            // Version
            version = pStream->readInt();

            // Services Supported
            services = pStream->readUnsignedLong();

            // Timestamp
            time = pStream->readLong();

            // Receiving Services Supported
            receivingServices = pStream->readUnsignedLong();

            // Receiving IPv6 (16 bytes)
            pStream->read(receivingIPv6, 16);

            // Receiving Port
            pStream->setInputEndian(ArcMist::Endian::BIG);
            receivingPort = pStream->readUnsignedShort();
            pStream->setInputEndian(ArcMist::Endian::LITTLE);

            // Transmitting Services (Same as Services Supported above)
            transmittingServices = pStream->readUnsignedLong();

            // Transmitting IPv6 (16 bytes)
            pStream->read(transmittingIPv6, 16);

            // Transmitting Port
            pStream->setInputEndian(ArcMist::Endian::BIG);
            transmittingPort = pStream->readUnsignedShort();
            pStream->setInputEndian(ArcMist::Endian::LITTLE);

            // Nonce (Random)
            nonce = pStream->readUnsignedLong();

            // User Agent Bytes
            uint64_t userAgentLength = readCompactInteger(pStream);
            if(userAgentLength > 512)
            {
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, BITCOIN_MESSAGE_LOG_NAME,
                  "User Agent too long : %d", userAgentLength);
                return false;
            }

            if(pSize - pStream->readOffset() - startReadOffset < userAgentLength + 5)
                return false;

            // User Agent
            userAgent = pStream->readString(userAgentLength);

            // Start Block Height
            startBlockHeight = pStream->readUnsignedInt();

            // Relay Transactions and Inventory Messages
            relay = pStream->readByte();

            return true;
        }

        void PingData::write(ArcMist::OutputStream *pStream)
        {
            // Nonce (Random)
            pStream->writeUnsignedLong(nonce);
        }

        bool PingData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            if(pSize < 4)
                return false;

            // Nonce (Random)
            nonce = pStream->readUnsignedLong();
            return true;
        }

        void PongData::write(ArcMist::OutputStream *pStream)
        {
            // Nonce (Random)
            pStream->writeUnsignedLong(nonce);
        }

        bool PongData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            // No nonce before version 60000
            if(pVersion <= 60000)
            {
                nonce = 0;
                return true;
            }

            if(pSize < 4)
                return false;

            // Nonce (Random)
            nonce = pStream->readUnsignedLong();
            return true;
        }

        void RejectData::write(ArcMist::OutputStream *pStream)
        {
            // User Command
            writeCompactInteger(pStream, strlen(command));

            // Command
            pStream->writeString(command);

            // Code
            pStream->writeByte(code);

            // User Reason
            writeCompactInteger(pStream, strlen(reason));

            // Reason
            pStream->writeString(reason);

            // Extra
            extra.setReadOffset(0);
            pStream->writeStream(&extra, extra.length());
        }

        bool RejectData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            if(pSize < 1)
                return false;

            unsigned int startReadOffset = pStream->readOffset();

            // Command Bytes
            uint64_t commandLength = readCompactInteger(pStream);
            if(pSize - pStream->readOffset() - startReadOffset < commandLength + 1)
                return false;

            // Command
            command = pStream->readString(commandLength);

            // Code
            code = pStream->readByte();

            // Reason Bytes
            uint64_t reasonLength = readCompactInteger(pStream);
            if(pSize - pStream->readOffset() - startReadOffset < reasonLength)
                return false;

            // Reason
            reason = pStream->readString(reasonLength);

            // Extra (remaining payload)
            pStream->readStream(&extra, pSize - pStream->readOffset() - startReadOffset);
            return true;
        }

        void Address::write(ArcMist::OutputStream *pStream) const
        {
            pStream->writeUnsignedInt(time);
            pStream->writeUnsignedLong(services);
            pStream->write(ip, 16);
            pStream->writeUnsignedShort(ArcMist::Endian::convert(port, ArcMist::Endian::BIG));
        }

        bool Address::read(ArcMist::InputStream *pStream)
        {
            if(pStream->remaining() < 30)
                return false;

            time = pStream->readUnsignedInt();
            services = pStream->readUnsignedLong();
            pStream->read(ip, 16);
            port = ArcMist::Endian::convert(pStream->readUnsignedShort(), ArcMist::Endian::BIG);
            return true;
        }

        void AddressesData::write(ArcMist::OutputStream *pStream)
        {
            // Address Count
            writeCompactInteger(pStream, addresses.size());

            // Addresses
            for(std::vector<Address>::iterator address=addresses.begin();address!=addresses.end();++address)
                address->write(pStream);
        }

        bool AddressesData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            if(pSize < 1)
                return false;

            unsigned int startReadOffset = pStream->readOffset();

            // Address Count
            uint64_t count = readCompactInteger(pStream);
            if(pSize - pStream->readOffset() - startReadOffset < count)
                return false;

            // Addresses
            addresses.clear();
            addresses.resize(count);
            for(std::vector<Address>::iterator address=addresses.begin();address!=addresses.end();++address)
                if(!address->read(pStream))
                    return false;

            return true;
        }

        void FeeFilterData::write(ArcMist::OutputStream *pStream)
        {
            // Fee
            pStream->writeUnsignedLong(minimumFeeRate);
        }

        bool FeeFilterData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            if(pSize < 8)
                return false;

            // Fee
            minimumFeeRate = pStream->readUnsignedLong();
            return true;
        }

        void FilterAddData::write(ArcMist::OutputStream *pStream)
        {
        }

        bool FilterAddData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            //if(pSize < 1)
            //    return false;

            return true;
        }

        void FilterLoadData::write(ArcMist::OutputStream *pStream)
        {
        }

        bool FilterLoadData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            //if(pSize < 1)
            //    return false;

            return true;
        }

        void GetBlocksData::write(ArcMist::OutputStream *pStream)
        {
            // Version
            pStream->writeUnsignedInt(version);

            // Block Headers Count
            if(blockHeaderHashes.size() > 0)
                writeCompactInteger(pStream, blockHeaderHashes.size());
            else
                writeCompactInteger(pStream, 0);

            // Block Header Hashes
            for(unsigned int i=0;i<blockHeaderHashes.size();i++)
                blockHeaderHashes[i].write(pStream);

            stopHeaderHash.write(pStream);
        }

        bool GetBlocksData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            if(pSize < 5)
                return false;

            unsigned int startReadOffset = pStream->readOffset();

            // Version
            version = pStream->readUnsignedInt();

            // Block Headers Count
            uint64_t count = readCompactInteger(pStream);
            if(pSize - pStream->remaining() - startReadOffset < count * 32)
                return false;

            // Block Header Hashes
            blockHeaderHashes.resize(count);
            for(unsigned int i=0;i<blockHeaderHashes.size();i++)
                if(!blockHeaderHashes[i].read(pStream, 32))
                    return false;

            // Stop header hash
            if(!stopHeaderHash.read(pStream, 32))
                return false;

            return true;
        }

        void GetHeadersData::write(ArcMist::OutputStream *pStream)
        {
            // Version
            pStream->writeUnsignedInt(version);

            // Block Headers Count
            if(blockHeaderHashes.size() > 0)
                writeCompactInteger(pStream, blockHeaderHashes.size());
            else
                writeCompactInteger(pStream, 0);

            // Block Header Hashes
            for(unsigned int i=0;i<blockHeaderHashes.size();i++)
                blockHeaderHashes[i].write(pStream);

            stopHeaderHash.write(pStream);
        }

        bool GetHeadersData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            if(pSize < 5)
                return false;

            unsigned int startReadOffset = pStream->readOffset();

            // Version
            version = pStream->readUnsignedInt();

            // Block Headers Count
            uint64_t count = readCompactInteger(pStream);
            if(pSize - pStream->remaining() - startReadOffset < count * 32)
                return false;

            // Block Header Hashes
            blockHeaderHashes.resize(count);
            for(unsigned int i=0;i<blockHeaderHashes.size();i++)
                if(!blockHeaderHashes[i].read(pStream, 32))
                    return false;

            // Stop header hash
            if(!stopHeaderHash.read(pStream, 32))
                return false;

            return true;
        }

        void HeadersData::write(ArcMist::OutputStream *pStream)
        {
            // Header count
            writeCompactInteger(pStream, headers.size());

            // Headers
            for(uint64_t i=0;i<headers.size();i++)
                headers[i]->write(pStream, false, true);
        }

        bool HeadersData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            if(pSize < 1)
                return false;

            unsigned int startReadOffset = pStream->readOffset();

            // Header count
            uint64_t count = readCompactInteger(pStream);
            if(pSize - pStream->readOffset() - startReadOffset < count)
                return false;

            // Headers
            headers.resize(count);
            for(uint64_t i=0;i<count;i++)
                headers[i] = NULL;

            for(uint64_t i=0;i<count;i++)
            {
                headers[i] = new Block();
                if(!headers[i]->read(pStream, false, true, true))
                    return false;
            }

            return true;
        }

        void MerkleBlockData::write(ArcMist::OutputStream *pStream)
        {
            // Block Header
            block.write(pStream, false, false);

            // Transaction Count (included in header)
            writeCompactInteger(pStream, block.transactionCount);

            // Hash Count
            writeCompactInteger(pStream, hashes.size());

            // Hashes
            for(unsigned int i=0;i<hashes.size();i++)
                hashes[i].write(pStream);

            // Flag Byte Count
            writeCompactInteger(pStream, flags.length());

            // Flags
            flags.setReadOffset(0);
            pStream->writeStream(&flags, flags.length());
        }

        bool MerkleBlockData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            unsigned int startReadOffset = pStream->readOffset();

            // Block Header
            if(!block.read(pStream, false, false, true))
                return false;

            // Transaction Count (included in header)

            if(pSize - pStream->remaining() - startReadOffset < 1)
                return false;

            // Hash Count
            uint64_t count = readCompactInteger(pStream);

            if(pSize - pStream->remaining() - startReadOffset < count * 32)
                return false;

            // Hashes
            hashes.resize(count);
            for(unsigned int i=0;i<hashes.size();i++)
                if(!hashes[i].read(pStream, 32))
                    return false;

            // Flag Byte Count
            flags.clear();
            count = readCompactInteger(pStream);

            if(pSize - pStream->remaining() - startReadOffset < count)
                return false;

            // Flags
            pStream->readStream(&flags, count);

            return true;
        }

        void PrefilledTransaction::write(ArcMist::OutputStream *pStream)
        {
            // Offset
            writeCompactInteger(pStream, offset);

            // Transaction
            transaction->write(pStream);
        }

        bool PrefilledTransaction::read(ArcMist::InputStream *pStream, unsigned int pSize)
        {
            // Offset
            offset = readCompactInteger(pStream);

            if(offset == 0xffffffff)
                return false;

            // Transaction
            return transaction->read(pStream);
        }

        CompactBlockData::CompactBlockData() : Data(COMPACT_BLOCK)
        {
            block = NULL;
        }

        CompactBlockData::~CompactBlockData()
        {
            if(deleteBlock && block != NULL)
                delete block;
        }

        bool CompactBlockData::updateShortIDs()
        {
            if(block == NULL)
                return false;

            ArcMist::Digest digest(ArcMist::Digest::SHA256);
            Hash sha256;
            Hash *shortID;
            bool found;

            // SHA256 of block header and nonce
            block->write(&digest, false, false);
            digest.writeUnsignedLong(nonce);
            digest.getResult(&sha256);

            for(std::vector<Transaction *>::iterator trans=block->transactions.begin();trans!=block->transactions.end();++trans)
            {
                // Check if in prefilled
                found = false;
                for(std::vector<PrefilledTransaction>::iterator prefilled=prefilledTransactionIDs.begin();prefilled!=prefilledTransactionIDs.end();++prefilled)
                    if(prefilled->transaction == *trans)
                    {
                        found = true;
                        break;
                    }

                if(found) // Don't put prefilled in short IDs
                    continue;

                // SipHash-2-4 of transaction ID and first two little endian 64 bit integers from header SHA256
                // Drop 2 most significant bytes from SipHash-2-4 to get to 6 bytes
                shortID = new Hash();
                if(!(*trans)->hash.getShortID(*shortID, sha256))
                {
                    delete shortID;
                    return false;
                }

                shortIDs.push_back(shortID);
            }

            return true;
        }

        void CompactBlockData::setBlock(Block *pBlock)
        {
            if(block != NULL)
                delete block;

            // Block
            block = pBlock;

            // Nonce
            nonce = ArcMist::Math::randomLong();

            // Short IDs
            shortIDs.clear();

            // Add Coinbase to prefilled automatically
            prefilledTransactionIDs.push_back(PrefilledTransaction(0, pBlock->transactions.front()));

            //TODO Add prefill transactions that we know the node doesn't have
        }

        bool CompactBlockData::fillBlock()
        {
            if(block == NULL)
                return false;

            // ArcMist::Digest digest(ArcMist::Digest::SHA256);
            // Hash sha256;
            // Hash shortID;
            // bool found;

            // // SHA256 of block header and nonce
            // block->write(&digest, false, false);
            // digest.writeUnsignedLong(nonce);
            // digest.getResult(&sha256);

            // for(HashList::iterator shortID=shortIDs.begin();shortID!=shortIDs.end();++shortID)
            // {
                // //TODO Search through mempool for transactions that compute a matching short ID
                // // If not all are found request with a GetBlockTransactionsData message
            // }

            return false;
        }

        void CompactBlockData::write(ArcMist::OutputStream *pStream)
        {
            if(block == NULL)
                return;

            // Block header without transaction count
            block->write(pStream, false, true);

            // A nonce for use in short transaction ID calculations
            pStream->writeUnsignedLong(nonce);

            updateShortIDs();

            // Number of short IDs
            writeCompactInteger(pStream, shortIDs.size());

            // Short IDs
            for(HashList::iterator shortID=shortIDs.begin();shortID!=shortIDs.end();++shortID)
                (*shortID)->write(pStream);

            // Number of prefilled transactions
            writeCompactInteger(pStream, prefilledTransactionIDs.size());

            // Prefilled transactions
            for(std::vector<PrefilledTransaction>::iterator trans=prefilledTransactionIDs.begin();trans!=prefilledTransactionIDs.end();++trans)
                trans->write(pStream);
        }

        bool CompactBlockData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            unsigned int startOffset = pStream->readOffset();

            if(block != NULL)
                delete block;

            block = new Block();

            if(pSize < 90)
                return false;

            // Block header without transaction count
            if(!block->read(pStream, false, false, true))
                return false;

            // A nonce for use in short transaction ID calculations
            nonce = pStream->readUnsignedLong();

            // Number of short IDs
            uint64_t count = readCompactInteger(pStream);

            if(count == 0xffffffff)
                return false;

            if(pSize - pStream->readOffset() - startOffset < count * 6)
                return false;

            shortIDs.resize(count);
            unsigned int readCount = 0;
            for(HashList::iterator shortID=shortIDs.begin();shortID!=shortIDs.end();++shortID)
            {
                *shortID = new Hash(6);

                if(!(*shortID)->read(pStream))
                {
                    delete *shortID;
                    shortIDs.erase(shortID);
                    shortIDs.resize(readCount);
                    break;
                }
                else
                    ++readCount;
            }

            if(readCount != count)
                return false;

            if(count == 0xffffffff)
                return false;

            // Number of prefilled transactions
            count = readCompactInteger(pStream);

            // Prefilled transactions
            prefilledTransactionIDs.resize(count);
            readCount = 0;
            for(std::vector<PrefilledTransaction>::iterator trans=prefilledTransactionIDs.begin();trans!=prefilledTransactionIDs.end();++trans)
            {
                if(!trans->read(pStream, pSize - pStream->readOffset() - startOffset))
                {
                    prefilledTransactionIDs.erase(trans);
                    prefilledTransactionIDs.resize(readCount);
                    break;
                }
                else
                    ++readCount;
            }

            if(readCount != count)
                return false;

            return true;
        }

        void GetBlockTransactionsData::write(ArcMist::OutputStream *pStream)
        {
            //TODO
        }

        bool GetBlockTransactionsData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            //TODO
            return false;
        }

        void BlockTransactionsData::write(ArcMist::OutputStream *pStream)
        {
            //TODO
        }

        bool BlockTransactionsData::read(ArcMist::InputStream *pStream, unsigned int pSize, int32_t pVersion)
        {
            //TODO
            return false;
        }

        bool test()
        {
            ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "------------- Starting Message Tests -------------");

            bool result = true;
            Interpreter interpreter;

            /***********************************************************************************************
             * VERSION
             ***********************************************************************************************/
            uint8_t rIP[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x04, 0x03, 0x02, 0x01 };
            uint8_t tIP[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x08, 0x07, 0x06, 0x05 };
            VersionData versionSendData(rIP, 1333, tIP, 1333, false, 125, false);
            ArcMist::Buffer messageBuffer;

            interpreter.write(&versionSendData, &messageBuffer);

            Data *messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed version message read");
                result = false;
            }
            else if(messageReceiveData->type != VERSION)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed version message read type");
                result = false;
            }
            else
            {
                // Check the messages have the same data
                VersionData *versionReceiveData = (VersionData *)messageReceiveData;
                bool versionDataMatches = true;

                if(versionSendData.version != versionReceiveData->version)
                    versionDataMatches = false;

                if(versionSendData.services != versionReceiveData->services)
                    versionDataMatches = false;

                if(versionSendData.time != versionReceiveData->time)
                    versionDataMatches = false;

                if(versionSendData.receivingServices != versionReceiveData->receivingServices)
                    versionDataMatches = false;

                if(std::memcmp(versionSendData.receivingIPv6, versionReceiveData->receivingIPv6, 16) != 0)
                    versionDataMatches = false;

                if(versionSendData.receivingPort != versionReceiveData->receivingPort)
                    versionDataMatches = false;

                if(versionSendData.transmittingServices != versionReceiveData->transmittingServices)
                    versionDataMatches = false;

                if(std::memcmp(versionSendData.transmittingIPv6, versionReceiveData->transmittingIPv6, 16) != 0)
                    versionDataMatches = false;

                if(versionSendData.transmittingPort != versionReceiveData->transmittingPort)
                    versionDataMatches = false;

                if(versionSendData.nonce != versionReceiveData->nonce)
                    versionDataMatches = false;

                if(versionSendData.userAgent != versionReceiveData->userAgent)
                    versionDataMatches = false;

                if(versionSendData.startBlockHeight != versionReceiveData->startBlockHeight)
                    versionDataMatches = false;

                if(versionSendData.relay != versionReceiveData->relay)
                    versionDataMatches = false;

                if(versionDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed version message");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed version message compare");
                    result = false;
                }
            }

            /***********************************************************************************************
             * VERACK
             ***********************************************************************************************/
            Data versionAcknowledgeData(VERACK);

            messageBuffer.clear();
            interpreter.write(&versionAcknowledgeData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed version acknowledge message read");
                result = false;
            }
            else if(messageReceiveData->type != VERACK)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed version acknowledge message read type");
                result = false;
            }
            else
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed version acknowledge message");

            /***********************************************************************************************
             * PING
             ***********************************************************************************************/
            PingData pingData;

            messageBuffer.clear();
            interpreter.write(&pingData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed ping message read");
                result = false;
            }
            else if(messageReceiveData->type != PING)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed ping message read type");
                result = false;
            }
            else
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed ping message");

            /***********************************************************************************************
             * PONG
             ***********************************************************************************************/
            PongData pongData(pingData.nonce);

            messageBuffer.clear();
            interpreter.write(&pongData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed pong message read");
                result = false;
            }
            else if(messageReceiveData->type != PONG)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed pong message read type");
                result = false;
            }
            else
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed pong message");

            /***********************************************************************************************
             * REJECT
             ***********************************************************************************************/
            RejectData rejectData("version", RejectData::PROTOCOL, "not cash", NULL);

            messageBuffer.clear();
            interpreter.write(&rejectData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed reject message read");
                result = false;
            }
            else if(messageReceiveData->type != REJECT)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed reject message read type");
                result = false;
            }
            else
            {
                RejectData *receivedRejectData = (RejectData *)messageReceiveData;
                bool rejectDataMatches = true;

                if(rejectData.command != receivedRejectData->command)
                    rejectDataMatches = false;

                if(rejectData.code != receivedRejectData->code)
                    rejectDataMatches = false;

                if(rejectData.reason != receivedRejectData->reason)
                    rejectDataMatches = false;

                if(rejectDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed reject message");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed reject message compare");
                    result = false;
                }
            }

            /***********************************************************************************************
             * GET_ADDRESSES
             ***********************************************************************************************/
            Data getAddressesData(GET_ADDRESSES);

            messageBuffer.clear();
            interpreter.write(&getAddressesData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed get addresses message read");
                result = false;
            }
            else if(messageReceiveData->type != GET_ADDRESSES)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed get addresses message read type");
                result = false;
            }
            else
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed get addresses message");

            /***********************************************************************************************
             * ADDRESSES
             ***********************************************************************************************/
            AddressesData addressesData;
            Address address;

            address.time = 123;
            address.services = 0x01;
            address.ip[15] = 0x80;
            address.port = 321;
            addressesData.addresses.push_back(address);

            address.time = 1234;
            address.services = 0x02;
            address.ip[15] = 0x88;
            address.port = 4321;
            addressesData.addresses.push_back(address);

            address.time = 12345;
            address.services = 0x03;
            address.ip[15] = 0xF0;
            address.port = 54321;
            addressesData.addresses.push_back(address);

            messageBuffer.clear();
            interpreter.write(&addressesData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed addresses message read");
                result = false;
            }
            else if(messageReceiveData->type != ADDRESSES)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed addresses message read type");
                result = false;
            }
            else
            {
                AddressesData *addressesReceiveData = (AddressesData *)messageReceiveData;
                bool addressesDataMatches = true;

                if(addressesData.addresses.size() != addressesReceiveData->addresses.size())
                    addressesDataMatches = false;

                if(addressesData.addresses[2].time != addressesReceiveData->addresses[2].time)
                    addressesDataMatches = false;

                if(addressesData.addresses[0].services != addressesReceiveData->addresses[0].services)
                    addressesDataMatches = false;

                if(std::memcmp(addressesData.addresses[0].ip, addressesReceiveData->addresses[0].ip, 16) != 0)
                    addressesDataMatches = false;

                if(addressesData.addresses[0].port != addressesReceiveData->addresses[0].port)
                    addressesDataMatches = false;

                if(addressesDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed addresses message");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed addresses message compare");
                    result = false;
                }
            }

            /***********************************************************************************************
             * FEE_FILTER
             ***********************************************************************************************/
            FeeFilterData feeFilterData(50);

            messageBuffer.clear();
            interpreter.write(&feeFilterData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed fee filter message read");
                result = false;
            }
            else if(messageReceiveData->type != FEE_FILTER)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed fee filter message read type");
                result = false;
            }
            else
            {
                FeeFilterData *receivedFeeFilterData = (FeeFilterData *)messageReceiveData;
                bool feeFilterDataMatches = true;

                if(feeFilterData.minimumFeeRate != receivedFeeFilterData->minimumFeeRate)
                    feeFilterDataMatches = false;

                if(feeFilterDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed fee filter message");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed fee filter message compare");
                    result = false;
                }
            }

            /***********************************************************************************************
             * FILTER_ADD
             ***********************************************************************************************/
            FilterAddData filterAddData;

            messageBuffer.clear();
            interpreter.write(&filterAddData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed filter add message read");
                result = false;
            }
            else if(messageReceiveData->type != FILTER_ADD)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed filter add message read type");
                result = false;
            }
            else
            {
                //FilterAddData *receivedFilterAddData = (FilterAddData *)messageReceiveData;
                //bool filterAddDataMatches = true;

                //TODO Filter Add data comparison test
                //if(filterAddData.minimumFeeRate != receivedFilterAddData->minimumFeeRate)
                //    filterAddDataMatches = false;

                //if(filterAddDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed filter add message");
                //else
                //{
                //    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed filter add message compare");
                //    result = false;
                //}
            }

            /***********************************************************************************************
             * FILTER_LOAD
             ***********************************************************************************************/
            FilterLoadData filterLoadData;

            messageBuffer.clear();
            interpreter.write(&filterLoadData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed filter load message read");
                result = false;
            }
            else if(messageReceiveData->type != FILTER_LOAD)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed filter load message read type");
                result = false;
            }
            else
            {
                //FilterLoadData *receivedFilterLoadData = (FilterLoadData *)messageReceiveData;
                //bool filterLoadDataMatches = true;

                //TODO Filter Load data comparison test
                //if(filterLoadData.minimumFeeRate != receivedFilterLoadData->minimumFeeRate)
                //    filterLoadDataMatches = false;

                //if(filterLoadDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed filter load message");
                //else
                //{
                //    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed filter load message compare");
                //    result = false;
                //}
            }

            /***********************************************************************************************
             * GET_BLOCKS
             ***********************************************************************************************/
            GetBlocksData getBlocksData;

            messageBuffer.clear();
            interpreter.write(&getBlocksData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed get blocks message read");
                result = false;
            }
            else if(messageReceiveData->type != GET_BLOCKS)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed get blocks message read type");
                result = false;
            }
            else
            {
                GetBlocksData *receivedGetBlocksDataData = (GetBlocksData *)messageReceiveData;
                bool getBlocksDataMatches = true;

                if(getBlocksData.version != receivedGetBlocksDataData->version)
                    getBlocksDataMatches = false;

                if(getBlocksData.blockHeaderHashes.size () != receivedGetBlocksDataData->blockHeaderHashes.size())
                    getBlocksDataMatches = false;

                for(unsigned int i=0;i<getBlocksData.blockHeaderHashes.size();i++)
                    if(getBlocksData.blockHeaderHashes[i] != receivedGetBlocksDataData->blockHeaderHashes[i])
                        getBlocksDataMatches = false;

                if(getBlocksData.stopHeaderHash != receivedGetBlocksDataData->stopHeaderHash)
                    getBlocksDataMatches = false;

                if(getBlocksDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed get blocks message");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed get blocks message compare");
                    result = false;
                }
            }

            /***********************************************************************************************
             * BLOCK
             ***********************************************************************************************/
            BlockData blockData;
            blockData.block = new Block();

            messageBuffer.clear();
            interpreter.write(&blockData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed block message read");
                result = false;
            }
            else if(messageReceiveData->type != BLOCK)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed block message read type");
                result = false;
            }
            else
            {
                BlockData *receivedBlockData = (BlockData *)messageReceiveData;
                bool blockDataMatches = true;

                if(blockData.block->version != receivedBlockData->block->version)
                    blockDataMatches = false;

                if(blockData.block->previousHash != receivedBlockData->block->previousHash)
                    blockDataMatches = false;

                if(blockData.block->merkleHash != receivedBlockData->block->merkleHash)
                    blockDataMatches = false;

                if(blockData.block->time != receivedBlockData->block->time)
                    blockDataMatches = false;

                if(blockData.block->targetBits != receivedBlockData->block->targetBits)
                    blockDataMatches = false;

                if(blockData.block->nonce != receivedBlockData->block->nonce)
                    blockDataMatches = false;

                if(blockData.block->transactions.size() != receivedBlockData->block->transactions.size())
                    blockDataMatches = false;

                //for(unsigned int i=0;i<blockData.transactions.size();i++)
                //    if(blockData.transactions[i] != receivedBlockData->transactions[i])
                //        blockDataMatches = false;

                if(blockDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed block message");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed block message compare");
                    result = false;
                }
            }

            /***********************************************************************************************
             * GET_DATA
             ***********************************************************************************************/
            GetDataData getDataData;

            messageBuffer.clear();
            interpreter.write(&getDataData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed get data message read");
                result = false;
            }
            else if(messageReceiveData->type != GET_DATA)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed get data message read type");
                result = false;
            }
            else
            {
                GetDataData *receivedGetDataData = (GetDataData *)messageReceiveData;
                bool getDataDataMatches = true;

                if(getDataData.inventory.size() != receivedGetDataData->inventory.size())
                    getDataDataMatches = false;

                Inventory::iterator item = getDataData.inventory.begin();
                Inventory::iterator receivedItem = receivedGetDataData->inventory.begin();
                for(;item!=getDataData.inventory.end() && receivedItem!=receivedGetDataData->inventory.end();++item,++receivedItem)
                    if(**item != **receivedItem)
                        getDataDataMatches = false;

                if(getDataDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed get data message");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed get data message compare");
                    result = false;
                }
            }

            /***********************************************************************************************
             * GET_HEADERS
             ***********************************************************************************************/
            GetHeadersData getHeadersData;

            messageBuffer.clear();
            interpreter.write(&getHeadersData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed get headers message read");
                result = false;
            }
            else if(messageReceiveData->type != GET_HEADERS)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed get headers message read type");
                result = false;
            }
            else
            {
                GetHeadersData *receivedGetHeadersData = (GetHeadersData *)messageReceiveData;
                bool getHeadersDataMatches = true;

                if(getHeadersData.version != receivedGetHeadersData->version)
                    getHeadersDataMatches = false;

                if(getHeadersData.blockHeaderHashes.size () != receivedGetHeadersData->blockHeaderHashes.size())
                    getHeadersDataMatches = false;

                for(unsigned int i=0;i<getHeadersData.blockHeaderHashes.size();i++)
                    if(getHeadersData.blockHeaderHashes[i] != receivedGetHeadersData->blockHeaderHashes[i])
                        getHeadersDataMatches = false;

                if(getHeadersData.stopHeaderHash != receivedGetHeadersData->stopHeaderHash)
                    getHeadersDataMatches = false;

                if(getHeadersDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed get headers message");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed get headers message compare");
                    result = false;
                }
            }

            /***********************************************************************************************
             * HEADERS
             ***********************************************************************************************/
            HeadersData headersData;

            messageBuffer.clear();
            interpreter.write(&headersData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed headers message read");
                result = false;
            }
            else if(messageReceiveData->type != HEADERS)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed headers message read type");
                result = false;
            }
            else
            {
                HeadersData *receivedHeadersData = (HeadersData *)messageReceiveData;
                bool headersDataMatches = true;

                if(headersData.headers.size() != receivedHeadersData->headers.size())
                    headersDataMatches = false;

                //for(unsigned int i=0;i<headersData.headers.size();i++)
                //    if(headersData.headers[i] != receivedHeadersData->headers[i])
                //        headersDataMatches = false;

                if(headersDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed headers message");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed headers message compare");
                    result = false;
                }
            }

            /***********************************************************************************************
             * INVENTORY
             ***********************************************************************************************/
            InventoryData inventoryData;

            messageBuffer.clear();
            interpreter.write(&inventoryData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed inventory message read");
                result = false;
            }
            else if(messageReceiveData->type != INVENTORY)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed inventory message read type");
                result = false;
            }
            else
            {
                InventoryData *receivedInventoryData = (InventoryData *)messageReceiveData;
                bool inventoryDataMatches = true;

                if(inventoryData.inventory.size() != receivedInventoryData->inventory.size())
                    inventoryDataMatches = false;

                Inventory::iterator item = inventoryData.inventory.begin();
                Inventory::iterator receivedItem = receivedInventoryData->inventory.begin();
                for(;item!=inventoryData.inventory.end() && receivedItem!=receivedInventoryData->inventory.end();++item,++receivedItem)
                    if(**item != **receivedItem)
                        inventoryDataMatches = false;

                if(inventoryDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed inventory message");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed inventory message compare");
                    result = false;
                }
            }

            /***********************************************************************************************
             * MEM_POOL
             ***********************************************************************************************/
            Data memPoolData(MEM_POOL);

            messageBuffer.clear();
            interpreter.write(&memPoolData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed mem pool message read");
                result = false;
            }
            else if(messageReceiveData->type != MEM_POOL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed mem pool message read type");
                result = false;
            }
            else
                ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed mem pool message");

            /***********************************************************************************************
             * MERKLE_BLOCK
             ***********************************************************************************************/
            MerkleBlockData merkleBlockData;

            messageBuffer.clear();
            interpreter.write(&merkleBlockData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed merkle block message read");
                result = false;
            }
            else if(messageReceiveData->type != MERKLE_BLOCK)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed merkle block message read type");
                result = false;
            }
            else
            {
                MerkleBlockData *receivedMerkleBlockData = (MerkleBlockData *)messageReceiveData;
                bool merkleBlockDataMatches = true;

                if(merkleBlockData.transactionCount != receivedMerkleBlockData->transactionCount)
                    merkleBlockDataMatches = false;

                if(merkleBlockData.hashes.size() != receivedMerkleBlockData->hashes.size())
                    merkleBlockDataMatches = false;

                for(unsigned int i=0;i<merkleBlockData.hashes.size();i++)
                    if(merkleBlockData.hashes[i] != receivedMerkleBlockData->hashes[i])
                        merkleBlockDataMatches = false;

                if(merkleBlockData.flags.length() != receivedMerkleBlockData->flags.length())
                    merkleBlockDataMatches = false;

                if(merkleBlockDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed merkle block message");
                else
                {
                    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed merkle block message compare");
                    result = false;
                }
            }

            /***********************************************************************************************
             * TRANSACTION
             ***********************************************************************************************/
            TransactionData transactionData;

            messageBuffer.clear();
            interpreter.write(&transactionData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed transaction message read");
                result = false;
            }
            else if(messageReceiveData->type != TRANSACTION)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed transaction message read type");
                result = false;
            }
            else
            {
                //TransactionData *receivedTransactionData = (TransactionData *)messageReceiveData;
                //bool transactionDataMatches = true;

                //TODO compare transaction
                //if(transactionData.transaction != receivedTransactionData->transaction)
                //    transactionDataMatches = false;

                //if(transactionDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed transaction message");
                //else
                //{
                //    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed transaction message compare");
                //    result = false;
                //}
            }

            /***********************************************************************************************
             * NOT_FOUND
             ***********************************************************************************************/
            NotFoundData notFoundData;

            messageBuffer.clear();
            interpreter.write(&notFoundData, &messageBuffer);
            messageReceiveData = interpreter.read(&messageBuffer, "Test");

            if(messageReceiveData == NULL)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed not found message read");
                result = false;
            }
            else if(messageReceiveData->type != NOT_FOUND)
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed not found message read type");
                result = false;
            }
            else
            {
                //NotFoundData *receivedNotFoundData = (NotFoundData *)messageReceiveData;
                //bool notFoundDataMatches = true;

                //TODO compare not found
                //if(notFoundData.transaction != receivedNotFoundData->transaction)
                //    notFoundDataMatches = false;

                //if(notFoundDataMatches)
                    ArcMist::Log::add(ArcMist::Log::INFO, BITCOIN_MESSAGE_LOG_NAME, "Passed not found message");
                //else
                //{
                //    ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_MESSAGE_LOG_NAME, "Failed not found message compare");
                //    result = false;
                //}
            }

            return result;
        }
    }
}
