/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_MESSAGE_HPP
#define BITCOIN_MESSAGE_HPP

#include "math.hpp"
#include "string.hpp"
#include "hash.hpp"
#include "stream.hpp"
#include "buffer.hpp"
#include "network.hpp"
#include "base.hpp"
#include "peer.hpp"
#include "transaction.hpp"
#include "block.hpp"
#include "key.hpp"
#include "bloom_filter.hpp"
#include "bloom_lookup.hpp"

#include <cstdint>


namespace BitCoin
{
    namespace Message
    {
        enum Type
        {
            UNKNOWN,

            // Control messages
            VERSION, VERACK, PING, PONG, GET_ADDRESSES, ADDRESSES, ALERT,
            FEE_FILTER, SEND_HEADERS,

            // Data messages
            GET_BLOCKS, BLOCK, GET_DATA, GET_HEADERS, HEADERS, INVENTORY,
            TRANSACTION,

            // Version >= 60002
            MEM_POOL, // BIP-0035 Respond with inventory of all transactions in mempool

            // Version >= 70001
            FILTER_ADD, FILTER_CLEAR, FILTER_LOAD, MERKLE_BLOCK, //BIP-0037
            NOT_FOUND,

            // Version >= 70002
            REJECT, // BIP-0061

            // Version >= 70014
            SEND_COMPACT, COMPACT_BLOCK, GET_COMPACT_TRANS, COMPACT_TRANS, // BIP-0152

            // BUIP-0093 Graphene
            GET_GRAPHENE, GRAPHENE, GET_GRAPHENE_TRANS, GRAPHENE_TRANS

        };

        const char *nameFor(Type pType);
        Type typeFor(const char *pCommand);

        class InventoryHash
        {
        public:

            enum Type { UNKNOWN = 0x00, TRANSACTION = 0x01, BLOCK = 0x02, FILTERED_BLOCK = 0x03,
              COMPACT_BLOCK = 0x04 };

            InventoryHash() : hash(32) { type = UNKNOWN; }
            InventoryHash(Type pType, const NextCash::Hash &pHash) { type = pType; hash = pHash; }
            InventoryHash(InventoryHash &pCopy) : hash(pCopy.hash) { type = pCopy.type; }

            bool operator == (const InventoryHash &pRight) { return type == pRight.type && hash == pRight.hash; }
            bool operator != (const InventoryHash &pRight) { return type != pRight.type || hash != pRight.hash; }

            void write(NextCash::OutputStream *pStream) const;
            bool read(NextCash::InputStream *pStream);

            Type type;
            NextCash::Hash hash;

        private:
            InventoryHash &operator = (InventoryHash &pRight);
        };

        class Inventory : public std::vector<InventoryHash *>
        {
        public:

            Inventory() {}
            ~Inventory();

            void write(NextCash::OutputStream *pStream) const;
            bool read(NextCash::InputStream *pStream, unsigned int pSize);

            void clear()
            {
                for(iterator hash=begin();hash!=end();++hash)
                    delete *hash;
                std::vector<InventoryHash *>::clear();
            }
            void clearNoDelete() { std::vector<InventoryHash *>::clear(); }

            typedef std::vector<InventoryHash *>::iterator iterator;
            typedef std::vector<InventoryHash *>::const_iterator const_iterator;

        private:
            Inventory(Inventory &pCopy);
            Inventory &operator = (Inventory &pRight);
        };

        class Data
        {
        public:

            Data(Type pType) { type = pType; }
            virtual ~Data() {}
            virtual void write(NextCash::OutputStream *pStream) {}
            virtual bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion)
            {
                if(pStream->remaining() < pSize)
                    return false;
                for(unsigned int i = 0; i < pSize; i++)
                    pStream->readByte();
                return true;
            }

            bool isBlockData();

            Type type;
            NextCash::stream_size size;

        };

        class Interpreter
        {
        public:

            Interpreter()
            {
                version = 0;
                pendingBlockStartTime = 0;
                pendingBlockLastReportTime = 0;
                pendingBlockUpdateTime = 0;
            }

            Data *read(NextCash::Buffer *pInput, const char *pName);
            void write(Data *pData, NextCash::Buffer *pOutput);

            int32_t version;
            NextCash::Hash pendingBlockHash;
            Time pendingBlockStartTime, pendingBlockLastReportTime, pendingBlockUpdateTime;
            unsigned int lastPendingBlockSize;

        };

        class VersionData : public Data
        {
        public:

            static const unsigned int FULL_NODE_BIT    = 0x01;
            static const unsigned int GETUTXO_NODE_BIT = 0x02; // BIP-0064
            static const unsigned int BLOOM_NODE_BIT   = 0x04; // BIP-0111 Supports bloom filters and merkle block requests
            static const unsigned int WITNESS_NODE_BIT = 0x08; // Segregated Witness
            static const unsigned int XTHIN_NODE_BIT   = 0x10; // BUIP-0010
            static const unsigned int CASH_NODE_BIT    = 0x20; // Bitcoin Cash (No longer used)
            static const unsigned int LIMITED_NODE_BIT = 0x0400; // BIP-0159 "Full" node serving only the last 288 (2 day) blocks

            VersionData() : Data(VERSION) { }
            VersionData(const uint8_t *pReceivingIP, uint16_t pReceivingPort, uint64_t pReceivingServices,
                        const uint8_t *pTransmittingIP, uint16_t pTransmittingPort,
                        bool pFullNode, uint32_t pStartBlockHeight, bool pRelay);

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            int32_t version;
            uint64_t services;
            int64_t time;
            uint64_t receivingServices;
            uint8_t receivingIPv6[16];
            uint16_t receivingPort;
            uint64_t transmittingServices; // Same as services
            uint8_t transmittingIPv6[16];
            uint16_t transmittingPort;
            uint64_t nonce;
            NextCash::String userAgent;
            uint32_t startBlockHeight;
            uint8_t relay; // Relay all transactions (without bloom filter)
        };

        class PingData : public Data
        {
        public:

            PingData() : Data(PING) { nonce = NextCash::Math::randomLong(); }

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            uint64_t nonce;
        };

        class PongData : public Data
        {
        public:

            PongData() : Data(PONG) { nonce = 0; }
            PongData(uint64_t pNonce) : Data(PONG) { nonce = pNonce; }

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            uint64_t nonce;
        };

        // BIP-0061
        class RejectData : public Data
        {
        public:

            enum Code
            {
                DECODE       = 0x01, // Decode issue, probably message header
                INVALID      = 0x10, // Invalid signature or proof of work
                PROTOCOL     = 0x11, // Unsupported version or protocol
                DUPLICATE    = 0x12, // Duplicate input spend or more than one of the same message
                NON_STANDARD = 0x40, // Transaction is non standard
                BELOW_DUST   = 0x41, // Output is below dust amount
                LOW_FEE      = 0x42, // Fee too low
                WRONG_CHAIN  = 0x43  // Block is for wrong chain
            };

            RejectData() : Data(REJECT) { code = 0; }
            RejectData(const char *pCommand, uint8_t pCode, const char *pReason, NextCash::Buffer *pExtra) : Data(REJECT)
            {
                command = pCommand;
                code = pCode;
                reason = pReason;

                if(pExtra != NULL)
                    extra.write(pExtra, pExtra->remaining());
            }

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            NextCash::String command;
            uint8_t code;
            NextCash::String reason;
            NextCash::Buffer extra;
        };

        class Address
        {
        public:

            Address()
            {
                time = 0;
                services = 0;
                std::memset(ip, 0, 16);
                port = 0;
            }
            Address(const Address &pCopy)
            {
                time = pCopy.time;
                services = pCopy.services;
                std::memcpy(ip, pCopy.ip, 16);
                port = pCopy.port;
            }

            void write(NextCash::OutputStream *pStream) const;
            bool read(NextCash::InputStream *pStream);

            Address &operator = (const Address &pRight)
            {
                time = pRight.time;
                services = pRight.services;
                std::memcpy(ip, pRight.ip, 16);
                port = pRight.port;
                return *this;
            }

            Address &operator = (const Peer &pRight)
            {
                time = pRight.time;
                services = pRight.services;
                std::memcpy(ip, pRight.address.ip, 16);
                port = pRight.address.port;
                return *this;
            }

            Time time;
            uint64_t services;
            uint8_t ip[16];
            uint16_t port;
        };

        class AddressesData : public Data
        {
        public:

            AddressesData() : Data(ADDRESSES) { }

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            std::vector<Address> addresses;
        };

        class FeeFilterData : public Data
        {
        public:

            FeeFilterData(uint64_t pMinimumFeeRate) : Data(FEE_FILTER) { minimumFeeRate = pMinimumFeeRate; }
            FeeFilterData() : Data(FEE_FILTER) { minimumFeeRate = 0; }

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            uint64_t minimumFeeRate; // Satoshis per KiB
        };

        class FilterAddData : public Data
        {
        public:

            FilterAddData() : Data(FILTER_ADD) { }

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            NextCash::Buffer data;
        };

        class FilterLoadData : public Data
        {
        public:

            FilterLoadData() : Data(FILTER_LOAD), filter(BloomFilter::STANDARD) { }

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            BloomFilter filter;
        };

        // Request block headers
        class GetBlocksData : public Data
        {
        public:

            GetBlocksData() : Data(GET_BLOCKS), stopHeaderHash(32) { version = PROTOCOL_VERSION; }

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            uint32_t version;
            NextCash::HashList hashes; // In reverse order (Highest block first)

            NextCash::Hash stopHeaderHash; // Zeroized to stop at highest block on chain

        };

        class BlockData : public Data
        {
        public:

            BlockData() : Data(BLOCK) {}
            BlockData(BlockReference &pBlock) : Data(BLOCK), block(pBlock) {}

            void write(NextCash::OutputStream *pStream)
            {
                if(block)
                    block->write(pStream);
            }
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion)
            {
                block = new Block();
                if(!block->read(pStream))
                {
                    block.clear();
                    return false;
                }
                return true;
            }

            BlockReference block;

        };

        class GetDataData : public Data
        {
        public:

            GetDataData() : Data(GET_DATA) { }

            void write(NextCash::OutputStream *pStream) { inventory.write(pStream); }
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion)
              { return inventory.read(pStream, pSize); }

            Inventory inventory;

        };

        // Request a Headers message
        class GetHeadersData : public Data
        {
        public:

            GetHeadersData() : Data(GET_HEADERS), stopHeaderHash(32) { version = PROTOCOL_VERSION; }

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            uint32_t version;

            // Listing of block hashes that you have in reverse order (Highest block first)
            // Maybe like every 100th block or something
            // First block in this list that they have they will send you headers for
            //   everything after through the stop header
            NextCash::HashList hashes;

            NextCash::Hash stopHeaderHash; // Zeroized to stop at highest block on chain

        };

        class HeadersData : public Data
        {
        public:

            HeadersData() : Data(HEADERS) {}

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            HeaderList headers;

        };

        class InventoryData : public Data
        {
        public:

            InventoryData() : Data(INVENTORY) { }

            void write(NextCash::OutputStream *pStream) { inventory.write(pStream); }
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion)
              { return inventory.read(pStream, pSize); }

            Inventory inventory;

        };

        // Used with FILTER_ADD, FILTER_CLEAR, FILTER_LOAD to request specific transactions
        class MerkleBlockData : public Data
        {
        public:

            MerkleBlockData() : Data(MERKLE_BLOCK) { }
            MerkleBlockData(BlockReference &pBlock, BloomFilter &pFilter,
              TransactionList &pIncludedTransactions);

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            // Validate hashes and get included "confirmed" transaction hashes.
            // Note: This assumes the block header has already been verified as valid in the most
            //   proof of work chain.
            bool validate(NextCash::HashList &pIncludedTransactionHashes);

            Header header;
            NextCash::HashList hashes;
            NextCash::Buffer flags;

        private:

            // Recursively parse merkle node hashes into a tree
            bool parse(MerkleNode *pNode, unsigned int pDepth, unsigned int &pHashesOffset, unsigned int &pBitOffset,
              unsigned char &pByte, NextCash::HashList &pIncludedTransactionHashes);

            // Recursively parse merkle tree and add hashes and flags for specified node
            void addNode(MerkleNode *pNode, unsigned int pDepth, unsigned int &pNextBitOffset,
              unsigned char &pNextByte, TransactionList &pIncludedTransactions);

        };

        class TransactionData : public Data
        {
        public:

            TransactionData() : Data(TRANSACTION) {}
            TransactionData(TransactionReference &pTransaction) : Data(TRANSACTION),
              transaction(pTransaction) {}

            void write(NextCash::OutputStream *pStream)
            {
                if(transaction)
                    transaction->write(pStream);
            }

            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion)
            {
                transaction = new Transaction();
                if(!transaction->read(pStream))
                {
                    transaction.clear();
                    return false;
                }
                return true;
            }

            TransactionReference transaction;

        };

        class NotFoundData : public Data
        {
        public:

            NotFoundData() : Data(NOT_FOUND) { }

            void write(NextCash::OutputStream *pStream) { inventory.write(pStream); }
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion)
              { return inventory.read(pStream, pSize); }

            Inventory inventory;

        };

        class SendCompactData : public Data
        {
        public:

            SendCompactData() : Data(SEND_COMPACT)
            {
                sendCompact = 0x00;
                version = 1L;
            }
            SendCompactData(bool pAnnounce, uint64_t pVersion) : Data(SEND_COMPACT)
            {
                if(pAnnounce)
                    sendCompact = 0x01;
                else
                    sendCompact = 0x00;
                version = pVersion;
            }

            void write(NextCash::OutputStream *pStream)
            {
                pStream->writeByte(sendCompact);
                pStream->writeUnsignedLong(version);
            }
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion)
            {
                if(pSize != 9)
                    return false;
                sendCompact = pStream->readByte();
                version = pStream->readUnsignedLong();
                return true;
            }

            bool sendCompact;
            uint64_t version;

        };

        class PrefilledTransaction
        {
        public:

            PrefilledTransaction() : transaction(NULL) { offset = 0; }
            PrefilledTransaction(const PrefilledTransaction &pCopy) :
              transaction(pCopy.transaction)
            {
                offset = pCopy.offset;
            }
            PrefilledTransaction(unsigned int pOffset, TransactionReference pTransaction) :
              transaction(pTransaction)
            {
                offset = pOffset;
            }
            ~PrefilledTransaction() {}

            PrefilledTransaction &operator = (const PrefilledTransaction &pRight)
            {
                offset = pRight.offset;
                transaction = pRight.transaction;
                return *this;
            }

            unsigned int offset;
            TransactionReference transaction; // Reference to transaction contained in block

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize);
        };

        class CompactBlockData : public Data
        {
        public:

            CompactBlockData();
            CompactBlockData(BlockReference &pBlock); // Create message from full block to send.

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            BlockReference block;
            uint64_t nonce;
            std::vector<uint64_t> shortIDs;
            std::vector<PrefilledTransaction> prefilled;

            // Return the short ID for the specified transaction ID.
            uint64_t calculateShortID(const NextCash::Hash &pTransactionID);

            Time time;

            // Calculate key values used in SipHash for short IDs.
            void calculateSipHashKeys();

        private:

            uint64_t mKey0 = 0;
            uint64_t mKey1 = 0;

        };

        class GetCompactTransData : public Data
        {
        public:

            GetCompactTransData() : Data(GET_COMPACT_TRANS) {}
            GetCompactTransData(const NextCash::Hash &pHeaderHash) : Data(GET_COMPACT_TRANS),
              headerHash(pHeaderHash) {}

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            NextCash::Hash headerHash;
            std::vector<unsigned int> offsets;

        };

        class CompactTransData : public Data
        {
        public:

            CompactTransData() : Data(COMPACT_TRANS) {}
            CompactTransData(const NextCash::Hash &pHeaderHash) : Data(COMPACT_TRANS),
              headerHash(pHeaderHash) {}
            ~CompactTransData() {}

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            NextCash::Hash headerHash;
            TransactionList transactions;
        };

        class GetGrapheneBlockData : public Data
        {
        public:

            GetGrapheneBlockData() : Data(GET_GRAPHENE) {}
            ~GetGrapheneBlockData() {}

            // void write(NextCash::OutputStream *pStream);
            // bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

        };

        class GrapheneBlockData : public Data
        {
        public:

            GrapheneBlockData() : Data(GRAPHENE), filter(BloomFilter::GRAPHENE) {}
            ~GrapheneBlockData() {}

            // void write(NextCash::OutputStream *pStream);
            // bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

            Header header;
            TransactionList transactions;
            uint64_t blockTransactionCount;

            // Set
            uint8_t ordered;
            uint64_t receiverItems;
            std::vector<uint8_t> order;
            BloomFilter filter;
            BloomLookup lookup;

        };

        class GetGrapheneTransactionData : public Data
        {
        public:

            GetGrapheneTransactionData() : Data(GET_GRAPHENE_TRANS) {}
            ~GetGrapheneTransactionData() {}

            // void write(NextCash::OutputStream *pStream);
            // bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

        };

        class GrapheneTransactionData : public Data
        {
        public:

            GrapheneTransactionData() : Data(GRAPHENE_TRANS) {}
            ~GrapheneTransactionData() {}

            // void write(NextCash::OutputStream *pStream);
            // bool read(NextCash::InputStream *pStream, unsigned int pSize, int32_t pVersion);

        };

        bool test();
    }
}

#endif
