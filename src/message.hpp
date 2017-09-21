/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_MESSAGE_HPP
#define BITCOIN_MESSAGE_HPP

#include "arcmist/base/math.hpp"
#include "arcmist/base/string.hpp"
#include "arcmist/io/stream.hpp"
#include "arcmist/io/buffer.hpp"
#include "arcmist/io/network.hpp"
#include "base.hpp"
#include "transaction.hpp"
#include "block.hpp"
#include "key.hpp"

#include <cstdint>


namespace BitCoin
{
    namespace Message
    {
        enum Type
        {
            UNKNOWN,

            // Control messages
            VERSION, VERACK, PING, PONG, REJECT, GET_ADDRESSES, ADDRESSES, ALERT,
            FEE_FILTER, FILTER_ADD, FILTER_CLEAR, FILTER_LOAD, SEND_HEADERS,

            // Data messages
            GET_BLOCKS, BLOCK, GET_DATA, GET_HEADERS, HEADERS, INVENTORY, MEM_POOL,
            MERKLE_BLOCK, NOT_FOUND, TRANSACTION,

            // Version >= 70014 BIP-0152
            SEND_COMPACT, COMPACT_BLOCK, GET_BLOCK_TRANSACTIONS, BLOCK_TRANSACTIONS

        };

        const char *nameFor(Type pType);
        Type typeFor(const char *pCommand);

        class InventoryHash
        {
        public:

            enum Type { UNKNOWN=0x00, TRANSACTION=0x01, BLOCK=0x02, FILTERED_BLOCK=0x03, COMPACT_BLOCK=0x04 };

            InventoryHash() : hash(32) { type = UNKNOWN; }
            InventoryHash(Type pType, const Hash &pHash) { type = pType; hash = pHash; }
            InventoryHash(InventoryHash &pCopy) : hash(pCopy.hash) { type = pCopy.type; }

            bool operator == (const InventoryHash &pRight) { return type == pRight.type && hash == pRight.hash; }
            bool operator != (const InventoryHash &pRight) { return type != pRight.type || hash != pRight.hash; }

            void write(ArcMist::OutputStream *pStream) const;
            bool read(ArcMist::InputStream *pStream);

            Type type;
            Hash hash;

        private:
            InventoryHash &operator = (InventoryHash &pRight);
        };

        class Inventory : public std::vector<InventoryHash *>
        {
        public:

            Inventory() {}
            ~Inventory();

            void write(ArcMist::OutputStream *pStream) const;
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

        private:
            Inventory(Inventory &pCopy);
            Inventory &operator = (Inventory &pRight);
        };

        class Data
        {
        public:

            Data(Type pType) { type = pType; }
            virtual ~Data() {}
            virtual void write(ArcMist::OutputStream *pStream) {}
            virtual bool read(ArcMist::InputStream *pStream, unsigned int pSize)
            {
                if(pStream->remaining() < pSize)
                    return false;
                for(unsigned int i=0;i<pSize;i++)
                    pStream->readByte();
                return true;
            }

            Type type;

        };

        class Interpreter
        {
        public:

            Interpreter() { pendingBlockStartTime = 0; pendingBlockLastReportTime = 0; }

            Data *read(ArcMist::Buffer *pInput, const char *pName);
            void write(Data *pData, ArcMist::Buffer *pOutput);

            Hash pendingBlockHash;
            uint32_t pendingBlockStartTime, pendingBlockLastReportTime;

        };

        class VersionData : public Data
        {
        public:

            VersionData() : Data(VERSION) { }
            VersionData(const uint8_t *pReceivingIP, uint16_t pReceivingPort,
                        const uint8_t *pTransmittingIP, uint16_t pTransmittingPort,
                        bool pFullNode, uint32_t pStartBlockHeight, bool pRelay);

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            int32_t version;
            uint64_t services;
            int64_t time;
            uint64_t receivingServices;
            char receivingIPv6[16];
            uint16_t receivingPort;
            uint64_t transmittingServices; // Same as services
            char transmittingIPv6[16];
            uint16_t transmittingPort;
            uint64_t nonce;
            ArcMist::String userAgent;
            int32_t startBlockHeight;
            uint8_t relay;
        };

        class PingData : public Data
        {
        public:

            PingData() : Data(PING) { nonce = ArcMist::Math::randomLong(); }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            uint64_t nonce;
        };

        class PongData : public Data
        {
        public:

            PongData() : Data(PONG) { nonce = 0; }
            PongData(uint64_t pNonce) : Data(PONG) { nonce = pNonce; }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            uint64_t nonce;
        };

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
            RejectData(const char *pCommand, uint8_t pCode, const char *pReason, ArcMist::Buffer *pExtra) : Data(REJECT)
            {
                command = pCommand;
                code = pCode;
                reason = pReason;

                if(pExtra != NULL)
                    extra.write(pExtra, pExtra->remaining());
            }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            ArcMist::String command;
            uint8_t code;
            ArcMist::String reason;
            ArcMist::Buffer extra;
        };

        class AddressesData : public Data
        {
        public:

            AddressesData() : Data(ADDRESSES) { }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            std::vector<Peer> addresses;
        };

        class FeeFilterData : public Data
        {
        public:

            FeeFilterData(uint64_t pMinimumFeeRate) : Data(FEE_FILTER) { minimumFeeRate = pMinimumFeeRate; }
            FeeFilterData() : Data(FEE_FILTER) { minimumFeeRate = 0; }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            uint64_t minimumFeeRate; // Satoshis per KiB
        };

        class FilterAddData : public Data
        {
        public:

            FilterAddData() : Data(FILTER_ADD) { }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            //TODO Filter Add data
        };

        class FilterLoadData : public Data
        {
        public:

            FilterLoadData() : Data(FILTER_LOAD) { }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            //TODO Filter Load data
        };

        // Request block headers
        class GetBlocksData : public Data
        {
        public:

            GetBlocksData() : Data(GET_BLOCKS), stopHeaderHash(32) { version = PROTOCOL_VERSION; }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            uint32_t version;
            std::vector<Hash> blockHeaderHashes; // In reverse order (Highest block first)

            Hash stopHeaderHash; // Zeroized to stop at highest block on chain

        };

        class BlockData : public Data
        {
        public:

            BlockData() : Data(BLOCK) { block = NULL; }
            ~BlockData() { if(block != NULL) delete block; }

            void write(ArcMist::OutputStream *pStream)
            {
                if(block != NULL)
                    block->write(pStream, true, true);
            }
            bool read(ArcMist::InputStream *pStream, unsigned int pSize)
            {
                if(block == NULL)
                    block = new Block();
                return block->read(pStream, true, true, true);
            }

            Block *block;

        };

        class GetDataData : public Data
        {
        public:

            GetDataData() : Data(GET_DATA) { }

            void write(ArcMist::OutputStream *pStream) { inventory.write(pStream); }
            bool read(ArcMist::InputStream *pStream, unsigned int pSize) { return inventory.read(pStream, pSize); }

            Inventory inventory;

        };

        // Request a Headers message
        class GetHeadersData : public Data
        {
        public:

            GetHeadersData() : Data(GET_HEADERS), stopHeaderHash(32) { version = PROTOCOL_VERSION; }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            uint32_t version;

            // Listing of block hashes that you have in reverse order (Highest block first)
            // Maybe like every 100th block or something
            // First block in this list that they have they will send you headers for
            //   everything after through the stop header
            std::vector<Hash> blockHeaderHashes;

            Hash stopHeaderHash; // Zeroized to stop at highest block on chain

        };

        class HeadersData : public Data
        {
        public:

            HeadersData() : Data(HEADERS) {}

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            BlockList headers;

        };

        class InventoryData : public Data
        {
        public:

            InventoryData() : Data(INVENTORY) { }

            void write(ArcMist::OutputStream *pStream) { inventory.write(pStream); }
            bool read(ArcMist::InputStream *pStream, unsigned int pSize) { return inventory.read(pStream, pSize); }

            Inventory inventory;

        };

        // Used with FILTER_ADD, FILTER_CLEAR, FILTER_LOAD to request specific transactions
        class MerkleBlockData : public Data
        {
        public:

            MerkleBlockData() : Data(MERKLE_BLOCK) { transactionCount = 0; }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            Block block;
            uint32_t transactionCount;
            std::vector<Hash> hashes;
            ArcMist::Buffer flags;

        };

        class TransactionData : public Data
        {
        public:

            TransactionData() : Data(TRANSACTION) { }

            void write(ArcMist::OutputStream *pStream) { transaction.write(pStream); }
            bool read(ArcMist::InputStream *pStream, unsigned int pSize) { return transaction.read(pStream); }

            Transaction transaction;

        };

        class NotFoundData : public Data
        {
        public:

            NotFoundData() : Data(NOT_FOUND) { }

            void write(ArcMist::OutputStream *pStream) { inventory.write(pStream); }
            bool read(ArcMist::InputStream *pStream, unsigned int pSize) { return inventory.read(pStream, pSize); }

            Inventory inventory;

        };

        class SendCompactData : public Data
        {
        public:

            SendCompactData() : Data(SEND_COMPACT) { }

            void write(ArcMist::OutputStream *pStream)
            {
                pStream->writeByte(sendCompact);
                pStream->writeUnsignedLong(encoding);
            }
            bool read(ArcMist::InputStream *pStream, unsigned int pSize)
            {
                if(pSize != 9)
                    return false;
                sendCompact = pStream->readByte();
                encoding = pStream->readUnsignedLong();
                return true;
            }

            bool sendCompact;
            uint64_t encoding;

        };

        class PrefilledTransaction
        {
        public:

            PrefilledTransaction() { offset = 0; transaction = 0; }
            PrefilledTransaction(unsigned int pOffset, Transaction *pTransaction)
            {
                offset = pOffset;
                transaction = pTransaction;
            }

            unsigned int offset;
            Transaction *transaction; // Reference to transaction contained in block

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);
        };

        class CompactBlockData : public Data
        {
        public:

            CompactBlockData();
            ~CompactBlockData();

            // Sets block to be sent in message
            void setBlock(Block *pBlock); // Does not delete block given this way

            // Decodes transaction IDs and puts transactions in the block
            bool fillBlock();

            bool updateShortIDs();

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

            Block *block;
            uint64_t nonce;
            HashList shortIDs;
            std::vector<PrefilledTransaction> prefilledTransactionIDs;

            bool deleteBlock;

        };

        class GetBlockTransactionsData : public Data
        {
        public:

            GetBlockTransactionsData() : Data(GET_BLOCK_TRANSACTIONS) {}

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

        };

        class BlockTransactionsData : public Data
        {
        public:

            BlockTransactionsData() : Data(BLOCK_TRANSACTIONS) {}

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream, unsigned int pSize);

        };

        bool test();
    }
}

#endif
