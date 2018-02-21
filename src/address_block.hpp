/**************************************************************************
 * Copyright 2018 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_ADDRESS_BLOCK_HPP
#define BITCOIN_ADDRESS_BLOCK_HPP

#include "arcmist/base/hash.hpp"
#include "arcmist/io/stream.hpp"
#include "block.hpp"
#include "transaction.hpp"
#include "chain.hpp"
#include "message.hpp"
#include "bloom_filter.hpp"

#include <vector>


namespace BitCoin
{
    /* Data set of addresses to monitor for an SPV wallet
     */
    class AddressBlock
    {
    public:

        AddressBlock();
        ~AddressBlock();

        void write(ArcMist::OutputStream *pStream);
        bool read(ArcMist::InputStream *pStream);

        unsigned int size() const { return mAddressHashes.size(); }
        unsigned int transactionCount() const { return mTransactions.size(); }

        void clear();

        bool loadAddresses(ArcMist::InputStream *pStream);

        void setupBloomFilter(BloomFilter &pFilter);

        // Get hashes for blocks that need merkle blocks
        void getNeededMerkleBlocks(unsigned int pNodeID, Chain &pChain, ArcMist::HashList &pBlockHashes,
          unsigned int pMaxCount = 100);

        bool filterNeedsResend(unsigned int pNodeID);
        bool needsClose(unsigned int pNodeID);

        void release(unsigned int pNodeID); // Release everything associated with the node
        bool addMerkleBlock(Chain &pChain, Message::MerkleBlockData *pData, unsigned int pNodeID);

        // Used for zero confirmation approval
        // Returns true if transaction should be requested
        bool addTransactionAnnouncement(const ArcMist::Hash &pTransactionHash, unsigned int pNodeID);

        // Add a received transaction if it was confirmed in a merkle block
        bool addTransaction(Chain &pChain, Message::TransactionData *pTransactionData); // Return true if added

        void revertBlock(const ArcMist::Hash &pBlockHash);

        void process(Chain &pChain);

        // Returns true if this transaction pays or spends an address in this block
        // RelationType relatesTo(Transaction *pTransaction, bool pAlreadyLocked = false);

        // Returns true if this transaction pays to an address in this block
        // bool paysTo(Transaction *pTransaction);

        // Returns true if this transaction spends a UTXO for an address in this block
        // bool spendsFrom(Transaction *pTransaction, bool pAlreadyLocked = false);

        //TODO Add expiration of pending transactions when not related to prevent receiving them more than once.
        //TODO Add handling of non P2PKH transactions
        //TODO Possibly add caching of spend from linking between related transactions
        //TODO Possibly add caching of which output pays which addresses in related transactions

        //TODO Current weakness. With auto remote bloom updates off and random switching between
        //   nodes for requesting merkle blocks it is possible to miss spend transactions since the
        //   bloom filter may not have been updated. At least a second pass is required to prevent
        //   this.
        // Fix is to add function that when a new "pays to" transaction is found. Reset all node's
        //   bloom filters to include the new UTXO. Reset pass' block height to height of new
        //   "pays to" transaction. Ensure all merkle blocks after that point are re-requested with
        //   the new bloom filters.

    private:

        ArcMist::Mutex mMutex;
        ArcMist::HashList mAddressHashes;
        BloomFilter mFilter;
        std::vector<unsigned int> mNodesToResendFilter, mNodesToClose;

        void refreshBloomFilter();

        // Data about a merkle block pass.
        // A "merkle block pass" is at least one merkle block for every block with a filter that
        //   includes all current addresses.
        class PassData
        {
        public:

            PassData() { blockHeight = 0; addressesIncluded = 0; }
            PassData(const PassData &pCopy) { blockHeight = pCopy.blockHeight; addressesIncluded = pCopy.addressesIncluded; }

            unsigned int blockHeight; // Highest block with a valid merkle block
            unsigned int addressesIncluded; // Number of addresses from block included. Always starts from first.

            void clear() { blockHeight = 0; addressesIncluded = 0; }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream);

        };

        std::vector<PassData *> mPasses;

        PassData mCurrentPass;

        class SPVTransactionData
        {
        public:

            SPVTransactionData()
            {
                transaction = NULL;
                amount = 0;
            }
            SPVTransactionData(const ArcMist::Hash &pBlockHash, Transaction *pTransaction)
            {
                blockHash = pBlockHash;
                transaction = pTransaction;
                amount = 0;
            }
            ~SPVTransactionData() { if(transaction != NULL) delete transaction; }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream);

            ArcMist::Hash blockHash; // Hash of block containing transaction
            Transaction *transaction;
            int64_t amount;
            std::vector<unsigned int> payOutputs, spendInputs;

        };

        void refreshTransaction(SPVTransactionData *pTransaction, bool pAllowPending);
        Output *getOutput(ArcMist::Hash &pTransactionHash, unsigned int pIndex, bool pAllowPending);
        bool getPayAddresses(Output *pOutput, ArcMist::HashList &pAddresses, bool pBlockOnly);

        // Transactions relating to the addresses in this block that have been confirmed in a block
        ArcMist::HashContainerList<SPVTransactionData *> mTransactions;

        // Pending transactions
        //   Transactions not in a confirmed block yet
        class PendingTransactionData : public SPVTransactionData
        {
        public:

            PendingTransactionData()
            {
                announceTime = getTime();
            }

            int32_t announceTime;
            std::vector<unsigned int> nodes; // IDs of nodes that announced this transaction

            bool addNode(unsigned int pNodeID)
            {
                for(std::vector<unsigned int>::iterator node=nodes.begin();node!=nodes.end();++node)
                    if(*node == pNodeID)
                        return false;
                nodes.push_back(pNodeID);
                return true;
            }

        };

        ArcMist::HashContainerList<PendingTransactionData *> mPendingTransactions;

        class MerkleRequestData
        {
        public:

            MerkleRequestData()
            {
                node = 0;
                requestTime = 0;
                receiveTime = 0;
                totalTransactions = 0;
                complete = false;
            }
            MerkleRequestData(unsigned int pNodeID, int32_t pRequestTime)
            {
                node = pNodeID;
                requestTime = pRequestTime;
                receiveTime = 0;
                totalTransactions = 0;
                complete = false;
            }
            ~MerkleRequestData();

            unsigned int node;
            int32_t requestTime, receiveTime;
            unsigned int totalTransactions; // Total transaction count of full block
            ArcMist::HashList transactionHashes; // Hashes of transactions in this block
            std::vector<SPVTransactionData *> transactions;
            bool complete;

            bool isComplete();
            void release();

        };

        ArcMist::HashContainerList<MerkleRequestData *> mMerkleRequests;

    };
}

#endif
