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

        int64_t balance(bool pLocked);
        unsigned int size() const { return mAddressHashes.size(); }
        unsigned int transactionCount() const { return mTransactions.size(); }

        void clear();

        // Load and add any new addresses from a text file
        bool loadAddresses(ArcMist::InputStream *pStream);

        unsigned int setupBloomFilter(BloomFilter &pFilter);

        // Get hashes for blocks that need merkle blocks
        void getNeededMerkleBlocks(unsigned int pNodeID, Chain &pChain, ArcMist::HashList &pBlockHashes,
          unsigned int pMaxCount = 250);

        bool filterNeedsResend(unsigned int pNodeID, unsigned int pBloomID);
        bool needsClose(unsigned int pNodeID);
        void release(unsigned int pNodeID); // Release everything associated with the node

        // Used for zero confirmation approval
        // Returns true if transaction should be requested
        bool addTransactionAnnouncement(const ArcMist::Hash &pTransactionHash, unsigned int pNodeID);

        // Add data from a received merkle block
        bool addMerkleBlock(Chain &pChain, Message::MerkleBlockData *pData, unsigned int pNodeID);

        // Add a received transaction if it was confirmed in a merkle block
        bool addTransaction(Chain &pChain, Message::TransactionData *pTransactionData); // Return true if added

        void revertBlock(const ArcMist::Hash &pBlockHash, unsigned int pBlockHeight);

        void process(Chain &pChain);

        //TODO Add expiration of pending transactions when not related to prevent receiving them more than once.
        //TODO Add handling of non P2PKH transactions
        //TODO Possibly add caching of spend from linking between related transactions
        //TODO Possibly add caching of which output pays which addresses in related transactions

    private:

        class SPVTransactionData
        {
        public:

            SPVTransactionData()
            {
                transaction = NULL;
                amount = 0;
                announceTime = getTime();
            }
            SPVTransactionData(const SPVTransactionData &pCopy) :
              payOutputs(pCopy.payOutputs), spendInputs(pCopy.spendInputs), nodes(pCopy.nodes)
            {
                blockHash = pCopy.blockHash;
                if(pCopy.transaction == NULL)
                    transaction = NULL;
                else
                {
                    transaction = new Transaction(*pCopy.transaction);
                }
                amount = pCopy.amount;
                announceTime = pCopy.announceTime;
            }
            SPVTransactionData(const ArcMist::Hash &pBlockHash)
            {
                blockHash = pBlockHash;
                transaction = NULL;
                amount = 0;
                announceTime = getTime();
            }
            SPVTransactionData(const ArcMist::Hash &pBlockHash, Transaction *pTransaction)
            {
                blockHash = pBlockHash;
                transaction = pTransaction;
                amount = 0;
                announceTime = getTime();
            }
            ~SPVTransactionData() { if(transaction != NULL) delete transaction; }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream);

            bool addNode(unsigned int pNodeID)
            {
                for(std::vector<unsigned int>::iterator node=nodes.begin();node!=nodes.end();++node)
                    if(*node == pNodeID)
                        return false;
                nodes.push_back(pNodeID);
                return true;
            }

            ArcMist::Hash blockHash; // Hash of block containing transaction
            Transaction *transaction;
            int64_t amount;
            std::vector<unsigned int> payOutputs, spendInputs;

            int32_t announceTime;
            std::vector<unsigned int> nodes; // IDs of nodes that announced this transaction

        };

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
            ArcMist::HashContainerList<SPVTransactionData *> transactions;
            bool complete;

            bool isComplete();
            void release();
            void clear();

        };

        // Data about a merkle block pass.
        // A "merkle block pass" is at least one merkle block for every block with a filter that
        //   includes all current addresses and UTXOs.
        class PassData
        {
        public:

            PassData();
            PassData(const PassData &pCopy);

            const PassData &operator =(const PassData &pRight);

            unsigned int beginBlockHeight; // Block height of beginning of pass
            unsigned int blockHeight; // Highest block with a valid merkle block
            unsigned int addressesIncluded; // Number of addresses from block included. Always starts from first.
            bool complete; // No longer processing this pass

            void clear() { beginBlockHeight = 0; blockHeight = 0; addressesIncluded = 0; complete = false; }

            void write(ArcMist::OutputStream *pStream);
            bool read(ArcMist::InputStream *pStream);

        };

        void refreshBloomFilter(bool pLocked);
        void refreshTransaction(SPVTransactionData *pTransaction, bool pAllowPending);
        Output *getOutput(ArcMist::Hash &pTransactionHash, unsigned int pIndex, bool pAllowPending);
        bool getPayAddresses(Output *pOutput, ArcMist::HashList &pAddresses, bool pBlockOnly);

        ArcMist::Mutex mMutex;
        ArcMist::HashList mAddressHashes;
        unsigned int mFilterID;
        BloomFilter mFilter;
        std::vector<unsigned int> mNodesToResendFilter, mNodesToClose;
        std::vector<PassData> mPasses;
        ArcMist::HashContainerList<MerkleRequestData *> mMerkleRequests;

        // Transactions relating to the addresses in this block that have been confirmed in a block
        ArcMist::HashContainerList<SPVTransactionData *> mTransactions;
        ArcMist::HashContainerList<SPVTransactionData *> mPendingTransactions;

    };
}

#endif
