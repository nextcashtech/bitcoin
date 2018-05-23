/**************************************************************************
 * Copyright 2018 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_ADDRESS_BLOCK_HPP
#define BITCOIN_ADDRESS_BLOCK_HPP

#include "hash.hpp"
#include "stream.hpp"
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
    class Monitor
    {
    public:

        class SPVTransactionData;

        Monitor();
        ~Monitor();

        void write(NextCash::OutputStream *pStream);
        bool read(NextCash::InputStream *pStream);

        unsigned int height(); // The block height of the lowest "pass"
        int64_t balance(bool pLocked = false); // Return total balance of all keys
        int64_t balance(Key *pKey, bool pIncludePending = false); // Return balance associated with a specific key
        unsigned int size() const { return mAddressHashes.size(); }
        unsigned int transactionCount() const { return mTransactions.size(); }
        bool getTransactions(Key *pKey, std::vector<SPVTransactionData *> &pTransactions,
          bool pIncludePending);

        class RelatedTransactionData
        {
        public:

            Transaction *transaction;
            NextCash::Hash blockHash;
            unsigned int nodesVerified;

            NextCash::HashList inputAddresses;
            std::vector<int64_t> relatedInputAmounts;
            NextCash::HashList outputAddresses;
            std::vector<bool> relatedOutputs;

        };

        bool getTransaction(NextCash::Hash pID, std::vector<Key *> *pRelatedToChainKeys,
          RelatedTransactionData &pTransaction);

        void clear();

        void markLoaded() { mLoaded = true; }

        // Load and add any new addresses from a text file.
        bool loadAddresses(NextCash::InputStream *pStream);

        // Sets up monitoring on a key store.
        // Each key in the key store must be "primed". Meaning there must be some address keys
        //   already generated under the "chain" key according to a known hierarchal structure.
        void setKeyStore(KeyStore *pKeyStore);

        // Removes all addresses and adds them back from key store, then updates all transactions
        //   and removes any that are no longer relevant.
        // Call this after removing a key from the keystore.
        void resetKeyStore();

        unsigned int setupBloomFilter(BloomFilter &pFilter);

        // Get hashes for blocks that need merkle blocks
        void getNeededMerkleBlocks(unsigned int pNodeID, Chain &pChain, NextCash::HashList &pBlockHashes,
#ifdef LOW_MEM
          unsigned int pMaxCount = 100);
#else
          unsigned int pMaxCount = 250);
#endif

        int changeID() const { return mChangeID; }

        bool filterNeedsResend(unsigned int pNodeID, unsigned int pBloomID);
        bool needsClose(unsigned int pNodeID);
        void release(unsigned int pNodeID); // Release everything associated with the node

        // Used for zero confirmation approval
        // Returns true if transaction should be requested
        bool addTransactionAnnouncement(const NextCash::Hash &pTransactionHash, unsigned int pNodeID);

        // Add data from a received merkle block
        bool addMerkleBlock(Chain &pChain, Message::MerkleBlockData *pData, unsigned int pNodeID);

        // Add a received transaction if it was confirmed in a merkle block
        bool addTransaction(Chain &pChain, Message::TransactionData *pTransactionData); // Return true if added

        void revertBlock(const NextCash::Hash &pBlockHash, unsigned int pBlockHeight);

        void process(Chain &pChain);

        //TODO Add expiration of pending transactions when not related to prevent receiving them more than once.
        //TODO Add handling of non P2PKH transactions
        //TODO Possibly add caching of spend from linking between related transactions
        //TODO Possibly add caching of which output pays which addresses in related transactions

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
            SPVTransactionData(const NextCash::Hash &pBlockHash)
            {
                blockHash = pBlockHash;
                transaction = NULL;
                amount = 0;
                announceTime = getTime();
            }
            SPVTransactionData(const NextCash::Hash &pBlockHash, Transaction *pTransaction)
            {
                blockHash = pBlockHash;
                transaction = pTransaction;
                amount = 0;
                announceTime = getTime();
            }
            ~SPVTransactionData() { if(transaction != NULL) delete transaction; }

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream);

            bool addNode(unsigned int pNodeID)
            {
                for(std::vector<unsigned int>::iterator node=nodes.begin();node!=nodes.end();++node)
                    if(*node == pNodeID)
                        return false;
                nodes.push_back(pNodeID);
                return true;
            }

            NextCash::Hash blockHash; // Hash of block containing transaction
            Transaction *transaction;
            int64_t amount;
            std::vector<unsigned int> payOutputs, spendInputs;

            int32_t announceTime;
            std::vector<unsigned int> nodes; // IDs of nodes that announced this transaction

        };

    private:

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
            NextCash::HashContainerList<SPVTransactionData *> transactions;
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

            void write(NextCash::OutputStream *pStream);
            bool read(NextCash::InputStream *pStream);

        };

        // Update address list from key store and add any missing.
        // Return number of new addresses added.
        unsigned int refreshKeyStore();

        void refreshBloomFilter(bool pLocked);
        // Returns true if the bloom filter is reset
        bool refreshTransaction(SPVTransactionData *pTransaction, bool pAllowPending);
        bool updateRelatedTransactionData(RelatedTransactionData &pData,
          std::vector<Key *> *pRelatedToChainKeys);
        Output *getOutput(NextCash::Hash &pTransactionHash, unsigned int pIndex, bool pAllowPending);
        bool getPayAddresses(Output *pOutput, NextCash::HashList &pAddresses, bool pBlockOnly);
        static bool outputIsRelated(Output *pOutput, std::vector<Key *> *pRelatedToChainKeys);

        // Start a new "pass" to check new addresses for previous transactions
        void startNewPass();

        // Cancel all pending merkle requests and update the bloom filter.
        void restartBloomFilter();
        void clearMerkleRequest(MerkleRequestData *pData);

        NextCash::Mutex mMutex;
        KeyStore *mKeyStore;
        NextCash::HashList mAddressHashes;
        unsigned int mFilterID;
        int mChangeID;
        BloomFilter mFilter;
        std::vector<unsigned int> mNodesToResendFilter, mNodesToClose;
        std::vector<PassData> mPasses;
        NextCash::HashContainerList<MerkleRequestData *> mMerkleRequests;
        bool mLoaded;

        // Transactions relating to the addresses in this block that have been confirmed in a block
        NextCash::HashContainerList<SPVTransactionData *> mTransactions;
        NextCash::HashContainerList<SPVTransactionData *> mPendingTransactions;

    };
}

#endif
