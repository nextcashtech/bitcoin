/**************************************************************************
 * Copyright 2018 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "address_block.hpp"

#include "arcmist/base/log.hpp"
#include "base.hpp"
#include "key.hpp"
#include "interpreter.hpp"

#define BITCOIN_ADDRESS_BLOCK_LOG_NAME "AddressBlock"
#define ADDRESS_HASH_SIZE 20


namespace BitCoin
{
    AddressBlock::AddressBlock() : mMutex("AddressBlock")
    {
    }

    AddressBlock::~AddressBlock()
    {
        mMutex.lock();
        for(ArcMist::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            delete *trans;
        for(ArcMist::HashContainerList<PendingTransactionData *>::Iterator transData=mPendingTransactions.begin();transData!=mPendingTransactions.end();++transData)
            delete *transData;
        for(ArcMist::HashContainerList<MerkleRequestData *>::Iterator request=mMerkleRequests.begin();request!=mMerkleRequests.end();++request)
            delete *request;
        for(std::vector<PassData *>::iterator pass=mPasses.begin();pass!=mPasses.end();++pass)
            delete *pass;
        mMutex.unlock();
    }

    AddressBlock::MerkleRequestData::~MerkleRequestData()
    {
        for(std::vector<SPVTransactionData *>::iterator trans=transactions.begin();trans!=transactions.end();++trans)
            delete *trans;
    }

    bool AddressBlock::MerkleRequestData::isComplete()
    {
        if(receiveTime == 0)
            return false;

        if(complete || transactionHashes.size() == 0)
            return true;

        if(transactionHashes.size() > transactions.size())
            return false;

        bool found;
        for(ArcMist::HashList::iterator hash=transactionHashes.begin();hash!=transactionHashes.end();++hash)
        {
            found = false;
            for(std::vector<SPVTransactionData *>::iterator trans=transactions.begin();trans!=transactions.end();++trans)
                if((*trans)->transaction != NULL && (*trans)->transaction->hash == *hash)
                {
                    found = true;
                    break;
                }

            if(!found)
                return false;
        }

        complete = true;
        return true;
    }

    void AddressBlock::MerkleRequestData::release()
    {
        node = 0;
        if(!isComplete())
            requestTime = 0;
    }

    void AddressBlock::write(ArcMist::OutputStream *pStream)
    {
        mMutex.lock();

        // Version
        pStream->writeUnsignedInt(1);

        // Current Pass
        mCurrentPass.write(pStream);

        // Passes
        pStream->writeUnsignedInt(mPasses.size());
        for(std::vector<PassData *>::iterator pass=mPasses.begin();pass!=mPasses.end();++pass)
            (*pass)->write(pStream);

        // Addresses
        pStream->writeUnsignedInt(mAddressHashes.size());
        for(ArcMist::HashList::iterator hash=mAddressHashes.begin();hash!=mAddressHashes.end();++hash)
            hash->write(pStream);

        // Transactions
        pStream->writeUnsignedInt(mTransactions.size());
        for(ArcMist::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            (*trans)->write(pStream);

        mMutex.unlock();
    }

    bool AddressBlock::read(ArcMist::InputStream *pStream)
    {
        clear();

        mMutex.lock();

        if(pStream->readUnsignedInt() != 1)
        {
            mMutex.unlock();
            return false; // Wrong version
        }

        // Current pass
        if(!mCurrentPass.read(pStream))
        {
            mMutex.unlock();
            clear();
            return false;
        }

        // Passes
        unsigned int passesCount = pStream->readUnsignedInt();
        PassData *newPassData;
        for(unsigned int i=0;i<passesCount;++i)
        {
            newPassData = new PassData();
            if(!newPassData->read(pStream))
            {
                delete newPassData;
                mMutex.unlock();
                clear();
                return false;
            }
            mPasses.push_back(newPassData);
        }

        // Addresses
        unsigned int addressCount = pStream->readUnsignedInt();
        mAddressHashes.reserve(addressCount);
        ArcMist::Hash addressHash(ADDRESS_HASH_SIZE);
        for(unsigned int i=0;i<addressCount;++i)
        {
            if(!addressHash.read(pStream, ADDRESS_HASH_SIZE))
            {
                mMutex.unlock();
                clear();
                return false;
            }
            mAddressHashes.push_back(addressHash);
        }

        // Transactions
        unsigned int transactionCount = pStream->readUnsignedInt();
        SPVTransactionData *newSPVTransaction;
        for(unsigned int i=0;i<transactionCount;++i)
        {
            newSPVTransaction = new SPVTransactionData();
            if(!newSPVTransaction->read(pStream))
            {
                delete newSPVTransaction;
                mMutex.unlock();
                clear();
                return false;
            }
            mTransactions.insert(newSPVTransaction->transaction->hash, newSPVTransaction);
        }

        // Update transactions
        for(ArcMist::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            refreshTransaction(*trans, true);

        mMutex.unlock();

        refreshBloomFilter();
        return true;
    }

    void AddressBlock::SPVTransactionData::write(ArcMist::OutputStream *pStream)
    {
        // Block hash
        blockHash.write(pStream);

        // Transaction
        transaction->write(pStream);

        // Amount
        pStream->writeLong(amount);

        // Payments
        pStream->writeUnsignedInt(payOutputs.size());
        for(std::vector<unsigned int>::iterator payment=payOutputs.begin();payment!=payOutputs.end();++payment)
            pStream->writeUnsignedInt(*payment);

        // Spends
        pStream->writeUnsignedInt(spendInputs.size());
        for(std::vector<unsigned int>::iterator spend=spendInputs.begin();spend!=spendInputs.end();++spend)
            pStream->writeUnsignedInt(*spend);
    }

    bool AddressBlock::SPVTransactionData::read(ArcMist::InputStream *pStream)
    {
        // Block hash
        if(!blockHash.read(pStream, 32))
            return false;

        // Transaction
        if(transaction != NULL)
            delete transaction;

        transaction = new Transaction();
        if(!transaction->read(pStream))
            return false;

        if(pStream->remaining() < 16)
            return false;

        // Amount
        amount = pStream->readLong();

        // Payments
        payOutputs.clear();
        unsigned int paymentCount = pStream->readUnsignedInt();

        if(pStream->remaining() < (paymentCount * 4) + 4)
            return false;

        payOutputs.resize(paymentCount);
        for(unsigned int i=0;i<paymentCount;++i)
            payOutputs[i] = pStream->readUnsignedInt();

        // Spends
        spendInputs.clear();
        unsigned int spendCount = pStream->readUnsignedInt();

        if(pStream->remaining() < spendCount * 4)
            return false;

        spendInputs.resize(spendCount);
        for(unsigned int i=0;i<spendCount;++i)
            spendInputs[i] = pStream->readUnsignedInt();

        return true;
    }

    void AddressBlock::PassData::write(ArcMist::OutputStream *pStream)
    {
        pStream->writeUnsignedInt(blockHeight);
        pStream->writeUnsignedInt(addressesIncluded);
    }

    bool AddressBlock::PassData::read(ArcMist::InputStream *pStream)
    {
        if(pStream->remaining() < 8)
            return false;

        blockHeight = pStream->readUnsignedInt();
        addressesIncluded = pStream->readUnsignedInt();
        return true;
    }

    Output *AddressBlock::getOutput(ArcMist::Hash &pTransactionHash, unsigned int pIndex, bool pAllowPending)
    {
        ArcMist::HashContainerList<SPVTransactionData *>::Iterator confirmedTransaction = mTransactions.get(pTransactionHash);
        if(confirmedTransaction != mTransactions.end() && (*confirmedTransaction)->transaction != NULL &&
          (*confirmedTransaction)->transaction->outputs.size() > pIndex)
                return (*confirmedTransaction)->transaction->outputs[pIndex];

        if(!pAllowPending)
            return NULL;

        ArcMist::HashContainerList<PendingTransactionData *>::Iterator pendingTransaction = mPendingTransactions.get(pTransactionHash);
        if(pendingTransaction != mPendingTransactions.end() && (*pendingTransaction)->transaction != NULL &&
          (*pendingTransaction)->transaction->outputs.size() > pIndex)
                return (*pendingTransaction)->transaction->outputs[pIndex];

        return NULL;
    }

    bool AddressBlock::getPayAddresses(Output *pOutput, ArcMist::HashList &pAddresses, bool pBlockOnly)
    {
        pAddresses.clear();

        if(pOutput == NULL)
            return false;

        // Parse the output for addresses
        ScriptInterpreter::ScriptType scriptType = ScriptInterpreter::parseOutputScript(pOutput->script, pAddresses);
        if(scriptType != ScriptInterpreter::P2PKH)
        {
            pAddresses.clear();
            return false;
        }


        if(pBlockOnly) // Check the output addresses against block addresses
            for(ArcMist::HashList::iterator hash=pAddresses.begin();hash!=pAddresses.end();)
            {
                if(mAddressHashes.contains(*hash))
                    ++hash;
                else
                    hash = pAddresses.erase(hash); // Erase addresses not in block
            }

        return pAddresses.size() > 0;
    }

    void AddressBlock::refreshTransaction(AddressBlock::SPVTransactionData *pTransaction, bool pAllowPending)
    {
        pTransaction->amount = 0;
        pTransaction->payOutputs.clear();
        pTransaction->spendInputs.clear();

        if(pTransaction->transaction == NULL)
            return;

        // Check for spends
        Output *spentOutput;
        ArcMist::HashList payAddresses;
        unsigned int index = 0;
        for(std::vector<Input *>::iterator input=pTransaction->transaction->inputs.begin();input!=pTransaction->transaction->inputs.end();++input)
        {
            // Find output being spent
            spentOutput = getOutput((*input)->outpoint.transactionID, (*input)->outpoint.index, pAllowPending);
            if(spentOutput != NULL && getPayAddresses(spentOutput, payAddresses, true)) // Check that output actually pays block address
            {
                pTransaction->spendInputs.push_back(index);
                pTransaction->amount -= spentOutput->amount;
            }

            ++index;
        }

        // Check for payments
        index = 0;
        for(std::vector<Output *>::iterator output=pTransaction->transaction->outputs.begin();output!=pTransaction->transaction->outputs.end();++output)
        {
            if(getPayAddresses(*output, payAddresses, true))
            {
                pTransaction->payOutputs.push_back(index);
                pTransaction->amount += (*output)->amount;
            }

            ++index;
        }
    }

    void AddressBlock::clear()
    {
        mMutex.lock();

        mCurrentPass.clear();

        for(std::vector<PassData *>::iterator pass=mPasses.begin();pass!=mPasses.end();++pass)
            delete *pass;
        mPasses.clear();

        mAddressHashes.clear();
        mFilter.clear();
        mNodesToResendFilter.clear();
        mNodesToClose.clear();

        for(ArcMist::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            delete *trans;
        mTransactions.clear();

        for(ArcMist::HashContainerList<MerkleRequestData *>::Iterator request=mMerkleRequests.begin();request!=mMerkleRequests.end();++request)
            delete *request;
        mMerkleRequests.clear();

        for(ArcMist::HashContainerList<PendingTransactionData *>::Iterator transData=mPendingTransactions.begin();transData!=mPendingTransactions.end();++transData)
            delete *transData;
        mPendingTransactions.clear();

        mMutex.unlock();
    }

    bool AddressBlock::loadAddresses(ArcMist::InputStream *pStream)
    {
        mMutex.lock();

        unsigned int addedCount = 0;
        ArcMist::String line;
        unsigned char nextChar;
        ArcMist::Hash addressHash;
        AddressType addressType;
        bool found;
        while(pStream->remaining())
        {
            line.clear();

            while(pStream->remaining())
            {
                nextChar = pStream->readByte();
                if(nextChar == '\r' || nextChar == '\n' || nextChar == ' ')
                    break;
                line += nextChar;
            }

            if(line.length() && decodeAddress(line, addressHash, addressType) && addressType == PUB_KEY_HASH &&
              addressHash.size() == ADDRESS_HASH_SIZE)
            {
                // Check if it is already in this block
                found = false;
                for(ArcMist::HashList::iterator hash=mAddressHashes.begin();hash!=mAddressHashes.end();++hash)
                    if(*hash == addressHash)
                    {
                        found = true;
                        break;
                    }

                if(!found)
                {
                    mAddressHashes.push_back(addressHash);
                    ++addedCount;
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                      "Adding address hash : %s", line.text());
                }
            }
        }

        if(addedCount)
        {
            if(mCurrentPass.blockHeight > 0)
            {
                // Push current pass, reset to zero block height, start new pass
                mPasses.push_back(new PassData(mCurrentPass));
                mCurrentPass.clear();
            }

            mCurrentPass.addressesIncluded = mAddressHashes.size();

            for(ArcMist::HashContainerList<MerkleRequestData *>::Iterator request=mMerkleRequests.begin();request!=mMerkleRequests.end();++request)
                delete *request;
            mMerkleRequests.clear();
        }

        mMutex.unlock();

        if(addedCount)
            refreshBloomFilter();

        return true;
    }

    void AddressBlock::refreshBloomFilter()
    {
        std::vector<Outpoint *> outpoints;
        ArcMist::HashContainerList<SPVTransactionData *>::Iterator confirmedTransaction, inputConfirmedTransaction;
        ArcMist::HashContainerList<PendingTransactionData *>::Iterator pendingTransaction, inputPendingTransaction;
        ScriptInterpreter::ScriptType scriptType;
        ArcMist::HashList payAddressHashes;
        unsigned int index;

        mMutex.lock();

        // Add outpoints to monitor for spending
        for(ArcMist::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            if((*trans)->transaction != NULL && (*trans)->payOutputs.size() > 0)
            {
                // Determine which outputs pay to a block address
                index = 0;
                for(std::vector<Output *>::iterator output=(*trans)->transaction->outputs.begin();output!=(*trans)->transaction->outputs.end();++output,++index)
                {
                    // Parse the output for addresses
                    scriptType = ScriptInterpreter::parseOutputScript((*output)->script, payAddressHashes);
                    if(scriptType == ScriptInterpreter::P2PKH)
                    {
                        // Check the output addresses against block addresses
                        for(ArcMist::HashList::iterator hash=payAddressHashes.begin();hash!=payAddressHashes.end();++hash)
                            if(mAddressHashes.contains(*hash))
                            {
                                outpoints.push_back(new Outpoint((*trans)->transaction->hash, index));
                                break;
                            }
                    }
                }
            }

        mFilter.setup(mAddressHashes.size() + outpoints.size(), BloomFilter::UPDATE_NONE, 0.00001);

        // Add Address hashes to monitor for "pay to" transactions
        for(ArcMist::HashList::iterator hash=mAddressHashes.begin();hash!=mAddressHashes.end();++hash)
            mFilter.add(*hash);

        // Add outpoints of UTXOs to monitor for "spend from" transactions
        for(std::vector<Outpoint *>::iterator outpoint=outpoints.begin();outpoint!=outpoints.end();++outpoint)
        {
            mFilter.add(**outpoint);
            delete *outpoint;
        }

        mMutex.unlock();
    }

    bool AddressBlock::filterNeedsResend(unsigned int pNodeID)
    {
        mMutex.lock();
        for(std::vector<unsigned int>::iterator node=mNodesToResendFilter.begin();node!=mNodesToResendFilter.end();++node)
            if(*node == pNodeID)
            {
                mNodesToResendFilter.erase(node);
                mMutex.unlock();
                return true;
            }
        mMutex.unlock();
        return false;
    }

    bool AddressBlock::needsClose(unsigned int pNodeID)
    {
        mMutex.lock();
        for(std::vector<unsigned int>::iterator node=mNodesToClose.begin();node!=mNodesToClose.end();++node)
            if(*node == pNodeID)
            {
                mNodesToClose.erase(node);
                mMutex.unlock();
                return true;
            }
        mMutex.unlock();
        return false;
    }

    void AddressBlock::release(unsigned int pNodeID)
    {
        mMutex.lock();

        for(ArcMist::HashContainerList<MerkleRequestData *>::Iterator request=mMerkleRequests.begin();request!=mMerkleRequests.end();++request)
            if((*request)->node == pNodeID)
                (*request)->release();

        for(std::vector<unsigned int>::iterator node=mNodesToResendFilter.begin();node!=mNodesToResendFilter.end();++node)
            if(*node == pNodeID)
            {
                mNodesToResendFilter.erase(node);
                break;
            }

        for(std::vector<unsigned int>::iterator node=mNodesToClose.begin();node!=mNodesToClose.end();++node)
            if(*node == pNodeID)
            {
                mNodesToClose.erase(node);
                break;
            }

        mMutex.unlock();
    }

    void AddressBlock::setupBloomFilter(BloomFilter &pFilter)
    {
        pFilter = mFilter;
    }

    void AddressBlock::getNeededMerkleBlocks(unsigned int pNodeID, Chain &pChain, ArcMist::HashList &pBlockHashes, unsigned int pMaxCount)
    {
        ArcMist::Hash nextBlockHash;
        ArcMist::HashContainerList<MerkleRequestData *>::Iterator request;
        MerkleRequestData *newMerkleRequest;
        unsigned int blockHeight = mCurrentPass.blockHeight;
        int32_t time = getTime();

        pBlockHashes.clear();

        while(pBlockHashes.size() < pMaxCount)
        {
            // Get next block hash
            if(!pChain.getBlockHash(++blockHeight, nextBlockHash))
                return;

            // Check if there is a merkle request for this block hash and if it needs more requests sent
            mMutex.lock();
            request = mMerkleRequests.get(nextBlockHash);
            if(request == mMerkleRequests.end())
            {
                if(mMerkleRequests.size() < 2000)
                {
                    // Add new merkle block request
                    newMerkleRequest = new MerkleRequestData(pNodeID, time);
                    mMerkleRequests.insert(nextBlockHash, newMerkleRequest);
                    pBlockHashes.push_back(nextBlockHash);
                }
                else
                {
                    mMutex.unlock();
                    break;
                }
            }
            else if(!(*request)->isComplete() &&
              ((*request)->requestTime == 0 || ((*request)->requestTime != 0 && time - (*request)->requestTime > 60)))
            {
                if((*request)->node != 0 && (*request)->requestTime != 0)
                {
                    bool found = false;
                    for(std::vector<unsigned int>::iterator node=mNodesToClose.begin();node!=mNodesToClose.end();++node)
                        if(*node == (*request)->node)
                        {
                            found = true;
                            break;
                        }

                    if(!found)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                          "Node [%d] needs closed. Merkle blocks too slow", (*request)->node);
                        mNodesToClose.push_back((*request)->node);
                    }
                }
                (*request)->node = pNodeID;
                (*request)->requestTime = time;
                pBlockHashes.push_back(nextBlockHash);
            }
            mMutex.unlock();
        }
    }

    bool AddressBlock::addMerkleBlock(Chain &pChain, Message::MerkleBlockData *pData, unsigned int pNodeID)
    {
        mMutex.lock();

        ArcMist::HashContainerList<MerkleRequestData *>::Iterator request = mMerkleRequests.get(pData->block->hash);
        if(request == mMerkleRequests.end())
        {
            mMutex.unlock();
            return false; // Not a requested block, so it probably isn't in the chain
        }

        // Check if it is already complete
        if((*request)->isComplete())
        {
            mMutex.unlock();
            return false;
        }

        // Validate
        ArcMist::HashList transactionHashes;
        if(!pData->validate(transactionHashes))
        {
            (*request)->release();
            mMutex.unlock();
            return false;
        }

        (*request)->node = pNodeID;
        (*request)->totalTransactions = pData->block->transactionCount;

        // Clear transactions because if more than one merkle block are received from different
        //   nodes, then they might have different bloom filters and different false positive
        //   transactions.
        (*request)->transactionHashes.clear();
        for(std::vector<SPVTransactionData *>::iterator trans=(*request)->transactions.begin();trans!=(*request)->transactions.end();++trans)
            delete *trans;
        (*request)->transactions.clear();

        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
          // "Received merkle block from node [%d] with %d transaction hashes : %s", pNodeID,
          // (*request)->transactionHashes.size(), pData->block->hash.hex().text());

        // Add transaction hashes
        for(ArcMist::HashList::iterator hash=transactionHashes.begin();hash!=transactionHashes.end();++hash)
        {
            // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
              // "Confirmed transaction hash : %s", hash->hex().text());
            (*request)->transactionHashes.push_back(*hash);
        }

        // Mark receive time
        if((*request)->receiveTime != 0)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
              "Repeated Merkle block from node [%d] with %d/%d transaction (%d sec ago) : %s", pNodeID,
              (*request)->transactions.size(), (*request)->transactionHashes.size(),
              getTime() - (*request)->receiveTime, pData->block->hash.hex().text());
        else
            (*request)->receiveTime = getTime();

        bool processNeeded = (*request)->isComplete();

        mMutex.unlock();

        // Note : Process function waits for transactions for the specified hashes, then removes
        //   the requests in chain order.
        if(processNeeded)
            process(pChain);

        return true;
    }

    bool AddressBlock::addTransaction(Chain &pChain, Message::TransactionData *pTransactionData)
    {
        bool result = false;

        mMutex.lock();

        if(mTransactions.get(pTransactionData->transaction->hash) != mTransactions.end())
        {
            mMutex.unlock();
            return result; // Already have this transaction
        }

        if(Info::instance().spvMode)
        {
            // Check that it has been proven by a merkle block
            MerkleRequestData *merkleRequest;
            bool transFound = false, processNeeded = false;
            SPVTransactionData *newTransaction;
            Transaction *transaction = pTransactionData->transaction;
            for(ArcMist::HashContainerList<MerkleRequestData *>::Iterator request=mMerkleRequests.begin();request!=mMerkleRequests.end();++request)
            {
                merkleRequest = *request;
                if(merkleRequest->transactionHashes.contains(pTransactionData->transaction->hash))
                {
                    result = true;

                    for(std::vector<SPVTransactionData *>::iterator trans=merkleRequest->transactions.begin();trans!=merkleRequest->transactions.end();++trans)
                        if((*trans)->transaction != NULL && (*trans)->transaction->hash == pTransactionData->transaction->hash)
                        {
                            transFound = true;
                            break;
                        }

                    if(!transFound)
                    {
                        newTransaction = new SPVTransactionData(request.hash(), pTransactionData->transaction);
                        pTransactionData->transaction = NULL; // Prevent it from being deleted
                        refreshTransaction(newTransaction, true);
                        merkleRequest->transactions.push_back(newTransaction);
                        processNeeded = merkleRequest->isComplete();
                        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                          // "Added confirmed transaction to merkle block request : %s", transaction->hash.hex().text());

                        // Update filter
                        if(newTransaction->payOutputs.size() > 0)
                        {
                            Outpoint outpoint;
                            outpoint.transactionID = newTransaction->transaction->hash;
                            for(std::vector<unsigned int>::iterator index=newTransaction->payOutputs.begin();index!=newTransaction->payOutputs.end();++index)
                            {
                                // Add new UTXO to filter
                                outpoint.index = *index;
                                mFilter.add(outpoint);
                            }
                        }
                    }

                    mMutex.unlock();
                    if(processNeeded)
                        process(pChain);
                    return result;
                }
            }

            // Check pending transactions
            ArcMist::HashContainerList<PendingTransactionData *>::Iterator pendingTransaction = mPendingTransactions.get(pTransactionData->transaction->hash);
            if(pendingTransaction != mPendingTransactions.end())
            {
                result = true;

                if((*pendingTransaction)->transaction == NULL)
                {
                    (*pendingTransaction)->transaction = pTransactionData->transaction;
                    pTransactionData->transaction = NULL; // Prevent it from being deleted
                    refreshTransaction(*pendingTransaction, true);
                    if((*pendingTransaction)->payOutputs.size() > 0 || (*pendingTransaction)->spendInputs.size() > 0)
                    {
                        // Needed this transaction
                        if((*pendingTransaction)->amount > 0)
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                              "Pending transaction paying %0.8f bitcoins : %s", bitcoins((*pendingTransaction)->amount),
                              (*pendingTransaction)->transaction->hash.hex().text());
                        else
                            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                              "Pending transaction spending %0.8f bitcoins : %s", -bitcoins((*pendingTransaction)->amount),
                              (*pendingTransaction)->transaction->hash.hex().text());
                    }
                    else
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                          "Removed unrelated pending transaction : %s", transaction->hash.hex().text());
                        delete *pendingTransaction;
                        mPendingTransactions.erase(pendingTransaction);
                    }
                }
            }

            if(!result)
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                  "Transaction not found in merkle block or pending : %s", transaction->hash.hex().text());

            mMutex.unlock();
            return result;
        }
        else
        {
            // Check if it relates to any block addresses
            //TODO Put into Pending Transactions
            //TODO Add a function when a block is validated to move the function from pending to confirmed
            // if(relatesTo(pTransaction, true) != NONE)
            // {
                // // Needed this transaction
                // result = true;
                // (*pendingTransaction)->transaction = pTransaction;
                // ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                  // "Received pending transaction : %s", pTransaction->hash.hex().text());
            // }
            // else
            // {
                // delete *pendingTransaction;
                // mPendingTransactions.erase(pendingTransaction);
                // ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                  // "Removed unrelated pending transaction : %s", pTransaction->hash.hex().text());
            // }

            mMutex.unlock();
            return result;
        }
    }

    bool AddressBlock::addTransactionAnnouncement(const ArcMist::Hash &pTransactionHash, unsigned int pNodeID)
    {
        bool result = false;
        mMutex.lock();

        if(Info::instance().spvMode)
        {
            ArcMist::HashContainerList<PendingTransactionData *>::Iterator pendingTransaction = mPendingTransactions.get(pTransactionHash);
            if(pendingTransaction == mPendingTransactions.end())
            {
                // Add new pending transaction
                PendingTransactionData *newPendingTransaction = new PendingTransactionData();
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                  "Pending transaction accepted on first node [%d] : %s", pNodeID, pTransactionHash.hex().text());
                newPendingTransaction->nodes.push_back(pNodeID);
                refreshTransaction(newPendingTransaction, true);
                mPendingTransactions.insert(pTransactionHash, newPendingTransaction);
                result = true; // Need transaction
            }
            else
            {
                result = (*pendingTransaction)->transaction == NULL; // Set true if still need transaction

                // Add node as accepting node
                bool found = false;
                for(std::vector<unsigned int>::iterator node=(*pendingTransaction)->nodes.begin();node!=(*pendingTransaction)->nodes.end();++node)
                    if(*node == pNodeID)
                    {
                        found = true;
                        break;
                    }

                if(!found)
                {
                    (*pendingTransaction)->nodes.push_back(pNodeID);
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                      "Pending transaction accepted on %d nodes. [%d] : %s", (*pendingTransaction)->nodes.size(),
                      pNodeID, pTransactionHash.hex().text());
                }

            }
        }
        else
        {
            //TODO Check if relates to address and add accept node for zero conf.
        }

        mMutex.unlock();
        return result;
    }

    void AddressBlock::revertBlock(const ArcMist::Hash &pBlockHash)
    {
        mMutex.lock();

        // If there is an active request then remove it and that is all
        ArcMist::HashContainerList<MerkleRequestData *>::Iterator request = mMerkleRequests.get(pBlockHash);
        if(request != mMerkleRequests.end())
        {
            delete *request;
            mMerkleRequests.erase(request);
            mMutex.unlock();
            return;
        }

        // Remove any transactions associated with this block
        unsigned int transactionCount = 0;
        for(ArcMist::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();)
        {
            if((*trans)->blockHash == pBlockHash)
            {
                ++transactionCount;
                delete *trans;
                trans = mTransactions.erase(trans);
            }
            else
                ++trans;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
          "Reverted block with %d transactions at height %d : %s", transactionCount,
          mCurrentPass.blockHeight, pBlockHash.hex().text());

        // Update last block height
        --mCurrentPass.blockHeight;

        mMutex.unlock();
    }

    // AddressBlock::RelationType AddressBlock::relatesTo(Transaction *pTransaction, bool pAlreadyLocked)
    // {
        // if(paysTo(pTransaction))
            // return PAYS_TO;

        // if(spendsFrom(pTransaction, pAlreadyLocked))
            // return SPENDS_FROM;

        // return NONE;

    // }

    // bool AddressBlock::paysTo(Transaction *pTransaction)
    // {
        // // Check outputs for any block addresses
        // ArcMist::HashList addressHashes;
        // ScriptInterpreter::ScriptType scriptType;

        // for(std::vector<Output *>::iterator output=pTransaction->outputs.begin();output!=pTransaction->outputs.end();++output)
        // {
            // scriptType = ScriptInterpreter::parseOutputScript((*output)->script, addressHashes);
            // if(scriptType != ScriptInterpreter::P2PKH)
                // continue;

            // for(ArcMist::HashList::iterator hash=addressHashes.begin();hash!=addressHashes.end();++hash)
                // if(mAddressHashes.contains(*hash))
                    // return true;
        // }

        // return false;
    // }

    // bool AddressBlock::spendsFrom(Transaction *pTransaction, bool pAlreadyLocked)
    // {
        // ArcMist::HashContainerList<SPVTransactionData *>::Iterator confirmedTransaction;
        // ArcMist::HashContainerList<PendingTransactionData *>::Iterator pendingTransaction;
        // Transaction *otherTransaction;
        // ArcMist::HashList addressHashes;
        // ScriptInterpreter::ScriptType scriptType;

        // if(!pAlreadyLocked)
            // mMutex.lock();

        // for(std::vector<Input *>::iterator input=pTransaction->inputs.begin();input!=pTransaction->inputs.end();++input)
        // {
            // // Check if a confirmed transaction exists for this outpoint
            // confirmedTransaction = mTransactions.get((*input)->outpoint.transactionID);
            // if(confirmedTransaction != mTransactions.end())
            // {
                // // Check that the confirmed transaction has enough outputs for the outpoint index
                // otherTransaction = (*confirmedTransaction)->transaction;
                // if(otherTransaction != NULL && (*input)->outpoint.index < otherTransaction->outputs.size())
                // {
                    // // Parse the output for addresses
                    // scriptType = ScriptInterpreter::parseOutputScript((otherTransaction->outputs[(*input)->outpoint.index])->script, addressHashes);
                    // if(scriptType == ScriptInterpreter::P2PKH)
                    // {
                        // // Check the output addresses against block addresses
                        // for(ArcMist::HashList::iterator hash=addressHashes.begin();hash!=addressHashes.end();++hash)
                            // if(mAddressHashes.contains(*hash))
                            // {
                                // if(!pAlreadyLocked)
                                    // mMutex.unlock();
                                // return true;
                            // }
                    // }
                // }
            // }

            // // Check if a pending transaction exists for this outpoint
            // pendingTransaction = mPendingTransactions.get((*input)->outpoint.transactionID);
            // if(pendingTransaction != mPendingTransactions.end())
            // {
                // // Check that the confirmed transaction has enough outputs for the outpoint index
                // otherTransaction = (*pendingTransaction)->transaction;
                // if(otherTransaction != NULL && (*input)->outpoint.index < otherTransaction->outputs.size())
                // {
                    // // Parse the output for addresses
                    // scriptType = ScriptInterpreter::parseOutputScript((otherTransaction->outputs[(*input)->outpoint.index])->script, addressHashes);
                    // if(scriptType != ScriptInterpreter::NON_STANDARD)
                    // {
                        // // Check the output addresses against block addresses
                        // for(ArcMist::HashList::iterator hash=addressHashes.begin();hash!=addressHashes.end();++hash)
                            // if(mAddressHashes.contains(*hash))
                            // {
                                // if(!pAlreadyLocked)
                                    // mMutex.unlock();
                                // return true;
                            // }
                    // }
                // }
            // }
        // }

        // if(!pAlreadyLocked)
            // mMutex.unlock();
        // return false;
    // }

    void AddressBlock::process(Chain &pChain)
    {
        if(Info::instance().spvMode)
        {
            if(mAddressHashes.size() == 0)
                return;

            unsigned int falsePositiveCount;
            ArcMist::Hash nextBlockHash;
            ArcMist::HashContainerList<MerkleRequestData *>::Iterator request;
            MerkleRequestData *merkleRequest;
            ArcMist::HashContainerList<PendingTransactionData *>::Iterator pendingTransaction;
            ArcMist::HashContainerList<SPVTransactionData *>::Iterator confirmedTransaction;

            while(true)
            {
                // Check if the next block has enough merkle confirms
                mMutex.lock();

                if(!pChain.getBlockHash(mCurrentPass.blockHeight + 1, nextBlockHash))
                {
                    mMutex.unlock();
                    break;
                }

                request = mMerkleRequests.get(nextBlockHash);
                if(request != mMerkleRequests.end())
                {
                    merkleRequest = *request;
                    if(!merkleRequest->isComplete())
                    {
                        // Waiting for more transactions
                        mMutex.unlock();
                        break;
                    }

                    // Process transactions
                    falsePositiveCount = 0;
                    for(std::vector<SPVTransactionData *>::iterator trans=merkleRequest->transactions.begin();trans!=merkleRequest->transactions.end();++trans)
                    {
                        // Remove from pending
                        pendingTransaction = mPendingTransactions.get((*trans)->transaction->hash);
                        if(pendingTransaction != mPendingTransactions.end())
                        {
                            delete *pendingTransaction;
                            mPendingTransactions.erase(pendingTransaction);
                        }

                        // Add to confirmed
                        confirmedTransaction = mTransactions.get((*trans)->transaction->hash);
                        if(confirmedTransaction == mTransactions.end())
                        {
                            // Refresh in case it spends pending or previous transaction in this block
                            refreshTransaction(*trans, false);

                            // Determine if transaction actually effects block addresses
                            if((*trans)->payOutputs.size() > 0 || (*trans)->spendInputs.size() > 0)
                            {
                                mTransactions.insert((*trans)->transaction->hash, *trans);
                                if((*trans)->amount > 0)
                                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                                      "Confirmed transaction paying %0.8f bitcoins : %s", bitcoins((*trans)->amount),
                                      (*trans)->transaction->hash.hex().text());
                                else
                                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                                      "Confirmed transaction spending %0.8f bitcoins : %s", -bitcoins((*trans)->amount),
                                      (*trans)->transaction->hash.hex().text());
                            }
                            else
                            {
                                delete *trans;
                                ++falsePositiveCount;
                            }
                        }
                        else
                            delete *trans; // Transaction already in mTransactions
                    }

                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                      "Adding merkle block from node [%d] with %d/%d trans at height %d : %s", merkleRequest->node,
                      merkleRequest->transactions.size() - falsePositiveCount, merkleRequest->transactions.size(),
                      mCurrentPass.blockHeight + 1, request.hash().hex().text());

                    // Clear so they aren't deleted since they were either reused or already deleted.
                    merkleRequest->transactions.clear();

                    // Check for false positive rate too high
                    if(merkleRequest->node != 0 && falsePositiveCount > 2 &&
                      (float)falsePositiveCount / (float)merkleRequest->totalTransactions > 0.001)
                    {
                        if(falsePositiveCount > 5 && (float)falsePositiveCount / (float)merkleRequest->totalTransactions > 0.02)
                        {
                            bool found = false;
                            for(std::vector<unsigned int>::iterator node=mNodesToClose.begin();node!=mNodesToClose.end();++node)
                                if(*node == merkleRequest->node)
                                {
                                    found = true;
                                    break;
                                }

                            if(!found)
                            {
                                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                                  "Node [%d] needs closed. False positive rate %d/%d", merkleRequest->node,
                                  falsePositiveCount, merkleRequest->totalTransactions);
                                mNodesToClose.push_back(merkleRequest->node);
                            }
                        }
                        else
                        {
                            bool found = false;
                            for(std::vector<unsigned int>::iterator node=mNodesToResendFilter.begin();node!=mNodesToResendFilter.end();++node)
                                if(*node == merkleRequest->node)
                                {
                                    found = true;
                                    break;
                                }

                            //TODO Add delay so bloom filter doesn't get sent after every merkle block received before it actually updates
                            if(!found)
                            {
                                ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESS_BLOCK_LOG_NAME,
                                  "Node [%d] needs bloom filter resend. False positive rate %d/%d", merkleRequest->node,
                                  falsePositiveCount, merkleRequest->totalTransactions);
                                mNodesToResendFilter.push_back(merkleRequest->node);
                            }
                        }
                    }

                    // Remove merkle request
                    delete *request;
                    mMerkleRequests.erase(request);

                    // Update last block hash and height
                    ++mCurrentPass.blockHeight;
                }
                else
                {
                    mMutex.unlock();
                    break;
                }

                mMutex.unlock();
            }
        }
    }
}
