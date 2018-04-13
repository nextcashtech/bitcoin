/**************************************************************************
 * Copyright 2018 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "monitor.hpp"

#include "log.hpp"
#include "base.hpp"
#include "key.hpp"
#include "interpreter.hpp"

#define BITCOIN_MONITOR_LOG_NAME "Monitor"

// Maximum number of concurrent merkle requests
#ifdef LOW_MEM
#define MAX_MERKLE_REQUESTS 500
#else
#define MAX_MERKLE_REQUESTS 2000
#endif


namespace BitCoin
{
    Monitor::Monitor() : mMutex("Monitor")
    {
        mKeyStore = NULL;
        mFilterID = 0;
        mFilter.setup(0);
        mPasses.push_back(PassData());

        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME, "Creating monitor object");
    }

    Monitor::~Monitor()
    {
        NextCash::Log::add(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME, "Destroying monitor object");

        mMutex.lock();
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            delete *trans;
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator transData=mPendingTransactions.begin();transData!=mPendingTransactions.end();++transData)
            delete *transData;
        for(NextCash::HashContainerList<MerkleRequestData *>::Iterator request=mMerkleRequests.begin();request!=mMerkleRequests.end();++request)
            delete *request;
        mMutex.unlock();
    }

    Monitor::MerkleRequestData::~MerkleRequestData()
    {
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans=transactions.begin();trans!=transactions.end();++trans)
            delete *trans;
    }

    bool Monitor::MerkleRequestData::isComplete()
    {
        if(receiveTime == 0)
            return false;

        if(complete || transactions.size() == 0)
            return true;

        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans=transactions.begin();trans!=transactions.end();++trans)
            if((*trans)->transaction == NULL)
                return false;

        complete = true;
        return true;
    }

    void Monitor::MerkleRequestData::release()
    {
        if(!isComplete())
            requestTime = 0;
    }

    void Monitor::MerkleRequestData::clear()
    {
        //node = 0;
        requestTime = 0;
        receiveTime = 0;
        totalTransactions = 0;
        complete = false;
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans=transactions.begin();trans!=transactions.end();++trans)
            delete *trans;
        transactions.clear();
    }

    void Monitor::write(NextCash::OutputStream *pStream)
    {
        mMutex.lock();

        // Version
        pStream->writeUnsignedInt(1);

        // Passes
        pStream->writeUnsignedInt(mPasses.size());
        for(std::vector<PassData>::iterator pass=mPasses.begin();pass!=mPasses.end();++pass)
            pass->write(pStream);

        // Addresses
        pStream->writeUnsignedInt(mAddressHashes.size());
        for(NextCash::HashList::iterator hash=mAddressHashes.begin();hash!=mAddressHashes.end();++hash)
            hash->write(pStream);

        // Transactions
        pStream->writeUnsignedInt(mTransactions.size());
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            (*trans)->write(pStream);

        mMutex.unlock();
    }

    bool Monitor::read(NextCash::InputStream *pStream)
    {
        clear();

        mMutex.lock();

        if(pStream->readUnsignedInt() != 1)
        {
            mMutex.unlock();
            return false; // Wrong version
        }

        // Passes
        unsigned int passesCount = pStream->readUnsignedInt();
        PassData newPassData;
        for(unsigned int i=0;i<passesCount;++i)
        {
            newPassData.clear();
            if(!newPassData.read(pStream))
            {
                mMutex.unlock();
                clear();
                return false;
            }
            mPasses.push_back(newPassData);
        }

        // Addresses
        unsigned int addressCount = pStream->readUnsignedInt();
        mAddressHashes.reserve(addressCount);
        NextCash::Hash addressHash(ADDRESS_HASH_SIZE);
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
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            refreshTransaction(*trans, true);

        refreshBloomFilter(true);

        mMutex.unlock();
        return true;
    }

    void Monitor::SPVTransactionData::write(NextCash::OutputStream *pStream)
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

    bool Monitor::SPVTransactionData::read(NextCash::InputStream *pStream)
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

    Monitor::PassData::PassData()
    {
        beginBlockHeight = 0;
        blockHeight = 0;
        addressesIncluded = 0;
        complete = false;
    }

    Monitor::PassData::PassData(const Monitor::PassData &pCopy)
    {
        beginBlockHeight = pCopy.beginBlockHeight;
        blockHeight = pCopy.blockHeight;
        addressesIncluded = pCopy.addressesIncluded;
        complete = pCopy.complete;
    }

    const Monitor::PassData &Monitor::PassData::operator =(const Monitor::PassData &pRight)
    {
        beginBlockHeight = pRight.beginBlockHeight;
        blockHeight = pRight.blockHeight;
        addressesIncluded = pRight.addressesIncluded;
        complete = pRight.complete;
        return *this;
    }

    void Monitor::PassData::write(NextCash::OutputStream *pStream)
    {
        pStream->writeUnsignedInt(beginBlockHeight);
        pStream->writeUnsignedInt(blockHeight);
        pStream->writeUnsignedInt(addressesIncluded);
        if(complete)
            pStream->writeByte(-1);
        else
            pStream->writeByte(0);
    }

    bool Monitor::PassData::read(NextCash::InputStream *pStream)
    {
        if(pStream->remaining() < 13)
            return false;

        beginBlockHeight = pStream->readUnsignedInt();
        blockHeight = pStream->readUnsignedInt();
        addressesIncluded = pStream->readUnsignedInt();
        if(pStream->readByte())
            complete = true;
        else
            complete = false;
        return true;
    }

    Output *Monitor::getOutput(NextCash::Hash &pTransactionHash, unsigned int pIndex, bool pAllowPending)
    {
        NextCash::HashContainerList<SPVTransactionData *>::Iterator confirmedTransaction = mTransactions.get(pTransactionHash);
        if(confirmedTransaction != mTransactions.end() && (*confirmedTransaction)->transaction != NULL &&
          (*confirmedTransaction)->transaction->outputs.size() > pIndex)
                return &(*confirmedTransaction)->transaction->outputs[pIndex];

        if(!pAllowPending)
            return NULL;

        NextCash::HashContainerList<SPVTransactionData *>::Iterator pendingTransaction = mPendingTransactions.get(pTransactionHash);
        if(pendingTransaction != mPendingTransactions.end() && (*pendingTransaction)->transaction != NULL &&
          (*pendingTransaction)->transaction->outputs.size() > pIndex)
                return &(*pendingTransaction)->transaction->outputs[pIndex];

        return NULL;
    }

    bool Monitor::getPayAddresses(Output *pOutput, NextCash::HashList &pAddresses, bool pBlockOnly)
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
            for(NextCash::HashList::iterator hash=pAddresses.begin();hash!=pAddresses.end();)
            {
                if(mAddressHashes.contains(*hash))
                    ++hash;
                else
                    hash = pAddresses.erase(hash); // Erase addresses not in block
            }

        return pAddresses.size() > 0;
    }

    void Monitor::refreshTransaction(Monitor::SPVTransactionData *pTransaction, bool pAllowPending)
    {
        pTransaction->amount = 0;
        pTransaction->payOutputs.clear();
        pTransaction->spendInputs.clear();

        if(pTransaction->transaction == NULL)
            return;

        // Check for spends
        Output *spentOutput;
        NextCash::HashList payAddresses;
        unsigned int index = 0;
        for(std::vector<Input>::iterator input=pTransaction->transaction->inputs.begin();input!=pTransaction->transaction->inputs.end();++input)
        {
            // Find output being spent
            spentOutput = getOutput(input->outpoint.transactionID, input->outpoint.index, pAllowPending);
            if(spentOutput != NULL && getPayAddresses(spentOutput, payAddresses, true)) // Check that output actually pays block address
            {
                pTransaction->spendInputs.push_back(index);
                pTransaction->amount -= spentOutput->amount;
            }
            ++index;
        }

        // Check for payments
        index = 0;
        bool updateNeeded = false, newAddressesCreated = false;
        for(std::vector<Output>::iterator output=pTransaction->transaction->outputs.begin();output!=pTransaction->transaction->outputs.end();++output)
        {
            if(getPayAddresses(&(*output), payAddresses, true))
            {
                if(mKeyStore != NULL)
                {
                    for(NextCash::HashList::iterator hash=payAddresses.begin();hash!=payAddresses.end();++hash)
                    {
                        mKeyStore->markUsed(*hash, 20, newAddressesCreated);
                        if(newAddressesCreated)
                            updateNeeded = true;
                    }
                }
                pTransaction->payOutputs.push_back(index);
                pTransaction->amount += output->amount;
            }

            ++index;
        }

        // Refresh addresses from key store and update bloom filter if necessary
        if(updateNeeded && refreshKeyStore())
            restartBloomFilter();
    }

    void Monitor::clear()
    {
        mMutex.lock();

        mPasses.clear();
        mAddressHashes.clear();
        mFilter.clear();
        mNodesToResendFilter.clear();
        mNodesToClose.clear();

        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            delete *trans;
        mTransactions.clear();

        for(NextCash::HashContainerList<MerkleRequestData *>::Iterator request=mMerkleRequests.begin();request!=mMerkleRequests.end();++request)
            delete *request;
        mMerkleRequests.clear();

        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator transData=mPendingTransactions.begin();transData!=mPendingTransactions.end();++transData)
            delete *transData;
        mPendingTransactions.clear();

        mMutex.unlock();
    }

    void Monitor::startNewPass()
    {
        unsigned int passIndex = 0;
        for(std::vector<PassData>::iterator pass=mPasses.begin();pass!=mPasses.end();++pass,++passIndex)
            if(!pass->complete && pass->blockHeight > 0)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                  "Pass %d marked complete at block height %d to start new pass for new addresses",
                  passIndex, pass->blockHeight);
                pass->complete = true;
            }

        if(mPasses.size() == 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
              "Starting first pass %d for %d addresses", mPasses.size() + 1, mAddressHashes.size());
            mPasses.push_back(PassData());
        }
        else if(mPasses.back().blockHeight > 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
              "Starting new pass %d for new addresses", mPasses.size() + 1);
            mPasses.push_back(PassData());
        }

        mPasses.back().addressesIncluded = mAddressHashes.size();

        restartBloomFilter();
    }

    void Monitor::restartBloomFilter()
    {
        for(NextCash::HashContainerList<MerkleRequestData *>::Iterator request=mMerkleRequests.begin();request!=mMerkleRequests.end();++request)
            delete *request;
        mMerkleRequests.clear();

        refreshBloomFilter(true);
    }

    bool Monitor::loadAddresses(NextCash::InputStream *pStream)
    {
        mMutex.lock();

        unsigned int addedCount = 0;
        NextCash::String line;
        unsigned char nextChar;
        NextCash::Hash addressHash;
        AddressType addressType;
        AddressFormat addressFormat;

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

            if(line.length() && decodeAddress(line, addressHash, addressType, addressFormat) &&
              addressType == PUB_KEY_HASH && addressHash.size() == ADDRESS_HASH_SIZE)
            {
                // Check if it is already in this block
                if(!mAddressHashes.contains(addressHash))
                {
                    mAddressHashes.push_back(addressHash);
                    ++addedCount;
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                      "Adding address hash : %s", line.text());
                }
            }
        }

        if(addedCount)
            startNewPass();

        mMutex.unlock();
        return true;
    }

    void Monitor::setKeyStore(KeyStore *pKeyStore)
    {
        mMutex.lock();
        mKeyStore = pKeyStore;
        if(refreshKeyStore())
            startNewPass();
        mMutex.unlock();
    }

    unsigned int Monitor::refreshKeyStore()
    {
        unsigned int addedCount = 0;
        std::vector<Key *> children;
        Key *chain;

        for(KeyStore::iterator key=mKeyStore->begin();key!=mKeyStore->end();++key)
        {
            if((*key)->depth() == 0)
            {
                // Check for BIP-0044 External Addresses
                chain = (*key)->chainKey(0, Key::BIP0044);
                if(chain != NULL && chain->childCount() > 0)
                {
                    chain->getChildren(children);
                    for(std::vector<Key *>::iterator child=children.begin();child!=children.end();++child)
                        if(!mAddressHashes.contains((*child)->hash()))
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                              "Added new BIP0044 external address from key store : %s", (*child)->address().text());
                            mAddressHashes.push_back((*child)->hash());
                            ++addedCount;
                        }
                }

                // Check for BIP-0044 Internal Addresses
                chain = (*key)->chainKey(1, Key::BIP0044);
                if(chain != NULL && chain->childCount() > 0)
                {
                    chain->getChildren(children);
                    for(std::vector<Key *>::iterator child=children.begin();child!=children.end();++child)
                        if(!mAddressHashes.contains((*child)->hash()))
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                              "Added new BIP0044 internal address from key store : %s", (*child)->address().text());
                            mAddressHashes.push_back((*child)->hash());
                            ++addedCount;
                        }
                }

                // Check for BIP-0032 External Addresses
                chain = (*key)->chainKey(0, Key::BIP0032);
                if(chain != NULL && chain->childCount() > 0)
                {
                    chain->getChildren(children);
                    for(std::vector<Key *>::iterator child=children.begin();child!=children.end();++child)
                        if(!mAddressHashes.contains((*child)->hash()))
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                              "Added new BIP0032 external address from key store : %s", (*child)->address().text());
                            mAddressHashes.push_back((*child)->hash());
                            ++addedCount;
                        }
                }

                // Check for BIP-0032 Internal Addresses
                chain = (*key)->chainKey(1, Key::BIP0032);
                if(chain != NULL && chain->childCount() > 0)
                {
                    chain->getChildren(children);
                    for(std::vector<Key *>::iterator child=children.begin();child!=children.end();++child)
                        if(!mAddressHashes.contains((*child)->hash()))
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                              "Added new BIP0032 internal address from key store : %s", (*child)->address().text());
                            mAddressHashes.push_back((*child)->hash());
                            ++addedCount;
                        }
                }

                // Check for SIMPLE External Addresses
                chain = (*key)->chainKey(0, Key::SIMPLE);
                if(chain != NULL && chain->childCount() > 0)
                {
                    chain->getChildren(children);
                    for(std::vector<Key *>::iterator child=children.begin();child!=children.end();++child)
                        if(!mAddressHashes.contains((*child)->hash()))
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                              "Added new SIMPLE external address from key store : %s", (*child)->address().text());
                            mAddressHashes.push_back((*child)->hash());
                            ++addedCount;
                        }
                }

                // Check for SIMPLE Internal Addresses
                chain = (*key)->chainKey(1, Key::SIMPLE);
                if(chain != NULL && chain->childCount() > 0)
                {
                    chain->getChildren(children);
                    for(std::vector<Key *>::iterator child=children.begin();child!=children.end();++child)
                        if(!mAddressHashes.contains((*child)->hash()))
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                              "Added new SIMPLE internal address from key store : %s", (*child)->address().text());
                            mAddressHashes.push_back((*child)->hash());
                            ++addedCount;
                        }
                }
            }
            else if((*key)->depth() == 0xff)
            {
                if(!mAddressHashes.contains((*key)->hash()))
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                      "Added new individual address from key store : %s", (*key)->address().text());
                    mAddressHashes.push_back((*key)->hash());
                    ++addedCount;
                }
            }
            else
            {
                // Check for immediate children addresses.
                // For scenarios like when a public chain key is provided for monitoring.
                (*key)->getChildren(children);
                for(std::vector<Key *>::iterator child=children.begin();child!=children.end();++child)
                    if(!mAddressHashes.contains((*child)->hash()))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                          "Added new immediate child address from key store : %s", (*child)->address().text());
                        mAddressHashes.push_back((*child)->hash());
                        ++addedCount;
                    }
            }
        }

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
          "Added %d new addresses from key store", addedCount);
        return addedCount;
    }

    void Monitor::refreshBloomFilter(bool pLocked)
    {
        std::vector<Outpoint *> outpoints;

        if(!pLocked)
            mMutex.lock();

        // Add outpoints to monitor for spending
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            for(std::vector<unsigned int>::iterator index=(*trans)->payOutputs.begin();index!=(*trans)->payOutputs.end();++index)
                outpoints.push_back(new Outpoint((*trans)->transaction->hash, *index));

        mFilter.setup(mAddressHashes.size() + outpoints.size(), BloomFilter::UPDATE_NONE, 0.00001);

        // Add Address hashes to monitor for "pay to" transactions
        for(NextCash::HashList::iterator hash=mAddressHashes.begin();hash!=mAddressHashes.end();++hash)
            mFilter.add(*hash);

        // Add outpoints of UTXOs to monitor for "spend from" transactions
        for(std::vector<Outpoint *>::iterator outpoint=outpoints.begin();outpoint!=outpoints.end();++outpoint)
        {
            mFilter.add(**outpoint);
            delete *outpoint;
        }

        ++mFilterID;
        mNodesToResendFilter.clear();
        if(!pLocked)
            mMutex.unlock();
    }

    unsigned int Monitor::height()
    {
        unsigned int result = 0;
        bool resultEmpty = true;

        mMutex.lock();
        for(std::vector<PassData>::iterator pass=mPasses.begin();pass!=mPasses.end();++pass)
            if(!pass->complete && (resultEmpty || pass->blockHeight < result))
            {
                resultEmpty = false;
                result = pass->blockHeight;
            }
        mMutex.unlock();

        return result;
    }

    int64_t Monitor::balance(bool pLocked)
    {
        if(!pLocked)
            mMutex.lock();
        int64_t result = 0;
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
            result += (*trans)->amount;
        if(!pLocked)
            mMutex.unlock();
        return result;
    }

    int64_t Monitor::balance(Key *pKey, bool pIncludePending)
    {
        int64_t result = 0;
        NextCash::HashList payAddresses;
        Output *output;

        mMutex.lock();
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();++trans)
        {
            for(std::vector<unsigned int>::iterator index=(*trans)->spendInputs.begin();index!=(*trans)->spendInputs.end();++index)
            {
                output = getOutput((*trans)->transaction->inputs[*index].outpoint.transactionID,
                  (*trans)->transaction->inputs[*index].outpoint.index, false);
                if(output != NULL && getPayAddresses(&(*trans)->transaction->outputs[*index], payAddresses, true))
                {
                    for(NextCash::HashList::iterator hash=payAddresses.begin();hash!=payAddresses.end();++hash)
                        if(pKey->findAddress(*hash) != NULL)
                        {
                            result -= (*trans)->transaction->outputs[*index].amount;
                            break;
                        }
                }
            }

            for(std::vector<unsigned int>::iterator index=(*trans)->payOutputs.begin();index!=(*trans)->payOutputs.end();++index)
            {
                if(getPayAddresses(&(*trans)->transaction->outputs[*index], payAddresses, true))
                {
                    for(NextCash::HashList::iterator hash=payAddresses.begin();hash!=payAddresses.end();++hash)
                        if(pKey->findAddress(*hash) != NULL)
                        {
                            result += (*trans)->transaction->outputs[*index].amount;
                            break;
                        }
                }
            }
        }
        mMutex.unlock();

        return result;
    }

    bool Monitor::filterNeedsResend(unsigned int pNodeID, unsigned int pBloomID)
    {
        mMutex.lock();

        if(pBloomID != mFilterID)
        {
            mMutex.unlock();
            return true;
        }

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

    bool Monitor::needsClose(unsigned int pNodeID)
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

    void Monitor::release(unsigned int pNodeID)
    {
        mMutex.lock();

        for(NextCash::HashContainerList<MerkleRequestData *>::Iterator request=mMerkleRequests.begin();request!=mMerkleRequests.end();++request)
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

    unsigned int Monitor::setupBloomFilter(BloomFilter &pFilter)
    {
        mMutex.lock();
        pFilter = mFilter;
        unsigned int result = mFilterID;
        mMutex.unlock();

        return result;
    }

    void Monitor::getNeededMerkleBlocks(unsigned int pNodeID, Chain &pChain, NextCash::HashList &pBlockHashes, unsigned int pMaxCount)
    {
        NextCash::Hash nextBlockHash;
        NextCash::HashContainerList<MerkleRequestData *>::Iterator request;
        MerkleRequestData *newMerkleRequest;
        unsigned int blockHeight;
        int32_t time = getTime();

        pBlockHashes.clear();

        mMutex.lock();

        for(std::vector<PassData>::reverse_iterator pass=mPasses.rbegin();pass!=mPasses.rend();++pass)
        {
            if(pass->complete)
                continue;

            blockHeight = pass->blockHeight;

            while(pBlockHashes.size() < pMaxCount)
            {
                // Get next block hash
                if(!pChain.getBlockHash(++blockHeight, nextBlockHash))
                    break;

                // Check if there is a merkle request for this block hash and if it needs more requests sent
                request = mMerkleRequests.get(nextBlockHash);
                if(request == mMerkleRequests.end())
                {
                    if(mMerkleRequests.size() < MAX_MERKLE_REQUESTS && !mFilter.isEmpty())
                    {
                        // Add new merkle block request
                        newMerkleRequest = new MerkleRequestData(pNodeID, time);
                        mMerkleRequests.insert(nextBlockHash, newMerkleRequest);
                        pBlockHashes.push_back(nextBlockHash);
                    }
                    else
                        break;
                }
                else if(!(*request)->isComplete() &&
                  (*request)->node != pNodeID && // Don't reassign to the same node
                  ((*request)->requestTime == 0 || ((*request)->requestTime != 0 && time - (*request)->requestTime > 60)))
                {
                    if((*request)->node != 0 && (*request)->requestTime != 0)
                    {
                        // Close slow node
                        bool found = false;
                        for(std::vector<unsigned int>::iterator node=mNodesToClose.begin();node!=mNodesToClose.end();++node)
                            if(*node == (*request)->node)
                            {
                                found = true;
                                break;
                            }

                        if(!found)
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                              "Node [%d] needs closed. Merkle blocks too slow", (*request)->node);
                            mNodesToClose.push_back((*request)->node);
                        }
                    }

                    // Assign request to this node
                    (*request)->node = pNodeID;
                    (*request)->requestTime = time;
                    pBlockHashes.push_back(nextBlockHash);
                }
            }

            if(pBlockHashes.size() >= pMaxCount)
                break;
        }

        mMutex.unlock();
    }

    bool Monitor::addMerkleBlock(Chain &pChain, Message::MerkleBlockData *pData, unsigned int pNodeID)
    {
        mMutex.lock();

        NextCash::HashContainerList<MerkleRequestData *>::Iterator requestIter = mMerkleRequests.get(pData->block->hash);
        if(requestIter == mMerkleRequests.end())
        {
            mMutex.unlock();
            return false; // Not a requested block, so it probably isn't in the chain
        }

        // Check if it is already complete
        // Check if node id matches. It must match to ensure this is based on the latest bloom filter.
        //   For Bloom filter updates based on finding new UTXOs.
        MerkleRequestData *request = *requestIter;
        if(request->isComplete() || request->node != pNodeID)
        {
            mMutex.unlock();
            return false;
        }

        // Validate
        NextCash::HashList transactionHashes;
        if(!pData->validate(transactionHashes))
        {
            request->release();
            mMutex.unlock();
            return false;
        }

        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MONITOR_LOG_NAME,
          // "Received merkle block from node [%d] with %d transaction hashes : %s", pNodeID,
          // transactionHashes.size(), pData->block->hash.hex().text());

        request->totalTransactions = pData->block->transactionCount;

        // Update transactions because if more than one merkle block are received from different
        //   nodes, then they might have different bloom filters and different false positive
        //   transactions.
        SPVTransactionData *newSPVTransaction;
        NextCash::HashContainerList<SPVTransactionData *>::Iterator transaction;
        NextCash::HashContainerList<SPVTransactionData *>::Iterator pendingTransaction;
        NextCash::HashContainerList<SPVTransactionData *>::Iterator confirmedTransaction;
        for(NextCash::HashList::iterator hash=transactionHashes.begin();hash!=transactionHashes.end();++hash)
        {
            transaction = request->transactions.get(*hash);
            if(transaction == request->transactions.end())
            {
                // Check Pending
                pendingTransaction = mPendingTransactions.get(*hash);
                if(pendingTransaction != mPendingTransactions.end())
                {
                    NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MONITOR_LOG_NAME,
                      "Transaction pulled from pending into merkle request : %s", hash->hex().text());
                    request->transactions.insert(*hash, *pendingTransaction);
                    (*pendingTransaction)->blockHash = pData->block->hash;
                    mPendingTransactions.erase(pendingTransaction);
                }
                else
                {
                    confirmedTransaction = mTransactions.get(*hash);
                    if(confirmedTransaction != mTransactions.end())
                    {
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MONITOR_LOG_NAME,
                          "Transaction found in confirmed for merkle request : %s", hash->hex().text());
                        newSPVTransaction = new SPVTransactionData(**confirmedTransaction);
                        request->transactions.insert(*hash, newSPVTransaction);
                        newSPVTransaction->blockHash = pData->block->hash;
                    }
                    else // Create empty transaction
                    {
                        newSPVTransaction = new SPVTransactionData(pData->block->hash);
                        request->transactions.insert(*hash, newSPVTransaction);
                    }
                }
            }
        }

        // Check for any extra transactions (different false positives from previous peer)
        for(transaction=request->transactions.begin();transaction!=request->transactions.end();)
        {
            if(transactionHashes.contains(transaction.hash()))
                ++transaction;
            else
            {
                // Move transaction to pending
                if(mPendingTransactions.get((*transaction)->transaction->hash) == mPendingTransactions.end())
                {
                    (*transaction)->blockHash.clear();
                    mPendingTransactions.insert((*transaction)->transaction->hash, *transaction);
                }
                else
                    delete *transaction; // Already in pending

                transaction = request->transactions.erase(transaction);
            }
        }

        // Mark receive time
        if(request->receiveTime != 0)
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MONITOR_LOG_NAME,
              "Repeated merkle block from node [%d] with %d transaction (%d sec ago) : %s", pNodeID,
              request->transactions.size(), getTime() - request->receiveTime, pData->block->hash.hex().text());

        request->receiveTime = getTime();

        bool processNeeded = request->isComplete();

        mMutex.unlock();

        // Note : Process function waits for transactions for the specified hashes, then removes
        //   the requests in chain order.
        if(processNeeded)
            process(pChain);

        return true;
    }

    bool Monitor::addTransaction(Chain &pChain, Message::TransactionData *pTransactionData)
    {
        bool result = false;

        mMutex.lock();

        if(mTransactions.get(pTransactionData->transaction->hash) != mTransactions.end())
        {
            mMutex.unlock();
            return result; // Already confirmed this transaction
        }

        if(Info::instance().spvMode)
        {
            // Check that it has been proven by a merkle block
            MerkleRequestData *request;
            bool processNeeded = false;
            NextCash::HashContainerList<SPVTransactionData *>::Iterator transactionIter;
            for(NextCash::HashContainerList<MerkleRequestData *>::Iterator requestIter=mMerkleRequests.begin();requestIter!=mMerkleRequests.end();++requestIter)
            {
                request = *requestIter;
                transactionIter = request->transactions.get(pTransactionData->transaction->hash);
                if(transactionIter != request->transactions.end())
                {
                    result = true;
                    if((*transactionIter)->transaction == NULL)
                    {
                        (*transactionIter)->transaction = pTransactionData->transaction;
                        pTransactionData->transaction = NULL; // Prevent it from being deleted
                        refreshTransaction(*transactionIter, true);
                        processNeeded = request->isComplete();
                        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MONITOR_LOG_NAME,
                          // "Added confirmed transaction to merkle block request : %s", transaction->hash.hex().text());

                        // Note: Bloom filter updated when merkle block is processed
                    }

                    mMutex.unlock();
                    if(processNeeded)
                        process(pChain);
                    return result;
                }
            }

            // Check pending transactions
            NextCash::HashContainerList<SPVTransactionData *>::Iterator pendingTransaction = mPendingTransactions.get(pTransactionData->transaction->hash);
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
                        NextCash::String subject, message;
                        if((*pendingTransaction)->amount > 0)
                        {
                            subject = "Bitcoin Cash Receive Pending";
                            message.writeFormatted("Receive pending for %0.8f bitcoins.\nTransaction : %s",
                              bitcoins((*pendingTransaction)->amount), (*pendingTransaction)->transaction->hash.hex().text());
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                              "Pending transaction receiving %0.8f bitcoins : %s", bitcoins((*pendingTransaction)->amount),
                              (*pendingTransaction)->transaction->hash.hex().text());
                        }
                        else
                        {
                            subject = "Bitcoin Cash Send Pending";
                            message.writeFormatted("Send pending for %0.8f bitcoins.\nTransaction : %s",
                              -bitcoins((*pendingTransaction)->amount), (*pendingTransaction)->transaction->hash.hex().text());
                            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                              "Pending transaction sending %0.8f bitcoins : %s", -bitcoins((*pendingTransaction)->amount),
                              (*pendingTransaction)->transaction->hash.hex().text());
                        }

                        notify(subject, message);
                    }
                    else
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                          "Pending transaction (unrelated) : %s", (*pendingTransaction)->transaction->hash.hex().text());
                        //delete *pendingTransaction;
                        //mPendingTransactions.erase(pendingTransaction);
                    }
                }
            }

            if(!result)
                NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MONITOR_LOG_NAME,
                  "Transaction not found in merkle block or pending : %s", pTransactionData->transaction->hash.hex().text());

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
                // NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                  // "Received pending transaction : %s", pTransaction->hash.hex().text());
            // }
            // else
            // {
                // delete *pendingTransaction;
                // mPendingTransactions.erase(pendingTransaction);
                // NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                  // "Removed unrelated pending transaction : %s", pTransaction->hash.hex().text());
            // }

            mMutex.unlock();
            return result;
        }
    }

    bool Monitor::addTransactionAnnouncement(const NextCash::Hash &pTransactionHash, unsigned int pNodeID)
    {
        bool result = false;
        mMutex.lock();

        if(Info::instance().spvMode)
        {
            NextCash::HashContainerList<SPVTransactionData *>::Iterator pendingTransaction = mPendingTransactions.get(pTransactionHash);
            if(pendingTransaction == mPendingTransactions.end())
            {
                // Add new pending transaction
                SPVTransactionData *newPendingTransaction = new SPVTransactionData();
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
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
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
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

    void Monitor::revertBlock(const NextCash::Hash &pBlockHash, unsigned int pBlockHeight)
    {
        mMutex.lock();

        // If there is an active request then remove it and that is all
        NextCash::HashContainerList<MerkleRequestData *>::Iterator request = mMerkleRequests.get(pBlockHash);
        if(request != mMerkleRequests.end())
        {
            // TODO Move transactions back to pending
            delete *request;
            mMerkleRequests.erase(request);
            mMutex.unlock();
            return;
        }

        // Remove any transactions associated with this block
        unsigned int transactionCount = 0;
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans=mTransactions.begin();trans!=mTransactions.end();)
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

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
          "Reverted block with %d transactions at height %d : %s", transactionCount,
          pBlockHeight, pBlockHash.hex().text());

        // Update last block height
        for(std::vector<PassData>::iterator pass=mPasses.begin();pass!=mPasses.end();++pass)
            if(!pass->complete && pass->blockHeight == pBlockHeight)
                --(pass->blockHeight);

        mMutex.unlock();
    }

    void Monitor::process(Chain &pChain)
    {
        if(Info::instance().spvMode)
        {
            if(mAddressHashes.size() == 0)
                return;

            mMutex.lock();

            unsigned int falsePositiveCount;
            bool resetNeeded = false, balanceUpdated = false;
            NextCash::Hash nextBlockHash;
            NextCash::HashContainerList<MerkleRequestData *>::Iterator request;
            MerkleRequestData *merkleRequest;
            NextCash::HashContainerList<SPVTransactionData *>::Iterator pendingTransaction;
            NextCash::HashContainerList<SPVTransactionData *>::Iterator confirmedTransaction;
            unsigned int passIndex = mPasses.size();

            if(pChain.isInSync() && pChain.height() > 5000 && mPasses.back().blockHeight < (unsigned int)pChain.height() - 5000)
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                  "Starting new pass at block height %d to monitor new blocks", pChain.height());
                PassData newPass;
                newPass.beginBlockHeight = pChain.height();
                newPass.blockHeight = newPass.beginBlockHeight;
                newPass.addressesIncluded = mAddressHashes.size();
                mPasses.push_back(newPass);
                ++passIndex;
            }

            for(std::vector<PassData>::reverse_iterator pass=mPasses.rbegin();pass!=mPasses.rend();++pass,--passIndex)
            {
                if(pass->complete)
                    continue;

                if(pass->blockHeight == (unsigned int)pChain.height() && passIndex < mPasses.size())
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                      "Pass %d completed at block height %d", passIndex, pass->blockHeight);
                    pass->complete = true;
                    continue;
                }

                while(true)
                {
                    // Check if the next block has enough merkle confirms
                    if(!pChain.getBlockHash(pass->blockHeight + 1, nextBlockHash))
                        break;

                    request = mMerkleRequests.get(nextBlockHash);
                    if(request != mMerkleRequests.end())
                    {
                        merkleRequest = *request;
                        if(!merkleRequest->isComplete())
                            break; // Waiting for more transactions

                        // Process transactions
                        falsePositiveCount = 0;
                        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans=merkleRequest->transactions.begin();trans!=merkleRequest->transactions.end();++trans)
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

                                // New UTXO requires new bloom filter and reset of all existing merkle requests
                                if((*trans)->payOutputs.size() > 0)
                                    resetNeeded = true;

                                // Determine if transaction actually effects block addresses
                                if((*trans)->payOutputs.size() > 0 || (*trans)->spendInputs.size() > 0)
                                {
                                    balanceUpdated = true;
                                    mTransactions.insert((*trans)->transaction->hash, *trans);
                                    NextCash::String subject, message;

                                    if((*trans)->amount > 0)
                                    {
                                        subject = "Bitcoin Cash Receive Confirmed";
                                        message.writeFormatted("Receive confirmed for %0.8f bitcoins in block %d\nNew Balance : %0.8f\nTransaction : %s",
                                          bitcoins((*trans)->amount), pass->blockHeight + 1, bitcoins(balance(true)),
                                          (*trans)->transaction->hash.hex().text());
                                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                                          "Confirmed transaction receiving %0.8f bitcoins : %s", bitcoins((*trans)->amount),
                                          (*trans)->transaction->hash.hex().text());
                                    }
                                    else
                                    {
                                        subject = "Bitcoin Cash Send Confirmed";
                                        message.writeFormatted("Send confirmed for %0.8f bitcoins in block %d.\nNew Balance : %0.8f\nTransaction : %s",
                                          -bitcoins((*trans)->amount), pass->blockHeight + 1, bitcoins(balance(true)),
                                          (*trans)->transaction->hash.hex().text());
                                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                                          "Confirmed transaction sending %0.8f bitcoins : %s", -bitcoins((*trans)->amount),
                                          (*trans)->transaction->hash.hex().text());
                                    }

                                    notify(subject, message);
                                }
                                else
                                {
                                    delete *trans;
                                    ++falsePositiveCount;
                                }
                            }
                            else
                                delete *trans; // Transaction already confirmed
                        }

                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                          "Adding merkle block from node [%d] with %d/%d trans at height %d : %s", merkleRequest->node,
                          merkleRequest->transactions.size() - falsePositiveCount, merkleRequest->transactions.size(),
                          pass->blockHeight + 1, request.hash().hex().text());

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
                                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
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
                                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
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
                        ++(pass->blockHeight);
                    }
                    else
                        break;

                    if(balanceUpdated)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                          "Total balance updated to %0.8f bitcoins", bitcoins(balance(true)));
                        balanceUpdated = false;
                    }

                    if(resetNeeded)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                          "New UTXO found. Resetting bloom filters and merkle requests");

                        // Update bloom filter and reset all node bloom filters
                        // Node bloom filters are reset with mFilterID
                        refreshBloomFilter(true);

                        // Reset all merkle requests so they are only received with updated bloom filters
                        for(NextCash::HashContainerList<MerkleRequestData *>::Iterator request=mMerkleRequests.begin();request!=mMerkleRequests.end();++request)
                            (*request)->clear();

                        break;
                    }
                }

                if(resetNeeded)
                    break;
            }

            mMutex.unlock();
        }
        else
        {
            // Not SPV mode

        }
    }
}
