/**************************************************************************
 * Copyright 2018 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "monitor.hpp"

#include "log.hpp"
#include "base.hpp"
#include "key.hpp"
#include "interpreter.hpp"

#include <algorithm>

#define BITCOIN_MONITOR_LOG_NAME "Monitor"

// Maximum number of concurrent merkle requests
#define MAX_MERKLE_REQUESTS 2000


namespace BitCoin
{
    Monitor::Monitor() : mMutex("Monitor")
    {
        mKeyStore = NULL;
        mFilterID = 0;
        mChangeID = 0;
        mFilter.setup(0);
        mLoaded = false;
        mLowestPassHeight = 0;
        mLowestPassHeightSet = false;
        mBloomFilterNeedsRestart = false;
        mRoughMerkleHeight = 0;
        mReversePassHeight = 0xffffffff;
    }

    Monitor::~Monitor()
    {
        NextCash::Log::add(NextCash::Log::DEBUG, BITCOIN_MONITOR_LOG_NAME,
          "Destroying monitor object");

        mMutex.lock();
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
            delete *trans;
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator transData =
          mPendingTransactions.begin(); transData != mPendingTransactions.end(); ++transData)
            delete *transData;
        for(NextCash::HashContainerList<MerkleRequestData *>::Iterator request =
          mMerkleRequests.begin(); request != mMerkleRequests.end(); ++request)
            delete *request;
        mMutex.unlock();
    }

    Monitor::MerkleRequestData::~MerkleRequestData()
    {
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          transactions.begin(); trans != transactions.end(); ++trans)
            if(*trans != NULL)
                delete *trans;
    }

    bool Monitor::MerkleRequestData::addNode(unsigned int pNodeID, Time pRequestTime)
    {
        if(complete || nodes.size() >= requiredNodeCount)
            return false;

        for(std::vector<NodeData>::iterator node = nodes.begin(); node != nodes.end(); ++node)
            if(node->nodeID == pNodeID)
                return false;

        nodes.emplace_back(pNodeID, pRequestTime);
        return true;
    }

    bool Monitor::MerkleRequestData::removeNode(unsigned int pNodeID)
    {
        for(std::vector<NodeData>::iterator node = nodes.begin(); node != nodes.end(); ++node)
            if(node->nodeID == pNodeID)
            {
                nodes.erase(node);
                return true;
            }

        return false;
    }

    unsigned int Monitor::MerkleRequestData::timedOutNode(Time pTime)
    {
        unsigned int result = 0;
        for(std::vector<NodeData>::iterator node = nodes.begin(); node != nodes.end(); ++node)
            if(node->receiveTime == 0 && pTime - node->requestTime > 60)
            {
                result = node->nodeID;
                nodes.erase(node);
                return result;
            }

        return result;
    }

    bool Monitor::MerkleRequestData::wasRequested(unsigned int pNodeID)
    {
        for(std::vector<NodeData>::iterator node = nodes.begin(); node != nodes.end(); ++node)
            if(node->nodeID == pNodeID)
                return true;

        return false;
    }

    bool Monitor::MerkleRequestData::markReceived(unsigned int pNodeID)
    {
        for(std::vector<NodeData>::iterator node = nodes.begin(); node != nodes.end(); ++node)
            if(node->nodeID == pNodeID && node->receiveTime == 0)
            {
                node->receiveTime = getTime();
                return true;
            }

        return false;
    }

    bool Monitor::MerkleRequestData::hasReceived()
    {
        bool received = false;
        for(std::vector<NodeData>::iterator node = nodes.begin(); node != nodes.end(); ++node)
            if(node->receiveTime != 0)
            {
                received = true;
                break;
            }

        if(!received)
            return false;

        // Check for missing transactions
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          transactions.begin(); trans != transactions.end(); ++trans)
            if(*trans != NULL)
                return false;

        return true;
    }

    bool Monitor::MerkleRequestData::isComplete()
    {
        if(complete)
            return true;

        if(nodes.size() < requiredNodeCount)
            return false;

        for(std::vector<NodeData>::iterator node = nodes.begin(); node != nodes.end(); ++node)
            if(node->receiveTime == 0)
                return false;

        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          transactions.begin(); trans != transactions.end(); ++trans)
            if(*trans != NULL && (*trans)->transaction == NULL)
                return false;

        complete = true;
        return true;
    }

    void Monitor::MerkleRequestData::release(unsigned int pNodeID)
    {
        if(!isComplete())
            removeNode(pNodeID);
    }

    void Monitor::MerkleRequestData::clear()
    {
        nodes.clear();
        totalTransactions = 0;
        complete = false;
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          transactions.begin(); trans != transactions.end(); ++trans)
            if(*trans != NULL)
                delete *trans;
        transactions.clear();
    }

    bool transGreater(Monitor::SPVTransactionData *pLeft, Monitor::SPVTransactionData *pRight)
    {
        return pLeft->blockHeight > pRight->blockHeight;
    }

    void Monitor::sortTransactions(Chain *pChain)
    {
        mMutex.lock();

        std::vector<SPVTransactionData *> transactions;
        transactions.reserve(mTransactions.size());
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
        {
            if((*trans)->blockHeight == 0xffffffff)
                (*trans)->blockHeight = pChain->hashHeight((*trans)->blockHash);
            transactions.push_back(*trans);
        }

        std::sort(transactions.begin(), transactions.end(), transGreater);

        mTransactions.clear();
        for(std::vector<SPVTransactionData *>::iterator trans = transactions.begin();
          trans != transactions.end(); ++trans)
            mTransactions.insert((*trans)->transaction->hash, *trans);

        mMutex.unlock();
    }

    void Monitor::write(NextCash::OutputStream *pStream)
    {
        mMutex.lock();

        if(!mLoaded)
        {
            mMutex.unlock();
            return;
        }

        // Version
        pStream->writeUnsignedInt(2);

        // Passes
        pStream->writeUnsignedInt(mPasses.size());
        for(std::vector<PassData>::iterator pass = mPasses.begin(); pass != mPasses.end(); ++pass)
            pass->write(pStream);

        // Addresses
        pStream->writeUnsignedInt(mAddressHashes.size());
        for(NextCash::HashList::iterator hash = mAddressHashes.begin();
          hash != mAddressHashes.end(); ++hash)
            hash->write(pStream);

        // Transactions
        pStream->writeUnsignedInt(mTransactions.size());
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
            (*trans)->write(pStream);

        mMutex.unlock();
    }

    bool Monitor::read(NextCash::InputStream *pStream)
    {
        clear();

        mMutex.lock();

        unsigned int version = pStream->readUnsignedInt();
        if(version != 1 && version != 2)
        {
            mMutex.unlock();
            return false; // Wrong version
        }

        // Passes
        unsigned int passesCount = pStream->readUnsignedInt();
        PassData newPassData;
        mLowestPassHeightSet = false;
        mLowestPassHeight = 0;
        for(unsigned int i=0;i<passesCount;++i)
        {
            newPassData.clear();
            if(!newPassData.read(pStream))
            {
                mMutex.unlock();
                clear();
                return false;
            }
            if(!newPassData.complete &&
              (!mLowestPassHeightSet || newPassData.blockHeight < mLowestPassHeight))
            {
                mLowestPassHeightSet = true;
                mLowestPassHeight = newPassData.blockHeight;
            }
            mPasses.push_back(newPassData);
        }

        mRoughMerkleHeight = mLowestPassHeight;

        // Addresses
        unsigned int addressCount = pStream->readUnsignedInt();
        mAddressHashes.reserve(addressCount);
        NextCash::Hash pubKeyHash(PUB_KEY_HASH_SIZE);
        for(unsigned int i=0;i<addressCount;++i)
        {
            if(!pubKeyHash.read(pStream, PUB_KEY_HASH_SIZE))
            {
                mMutex.unlock();
                clear();
                return false;
            }
            mAddressHashes.push_back(pubKeyHash);
        }

        // Transactions
        unsigned int transactionCount = pStream->readUnsignedInt();
        SPVTransactionData *newSPVTransaction;
        for(unsigned int i=0;i<transactionCount;++i)
        {
            newSPVTransaction = new SPVTransactionData();
            if(!newSPVTransaction->read(pStream, version))
            {
                delete newSPVTransaction;
                mMutex.unlock();
                clear();
                return false;
            }
            mTransactions.insert(newSPVTransaction->transaction->hash, newSPVTransaction);
        }

        // Update transactions
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
            refreshTransaction(*trans, true);

        refreshBloomFilter(true);

        mLoaded = true;
        mMutex.unlock();
        return true;
    }

    void Monitor::SPVTransactionData::write(NextCash::OutputStream *pStream)
    {
        // Block height
        pStream->writeUnsignedInt(blockHeight);

        // Block hash
        blockHash.write(pStream);

        // Transaction
        transaction->write(pStream);

        // Amount
        pStream->writeLong(amount);

        // Payments
        pStream->writeUnsignedInt(payOutputs.size());
        for(std::vector<unsigned int>::iterator payment =
          payOutputs.begin(); payment != payOutputs.end(); ++payment)
            pStream->writeUnsignedInt(*payment);

        // Spends
        pStream->writeUnsignedInt(spendInputs.size());
        for(std::vector<unsigned int>::iterator spend =
          spendInputs.begin(); spend != spendInputs.end(); ++spend)
            pStream->writeUnsignedInt(*spend);
    }

    bool Monitor::SPVTransactionData::read(NextCash::InputStream *pStream, unsigned int pVersion)
    {
        if(pVersion > 1)
            blockHeight = pStream->readUnsignedInt();
        else
            blockHeight = 0xffffffff;

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

    Monitor::PassData::PassData(unsigned int pBlockHeight)
    {
        beginBlockHeight = pBlockHeight;
        blockHeight = pBlockHeight;
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

    bool Monitor::getOutput(NextCash::Hash &pTransactionHash, unsigned int pIndex,
      bool pAllowPending, Output &pOutput)
    {
        NextCash::HashContainerList<SPVTransactionData *>::Iterator confirmedTransaction =
          mTransactions.get(pTransactionHash);
        if(confirmedTransaction != mTransactions.end() &&
          (*confirmedTransaction)->transaction != NULL &&
          (*confirmedTransaction)->transaction->outputs.size() > pIndex)
        {
            pOutput = (*confirmedTransaction)->transaction->outputs[pIndex];
            return true;
        }

        if(!pAllowPending)
            return false;

        NextCash::HashContainerList<SPVTransactionData *>::Iterator pendingTransaction =
          mPendingTransactions.get(pTransactionHash);
        if(pendingTransaction != mPendingTransactions.end() &&
          (*pendingTransaction)->transaction != NULL &&
          (*pendingTransaction)->transaction->outputs.size() > pIndex)
        {
            pOutput = (*pendingTransaction)->transaction->outputs[pIndex];
            return true;
        }

        return false;
    }

    bool Monitor::getPayAddresses(Output &pOutput, NextCash::HashList &pAddresses,
      bool pRelatedOnly)
    {
        pAddresses.clear();

        // Parse the output for addresses
        ScriptInterpreter::ScriptType scriptType =
          ScriptInterpreter::parseOutputScript(pOutput.script, pAddresses);
        if(scriptType != ScriptInterpreter::P2PKH)
        {
            pAddresses.clear();
            return false;
        }

        if(pRelatedOnly) // Check the output addresses against related addresses
            for(NextCash::HashList::iterator hash = pAddresses.begin(); hash != pAddresses.end();)
            {
                if(mAddressHashes.contains(*hash))
                    ++hash;
                else
                    hash = pAddresses.erase(hash); // Erase addresses not in block
            }

        return pAddresses.size() > 0;
    }

    bool Monitor::refreshTransaction(Monitor::SPVTransactionData *pTransaction, bool pAllowPending)
    {
        pTransaction->amount = 0;
        pTransaction->payOutputs.clear();
        pTransaction->spendInputs.clear();

        if(pTransaction->transaction == NULL)
            return false;

        // Check for spends
        Output spentOutput;
        NextCash::HashList payAddresses;
        unsigned int index = 0;
        for(std::vector<Input>::iterator input = pTransaction->transaction->inputs.begin();
          input != pTransaction->transaction->inputs.end(); ++input, ++index)
        {
            // Find output being spent.
            // Check that output actually pays related address.
            if(getOutput(input->outpoint.transactionID, input->outpoint.index, pAllowPending,
              spentOutput) && getPayAddresses(spentOutput, payAddresses, true))
            {
                pTransaction->spendInputs.push_back(index);
                pTransaction->amount -= spentOutput.amount;
            }
        }

        // Check for payments
        index = 0;
        bool newUTXO = false, newAddress = false, newAddressesCreated = false;
        for(std::vector<Output>::iterator output = pTransaction->transaction->outputs.begin();
          output != pTransaction->transaction->outputs.end(); ++output, ++index)
            if(getPayAddresses(*output, payAddresses, true))
            {
                if(mKeyStore != NULL)
                {
                    for(NextCash::HashList::iterator hash = payAddresses.begin();
                      hash != payAddresses.end(); ++hash)
                    {
                        mKeyStore->markUsed(*hash, 20, newAddressesCreated);
                        if(newAddressesCreated)
                            newAddress = true;
                    }
                }

                pTransaction->payOutputs.push_back(index);
                pTransaction->amount += output->amount;

                // Check if this is a new output that needs to be monitored.
                if(mPendingTransactions.get(pTransaction->transaction->hash) ==
                  mPendingTransactions.end() &&
                  mTransactions.get(pTransaction->transaction->hash) == mTransactions.end())
                    newUTXO = true;
            }

        // Refresh addresses from key store and update bloom filter if necessary
        if((newAddress && refreshKeyStore()) || newUTXO)
        {
            mBloomFilterNeedsRestart = true;
            return true;
        }
        else
            return false;
    }

    void Monitor::clear()
    {
        mMutex.lock();

        mPasses.clear();
        mAddressHashes.clear();
        mFilter.clear();
        mNodesToResendFilter.clear();
        mNodesToClose.clear();

        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
            delete *trans;
        mTransactions.clear();

        for(NextCash::HashContainerList<MerkleRequestData *>::Iterator request =
          mMerkleRequests.begin(); request != mMerkleRequests.end(); ++request)
            delete *request;
        mMerkleRequests.clear();

        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator transData =
          mPendingTransactions.begin(); transData != mPendingTransactions.end(); ++transData)
            delete *transData;
        mPendingTransactions.clear();

        mMutex.unlock();
    }

    void Monitor::updatePasses(Chain *pChain)
    {
        if(!pChain->isInSync())
            return;

        mMutex.lock();

        if(mKeyStore == NULL || mKeyStore->allPassesStarted())
        {
            mMutex.unlock();
            return;
        }

        // Find oldest create date which does not have a pass started.
        Time oldestCreateDate = 0, thisCreateDate;
        for(unsigned int i = 0; i < mKeyStore->size(); ++i)
            if(!mKeyStore->passStarted(i))
            {
                thisCreateDate = mKeyStore->createdDate(i);
                if(oldestCreateDate == 0 || thisCreateDate < oldestCreateDate)
                    oldestCreateDate = thisCreateDate;
            }

        if(oldestCreateDate != 0)
        {
            unsigned int height = pChain->heightBefore(oldestCreateDate);
            // Backup a little more to be safe.
            if(height > 100)
                height -= 100;
            else
                height = 0;
            startPass(height);
        }

        mKeyStore->setAllPassStarted();
        mMutex.unlock();
    }

    void Monitor::startPass(unsigned int pBlockHeight)
    {
        // Check for existing passes that are close to this block height
        unsigned int passIndex = 0;
        unsigned int blockHeight = pBlockHeight;
        bool add = true;
        for(std::vector<PassData>::iterator pass = mPasses.begin(); pass != mPasses.end();
          ++pass, ++passIndex)
            if(!pass->complete)
            {
                if(pass->blockHeight > blockHeight && pass->blockHeight - blockHeight < 10000)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                      "Pass %d marked complete at height %d to start new pass at height %d",
                      passIndex, pass->blockHeight, blockHeight);
                    pass->complete = true;
                    refreshLowestPassHeight();
                }
                else if(pass->blockHeight < blockHeight && blockHeight - pass->blockHeight < 10000)
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                      "Existing pass %d (at height %d) is before and close enough to use for height %d",
                      passIndex, pass->blockHeight, blockHeight);
                    add = false;
                }
            }

        if(add)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
              "Starting new pass %d for new addresses at height %d", mPasses.size() + 1,
              blockHeight);
            mPasses.emplace_back(blockHeight);
            mPasses.back().addressesIncluded = mAddressHashes.size();
            if(!mLowestPassHeightSet || blockHeight < mLowestPassHeight)
            {
                mLowestPassHeightSet = true;
                mLowestPassHeight = blockHeight;
                if(mRoughMerkleHeight < mLowestPassHeight)
                    mRoughMerkleHeight = mLowestPassHeight;
            }
        }

        ++mChangeID;
    }

    void Monitor::restartBloomFilter()
    {
        for(NextCash::HashContainerList<MerkleRequestData *>::Iterator request =
          mMerkleRequests.begin(); request != mMerkleRequests.end(); ++request)
            clearMerkleRequest(*request);

        refreshBloomFilter(true);
        mBloomFilterNeedsRestart = false;
    }

    bool Monitor::loadAddresses(NextCash::InputStream *pStream)
    {
        mMutex.lock();

        unsigned int addedCount = 0;
        NextCash::String line;
        unsigned char nextChar;
        PaymentRequest request;

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

            if(line.length())
            {
                request = decodePaymentCode(line);
                if(request.format != PaymentRequest::Format::INVALID &&
                  request.network == MAINNET && request.pubKeyHash.size() == PUB_KEY_HASH_SIZE)
                {
                    // Check if it is already in this block
                    if(!mAddressHashes.contains(request.pubKeyHash))
                    {
                        mAddressHashes.push_back(request.pubKeyHash);
                        ++addedCount;
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                          "Adding address hash : %s", line.text());
                    }
                }
            }
        }

        if(addedCount)
        {
            startPass();
            mBloomFilterNeedsRestart = true;
        }

        mMutex.unlock();
        return true;
    }

    void Monitor::setKeyStore(KeyStore *pKeyStore)
    {
        mMutex.lock();
        mKeyStore = pKeyStore;
        refreshKeyStore();
        mMutex.unlock();
    }

    void Monitor::resetKeyStore()
    {
        mMutex.lock();

        mAddressHashes.clear();
        refreshKeyStore();

        // Update all transactions and remove any that are no longer relevant
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end();)
        {
            if(mAddressHashes.size() == 0)
            {
                delete *trans;
                trans = mTransactions.erase(trans);
            }
            else
            {
                refreshTransaction(*trans, false);
                if((*trans)->payOutputs.size() == 0 && (*trans)->spendInputs.size() == 0)
                {
                    delete *trans;
                    trans = mTransactions.erase(trans);
                }
                else
                    ++trans;
            }
        }

        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mPendingTransactions.begin(); trans != mPendingTransactions.end();)
        {
            if(mAddressHashes.size() == 0)
            {
                delete *trans;
                trans = mPendingTransactions.erase(trans);
            }
            else
            {
                refreshTransaction(*trans, false);
                if((*trans)->payOutputs.size() == 0 && (*trans)->spendInputs.size() == 0)
                    trans = mPendingTransactions.erase(trans);
                else
                    ++trans;
            }
        }

        if(mAddressHashes.size() == 0)
            mPasses.clear();

        mBloomFilterNeedsRestart = true;
        mMutex.unlock();
    }

    unsigned int Monitor::refreshKeyStore()
    {
        unsigned int addedCount = 0;
        std::vector<Key *> children;
        std::vector<Key *> *chainKeys;

        for(unsigned int i = 0; i < mKeyStore->size(); ++i)
        {
            chainKeys = mKeyStore->chainKeys(i);

            if(chainKeys == NULL)
                continue;

            for(std::vector<Key *>::iterator chainKey = chainKeys->begin();
              chainKey != chainKeys->end(); ++chainKey)
            {
                if((*chainKey)->depth() == Key::NO_DEPTH)
                {
                    if(!mAddressHashes.contains((*chainKey)->hash()))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                          "Added new address from key store hash : %s",
                          (*chainKey)->address().text());
                        mAddressHashes.push_back((*chainKey)->hash());
                        ++addedCount;
                    }
                }
                else
                {
                    (*chainKey)->getChildren(children);
                    for(std::vector<Key *>::iterator child = children.begin();
                      child != children.end(); ++child)
                        if(!mAddressHashes.contains((*child)->hash()))
                        {
                            NextCash::Log::addFormatted(NextCash::Log::INFO,
                              BITCOIN_MONITOR_LOG_NAME,
                              "Added new address from key store chain : %s",
                              (*child)->address().text());
                            mAddressHashes.push_back((*child)->hash());
                            ++addedCount;
                        }
                }
            }
        }

        if(addedCount > 0)
            mBloomFilterNeedsRestart = true;

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
          "Added %d new addresses from key store", addedCount);
        return addedCount;
    }

    void Monitor::refreshBloomFilter(bool pLocked)
    {
        std::vector<Outpoint> outpoints;

        if(!pLocked)
            mMutex.lock();

        // Add pending outpoints to monitor for being spent.
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mPendingTransactions.begin(); trans != mPendingTransactions.end(); ++trans)
            for(std::vector<unsigned int>::iterator index = (*trans)->payOutputs.begin();
              index != (*trans)->payOutputs.end(); ++index)
                if((*trans)->transaction != NULL)
                    outpoints.emplace_back((*trans)->transaction->hash, *index);

        // Add confirmed outpoints to monitor for being spent.
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
            for(std::vector<unsigned int>::iterator index = (*trans)->payOutputs.begin();
              index != (*trans)->payOutputs.end(); ++index)
                outpoints.emplace_back((*trans)->transaction->hash, *index);

        // Remove confirmed spent outpoints.
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
            for(std::vector<unsigned int>::iterator index = (*trans)->spendInputs.begin();
              index != (*trans)->spendInputs.end(); ++index)
                for(std::vector<Outpoint>::iterator outpoint = outpoints.begin();
                  outpoint != outpoints.end(); ++outpoint)
                    if(*outpoint == (*trans)->transaction->inputs[*index].outpoint)
                    {
                        outpoints.erase(outpoint);
                        break;
                    }

        mFilter.setup((unsigned int)(mAddressHashes.size() + outpoints.size()),
          BloomFilter::UPDATE_NONE, 0.00001);

        // Add Address hashes to monitor for "pay to" transactions
        for(NextCash::HashList::iterator hash = mAddressHashes.begin();
          hash != mAddressHashes.end(); ++hash)
            mFilter.add(*hash);

        // Add outpoints of UTXOs to monitor for "spend from" transactions
        for(std::vector<Outpoint>::iterator outpoint = outpoints.begin();
          outpoint != outpoints.end(); ++outpoint)
            mFilter.add(*outpoint);

        ++mFilterID;
        mNodesToResendFilter.clear();
        if(!pLocked)
            mMutex.unlock();
    }

    void Monitor::refreshLowestPassHeight()
    {
        unsigned int result = 0;
        bool resultEmpty = true;

        for(std::vector<PassData>::iterator pass = mPasses.begin(); pass != mPasses.end(); ++pass)
            if(!pass->complete && (resultEmpty || pass->blockHeight < result))
            {
                resultEmpty = false;
                result = pass->blockHeight;
            }

        mLowestPassHeight = result;
        mLowestPassHeightSet = !resultEmpty;
        if(mRoughMerkleHeight < mLowestPassHeight)
            mRoughMerkleHeight = mLowestPassHeight;
    }

    unsigned int Monitor::highestPassHeight(bool pLocked)
    {
        unsigned int result = 0;

        if(!pLocked)
            mMutex.lock();
        for(std::vector<PassData>::iterator pass = mPasses.begin(); pass != mPasses.end(); ++pass)
            if(!pass->complete && pass->blockHeight > result)
                result = pass->blockHeight;
        if(!pLocked)
            mMutex.unlock();

        return result;
    }

    int64_t Monitor::balance(bool pLocked)
    {
        if(!pLocked)
            mMutex.lock();
        int64_t result = 0;
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
            result += (*trans)->amount;
        if(!pLocked)
            mMutex.unlock();
        return result;
    }

    int64_t Monitor::balance(std::vector<Key *>::iterator pChainKeyBegin,
      std::vector<Key *>::iterator pChainKeyEnd, bool pIncludePending)
    {
        int64_t result = 0;
        NextCash::HashList payAddresses;
        Output output;

        mMutex.lock();

        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
        {
            // Subtract "spends" in inputs.
            for(std::vector<unsigned int>::iterator index = (*trans)->spendInputs.begin();
              index != (*trans)->spendInputs.end(); ++index)
                if(getOutput((*trans)->transaction->inputs[*index].outpoint.transactionID,
                  (*trans)->transaction->inputs[*index].outpoint.index, pIncludePending, output) &&
                  getPayAddresses(output, payAddresses, true))
                {
                    for(NextCash::HashList::iterator hash = payAddresses.begin();
                      hash != payAddresses.end(); ++hash)
                        for(std::vector<Key *>::iterator key = pChainKeyBegin;
                          key != pChainKeyEnd; ++key)
                            if((*key)->findAddress(*hash) != NULL)
                            {
                                result -= output.amount;
                                break;
                            }
                }

            // Add "pays" in outputs.
            for(std::vector<unsigned int>::iterator index = (*trans)->payOutputs.begin();
              index != (*trans)->payOutputs.end(); ++index)
                if(getPayAddresses((*trans)->transaction->outputs[*index], payAddresses, true))
                {
                    for(NextCash::HashList::iterator hash = payAddresses.begin();
                      hash != payAddresses.end(); ++hash)
                        for(std::vector<Key *>::iterator key = pChainKeyBegin;
                          key != pChainKeyEnd; ++key)
                            if((*key)->findAddress(*hash) != NULL)
                            {
                                result += (*trans)->transaction->outputs[*index].amount;
                                break;
                            }
                }
        }

        if(pIncludePending)
        {
            for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
              mPendingTransactions.begin(); trans != mPendingTransactions.end(); ++trans)
            {
                // Subtract "spends" in inputs.
                for(std::vector<unsigned int>::iterator index = (*trans)->spendInputs.begin();
                  index != (*trans)->spendInputs.end(); ++index)
                    if(getOutput((*trans)->transaction->inputs[*index].outpoint.transactionID,
                      (*trans)->transaction->inputs[*index].outpoint.index, pIncludePending,
                      output) && getPayAddresses(output, payAddresses, true))
                    {
                        for(NextCash::HashList::iterator hash = payAddresses.begin();
                          hash != payAddresses.end(); ++hash)
                            for(std::vector<Key *>::iterator key = pChainKeyBegin;
                              key != pChainKeyEnd; ++key)
                                if((*key)->findAddress(*hash) != NULL)
                                {
                                    result -= output.amount;
                                    break;
                                }
                    }

                // Add "pays" in outputs.
                for(std::vector<unsigned int>::iterator index = (*trans)->payOutputs.begin();
                  index != (*trans)->payOutputs.end(); ++index)
                    if(getPayAddresses((*trans)->transaction->outputs[*index], payAddresses, true))
                    {
                        for(NextCash::HashList::iterator hash = payAddresses.begin();
                          hash != payAddresses.end(); ++hash)
                            for(std::vector<Key *>::iterator key = pChainKeyBegin;
                              key != pChainKeyEnd; ++key)
                                if((*key)->findAddress(*hash) != NULL)
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

    bool containsAddress(const NextCash::Hash &pHash, std::vector<Key *>::iterator pChainKeyBegin,
      std::vector<Key *>::iterator pChainKeyEnd)
    {
        for(std::vector<Key *>::iterator key = pChainKeyBegin; key != pChainKeyEnd; ++ key)
            if((*key)->findAddress(pHash))
                return true;
        return false;
    }

    bool outpointOlder(BitCoin::Outpoint &pLeft, BitCoin::Outpoint &pRight)
    {
        return pLeft.confirmations > pRight.confirmations;
    }

    bool Monitor::getUnspentOutputs(std::vector<Key *>::iterator pChainKeyBegin,
      std::vector<Key *>::iterator pChainKeyEnd, std::vector<Outpoint> &pOutputs, Chain *pChain,
      bool pIncludePending)
    {
        NextCash::HashList payAddresses;

        pOutputs.clear();

        mMutex.lock();

        // Get outputs
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
        {
            for(std::vector<unsigned int>::iterator index = (*trans)->payOutputs.begin();
              index != (*trans)->payOutputs.end(); ++index)
                if(getPayAddresses((*trans)->transaction->outputs[*index], payAddresses, true))
                {
                    for(NextCash::HashList::iterator hash = payAddresses.begin();
                      hash != payAddresses.end(); ++hash)
                        if(containsAddress(*hash, pChainKeyBegin, pChainKeyEnd))
                        {
                            pOutputs.emplace_back((*trans)->transaction->hash, *index);
                            pOutputs.back().output =
                              new Output((*trans)->transaction->outputs[*index]);
                            pOutputs.back().confirmations = pChain->headerHeight() -
                              pChain->hashHeight((*trans)->blockHash) + 1;
                            break;
                        }
                }
        }

        // Remove spent
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
        {
            for(std::vector<unsigned int>::iterator index = (*trans)->spendInputs.begin();
              index != (*trans)->spendInputs.end(); ++index)
                for(std::vector<Outpoint>::iterator output = pOutputs.begin();
                  output != pOutputs.end(); ++output)
                    if(*output == (*trans)->transaction->inputs[*index].outpoint)
                    {
                        pOutputs.erase(output);
                        break;
                    }
        }

        if(pIncludePending)
        {
            // Get pending outputs
            for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
              mPendingTransactions.begin(); trans != mPendingTransactions.end(); ++trans)
            {
                for(std::vector<unsigned int>::iterator index = (*trans)->payOutputs.begin();
                  index != (*trans)->payOutputs.end(); ++index)
                    if(getPayAddresses((*trans)->transaction->outputs[*index], payAddresses, true))
                    {
                        for(NextCash::HashList::iterator hash = payAddresses.begin();
                          hash != payAddresses.end(); ++hash)
                            if(containsAddress(*hash, pChainKeyBegin, pChainKeyEnd))
                            {
                                pOutputs.emplace_back((*trans)->transaction->hash, *index);
                                pOutputs.back().output =
                                  new Output((*trans)->transaction->outputs[*index]);
                                pOutputs.back().confirmations = 0;
                                break;
                            }
                    }
            }
        }

        // Remove spent
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mPendingTransactions.begin(); trans != mPendingTransactions.end(); ++trans)
        {
            for(std::vector<unsigned int>::iterator index = (*trans)->spendInputs.begin();
              index != (*trans)->spendInputs.end(); ++index)
                for(std::vector<Outpoint>::iterator output = pOutputs.begin();
                  output != pOutputs.end(); ++output)
                    if(*output == (*trans)->transaction->inputs[*index].outpoint)
                    {
                        pOutputs.erase(output);
                        break;
                    }
        }

        mMutex.unlock();

        std::sort(pOutputs.begin(), pOutputs.end(), outpointOlder);

        return true;
    }

    bool Monitor::outputIsRelated(Output &pOutput, std::vector<Key *>::iterator pChainKeyBegin,
      std::vector<Key *>::iterator pChainKeyEnd)
    {
        // Parse the output for addresses
        NextCash::HashList payAddresses;
        ScriptInterpreter::ScriptType scriptType =
          ScriptInterpreter::parseOutputScript(pOutput.script, payAddresses);
        if(scriptType != ScriptInterpreter::P2PKH)
            return false;

        for(NextCash::HashList::iterator hash=payAddresses.begin();hash!=payAddresses.end();++hash)
            for(std::vector<Key *>::iterator chainKey = pChainKeyBegin; chainKey != pChainKeyEnd;
              ++chainKey)
                if((*chainKey)->findAddress(*hash) != NULL)
                    return true;

        return false;
    }

    bool Monitor::updateRelatedTransactionData(RelatedTransactionData &pData,
      std::vector<Key *>::iterator pChainKeyBegin, std::vector<Key *>::iterator pChainKeyEnd)
    {
        if(pData.transaction.hash.isEmpty())
            return false;

        Output spentOutput;
        NextCash::HashList payAddresses;
        ScriptInterpreter::ScriptType scriptType;
        unsigned int offset = 0;
        pData.relatedInputAmounts.resize(pData.transaction.inputs.size());
        pData.inputAddresses.resize(pData.transaction.inputs.size());
        for(std::vector<Input>::iterator input = pData.transaction.inputs.begin();
          input != pData.transaction.inputs.end(); ++input, ++offset)
        {
            pData.relatedInputAmounts[offset] = -1;
            pData.inputAddresses[offset].clear();

            // Find output being spent
            // Check that output actually pays related address
            if(getOutput(input->outpoint.transactionID, input->outpoint.index, true, spentOutput) &&
              outputIsRelated(spentOutput, pChainKeyBegin, pChainKeyEnd))
            {
                pData.relatedInputAmounts[offset] = spentOutput.amount;
                scriptType = ScriptInterpreter::parseOutputScript(spentOutput.script,
                  payAddresses);
                if(scriptType == ScriptInterpreter::P2PKH)
                    pData.inputAddresses[offset] = encodeCashAddress(payAddresses.front(),
                      MAIN_PUB_KEY_HASH);
                else if(scriptType == ScriptInterpreter::P2SH)
                    pData.inputAddresses[offset] = encodeCashAddress(payAddresses.front(),
                      MAIN_SCRIPT_HASH);
            }
        }

        offset = 0;
        pData.relatedOutputs.resize(pData.transaction.outputs.size());
        pData.outputAddresses.resize(pData.transaction.outputs.size());
        for(std::vector<Output>::iterator output = pData.transaction.outputs.begin();
          output != pData.transaction.outputs.end(); ++output, ++offset)
        {
            pData.relatedOutputs[offset] = outputIsRelated(*output, pChainKeyBegin, pChainKeyEnd);
            scriptType = ScriptInterpreter::parseOutputScript(output->script, payAddresses);
            if(scriptType == ScriptInterpreter::P2PKH)
                pData.outputAddresses[offset] = encodeCashAddress(payAddresses.front(),
                  MAIN_PUB_KEY_HASH);
            else if(scriptType == ScriptInterpreter::P2SH)
                pData.outputAddresses[offset] = encodeCashAddress(payAddresses.front(),
                  MAIN_SCRIPT_HASH);
        }

        return true;
    }

    int64_t Monitor::RelatedTransactionData::amount() const
    {
        int64_t result = 0;
        for(std::vector<int64_t>::const_iterator input = relatedInputAmounts.begin();
          input != relatedInputAmounts.end(); ++input)
            if(*input != -1)
                result -= *input;

        unsigned int offset = 0;
        for(std::vector<bool>::const_iterator output = relatedOutputs.begin();
          output != relatedOutputs.end(); ++output, ++offset)
            if(*output)
                result += transaction.outputs[offset].amount;

        return result;
    }

    bool Monitor::getTransaction(NextCash::Hash pID, std::vector<Key *>::iterator pChainKeyBegin,
      std::vector<Key *>::iterator pChainKeyEnd, RelatedTransactionData &pTransaction)
    {
        mMutex.lock();

        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
            if((*trans)->transaction->hash == pID)
            {
                pTransaction.transaction = *(*trans)->transaction;
                pTransaction.blockHash = (*trans)->blockHash;
                pTransaction.blockHeight = (*trans)->blockHeight;
                pTransaction.nodesVerified = 0xffffffff;
                updateRelatedTransactionData(pTransaction, pChainKeyBegin, pChainKeyEnd);
                mMutex.unlock();
                return true;
            }

        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mPendingTransactions.begin(); trans != mPendingTransactions.end(); ++trans)
            if((*trans)->transaction->hash == pID)
            {
                pTransaction.transaction = *(*trans)->transaction;
                pTransaction.blockHash = (*trans)->blockHash;
                pTransaction.blockHeight = (*trans)->blockHeight;
                pTransaction.nodesVerified = (unsigned int)(*trans)->nodes.size();
                updateRelatedTransactionData(pTransaction, pChainKeyBegin, pChainKeyEnd);
                mMutex.unlock();
                return true;
            }

        mMutex.unlock();
        return false;
    }

    bool Monitor::getTransactions(std::vector<Key *>::iterator pChainKeyBegin,
      std::vector<Key *>::iterator pChainKeyEnd, std::vector<RelatedTransactionData> &pTransactions,
      bool pIncludePending)
    {
        pTransactions.clear();

        NextCash::HashList payAddresses;
        Output output;
        bool added;
        RelatedTransactionData *newTransaction;

        mMutex.lock();

        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end(); ++trans)
        {
            added = false;

            for(std::vector<unsigned int>::iterator index = (*trans)->spendInputs.begin();
              index != (*trans)->spendInputs.end() && !added; ++index)
            {
                if(getOutput((*trans)->transaction->inputs[*index].outpoint.transactionID,
                  (*trans)->transaction->inputs[*index].outpoint.index, false, output) &&
                  getPayAddresses(output, payAddresses, true))
                {
                    for(NextCash::HashList::iterator hash = payAddresses.begin();
                      hash != payAddresses.end(); ++hash)
                        for(std::vector<Key *>::iterator key = pChainKeyBegin;
                          key != pChainKeyEnd; ++key)
                            if((*key)->findAddress(*hash) != NULL)
                            {
                                pTransactions.emplace_back();
                                newTransaction = &pTransactions.back();
                                newTransaction->transaction = *(*trans)->transaction;
                                newTransaction->blockHash = (*trans)->blockHash;
                                newTransaction->blockHeight = (*trans)->blockHeight;
                                newTransaction->nodesVerified = 0xffffffff;
                                updateRelatedTransactionData(*newTransaction, pChainKeyBegin,
                                  pChainKeyEnd);
                                added = true;
                                break;
                            }
                }
            }

            for(std::vector<unsigned int>::iterator index =
              (*trans)->payOutputs.begin(); index != (*trans)->payOutputs.end() && !added; ++index)
            {
                if(getPayAddresses((*trans)->transaction->outputs[*index], payAddresses, true))
                {
                    for(NextCash::HashList::iterator hash = payAddresses.begin();
                      hash != payAddresses.end(); ++hash)
                        for(std::vector<Key *>::iterator key = pChainKeyBegin;
                          key != pChainKeyEnd; ++key)
                            if((*key)->findAddress(*hash) != NULL)
                            {
                                pTransactions.emplace_back();
                                newTransaction = &pTransactions.back();
                                newTransaction->transaction = *(*trans)->transaction;
                                newTransaction->blockHash = (*trans)->blockHash;
                                newTransaction->blockHeight = (*trans)->blockHeight;
                                newTransaction->nodesVerified = 0xffffffff;
                                updateRelatedTransactionData(*newTransaction, pChainKeyBegin,
                                  pChainKeyEnd);
                                added = true;
                                break;
                            }
                }
            }
        }

        if(pIncludePending)
        {
            for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
              mPendingTransactions.begin(); trans != mPendingTransactions.end(); ++trans)
            {
                added = false;

                for(std::vector<unsigned int>::iterator index = (*trans)->spendInputs.begin();
                  index != (*trans)->spendInputs.end() && !added; ++index)
                {
                    if(getOutput((*trans)->transaction->inputs[*index].outpoint.transactionID,
                      (*trans)->transaction->inputs[*index].outpoint.index, false, output) &&
                      getPayAddresses(output, payAddresses, true))
                    {
                        for(NextCash::HashList::iterator hash = payAddresses.begin();
                          hash != payAddresses.end(); ++hash)
                            for(std::vector<Key *>::iterator key = pChainKeyBegin;
                              key != pChainKeyEnd; ++key)
                                if((*key)->findAddress(*hash) != NULL)
                                {
                                    pTransactions.emplace_back();
                                    newTransaction = &pTransactions.back();
                                    newTransaction->transaction = *(*trans)->transaction;
                                    newTransaction->blockHash = (*trans)->blockHash;
                                    newTransaction->blockHeight = (*trans)->blockHeight;
                                    newTransaction->nodesVerified = (int)(*trans)->nodes.size();
                                    updateRelatedTransactionData(*newTransaction, pChainKeyBegin,
                                      pChainKeyEnd);
                                    added = true;
                                    break;
                                }
                    }
                }

                for(std::vector<unsigned int>::iterator index = (*trans)->payOutputs.begin();
                  index != (*trans)->payOutputs.end() && !added; ++index)
                {
                    if(getPayAddresses((*trans)->transaction->outputs[*index], payAddresses, true))
                    {
                        for(NextCash::HashList::iterator hash = payAddresses.begin();
                          hash != payAddresses.end(); ++hash)
                            for(std::vector<Key *>::iterator key = pChainKeyBegin;
                              key != pChainKeyEnd; ++key)
                                if((*key)->findAddress(*hash) != NULL)
                                {
                                    pTransactions.emplace_back();
                                    newTransaction = &pTransactions.back();
                                    newTransaction->transaction = *(*trans)->transaction;
                                    newTransaction->blockHash = (*trans)->blockHash;
                                    newTransaction->blockHeight = (*trans)->blockHeight;
                                    newTransaction->nodesVerified = (int)(*trans)->nodes.size();
                                    updateRelatedTransactionData(*newTransaction, pChainKeyBegin,
                                      pChainKeyEnd);
                                    added = true;
                                    break;
                                }
                    }
                }
            }
        }

        mMutex.unlock();

        return true;
    }

    bool Monitor::filterNeedsResend(unsigned int pNodeID, unsigned int pBloomID)
    {
        mMutex.lock();

        if(pBloomID != mFilterID)
        {
            mMutex.unlock();
            return true;
        }

        for(std::vector<unsigned int>::iterator node = mNodesToResendFilter.begin();
          node != mNodesToResendFilter.end(); ++node)
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
        for(std::vector<unsigned int>::iterator node = mNodesToClose.begin();
          node != mNodesToClose.end(); ++node)
            if(*node == pNodeID)
            {
                mNodesToClose.erase(node);
                mMutex.unlock();
                return true;
            }
        mMutex.unlock();
        return false;
    }

    bool Monitor::addNeedsClose(unsigned int pNodeID)
    {
        for(std::vector<unsigned int>::iterator node = mNodesToClose.begin();
          node != mNodesToClose.end(); ++node)
            if(*node == pNodeID)
                return false;
        mNodesToClose.push_back(pNodeID);
        return true;
    }

    void Monitor::release(unsigned int pNodeID)
    {
        mMutex.lock();

        for(NextCash::HashContainerList<MerkleRequestData *>::Iterator request =
          mMerkleRequests.begin(); request != mMerkleRequests.end(); ++request)
            (*request)->release(pNodeID);

        for(std::vector<unsigned int>::iterator node = mNodesToResendFilter.begin();
          node != mNodesToResendFilter.end(); ++node)
            if(*node == pNodeID)
            {
                mNodesToResendFilter.erase(node);
                break;
            }

        for(std::vector<unsigned int>::iterator node = mNodesToClose.begin();
          node != mNodesToClose.end(); ++node)
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

    void Monitor::getNeededMerkleBlocks(unsigned int pNodeID, Chain &pChain,
      NextCash::HashList &pBlockHashes, unsigned int pMaxCount)
    {
        if(mFilter.isEmpty())
            return;

        NextCash::Hash nextBlockHash;
        NextCash::HashContainerList<MerkleRequestData *>::Iterator request;
        MerkleRequestData *newMerkleRequest;
        unsigned int blockHeight;
        Time time = getTime();
        uint8_t requiredNodeCount = Info::instance().merkleBlockCountRequired;
        bool found;

        pBlockHashes.clear();

        mMutex.lock();

        for(std::vector<PassData>::reverse_iterator pass = mPasses.rbegin(); pass != mPasses.rend();
          ++pass)
        {
            if(pass->complete)
                continue;

            blockHeight = pass->blockHeight;
            while(pBlockHashes.size() < pMaxCount)
            {
                // Get next block hash
                if(!pChain.getHash(++blockHeight, nextBlockHash))
                    break;

                // Check if there is a merkle request for this block hash and if it needs more
                //   requests sent.
                found = false;
                request = mMerkleRequests.get(nextBlockHash);
                if(request != mMerkleRequests.end())
                {
                    if(!(*request)->isReverse)
                    {
                        found = true;
                        if((*request)->addNode(pNodeID, time))
                            pBlockHashes.push_back(nextBlockHash);
                    }
                    else
                    {
                        // Check next item
                        ++request;
                        if(request != mMerkleRequests.end() &&
                          request.hash() == nextBlockHash && !(*request)->isReverse)
                        {
                            found = true;
                            if((*request)->addNode(pNodeID, time))
                                pBlockHashes.push_back(nextBlockHash);
                        }
                    }
                }

                if(!found)
                {
                    if(mMerkleRequests.size() < MAX_MERKLE_REQUESTS)
                    {
                        // Add new merkle block request
                        newMerkleRequest = new MerkleRequestData(requiredNodeCount, pNodeID, time);
                        mMerkleRequests.insert(nextBlockHash, newMerkleRequest);
                        pBlockHashes.push_back(nextBlockHash);
                    }
                    else
                        break;
                }
            }
        }

        if(pBlockHashes.size() >= pMaxCount)
        {
            mMutex.unlock();
            return;
        }

        if(mReversePassHeight == 0xffffffff)
            mReversePassHeight = pChain.headerHeight();

        unsigned int lastReverseHeight = pChain.headerHeight();
        if(lastReverseHeight > 2016)
            lastReverseHeight -= 2016;
        else
            lastReverseHeight = 0;

        blockHeight = mReversePassHeight;
        while(pBlockHashes.size() < pMaxCount && blockHeight > lastReverseHeight)
        {
            // Get next block hash
            if(!pChain.getHash(blockHeight--, nextBlockHash))
                break;

            // Check if there is a merkle request for this block hash and if it needs more
            //   requests sent.
            found = false;
            request = mMerkleRequests.get(nextBlockHash);
            if(request != mMerkleRequests.end())
            {
                if((*request)->isReverse)
                {
                    found = true;
                    if((*request)->addNode(pNodeID, time))
                    {
                        pBlockHashes.push_back(nextBlockHash);
                        NextCash::Log::addFormatted(NextCash::Log::INFO,
                          BITCOIN_MONITOR_LOG_NAME,
                          "Requesting reverse merkle for height %d", blockHeight + 1);
                    }
                }
                else
                {
                    // Check next item
                    ++request;
                    if(request != mMerkleRequests.end() &&
                       request.hash() == nextBlockHash && (*request)->isReverse)
                    {
                        found = true;
                        if((*request)->addNode(pNodeID, time))
                        {
                            pBlockHashes.push_back(nextBlockHash);
                            NextCash::Log::addFormatted(NextCash::Log::INFO,
                              BITCOIN_MONITOR_LOG_NAME,
                              "Requesting reverse merkle for height %d", blockHeight + 1);
                        }
                    }
                }
            }

            if(!found)
            {
                if(mMerkleRequests.size() < MAX_MERKLE_REQUESTS)
                {
                    // Add new merkle block request
                    newMerkleRequest = new MerkleRequestData(1, pNodeID, time);
                    newMerkleRequest->isReverse = true;
                    mMerkleRequests.insert(nextBlockHash, newMerkleRequest);
                    pBlockHashes.push_back(nextBlockHash);

                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                      "Requesting reverse merkle for height %d", blockHeight + 1);
                }
                else
                    break;
            }
        }

        mMutex.unlock();
    }

    bool Monitor::addMerkleBlock(Chain &pChain, Message::MerkleBlockData *pData,
      unsigned int pNodeID)
    {
        mMutex.lock();

        NextCash::HashContainerList<MerkleRequestData *>::Iterator requestIter =
          mMerkleRequests.get(pData->header.hash);
        if(requestIter == mMerkleRequests.end())
        {
            mMutex.unlock();
            return false; // Not a requested block, so it probably isn't in the chain
        }

        // Check if it is already complete.
        // Check if node id matches. It must match to ensure this is based on the latest bloom
        //   filter.
        // For Bloom filter updates based on finding new UTXOs.
        if(!(*requestIter)->wasRequested(pNodeID))
        {
            // Check next item (for reverse mode)
            ++requestIter;
            if(requestIter == mMerkleRequests.end() || requestIter.hash() != pData->header.hash ||
               !(*requestIter)->wasRequested(pNodeID))
            {
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                  "Node [%d] sent unrequested merkle block.", pNodeID);
                mMutex.unlock();
                return false;
            }
        }

        MerkleRequestData *request = *requestIter;
        if(request->isComplete())
        {
            mMutex.unlock();
            return false;
        }

        mMutex.unlock();

        // Validate and retrieve transaction hashes matching bloom filter.
        // Do this outside of the lock to improve multi-threading.
        NextCash::HashList transactionHashes;
        if(!pData->validate(transactionHashes))
        {
            mMutex.lock();
            requestIter = mMerkleRequests.get(pData->header.hash);
            if(requestIter != mMerkleRequests.end())
                (*requestIter)->removeNode(pNodeID);
            if(addNeedsClose(pNodeID))
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                  "Node [%d] needs closed. Sent invalid merkle block.", pNodeID);
            mMutex.unlock();
            return false;
        }

        mMutex.lock();

        requestIter = mMerkleRequests.get(pData->header.hash);
        if(requestIter == mMerkleRequests.end())
        {
            mMutex.unlock();
            return false;
        }

        if(!(*requestIter)->wasRequested(pNodeID))
        {
            // Check next item (for reverse mode)
            ++requestIter;
            if(requestIter == mMerkleRequests.end() || requestIter.hash() != pData->header.hash ||
              !(*requestIter)->wasRequested(pNodeID))
            {
                mMutex.unlock();
                return false;
            }
        }

        request = *requestIter;
        if(!request->markReceived(pNodeID))
        {
            mMutex.unlock();
            return false;
        }

        // NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_MONITOR_LOG_NAME,
        // "Received merkle block from node [%d] with %d transaction hashes : %s", pNodeID,
        // transactionHashes.size(), pData->block->hash.hex().text());

        request->totalTransactions = pData->header.transactionCount;

        // Update transactions because if more than one merkle block are received from different
        //   nodes, then they might have different bloom filters and different false positive
        //   transactions.
        SPVTransactionData *newSPVTransaction;
        NextCash::HashContainerList<SPVTransactionData *>::Iterator transaction;
        NextCash::HashContainerList<SPVTransactionData *>::Iterator pendingTransaction;
        unsigned int blockHeight = pChain.hashHeight(pData->header.hash);
        for(NextCash::HashList::iterator hash = transactionHashes.begin();
          hash != transactionHashes.end(); ++hash)
        {
            transaction = request->transactions.get(*hash);
            if(transaction == request->transactions.end())
            {
                // Check if already confirmed
                if(isConfirmed(*hash, true))
                {
                    newSPVTransaction = NULL;
                    request->transactions.insert(*hash, newSPVTransaction);
                }
                else
                {
                    // Check if transaction is already in pending
                    pendingTransaction = mPendingTransactions.get(*hash);
                    if(pendingTransaction != mPendingTransactions.end())
                    {
                        NextCash::Log::addFormatted(NextCash::Log::VERBOSE,
                          BITCOIN_MONITOR_LOG_NAME,
                          "Transaction pulled from pending into merkle request : %s",
                          hash->hex().text());
                        newSPVTransaction = *pendingTransaction;
                        mPendingTransactions.erase(pendingTransaction);

                        newSPVTransaction->blockHash = pData->header.hash;
                        newSPVTransaction->blockHeight = blockHeight;

                        if(!confirmTransaction(newSPVTransaction))
                            delete newSPVTransaction;

                        // Put a null in the merkle request since we already had this transaction
                        //   and just processed it.
                        newSPVTransaction = NULL;
                        request->transactions.insert(*hash, newSPVTransaction);
                    }
                    else // Create empty transaction
                    {
                        newSPVTransaction = new SPVTransactionData(pData->header.hash,
                          pChain.hashHeight(pData->header.hash));
                        request->transactions.insert(*hash, newSPVTransaction);
                    }
                }
            }
        }

        if(mRoughMerkleHeight == blockHeight - 1)
        {
            mRoughMerkleHeight = blockHeight;
            ++mChangeID;
        }
        else if(mRoughMerkleHeight < blockHeight)
        {
            // Check if previous merkle blocks have been verified as they can happen out of order.
            NextCash::Hash blockHash(BLOCK_HASH_SIZE);
            for(unsigned int testHeight = mRoughMerkleHeight + 1; testHeight < blockHeight;
              ++testHeight)
            {
                if(!pChain.getHash(testHeight, blockHash))
                    break;
                requestIter = mMerkleRequests.get(blockHash);
                if(requestIter != mMerkleRequests.end() && (*requestIter)->hasReceived())
                {
                    mRoughMerkleHeight = testHeight;
                    ++mChangeID;
                }
                else
                    break;

            }
        }

        bool processNeeded = request->isComplete();

        // Note : Process function waits for transactions for the specified hashes, then removes
        //   the requests in chain order.
        if(processNeeded)
            process(pChain, true);

        mMutex.unlock();
        return true;
    }

    NextCash::Hash Monitor::confirmBlockHash(const NextCash::Hash &pTransactionID)
    {
        NextCash::Hash result;

        mMutex.lock();
        NextCash::HashContainerList<SPVTransactionData *>::Iterator transaction =
          mTransactions.get(pTransactionID);
        if(transaction != mTransactions.end())
            result = (*transaction)->blockHash;
        mMutex.unlock();

        return result;
    }

    void Monitor::addTransaction(Chain &pChain, Message::TransactionData *pTransactionData)
    {
        mMutex.lock();

        if(isConfirmed(pTransactionData->transaction->hash, true))
        {
            mMutex.unlock();
            return; // Already confirmed this transaction
        }

        if(Info::instance().spvMode)
        {
            // Check that it has been proven by a merkle block
            MerkleRequestData *request;
            bool processNeeded = false;
            NextCash::HashContainerList<SPVTransactionData *>::Iterator transactionIter;
            for(NextCash::HashContainerList<MerkleRequestData *>::Iterator requestIter =
              mMerkleRequests.begin(); requestIter != mMerkleRequests.end(); ++requestIter)
            {
                request = *requestIter;
                transactionIter = request->transactions.get(pTransactionData->transaction->hash);
                if(transactionIter != request->transactions.end())
                {
                    if(*transactionIter != NULL && (*transactionIter)->transaction == NULL)
                    {
                        (*transactionIter)->transaction = pTransactionData->transaction;
                        pTransactionData->transaction = NULL; // Prevent it from being deleted
                        if(!confirmTransaction(*transactionIter))
                            delete *transactionIter; // Unrelated transaction

                        *transactionIter = NULL;
                        processNeeded = request->isComplete();
                    }

                    if(processNeeded || mBloomFilterNeedsRestart)
                        process(pChain, true);

                    mMutex.unlock();
                    return;
                }
            }

            // Check pending transactions
            NextCash::HashContainerList<SPVTransactionData *>::Iterator pendingTransaction =
              mPendingTransactions.get(pTransactionData->transaction->hash);
            if(pendingTransaction != mPendingTransactions.end() &&
               (*pendingTransaction)->transaction == NULL)
            {
                (*pendingTransaction)->transaction = pTransactionData->transaction;
                pTransactionData->transaction = NULL; // Prevent it from being deleted
                refreshTransaction(*pendingTransaction, true);

                if((*pendingTransaction)->payOutputs.size() > 0 ||
                  (*pendingTransaction)->spendInputs.size() > 0)
                {
                    // Needed this transaction
                    NextCash::String subject, message;
                    if((*pendingTransaction)->amount > 0)
                    {
                        subject = "Bitcoin Cash Receive Pending";
                        message.writeFormatted(
                          "Receive pending for %0.8f bitcoins.\nTransaction : %s",
                          bitcoins((*pendingTransaction)->amount),
                          (*pendingTransaction)->transaction->hash.hex().text());
                        NextCash::Log::addFormatted(NextCash::Log::INFO,
                          BITCOIN_MONITOR_LOG_NAME,
                          "Pending transaction receiving %0.8f bitcoins : %s",
                          bitcoins((*pendingTransaction)->amount),
                          (*pendingTransaction)->transaction->hash.hex().text());
                    }
                    else
                    {
                        subject = "Bitcoin Cash Send Pending";
                        message.writeFormatted(
                          "Send pending for %0.8f bitcoins.\nTransaction : %s",
                          -bitcoins((*pendingTransaction)->amount),
                          (*pendingTransaction)->transaction->hash.hex().text());
                        NextCash::Log::addFormatted(NextCash::Log::INFO,
                          BITCOIN_MONITOR_LOG_NAME,
                          "Pending transaction sending %0.8f bitcoins : %s",
                          -bitcoins((*pendingTransaction)->amount),
                          (*pendingTransaction)->transaction->hash.hex().text());
                    }

                    notify(subject, message);
                    ++mChangeID;
                }
                else
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                      "Pending transaction (unrelated) : %s",
                      (*pendingTransaction)->transaction->hash.hex().text());
            }

            if(mBloomFilterNeedsRestart)
                process(pChain, true);

            mMutex.unlock();
        }
        else
        {
            // Check if it relates to any related addresses
            //TODO Put into Pending Transactions
            //TODO Add a function when a block is validated to move the function from pending to
            //   confirmed
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
        }
    }

    bool Monitor::addTransactionAnnouncement(const NextCash::Hash &pTransactionHash,
      unsigned int pNodeID)
    {
        bool result = false;
        mMutex.lock();

        if(Info::instance().spvMode)
        {
            NextCash::HashContainerList<SPVTransactionData *>::Iterator pendingTransaction =
              mPendingTransactions.get(pTransactionHash);
            if(pendingTransaction == mPendingTransactions.end())
            {
                // Add new pending transaction
                SPVTransactionData *newPendingTransaction = new SPVTransactionData();
                newPendingTransaction->addNode(pNodeID);
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                  "Pending transaction accepted on first node [%d] : %s", pNodeID,
                  pTransactionHash.hex().text());
                ++mChangeID;
                mPendingTransactions.insert(pTransactionHash, newPendingTransaction);
                result = true; // Need transaction
            }
            else
            {
                // Set true if still need transaction
                result = (*pendingTransaction)->transaction == NULL;

                // Add node as accepting node
                (*pendingTransaction)->addNode(pNodeID);
                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                  "Pending transaction accepted on %d nodes. [%d] : %s",
                  (*pendingTransaction)->nodes.size(), pNodeID, pTransactionHash.hex().text());
                ++mChangeID;
            }
        }
        else
        {
            //TODO Check if relates to address and add accept node for zero conf.
        }

        mMutex.unlock();
        return result;
    }

    void Monitor::revertBlockHash(NextCash::Hash &pHash)
    {
        mMutex.lock();

        // If there is an active request then remove it and that is all
        NextCash::HashContainerList<MerkleRequestData *>::Iterator request =
          mMerkleRequests.get(pHash);
        if(request != mMerkleRequests.end())
        {
            // TODO Move transactions back to pending
            delete *request;
            mMerkleRequests.erase(request);
        }

        NextCash::HashContainerList<SPVTransactionData *>::Iterator pending;
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end();)
        {
            if((*trans)->blockHash == pHash)
            {
                pending = mPendingTransactions.get((*trans)->transaction->hash);
                if(pending == mPendingTransactions.end())
                {
                    (*trans)->blockHeight = 0xffffffff;
                    (*trans)->blockHash.clear();
                    mPendingTransactions.insert((*trans)->transaction->hash, *trans);
                }
                else
                    delete *trans;
                trans = mTransactions.erase(trans);
                ++mChangeID;
            }
            else
                ++trans;
        }

        mMutex.unlock();
    }

    void Monitor::revertToHeight(unsigned int pBlockHeight)
    {
        mMutex.lock();

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
          "Reverted to block height %d", pBlockHeight);

        // Update last block height
        for(std::vector<PassData>::iterator pass = mPasses.begin(); pass != mPasses.end(); ++pass)
            if(!pass->complete && pass->blockHeight == pBlockHeight)
            {
                if(mLowestPassHeight == pass->blockHeight)
                    --mLowestPassHeight;
                if(mRoughMerkleHeight == pass->blockHeight)
                    --mRoughMerkleHeight;
                --(pass->blockHeight);
                ++mChangeID;
            }

        NextCash::HashContainerList<SPVTransactionData *>::Iterator pending;
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
          mTransactions.begin(); trans != mTransactions.end();)
        {
            if((*trans)->blockHeight > pBlockHeight)
            {
                pending = mPendingTransactions.get((*trans)->transaction->hash);
                if(pending == mPendingTransactions.end())
                {
                    (*trans)->blockHeight = 0xffffffff;
                    (*trans)->blockHash.clear();
                    mPendingTransactions.insert((*trans)->transaction->hash, *trans);
                }
                else
                    delete *trans;
                trans = mTransactions.erase(trans);
                ++mChangeID;
            }
            else
                ++trans;
        }

        mMutex.unlock();
    }

    bool Monitor::confirmTransaction(SPVTransactionData *pTransaction)
    {
        if(pTransaction->transaction == NULL)
            return false;

        // Remove from pending (in case some how duplicated)
        NextCash::HashContainerList<SPVTransactionData *>::Iterator pendingTransaction =
          mPendingTransactions.get(pTransaction->transaction->hash);
        if(pendingTransaction != mPendingTransactions.end())
        {
            delete *pendingTransaction;
            mPendingTransactions.erase(pendingTransaction);
        }

        // Add to confirmed
        NextCash::HashContainerList<SPVTransactionData *>::Iterator confirmedTransaction =
          mTransactions.get(pTransaction->transaction->hash);
        if(confirmedTransaction == mTransactions.end())
        {
            // Refresh in case it spends pending or previous transaction in this block.
            refreshTransaction(pTransaction, false);

            // New UTXO requires new bloom filter and reset of all existing merkle requests.
            if(pTransaction->payOutputs.size() > 0)
                mBloomFilterNeedsRestart = true;

            // Determine if transaction actually effects related addresses.
            if(pTransaction->payOutputs.size() > 0 || pTransaction->spendInputs.size() > 0)
            {
                mTransactions.insert(pTransaction->transaction->hash, pTransaction);
                NextCash::String subject, message;

                if(pTransaction->amount > 0)
                {
                    subject = "Bitcoin Cash Receive Confirmed";
                    message.writeFormatted("Receive confirmed for %0.8f bitcoins in block %d\nNew Balance : %0.8f\nTransaction : %s",
                      bitcoins(pTransaction->amount), pTransaction->blockHeight,
                      bitcoins(balance(true)), pTransaction->transaction->hash.hex().text());
                    NextCash::Log::addFormatted(NextCash::Log::INFO,
                      BITCOIN_MONITOR_LOG_NAME,
                      "Confirmed transaction receiving %0.8f bitcoins : %s",
                      bitcoins(pTransaction->amount), pTransaction->transaction->hash.hex().text());
                }
                else
                {
                    subject = "Bitcoin Cash Send Confirmed";
                    message.writeFormatted("Send confirmed for %0.8f bitcoins in block %d.\nNew Balance : %0.8f\nTransaction : %s",
                      -bitcoins(pTransaction->amount), pTransaction->blockHeight,
                      bitcoins(balance(true)), pTransaction->transaction->hash.hex().text());
                    NextCash::Log::addFormatted(NextCash::Log::INFO,
                      BITCOIN_MONITOR_LOG_NAME,
                      "Confirmed transaction sending %0.8f bitcoins : %s",
                      -bitcoins(pTransaction->amount),
                      pTransaction->transaction->hash.hex().text());
                }

                NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                  "Total balance updated to %0.8f bitcoins", bitcoins(balance(true)));

                notify(subject, message);
                ++mChangeID;
                return true;
            }
            else // Unrelated
                return false;
        }
        else
            return false; // Transaction already confirmed
    }

    bool Monitor::processRequest(Chain &pChain, unsigned int pHeight, bool pIsReverse)
    {
        NextCash::Hash blockHash(BLOCK_HASH_SIZE);

        // Check if the next block has enough merkle confirms
        if(!pChain.getHash(pHeight, blockHash))
            return false;

        NextCash::HashContainerList<MerkleRequestData *>::Iterator request =
          mMerkleRequests.get(blockHash);
        if(request != mMerkleRequests.end() && (*request)->isReverse != pIsReverse)
            ++request;

        if(request != mMerkleRequests.end() && request.hash() == blockHash &&
          (*request)->isReverse == pIsReverse)
        {
            MerkleRequestData *merkleRequest = *request;
            unsigned int nodeID;
            Time time = getTime();
            if(!merkleRequest->isComplete())
            {
                // Time out requests
                while((nodeID = merkleRequest->timedOutNode(time)) != 0)
                    if(addNeedsClose(nodeID))
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO,
                          BITCOIN_MONITOR_LOG_NAME,
                          "Node [%d] needs closed. Merkle blocks too slow", nodeID);
                    }

                return false; // Waiting for more transactions
            }

            // Delete remaining transactions
            for(NextCash::HashContainerList<SPVTransactionData *>::Iterator trans =
              merkleRequest->transactions.begin(); trans != merkleRequest->transactions.end();
              ++trans)
                if(*trans != NULL)
                    delete *trans;

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
              "Processed merkle block with %d/%d trans (%d) : %s",
              merkleRequest->transactions.size(), merkleRequest->transactions.size(),
              pHeight, request.hash().hex().text());

            // Clear so they aren't deleted since they were either reused or already deleted.
            merkleRequest->transactions.clear();

            //TODO Check for false positive rate too high

            // Remove merkle request
            delete *request;
            mMerkleRequests.erase(request);

            if(!pIsReverse && (!mLowestPassHeightSet || pHeight <= mLowestPassHeight + 1))
            {
                mLowestPassHeight = pHeight;
                if(mRoughMerkleHeight < mLowestPassHeight)
                    mRoughMerkleHeight = mLowestPassHeight;
            }

            ++mChangeID;
            return true;
        }
        else
            return false;
    }

    void Monitor::process(Chain &pChain, bool pLocked)
    {
        if(Info::instance().spvMode)
        {
            if(mAddressHashes.size() == 0)
                return;

            if(!pLocked)
                mMutex.lock();

            if(mBloomFilterNeedsRestart)
                restartBloomFilter();

            unsigned int passIndex = mPasses.size();
            for(std::vector<PassData>::reverse_iterator pass = mPasses.rbegin();
              pass != mPasses.rend(); ++pass, --passIndex)
            {
                if(pass->complete)
                    continue;

                if(pass->blockHeight == pChain.headerHeight() &&
                  passIndex < mPasses.size())
                {
                    NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_MONITOR_LOG_NAME,
                      "Pass %d completed at block height %d", passIndex, pass->blockHeight);
                    pass->complete = true;
                    refreshLowestPassHeight();
                    ++mChangeID;
                    continue;
                }

                while(processRequest(pChain, pass->blockHeight + 1, false))
                    ++(pass->blockHeight);

                if(mBloomFilterNeedsRestart)
                    break;
            }

            if(!mBloomFilterNeedsRestart)
            {
                if(mReversePassHeight == 0xffffffff)
                    mReversePassHeight = pChain.headerHeight();

                unsigned int lastReverseHeight = pChain.headerHeight();
                if(lastReverseHeight > 2016)
                    lastReverseHeight -= 2016;
                else
                    lastReverseHeight = 0;

                while(mReversePassHeight > lastReverseHeight &&
                  processRequest(pChain, mReversePassHeight, true))
                    --mReversePassHeight;
            }

            if(!pLocked)
                mMutex.unlock();
        }
        else
        {
            // Not SPV mode

        }
    }

    void Monitor::clearMerkleRequest(MerkleRequestData *pData)
    {
        // Move transactions back to pending
        for(NextCash::HashContainerList<SPVTransactionData *>::Iterator transaction =
          pData->transactions.begin(); transaction != pData->transactions.end();)
            if(*transaction != NULL &&
              mPendingTransactions.get(transaction.hash()) == mPendingTransactions.end())
            {
                (*transaction)->blockHash.clear();
                (*transaction)->blockHeight = 0xffffffff;
                mPendingTransactions.insert(transaction.hash(), *transaction);
                transaction = pData->transactions.erase(transaction);
            }
            else
                ++transaction;

        pData->clear();
    }
}
