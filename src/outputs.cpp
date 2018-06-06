/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                   *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "outputs.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#endif

#include "info.hpp"
#include "interpreter.hpp"
#include "block.hpp"

#include <cstring>


namespace BitCoin
{
    void Output::write(NextCash::OutputStream *pStream, bool pBlockFile)
    {
        if(pBlockFile)
            blockFileOffset = pStream->writeOffset();
        pStream->writeLong(amount);
        writeCompactInteger(pStream, script.length());
        script.setReadOffset(0);
        pStream->writeStream(&script, script.length());
    }

    bool Output::read(NextCash::InputStream *pStream, bool pBlockFile)
    {
        if(pBlockFile)
            blockFileOffset = pStream->readOffset();

        if(pStream->remaining() < 8)
            return false;

        amount = pStream->readLong();

        uint64_t bytes = readCompactInteger(pStream);
        if(pStream->remaining() < bytes)
            return false;
        script.setSize(bytes);
        script.reset();
        script.writeStreamCompact(*pStream, bytes);

        return true;
    }

    bool Output::skip(NextCash::InputStream *pInputStream, NextCash::OutputStream *pOutputStream)
    {
        // Amount
        if(pInputStream->remaining() < 8)
            return false;
        if(pOutputStream == NULL)
            pInputStream->setReadOffset(pInputStream->readOffset() + 8);
        else
            pOutputStream->writeLong(pInputStream->readLong());

        // Script
        uint64_t bytes = readCompactInteger(pInputStream);
        if(pOutputStream != NULL)
            writeCompactInteger(pOutputStream, bytes);
        if(pInputStream->remaining() < bytes)
            return false;
        if(pOutputStream == NULL)
            pInputStream->setReadOffset(pInputStream->readOffset() + bytes);
        else
            pInputStream->readStream(pOutputStream, bytes);
        return true;
    }

    void Output::print(Forks &pForks, NextCash::Log::Level pLevel)
    {
        NextCash::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "Output");
        NextCash::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Amount : %.08f", bitcoins(amount));
        script.setReadOffset(0);
        NextCash::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Script : (%d bytes)", script.length());
        ScriptInterpreter::printScript(script, pForks, pLevel);
    }

    bool TransactionReference::allocateOutputs(unsigned int pCount)
    {
        // Allocate the number of outputs needed
        if(mOutputCount != pCount)
        {
            if(mOutputs != NULL)
                delete[] mOutputs;
            mOutputCount = pCount;
            if(mOutputCount == 0)
                mOutputs = NULL;
            else
            {
                try
                {
                    mOutputs = new OutputReference[mOutputCount];
                }
                catch(std::bad_alloc &pBadAlloc)
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                      "Bad allocation (Allocate %d Outputs) : %s", mOutputCount, pBadAlloc.what());
                    return false;
                }
            }
        }

        return true;
    }

    void TransactionReference::clearOutputs()
    {
        if(mOutputs != NULL)
            delete[] mOutputs;
        mOutputCount = 0;
        mOutputs = NULL;
    }

    bool TransactionReference::read(NextCash::InputStream *pStream)
    {
        if(pStream->remaining() < 8)
            return false;

        blockHeight = pStream->readUnsignedInt();
        if(blockHeight > MAX_BLOCK_HEIGHT)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Block height too high : %d", blockHeight);
            return false;
        }

        unsigned int outputCount = pStream->readUnsignedInt();
        if(outputCount > MAX_OUTPUT_COUNT)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Output Count too high : %d", outputCount);
            return false;
        }

        if(pStream->remaining() < OutputReference::SIZE * outputCount)
            return false;

        if(!allocateOutputs(outputCount))
            return false;

        pStream->read(mOutputs, mOutputCount * OutputReference::SIZE);
        return true;
    }

    bool TransactionReference::write(NextCash::OutputStream *pStream)
    {
        pStream->writeUnsignedInt(blockHeight);
        pStream->writeUnsignedInt(mOutputCount);
        pStream->write(mOutputs, mOutputCount * OutputReference::SIZE);
        return true;
    }

    unsigned int TransactionReference::spentOutputCount() const
    {
        if(mOutputs == NULL) // Header only
            return 0;
        unsigned int result = 0;
        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
            if(output->spentBlockHeight != 0)
                ++result;
        return result;
    }

    // Mark an output as spent
    void TransactionReference::spendInternal(unsigned int pIndex, unsigned int pBlockHeight)
    {
        OutputReference *output = outputAt(pIndex);
        if(output == NULL)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Spend index %d not found", pIndex);
            return;
        }
        else if(output->spentBlockHeight != 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Spend index %d already spent at block height %d", pIndex, output->spentBlockHeight);
            return;
        }
        output->spendInternal(pBlockHeight);
        setModified();
    }

    bool TransactionReference::wasModifiedInOrAfterBlock(unsigned int pBlockHeight) const
    {
        if(blockHeight >= pBlockHeight)
            return true;

        if(mOutputCount == 0 || mOutputs == NULL)
            return false;

        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
            if(output->spentBlockHeight >= pBlockHeight)
                return true;

        return false;
    }

    unsigned int TransactionReference::spentBlockHeight() const
    {
        unsigned int result = 0;
        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i)
        {
            if(output->spentBlockHeight == 0)
                return MAX_BLOCK_HEIGHT;
            else if(output->spentBlockHeight > result)
                result = output->spentBlockHeight;
            ++output;
        }
        return result;
    }

    void TransactionReference::commit(std::vector<Output> &pOutputs)
    {
        if(mOutputCount != pOutputs.size())
        {
            NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_OUTPUTS_LOG_NAME,
              "Mismatched transaction outputs on commit %d != %d", mOutputCount, pOutputs.size());
            return;
        }

        OutputReference *output = mOutputs;
        for(std::vector<Output>::iterator fullOutput=pOutputs.begin();fullOutput!=pOutputs.end();++fullOutput,++output)
            if(output->commit(*fullOutput))
                setModified();
    }

    void TransactionReference::print(NextCash::Log::Level pLevel)
    {
        NextCash::Log::add(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "Transaction Reference");
        NextCash::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Height         : %d", blockHeight);

        OutputReference *output = mOutputs;
        for(unsigned int i=0;i<mOutputCount;++i,++output)
        {
            NextCash::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "  Output Reference %d", i);
            NextCash::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    File Offset : %d", output->blockFileOffset);
            NextCash::Log::addFormatted(pLevel, BITCOIN_OUTPUTS_LOG_NAME, "    Spent       : %d", output->spentBlockHeight);
        }
    }

    const unsigned int TransactionOutputPool::BIP0030_HEIGHTS[BIP0030_HASH_COUNT] = { 91842, 91880 };
    const NextCash::Hash TransactionOutputPool::BIP0030_HASHES[BIP0030_HASH_COUNT] =
    {
        NextCash::Hash("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"),
        NextCash::Hash("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")
    };

    bool TransactionOutputPool::checkDuplicates(const std::vector<Transaction *> &pBlockTransactions,
      unsigned int pBlockHeight, const NextCash::Hash &pBlockHash)
    {
        Iterator reference;
        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
        {
            // Get references set for transaction ID
            reference = get((*transaction)->hash);
            while(reference && reference.hash() == (*transaction)->hash)
            {
                if(!((TransactionReference *)(*reference))->markedRemove() &&
                  ((TransactionReference *)(*reference))->hasUnspentOutputs())
                {
                    bool exceptionFound = false;
                    for(unsigned int i=0;i<BIP0030_HASH_COUNT;++i)
                        if(BIP0030_HEIGHTS[i] == pBlockHeight && BIP0030_HASHES[i] == pBlockHash)
                            exceptionFound = true;
                    if(exceptionFound)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
                          "BIP-0030 Exception for duplicate transaction ID at block height %d : transaction %s",
                          ((TransactionReference *)(*reference))->blockHeight, (*transaction)->hash.hex().text());
                    }
                    else
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Matching transaction output hash from block height %d has unspent outputs : %s",
                          ((TransactionReference *)(*reference))->blockHeight, (*transaction)->hash.hex().text());
                        return false;
                    }
                }

                ++reference;
            }
        }

        return true;
    }

    // Add all the outputs from a block (cached since they have no block file IDs or offsets yet)
    bool TransactionOutputPool::add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Outputs Add Block");
#endif
        mToCommit.clear();
        mToCommitHashes.clear();

        if(pBlockHeight != mNextBlockHeight)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't add transaction outputs for non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight);
            return false;
        }

        TransactionReference *transactionReference;
        Iterator item;
        unsigned int count = 0;
        bool success = true, valid;
        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
        {
            // Get references set for transaction ID
            transactionReference = new TransactionReference(pBlockHeight, (*transaction)->outputs.size());

            valid = true;
            if(!insert((*transaction)->hash, transactionReference))
            {
                // Check for matching transaction marked for removal
                Iterator item = get((*transaction)->hash);

                valid = false;
                while(item && item.hash() == (*transaction)->hash)
                {
                    if(transactionReference->valuesMatch(*item) && (*item)->markedRemove())
                    {
                        // Unmark the matching item for removal
                        NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
                          "Reversing removal of transaction output for block height %d : %s", pBlockHeight,
                          (*transaction)->hash.hex().text());
                        (*item)->clearRemove();
                        valid = true;
                        delete transactionReference;
                        transactionReference = (TransactionReference *)*item;
                        break;
                    }
                    ++item;
                }
            }

            if(valid)
            {
                mToCommit.push_back(transactionReference);
                mToCommitHashes.push_back((*transaction)->hash);
                ++count;
            }
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to insert transaction output for block height %d : %s", pBlockHeight,
                  (*transaction)->hash.hex().text());
                success = false;
                delete transactionReference;
            }
        }

        return success;
    }

    bool TransactionOutputPool::commit(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
        if(!mIsValid)
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME, "Can't commit invalid unspent pool");
            return false;
        }

#ifdef PROFILER_ON
        NextCash::Profiler profiler("Outputs Commit");
#endif
        if(pBlockHeight != mNextBlockHeight)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't commit non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight - 1);
            return false;
        }

        if(mToCommit.size() != pBlockTransactions.size())
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't commit non matching transaction set");
            return false;
        }

        std::vector<TransactionReference *>::iterator reference = mToCommit.begin();
        NextCash::HashList::iterator hash = mToCommitHashes.begin();
        for(std::vector<Transaction *>::const_iterator transaction=pBlockTransactions.begin();transaction!=pBlockTransactions.end();++transaction)
        {
            if(*hash == (*transaction)->hash)
            {
                (*reference)->commit((*transaction)->outputs);
                ++reference;
                ++hash;
            }
            else
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Can't commit non matching transaction");
                return false;
            }
        }

        mToCommit.clear();
        mToCommitHashes.clear();
        ++mNextBlockHeight;
        return true;
    }

    bool TransactionOutputPool::revert(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
        if(!mIsValid)
            return false;

        if(mToCommit.size() > 0)
        {
            if(pBlockHeight != mNextBlockHeight)
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Can't revert non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight);
                return false;
            }
        }
        else if(pBlockHeight != mNextBlockHeight - 1)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Can't revert non matching block height %d. Should be %d", pBlockHeight, mNextBlockHeight - 1);
            return false;
        }

        std::vector<Input>::const_iterator input;
        Iterator reference;
        OutputReference *outputReference;
        bool success = true;
        bool found;

        // Process transactions in reverse since they can unspend previous transactions in the same block
        for(std::vector<Transaction *>::const_reverse_iterator transaction=pBlockTransactions.rbegin();transaction!=pBlockTransactions.rend();++transaction)
        {
            // Unspend inputs
            for(input=(*transaction)->inputs.begin();input!=(*transaction)->inputs.end();++input)
                if(input->outpoint.index != 0xffffffff) // Coinbase input has no outpoint transaction
                {
                    reference = get(input->outpoint.transactionID);
                    found = false;
                    while(reference && reference.hash() == input->outpoint.transactionID)
                    {
                        if(!((TransactionReference *)(*reference))->markedRemove())
                        {
                            outputReference = ((TransactionReference *)(*reference))->outputAt(input->outpoint.index);
                            if(outputReference != NULL && outputReference->spentBlockHeight != 0)
                            {
                                NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
                                  "Reverting spend on input transaction : index %d %s", input->outpoint.index,
                                  input->outpoint.transactionID.hex().text());
                                outputReference->spentBlockHeight = 0;
                                reference->setModified();
                                found = true;
                                break;
                            }
                        }

                        ++reference;
                    }

                    if(!found)
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                          "Input transaction not found to revert spend : index %d %s", input->outpoint.index,
                          input->outpoint.transactionID.hex().text());
                        success = false;
                        break;
                    }
                }

            // Remove transaction
            reference = get((*transaction)->hash);
            found = false;
            while(reference && reference.hash() == (*transaction)->hash)
            {
                if(!((TransactionReference *)(*reference))->markedRemove())
                {
                    NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
                      "Removing transaction : %s", (*transaction)->hash.hex().text());
                    reference->setRemove();
                    found = true;
                    break;
                }

                ++reference;
            }

            if(!found)
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Transaction not found to remove for revert : %s", (*transaction)->hash.hex().text());
                success = false;
                break;
            }
        }

        mToCommit.clear();
        mToCommitHashes.clear();
        if(success)
            --mNextBlockHeight;
        return success;
    }

    TransactionReference *TransactionOutputPool::findUnspent(const NextCash::Hash &pTransactionID, uint32_t pIndex)
    {
        if(!mIsValid)
            return NULL;

#ifdef PROFILER_ON
        NextCash::Profiler profiler("Find Unspent");
#endif
        Iterator reference = get(pTransactionID);
        while(reference && reference.hash() == pTransactionID)
        {
            if(!((TransactionReference *)(*reference))->markedRemove() &&
              ((TransactionReference *)(*reference))->hasUnspentOutput(pIndex))
                return (TransactionReference *)*reference;

            ++reference;
        }

        return NULL;
    }

    TransactionReference *TransactionOutputPool::find(const NextCash::Hash &pTransactionID, uint32_t pIndex)
    {
        if(!mIsValid)
            return NULL;

#ifdef PROFILER_ON
        NextCash::Profiler profiler("Find Unspent");
#endif
        Iterator reference = get(pTransactionID);
        TransactionReference *result = NULL;
        while(reference && reference.hash() == pTransactionID)
        {
            if(!((TransactionReference *)(*reference))->markedRemove())
            {
              if(((TransactionReference *)(*reference))->hasUnspentOutput(pIndex))
                  return (TransactionReference *)*reference;
              else
                  result = (TransactionReference *)*reference;
            }

            ++reference;
        }

        return result;
    }

    // Mark an output as spent
    void TransactionOutputPool::spend(TransactionReference *pReference, unsigned int pIndex, unsigned int pBlockHeight)
    {
        pReference->spendInternal(pIndex, pBlockHeight);
    }

    bool TransactionOutputPool::load(const char *pFilePath, uint64_t pCacheDataTargetSize)
    {
        NextCash::String filePath = pFilePath;
        filePath.pathAppend("outputs");

        if(!HashDataSet::load("Outputs", filePath))
            return false;

        NextCash::String filePathName = filePath;
        filePathName.pathAppend("height");
        if(!NextCash::fileExists(filePathName))
            mNextBlockHeight = 0;
        else
        {
            NextCash::FileInputStream file(filePathName);
            if(!file.isValid())
            {
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
                  "Failed to open height file to load");
                mIsValid = false;
                return false;
            }

            // Read block height
            mNextBlockHeight = file.readUnsignedInt();
        }

        if(mIsValid)
        {
            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
              "Loaded %d transaction outputs at block height %d (%d KiB cached)",
              size(), mNextBlockHeight - 1, cacheDataSize() / 1024);
            mSavedBlockHeight = mNextBlockHeight;

            setTargetCacheDataSize(pCacheDataTargetSize);
        }

        return mIsValid;
    }

    bool TransactionOutputPool::save()
    {
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Saving transaction outputs at block height %d (%d KiB cached)", mNextBlockHeight - 1,
          cacheDataSize() / 1024);

        if(!HashDataSet::save())
            return false;

        NextCash::String filePathName = path();
        filePathName.pathAppend("height");
        NextCash::FileOutputStream file(filePathName, true);
        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_OUTPUTS_LOG_NAME,
              "Failed to open height file to save");
            return false;
        }

        // Block Height
        file.writeUnsignedInt(mNextBlockHeight);
        file.flush();

        mSavedBlockHeight = mNextBlockHeight;
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
          "Saved %d transaction outputs at block height %d (%d KiB cached)", size(), mNextBlockHeight - 1, cacheDataSize() / 1024);
        return true;
    }
}
