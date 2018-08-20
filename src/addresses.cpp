/**************************************************************************
 * Copyright 2017 NextCash, LLC                                           *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "addresses.hpp"

#include "block.hpp"
#include "interpreter.hpp"

#ifdef PROFILER_ON
#include "profiler.hpp"
#endif


namespace BitCoin
{
    void FullOutputData::print()
    {
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_ADDRESSES_LOG_NAME,
          "Output %d for %f bitcoins in block %d : %s",
          index, bitcoins(output.amount), blockHeight, transactionID.hex().text());
    }

    bool AddressOutputReference::getFullOutput(FullOutputData &pOutput) const
    {
        pOutput.blockHeight = blockHeight;
        pOutput.index = outputIndex;
        return Block::getOutput(blockHeight, transactionOffset, outputIndex,
          pOutput.transactionID, pOutput.output);
    }

    bool Addresses::getOutputs(const NextCash::Hash &pPubKeyHash, std::vector<FullOutputData> &pOutputs)
    {
        pOutputs.clear();
        Iterator item = get(pPubKeyHash, true);

        if(!item)
            return false;

        Iterator counter = item;
        unsigned int count = 0;
        while(counter && counter.hash() == pPubKeyHash)
        {
            if(!(*counter)->markedRemove())
                ++count;
            ++counter;
        }

        pOutputs.clear();
        pOutputs.reserve(count);

        FullOutputData output;
        for(unsigned int i = 0; i < count && item;)
        {
            if(!(*item)->markedRemove())
            {
                if(!((AddressOutputReference *)(*item))->getFullOutput(output))
                    return false;
                pOutputs.push_back(output);
                ++i;
            }
            ++item;
        }

        return true;
    }

    bool Addresses::add(std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
#ifdef PROFILER_ON
        NextCash::Profiler profiler("Addresses Add");
#endif
        if(pBlockHeight != mNextBlockHeight)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_ADDRESSES_LOG_NAME,
              "Can't add transaction addresses for non matching block height %d. Should be %d",
              pBlockHeight, mNextBlockHeight);
            return false;
        }

        NextCash::HashList hashes;
        Iterator newItem;
        unsigned int transactionOffset = 0, outputOffset;
        NextCash::HashData *newAddress;
        bool success = true;
        for(std::vector<Transaction *>::iterator trans = pBlockTransactions.begin();
          trans != pBlockTransactions.end(); ++trans, ++transactionOffset)
        {
            outputOffset = 0;
            for(std::vector<Output>::iterator output = (*trans)->outputs.begin();
              output != (*trans)->outputs.end(); ++output, ++outputOffset)
            {
                switch(ScriptInterpreter::parseOutputScript(output->script, hashes))
                {
                    case ScriptInterpreter::P2PKH:
                    case ScriptInterpreter::P2PK:
                    case ScriptInterpreter::P2SH:
                    case ScriptInterpreter::MULTI_SIG:
                        for(NextCash::HashList::iterator hash = hashes.begin();
                          hash != hashes.end(); ++hash)
                        {
                            newAddress = new AddressOutputReference(pBlockHeight,
                              transactionOffset, outputOffset);
                            if(!insert(*hash, newAddress))
                            {
                                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_ADDRESSES_LOG_NAME,
                                  "Failed to insert block %d transaction %d output %d for address %s",
                                  pBlockHeight, transactionOffset, outputOffset, hash->hex().text());
                                delete newAddress;
                                success = false;
                            }
                        }
                        break;
                    default:
                        break;
                }
            }
        }

        ++mNextBlockHeight;
        return success;
    }

    bool Addresses::remove(std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
        if(mNextBlockHeight == 0 || pBlockHeight != mNextBlockHeight - 1)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_ADDRESSES_LOG_NAME,
              "Can't remove transaction addresses for non matching block height %d. Should be %d",
              pBlockHeight, mNextBlockHeight - 1);
            return false;
        }

        NextCash::Log::addFormatted(NextCash::Log::VERBOSE, BITCOIN_ADDRESSES_LOG_NAME,
          "Removing transaction addresses for %d transactions at block height %d.",
          pBlockTransactions.size(), pBlockHeight);

        bool success = true;
        AddressOutputReference newAddress;
        unsigned int transactionOffset = 0, outputOffset;
        NextCash::HashList hashes;

        for(std::vector<Transaction *>::iterator trans = pBlockTransactions.begin();
          trans != pBlockTransactions.end(); ++trans, ++transactionOffset)
        {
            // Remove addresses added by outputs from this block's transactions
            outputOffset = 0;
            for(std::vector<Output>::iterator output = (*trans)->outputs.begin();
              output != (*trans)->outputs.end(); ++output, ++outputOffset)
            {
                newAddress.set(pBlockHeight, transactionOffset, outputOffset);

                switch(ScriptInterpreter::parseOutputScript(output->script, hashes))
                {
                    case ScriptInterpreter::P2PKH:
                    case ScriptInterpreter::P2PK:
                    case ScriptInterpreter::P2SH:
                    case ScriptInterpreter::MULTI_SIG:
                        for(NextCash::HashList::iterator hash = hashes.begin();
                          hash != hashes.end(); ++hash)
                        {
                            if(removeIfMatching(*hash, &newAddress))
                            {
                                NextCash::Log::addFormatted(NextCash::Log::DEBUG,
                                  BITCOIN_ADDRESSES_LOG_NAME,
                                  "Removing transaction (%d) output (%d) address for block height %d : %s",
                                  transactionOffset, outputOffset, pBlockHeight, hash->hex().text());
                                break;
                            }
                            else
                            {
                                NextCash::Log::addFormatted(NextCash::Log::ERROR,
                                  BITCOIN_ADDRESSES_LOG_NAME,
                                  "Failed to remove transaction address for block height %d : %s",
                                  pBlockHeight, hash->hex().text());
                                success = false;
                                break;
                            }
                        }
                        break;
                    default:
                        break;
                }
            }
        }

        --mNextBlockHeight;
        return success;
    }

    bool Addresses::load(const char *pFilePath, uint64_t pCacheDataTargetSize)
    {
        NextCash::String filePath = pFilePath;
        filePath.pathAppend("addresses");

        if(!HashDataSet::load("Addresses", filePath))
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
                NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_ADDRESSES_LOG_NAME,
                  "Failed to open height file to load");
                mIsValid = false;
                return false;
            }

            // Read block height
            mNextBlockHeight = file.readUnsignedInt();
        }

        if(mIsValid)
        {
            setTargetCacheDataSize(pCacheDataTargetSize);

            NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_ADDRESSES_LOG_NAME,
              "Loaded %d transaction addresses at block height %d (cached %d KiB)",
              size(), mNextBlockHeight - 1, cacheDataSize() / 1024);
        }

        return mIsValid;
    }

    bool Addresses::save(unsigned int pThreadCount)
    {
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_ADDRESSES_LOG_NAME,
          "Saving transaction addresses at block height %d (%d KiB cached)", mNextBlockHeight - 1,
          cacheDataSize() / 1024);

#ifdef SINGLE_THREAD
        if(!HashDataSet::save())
#else
        if(!HashDataSet::saveMultiThreaded(pThreadCount))
#endif
            return false;

        NextCash::String filePathName = path();
        filePathName.pathAppend("height");
        NextCash::FileOutputStream file(filePathName, true);
        if(!file.isValid())
        {
            NextCash::Log::add(NextCash::Log::ERROR, BITCOIN_ADDRESSES_LOG_NAME,
              "Failed to open height file to save");
            return false;
        }

        // Block Height
        file.writeUnsignedInt(mNextBlockHeight);
        file.flush();

        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_ADDRESSES_LOG_NAME,
          "Saved %d transaction addresses at block height %d (cache %d KiB)", size(),
          mNextBlockHeight - 1, cacheDataSize() / 1024);
        return true;
    }
}

