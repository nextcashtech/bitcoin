/**************************************************************************
 * Copyright 2017 NextCash, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
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
        return BlockFile::readBlockTransactionOutput(blockHeight, transactionOffset, outputIndex,
          pOutput.transactionID, pOutput.output);
    }

    bool Addresses::getOutputs(const NextCash::Hash &pAddress, std::vector<FullOutputData> &pOutputs)
    {
        pOutputs.clear();
        Iterator item = get(pAddress, true);

        if(!item)
            return false;

        Iterator counter = item;
        unsigned int count = 0;
        while(counter && counter.hash() == pAddress)
        {
            if(!(*counter)->markedRemove())
                ++count;
            ++counter;
        }

        pOutputs.clear();
        pOutputs.resize(count);

        std::vector<FullOutputData>::iterator output = pOutputs.begin();
        while(item && item.hash() == pAddress)
        {
            if(!(*item)->markedRemove())
            {
                // NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_ADDRESSES_LOG_NAME,
                  // "Fetching transaction %d output %d from block at height %d",
                  // ((AddressOutputReference *)(*item))->transactionOffset,
                  // ((AddressOutputReference *)(*item))->outputIndex, ((AddressOutputReference *)(*item))->blockHeight);
                if(!((AddressOutputReference *)(*item))->getFullOutput(*output))
                    return false;
                ++output;
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
        for(std::vector<Transaction *>::iterator trans=pBlockTransactions.begin();trans!=pBlockTransactions.end();++trans,++transactionOffset)
        {
            outputOffset = 0;
            for(std::vector<Output>::iterator output=(*trans)->outputs.begin();output!=(*trans)->outputs.end();++output,++outputOffset)
            {
                switch(ScriptInterpreter::parseOutputScript(output->script, hashes))
                {
                    case ScriptInterpreter::P2PKH:
                    case ScriptInterpreter::P2PK:
                    case ScriptInterpreter::P2SH:
                    case ScriptInterpreter::MULTI_SIG:
                        for(NextCash::HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
                        {
                            newAddress = new AddressOutputReference(pBlockHeight, transactionOffset, outputOffset);
                            if(!insert(*hash, newAddress))
                            {
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
        if(pBlockHeight != mNextBlockHeight - 1)
        {
            NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_ADDRESSES_LOG_NAME,
              "Can't remove transaction addresses for non matching block height %d. Should be %d",
              pBlockHeight, mNextBlockHeight - 1);
            return false;
        }

        bool success = true;
        NextCash::HashData *newAddress;
        unsigned int transactionOffset = 0, outputOffset;
        NextCash::HashList hashes;
        Iterator item;
        bool found;

        for(std::vector<Transaction *>::iterator trans=pBlockTransactions.begin();trans!=pBlockTransactions.end();++trans,++transactionOffset)
        {
            // Remove addresses added by outputs from this block's transactions
            outputOffset = 0;
            for(std::vector<Output>::iterator output=(*trans)->outputs.begin();output!=(*trans)->outputs.end();++output,++outputOffset)
            {
                switch(ScriptInterpreter::parseOutputScript(output->script, hashes))
                {
                    case ScriptInterpreter::P2PKH:
                    case ScriptInterpreter::P2PK:
                    case ScriptInterpreter::P2SH:
                    case ScriptInterpreter::MULTI_SIG:
                        for(NextCash::HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
                        {
                            newAddress = new AddressOutputReference(pBlockHeight, transactionOffset, outputOffset);

                            // Check for matching address marked for removal
                            item = get(*hash);
                            found = false;

                            while(item && item.hash() == *hash)
                            {
                                if(newAddress->valuesMatch(*item) && !(*item)->markedRemove())
                                {
                                    NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_ADDRESSES_LOG_NAME,
                                      "Removing transaction address for block height %d : %s", pBlockHeight,
                                      item.hash().hex().text());
                                    (*item)->setRemove();
                                    found = true;
                                    break;
                                }
                                ++item;
                            }

                            delete newAddress;

                            if(!found)
                            {
                                NextCash::Log::addFormatted(NextCash::Log::ERROR, BITCOIN_ADDRESSES_LOG_NAME,
                                  "Failed to remove transaction address for block height %d : %s", pBlockHeight,
                                  item.hash().hex().text());
                                success = false;
                                break;
                            }
                        }
                        break;
                    default:
                        break;
                }
            }

            // Unspend all addresses spent by inputs from this block's transactions
            // inputOffset = 0;
            // for(std::vector<Input *>::const_iterator output=(*trans)->inputs.begin();output!=(*trans)->inputs.end();++output,++inputOffset)
            // {
                // // Get outpoint
                // reference = pOutputs.findUnspent()

                // switch(ScriptInterpreter::parseOutputScript((*output)->script, hashes))
                // {
                    // case ScriptInterpreter::P2PKH:
                    // case ScriptInterpreter::P2PK:
                    // case ScriptInterpreter::P2SH:
                    // case ScriptInterpreter::MULTI_SIG:
                        // for(NextCash::HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
                        // {
                            // newAddress = new AddressOutputReference(pBlockHeight, transactionOffset, outputOffset);

                            // // Check for matching address marked for removal
                            // Iterator item = get(*hash);

                            // while(item && item.hash() == *hash)
                            // {
                                // if(newAddress->valuesMatch(*item) && (*item)->markedRemove())
                                // {
                                    // // Unmark the matching item for removal
                                    // NextCash::Log::addFormatted(NextCash::Log::DEBUG, BITCOIN_ADDRESSES_LOG_NAME,
                                      // "Reversing removal of transaction address for block height %d : %s", pBlockHeight,
                                      // item.hash().hex().text());
                                    // (*item)->clearRemove();
                                    // break;
                                // }
                                // ++item;
                            // }

                            // delete newAddress;
                        // }
                        // break;
                    // default:
                        // break;
                // }
            // }
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

    bool Addresses::save()
    {
        NextCash::Log::addFormatted(NextCash::Log::INFO, BITCOIN_ADDRESSES_LOG_NAME,
          "Saving transaction addresses at block height %d (%d KiB cached)", mNextBlockHeight - 1,
          cacheDataSize() / 1024);

        if(!HashDataSet::save())
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

