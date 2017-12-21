/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "addresses.hpp"

#include "block.hpp"
#include "interpreter.hpp"

#ifdef PROFILER_ON
#include "arcmist/dev/profiler.hpp"
#endif


namespace BitCoin
{
    void FullOutputData::print()
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_ADDRESSES_LOG_NAME,
          "Transaction output %d for %f from block %d : %s",
          index, output.amount, blockHeight, transactionID.hex().text());
    }

    bool AddressOutputReference::getFullOutput(FullOutputData &pOutput) const
    {
        pOutput.blockHeight = blockHeight;
        pOutput.index = outputIndex;
        return BlockFile::readBlockTransactionOutput(blockHeight, transactionOffset, outputIndex,
          pOutput.transactionID, pOutput.output);
    }

    bool Addresses::getOutputs(const ArcMist::Hash &pAddress, std::vector<FullOutputData> &pOutputs)
    {
        pOutputs.clear();
        Iterator item = get(pAddress, true);

        if(!item)
            return false;

        Iterator counter = item;
        unsigned int count = 0;
        while(counter && counter.hash() == pAddress)
        {
            ++count;
            ++counter;
        }

        pOutputs.clear();
        pOutputs.resize(count);

        std::vector<FullOutputData>::iterator output = pOutputs.begin();
        while(item && item.hash() == pAddress)
        {
            if(!((AddressOutputReference *)(*item))->getFullOutput(*output))
                return false;
            ++output;
            ++item;
        }

        return true;
    }

    bool Addresses::add(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
#ifdef PROFILER_ON
        ArcMist::Profiler profiler("Addresses Add");
#endif
        if(pBlockHeight != mNextBlockHeight)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_ADDRESSES_LOG_NAME,
              "Can't add transaction addresses for non matching block height %d. Should be %d",
              pBlockHeight, mNextBlockHeight);
            return false;
        }

        ArcMist::HashList hashes;
        Iterator newItem;
        unsigned int transactionOffset = 0, outputOffset;
        ArcMist::HashData *newAddress;
        bool success = true;
        for(std::vector<Transaction *>::const_iterator trans=pBlockTransactions.begin();trans!=pBlockTransactions.end();++trans,++transactionOffset)
        {
            outputOffset = 0;
            for(std::vector<Output *>::const_iterator output=(*trans)->outputs.begin();output!=(*trans)->outputs.end();++output,++outputOffset)
            {
                switch(ScriptInterpreter::parseOutputScript((*output)->script, hashes))
                {
                    case ScriptInterpreter::P2PKH:
                    case ScriptInterpreter::P2PK:
                    case ScriptInterpreter::P2SH:
                    case ScriptInterpreter::MULTI_SIG:
                        for(ArcMist::HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
                        {
                            newAddress = new AddressOutputReference(pBlockHeight, transactionOffset, outputOffset);
                            if(!insert(**hash, newAddress))
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

    bool Addresses::remove(const std::vector<Transaction *> &pBlockTransactions, unsigned int pBlockHeight)
    {
        if(pBlockHeight != mNextBlockHeight - 1)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, BITCOIN_ADDRESSES_LOG_NAME,
              "Can't remove transaction addresses for non matching block height %d. Should be %d",
              pBlockHeight, mNextBlockHeight - 1);
            return false;
        }

        bool success = true;
        ArcMist::HashData *newAddress;
        unsigned int transactionOffset = 0, outputOffset;
        ArcMist::HashList hashes;
        for(std::vector<Transaction *>::const_iterator trans=pBlockTransactions.begin();trans!=pBlockTransactions.end();++trans,++transactionOffset)
        {
            outputOffset = 0;
            for(std::vector<Output *>::const_iterator output=(*trans)->outputs.begin();output!=(*trans)->outputs.end();++output,++outputOffset)
            {
                switch(ScriptInterpreter::parseOutputScript((*output)->script, hashes))
                {
                    case ScriptInterpreter::P2PKH:
                    case ScriptInterpreter::P2PK:
                    case ScriptInterpreter::P2SH:
                    case ScriptInterpreter::MULTI_SIG:
                        for(ArcMist::HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
                        {
                            newAddress = new AddressOutputReference(pBlockHeight, transactionOffset, outputOffset);

                            // Check for matching address marked for removal
                            Iterator item = get(**hash);

                            while(item && item.hash() == **hash)
                            {
                                if(newAddress->valuesMatch(*item) && (*item)->markedRemove())
                                {
                                    // Unmark the matching item for removal
                                    ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, BITCOIN_OUTPUTS_LOG_NAME,
                                      "Reversing removal of transaction address for block height %d : %s", pBlockHeight,
                                      item.hash().hex().text());
                                    (*item)->clearRemove();
                                    break;
                                }
                                ++item;
                            }

                            delete newAddress;
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
        ArcMist::String filePath = pFilePath;
        filePath.pathAppend("addresses");

        if(!HashDataSet::load("Addresses", filePath))
            return false;

        ArcMist::String filePathName = filePath;
        filePathName.pathAppend("height");
        if(!ArcMist::fileExists(filePathName))
            mNextBlockHeight = 0;
        else
        {
            ArcMist::FileInputStream file(filePathName);
            if(!file.isValid())
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_ADDRESSES_LOG_NAME,
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

            ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_OUTPUTS_LOG_NAME,
              "Loaded %d transaction addresses at block height %d (cached %d KiB)",
              size(), mNextBlockHeight - 1, cacheDataSize() / 1024);
        }

        return mIsValid;
    }

    bool Addresses::save()
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESSES_LOG_NAME,
          "Saving transaction addresses at block height %d (%d KiB cached)", mNextBlockHeight - 1,
          cacheDataSize() / 1024);

        if(!HashDataSet::save())
            return false;

        ArcMist::String filePathName = path();
        filePathName.pathAppend("height");
        ArcMist::FileOutputStream file(filePathName, true);
        if(!file.isValid())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_ADDRESSES_LOG_NAME,
              "Failed to open height file to save");
            return false;
        }

        // Block Height
        file.writeUnsignedInt(mNextBlockHeight);
        file.flush();

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_ADDRESSES_LOG_NAME,
          "Saved %d transaction addresses at block height %d (cache %d KiB)", size(),
          mNextBlockHeight - 1, cacheDataSize() / 1024);
        return true;
    }
}

