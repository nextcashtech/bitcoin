/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "message.hpp"
#include "key.hpp"
#include "transaction.hpp"
#include "interpreter.hpp"
#include "chain.hpp"
#include "info.hpp"

#include "arcmist/base/log.hpp"

bool chainTest();

int main(int pArgumentCount, char **pArguments)
{
    int failed = 0;

    ArcMist::Log::setLevel(ArcMist::Log::DEBUG);

    if(!BitCoin::Base::test())
        failed++;

    if(!BitCoin::Info::test())
        failed++;

    if(!BitCoin::Key::test())
        failed++;

    if(!BitCoin::Transaction::test())
        failed++;

    if(!BitCoin::ScriptInterpreter::test())
        failed++;

    if(!BitCoin::Message::test())
        failed++;

    if(!BitCoin::TransactionOutputPool::test())
        failed++;

    if(!BitCoin::Chain::test())
        failed++;

    BitCoin::Chain::tempTest();

    // if(!chainTest())
        // failed++;

    // if(!cashDAATest())
        // failed++;

    if(failed)
        return 1;
    else
        return 0;
}

const BitCoin::Hash &addBlock(BitCoin::Chain &pChain, const BitCoin::Hash &pPreviousHash, const BitCoin::Hash &pCoinbaseKeyHash,
  int pBlockHeight, uint32_t pBlockTime, uint32_t pTargetBits)
{
    const static BitCoin::Hash zeroHash;
    BitCoin::Block *newBlock = new BitCoin::Block();
    newBlock->time = pBlockTime;
    newBlock->targetBits = pTargetBits;
    if(pChain.height() == -1)
        newBlock->previousHash.zeroize();
    else
        newBlock->previousHash = pPreviousHash;
    newBlock->transactions.push_back(BitCoin::Transaction::createCoinbaseTransaction(pBlockHeight, 0, pCoinbaseKeyHash));
    newBlock->finalize();

    if(!pChain.addPendingBlock(newBlock))
    {
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, "Test", "Failed to add pending block %d : %s",
          pBlockHeight, newBlock->hash.hex().text());
        return zeroHash;
    }

    return newBlock->hash;
}

// Build blocks with zero difficulty and test chain reverts and branch switches
bool chainTest()
{
    // Highest target bits = 0x2100ffff
    uint32_t maxTargetBits = 0x2100ffff; // Genesis 0x203fffc0 ?
    BitCoin::Hash difficulty;
    difficulty.setDifficulty(maxTargetBits);
    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, "Test", "Min difficulty : %s", difficulty.hex().text());

    ArcMist::removeDirectory("chain_test");
    ArcMist::createDirectory("chain_test");
    BitCoin::setNetwork(BitCoin::MAINNET);
    BitCoin::Info::instance().setPath("chain_test");

    std::vector<BitCoin::Hash> branchHashes;
    int height = 0;
    BitCoin::Hash lastHash, preBranchHash;

    if(true)
    {
        BitCoin::Chain chain;
        chain.setMaxTargetBits(maxTargetBits); // zero difficulty (all block hashes are valid)
        chain.load(true);

        BitCoin::PrivateKey privateKey;
        privateKey.generate();
        BitCoin::PublicKey publicKey;
        privateKey.generatePublicKey(publicKey);
        BitCoin::Hash publicKeyHash;
        publicKey.getHash(publicKeyHash);

        // Genesis block time
        uint32_t time = chain.blockStats().time(0);

        // Add 2016 blocks
        for(unsigned int i=0;i<2016;++i)
        {
            if(addBlock(chain, chain.lastPendingBlockHash(), publicKeyHash, i + 1, time, maxTargetBits).isEmpty())
                return false;
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain work : %s", chain.accumulatedWork().hex().text());
            chain.process();
            time += 605; // a little over 10 minutes to adjust for the 2015 block skew so difficulty doesn't increase
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain previous last hash before branch : %s",
          chain.lastPendingBlockHash().hex().text());

        // Add a branch 5 blocks back
        int branchHeight = chain.height() - 5;
        BitCoin::Hash branchHash;
        chain.getBlockHash(branchHeight, branchHash);
        preBranchHash = branchHash;
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain hash before branch : %s", branchHash.hex().text());
        branchHash = addBlock(chain, branchHash, publicKeyHash, ++branchHeight, time, maxTargetBits);
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain work : %s", chain.accumulatedWork().hex().text());
        if(branchHash.isEmpty())
            return false;
        for(unsigned int j=0;j<20;++j)
            chain.process();
        time += 605;

        branchHashes.reserve(16);
        branchHashes.push_back(branchHash);

        // Extend the branch
        for(unsigned int i=0;i<20;++i)
        {
            branchHash = addBlock(chain, branchHash, publicKeyHash, ++branchHeight, time, maxTargetBits);
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain work : %s", chain.accumulatedWork().hex().text());
            if(branchHash.isEmpty())
                return false;
            branchHashes.push_back(branchHash);

            for(unsigned int j=0;j<20;++j)
                chain.process();
            time += 605; // a little over 10 minutes to adjust for the 2015 block skew so difficulty doesn't increase
        }

        for(unsigned int j=0;j<20;++j)
            chain.process();

        // Confirm the branch is the main chain now
        if(chain.lastBlockHash() != branchHash)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Chain last hash doesn't match branch");
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Last Hash   : %s", chain.lastBlockHash().hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Branch Hash : %s", branchHash.hex().text());
            return false;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Chain final last hash : %s",
          chain.lastBlockHash().hex().text());

        height = chain.height();
        lastHash = chain.lastBlockHash();

        if(!chain.save())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed to save chain");
            return false;
        }
    }

    BitCoin::Chain chain2;
    chain2.setMaxTargetBits(maxTargetBits); // zero difficulty (all block hashes are valid)

    if(!chain2.load(true))
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed to load chain2");
        return false;
    }

    ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Reloaded chain last hash : %s", chain2.lastBlockHash().hex().text());

    if(chain2.height() != height)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Reloaded height doesn't match : original %d != reloaded %d",
          height, chain2.height());
        return false;
    }

    ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed reloaded chain height");

    BitCoin::Hash hash;
    for(std::vector<BitCoin::Hash>::reverse_iterator branchHash=branchHashes.rbegin();branchHash!=branchHashes.rend();++branchHash)
    {
        chain2.getBlockHash(height, hash);
        if(hash != *branchHash)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Reloaded height %d hash doesn't match", height);
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Chain Hash  : %s", hash.hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Branch Hash : %s", branchHash->hex().text());
            return false;
        }
        --height;
    }

    ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed reloaded branch hashes");

    chain2.getBlockHash(height, hash);
    if(hash != preBranchHash)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Reloaded height %d hash doesn't match pre branch hash", height);
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Chain Hash      : %s", hash.hex().text());
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Pre Branch Hash : %s", preBranchHash.hex().text());
        return false;
    }

    ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed reloaded pre branch hash");

    if(!chain2.save())
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed to save reloaded");
        return false;
    }

    ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed chain test");
    return true;
}

// bool cashDAATest()
// {
    // // Highest target bits = 0x2100ffff
    // uint32_t maxTargetBits = 0x2100ffff; // Genesis 0x203fffc0 ?
    // BitCoin::Hash difficulty;
    // difficulty.setDifficulty(maxTargetBits);
    // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, "Test", "Min difficulty : %s", difficulty.hex().text());
    // bool success = true;

    // ArcMist::removeDirectory("cash_test");
    // ArcMist::createDirectory("cash_test");
    // BitCoin::setNetwork(BitCoin::MAINNET);
    // BitCoin::Info::instance().setPath("cash_test");

    // BitCoin::Chain chain;
    // chain.setMaxTargetBits(maxTargetBits); // zero difficulty (all block hashes are valid)
    // chain.load(true);




    // return true;
// }
