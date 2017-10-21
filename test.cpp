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
    //     failed++;

    if(failed)
        return 1;
    else
        return 0;
}

bool addBlock(BitCoin::Chain &pChain, const BitCoin::Hash &pCoinbaseKeyHash, uint32_t pBlockTime, uint32_t pTargetBits)
{
    int originalHeight = pChain.blockHeight();

    BitCoin::Block *newBlock = new BitCoin::Block();
    newBlock->time = pBlockTime;
    newBlock->targetBits = pTargetBits;
    if(pChain.blockHeight() == -1)
        newBlock->previousHash.zeroize();
    else
        newBlock->previousHash = pChain.lastBlockHash();
    newBlock->transactions.push_back(BitCoin::ScriptInterpreter::createCoinbaseTransaction(pChain.blockHeight() + 1,
      pCoinbaseKeyHash));
    newBlock->finalize();

    if(!pChain.addPendingBlock(newBlock))
    {
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, "Test", "Failed to add pending block %d : %s",
          pChain.blockHeight() + 1, newBlock->hash.hex().text());
        return false;
    }

    pChain.process();
    return originalHeight + 1 == pChain.blockHeight();
}

// Build blocks with zero difficulty and test chain reverts and branch switches
bool chainTest()
{
    BitCoin::Hash difficulty;
    difficulty.setDifficulty(0x2100ffff);
    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, "Test", "Min difficulty : %s", difficulty.hex().text());

    ArcMist::removeDirectory("chain_test");
    ArcMist::createDirectory("chain_test");
    BitCoin::Info::instance().setPath("chain_test");

    BitCoin::Chain chain;
    chain.setMaxTargetBits(0x2100ffff); // zero difficulty (all block hashes are valid)
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
        if(!addBlock(chain, publicKeyHash, time, 0x2100ffff))
            return false;
        time += 610; // a little over 10 minutes to adjust for the 2015 block skew so difficulty doesn't increase
    }

    return true;
}
