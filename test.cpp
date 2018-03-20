/**************************************************************************
 * Copyright 2017-2018 ArcMist, LLC                                       *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "message.hpp"
#include "key.hpp"
#include "transaction.hpp"
#include "interpreter.hpp"
#include "bloom_filter.hpp"
#include "chain.hpp"
#include "info.hpp"

#include "arcmist/base/log.hpp"

bool chainTest();
bool merkleTest1();
bool merkleTest2();

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

    if(!BitCoin::BloomFilter::test())
        failed++;

    if(!BitCoin::Chain::test())
        failed++;

    // if(!merkleTest1())
        // failed++;

    // if(!merkleTest2())
        // failed++;

    // BitCoin::Chain::tempTest();

    // if(!chainTest())
        // failed++;

    // if(!cashDAATest())
        // failed++;

    if(failed)
        return 1;
    else
        return 0;
}

bool merkleTest1()
{
    ArcMist::Log::add(ArcMist::Log::INFO, "Test", "------------- Starting Merkle Tree Test 1 -------------");
    BitCoin::setNetwork(BitCoin::MAINNET);
    BitCoin::Info::instance().setPath("/var/bitcoin/mainnet/");

    /***********************************************************************************************
     * Merkle block (Randomly chosen transaction)
     ***********************************************************************************************/
    BitCoin::Block block;

    if(!BitCoin::BlockFile::readBlock(515695, block))
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed read block %d", 515695);
        return false;
    }

    // Validate Merkle Hash
    ArcMist::Hash calculatedMerkleHash;
    block.calculateMerkleHash(calculatedMerkleHash);
    if(calculatedMerkleHash != block.merkleHash)
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed match merkle root hash");
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "  Block Hash : %s", block.merkleHash.hex().text());
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "  Calc Hash  : %s", calculatedMerkleHash.hex().text());
        return false;
    }

    BitCoin::BloomFilter filter(100);
    ArcMist::Hash addressHash;
    BitCoin::AddressType addressType;
    BitCoin::AddressFormat addressFormat;

    ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Created bloom filter with %d bytes and %d functions",
      filter.size(), filter.functionCount());

    if(!BitCoin::decodeAddress("1HPB2uYumdS6hSkpdaGxTMhqAypzT8SjeX", addressHash, addressType, addressFormat))
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed decode address : %s", "1HPB2uYumdS6hSkpdaGxTMhqAypzT8SjeX");
        return false;
    }

    filter.add(addressHash);

    BitCoin::MerkleNode *merkleTreeRoot = BitCoin::buildMerkleTree(block.transactions, filter);

    //merkleTreeRoot->print();

    if(merkleTreeRoot == NULL)
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed create merkle tree");
        return false;
    }
    else
        ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed create merkle tree");

    if(merkleTreeRoot->hash != block.merkleHash)
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed merkle tree hash");
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "  Merkle Hash : %s", block.merkleHash.hex().text());
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "  Merkle Tree : %s", merkleTreeRoot->hash.hex().text());
        return false;
    }
    else
        ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed merkle tree hash");

    if(!merkleTreeRoot->matches)
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed merkle tree match");
        return false;
    }
    else
        ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed merkle tree match");

    ArcMist::Hash transactionHash("98bde91934d6abc038e5162c583204c630e974f7cb9bf03daa8655d92e2d08d1"), foundHash;
    BitCoin::MerkleNode *node = merkleTreeRoot;
    bool found = false;

    while(node != NULL)
    {
        if(node->transaction != NULL)
        {
            foundHash = node->transaction->hash;
            if(node->transaction->hash == transactionHash)
                found = true;
            break;
        }

        if(node->left->matches)
            node = node->left;
        else if(node->right->matches)
            node = node->right;
        else
            break;
    }

    if(found)
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Passed merkle tree match found : %s", foundHash.hex().text());
    else
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed merkle tree match found : %s", foundHash.hex().text());
        return false;
    }

    // Check building merkle block message and parsing it
    std::vector<BitCoin::Transaction *> transactionsToSend;
    BitCoin::Message::MerkleBlockData merkleBlockMessage(&block, filter, transactionsToSend);

    found = false;
    for(std::vector<BitCoin::Transaction *>::iterator trans=transactionsToSend.begin();trans!=transactionsToSend.end();++trans)
        if((*trans)->hash == transactionHash)
        {
            found = true;
            break;
        }

    if(found)
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Passed merkle block message transaction found : %s",
          transactionHash.hex().text());
    else
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed merkle block message transaction found : %s",
          transactionHash.hex().text());
        return false;
    }

    BitCoin::Message::Interpreter interpreter;
    ArcMist::Buffer messageBuffer;

    interpreter.write(&merkleBlockMessage, &messageBuffer);

    BitCoin::Message::Data *messageData = interpreter.read(&messageBuffer, "Test");

    if(messageData == NULL)
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed merkle block message read");
        return false;
    }
    else if(messageData->type != BitCoin::Message::MERKLE_BLOCK)
    {
        delete messageData;
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed merkle block message read type");
        return false;
    }

    ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed merkle block message read");

    BitCoin::Message::MerkleBlockData *message = (BitCoin::Message::MerkleBlockData *)messageData;

    ArcMist::HashList confirmedTransactionHashes;
    if(message->validate(confirmedTransactionHashes))
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Passed merkle block message validate : %d trans",
          confirmedTransactionHashes.size());
    }
    else
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed merkle block message validate");
        delete messageData;
        return false;
    }

    if(confirmedTransactionHashes.contains(transactionHash))
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Passed merkle block message transaction confirmed : %s",
          transactionHash.hex().text());
    else
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed merkle block message transaction confirmed : %s",
          transactionHash.hex().text());
        delete messageData;
        return false;
    }

    delete messageData;
    return true;
}

bool merkleTest2()
{
    ArcMist::Log::add(ArcMist::Log::INFO, "Test", "------------- Starting Merkle Tree Test 2 -------------");

    /***********************************************************************************************
     * Merkle block (Randomly chosen transaction)
     ***********************************************************************************************/
    BitCoin::Block block;

    if(!BitCoin::BlockFile::readBlock(515712, block))
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed read block %d", 515712);
        return false;
    }

    // Validate Merkle Hash
    ArcMist::Hash calculatedMerkleHash;
    block.calculateMerkleHash(calculatedMerkleHash);
    if(calculatedMerkleHash != block.merkleHash)
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed match merkle root hash");
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "  Block Hash : %s", block.merkleHash.hex().text());
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "  Calc Hash  : %s", calculatedMerkleHash.hex().text());
        return false;
    }

    BitCoin::BloomFilter filter(100);
    ArcMist::Hash addressHash;
    BitCoin::AddressType addressType;
    BitCoin::AddressFormat addressFormat;

    ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Created bloom filter with %d bytes and %d functions",
      filter.size(), filter.functionCount());

    if(!BitCoin::decodeAddress("1Ff79dW4CymX2msdyat4SbTupCG1d6imib", addressHash, addressType, addressFormat))
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed decode address : %s", "1Ff79dW4CymX2msdyat4SbTupCG1d6imib");
        return false;
    }

    filter.add(addressHash);

    BitCoin::MerkleNode *merkleTreeRoot = BitCoin::buildMerkleTree(block.transactions, filter);

    if(merkleTreeRoot == NULL)
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed create merkle tree");
        return false;
    }
    else
        ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed create merkle tree");

    if(merkleTreeRoot->hash != block.merkleHash)
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed merkle tree hash");
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "  Merkle Hash : %s", block.merkleHash.hex().text());
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "  Merkle Tree : %s", merkleTreeRoot->hash.hex().text());
        return false;
    }
    else
        ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed merkle tree hash");

    if(!merkleTreeRoot->matches)
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed merkle tree match");
        return false;
    }
    else
        ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed merkle tree match");

    ArcMist::Hash transactionHash("a13a63717ef85e88973ee54a9d86794e27a913784d45bfa6e3f659cf03db32e6"), foundHash;
    BitCoin::MerkleNode *node = merkleTreeRoot;
    bool found = false;

    while(node != NULL)
    {
        if(node->transaction != NULL)
        {
            foundHash = node->transaction->hash;
            if(node->transaction->hash == transactionHash)
                found = true;
            break;
        }

        if(node->left->matches)
            node = node->left;
        else if(node->right->matches)
            node = node->right;
        else
            break;
    }

    if(found)
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Passed merkle tree match found : %s", foundHash.hex().text());
    else
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed merkle tree match found : %s", foundHash.hex().text());
        return false;
    }

    // Check building merkle block message and parsing it
    std::vector<BitCoin::Transaction *> transactionsToSend;
    BitCoin::Message::MerkleBlockData merkleBlockMessage(&block, filter, transactionsToSend);

    found = false;
    for(std::vector<BitCoin::Transaction *>::iterator trans=transactionsToSend.begin();trans!=transactionsToSend.end();++trans)
        if((*trans)->hash == transactionHash)
        {
            found = true;
            break;
        }

    if(found)
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Passed merkle block message transaction found : %s",
          transactionHash.hex().text());
    else
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed merkle block message transaction found : %s",
          transactionHash.hex().text());
        return false;
    }

    BitCoin::Message::Interpreter interpreter;
    ArcMist::Buffer messageBuffer;

    interpreter.write(&merkleBlockMessage, &messageBuffer);

    BitCoin::Message::Data *messageData = interpreter.read(&messageBuffer, "Test");

    if(messageData == NULL)
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed merkle block message read");
        return false;
    }
    else if(messageData->type != BitCoin::Message::MERKLE_BLOCK)
    {
        delete messageData;
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed merkle block message read type");
        return false;
    }

    ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed merkle block message read");

    BitCoin::Message::MerkleBlockData *message = (BitCoin::Message::MerkleBlockData *)messageData;

    ArcMist::HashList confirmedTransactionHashes;
    if(message->validate(confirmedTransactionHashes))
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Passed merkle block message validate : %d trans",
          confirmedTransactionHashes.size());
    }
    else
    {
        ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed merkle block message validate");
        delete messageData;
        return false;
    }

    if(confirmedTransactionHashes.contains(transactionHash))
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Passed merkle block message transaction confirmed : %s",
          transactionHash.hex().text());
    else
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed merkle block message transaction confirmed : %s",
          transactionHash.hex().text());
        delete messageData;
        return false;
    }

    delete messageData;
    return true;
}

const ArcMist::Hash &addBlock(BitCoin::Chain &pChain, const ArcMist::Hash &pPreviousHash, const ArcMist::Hash &pCoinbaseKeyHash,
  int pBlockHeight, uint32_t pBlockTime, uint32_t pTargetBits, ArcMist::Hash &pTransactionID)
{
    const static ArcMist::Hash zeroHash;
    BitCoin::Block *newBlock = new BitCoin::Block();
    newBlock->time = pBlockTime;
    newBlock->targetBits = pTargetBits;
    if(pChain.height() == -1)
        newBlock->previousHash.zeroize();
    else
        newBlock->previousHash = pPreviousHash;
    newBlock->transactions.push_back(BitCoin::Transaction::createCoinbaseTransaction(pBlockHeight, 0, pCoinbaseKeyHash));
    pTransactionID = newBlock->transactions.front()->hash;
    newBlock->finalize();

    if(!pChain.addPendingBlock(newBlock))
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed to add pending block %d : %s",
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
    ArcMist::Hash difficulty;
    difficulty.setDifficulty(maxTargetBits);
    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, "Test", "Min difficulty : %s", difficulty.hex().text());

    ArcMist::removeDirectory("chain_test");
    ArcMist::createDirectory("chain_test");
    BitCoin::setNetwork(BitCoin::MAINNET);
    BitCoin::Info::instance().setPath("chain_test");

    std::vector<ArcMist::Hash> branchHashes;
    int height = 0;
    ArcMist::Hash lastHash, preBranchHash, transactionID;
    ArcMist::HashList transactionHashes;
    ArcMist::Hash publicKeyHash;
    std::vector<BitCoin::FullOutputData> coinbaseOutputs;
    std::vector<BitCoin::FullOutputData>::iterator fullOutput;
    BitCoin::Key privateKey;

    if(true)
    {
        BitCoin::Chain chain;
        chain.setMaxTargetBits(maxTargetBits); // zero difficulty (all block hashes are valid)
        chain.load(true);

        privateKey.generatePrivate(BitCoin::MAINNET);

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Using coinbase payment address : %s", privateKey.hash().hex().text());

        // Genesis block time
        uint32_t time = chain.blockStats().time(0);

        // Add 2016 blocks
        for(unsigned int i=0;i<2016;++i)
        {
            if(addBlock(chain, chain.lastPendingBlockHash(), privateKey.hash(), i + 1, time, maxTargetBits, transactionID).isEmpty())
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed to add block");
                return false;
            }
            transactionHashes.push_back(transactionID);
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain work : %s", chain.accumulatedWork().hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain pending work : %s", chain.pendingAccumulatedWork().hex().text());
            chain.process();
            time += 605; // a little over 10 minutes to adjust for the 2015 block skew so difficulty doesn't increase
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain previous last hash before branch : %s",
          chain.lastPendingBlockHash().hex().text());

        // Add a branch 5 blocks back
        int branchHeight = chain.height() - 5;
        ArcMist::Hash branchHash;
        chain.getBlockHash(branchHeight, branchHash);
        preBranchHash = branchHash;
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain hash before branch : %s", branchHash.hex().text());
        branchHash = addBlock(chain, branchHash, privateKey.hash(), ++branchHeight, time, maxTargetBits, transactionID);
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain work : %s", chain.accumulatedWork().hex().text());
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain pending work : %s", chain.pendingAccumulatedWork().hex().text());
        const BitCoin::Branch *branch;
        for(unsigned int i=0;i<chain.branchCount();++i)
        {
            branch = chain.branchAt(i);
            if(branch == NULL)
                break;
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test",
              "Branch %d work: %s", i + 1, branch->accumulatedWork.hex().text());
        }
        if(branchHash.isEmpty())
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed to add branch block");
            return false;
        }
        for(unsigned int j=0;j<20;++j)
            chain.process();
        time += 605;

        branchHashes.reserve(16);
        branchHashes.push_back(branchHash);

        // Extend the branch
        for(unsigned int i=0;i<20;++i)
        {
            branchHash = addBlock(chain, branchHash, privateKey.hash(), ++branchHeight, time, maxTargetBits, transactionID);
            if(branchHash.isEmpty())
            {
                ArcMist::Log::add(ArcMist::Log::ERROR, "Test", "Failed to add branch block");
                return false;
            }
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain work : %s", chain.accumulatedWork().hex().text());
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Main chain pending work : %s", chain.pendingAccumulatedWork().hex().text());
            for(unsigned int i=0;i<chain.branchCount();++i)
            {
                branch = chain.branchAt(i);
                if(branch == NULL)
                    break;
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test",
                  "Branch %d work: %s", i + 1, branch->accumulatedWork.hex().text());
            }
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

        chain.addresses().getOutputs(publicKeyHash, coinbaseOutputs);

        if(coinbaseOutputs.size() == (unsigned int)chain.height())
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, "Test", "Passed transaction address output count : %d", coinbaseOutputs.size());
        else
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed transaction address output count : %d != %d",
              coinbaseOutputs.size(), chain.height());
            return false;
        }

        unsigned int checkCount = 0;
        for(fullOutput=coinbaseOutputs.begin();fullOutput!=coinbaseOutputs.end() && checkCount<transactionHashes.size();++fullOutput)
            if(transactionHashes.contains(fullOutput->transactionID))
                ++checkCount;

        if(checkCount == transactionHashes.size())
            ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed transaction address outputs check");
        else
        {
            ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed transaction address output trans ID for block %d : %s",
              fullOutput->blockHeight, fullOutput->transactionID.hex().text());
            return false;
        }

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

    ArcMist::Hash hash;
    for(std::vector<ArcMist::Hash>::reverse_iterator branchHash=branchHashes.rbegin();branchHash!=branchHashes.rend();++branchHash)
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

    chain2.addresses().getOutputs(privateKey.hash(), coinbaseOutputs);

    if(coinbaseOutputs.size() == (unsigned int)chain2.height())
        ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed transaction address output count after save");
    else
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed transaction address output count after save : %d != %d",
          coinbaseOutputs.size(), chain2.height());
        return false;
    }

    unsigned int checkCount = 0;
    for(fullOutput=coinbaseOutputs.begin();fullOutput!=coinbaseOutputs.end() && checkCount<transactionHashes.size();++fullOutput)
        if(transactionHashes.contains(fullOutput->transactionID))
            ++checkCount;

    if(checkCount == transactionHashes.size())
        ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed transaction address outputs check");
    else
    {
        ArcMist::Log::addFormatted(ArcMist::Log::ERROR, "Test", "Failed transaction address output trans ID after save for block %d : %s",
          fullOutput->blockHeight, fullOutput->transactionID.hex().text());
        return false;
    }

    ArcMist::Log::add(ArcMist::Log::INFO, "Test", "Passed transaction address outputs check after save");

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
