/**************************************************************************
 * Copyright 2017 NextCash, LLC                                           *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/

#ifdef PROFILER_ON
#include "profiler.hpp"
#endif

#include "string.hpp"
#include "math.hpp"
#include "hash.hpp"
#include "log.hpp"
#include "file_stream.hpp"
#include "buffer.hpp"
#include "network.hpp"
#include "endian.hpp"
#include "info.hpp"
#include "chain.hpp"
#include "daemon.hpp"

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <csignal>
#include <unistd.h>

#define MAIN_LOG_NAME "Main"


pid_t daemonPID(const char *pPath);
void printHelp(const char *pPath);

int main(int pArgumentCount, char **pArguments)
{
    bool nextIsPath = false;
    NextCash::String path;
    bool start = false;
    bool noDaemon = false;
    bool stop = false;
    bool validate = false;
    bool rebuild = false;
    bool listblocks = false;
    bool testnet = false;
    NextCash::String printBlock, address;
    bool nextIsPrintBlock = false;
    bool nextIsAddress = false;

    if(pArgumentCount < 2)
    {
        std::cerr << "Too few arguments" << std::endl;
        printHelp(path);
        return 1;
    }

    if(std::strcmp(pArguments[1], "start") == 0)
        start = true;
    else if(std::strcmp(pArguments[1], "stop") == 0)
        stop = true;
    else if(std::strcmp(pArguments[1], "validate") == 0)
        validate = true;
    else if(std::strcmp(pArguments[1], "rebuild") == 0)
        rebuild = true;
    else if(std::strcmp(pArguments[1], "listblocks") == 0)
        listblocks = true;
    else if(std::strcmp(pArguments[1], "printblock") == 0)
        nextIsPrintBlock = true;
    else if(std::strcmp(pArguments[1], "address") == 0)
        nextIsAddress = true;
    else if(std::strcmp(pArguments[1], "help") == 0)
    {
        printHelp(path);
        return 0;
    }
    else
    {
        printHelp(path);
        return 1;
    }

    for(int i=2;i<pArgumentCount;i++)
        if(nextIsPath)
        {
            path = pArguments[i];
            if(path[path.length()-1] != '/')
                path += "/";
            nextIsPath = false;
        }
        else if(nextIsPrintBlock)
        {
            printBlock = pArguments[i];
            nextIsPrintBlock = false;
        }
        else if(nextIsAddress)
        {
            address = pArguments[i];
            nextIsAddress = false;
        }
        else if(std::strcmp(pArguments[i], "-v") == 0)
            NextCash::Log::setLevel(NextCash::Log::VERBOSE);
        else if(std::strcmp(pArguments[i], "-vv") == 0)
            NextCash::Log::setLevel(NextCash::Log::DEBUG);
        else if(std::strcmp(pArguments[i], "--nodaemon") == 0)
            noDaemon = true;
        else if(std::strcmp(pArguments[i], "--path") == 0)
            nextIsPath = true;
        else if(std::strcmp(pArguments[i], "--testnet") == 0)
            testnet = true;
        else if(std::strcmp(pArguments[i], "--help") == 0 ||
          std::strcmp(pArguments[i], "-h") == 0)
        {
            printHelp(path);
            return 0;
        }
        else
        {
            std::cerr << "Unknown command line parameter : " << pArguments[i] << std::endl;
            printHelp(path);
            return 1;
        }

    if(testnet)
        BitCoin::setNetwork(BitCoin::TESTNET);
    else
        BitCoin::setNetwork(BitCoin::MAINNET);

    if(!path)
    {
        if(testnet)
            path = "/var/bitcoin/testnet/";
        else
            path = "/var/bitcoin/mainnet/";
    }

    NextCash::createDirectory(path);
    BitCoin::Info::setPath(path);

    if(printBlock)
    {
        BitCoin::Block block;
        BitCoin::BlockStats blockStats;
        BitCoin::Forks forks;

        if(!blockStats.load() || !forks.load(blockStats))
        {
            NextCash::Log::add(NextCash::Log::ERROR, MAIN_LOG_NAME,
              "Failed to load block stats or forks");
            return 1;
        }

        if(printBlock.length() == 64)
        {
            NextCash::Hash hash;
            BitCoin::Chain chain;
            chain.load(false);
            NextCash::Buffer buffer;
            buffer.writeHex(printBlock.text());
            hash.read(&buffer, 32);

            if(!chain.getBlock(hash, block))
            {
                NextCash::Log::add(NextCash::Log::ERROR, MAIN_LOG_NAME, "Failed to read block");
                return 1;
            }
        }
        else
        {
            unsigned int height = std::stol(printBlock.text());
            if(!BitCoin::BlockFile::readBlock(height, block))
            {
                NextCash::Log::addFormatted(NextCash::Log::ERROR, MAIN_LOG_NAME,
                  "Failed to find block at height %d", height);
                return 1;
            }
        }

        block.print(forks, NextCash::Log::INFO, false);
        return 0;
    }

    if(address)
    {
        NextCash::Log::addFormatted(NextCash::Log::INFO, MAIN_LOG_NAME,
          "Checking address : %s", address.text());

        NextCash::Hash keyHash;
        BitCoin::AddressType addressType;
        BitCoin::AddressFormat addressFormat;

        if(!BitCoin::decodeAddress(address.text(), keyHash, addressType, addressFormat))
            return 1;

        if(addressType != BitCoin::PUB_KEY_HASH)
        {
            NextCash::Log::add(NextCash::Log::INFO, MAIN_LOG_NAME,
              "Not a public key hash address");
            return 1;
        }

        NextCash::Log::addFormatted(NextCash::Log::INFO, MAIN_LOG_NAME,
          "Public key hash : %s", keyHash.hex().text());

        if(!keyHash.isEmpty())
        {
            BitCoin::Addresses addresses;
            BitCoin::TransactionOutputPool outputs;
            std::vector<BitCoin::FullOutputData> outputList;
            BitCoin::TransactionOutputPool::Iterator reference;
            BitCoin::OutputReference *outputReference;
            uint64_t balance = 0;
            addresses.load(BitCoin::Info::instance().path(), 0);
            outputs.load(BitCoin::Info::instance().path(), BitCoin::Info::instance().outputsThreshold);

            if(!addresses.getOutputs(keyHash, outputList))
                return false;

            // Print addresses
            for(std::vector<BitCoin::FullOutputData>::iterator output=outputList.begin();output!=outputList.end();++output)
            {
                output->print();
                reference = outputs.get(output->transactionID);
                if(reference)
                {
                    outputReference = ((BitCoin::TransactionReference *)*reference)->outputAt(output->index);
                    if(outputReference != NULL)
                    {
                        if(outputReference->spentBlockHeight == 0)
                        {
                            NextCash::Log::add(NextCash::Log::INFO, MAIN_LOG_NAME, "Unspent");
                            balance += output->output.amount;
                        }
                        else
                            NextCash::Log::addFormatted(NextCash::Log::INFO, MAIN_LOG_NAME,
                              "Spent at block height %d", outputReference->spentBlockHeight);
                    }
                    else
                    {
                        NextCash::Log::addFormatted(NextCash::Log::ERROR, MAIN_LOG_NAME,
                          "Transaction Output Reference not found : index %d - %s", output->index,
                          output->transactionID.hex().text());
                        return 1;
                    }
                }
                else
                {
                    NextCash::Log::addFormatted(NextCash::Log::ERROR, MAIN_LOG_NAME,
                      "Transaction Reference not found : %s", output->transactionID.hex().text());
                    return 1;
                }
            }

            NextCash::Log::addFormatted(NextCash::Log::INFO, MAIN_LOG_NAME,
              "Balance : %f bitcoins", BitCoin::bitcoins(balance));
        }

        return 0;
    }

    // These have to be static or they overflows the stack
    static BitCoin::Chain chain;

    if(listblocks)
    {
        NextCash::Log::setOutput(new NextCash::FileOutputStream(std::cout), true);
        if(chain.load(true))
            return 0;
        else
            return 1;
    }

    if(validate || rebuild)
    {
        NextCash::Log::setOutput(new NextCash::FileOutputStream(std::cout), true);
        if(!chain.validate(rebuild))
            return 1;

        // if(validate)
        // {
            // // Compare pool transaction outputs with those loaded from files
            // BitCoin::TransactionOutputPool savedPool;
            // if(!savedPool.load())
                // return 1;
            // pool.compare(savedPool, "Calculated", "Saved");
        // }

        return 0;
    }

    NextCash::String logFilePath = BitCoin::Info::path();
    logFilePath.pathAppend("logs");
    NextCash::createDirectory(logFilePath);
    logFilePath.pathAppend("daemon.log");
    NextCash::String pidFilePath = BitCoin::Info::path();
    pidFilePath.pathAppend("pid");

    if(stop)
    {
        NextCash::Log::addFormatted(NextCash::Log::INFO, MAIN_LOG_NAME, "PID file : %s", pidFilePath.text());
        pid_t killPID = daemonPID(pidFilePath.text());

        if(killPID == 0)
        {
            NextCash::Log::add(NextCash::Log::ERROR, MAIN_LOG_NAME, "PID not found");
            return 1;
        }

        NextCash::Log::addFormatted(NextCash::Log::INFO, MAIN_LOG_NAME, "Killing daemon PID %d", killPID);

        if(kill(killPID, SIGTERM) < 0)
        {
            NextCash::Log::add(NextCash::Log::ERROR, MAIN_LOG_NAME, "Kill PID failed. Deleting PID file");
            std::remove(pidFilePath.text());
        }

        return 0;
    }
    else if(!start)
    {
        printHelp(path);
        return 1;
    }

    NextCash::Log::addFormatted(NextCash::Log::INFO, MAIN_LOG_NAME, "Log file : %s", logFilePath.text());

    if(!noDaemon)
    {
        NextCash::Log::addFormatted(NextCash::Log::INFO, MAIN_LOG_NAME, "PID file : %s", pidFilePath.text());

        // Check if already running
        pid_t currentPID = daemonPID(pidFilePath.text());
        if(currentPID != 0)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, MAIN_LOG_NAME, "Daemon is already running under PID %d", currentPID);
            NextCash::Log::add(NextCash::Log::WARNING, MAIN_LOG_NAME, "Call with \"stop\" command");
            return 1;
        }
    }

    //TODO Move new connections to seperate thread

    pid_t pid = 0;

    if(!noDaemon)
    {
        pid = fork();

        if(pid < 0)
        {
            NextCash::Log::add(NextCash::Log::ERROR, MAIN_LOG_NAME, "Fork failed");
            return 1;
        }

        if(pid > 0)
            return 0; // The original process will return here

        // From here down is the forked child process
        pid = getpid();
        NextCash::Log::addFormatted(NextCash::Log::INFO, MAIN_LOG_NAME, "Daemon pid is %d", pid);

        if(setsid() < 0)
            return 1;
    }

    // Set up daemon to log to a file
    NextCash::Log::setOutputFile(logFilePath);

    // Write pid to file
    if(!noDaemon)
    {
        NextCash::FileOutputStream pidStream(pidFilePath.text(), true);
        pidStream.writeFormatted("%d", pid);
        pidStream.writeByte('\n');
    }

#ifdef PROFILER_ON
    NextCash::Profiler profiler("Main"); // Attempt to trigger destroy of profiler instance after daemon instance
#endif
    BitCoin::Daemon daemon;

    daemon.run(!noDaemon);

    if(!noDaemon)
        NextCash::removeFile(pidFilePath.text());

    return 0;
}

pid_t daemonPID(const char *pPath)
{
    NextCash::FileInputStream pidStream(pPath);
    if(!pidStream.isValid())
        return 0;
    NextCash::Buffer pidBuffer;
    uint8_t byte;
    while(pidStream.remaining())
    {
        byte = pidStream.readByte();
        if(NextCash::isWhiteSpace(byte))
            break;
        pidBuffer.writeByte(byte);
    }
    NextCash::String pidString = pidBuffer.readString(pidBuffer.length());
    if(!pidString)
        return 0;
    return std::stol(pidString.text());
}

void printHelp(const char *pPath)
{
    std::cerr << "Usage : bitcoin command [options]" << std::endl;
    std::cerr << "Commands :" << std::endl;
    std::cerr << "    help                            -> Display this message" << std::endl;
    std::cerr << "    start                           -> Start daemon" << std::endl;
    std::cerr << "    stop                            -> Stop active daemon" << std::endl;
    std::cerr << "    listblocks                      -> List hashes of all blocks" << std::endl;
    std::cerr << "    printblock BLOCKNUM or HASH     -> Display block information" << std::endl;
    std::cerr << "    address BASE_58_PUBKEYHASH      -> Display address information" << std::endl;
    std::cerr << "    validate                        -> Validate local block chain" << std::endl;
    std::cerr << "    rebuild                         -> Validate and rebuild unspent transactions from block chain" << std::endl;
    std::cerr << "Options :" << std::endl;
    std::cerr << "    --help or -h                    -> Display this message" << std::endl;
    std::cerr << "    --path PATH                     -> Specify directory for daemon files. Default : " << pPath << std::endl;
    std::cerr << "    --testnet                       -> Run on testnet instead of mainnet" << std::endl;
    std::cerr << "    --nodaemon                      -> Don't do daemon fork. (i.e. run in this process)" << std::endl;
    std::cerr << "    -v                              -> Verbose logging" << std::endl;
    std::cerr << "    -vv                             -> Debug logging" << std::endl;
    std::cerr << std::endl;
}
