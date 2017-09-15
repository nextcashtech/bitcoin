
#include "arcmist/base/string.hpp"
#include "arcmist/base/math.hpp"
#include "arcmist/base/log.hpp"
#include "arcmist/io/file_stream.hpp"
#include "arcmist/io/buffer.hpp"
#include "arcmist/io/network.hpp"
#include "arcmist/base/endian.hpp"
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
    bool nextIsPath = false, nextIsSeed = false;
    ArcMist::String path, seed;
    bool start = false;
    bool noDaemon = false;
    bool stop = false;
    bool validate = false;
    bool rebuild = false;
    bool listblocks = false;
    bool testnet = false;
    ArcMist::String printBlock;
    bool nextIsPrintBlock = false;

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
    else //if(std::strcmp(pArguments[1], "help") == 0)
    {
        printHelp(path);
        return 0;
    }

    for(int i=2;i<pArgumentCount;i++)
        if(nextIsPath)
        {
            path = pArguments[i];
            if(path[path.length()-1] != '/')
                path += "/";
            nextIsPath = false;
        }
        else if(nextIsSeed)
        {
            seed = pArguments[i];
            nextIsSeed = false;
        }
        else if(nextIsPrintBlock)
        {
            printBlock = pArguments[i];
            nextIsPrintBlock = false;
        }
        else if(std::strcmp(pArguments[i], "-v") == 0)
            ArcMist::Log::setLevel(ArcMist::Log::VERBOSE);
        else if(std::strcmp(pArguments[i], "-vv") == 0)
            ArcMist::Log::setLevel(ArcMist::Log::DEBUG);
        else if(std::strcmp(pArguments[i], "--nodaemon") == 0)
            noDaemon = true;
        else if(std::strcmp(pArguments[i], "--path") == 0)
            nextIsPath = true;
        else if(std::strcmp(pArguments[i], "--testnet") == 0)
            testnet = true;
        else if(std::strcmp(pArguments[i], "--seed") == 0)
            nextIsSeed = true;
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
            return 0;
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

    ArcMist::createDirectory(path);
    BitCoin::Info::setPath(path);

    if(printBlock)
    {
        BitCoin::Chain chain;
        BitCoin::Hash hash;
        BitCoin::Block block;

        if(printBlock.length() == 32)
        {
            ArcMist::Buffer buffer;
            buffer.writeString(printBlock.text(), printBlock.length());
            hash.read(&buffer, 32);
        }
        else
        {
            unsigned int height = std::stol(printBlock.text());
            if(!chain.getBlockHash(height, hash))
            {
                ArcMist::Log::addFormatted(ArcMist::Log::ERROR, MAIN_LOG_NAME,
                  "Failed to find hash at height %d", height);
                return 1;
            }

            ArcMist::Log::addFormatted(ArcMist::Log::INFO, MAIN_LOG_NAME,
              "Found hash at height %d : %s", height, hash.hex().text());
        }

        BitCoin::UnspentPool unspentPool;
        chain.load(unspentPool, false);

        if(chain.getBlock(hash, block))
        {
            block.print(ArcMist::Log::INFO);
            return 0;
        }
        else
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, MAIN_LOG_NAME, "Failed to read block");
            return 1;
        }
    }

    // These have to be static or they overflows the stack
    static BitCoin::Chain chain;
    static BitCoin::UnspentPool unspentPool;

    if(listblocks)
    {
        ArcMist::Log::setOutput(new ArcMist::FileOutputStream(std::cout), true);
        if(chain.load(unspentPool, true))
            return 0;
        else
            return 1;
    }

    if(validate || rebuild)
    {
        ArcMist::Log::setOutput(new ArcMist::FileOutputStream(std::cout), true);
        if(!chain.validate(unspentPool, rebuild))
            return 1;

        if(validate)
        {
            // Compare unspentPool with those loaded from files
            BitCoin::UnspentPool savedUnspentPool;
            if(!savedUnspentPool.load())
                return 1;
            unspentPool.compare(savedUnspentPool, "Calculated", "Saved");
        }

        return 0;
    }

    ArcMist::String logFilePath = BitCoin::Info::path();
    logFilePath.pathAppend("logs");
    ArcMist::createDirectory(logFilePath);
    logFilePath.pathAppend("daemon.log");
    ArcMist::String pidFilePath = BitCoin::Info::path();
    pidFilePath.pathAppend("pid");

    if(stop)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, MAIN_LOG_NAME, "PID file : %s", pidFilePath.text());
        pid_t killPID = daemonPID(pidFilePath.text());

        if(killPID == 0)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, MAIN_LOG_NAME, "PID not found");
            return 1;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, MAIN_LOG_NAME, "Killing daemon PID %d", killPID);

        if(kill(killPID, SIGTERM) < 0)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, MAIN_LOG_NAME, "Kill PID failed. Deleting PID file");
            std::remove(pidFilePath.text());
        }

        return 0;
    }
    else if(!start)
    {
        printHelp(path);
        return 1;
    }

    ArcMist::Log::addFormatted(ArcMist::Log::INFO, MAIN_LOG_NAME, "Log file : %s", logFilePath.text());

    if(!noDaemon)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, MAIN_LOG_NAME, "PID file : %s", pidFilePath.text());

        // Check if already running
        pid_t currentPID = daemonPID(pidFilePath.text());
        if(currentPID != 0)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, MAIN_LOG_NAME, "Daemon is already running under PID %d", currentPID);
            ArcMist::Log::add(ArcMist::Log::WARNING, MAIN_LOG_NAME, "Call with \"stop\" command");
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
            ArcMist::Log::add(ArcMist::Log::ERROR, MAIN_LOG_NAME, "Fork failed");
            return 1;
        }

        if(pid > 0)
            return 0; // The original process will return here

        // From here down is the forked child process
        pid = getpid();
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, MAIN_LOG_NAME, "Daemon pid is %d", pid);

        if(setsid() < 0)
            return 1;
    }

    BitCoin::Daemon &daemon = BitCoin::Daemon::instance();

    // Set up daemon to log to a file
    ArcMist::Log::setOutputFile(logFilePath);

    // Write pid to file
    if(!noDaemon)
    {
        ArcMist::FileOutputStream pidStream(pidFilePath.text(), true);
        pidStream.writeFormatted("%d", pid);
        pidStream.writeByte('\n');
    }

    // "testnet-seed.bitcoin.jonasschnelli.ch"
    // seed.tbtc.petertodd.org
    // testnet-seed.bluematt.me
    // testnet-seed.bitcoin.schildbach.de

    daemon.run(seed, !noDaemon);

    if(!noDaemon)
        ArcMist::removeFile(pidFilePath.text());

    return 0;
}

pid_t daemonPID(const char *pPath)
{
    ArcMist::FileInputStream pidStream(pPath);
    if(!pidStream.isValid())
        return 0;
    ArcMist::Buffer pidBuffer;
    uint8_t byte;
    while(pidStream.remaining())
    {
        byte = pidStream.readByte();
        if(ArcMist::isWhiteSpace(byte))
            break;
        pidBuffer.writeByte(byte);
    }
    ArcMist::String pidString = pidBuffer.readString(pidBuffer.length());
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
    std::cerr << "    validate                        -> Validate local block chain" << std::endl;
    std::cerr << "    rebuild                         -> Validate and rebuild unspent transactions from block chain" << std::endl;
    std::cerr << "Options :" << std::endl;
    std::cerr << "    --help or -h                    -> Display this message" << std::endl;
    std::cerr << "    --path PATH                     -> Specify directory for daemon files. Default : " << pPath << std::endl;
    std::cerr << "    --seed SEED_NAME                -> Start daemon and load peers from seed" << std::endl;
    std::cerr << "    --testnet                       -> Run on testnet instead of mainnet" << std::endl;
    std::cerr << "    --nodaemon                      -> Don't do daemon fork. (i.e. run in this process)" << std::endl;
    std::cerr << "    -v                              -> Verbose logging" << std::endl;
    std::cerr << "    -vv                             -> Debug logging" << std::endl;
    std::cerr << std::endl;
}
