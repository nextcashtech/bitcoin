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
    bool testnet = false;

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
    std::cerr << "Options :" << std::endl;
    std::cerr << "    --help or -h                    -> Display this message" << std::endl;
    std::cerr << "    --path PATH                     -> Specify directory for daemon files. Default : " << pPath << std::endl;
    std::cerr << "    --testnet                       -> Run on testnet instead of mainnet" << std::endl;
    std::cerr << "    --nodaemon                      -> Don't do daemon fork. (i.e. run in this process)" << std::endl;
    std::cerr << "    -v                              -> Verbose logging" << std::endl;
    std::cerr << "    -vv                             -> Debug logging" << std::endl;
    std::cerr << std::endl;
}
