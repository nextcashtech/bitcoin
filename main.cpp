
#include "arcmist/base/string.hpp"
#include "arcmist/base/math.hpp"
#include "arcmist/base/log.hpp"
#include "arcmist/io/file_stream.hpp"
#include "arcmist/io/buffer.hpp"
#include "arcmist/io/network.hpp"
#include "arcmist/base/endian.hpp"
#include "message.hpp"
#include "info.hpp"
#include "node.hpp"
#include "daemon.hpp"

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <csignal>
#include <unistd.h>

#define MAIN_LOG_NAME "Main"


int main(int pArgumentCount, char **pArguments)
{
    ArcMist::Log::setLevel(ArcMist::Log::VERBOSE);
    bool nextIsPath = false, nextIsSeed = false, noDaemon = false;
    ArcMist::String path = "/home/curtis/Development/bcc_test/", seed;
    bool stop = false;

    for(int i=1;i<pArgumentCount;i++)
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
        else if(std::strcmp(pArguments[i], "--nodaemon") == 0)
            noDaemon = true;
        else if(std::strcmp(pArguments[i], "--path") == 0)
            nextIsPath = true;
        else if(std::strcmp(pArguments[i], "--seed") == 0)
            nextIsSeed = true;
        else if(std::strcmp(pArguments[i], "help") == 0 ||
          std::strcmp(pArguments[i], "--help") == 0 ||
          std::strcmp(pArguments[i], "-h") == 0)
        {
            std::cerr << "Usage :" << std::endl;
            std::cerr << "    help or --help or -h -> Display this message" << std::endl;
            std::cerr << "    --stop               -> Kill active daemon" << std::endl;
            std::cerr << "    --path PATH          -> Specify directory for daemon files. Default : " << path.text() << std::endl;
            std::cerr << "    --seed SEED_NAME     -> Start daemon and load peers from seed" << std::endl;
            std::cerr << "    --nodaemon           -> Don't perform daemon process fork" << std::endl;
            std::cerr << std::endl;
            return 0;
        }
        else if(std::strcmp(pArguments[i], "--stop") == 0)
            stop = true;

    BitCoin::Info::setPath(path);
    ArcMist::String logFilePath = BitCoin::Info::path() + "daemon.log";
    ArcMist::String pidFilePath = BitCoin::Info::path() + "pid";

    if(stop)
    {
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, MAIN_LOG_NAME, "PID file : %s", pidFilePath.text());
        pid_t kill_pid = 0;
        ArcMist::FileInputStream pidStream(pidFilePath.text());
        ArcMist::Buffer pidBuffer;
        uint8_t byte;
        while(pidStream.remaining())
        {
            byte = pidStream.readByte();
            if(byte == '\n')
                break;
            pidBuffer.writeByte(byte);
        }
        ArcMist::String pidString = pidBuffer.readString(pidBuffer.length());
        if(!pidString)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, MAIN_LOG_NAME, "Daemon pid not found");
            return 1;
        }
        kill_pid = std::stol(pidString.text());
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, MAIN_LOG_NAME, "Killing daemon pid %d", kill_pid);

        if(kill_pid == 0)
            return 1;

        if(kill(kill_pid, SIGTERM) < 0)
            ArcMist::Log::add(ArcMist::Log::INFO, MAIN_LOG_NAME, "Kill pid failed");

        return 0;
    }

    ArcMist::Log::addFormatted(ArcMist::Log::INFO, MAIN_LOG_NAME, "Log file : %s", logFilePath.text());
    if(!noDaemon)
        ArcMist::Log::addFormatted(ArcMist::Log::INFO, MAIN_LOG_NAME, "PID file : %s", pidFilePath.text());

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

    BitCoin::setNetwork(BitCoin::TESTNET);
    BitCoin::Daemon &daemon = BitCoin::Daemon::instance();

    // Set up daemon to log to a file
    ArcMist::FileOutputStream *logStream = new ArcMist::FileOutputStream(logFilePath.text(), true, false);
    ArcMist::Log::setOutput(logStream);

    // Write pid to file
    if(!noDaemon)
    {
        ArcMist::FileOutputStream pidStream(pidFilePath.text(), false, true);
        pidStream.writeFormatted("%d", pid);
        pidStream.writeByte('\n');
    }

    // "testnet-seed.bitcoin.jonasschnelli.ch"

    daemon.run(seed);

    if(!noDaemon)
        std::remove(pidFilePath.text());

    if(logStream)
        delete logStream;

    return 0;
}
