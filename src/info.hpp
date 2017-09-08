#ifndef BITCOIN_INFO_HPP
#define BITCOIN_INFO_HPP

#include "arcmist/base/string.hpp"
#include "arcmist/base/mutex.hpp"
#include "arcmist/io/buffer.hpp"
#include "base.hpp"
#include "block.hpp"

#include <cstdint>
#include <list>


namespace BitCoin
{
    class Info
    {
    public:

        static Info &instance();
        static void destroy();
        static void setPath(const char *pPath);
        static ArcMist::String path() { return sPath; }

        uint8_t *ip;
        uint16_t port;
        bool fullMode;
        uint32_t maxConnections;
        uint64_t minFee;

        // Return list of peers in random order
        void randomizePeers(std::vector<Peer *> &pPeers, int pMinimumRating);
        void updatePeer(IPAddress &pAddress, const char *pUserAgent);
        void addPeerFail(IPAddress &pAddress);

        void save();

        static bool test();

    protected:

        Info();
        ~Info();

        void readSettingsFile(const char *pPath);
        void applyValue(ArcMist::Buffer &pName, ArcMist::Buffer &pValue);

        void writeDataFile();

        void writePeersFile();
        void readPeersFile();

        // Peers
        bool mPeersModified;
        ArcMist::Mutex mPeerMutex;
        std::list<Peer *> mPeers;

        static ArcMist::String sPath;
        static Info *sInstance;
    };
}

#endif
