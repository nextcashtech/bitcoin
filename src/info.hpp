/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
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
    void notify(const char *pSubject, const char *pMessage);

    class Peer
    {
    public:

        Peer() { rating = 0; }
        Peer(const Peer &pCopy)
        {
            time = pCopy.time;
            services = pCopy.services;
            userAgent = pCopy.userAgent;
            rating = pCopy.rating;
            address = pCopy.address;
        }

        void write(ArcMist::OutputStream *pStream) const;
        bool read(ArcMist::InputStream *pStream);

        void updateTime() { time = getTime(); }

        Peer &operator = (const Peer &pRight)
        {
            time = pRight.time;
            services = pRight.services;
            userAgent = pRight.userAgent;
            rating = pRight.rating;
            address = pRight.address;
            return *this;
        }

        uint32_t time;
        uint64_t services;
        ArcMist::String userAgent;
        int32_t rating;
        IPAddress address;
    };

    class Info
    {
    public:

        static Info &instance();
        static void destroy();
        static void setPath(const char *pPath);
        static ArcMist::String path() { return sPath; }

        uint8_t *ip;
        uint16_t port;
        bool spvMode;

        // Maximum number of connections incoming and outgoing
        uint32_t maxConnections;

        // Maximum size in bytes/block count to download and save while waiting for processing
        uint32_t pendingSizeThreshold;
        uint32_t pendingBlocksThreshold;

        // Amount of memory to use to cache transaction outputs. Will build to double this, then save and reduce cache.
        uint32_t outputsThreshold;

        // Amount of memory to use for transaction outputs before saving to file
        uint32_t addressesThreshold;

        // Minimum fee for transaction mem pool (Satoshis per KB)
        uint64_t minFee;

        // The size of the mem pool (unconfirmed transactions) at which they start getting dropped
        uint32_t memPoolThreshold;

        // Number of merkle blocks for same block header required from different peers to confirm a block's transactions
        //   More than one required to prevent data withholding.
        unsigned int merkleBlockCountRequired;

        // Number of peers that an unconfirmed transaction must be announced from before it has zero confirm trust.
        unsigned int spvMemPoolCountRequired;

        ArcMist::String notifyEmail;

        // Return list of peers in random order
        void getRandomizedPeers(std::vector<Peer *> &pPeers, int pMinimumRating, uint64_t mServicesRequiredMask = 0);
        void updatePeer(const IPAddress &pAddress, const char *pUserAgent, uint64_t pServices);
        void addPeerFail(const IPAddress &pAddress, int pCount = 1);

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
        ArcMist::ReadersLock mPeerLock;
        std::list<Peer *> mPeers;

        static ArcMist::String sPath;
        static Info *sInstance;

    private:
        Info(const Info &pCopy);
        const Info &operator = (const Info &pRight);
    };
}

#endif
