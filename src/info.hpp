/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_INFO_HPP
#define BITCOIN_INFO_HPP

#include "string.hpp"
#include "mutex.hpp"
#include "buffer.hpp"
#include "base.hpp"
#include "peer.hpp"
#include "block.hpp"

#include <cstdint>
#include <list>


namespace BitCoin
{
    void notify(const char *pSubject, const char *pMessage);

    class Info
    {
    public:

        static Info &instance();
        static void destroy();
        static void setPath(const char *pPath);
        static NextCash::String path() { return sPath; }

        uint8_t ip[INET6_ADDRLEN];
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

        NextCash::String notifyEmail;

        // Return list of peers in random order
        void getRandomizedPeers(std::vector<Peer *> &pPeers, int pMinimumRating, uint64_t mServicesRequiredMask = 0);
        bool addPeer(const IPAddress &pAddress, uint64_t pServices);
        void updatePeer(const IPAddress &pAddress, const char *pUserAgent, uint64_t pServices);
        void addPeerSuccess(const IPAddress &pAddress, int pCount = 1);
        void addPeerFail(const IPAddress &pAddress, int pCount = 1, int pMinimum = -500);

        bool initialBlockDownloadIsComplete() { return mInitialBlockDownloadComplete; }
        void setInitialBlockDownloadComplete()
        {
            if(!mInitialBlockDownloadComplete)
            {
                mInitialBlockDownloadComplete = true;
                mDataModified = true;
            }
        }

        bool load();
        void save();

        static bool test();

    protected:

        Info();
        ~Info();

        void readSettingsFile(NextCash::InputStream *pStream);
        void applyValue(NextCash::Buffer &pName, NextCash::Buffer &pValue);

        void writeDataFile();
        bool readDataFile();

        void writePeersFile();
        bool readPeersFile();

        // Peers
        bool mPeersModified;
        NextCash::ReadersLock mPeerLock;
        std::list<Peer *> mPeers;

        static NextCash::String sPath;
        static Info *sInstance;
        static NextCash::MutexWithConstantName sMutex;

    private:
        Info(const Info &pCopy);
        const Info &operator = (const Info &pRight);

        bool mDataModified;
        bool mInitialBlockDownloadComplete;
    };
}

#endif
