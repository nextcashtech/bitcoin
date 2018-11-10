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

        // Maximum number of connections incoming and outgoing.
        uint32_t maxConnections;

        // Maximum size in bytes/block count to download and save while waiting for processing.
        NextCash::stream_size pendingSize;
        uint32_t pendingBlocks;

        // Amount of memory to use to cache transaction output data.
        NextCash::stream_size outputsCacheSize;
        // Amount of additional memory to use before saving and trimming the outputs data cache.
        NextCash::stream_size outputsCacheDelta;

        // Amount of memory to use for transaction outputs before saving to file.
        NextCash::stream_size addressesCacheSize;

        // Lowest fee that will be accepted into the mem pool (Satoshis per KB).
        uint64_t minFee;

        // When the mem pool size reaches the memPoolLowFeeSize, fees below lowFee will be dropped
        //   to keep the size under memPoolLowFeeSize. The mem pool size can only grow above
        //   memPoolLowFeeSize with all fees above lowFee.
        NextCash::stream_size memPoolLowFeeSize;
        uint64_t lowFee; // (Satoshis per KB).

        // When the mem pool size reaches the memPoolSize, the lowest fee/oldest transactions will
        //   be dropped to keep the size under memPoolSize.
        NextCash::stream_size memPoolSize;

        // Number of merkle blocks per block required from different peers to confirm a block's
        //   transactions.
        // More than one required to prevent data withholding.
        uint8_t merkleBlockCountRequired;

        // Number of peers that an unconfirmed transaction must be announced from before it has
        //   zero confirm trust.
        unsigned int spvMemPoolCountRequired;

        // Number of threads used to process and save data.
        unsigned int threadCount;

        // The block header hash of the highest pre-approved block. During IBD all blocks below
        //   this will not be fully validated. They will just be processed to update UTXOs and
        //   the address database.
        NextCash::Hash approvedHash;

        // Email address to send notifications to.
        NextCash::String notifyEmail;

        // Return list of peers in random order
        void getRandomizedPeers(std::vector<Peer *> &pPeers, int pMinimumRating,
          uint64_t mServicesRequiredMask = 0, int pMaximumRating = 500000);
        bool addPeer(const NextCash::IPAddress &pAddress, uint64_t pServices);
        void updatePeer(const NextCash::IPAddress &pAddress, const char *pUserAgent, uint64_t pServices);
        void addPeerSuccess(const NextCash::IPAddress &pAddress, int pCount = 1);
        void addPeerFail(const NextCash::IPAddress &pAddress, int pCount = 1, int pMinimum = -500);

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
