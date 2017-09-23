/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_NODE_HPP
#define BITCOIN_NODE_HPP

#include "arcmist/base/mutex.hpp"
#include "arcmist/base/thread.hpp"
#include "arcmist/io/buffer.hpp"
#include "arcmist/io/network.hpp"
#include "base.hpp"
#include "message.hpp"
#include "chain.hpp"

#include <cstdint>
#include <list>


namespace BitCoin
{
    class BlockHashInfo
    {
    public:
        BlockHashInfo(const Hash &pHash, unsigned int pHeight)
        {
            hash = pHash;
            height = pHeight;
        }

        Hash hash;
        unsigned int height;

    private:
        BlockHashInfo(BlockInfo &pCopy);
        BlockHashInfo &operator = (BlockInfo &pRight);
    };

    class Node
    {
    public:

        Node(ArcMist::Network::Connection *pConnection, Chain *pChain, bool pIncoming, bool pIsSeed = false);
        ~Node();

        static void run();

        unsigned int id() { return mID; }
        bool isOpen();
        void close();

        void process(Chain &pChain);

        void requestStop();

        bool isIncoming() const { return mIsIncoming; }

        // Time that the node connected
        uint32_t connectedTime() { return mConnectedTime; }
        // Last time a message was received from this peer
        uint32_t lastReceiveTime() { return mLastReceiveTime; }

        unsigned int blockHeight() { if(mVersionData == NULL) return 0; else return mVersionData->startBlockHeight; }

        // Check if node should be closed
        void check(Chain &pChain);

        bool waitingForRequests() { return mBlocksRequested.size() > 0 || !mHeaderRequested.isEmpty(); }
        bool requestHeaders(Chain &pChain, const Hash &pStartingHash);
        bool requestBlocks(Chain &pChain, unsigned int pCount, bool pReduceOnly);
        unsigned int blocksRequestedCount() { return mBlocksRequested.size(); }
        void releaseBlockRequests();

        // Send notification of a new block on the chain
        bool announceBlock(const Hash &pHash, Chain &pChain);

        // Send notification of a new transaction in the mempool
        //TODO Make this send periodically with a list. Filter list to remove transaction inventory received from node
        bool announceTransaction(const Hash &pHash);

        const IPAddress &address() { return mAddress; }

        // Add statistics to collection and clear them
        void collectStatistics(Statistics &pCollection);

    private:

        int mSocketID;

        Message::Interpreter mMessageInterpreter;

        bool sendMessage(Message::Data *pData);
        bool sendVersion(Chain &pChain);
        bool sendPing();
        bool sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason);
        bool sendBlock(Block &pBlock);

        unsigned int mID;
        ArcMist::String mName;
        ArcMist::Thread *mThread;
        IPAddress mAddress;
        Chain *mChain;
        ArcMist::Mutex mConnectionMutex;
        ArcMist::Network::Connection *mConnection;
        ArcMist::Buffer mReceiveBuffer;
        Statistics mStatistics;
        bool mStop, mStopped;
        bool mIsIncoming, mIsSeed;
        bool mSendBlocksCompact;

        Message::VersionData *mVersionData;
        bool mVersionSent, mVersionAcknowledged, mVersionAcknowledgeSent, mSendHeaders;
        uint32_t mLastReceiveTime;
        uint32_t mLastPingTime;
        uint64_t mLastPingNonce;
        uint32_t mPingRoundTripTime;
        uint64_t mMinimumFeeRate;

        Hash mHeaderRequested;
        uint32_t mHeaderRequestTime;

        ArcMist::Mutex mBlockRequestMutex;
        HashList mBlocksRequested;
        uint32_t mBlockRequestTime;

        bool mConnected;
        uint32_t mConnectedTime;
        unsigned int mMessagesReceived;

        static unsigned int mNextID;

        Node(const Node &pCopy);
        const Node &operator = (const Node &pRight);

    };
}

#endif
