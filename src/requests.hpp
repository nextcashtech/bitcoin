/**************************************************************************
 * Copyright 2017-2018 NextCash, LLC                                       *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_REQUESTS_HPP
#define BITCOIN_REQUESTS_HPP

#include "mutex.hpp"
#include "thread.hpp"
#include "network.hpp"
#include "buffer.hpp"

#include "chain.hpp"


namespace BitCoin
{
    class RequestChannel
    {
    public:

        RequestChannel(NextCash::Network::Connection *pConnection, Chain *pChain);
        ~RequestChannel();

        static void run();

        void requestStop();

        bool isStopped() { return mStopped; }

    private:

        void process();

        unsigned int mID;
        NextCash::String mName;
        NextCash::Thread *mThread;
        NextCash::Mutex mConnectionMutex;
        NextCash::Network::Connection *mConnection;
        NextCash::Buffer mReceiveBuffer;
        bool mStop, mStopped, mAuthenticated;

        int32_t mLastReceiveTime;
        int32_t mConnectedTime;

        Chain *mChain;

        static unsigned int mNextID;

        RequestChannel(const RequestChannel &pCopy);
        const RequestChannel &operator = (const RequestChannel &pRight);

    };
}

#endif
