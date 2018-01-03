/**************************************************************************
 * Copyright 2017-2018 ArcMist, LLC                                       *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_REQUESTS_HPP
#define BITCOIN_REQUESTS_HPP

#include "arcmist/base/mutex.hpp"
#include "arcmist/base/thread.hpp"
#include "arcmist/io/network.hpp"
#include "arcmist/io/buffer.hpp"

#include "chain.hpp"


namespace BitCoin
{
    class RequestChannel
    {
    public:

        RequestChannel(ArcMist::Network::Connection *pConnection, Chain *pChain);
        ~RequestChannel();

        static void run();

        void requestStop();

        bool isStopped() { return mStopped; }

    private:

        void process();

        ArcMist::Thread *mThread;
        ArcMist::Mutex mConnectionMutex;
        ArcMist::Network::Connection *mConnection;
        ArcMist::Buffer mReceiveBuffer;
        bool mStop, mStopped, mAuthenticated;

        int32_t mLastReceiveTime;
        int32_t mConnectedTime;

        Chain *mChain;

        RequestChannel(const RequestChannel &pCopy);
        const RequestChannel &operator = (const RequestChannel &pRight);

    };
}

#endif
