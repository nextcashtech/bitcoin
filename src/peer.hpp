/**************************************************************************
 * Copyright 2018 NextCash, LLC                                           *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_PEER_HPP
#define BITCOIN_PEER_HPP

#include "string.hpp"
#include "network.hpp"
#include "base.hpp"


namespace BitCoin
{
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

        void write(NextCash::OutputStream *pStream) const;
        bool read(NextCash::InputStream *pStream);

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

        int32_t time;
        uint64_t services;
        NextCash::String userAgent;
        int32_t rating;
        IPAddress address;
    };
}

#endif
