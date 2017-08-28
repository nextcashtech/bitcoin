#ifndef BITCOIN_NODE_HPP
#define BITCOIN_NODE_HPP

#include "arcmist/io/buffer.hpp"
#include "arcmist/io/network.hpp"
#include "base.hpp"
#include "message.hpp"

#include <cstdint>


namespace BitCoin
{
    class Node
    {
    public:

        Node(const char *pIP, const char *pPort);
        Node(unsigned int pFamily, const uint8_t *pIP, uint16_t pPort);
        Node(IPAddress &pAddress);
        ~Node() { clear(); }

        unsigned int id() { return mID; }
        bool isOpen() { return mConnection.isOpen(); }

        void process();
        void clear();

    private:

        bool versionSupported(int32_t pVersion);

        void sendMessage(Message::Data *pData);
        void sendVersion();
        void sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason);

        unsigned int mID;
        IPAddress mAddress;
        ArcMist::Connection mConnection;
        ArcMist::Buffer mReceiveBuffer;
        
        Message::VersionData *mVersionData;
        bool mVersionSent, mVersionAcknowledged, mVersionAcknowledgeSent, mSendHeaders;
        uint64_t mLastTime;
        uint64_t mPingNonce;
        uint64_t mMinimumFeeRate;

        static unsigned int mNextID;

    };
}

#endif
