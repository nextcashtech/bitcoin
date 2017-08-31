#ifndef BITCOIN_NODE_HPP
#define BITCOIN_NODE_HPP

#include "arcmist/base/mutex.hpp"
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

        bool hasBlock(Hash &pHash)
        {
            mBlockHeaderHashMutex.lock();
            for(std::list<Hash>::iterator i=mBlockHeaderHashes.begin();i!=mBlockHeaderHashes.end();++i)
                if(*i == pHash)
                {
                    mBlockHeaderHashMutex.unlock();
                    return true;
                }
            mBlockHeaderHashMutex.unlock();
            return false;
        }
        void requestBlock(Hash &pHash);

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

        // List of pending block headers this node is known to have
        ArcMist::Mutex mBlockHeaderHashMutex;
        void addBlockHeaderHash(Hash &pHash);
        std::list<Hash> mBlockHeaderHashes;

        static unsigned int mNextID;

    };
}

#endif
