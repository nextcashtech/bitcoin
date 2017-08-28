#include "node.hpp"

#include "arcmist/base/log.hpp"
#include "info.hpp"
#include "message.hpp"

#define NODE_LOG_NAME "Node"


namespace BitCoin
{
    unsigned int Node::mNextID = 256;

    Node::Node(IPAddress &pAddress)
    {
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mLastTime = 0;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        mVersionData = 0;
        mID = mNextID++;
        mAddress = pAddress;
        mReceiveBuffer.setInputEndian(ArcMist::Endian::LITTLE);
        mReceiveBuffer.setOutputEndian(ArcMist::Endian::LITTLE);

        if(!mConnection.open(AF_INET6, pAddress.ip, pAddress.port))
        {
            Info::instance().addPeerFail(pAddress);
            return;
        }

        sendVersion();
    }

    Node::Node(const char *pIP, const char *pPort)
    {
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mLastTime = 0;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        mVersionData = 0;
        mID = mNextID++;

        if(!mConnection.open(pIP, pPort))
        {
            mAddress = mConnection;
            Info::instance().addPeerFail(mAddress);
            return;
        }

        mAddress = mConnection;
        sendVersion();
    }

    Node::Node(unsigned int pFamily, const uint8_t *pIP, uint16_t pPort)
    {
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mLastTime = 0;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        mVersionData = 0;
        mID = mNextID++;

        if(!mConnection.open(pFamily, pIP, pPort))
        {
            mAddress = mConnection;
            Info::instance().addPeerFail(mAddress);
            return;
        }

        mAddress = mConnection;
        sendVersion();
    }

    void Node::clear()
    {
        mConnection.close();
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mLastTime = 0;
        mPingNonce = 0;
        mMinimumFeeRate = 0;
        if(mVersionData != 0)
            delete mVersionData;
        mVersionData = 0;
    }

    bool Node::versionSupported(int32_t pVersion)
    {
        // TODO Check version protocol
        return true;
    }

    void Node::sendMessage(Message::Data *pData)
    {
        ArcMist::Buffer send;
        Message::writeFull(pData, &send);
        mConnection.send(&send);
        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, NODE_LOG_NAME, "[%d] Sent <%s>", Message::nameFor(pData->type));
    }

    void Node::sendVersion()
    {
        Info &info = Info::instance();
        Message::VersionData versionMessage(mConnection.ipv6Bytes(), mConnection.port(), info.ip, info.port,
          info.fullMode, BlockChain::instance().blockCount(), info.fullMode);
        sendMessage(&versionMessage);
        mVersionSent = true;
    }

    void Node::sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason)
    {
        Message::RejectData rejectMessage(pCommand, pCode, pReason, NULL);
        sendMessage(&rejectMessage);
    }

    void Node::process()
    {
        if(!mConnection.isOpen() || !mConnection.receive(&mReceiveBuffer))
            return;

        // Check for a complete message
        Message::Data *message = Message::readFull(&mReceiveBuffer);
        bool dontDeleteMessage = false;

        if(message == NULL)
            return;

        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, NODE_LOG_NAME, "[%d] Received <%s>", Message::nameFor(message->type));
        mLastTime = time();

        switch(message->type)
        {
            case Message::VERSION:
            {
                if(mVersionData != NULL)
                {
                    sendReject(Message::nameFor(message->type), Message::RejectData::DUPLICATE, "");
                    break;
                }

                mVersionData = (Message::VersionData *)message;
                dontDeleteMessage = true;
                if(mVersionData->relay)
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, NODE_LOG_NAME, "[%d] Version : %s (%d), %d blocks, relay on",
                      mID, mVersionData->userAgent.text(), mVersionData->version, mVersionData->startBlockHeight);
                else
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, NODE_LOG_NAME, "[%d] Version : %s (%d), %d blocks, relay off",
                      mID, mVersionData->userAgent.text(), mVersionData->version, mVersionData->startBlockHeight);

                if(!versionSupported(mVersionData->version))
                    sendReject(Message::nameFor(message->type), Message::RejectData::PROTOCOL, "");

                //TODO Reject recent sent version nonces

                // Send version acknowledge
                Message::Data versionAcknowledgeMessage(Message::VERACK);
                sendMessage(&versionAcknowledgeMessage);
                mVersionAcknowledgeSent = true;

                // Update peer
                if(mVersionData->relay && mVersionAcknowledged)
                {
                    mAddress.updateTime();
                    mAddress.services = mVersionData->transmittingServices;
                    if(mAddress.port == 0)
                        mAddress.port = mVersionData->transmittingPort;
                    Info::instance().updatePeer(mAddress, mVersionData->userAgent);
                }

                break;
            }
            case Message::VERACK:
                mVersionAcknowledged = true;

                // Update peer
                if(mVersionData != NULL && mVersionData->relay)
                {
                    mAddress.updateTime();
                    mAddress.services = mVersionData->transmittingServices;
                    if(mAddress.port == 0)
                        mAddress.port = mVersionData->transmittingPort;
                    Info::instance().updatePeer(mAddress, mVersionData->userAgent);
                }
                break;

            case Message::PING:
            {
                Message::PongData pongData(((Message::PingData *)message)->nonce);
                sendMessage(&pongData);
                break;
            }
            case Message::PONG:
                if(mPingNonce != ((Message::PongData *)message)->nonce)
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, NODE_LOG_NAME, "[%d] Pong nonce doesn't match sent Ping", mID);
                break;

            case Message::REJECT:
            {
                Message::RejectData *rejectData = (Message::RejectData *)message;
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, NODE_LOG_NAME, "[%d] Reject %s [%02x] - %s", mID,
                  rejectData->command, rejectData->code, rejectData->reason);

                // TODO Determine if closing node is necessary
                break;
            }
            case Message::GET_ADDRESSES:
            {
                // Send known peer addresses
                Message::AddressesData addressData;
                std::vector<Peer *> peers;

                // Get list of peers
                Info::instance().randomizePeers(peers);

                unsigned int count = peers.size();
                if(count > 100) // Maximum of 100
                    count = 100;

                // Add peers to message
                addressData.addresses.resize(count);
                for(unsigned int i=0;i<count;i++)
                    addressData.addresses[i] = peers[i]->address;

                sendMessage(&addressData);
                break;
            }
            case Message::ADDRESSES:
            {
                Message::AddressesData *addressesData = (Message::AddressesData *)message;

                Info &info = Info::instance();
                for(unsigned int i=0;i<addressesData->addresses.size();i++)
                    info.updatePeer(addressesData->addresses[i], NULL);

                break;
            }
            case Message::ALERT:
                //TODO Determine if anything needs to be done for alerts
                break;

            case Message::FEE_FILTER:
                mMinimumFeeRate = ((Message::FeeFilterData *)message)->minimumFeeRate;
                ArcMist::Log::addFormatted(ArcMist::Log::WARNING, NODE_LOG_NAME, "[%d] Fee minimum rate set to %d", mID,
                  mMinimumFeeRate);
                break;

            case Message::FILTER_ADD:
                // TODO Implement FILTER_ADD
                break;

            case Message::FILTER_CLEAR:
                // TODO Implement FILTER_CLEAR
                break;

            case Message::FILTER_LOAD:
                // TODO Implement FILTER_LOAD
                break;

            case Message::SEND_HEADERS:
                mSendHeaders = true;
                break;

            case Message::GET_BLOCKS:
            {
                // Send Inventory of block headers
                Message::InventoryData inventoryData;
                std::vector<Peer *> peers;

                // Get list of peers
                Info::instance().randomizePeers(peers);

                unsigned int count = peers.size();
                if(count > 100) // Maximum of 100
                    count = 100;

                //TODO Add inventory to message
                //inventoryData.inventory.resize(count);
                //for(unsigned int i=0;i<count;i++)
                //    inventoryData.inventory[i] = ;

                sendMessage(&inventoryData);
                break;
            }
            case Message::BLOCK:
                // TODO Implement BLOCK
                break;

            case Message::GET_DATA:
                // TODO Implement GET_DATA
                break;

            case Message::GET_HEADERS:
                // TODO Implement GET_HEADERS
                break;

            case Message::HEADERS:
                // TODO Implement HEADERS
                break;

            case Message::INVENTORY:
                // TODO Implement INVENTORY
                break;

            case Message::MEM_POOL:
                // TODO Implement MEM_POOL
                break;

            case Message::MERKLE_BLOCK:
                // TODO Implement MERKLE_BLOCK
                break;

            case Message::NOT_FOUND:
                // TODO Implement NOT_FOUND
                break;

            case Message::TRANSACTION:
                // TODO Implement TRANSACTION
                break;

            case Message::UNKNOWN:
                break;
        }

        if(!dontDeleteMessage)
            delete message;
    }
}
