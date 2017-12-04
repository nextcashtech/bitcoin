/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "node.hpp"

#include "arcmist/base/log.hpp"
#include "arcmist/crypto/digest.hpp"
#include "info.hpp"
#include "message.hpp"
#include "block.hpp"
#include "chain.hpp"

#define BITCOIN_NODE_LOG_NAME "Node"


namespace BitCoin
{
    unsigned int Node::mNextID = 256;

    Node::Node(ArcMist::Network::Connection *pConnection, Chain *pChain, bool pIncoming, bool pIsSeed) : mID(mNextID++),
      mConnectionMutex("Node Connection"), mBlockRequestMutex("Node Block Request"), mAnnounceMutex("Node Announce")
    {
        mIsIncoming = pIncoming;
        mConnected = false;
        mVersionSent = false;
        mVersionAcknowledged = false;
        mVersionAcknowledgeSent = false;
        mSendHeaders = false;
        mMinimumFeeRate = 0;
        mVersionData = NULL;
        mID = mNextID++;
        mHeaderRequestTime = 0;
        mBlockRequestTime = 0;
        mBlockReceiveTime = 0;
        mLastReceiveTime = getTime();
        mLastCheckTime = getTime();
        mLastBlackListCheck = getTime();
        mLastPingNonce = 0;
        mLastPingTime = 0;
        mPingRoundTripTime = -1;
        mPingCutoff = 30;
        mBlockDownloadCount = 0;
        mBlockDownloadSize = 0;
        mBlockDownloadTime = 0;
        mMessagesReceived = 0;
        mPingCount = 0;
        mConnectedTime = getTime();
        mStop = false;
        mStopped = false;
        mIsSeed = pIsSeed;
        mSendBlocksCompact = false;
        mThread = NULL;
        mSocketID = -1;

        mChain = pChain;

        if(mIsIncoming)
            mName.writeFormatted("Node i[%d]", mID);
        else
            mName.writeFormatted("Node o[%d]", mID);

        // Verify connection
        mConnectionMutex.lock();
        mConnection = pConnection;
        mSocketID = pConnection->socket();
        if(!mIsIncoming)
            mAddress = *mConnection;
        if(!mConnection->isOpen())
        {
            mConnectionMutex.unlock();
            mStopped = true;
            if(!mIsSeed && !mIsIncoming)
                Info::instance().addPeerFail(mAddress);
            return;
        }
        mConnected = true;
        mConnectionMutex.unlock();
        if(mIsIncoming)
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Incoming Connection %s : %d (socket %d)",
              mConnection->ipv6Address(), mConnection->port(), mSocketID);
        else
            ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Outgoing Connection %s : %d (socket %d)",
              mConnection->ipv6Address(), mConnection->port(), mSocketID);

        // Start thread
        mThread = new ArcMist::Thread(mName, run, this);
        ArcMist::Thread::sleep(500); // Give the thread a chance to initialize
    }

    Node::~Node()
    {
        if(mConnected)
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Disconnecting (socket %d)", mSocketID);
        if(!mMessageInterpreter.pendingBlockHash.isEmpty())
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
              "Dropped block in progress %d KiB (%d secs) : %s", mReceiveBuffer.length() / 1024,
              mMessageInterpreter.pendingBlockUpdateTime - mMessageInterpreter.pendingBlockStartTime,
              mMessageInterpreter.pendingBlockHash.hex().text());

        requestStop();
        if(mThread != NULL)
            delete mThread;
        mConnectionMutex.lock();
        if(mConnection != NULL)
            delete mConnection;
        mConnectionMutex.unlock();
        if(mVersionData != NULL)
            delete mVersionData;
    }

    bool Node::isOpen()
    {
        mConnectionMutex.lock();
        bool result = mConnection != NULL && mConnection->isOpen();
        mConnectionMutex.unlock();
        return result;
    }

    double Node::blockDownloadBytesPerSecond() const
    {
        if(mBlockDownloadSize == 0 || mBlockDownloadTime == 0)
            return 0.0;
        return (double)mBlockDownloadSize / (double)mBlockDownloadTime;
    }

    void Node::close()
    {
        mConnectionMutex.lock();
        if(mConnection != NULL)
            mConnection->close();
        mConnectionMutex.unlock();
        requestStop();
        mChain->releaseBlocksForNode(mID);
        mChain->memPool().releaseForNode(mID);
    }

    void Node::releaseBlockRequests()
    {
        mBlockRequestMutex.lock();
        mBlocksRequested.clear();
        mBlockRequestMutex.unlock();
        mChain->releaseBlocksForNode(mID);
    }

    void Node::requestStop()
    {
        releaseBlockRequests();
        if(mThread == NULL)
            return;
        mStop = true;
    }

    void Node::collectStatistics(Statistics &pCollection)
    {
        mConnectionMutex.lock();
        mStatistics.bytesReceived += mConnection->bytesReceived();
        mStatistics.bytesSent += mConnection->bytesSent();
        mConnection->resetByteCounts();
        mConnectionMutex.unlock();
        pCollection += mStatistics;
        mStatistics.clear();
    }

    void Node::check()
    {
        if(!isOpen())
            return;

        if(mIsSeed && getTime() - mConnectedTime > 120)
        {
            ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Seed connected for too long");
            close();
            return;
        }

        if(mPingRoundTripTime == -1 && getTime() - mConnectedTime > 120)
        {
            ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. No pong within 120 seconds of connection");
            close();
            return;
        }

        if(!mIsIncoming && !mChain->isInSync())
        {
            uint32_t time = getTime();

            if(mBlocksRequested.size() > 0 && time - mBlockRequestTime > 30 && time - mBlockReceiveTime > 30)
            {
                if(mMessageInterpreter.pendingBlockUpdateTime == 0) // Haven't started receiving blocks 30 seconds after requesting
                {
                    ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. No block for 30 seconds");
                    Info::instance().addPeerFail(mAddress);
                    close();
                    return;
                }

                if(time - mMessageInterpreter.pendingBlockUpdateTime > 30) // Haven't received more of the block in the last 60 seconds
                {
                    ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. No update on block for 30 seconds");
                    Info::instance().addPeerFail(mAddress);
                    close();
                    return;
                }
            }

            if(!mHeaderRequested.isEmpty() && time - mHeaderRequestTime > 180)
            {
                ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Not providing headers");
                Info::instance().addPeerFail(mAddress);
                close();
                return;
            }

            if(mLastReceiveTime != 0 && time - mLastReceiveTime > 1200)
            {
                ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Not responding");
                Info::instance().addPeerFail(mAddress);
                close();
                return;
            }
        }
    }

    bool Node::sendMessage(Message::Data *pData)
    {
        if(!isOpen())
            return false;

        ArcMist::Buffer send;
        mMessageInterpreter.write(pData, &send);
        mConnectionMutex.lock();
        bool success = mConnection->send(&send);
        mConnectionMutex.unlock();
        if(success)
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName, "Sent <%s>", Message::nameFor(pData->type));
        else
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Failed to send <%s>", Message::nameFor(pData->type));
            close(); // Disconnect
        }
        return success;
    }

    bool Node::requestHeaders()
    {
        if(!isOpen() || mIsIncoming || waitingForRequests())
            return false;

        if(mLastHeaderRequested == mChain->lastPendingBlockHash())
            return false;

        HashList hashes;
        if(!mChain->getReverseBlockHashes(hashes, 5))
            return false;

        Message::GetHeadersData getHeadersData;
        for(HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
            getHeadersData.blockHeaderHashes.push_back(**hash);

        ArcMist::Log::add(ArcMist::Log::VERBOSE, mName, "Sending header request");
        bool success = sendMessage(&getHeadersData);
        if(success)
        {
            mHeaderRequested = *hashes.back();
            mLastHeaderRequested = *hashes.back();
            mHeaderRequestTime = getTime();
        }
        return success;
    }

    bool Node::requestBlocks(HashList &pList)
    {
        if(pList.size() == 0 || !isOpen() || mIsIncoming || mIsSeed)
            return false;

        // Put block hashes into block request message
        Message::GetDataData getDataData;
        for(HashList::iterator hash=pList.begin();hash!=pList.end();++hash)
            getDataData.inventory.push_back(new Message::InventoryHash(Message::InventoryHash::BLOCK, **hash));

        bool success = sendMessage(&getDataData);
        if(success)
        {
            mBlockRequestMutex.lock();
            mBlocksRequested.clear();
            for(HashList::iterator hash=pList.begin();hash!=pList.end();++hash)
                mBlocksRequested.push_back(new Hash(**hash));
            mBlockRequestTime = getTime();
            mBlockRequestMutex.unlock();
            mChain->markBlocksForNode(pList, mID);
            if(pList.size() == 1)
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Sending request for block at (%d) : %s",
                  mChain->blockHeight(*pList.front()), pList.front()->hex().text());
            else
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Sending request for %d blocks starting at (%d) : %s",
                  pList.size(), mChain->blockHeight(*pList.front()), pList.front()->hex().text());
        }
        else
        {
            // Clear requested blocks
            mBlockRequestMutex.lock();
            mBlocksRequested.clear();
            mBlockRequestMutex.unlock();
            mChain->releaseBlocksForNode(mID);
        }

        return success;
    }

    bool Node::hasTransaction(const Hash &pHash)
    {
        mAnnounceMutex.lock();
        bool result = mAnnounceTransactions.contains(pHash);
        mAnnounceMutex.unlock();
        return result;
    }

    bool Node::requestTransactions(HashList &pList)
    {
        if(pList.size() == 0 || !isOpen() || mIsIncoming || mIsSeed)
            return false;

        // Put transaction hashes into transaction request message
        Message::GetDataData getDataData;
        for(HashList::iterator hash=pList.begin();hash!=pList.end();++hash)
            getDataData.inventory.push_back(new Message::InventoryHash(Message::InventoryHash::TRANSACTION, **hash));

        bool success = sendMessage(&getDataData);
        if(success)
        {
            mChain->memPool().markForNode(pList, mID);
            if(pList.size() == 1)
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName, "Sending request for transaction %s",
                  pList.front()->hex().text());
            else
                ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName, "Sending request for %d transactions starting with %s",
                  pList.size(), pList.front()->hex().text());
        }
        else
            mChain->memPool().releaseForNode(mID);

        return success;
    }

    bool Node::requestPeers()
    {
        ArcMist::Log::add(ArcMist::Log::INFO, mName, "Sending peer request");
        Message::Data getAddresses(Message::GET_ADDRESSES);
        return sendMessage(&getAddresses);
    }

    bool Node::sendBlock(Block &pBlock)
    {
        if(!isOpen())
            return false;

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Sending block : %s", pBlock.hash.hex().text());
        Message::BlockData blockData;
        blockData.block = &pBlock;
        bool success = sendMessage(&blockData);
        if(success)
            ++mStatistics.blocksSent;
        blockData.block = NULL; // We don't want to delete the block when the message is deleted
        return success;
    }

    bool Node::announceBlock(Block *pBlock)
    {
        if(!isOpen() || mVersionData == NULL || !mVersionData->relay)
            return false;

        mAnnounceMutex.lock();
        if(mAnnounceBlocks.contains(pBlock->hash))
        {
            // Don't announce to node that already announced to you
            mAnnounceMutex.unlock();
            return false;
        }
        mAnnounceMutex.unlock();

        //TODO if(mSendBlocksCompact)
        // {
            // //TODO  Send CompactBlockData
            // //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
            // //  "Announcing block with compact : %s", pBlock->hash.hex().text());
            // return false;
        // }
        // else

        if(mSendHeaders)
        {
            // Send the header
            Message::HeadersData headersData;
            headersData.headers.push_back(pBlock);
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName,
              "Announcing block with header : %s", pBlock->hash.hex().text());
            bool success = sendMessage(&headersData);
            if(success)
                mStatistics.headersSent += headersData.headers.size();
            headersData.headers.clearNoDelete(); // We don't want to delete pBlock since it will be reused
            return success;
        }
        else
        {
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName,
              "Announcing block with hash : %s", pBlock->hash.hex().text());
            Message::InventoryData inventoryData;
            inventoryData.inventory.push_back(new Message::InventoryHash(Message::InventoryHash::BLOCK, pBlock->hash));
            return sendMessage(&inventoryData);
        }
    }

    bool Node::announceTransaction(Transaction *pTransaction)
    {
        if(mVersionData == NULL || !mVersionData->relay)
            return false;

        mAnnounceMutex.lock();
        if(mAnnounceTransactions.contains(pTransaction->hash))
        {
            // Don't announce to node that already announced to you
            mAnnounceMutex.unlock();
            return false;
        }
        mAnnounceMutex.unlock();

        // Check against minimum fee rate
        if(pTransaction->feeRate() < mMinimumFeeRate)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName,
              "Not announcing transaction fee rate %d below min rate %d : %s", pTransaction->feeRate(),
              mMinimumFeeRate, pTransaction->hash.hex().text());
            return false;
        }

        // ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
          // "Announcing transaction with fee rate %d above min rate %d : %s", pTransaction->feeRate(),
          // mMinimumFeeRate, pTransaction->hash.hex().text());
        Message::InventoryData inventoryData;
        inventoryData.inventory.push_back(new Message::InventoryHash(Message::InventoryHash::TRANSACTION, pTransaction->hash));
        return sendMessage(&inventoryData);
    }

    bool Node::sendVersion()
    {
        if(!isOpen())
            return false;

        Info &info = Info::instance();
        Message::VersionData versionMessage(mConnection->ipv6Bytes(), mConnection->port(), info.ip,
          info.port, info.fullMode, mChain->forks().cashActive(), mChain->height(), info.fullMode && (!mIsIncoming && !mIsSeed));
        bool success = sendMessage(&versionMessage);
        mVersionSent = true;
        return success;
    }

    bool Node::sendPing()
    {
        uint32_t time = getTime();
        if(time - mLastPingTime < 60)
            return true;
        Message::PingData pingData;
        bool success = sendMessage(&pingData);
        if(success)
        {
            mLastPingNonce = pingData.nonce;
            mLastPingTime = time;
        }
        return success;
    }

    bool Node::sendFeeFilter()
    {
        Message::FeeFilterData feeData;
        feeData.minimumFeeRate = Info::instance().minFee;
        return sendMessage(&feeData);
    }

    bool Node::sendReject(const char *pCommand, Message::RejectData::Code pCode, const char *pReason)
    {
        if(!isOpen())
            return false;

        ArcMist::Log::addFormatted(ArcMist::Log::INFO, BITCOIN_NODE_LOG_NAME, "Sending reject : %s", pReason);
        Message::RejectData rejectMessage(pCommand, pCode, pReason, NULL);
        return sendMessage(&rejectMessage);
    }

    void Node::run()
    {
        Node *node = (Node *)ArcMist::Thread::getParameter();
        if(node == NULL)
        {
            ArcMist::Log::add(ArcMist::Log::ERROR, BITCOIN_NODE_LOG_NAME, "Thread parameter is null. Stopping");
            return;
        }

        ArcMist::String name = node->mName;

        if(node->mStop)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, name, "Node stopped before thread started");
            node->mStopped = true;
            return;
        }

        node->sendVersion();

        while(!node->mStop)
        {
            node->process();

            if(node->mStop)
                break;

            ArcMist::Thread::sleep(100);
        }

        node->mStopped = true;
    }

    void Node::addAnnouncedBlock(const Hash &pHash)
    {
        mAnnounceMutex.lock();
        if(!mAnnounceBlocks.contains(pHash))
        {
            // Keep list at 1024 or less
            if(mAnnounceBlocks.size() > 1024)
                mAnnounceBlocks.erase(mAnnounceBlocks.begin());
            mAnnounceBlocks.push_back(new Hash(pHash));
        }
        mAnnounceMutex.unlock();
    }

    void Node::addAnnouncedTransaction(const Hash &pHash)
    {
        mAnnounceMutex.lock();
        if(!mAnnounceTransactions.contains(pHash))
        {
            // Keep list at 1024 or less
            if(mAnnounceTransactions.size() > 1024)
                mAnnounceTransactions.erase(mAnnounceTransactions.begin());
            mAnnounceTransactions.push_back(new Hash(pHash));
        }
        mAnnounceMutex.unlock();
    }

    void Node::process()
    {
        int32_t time = getTime();
        if(time - mLastCheckTime > 10)
            check();

        mConnectionMutex.lock();
        if(mConnection == NULL)
        {
            mConnectionMutex.unlock();
            return;
        }

        if(!mConnection->isOpen())
        {
            mConnectionMutex.unlock();
            return;
        }
        mConnection->receive(&mReceiveBuffer);
        mConnectionMutex.unlock();

        if(mVersionData != NULL && mVersionAcknowledged && mLastPingTime != 0 &&
          mPingRoundTripTime == -1 && mPingCutoff != -1 &&
          time - mLastPingTime > mPingCutoff)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, mName,
              "Dropping. Ping not received within cutoff of %ds", mPingCutoff);
            Info::instance().addPeerFail(mAddress);
            close();
            return;
        }

        if(time - mLastBlackListCheck > 10)
        {
            mLastBlackListCheck = time;
            for(HashList::iterator hash=mAnnounceTransactions.begin();hash!=mAnnounceTransactions.end();++hash)
                if(mChain->memPool().isBlackListed(**hash))
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, mName,
                      "Dropping. Detected black listed transaction : %s", (*hash)->hex().text());
                    Info::instance().addPeerFail(mAddress);
                    close();
                    return;
                }
        }

        // Check for a complete message
        Message::Data *message = mMessageInterpreter.read(&mReceiveBuffer, mName);
        bool dontDeleteMessage = false;

        if(message == NULL)
        {
            if(mMessagesReceived == 0 && time - mConnectedTime > 60)
            {
                ArcMist::Log::add(ArcMist::Log::WARNING, mName, "No valid messages within 60 seconds of connecting");
                close();
                if(!mIsSeed)
                    Info::instance().addPeerFail(mAddress);
                return;
            }

            if(time - mLastReceiveTime > 600) // 10 minutes
                sendPing();

            if(!mMessageInterpreter.pendingBlockHash.isEmpty() && mMessageInterpreter.pendingBlockUpdateTime != 0)
                mChain->updateBlockProgress(mMessageInterpreter.pendingBlockHash, mID, mMessageInterpreter.pendingBlockUpdateTime);

            return;
        }

        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName, "Received <%s>", Message::nameFor(message->type));
        mLastReceiveTime = time;

        if(mMessagesReceived < 2 && message->type != Message::VERSION && message->type != Message::VERACK &&
          message->type != Message::REJECT)
        {
            ArcMist::Log::addFormatted(ArcMist::Log::WARNING, mName, "First 2 messages not a version and verack : <%s>",
              Message::nameFor(message->type));
            close();
            if(!mIsSeed)
                Info::instance().addPeerFail(mAddress);
            delete message;
            return;
        }

        ++mMessagesReceived;

        if(mMessagesReceived > 500)
        {
            ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Reached message limit");
            close();
        }

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

                ArcMist::String timeText;
                timeText.writeFormattedTime(mVersionData->time);
                ArcMist::String versionText;
                versionText.writeFormatted("Version : %s (%d), %d blocks", mVersionData->userAgent.text(),
                  mVersionData->version, mVersionData->startBlockHeight);
                if(mVersionData->relay)
                    versionText += ", relay";
                if(mVersionData->transmittingServices & Message::VersionData::FULL_NODE_BIT)
                    versionText += ", full";
                if(mVersionData->transmittingServices & Message::VersionData::CASH_NODE_BIT)
                    versionText += ", cash";
                versionText += ", time ";
                versionText += timeText;
                ArcMist::Log::add(ArcMist::Log::INFO, mName, versionText);

                std::memcpy(mAddress.ip, mVersionData->transmittingIPv6, 16);
                mAddress.port = mVersionData->transmittingPort;
                mMessageInterpreter.version = mVersionData->version;

                // Require full node bit for outgoing nodes
                if(!mIsIncoming && !mIsSeed && !(mVersionData->transmittingServices & Message::VersionData::FULL_NODE_BIT))
                {
                    sendReject(Message::nameFor(message->type), Message::RejectData::PROTOCOL,
                      "Full node bit (0x01) required in protocol version");
                    ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Missing full node bit");
                    Info::instance().addPeerFail(mAddress);
                    close();
                }
                else if(!mIsIncoming && !mIsSeed && mChain->forks().cashActive() &&
                  !(mVersionData->transmittingServices & Message::VersionData::CASH_NODE_BIT))
                {
                    sendReject(Message::nameFor(message->type), Message::RejectData::PROTOCOL,
                      "Cash node bit (0x20) required in protocol version");
                    ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Missing cash node bit");
                    Info::instance().addPeerFail(mAddress);
                    close();
                }
                else if(!mIsIncoming && !mIsSeed && !mChain->isInSync() && (mVersionData->startBlockHeight < 0 ||
                  mVersionData->startBlockHeight < mChain->height()))
                {
                    ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Low block height");
                    close();
                }
                else
                {
                    // Send version acknowledge
                    Message::Data versionAcknowledgeMessage(Message::VERACK);
                    sendMessage(&versionAcknowledgeMessage);
                    mVersionAcknowledgeSent = true;

                    if(mIsSeed)
                        requestPeers(); // Request addresses from the
                    else if(mVersionAcknowledged)
                    {
                        if(!mIsIncoming)
                            sendFeeFilter();
                        sendPing();
                    }
                }
                break;
            }
            case Message::VERACK:
                mVersionAcknowledged = true;
                if(mVersionData != NULL)
                {
                    if(!mIsIncoming)
                        sendFeeFilter();
                    sendPing();
                }
                break;
            case Message::PING:
            {
                ++mPingCount;
                Message::PongData pongData(((Message::PingData *)message)->nonce);
                sendMessage(&pongData);

                if(mPingCount > 100)
                {
                    ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Reached ping limit");
                    close();
                }
                break;
            }
            case Message::PONG:
                if(((Message::PongData *)message)->nonce != 0 && mLastPingNonce != ((Message::PongData *)message)->nonce)
                {
                    ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Pong nonce doesn't match sent Ping");
                    close();
                }
                else
                {
                    if(mPingRoundTripTime == -1)
                    {
                        mPingRoundTripTime = time - mLastPingTime;
                        if(!mIsIncoming && !mIsSeed && mPingCutoff != -1)
                        {
                            if(mPingRoundTripTime > mPingCutoff)
                            {
                                ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName,
                                  "Dropping. Ping time %ds not within cutoff of %ds", mPingRoundTripTime, mPingCutoff);
                                close();
                            }
                            else if(mVersionData != NULL && !mIsIncoming && !mIsSeed)
                            {
                                Info::instance().updatePeer(mAddress, mVersionData->userAgent,
                                  mVersionData->transmittingServices);
                            }
                        }
                    }
                    mLastPingNonce = 0;
                }
                break;
            case Message::REJECT:
            {
                Message::RejectData *rejectData = (Message::RejectData *)message;
                if(rejectData->command == "version")
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Closing for version reject [%02x] - %s",
                      rejectData->code, rejectData->reason.text());
                    close();
                }
                else
                    ArcMist::Log::addFormatted(ArcMist::Log::WARNING, mName, "Reject %s [%02x] - %s",
                      rejectData->command.text(), rejectData->code, rejectData->reason.text());

                // if(rejectData->code == Message::RejectData::LOW_FEE)
                //   Possibly look up transaction and set minimum fee filter above rate of
                //     transaction that was rejected

                // TODO Determine if closing node is necessary
                break;
            }
            case Message::GET_ADDRESSES:
            {
                // Send known peer addresses
                Message::AddressesData addressData;
                std::vector<Peer *> peers;
                uint64_t servicesMask = Message::VersionData::FULL_NODE_BIT;

                if(mChain->forks().cashActive())
                    servicesMask |= Message::VersionData::CASH_NODE_BIT;

                // Get list of peers
                Info::instance().getRandomizedPeers(peers, 1, servicesMask);

                unsigned int count = peers.size();
                if(count > 1000) // Maximum of 1000
                    count = 1000;
                if(count == 0)
                {
                    ArcMist::Log::add(ArcMist::Log::VERBOSE, mName, "No peer addresses available to send");
                    break;
                }

                // Add peers to message
                addressData.addresses.resize(count);
                std::vector<Peer *>::iterator peer = peers.begin();
                for(std::vector<Message::Address>::iterator toSend=addressData.addresses.begin();toSend!=addressData.addresses.end();++toSend)
                    *toSend = **peer++;

                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Sending %d peer addresses",
                  addressData.addresses.size());
                sendMessage(&addressData);
                break;
            }
            case Message::ADDRESSES:
            {
                Message::AddressesData *addressesData = (Message::AddressesData *)message;
                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Received %d peer addresses",
                  addressesData->addresses.size());
                IPAddress ip;

                Info &info = Info::instance();
                for(std::vector<Message::Address>::iterator address=addressesData->addresses.begin();address!=addressesData->addresses.end();++address)
                {
                    ip.set(address->ip, address->port);
                    info.updatePeer(ip, NULL, address->services);
                }

                if(mIsSeed)
                {
                    ArcMist::Log::add(ArcMist::Log::VERBOSE, mName, "Closing seed because it gave addresses");
                    close(); // Disconnect from seed node because it has done its job
                }
                break;
            }
            case Message::ALERT:
                //TODO Determine if anything needs to be done for alerts
                break;

            case Message::FEE_FILTER:
                mMinimumFeeRate = ((Message::FeeFilterData *)message)->minimumFeeRate;
                ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName, "Fee minimum rate set to %d", mMinimumFeeRate);
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
                Message::GetBlocksData *getBlocksData = (Message::GetBlocksData *)message;

                // Find appropriate hashes
                HashList hashes;
                for(std::vector<Hash>::iterator i=getBlocksData->blockHeaderHashes.begin();i!=getBlocksData->blockHeaderHashes.end();++i)
                    if(mChain->getBlockHashes(hashes, *i, 500))
                        break;

                if(hashes.size() == 0)
                {
                    // No matching starting hashes found. Start from genesis
                    Hash emptyHash;
                    mChain->getBlockHashes(hashes, emptyHash, 500);
                }

                unsigned int count = hashes.size();
                if(count > 500) // Maximum of 500
                    count = 500;

                // Add inventory to message
                bool dontStop = getBlocksData->stopHeaderHash.isZero();
                Message::InventoryData inventoryData;
                inventoryData.inventory.resize(count);
                unsigned int actualCount = 0;
                Message::Inventory::iterator item = inventoryData.inventory.begin();
                for(HashList::iterator hash=hashes.begin();hash!=hashes.end();++hash)
                {
                    *item = new Message::InventoryHash(Message::InventoryHash::BLOCK, **hash);
                    ++actualCount;
                    ++item;
                    if(!dontStop && **hash == getBlocksData->stopHeaderHash)
                        break;
                }
                inventoryData.inventory.resize(actualCount);

                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Sending %d block hashes", actualCount);
                sendMessage(&inventoryData);
                break;
            }
            case Message::GET_DATA:
            {
                // Don't respond to data requests before receiving the version message
                if(mVersionData == NULL)
                    break;

                Message::GetDataData *getDataData = (Message::GetDataData *)message;
                Message::NotFoundData notFoundData;
                Block block;
                bool fail = false;

                for(Message::Inventory::iterator item=getDataData->inventory.begin();item!=getDataData->inventory.end();++item)
                {
                    switch((*item)->type)
                    {
                    case Message::InventoryHash::BLOCK:
                    {
                        int height = mChain->blockHeight((*item)->hash);

                        if(height == -1)
                            notFoundData.inventory.push_back(new Message::InventoryHash(**item));
                        else if(height < mVersionData->startBlockHeight - 1000)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                              "Not sending block. Block height %d below node's start block height %d : %s",
                              height, mVersionData->startBlockHeight, (*item)->hash.hex().text());
                        }
                        else if(mChain->getBlock((*item)->hash, block))
                        {
                            if(!sendBlock(block))
                                fail = true;
                        }
                        else
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Block not found : %s",
                              (*item)->hash.hex().text());
                            notFoundData.inventory.push_back(new Message::InventoryHash(**item));
                        }
                        break;
                    }
                    case Message::InventoryHash::TRANSACTION:
                    {
                        Message::TransactionData transactionData;
                        transactionData.transaction = mChain->memPool().get((*item)->hash);
                        if(transactionData.transaction == NULL)
                            notFoundData.inventory.push_back(new Message::InventoryHash(**item));
                        else
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Sending Transaction (%d bytes) : %s",
                              transactionData.transaction->size(), (*item)->hash.hex().text());
                            sendMessage(&transactionData);
                        }
                        transactionData.transaction = NULL; // Don't delete it. It is still in the mem pool
                        break;
                    }
                    case Message::InventoryHash::FILTERED_BLOCK:
                        //TODO Implement GET_DATA filtered blocks (MERKLE_BLOCK)
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Requested Merkle Block (Not implemented) : %s",
                          (*item)->hash.hex().text());
                        break;
                    case Message::InventoryHash::COMPACT_BLOCK:
                        //TODO Implement GET_DATA compact blocks (COMPACT_BLOCK)
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Requested Compact Block (Not implemented) : %s",
                          (*item)->hash.hex().text());
                        break;
                    case Message::InventoryHash::UNKNOWN:
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Unknown request inventory type %02x",
                          (*item)->type);
                        break;
                    }

                    if(fail)
                        break;
                }

                if(notFoundData.inventory.size() > 0)
                    sendMessage(&notFoundData);
                break;
            }
            case Message::GET_HEADERS:
            {
                // Don't respond to header requests before receiving the version message
                if(mVersionData == NULL)
                    break;

                Message::GetHeadersData *getHeadersData = (Message::GetHeadersData *)message;
                Message::HeadersData headersData;
                int height;
                bool found = false;

                for(std::vector<Hash>::iterator hash=getHeadersData->blockHeaderHashes.begin();hash!=getHeadersData->blockHeaderHashes.end();++hash)
                {
                    height = mChain->blockHeight(*hash);
                    if(height != -1)
                    {
                        if(height < mVersionData->startBlockHeight - 2000)
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                              "Not sending headers. Header height %d below node's start block height %d : %s",
                              height, mVersionData->startBlockHeight, hash->hex().text());
                            break;
                        }
                        else if(mChain->getBlockHeaders(headersData.headers, *hash, getHeadersData->stopHeaderHash, 2000))
                        {
                            found = true;
                            break; // match found
                        }
                    }
                }

                if(found)
                {
                    if(headersData.headers.size() == 0)
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                          "Sending zero block headers", headersData.headers.size());
                    else
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                          "Sending %d block headers starting at height %d", headersData.headers.size(),
                          mChain->blockHeight(headersData.headers.front()->hash));
                    if(sendMessage(&headersData))
                        mStatistics.headersSent += headersData.headers.size();
                }
                break;
            }
            case Message::INVENTORY:
            {
                Message::InventoryData *inventoryData = (Message::InventoryData *)message;
                unsigned int blockCount = 0;
                bool headersNeeded = false;
                HashList blockList, transactionList;

                for(Message::Inventory::iterator item=inventoryData->inventory.begin();item!=inventoryData->inventory.end();++item)
                {
                    switch((*item)->type)
                    {
                    case Message::InventoryHash::BLOCK:
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Block Inventory : %s",
                          (*item)->hash.hex().text());
                        blockCount++;
                        addAnnouncedBlock((*item)->hash);

                        // Clear last header request so it doesn't prevent a new header request
                        mLastHeaderRequested.clear();

                        // Only pay attention to outgoing nodes inventory messages
                        if(!mIsIncoming && !mIsSeed)
                        {
                            switch(mChain->addPendingHash((*item)->hash, mID))
                            {
                                case Chain::NEED_HEADER:
                                    headersNeeded = true;
                                    break;
                                case Chain::NEED_BLOCK:
                                    blockList.push_back(new Hash((*item)->hash));
                                    break;
                                case Chain::BLACK_LISTED:
                                    sendReject(Message::nameFor(message->type), Message::RejectData::WRONG_CHAIN,
                                      "Announced block failed verification");
                                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName,
                                      "Dropping. Black listed block announced : %s", (*item)->hash.hex().text());
                                    close();
                                    break;
                                case Chain::ALREADY_HAVE:
                                    break;
                            }
                        }
                        break;
                    case Message::InventoryHash::TRANSACTION:
                        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName,
                          "Transaction Inventory : %s", (*item)->hash.hex().text());

                        addAnnouncedTransaction((*item)->hash);

                        // Only pay attention to outgoing nodes inventory messages
                        if(!mIsIncoming && !mIsSeed)
                        {
                            //TODO Transaction inventory messages
                            switch(mChain->memPool().addPending((*item)->hash, mID))
                            {
                                case MemPool::NEED:
                                    transactionList.push_back(new Hash((*item)->hash));
                                    break;
                                case MemPool::ALREADY_HAVE:
                                    break;
                                case MemPool::BLACK_LISTED:
                                    sendReject(Message::nameFor(message->type), Message::RejectData::WRONG_CHAIN,
                                      "Announced transaction failed verification");
                                    ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName,
                                      "Dropping. Black listed transaction announced : %s", (*item)->hash.hex().text());
                                    close();
                                    break;
                            }
                        }
                        break;
                    case Message::InventoryHash::FILTERED_BLOCK:
                        break;
                    case Message::InventoryHash::COMPACT_BLOCK:
                        break;
                    default:
                        ArcMist::Log::addFormatted(ArcMist::Log::WARNING, mName,
                          "Unknown Transaction Inventory Type : %02x", (*item)->type);
                        break;
                    }

                    if(!isOpen())
                        break;
                }

                if(blockCount > 1)
                    ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName, "Received %d block inventory",
                      blockCount);

                if(headersNeeded)
                {
                    ArcMist::Log::add(ArcMist::Log::DEBUG, mName, "Requesting header for announced block");
                    requestHeaders();
                }

                if(blockList.size() > 0)
                {
                    ArcMist::Log::add(ArcMist::Log::DEBUG, mName, "Requesting announced block");
                    requestBlocks(blockList);
                }

                if(transactionList.size() > 0)
                {
                    ArcMist::Log::add(ArcMist::Log::DEBUG, mName, "Requesting announced transactions");
                    requestTransactions(transactionList);
                }
                break;
            }
            case Message::HEADERS:
                // Only pay attention to outgoing nodes header messages
                if(!mIsIncoming && !mIsSeed)
                {
                    Message::HeadersData *headersData = (Message::HeadersData *)message;
                    unsigned int addedCount = 0;
                    HashList blockList;

                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                      "Received %d block headers", headersData->headers.size());
                    mHeaderRequested.clear();
                    mHeaderRequestTime = 0;
                    mStatistics.headersReceived += headersData->headers.size();

                    for(std::vector<Block *>::iterator header=headersData->headers.begin();header!=headersData->headers.end();)
                    {
                        if(mChain->addPendingBlock(*header))
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName, "Added Header : %s",
                              (*header)->hash.hex().text());
                            // memory will be deleted by block chain after it is processed so remove it from this list
                            header = headersData->headers.erase(header);
                            addedCount++;

                            if(mChain->isInSync())
                                blockList.push_back(new Hash((*header)->hash));
                        }
                        else
                        {
                            ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName, "Didn't add Header : %s",
                              (*header)->hash.hex().text());
                            ++header;
                        }
                    }

                    if(blockList.size() > 0)
                        requestBlocks(blockList);

                    if(addedCount > 0 && !mIsSeed && mVersionData != NULL)
                        Info::instance().updatePeer(mAddress, mVersionData->userAgent, mVersionData->transmittingServices);

                    ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName, "Added %d pending headers", addedCount);
                }
                break;
            case Message::BLOCK:
                // Only pay attention to outgoing nodes block messages
                if(!mIsIncoming && !mIsSeed)
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                      "Received block (height %d) (%d KiB) : %s", mChain->blockHeight(((Message::BlockData *)message)->block->hash),
                      ((Message::BlockData *)message)->block->size() / 1024, ((Message::BlockData *)message)->block->hash.hex().text());
                    ++mStatistics.blocksReceived;

                    // Remove from blocks requested
                    time = getTime();
                    mBlockRequestMutex.lock();
                    for(HashList::iterator hash=mBlocksRequested.begin();hash!=mBlocksRequested.end();++hash)
                        if(**hash == ((Message::BlockData *)message)->block->hash)
                        {
                            delete *hash;
                            mBlocksRequested.erase(hash);
                            mBlockReceiveTime = time;
                            ++mBlockDownloadCount;
                            mBlockDownloadTime += time - mMessageInterpreter.pendingBlockStartTime;
                            mBlockDownloadSize += ((Message::BlockData *)message)->block->size();
                            break;
                        }
                    mBlockRequestMutex.unlock();

                    if(mMessageInterpreter.pendingBlockStartTime != 0 &&
                      time - mMessageInterpreter.pendingBlockStartTime > 60)
                    {
                        // Drop after the block finishes so it doesn't have to be restarted
                        ArcMist::Log::addFormatted(ArcMist::Log::INFO, mName,
                          "Dropping. Block download took %ds", time - mMessageInterpreter.pendingBlockStartTime);
                        Info::instance().addPeerFail(mAddress, 5);
                        close();
                    }

                    if(mChain->addPendingBlock(((Message::BlockData *)message)->block))
                    {
                        ((Message::BlockData *)message)->block = NULL; // Memory has been handed off
                        if(!mIsSeed && mVersionData != NULL)
                            Info::instance().updatePeer(mAddress, mVersionData->userAgent, mVersionData->transmittingServices);
                    }
                }
                break;
            case Message::TRANSACTION:
                // Only pay attention to outgoing node's transaction messages
                if(!mIsIncoming && !mIsSeed)
                {
                    // Verify and add to mempool
                    Message::TransactionData *transactionData = (Message::TransactionData *)message;
                    if(transactionData->transaction != NULL)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::DEBUG, mName,
                          "Received transaction (%d bytes) : %s", transactionData->transaction->size(),
                          transactionData->transaction->hash.hex().text());
                        if(mChain->memPool().add(transactionData->transaction, mChain->outputs(),
                          mChain->blockStats(), mChain->forks(), Info::instance().minFee))
                            transactionData->transaction = NULL; // So it won't be deleted with the message
                    }
                }
                break;
            case Message::MEM_POOL:
                // TODO Implement MEM_POOL
                // Send Inventory message with all transactions in the mempool
                //   For large mempools break in to multiple messages
                break;

            case Message::MERKLE_BLOCK:
                // TODO Implement MERKLE_BLOCK
                break;

            case Message::NOT_FOUND:
            {
                Message::NotFoundData *notFoundData = (Message::NotFoundData *)message;
                for(Message::Inventory::iterator item=notFoundData->inventory.begin();item!=notFoundData->inventory.end();++item)
                {
                    switch((*item)->type)
                    {
                    case Message::InventoryHash::BLOCK:
                    {
                        bool wasRequested = false;
                        mBlockRequestMutex.lock();
                        for(HashList::iterator hash=mBlocksRequested.begin();hash!=mBlocksRequested.end();++hash)
                            if(**hash == (*item)->hash)
                            {
                                ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                                  "Block hash returned not found : %s", (*hash)->hex().text());
                                wasRequested = true;
                                break;
                            }
                        mBlockRequestMutex.unlock();

                        if(wasRequested)
                        {
                            ArcMist::Log::add(ArcMist::Log::INFO, mName, "Dropping. Blocks not found");
                            close();
                        }
                        break;
                    }
                    case Message::InventoryHash::TRANSACTION:
                        //TODO Implement Transaction not found
                        break;
                    case Message::InventoryHash::FILTERED_BLOCK:
                        //TODO Implement filtered blocks not found
                        break;
                    case Message::InventoryHash::COMPACT_BLOCK:
                        //TODO Implement compact blocks not found
                        break;
                    case Message::InventoryHash::UNKNOWN:
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                          "Unknown \"not found\" inventory item type %d", (*item)->type);
                        break;
                    }
                }
                break;
            }
            case Message::SEND_COMPACT:
            {
                Message::SendCompactData *sendCompactData = (Message::SendCompactData *)message;

                if(sendCompactData->encoding == 1)
                {
                    if(sendCompactData->sendCompact == 1)
                    {
                        ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName, "Send Compact Activated");
                        mSendBlocksCompact = true;
                    }
                    else if(sendCompactData->sendCompact == 0)
                        mSendBlocksCompact = false;
                }
                else
                {
                    ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, mName,
                      "Unknown Send Compact encoding %08x%08x", sendCompactData->encoding >> 32,
                      sendCompactData->encoding & 0xffffffff);
                }
                break;
            }
            case Message::COMPACT_BLOCK:
            {
                //TODO Message::CompactBlockData *compactBlockData = (Message::CompactBlockData *)message;
                break;
            }
            case Message::GET_BLOCK_TRANSACTIONS:
            {
                //TODO Message::GetBlockTransactionsData *getBlockTransactionsData = (Message::GetBlockTransactionsData *)message;
                break;
            }
            case Message::BLOCK_TRANSACTIONS:
            {
                //TODO Message::BlockTransactionsData *blockTransactionsData = (Message::BlockTransactionsData *)message;
                break;
            }

            case Message::UNKNOWN:
                break;
        }

        if(!dontDeleteMessage)
            delete message;
    }
}
