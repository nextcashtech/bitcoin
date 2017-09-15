/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "events.hpp"

#include "arcmist/base/log.hpp"

#define BITCOIN_EVENT_LOG_NAME "BitCoin Events"


namespace BitCoin
{
    Events *Events::sInstance = 0;

    Events &Events::instance()
    {
        if(!sInstance)
        {
            sInstance = new Events();
            std::atexit(destroy);
        }

        return *Events::sInstance;
    }

    void Events::destroy()
    {
        delete Events::sInstance;
        Events::sInstance = 0;
    }

    Events::Events() : mMutex("Events")
    {
        mInfoSavedLastTime = 0;
        mUnspentsSavedLastTime = 0;
        mBlockRequestedLastTime = 0;
        mBlockReceivePartialLastTime = 0;
        mBlockReceiveFinishedLastTime = 0;
    }

    Events::~Events()
    {
    }

    void Events::post(Event::Type pEventType)
    {
        switch(pEventType)
        {
        case Event::INFO_SAVED:
            //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_EVENT_LOG_NAME, "Info Save Posted at : %d", getTime());
            mInfoSavedLastTime = getTime();
            break;
        case Event::UNSPENTS_SAVED:
            //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_EVENT_LOG_NAME, "Unspents Save Posted at : %d", getTime());
            mUnspentsSavedLastTime = getTime();
            break;
        case Event::BLOCK_REQUESTED:
            //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_EVENT_LOG_NAME, "Block Requested Posted at : %d", getTime());
            mBlockRequestedLastTime = getTime();
            break;
        case Event::BLOCK_RECEIVE_PARTIAL:
            //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_EVENT_LOG_NAME, "Partial Block Receive Posted at : %d", getTime());
            mBlockReceivePartialLastTime = getTime();
            break;
        case Event::BLOCK_RECEIVE_FINISHED:
            mBlockReceiveFinishedLastTime = getTime();
            break;
        }
    }

    void Events::post(Event &pEvent)
    {
        post(pEvent.type);
    }

    void Events::prune()
    {
        /*mMutex.lock();
        for(std::list<Event>::iterator i=mEvents.rbegin();i!=mEvents.rend();++i)
        {
            switch((*i).type)
            {
            case Event::INFO_SAVED:
                if(saveFound)
                    mEvents.erase(i);
                else
                    saveFound = true;
                break;
            case Event::BLOCK_REQUESTED:
                break;
            case Event::BLOCK_RECEIVE_PARTIAL:
                break;
            case Event::BLOCK_RECEIVE_FINISHED:
                break;
            }
        }
        mMutex.unlock();*/
    }

    uint64_t Events::lastOccurence(Event::Type pType)
    {
        switch(pType)
        {
        case Event::INFO_SAVED:
            return mInfoSavedLastTime;
        case Event::UNSPENTS_SAVED:
            return mUnspentsSavedLastTime;
        case Event::BLOCK_REQUESTED:
            return mBlockRequestedLastTime;
        case Event::BLOCK_RECEIVE_PARTIAL:
            return mBlockReceivePartialLastTime;
        case Event::BLOCK_RECEIVE_FINISHED:
            return mBlockReceiveFinishedLastTime;
        default:
            return 0;
        }
    }

    bool Events::elapsedSince(Event::Type pType, unsigned int pSeconds)
    {
        switch(pType)
        {
        case Event::INFO_SAVED:
            //ArcMist::Log::addFormatted(ArcMist::Log::VERBOSE, BITCOIN_EVENT_LOG_NAME, "Info Save last posted at : %d", mInfoSavedLastTime);
            return getTime() - mInfoSavedLastTime > pSeconds;
        case Event::UNSPENTS_SAVED:
            return getTime() - mUnspentsSavedLastTime > pSeconds;
        case Event::BLOCK_REQUESTED:
            return getTime() - mBlockRequestedLastTime > pSeconds;
        case Event::BLOCK_RECEIVE_PARTIAL:
            return getTime() - mBlockReceivePartialLastTime > pSeconds;
        case Event::BLOCK_RECEIVE_FINISHED:
            return getTime() - mBlockReceiveFinishedLastTime > pSeconds;
        default:
            return false;
        }
    }
}
