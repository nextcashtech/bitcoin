/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_EVENTS_HPP
#define BITCOIN_EVENTS_HPP

#include "arcmist/base/mutex.hpp"
#include "base.hpp"

#include <list>


namespace BitCoin
{
    class Event
    {
    public:

        enum Type
        {
            INFO_SAVED,             // Information saved to file system
            UNSPENTS_SAVED,         // Unspent transaction outputs saved to file system
            BLOCK_REQUESTED,        // Block requested from node
            BLOCK_RECEIVE_PARTIAL,  // Received part of a block from a node
            BLOCK_RECEIVE_FINISHED  // Finished receiving block from node
        };

        Event(Type pType)
        {
            type = pType;
            time = getTime();
        }

        Type type;
        uint64_t time;

    };

    class Events
    {
    public:

        static Events &instance();
        static void destroy();

        // Post a new event
        void post(Event::Type pEventType);
        void post(Event &pEvent);

        // Remove events that are no longer needed
        void prune();

        // Return the time of the last occurence of a specific event type
        uint64_t lastOccurence(Event::Type pType);

        // Returns true if the seconds since the specified event type occurred is larger than the specified seconds
        bool elapsedSince(Event::Type pType, unsigned int pSeconds);

    protected:

        Events();
        ~Events();

        ArcMist::Mutex mMutex;

        std::list<Event> mEvents;

        uint64_t mInfoSavedLastTime;
        uint64_t mUnspentsSavedLastTime;
        uint64_t mBlockRequestedLastTime;
        uint64_t mBlockReceivePartialLastTime;
        uint64_t mBlockReceiveFinishedLastTime;

        static Events *sInstance;

    };
}

#endif
