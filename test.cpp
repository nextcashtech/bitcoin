/**************************************************************************
 * Copyright 2017 ArcMist, LLC                                            *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@arcmist.com>                                    *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "message.hpp"
#include "key.hpp"
#include "transaction.hpp"
#include "interpreter.hpp"
#include "chain.hpp"
#include "info.hpp"

#include "arcmist/base/log.hpp"


int main(int pArgumentCount, char **pArguments)
{
    int failed = 0;

    ArcMist::Log::setLevel(ArcMist::Log::DEBUG);

    if(!BitCoin::Base::test())
        failed++;

    if(!BitCoin::Key::test())
        failed++;

    if(!BitCoin::Transaction::test())
        failed++;

    if(!BitCoin::ScriptInterpreter::test())
        failed++;

    if(!BitCoin::Chain::test())
        failed++;

    if(!BitCoin::Message::test())
        failed++;

    if(!BitCoin::Info::test())
        failed++;

    if(failed)
        return 1;
    else
        return 0;
}
