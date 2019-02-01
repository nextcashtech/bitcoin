/**************************************************************************
 * Copyright 2017-2019 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_OUTPUT_HPP
#define BITCOIN_OUTPUT_HPP

#include "stream.hpp"
#include "buffer.hpp"
#include "forks.hpp"

#include <cstdint>

#define BITCOIN_OUTPUT_LOG_NAME "Output"


namespace BitCoin
{
    class Output
    {
    public:

        Output() { }
        Output(const Output &pCopy) : script(pCopy.script)
        {
            amount = pCopy.amount;
        }

        Output &operator = (const Output &pRight)
        {
            amount = pRight.amount;
            script = pRight.script;
            return *this;
        }

        bool operator == (const Output &pRight)
        {
            return amount == pRight.amount && script == pRight.script;
        }

        // 8 amount + script length size + script length
        NextCash::stream_size size() const
          { return 8 + compactIntegerSize(script.length()) + script.length(); }

        void write(NextCash::OutputStream *pStream, bool pTrim = false);
        bool read(NextCash::InputStream *pStream);

        // Skip over output in stream
        //   (The input stream's read offset must be at the beginning of an output)
        static bool skip(NextCash::InputStream *pInputStream,
          NextCash::OutputStream *pOutputStream = NULL);

        // Print human readable version to log
        void print(const Forks &pForks, const char *pLogName = BITCOIN_OUTPUT_LOG_NAME,
          NextCash::Log::Level pLevel = NextCash::Log::VERBOSE);

        int64_t amount; // Number of Satoshis spent (documentation says this should be signed)
        NextCash::Buffer script;

    };
}

#endif
