/**************************************************************************
 * Copyright 2017-2019 NextCash, LLC                                      *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#include "output.hpp"

#include "interpreter.hpp"


namespace BitCoin
{
    void Output::write(NextCash::OutputStream *pStream, bool pTrim)
    {
        pStream->writeLong(amount);
        if(pTrim && ScriptInterpreter::isOPReturn(script))
        {
            // Trim OP_RETURN data
            writeCompactInteger(pStream, 1);
            pStream->writeByte(OP_RETURN);
        }
        else
        {
            writeCompactInteger(pStream, script.length());
            pStream->write(script.begin(), script.length());
        }
    }

    bool Output::read(NextCash::InputStream *pStream)
    {
        if(pStream->remaining() < 8)
            return false;

        amount = pStream->readLong();

        NextCash::stream_size bytes = readCompactInteger(pStream);
        if(bytes > MAX_SCRIPT_SIZE)
        {
            NextCash::Log::addFormatted(NextCash::Log::WARNING, BITCOIN_OUTPUT_LOG_NAME,
              "Failed to read output. Script too long : %d", bytes);
            return false;
        }
        if(pStream->remaining() < bytes)
            return false;
        script.setSize(bytes);
        script.reset();
        script.writeStreamCompact(*pStream, bytes);

        return true;
    }

    bool Output::skip(NextCash::InputStream *pInputStream, NextCash::OutputStream *pOutputStream)
    {
        // Amount
        if(pInputStream->remaining() < 8)
            return false;
        if(pOutputStream == NULL)
            pInputStream->setReadOffset(pInputStream->readOffset() + 8);
        else
            pOutputStream->writeLong(pInputStream->readLong());

        // Script
        NextCash::stream_size bytes = readCompactInteger(pInputStream);
        if(pOutputStream != NULL)
            writeCompactInteger(pOutputStream, bytes);
        if(pInputStream->remaining() < bytes)
            return false;
        if(pOutputStream == NULL)
            pInputStream->setReadOffset(pInputStream->readOffset() + bytes);
        else
            pInputStream->readStream(pOutputStream, bytes);
        return true;
    }

    void Output::print(const Forks &pForks, const char *pLogName, NextCash::Log::Level pLevel)
    {
        NextCash::Log::addFormatted(pLevel, pLogName, "  Amount : %.08f",
          bitcoins(amount));
        NextCash::Log::addFormatted(pLevel, pLogName, "  Script : (%d bytes)",
          script.length());
        script.setReadOffset(0);
        ScriptInterpreter::printScript(script, pForks, pLevel);
    }
}