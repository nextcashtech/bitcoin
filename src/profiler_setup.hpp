/**************************************************************************
 * Copyright 2018 NextCash, LLC                                           *
 * Contributors :                                                         *
 *   Curtis Ellis <curtis@nextcash.tech>                                  *
 * Distributed under the MIT software license, see the accompanying       *
 * file license.txt or http://www.opensource.org/licenses/mit-license.php *
 **************************************************************************/
#ifndef BITCOIN_PROFILER_SETUP_HPP
#define BITCOIN_PROFILER_SETUP_HPP

#ifdef PROFILER_ON

    static const unsigned int PROFILER_SET = 1;

    static const unsigned int PROFILER_OUTPUTS_PULL_ID = 0;
    static const char *PROFILER_OUTPUTS_PULL_NAME __attribute__ ((unused)) = "Outputs::pull";
    static const unsigned int PROFILER_OUTPUTS_ADD_ID = 1;
    static const char *PROFILER_OUTPUTS_ADD_NAME __attribute__ ((unused)) = "Outputs::add";
    static const unsigned int PROFILER_OUTPUTS_INSERT_ID = 2;
    static const char *PROFILER_OUTPUTS_INSERT_NAME __attribute__ ((unused)) = "Outputs::insert";
    static const unsigned int PROFILER_OUTPUTS_WRITE_ID = 3;
    static const char *PROFILER_OUTPUTS_WRITE_NAME __attribute__ ((unused)) = "Outputs::write";
    static const unsigned int PROFILER_OUTPUTS_GET_ID = 4;
    static const char *PROFILER_OUTPUTS_GET_NAME __attribute__ ((unused)) = "Outputs::get";
    static const unsigned int PROFILER_OUTPUTS_GET_OUTPUT_ID = 5;
    static const char *PROFILER_OUTPUTS_GET_OUTPUT_NAME __attribute__ ((unused)) = "Outputs::getOutput";
    static const unsigned int PROFILER_OUTPUTS_IS_UNSPENT_ID = 6;
    static const char *PROFILER_OUTPUTS_IS_UNSPENT_NAME __attribute__ ((unused)) = "Outputs::isUnspent";
    static const unsigned int PROFILER_OUTPUTS_SPEND_ID = 7;
    static const char *PROFILER_OUTPUTS_SPEND_NAME __attribute__ ((unused)) = "Outputs::spend";
    static const unsigned int PROFILER_OUTPUTS_HAS_UNSPENT_ID = 8;
    static const char *PROFILER_OUTPUTS_HAS_UNSPENT_NAME __attribute__ ((unused)) = "Outputs::hasUnspent";
    static const unsigned int PROFILER_OUTPUTS_EXISTS_ID = 9;
    static const char *PROFILER_OUTPUTS_EXISTS_NAME __attribute__ ((unused)) = "Outputs::exists";

    static const unsigned int PROFILER_INTERP_PROCESS_ID = 10;
    static const char *PROFILER_INTERP_PROCESS_NAME __attribute__ ((unused)) = "Interpreter::process";

    static const unsigned int PROFILER_TRANS_READ_ID = 11;
    static const char *PROFILER_TRANS_READ_NAME __attribute__ ((unused)) = "Transaction::read";
    static const unsigned int PROFILER_TRANS_WRITE_SIG_ID = 12;
    static const char *PROFILER_TRANS_WRITE_SIG_NAME __attribute__ ((unused)) = "Transaction::writeSigData";

    static const unsigned int PROFILER_BLOCK_READ_ID = 13;
    static const char *PROFILER_BLOCK_READ_NAME __attribute__ ((unused)) = "Block::read";

    static const unsigned int PROFILER_KEY_VERIFY_SIG_ID = 14;
    static const char *PROFILER_KEY_VERIFY_SIG_NAME __attribute__ ((unused)) = "Key::verifySig";

#endif

#endif
