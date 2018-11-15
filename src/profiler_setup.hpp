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
    static const unsigned int PROFILER_OUTPUTS_SAMPLE_ID = 1;
    static const char *PROFILER_OUTPUTS_SAMPLE_NAME __attribute__ ((unused)) = "Outputs::findSample";
    static const unsigned int PROFILER_OUTPUTS_ADD_ID = 2;
    static const char *PROFILER_OUTPUTS_ADD_NAME __attribute__ ((unused)) = "Outputs::add";
    static const unsigned int PROFILER_OUTPUTS_INSERT_ID = 3;
    static const char *PROFILER_OUTPUTS_INSERT_NAME __attribute__ ((unused)) = "Outputs::insert";
    static const unsigned int PROFILER_OUTPUTS_WRITE_ID = 4;
    static const char *PROFILER_OUTPUTS_WRITE_NAME __attribute__ ((unused)) = "Outputs::write";
    static const unsigned int PROFILER_OUTPUTS_GET_ID = 5;
    static const char *PROFILER_OUTPUTS_GET_NAME __attribute__ ((unused)) = "Outputs::get";
    static const unsigned int PROFILER_OUTPUTS_CHECK_ID = 6;
    static const char *PROFILER_OUTPUTS_CHECK_NAME __attribute__ ((unused)) = "Outputs::checkDuplicate";
    static const unsigned int PROFILER_OUTPUTS_GET_OUTPUT_ID = 7;
    static const char *PROFILER_OUTPUTS_GET_OUTPUT_NAME __attribute__ ((unused)) = "Outputs::getOutput";
    static const unsigned int PROFILER_OUTPUTS_IS_UNSPENT_ID = 8;
    static const char *PROFILER_OUTPUTS_IS_UNSPENT_NAME __attribute__ ((unused)) = "Outputs::isUnspent";
    static const unsigned int PROFILER_OUTPUTS_UNSPENT_STATUS_ID = 9;
    static const char *PROFILER_OUTPUTS_UNSPENT_STATUS_NAME __attribute__ ((unused)) = "Outputs::unspentStatus";
    static const unsigned int PROFILER_OUTPUTS_SPEND_ID = 10;
    static const char *PROFILER_OUTPUTS_SPEND_NAME __attribute__ ((unused)) = "Outputs::spend";
    static const unsigned int PROFILER_OUTPUTS_HAS_UNSPENT_ID = 11;
    static const char *PROFILER_OUTPUTS_HAS_UNSPENT_NAME __attribute__ ((unused)) = "Outputs::hasUnspent";
    static const unsigned int PROFILER_OUTPUTS_EXISTS_ID = 12;
    static const char *PROFILER_OUTPUTS_EXISTS_NAME __attribute__ ((unused)) = "Outputs::exists";

    static const unsigned int PROFILER_INTERP_PROCESS_ID = 13;
    static const char *PROFILER_INTERP_PROCESS_NAME __attribute__ ((unused)) = "Interpreter::process";

    static const unsigned int PROFILER_TRANS_READ_ID = 14;
    static const char *PROFILER_TRANS_READ_NAME __attribute__ ((unused)) = "Transaction::read (B)";
    static const unsigned int PROFILER_TRANS_WRITE_SIG_ID = 15;
    static const char *PROFILER_TRANS_WRITE_SIG_NAME __attribute__ ((unused)) = "Transaction::writeSigData";

    static const unsigned int PROFILER_BLOCK_READ_ID = 16;
    static const char *PROFILER_BLOCK_READ_NAME __attribute__ ((unused)) = "Block::read (B)";
    static const unsigned int PROFILER_BLOCK_PROCESS_ID = 17;
    static const char *PROFILER_BLOCK_PROCESS_NAME __attribute__ ((unused)) = "Block::process (B)"; // hits are bytes

    static const unsigned int PROFILER_KEY_SIGN_ID = 18;
    static const char *PROFILER_KEY_SIGN_NAME __attribute__ ((unused)) = "Key::sign";
    static const unsigned int PROFILER_KEY_VERIFY_SIG_ID = 19;
    static const char *PROFILER_KEY_VERIFY_SIG_NAME __attribute__ ((unused)) = "Key::verifySig";

    static const unsigned int PROFILER_MEMPOOL_STATUS_ID = 20;
    static const char *PROFILER_MEMPOOL_STATUS_NAME __attribute__ ((unused)) = "MemPool::status";
    static const unsigned int PROFILER_MEMPOOL_ADD_ID = 21;
    static const char *PROFILER_MEMPOOL_ADD_NAME __attribute__ ((unused)) = "MemPool::add";
    static const unsigned int PROFILER_MEMPOOL_ADD_B_ID = 22;
    static const char *PROFILER_MEMPOOL_ADD_B_NAME __attribute__ ((unused)) = "MemPool::add (B)"; // hits are bytes
    static const unsigned int PROFILER_MEMPOOL_ADD_DUP_B_ID = 23;
    static const char *PROFILER_MEMPOOL_ADD_DUP_B_NAME __attribute__ ((unused)) = "MemPool::add (dup B)"; // hits are bytes
    static const unsigned int PROFILER_MEMPOOL_PENDING_ID = 24;
    static const char *PROFILER_MEMPOOL_PENDING_NAME __attribute__ ((unused)) = "MemPool::checkPending";
    static const unsigned int PROFILER_MEMPOOL_GET_TRANS_ID = 25;
    static const char *PROFILER_MEMPOOL_GET_TRANS_NAME __attribute__ ((unused)) = "MemPool::getTrans";
    static const unsigned int PROFILER_MEMPOOL_GET_TRANS_SHORT_ID = 26;
    static const char *PROFILER_MEMPOOL_GET_TRANS_SHORT_NAME __attribute__ ((unused)) = "MemPool::getTransShort";
    static const unsigned int PROFILER_MEMPOOL_GET_OUTPUT_ID = 27;
    static const char *PROFILER_MEMPOOL_GET_OUTPUT_NAME __attribute__ ((unused)) = "MemPool::getOutput";

#endif

#endif
