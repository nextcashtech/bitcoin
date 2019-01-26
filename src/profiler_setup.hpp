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
    static unsigned int sNextID = 0;

    static const unsigned int PROFILER_OUTPUTS_PULL_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_PULL_NAME __attribute__ ((unused)) = "Outputs::pull";
    static const unsigned int PROFILER_OUTPUTS_SAMPLE_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_SAMPLE_NAME __attribute__ ((unused)) = "Outputs::findSample";
    static const unsigned int PROFILER_OUTPUTS_ADD_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_ADD_NAME __attribute__ ((unused)) = "Outputs::add";
    static const unsigned int PROFILER_OUTPUTS_INSERT_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_INSERT_NAME __attribute__ ((unused)) = "Outputs::insert";
    static const unsigned int PROFILER_OUTPUTS_WRITE_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_WRITE_NAME __attribute__ ((unused)) = "Outputs::write";
    static const unsigned int PROFILER_OUTPUTS_GET_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_GET_NAME __attribute__ ((unused)) = "Outputs::get";
    static const unsigned int PROFILER_OUTPUTS_CHECK_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_CHECK_NAME __attribute__ ((unused)) = "Outputs::checkDuplicate";
    static const unsigned int PROFILER_OUTPUTS_GET_OUTPUT_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_GET_OUTPUT_NAME __attribute__ ((unused)) = "Outputs::getOutput";
    static const unsigned int PROFILER_OUTPUTS_IS_UNSPENT_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_IS_UNSPENT_NAME __attribute__ ((unused)) = "Outputs::isUnspent";
    static const unsigned int PROFILER_OUTPUTS_UNSPENT_STATUS_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_UNSPENT_STATUS_NAME __attribute__ ((unused)) = "Outputs::unspentStatus";
    static const unsigned int PROFILER_OUTPUTS_SPEND_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_SPEND_NAME __attribute__ ((unused)) = "Outputs::spend";
    static const unsigned int PROFILER_OUTPUTS_HAS_UNSPENT_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_HAS_UNSPENT_NAME __attribute__ ((unused)) = "Outputs::hasUnspent";
    static const unsigned int PROFILER_OUTPUTS_EXISTS_ID = sNextID++;
    static const char *PROFILER_OUTPUTS_EXISTS_NAME __attribute__ ((unused)) = "Outputs::exists";

    static const unsigned int PROFILER_INTERP_PROCESS_ID = sNextID++;
    static const char *PROFILER_INTERP_PROCESS_NAME __attribute__ ((unused)) = "Interpreter::process";

    static const unsigned int PROFILER_TRANS_READ_ID = sNextID++;
    static const char *PROFILER_TRANS_READ_NAME __attribute__ ((unused)) = "Transaction::read (B)";
    static const unsigned int PROFILER_TRANS_WRITE_SIG_ID = sNextID++;
    static const char *PROFILER_TRANS_WRITE_SIG_NAME __attribute__ ((unused)) = "Transaction::writeSigData";

    static const unsigned int PROFILER_BLOCK_READ_ID = sNextID++;
    static const char *PROFILER_BLOCK_READ_NAME __attribute__ ((unused)) = "Block::read (B)";
    static const unsigned int PROFILER_BLOCK_GET_ID = sNextID++;
    static const char *PROFILER_BLOCK_GET_NAME __attribute__ ((unused)) = "Block::get (B)";
    static const unsigned int PROFILER_BLOCK_PROCESS_ID = sNextID++;
    static const char *PROFILER_BLOCK_PROCESS_NAME __attribute__ ((unused)) = "Block::process (B)"; // hits are bytes
    static const unsigned int PROFILER_BLOCK_MERKLE_CALC_ID = sNextID++;
    static const char *PROFILER_BLOCK_MERKLE_CALC_NAME __attribute__ ((unused)) = "Block::merkleCalc";

    static const unsigned int PROFILER_KEY_SIGN_ID = sNextID++;
    static const char *PROFILER_KEY_SIGN_NAME __attribute__ ((unused)) = "Key::sign";
    static const unsigned int PROFILER_KEY_VERIFY_SIG_ID = sNextID++;
    static const char *PROFILER_KEY_VERIFY_SIG_NAME __attribute__ ((unused)) = "Key::verifySig";
    static const unsigned int PROFILER_KEY_STATIC_VERIFY_SIG_ID = sNextID++;
    static const char *PROFILER_KEY_STATIC_VERIFY_SIG_NAME __attribute__ ((unused)) = "Key::verifySigStatic";
    static const unsigned int PROFILER_KEY_SIG_READ_ID = sNextID++;
    static const char *PROFILER_KEY_SIG_READ_NAME __attribute__ ((unused)) = "Key::SigRead";

    static const unsigned int PROFILER_MEMPOOL_STATUS_ID = sNextID++;
    static const char *PROFILER_MEMPOOL_STATUS_NAME __attribute__ ((unused)) = "MemPool::status";
    static const unsigned int PROFILER_MEMPOOL_ADD_ID = sNextID++;
    static const char *PROFILER_MEMPOOL_ADD_NAME __attribute__ ((unused)) = "MemPool::add";
    static const unsigned int PROFILER_MEMPOOL_ADD_INTERNAL_ID = sNextID++;
    static const char *PROFILER_MEMPOOL_ADD_INTERNAL_NAME __attribute__ ((unused)) = "MemPool::addInternal";
    static const unsigned int PROFILER_MEMPOOL_ADD_INTERNAL_B_ID = sNextID++;
    static const char *PROFILER_MEMPOOL_ADD_INTERNAL_B_NAME __attribute__ ((unused)) = "MemPool::addInternal (B)"; // hits are bytes
    static const unsigned int PROFILER_MEMPOOL_ADD_DUP_B_ID = sNextID++;
    static const char *PROFILER_MEMPOOL_ADD_DUP_B_NAME __attribute__ ((unused)) = "MemPool::add (dup B)"; // hits are bytes
    static const unsigned int PROFILER_MEMPOOL_PENDING_ID = sNextID++;
    static const char *PROFILER_MEMPOOL_PENDING_NAME __attribute__ ((unused)) = "MemPool::checkPending";
    static const unsigned int PROFILER_MEMPOOL_GET_TRANS_ID = sNextID++;
    static const char *PROFILER_MEMPOOL_GET_TRANS_NAME __attribute__ ((unused)) = "MemPool::getTrans";
    static const unsigned int PROFILER_MEMPOOL_GET_TRANS_COPY_ID = sNextID++;
    static const char *PROFILER_MEMPOOL_GET_TRANS_COPY_NAME __attribute__ ((unused)) = "MemPool::getTransCopy";
    static const unsigned int PROFILER_MEMPOOL_GET_COMPACT_TRANS_CALC_ID = sNextID++;
    static const char *PROFILER_MEMPOOL_GET_COMPACT_TRANS_CALC_NAME __attribute__ ((unused)) = "MemPool::calcShortIDs";
    static const unsigned int PROFILER_MEMPOOL_GET_OUTPUT_ID = sNextID++;
    static const char *PROFILER_MEMPOOL_GET_OUTPUT_NAME __attribute__ ((unused)) = "MemPool::getOutput";
    static const unsigned int PROFILER_MEMPOOL_PULL_ID = sNextID++;
    static const char *PROFILER_MEMPOOL_PULL_NAME __attribute__ ((unused)) = "MemPool::pull";
    static const unsigned int PROFILER_MEMPOOL_FINALIZE_ID = sNextID++;
    static const char *PROFILER_MEMPOOL_FINALIZE_NAME __attribute__ ((unused)) = "MemPool::finalize";

    static const unsigned int PROFILER_NODE_FILL_COMPACT_ID = sNextID++;
    static const char *PROFILER_NODE_FILL_COMPACT_NAME __attribute__ ((unused)) = "Node::fillCompactBlock";
    static const unsigned int PROFILER_NODE_COMPACT_ADD_TRANS_ID = sNextID++;
    static const char *PROFILER_NODE_COMPACT_ADD_TRANS_NAME __attribute__ ((unused)) = "Node::compactAddTrans";

#endif

#endif
