# NextCash Bitcoin Cash

cmake_minimum_required(VERSION 3.4.1)

add_definitions( -DANDROID -DJAVA )


include_directories( ../nextcash/src/base
                     ../nextcash/src/io
                     ../nextcash/src/crypto
                     ../nextcash/src/dev
                     ../secp256k1/include
                     src )

add_library( bitcoin STATIC SHARED
             src/addresses.cpp
             src/base.cpp
             src/block.cpp
             src/bloom_filter.cpp
             src/chain.cpp
             src/daemon.cpp
             src/forks.cpp
             src/info.cpp
             src/interpreter.cpp
             src/key.cpp
             src/mem_pool.cpp
             src/message.cpp
             src/monitor.cpp
             src/node.cpp
             src/outputs.cpp
             src/requests.cpp
             src/transaction.cpp )

target_link_libraries( bitcoin nextcash secp256k1 )