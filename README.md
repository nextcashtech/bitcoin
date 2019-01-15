# bitcoin
Fresh Bitcoin Cash/SV Implementation

This is a new Bitcoin Cash/SV implementation built almost completely from the ground up.
It currently uses Pieter Wuille's secp256k1 implementation. Copyright (c) 2013 Pieter Wuille.

Support for selecting the Bitcoin SV chain has recently been added.

It is currently fully functional. There is an SPV mode on which an Android wallet is being built.

With it I hope to try performance improvements and to also add security to Bitcoin through more diverse implementations.

Keep in mind it is still in early development and still needs complete consensus rules verification, performance improvements, code cleanup, and many tests.

Current notable features
* Multi-threaded design from the ground up
* Multi-threaded block validation
* Multi-threaded mempool acceptance
* Multi-threaded UTXO set saving
* UTXO set design in which 10 million transactions can be indexed in memory using around 1 GB.
* Initial block download with pre-approved block hash below which blocks will not be validated, and just used to update the UTXO set
* Custom requests interface for quering block chain data through TCP/IP.

Future features
* Graphene

Please feel free to send comments.

Build/install instructions are in the wiki of this repo.
https://github.com/nextcashtech/bitcoin/wiki/Compiler-Setup
