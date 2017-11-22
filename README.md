# bitcoin
Fresh Bitcoin Implementation

This is a new Bitcoin implementation built almost completely from the ground up.
It currently uses Pieter Wuille's secp256k1 implementation. Copyright (c) 2013 Pieter Wuille

With it I hope to try performance improvements and to also add security to Bitcoin through more diverse implementations.

Keep in mind it is still in early development and needs many performance improvements, code cleanup, and tests.

Currently it can perform an IBD (Initial Block Download), validate and propagate transactions and blocks,
and stay in sync with the Bitcoin Cash chain.

There are many features yet to be added including SPV (Simplified Payment Verification) support, RPC (Remote Procedure Call),
and indexing of addresses for balance/transaction lookups.

Please feel free to send comments.
