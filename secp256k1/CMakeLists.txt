# SECP256K1 Implementation

cmake_minimum_required(VERSION 3.4.1)


# Use Basic Configuration
add_definitions( -DUSE_NUM_NONE )
add_definitions( -DUSE_FIELD_INV_BUILTIN )
add_definitions( -DUSE_SCALAR_INV_BUILTIN )
add_definitions( -DUSE_FIELD_10X26 )
add_definitions( -DUSE_SCALAR_8X32 )

include_directories( ./ include )

add_library( secp256k1 STATIC SHARED
		src/secp256k1.c )
