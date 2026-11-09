# Independent vendored Monocypher C11 static library.
# This is deliberately NOT a Salts::Crypto internal object, and it is not a
# second TLS provider. Preserve the CNet-private symbol namespace unchanged.
add_library(saltscore_cnet_monocypher STATIC monocypher.c)
add_library(Monocypher::Monocypher ALIAS saltscore_cnet_monocypher)
target_compile_features(saltscore_cnet_monocypher PUBLIC c_std_11)
target_include_directories(saltscore_cnet_monocypher PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(saltscore_cnet_monocypher PROPERTIES
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)

# Preserve the existing private ABI without a wrapper source/header. The same
# usage requirements rename both the upstream implementation and its callers.
set(_cnet_monocypher_symbols
  crypto_aead_ctx
  crypto_aead_init_djb
  crypto_aead_init_ietf
  crypto_aead_init_x
  crypto_aead_lock
  crypto_aead_read
  crypto_aead_unlock
  crypto_aead_write
  crypto_argon2
  crypto_argon2_config
  crypto_argon2_extras
  crypto_argon2_inputs
  crypto_argon2_no_extras
  crypto_blake2b
  crypto_blake2b_ctx
  crypto_blake2b_final
  crypto_blake2b_init
  crypto_blake2b_keyed
  crypto_blake2b_keyed_init
  crypto_blake2b_update
  crypto_chacha20_djb
  crypto_chacha20_h
  crypto_chacha20_ietf
  crypto_chacha20_x
  crypto_curve_to_hidden
  crypto_eddsa_check
  crypto_eddsa_check_equation
  crypto_eddsa_key_pair
  crypto_eddsa_mul_add
  crypto_eddsa_reduce
  crypto_eddsa_scalarbase
  crypto_eddsa_sign
  crypto_eddsa_to_x25519
  crypto_eddsa_trim_scalar
  crypto_elligator_key_pair
  crypto_elligator_map
  crypto_elligator_rev
  crypto_lock
  crypto_poly1305
  crypto_poly1305_ctx
  crypto_poly1305_final
  crypto_poly1305_init
  crypto_poly1305_update
  crypto_verify16
  crypto_verify32
  crypto_verify64
  crypto_wipe
  crypto_x25519
  crypto_x25519_dirty_fast
  crypto_x25519_dirty_small
  crypto_x25519_inverse
  crypto_x25519_public_key
  crypto_x25519_to_eddsa)
foreach(_symbol IN LISTS _cnet_monocypher_symbols)
  target_compile_definitions(saltscore_cnet_monocypher PUBLIC
    "${_symbol}=salts_cnet_private_${_symbol}")
endforeach()
