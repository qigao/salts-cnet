# Private curve/signature implementation; no standalone SDK export.
add_library(
  crypto_libecc STATIC
  src/curves/aff_pt.c
  src/curves/aff_pt_edwards.c
  src/curves/aff_pt_montgomery.c
  src/curves/curves.c
  src/curves/ec_edwards.c
  src/curves/ec_montgomery.c
  src/curves/ec_params.c
  src/curves/ec_shortw.c
  src/curves/prj_pt.c
  src/fp/fp.c
  src/fp/fp_add.c
  src/fp/fp_montgomery.c
  src/fp/fp_mul.c
  src/fp/fp_mul_redc1.c
  src/fp/fp_pow.c
  src/fp/fp_rand.c
  src/fp/fp_sqrt.c
  src/nn/nn.c
  src/nn/nn_add.c
  src/nn/nn_div.c
  src/nn/nn_logical.c
  src/nn/nn_mod_pow.c
  src/nn/nn_modinv.c
  src/nn/nn_mul.c
  src/nn/nn_mul_redc1.c
  src/nn/nn_rand.c
  src/hash/hash_algs.c
  src/hash/sha256.c
  src/hash/sha384.c
  src/hash/sha512.c
  src/hash/sha512_core.c
  src/hash/shake.c
  src/hash/shake256.c
  src/sig/ec_key.c
  src/sig/ecdsa.c
  src/sig/ecdsa_common.c
  src/sig/eddsa.c
  src/sig/sig_algs.c
  src/utils/utils.c)
set_target_properties(
  crypto_libecc PROPERTIES POSITION_INDEPENDENT_CODE ON
                                 C_VISIBILITY_PRESET hidden)
target_include_directories(crypto_libecc
                           PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
# All adapters use this same feature set and private SHA namespace. GmSSL
# and libecc have distinct context ABIs for their native SHA entry points.
target_compile_definitions(crypto_libecc PRIVATE
  WITH_STDLIB WITH_LIBECC_CONFIG_OVERRIDE WITH_CURVE_WEI448 WITH_CURVE_WEI25519
  WITH_CURVE_SECP256R1 WITH_CURVE_SECP384R1 WITH_CURVE_SECP521R1 WITH_CURVE_SECP256K1
  WITH_HASH_SHAKE256 WITH_HASH_SHA256 WITH_HASH_SHA384 WITH_HASH_SHA512
  WITH_SIG_EDDSA448 WITH_SIG_EDDSA25519 WITH_SIG_ECDSA WORDSIZE=64)
foreach(hash IN ITEMS sha256 sha384 sha512)
  foreach(operation IN ITEMS init update final)
    target_compile_definitions(crypto_libecc PRIVATE
      "${hash}_${operation}=salts_private_libecc_${hash}_${operation}")
  endforeach()
endforeach()
if(MSVC)
  target_compile_options(crypto_libecc PRIVATE /experimental:c11atomics)
endif()
