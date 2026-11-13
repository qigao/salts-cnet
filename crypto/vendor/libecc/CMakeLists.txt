# Vendored libecc build ownership: private Ed448 object compilation only.
# This directory must not install or export an independent libecc package,
# archive, compatibility target, or SHA256 implementation.
add_library(crypto_libecc_ed448_objects OBJECT
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
  src/hash/shake.c
  src/hash/shake256.c
  src/sig/ec_key.c
  src/sig/eddsa.c
  src/sig/sig_algs.c
  src/utils/utils.c)
set_target_properties(crypto_libecc_ed448_objects PROPERTIES
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
target_include_directories(crypto_libecc_ed448_objects PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
# Keep the reviewed WEI448/SHAKE256/EdDSA-only macro and WORDSIZE=64 ABI.
target_compile_definitions(crypto_libecc_ed448_objects PRIVATE
  WITH_STDLIB WITH_LIBECC_CONFIG_OVERRIDE WITH_CURVE_WEI448
  WITH_HASH_SHAKE256 WITH_SIG_EDDSA448 WORDSIZE=64)
if(MSVC)
  target_compile_options(crypto_libecc_ed448_objects PRIVATE /experimental:c11atomics)
endif()
