# Source-owned GF(256) Reed-Solomon FEC, independent of Monocypher
# and Salts::Crypto. Keep the existing internal target and wire semantics.
find_path(SALTSCORE_CNET_SIMDE_INCLUDE_DIR NAMES simde/x86/sse2.h REQUIRED)
add_library(saltscore_cnet_reed STATIC gf256.c)
add_library(Reed::Reed ALIAS saltscore_cnet_reed)
target_compile_features(saltscore_cnet_reed PUBLIC c_std_11)
target_include_directories(saltscore_cnet_reed
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}"
  PRIVATE "${SALTSCORE_CNET_SIMDE_INCLUDE_DIR}")
set_target_properties(saltscore_cnet_reed PROPERTIES
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
