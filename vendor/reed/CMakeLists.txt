# Source-owned GF(256) Reed-Solomon FEC, independent of Monocypher
# and Salts::Crypto. Keep the existing internal target and wire semantics.
find_path(cnet_SIMDE_INCLUDE_DIR NAMES simde/x86/sse2.h
  PATHS "${SALTS_DEPENDENCY_PREFIX}/include" NO_DEFAULT_PATH REQUIRED)
add_library(reed STATIC gf256.c)
add_library(Reed::Reed ALIAS reed)
target_compile_features(reed PUBLIC c_std_11)
target_include_directories(reed
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}"
  PRIVATE "${cnet_SIMDE_INCLUDE_DIR}")
set_target_properties(reed PROPERTIES
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
