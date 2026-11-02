# Independent vendored Monocypher C11 static library.
# This is deliberately NOT a Salts::Crypto internal object, and it is not a
# second TLS provider. Preserve the CNet-private symbol namespace unchanged.
add_library(saltscore_cnet_monocypher STATIC cnet_monocypher.c)
add_library(Monocypher::Monocypher ALIAS saltscore_cnet_monocypher)
target_compile_features(saltscore_cnet_monocypher PUBLIC c_std_11)
target_include_directories(saltscore_cnet_monocypher PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(saltscore_cnet_monocypher PROPERTIES
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
