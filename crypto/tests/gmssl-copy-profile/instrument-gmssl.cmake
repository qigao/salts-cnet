# GmSSL's project() hook runs before its existing target is declared.
function(salts_gmssl_copy_instrument)
  set(_copy_source "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../../src")
  target_sources(gmssl PRIVATE "${_copy_source}/crypto_gmssl_copy_test.c")
  target_compile_features(gmssl PRIVATE c_std_11)
  set_target_properties(gmssl PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_compile_definitions(gmssl PRIVATE "$<$<COMPILE_LANGUAGE:C>:SALTS_GMSSL_COPY_INJECT=1>")
  target_compile_options(gmssl PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:SHELL:-include \"${_copy_source}/crypto_gmssl_copy_test.h\">")
endfunction()
cmake_language(DEFER CALL salts_gmssl_copy_instrument)
