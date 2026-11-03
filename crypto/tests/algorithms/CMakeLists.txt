add_executable(salts_crypto_sha_ed448_vectors sha_ed448_vectors.c)
target_compile_features(salts_crypto_sha_ed448_vectors PRIVATE c_std_11)
# Source-tree tests use the pinned installed vcpkg GmSSL headers;
# never access a locally copied native implementation.
target_link_libraries(salts_crypto_sha_ed448_vectors PRIVATE
  Salts::Crypto Salts::TinyTest GmSSL::GmSSL)
add_test(NAME crypto.algorithms.sha256_sm3_ed448_rfc8032 COMMAND salts_crypto_sha_ed448_vectors)
set_tests_properties(crypto.algorithms.sha256_sm3_ed448_rfc8032 PROPERTIES TIMEOUT 120)

add_executable(crypto_algorithms_cpp_header header_cpp.cpp)
set_target_properties(crypto_algorithms_cpp_header PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
target_link_libraries(crypto_algorithms_cpp_header PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.algorithms.cpp17_header COMMAND crypto_algorithms_cpp_header)
