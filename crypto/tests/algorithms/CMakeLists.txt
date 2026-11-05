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

add_executable(salts_crypto_shangmi_vectors shangmi_vectors.c)
target_link_libraries(salts_crypto_shangmi_vectors PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.algorithms.shangmi_public COMMAND salts_crypto_shangmi_vectors)
set_tests_properties(crypto.algorithms.shangmi_public PROPERTIES TIMEOUT 120)

add_executable(salts_crypto_sm9_vectors sm9_vectors.c)
target_link_libraries(salts_crypto_sm9_vectors PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.algorithms.sm9_public COMMAND salts_crypto_sm9_vectors)
set_tests_properties(crypto.algorithms.sm9_public PROPERTIES TIMEOUT 120)

add_executable(salts_crypto_sm9_provider_failure sm9_provider_failure.c)
target_link_libraries(salts_crypto_sm9_provider_failure PRIVATE Salts::Crypto Salts::TinyTest GmSSL::GmSSL)
add_test(NAME crypto.algorithms.sm9_provider_failure COMMAND salts_crypto_sm9_provider_failure)
set_tests_properties(crypto.algorithms.sm9_provider_failure PROPERTIES TIMEOUT 120)

add_executable(salts_crypto_sm9_exchange_test sm9_exchange_test.c)
target_link_libraries(salts_crypto_sm9_exchange_test PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.algorithms.sm9_exchange COMMAND salts_crypto_sm9_exchange_test)
set_tests_properties(crypto.algorithms.sm9_exchange PROPERTIES TIMEOUT 120)

add_executable(salts_crypto_sm2_exchange_test sm2_exchange_test.c)
target_link_libraries(salts_crypto_sm2_exchange_test PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.algorithms.sm2_exchange COMMAND salts_crypto_sm2_exchange_test)
set_tests_properties(crypto.algorithms.sm2_exchange PROPERTIES TIMEOUT 120)

add_executable(salts_crypto_sm2_exchange_vectors sm2_exchange_vectors.c)
target_link_libraries(salts_crypto_sm2_exchange_vectors PRIVATE Salts::Crypto Salts::TinyTest GmSSL::GmSSL)
add_test(NAME crypto.algorithms.sm2_exchange_vectors COMMAND salts_crypto_sm2_exchange_vectors)
set_tests_properties(crypto.algorithms.sm2_exchange_vectors PROPERTIES TIMEOUT 120)
