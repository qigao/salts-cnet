# Crypto-specific ECDSA DER and RFC 8410 key-format formats only.
# Generic BER/DER Reader and Value conformance belongs to Salts::ASN1.
cmake_add_executable(crypto_asn1_crypto_test SOURCES crypto.c
  FOLDER "crypto/tests/asn1")
target_link_libraries(crypto_asn1_crypto_test PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.asn1.crypto COMMAND crypto_asn1_crypto_test)
cmake_add_executable(crypto_asn1_header_cpp_test SOURCES header_cpp.cpp
  FOLDER "crypto/tests/asn1")
target_link_libraries(crypto_asn1_header_cpp_test PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.asn1.header_cpp17 COMMAND crypto_asn1_header_cpp_test)

add_executable(crypto_sm2_keys_test sm2_keys.c)
target_sources(crypto_sm2_keys_test PRIVATE
  "${_salts_crypto_source_dir}/src/crypto_sm2_keys.c")
target_link_libraries(crypto_sm2_keys_test PRIVATE Salts::Crypto Salts::TinyTest GmSSL::GmSSL)
set_target_properties(crypto_sm2_keys_test PROPERTIES FOLDER "Crypto/tests/asn1")
add_test(NAME crypto.asn1.sm2_keys COMMAND crypto_sm2_keys_test)
set_tests_properties(crypto.asn1.sm2_keys PROPERTIES TIMEOUT 120)

add_subdirectory(e2e)
