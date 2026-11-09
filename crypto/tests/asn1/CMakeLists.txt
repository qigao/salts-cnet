# Crypto-specific ECDSA DER and RFC 8410 key-format formats only.
# Generic BER/DER Reader and Value conformance belongs to Salts::ASN1.
cmake_add_executable(crypto_asn1_crypto_test SOURCES crypto.c
  FOLDER "crypto/tests/asn1")
target_compile_features(crypto_asn1_crypto_test PRIVATE c_std_11)
set_target_properties(crypto_asn1_crypto_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(crypto_asn1_crypto_test PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.asn1.crypto COMMAND crypto_asn1_crypto_test)
cmake_add_executable(crypto_asn1_header_cpp_test SOURCES header_cpp.cpp
  FOLDER "crypto/tests/asn1")
target_compile_features(crypto_asn1_header_cpp_test PRIVATE cxx_std_17)
target_link_libraries(crypto_asn1_header_cpp_test PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.asn1.header_cpp17 COMMAND crypto_asn1_header_cpp_test)

add_executable(crypto_sm2_keys_test sm2_keys.c)
target_link_libraries(crypto_sm2_keys_test PRIVATE Salts::Crypto Salts::TinyTest GmSSL::GmSSL)
set_target_properties(crypto_sm2_keys_test PROPERTIES FOLDER "Crypto/tests/asn1")
add_test(NAME crypto.asn1.sm2_keys COMMAND crypto_sm2_keys_test)
set_tests_properties(crypto.asn1.sm2_keys PROPERTIES TIMEOUT 120)

find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_executable(crypto_sm2_keys_peer sm2_keys_peer.c)
target_link_libraries(crypto_sm2_keys_peer PRIVATE Salts::Crypto)
set_target_properties(crypto_sm2_keys_peer PROPERTIES FOLDER "Crypto/tests/asn1")
add_test(NAME crypto.asn1.sm2_keys_independent
  COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/sm2_keys_peer.py"
    "$<TARGET_FILE:crypto_sm2_keys_peer>")
set_tests_properties(crypto.asn1.sm2_keys_independent PROPERTIES TIMEOUT 120)

add_executable(crypto_pkcs12_peer pkcs12_peer.c)
target_link_libraries(crypto_pkcs12_peer PRIVATE Salts::Crypto)
set_target_properties(crypto_pkcs12_peer PROPERTIES FOLDER "Crypto/tests/asn1")
add_test(NAME crypto.asn1.pkcs12_independent
  COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/pkcs12_peer.py"
    "$<TARGET_FILE:crypto_pkcs12_peer>")
set_tests_properties(crypto.asn1.pkcs12_independent PROPERTIES TIMEOUT 120)
