# Crypto-specific ECDSA DER and RFC 8410 key-format formats only.
# Generic BER/DER Reader and Value conformance belongs to Salts::ASN1.
add_executable(crypto_asn1_crypto_test crypto.c)
target_compile_features(crypto_asn1_crypto_test PRIVATE c_std_11)
set_target_properties(crypto_asn1_crypto_test PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
target_link_libraries(crypto_asn1_crypto_test PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.asn1.crypto COMMAND crypto_asn1_crypto_test)
add_executable(crypto_asn1_header_cpp_test header_cpp.cpp)
target_compile_features(crypto_asn1_header_cpp_test PRIVATE cxx_std_17)
target_link_libraries(crypto_asn1_header_cpp_test PRIVATE Salts::Crypto Salts::TinyTest)
add_test(NAME crypto.asn1.header_cpp17 COMMAND crypto_asn1_header_cpp_test)
