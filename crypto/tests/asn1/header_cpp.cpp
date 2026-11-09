#include <asn1.h>
#include <asn1_value.h>
#include <crypto/asn1_crypto.h>
#include <crypto/tls_credentials.h>
#include <crypto/tls_group.h>
#include <crypto/tls_stream.h>
#include <crypto/sm2_keys.h>
#include <tinytest.hpp>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <type_traits>

static_assert(std::is_standard_layout<salts_asn1_tlv>::value, "TLV ABI");
static_assert(std::is_standard_layout<salts_asn1_reader>::value, "reader ABI");
static_assert(SALTS_ASN1_ABI_VERSION == 1u, "ASN.1 ABI version");

spec("Crypto ASN.1 C++17 public header") {
    it("round trips the explicit SM2 AES256 key container through the C ABI") {
        std::uint8_t key[32]{}, imported[32]{}, der[SALTS_CRYPTO_SM2_ENCRYPTED_PKCS8_MAX_SIZE]{};
        const std::uint8_t password[] = {'p', 0, 'w'};
        std::size_t written = 0u;
        key[31] = 1u;
        check_equal(salts_crypto_sm2_pkcs8_aes256_encrypt(key, password, sizeof(password), 10000u,
            der, sizeof(der), &written), SALTS_CRYPTO_OK);
        check_equal(salts_crypto_sm2_pkcs8_aes256_decrypt(der, written, password, sizeof(password),
            10000u, imported), SALTS_CRYPTO_OK);
        check_equal(std::memcmp(imported, key, sizeof(key)), 0);
    }
    it("links immutable credential lifetime operations through the C ABI") {
        crypto_tls_credential_object *object = nullptr;
        check_equal(crypto_tls_credential_object_retain(object), static_cast<int>(CRYPTO_TLS_STREAM_EINVAL));
        crypto_tls_credential_object_release(object);
        check_equal(crypto_tls_credential_object_from_pkcs12(nullptr, nullptr,
            CRYPTO_TLS_CREDENTIAL_SINGLE, &object), static_cast<int>(CRYPTO_TLS_STREAM_EINVAL));
        check_null(object);
        static_assert(CRYPTO_TLS_GROUP_SECP256R1 == 0x0017, "P256 wire group");
        static_assert(CRYPTO_TLS_GROUP_SM2P256V1 == 0x0029, "SM2 wire group");
    }
    it("links the C ABI and validates DER") {
        const std::uint8_t encoded[] = {0x02,0x01,0x2a};
        check_equal(salts_asn1_validate(encoded, sizeof(encoded), SALTS_ASN1_DER), SALTS_ASN1_OK);
    }
    it("creates and releases an owned value through the C ABI") {
        salts_asn1_value *sequence = nullptr;
        salts_asn1_value *integer = nullptr;
        check_equal(salts_asn1_value_create_sequence(&sequence), SALTS_ASN1_OK);
        check_equal(salts_asn1_value_create_integer(42, &integer), SALTS_ASN1_OK);
        check_equal(salts_asn1_value_add_child(sequence, integer), SALTS_ASN1_OK);
        check_equal(salts_asn1_value_child_count(sequence), static_cast<std::size_t>(1u));
        salts_asn1_value_free(sequence);
    }
    it("exposes the RFC 8410 C ABI") {
        std::uint8_t key[CRYPTO_ASN1_RFC8410_KEY_BYTES]{};
        std::uint8_t der[CRYPTO_ASN1_RFC8410_SPKI_BYTES]{};
        std::size_t written = 0u;
        check_equal(crypto_asn1_rfc8410_spki_encode(
                        CRYPTO_ASN1_RFC8410_ED25519, key, der, sizeof(der),
                        &written),
                    SALTS_ASN1_OK);
        check_equal(written, static_cast<std::size_t>(sizeof(der)));
    }
}
