#include <asn1.h>
#include <asn1_value.h>
#include <tinytest.hpp>
#include <cstddef>
#include <cstdint>
#include <type_traits>

static_assert(std::is_standard_layout<salts_asn1_tlv>::value, "TLV ABI");
static_assert(std::is_standard_layout<salts_asn1_reader>::value, "reader ABI");
static_assert(SALTS_ASN1_ABI_VERSION == 1u, "ABI version");

spec("Standalone Salts ASN.1 C++17 header") {
    it("validates strict DER through the exported C ABI") {
        const std::uint8_t der[]{0x02u,0x01u,0x2au};
        check_equal(salts_asn1_validate(der,sizeof(der),SALTS_ASN1_DER),SALTS_ASN1_OK);
    }
    it("allocates and transfers a single owned value") {
        salts_asn1_value *root=nullptr, *v=nullptr;
        check_equal(salts_asn1_value_create_sequence(&root),SALTS_ASN1_OK);
        check_equal(salts_asn1_value_create_integer(42,&v),SALTS_ASN1_OK);
        check_equal(salts_asn1_value_add_child(root,v),SALTS_ASN1_OK);
        check_equal(salts_asn1_value_child_count(root),static_cast<std::size_t>(1u));
        salts_asn1_value_free(root);
    }
}
