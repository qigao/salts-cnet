#include "tinytest.h"

/* Regression coverage for the tinytest review fixes:
 * - names with '%' are literals, not printf formats (MED-1)
 * - 64-bit integer assertions do not truncate (MED-2)
 * - check_warn does not count toward assertion totals (LOW-4)
 */
suite("review fixes") {
  it("keeps a literal % sign in the name") {
    check_true(1);
  }

  it("interprets unformatted assertions as literal diagnostics, never printf formats") {
    const unsigned value = 17u;
    const char *percent_text = "rate=10%";
    check((value % 5u) == 2u);
    check(percent_text[7] == '%');
    check_warn((value % 5u) == 2u);
  }

  it("compares 64-bit signed values") {
    check_equal(0x100000000LL, 0x100000000LL);
    check_not_equal(0x100000000LL, 0LL);
    check_greater(0x100000001LL, 0x100000000LL);
    check_greater_equal(0x100000000LL, 0x100000000LL);
    check_less(-0x100000001LL, -0x100000000LL);
    check_less_equal(-0x100000000LL, -0x100000000LL);
  }

  it("compares 64-bit unsigned values") {
    check_equal(0x100000000ULL, 0x100000000ULL);
    check_not_equal(0x100000000ULL, 0ULL);
  }

  it("matches bit masks above 32 bits") {
    check_bits(0x100000000ULL, 0x100000000ULL);
  }

  it("does not count warnings as assertions") {
    size_t before = ttest_active_config__->assertion_count;
    size_t warn_before = ttest_active_config__->warn_count;
    check_warn(1 == 2, "intentional warning");
    check_equal(ttest_active_config__->assertion_count, before);
    check_equal(ttest_active_config__->warn_count, warn_before + 1);
  }
}


suite("MSVC C registration retention") {
  it("retains a second C suite registration entry") {
    check_true(1);
  }
}
