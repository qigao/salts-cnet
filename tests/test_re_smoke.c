/* Original bounded regex engine: TinyTest is test-only; native C11
 * parser and limits remain the single Core-owned runtime implementation.
 * The original 25 more detailed TinyTest cases remain in test_re.c.
 */
#include "re.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <tinytest.h>

spec("Original bounded regex engine") {
  it("retains binary matching, budget limits and invalid-pattern rejection") {
    re_t compiled = NULL;
    re_match_result_t result = {RE_NPOS, 0u};
    re_limits_t limits = re_limits_default();
    static const char binary[] = {'x', '\0', 'a', 'a', 'b', 'y'};
    static const char no_match[] = "xxxxxxxxxxxxxxxxxxxx";
    int matched = -1;

    check(limits.struct_size == sizeof(limits));
    check(limits.max_pattern_bytes > 1u);
    check(limits.max_text_bytes > 4u);
    check(limits.max_steps > 0u);
    check(re_status_string(RE_STATUS_NO_MATCH) != NULL);
    check(re_status_string(RE_STATUS_NO_MATCH)[0] != '\0');
    check(re_validate_n("(a|b", 4u, NULL) == RE_STATUS_INVALID_PATTERN);
    check(re_compile_n("a+b", 3u, NULL, &compiled) == RE_STATUS_OK);
    check(compiled != NULL);
    check(re_matchn(compiled, binary, sizeof(binary), NULL, &result)
            == RE_STATUS_OK);
    check(result.index == 2u && result.length == 3u);
    re_destroy(compiled);
    compiled = NULL;

    check(re_match_n("a+b", 3u, binary, sizeof(binary), NULL, &result)
            == RE_STATUS_OK);
    check(result.index == 2u && result.length == 3u);
    check(re_match("(cat|dog)", "xxdogyy", &matched) == 2);
    check(matched == 3);

    limits.max_text_bytes = 4u;
    check(re_match_n("a", 1u, no_match, sizeof(no_match) - 1u,
                       &limits, &result) == RE_STATUS_TEXT_LIMIT);
    limits = re_limits_default();
    limits.max_pattern_bytes = 2u;
    check(re_validate_n("a+b", 3u, &limits) == RE_STATUS_PATTERN_LIMIT);

    check(re_match_n("q", 1u, no_match, sizeof(no_match) - 1u,
                       NULL, &result) == RE_STATUS_NO_MATCH);
    check(re_compile("*bad") == NULL);
    check(re_compile_n(NULL, 1u, NULL, &compiled)
            == RE_STATUS_INVALID_ARGUMENT);
    check(compiled == NULL);
  }
}
