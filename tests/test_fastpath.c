#include <fastpath.h>
#include <error_codes.h>
#include <tinytest.h>

spec("Platform fast-key native owner") {
  it("supports branch, enable, consume, disable and rejected inputs") {
    SALTS_FAST_KEY(key, false);
    check(!salts_fast_branch(&key));
    check(salts_fast_enable(&key) == SALTS_OK);
    check(salts_fast_branch(&key) && salts_fast_key_read(&key));
    check(salts_fast_key_consume(&key) && !salts_fast_key_read(&key));
    check(salts_fast_disable(&key) == SALTS_OK);
    check(salts_fast_key_set(&key, true) == SALTS_OK);
    check(salts_fast_key_set(NULL, true) == SALTS_EINVAL);
    check(!salts_fast_key_consume(NULL));
    check(salts_fast_key_read(&key));
  }
}
