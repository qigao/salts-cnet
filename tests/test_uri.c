#include <uri_parser.h>
#include <tinytest.h>
#include <limits.h>
#include <string.h>

static int has(const char *a, const char *b) { return strcmp(a, b) == 0; }

spec("Native URI parser") {
  it("preserves host, credentials, IPv6, invalid input and overflow contracts") {
    uri_t u = {0};
    check(uri_parse("http://example.com", &u) && u.valid &&
          has(u.scheme, "http") && has(u.host, "example.com") &&
          u.host_type == URI_HOST_REGNAME);
    check(uri_parse("https://user:pass@example.com:443/path?x=y#frag", &u) &&
          has(u.userinfo, "user:pass") && has(u.scheme, "https") &&
          has(u.host, "example.com") && u.port == 443 &&
          has(u.path, "/path") && has(u.query, "x=y") &&
          has(u.fragment, "frag") &&
          (u.component_flags & (URI_COMPONENT_PORT | URI_COMPONENT_USERINFO |
                                URI_COMPONENT_QUERY | URI_COMPONENT_FRAGMENT)) ==
              (URI_COMPONENT_PORT | URI_COMPONENT_USERINFO |
               URI_COMPONENT_QUERY | URI_COMPONENT_FRAGMENT));
    check(uri_parse("http://[::1]:8080/path", &u) &&
          has(u.host, "::1") && u.host_type == URI_HOST_IPV6ADDR &&
          u.port == 8080);
    check(!uri_parse("http://example.com:", &u) && !u.valid &&
          !uri_parse("example.com", &u) && !uri_parse(NULL, &u) &&
          !uri_parse("http://example.com", NULL));
    check(uri_parse("tcp://example.com:999999999999999999999", &u) &&
          (u.component_flags & URI_COMPONENT_PORT) &&
          (u.overflow_flags & URI_OVERFLOW_PORT) && u.port == INT_MAX);
    check(uri_parse("tcp://example.com:80?", &u) &&
          (u.component_flags & URI_COMPONENT_QUERY) && has(u.query, ""));
  }
}
