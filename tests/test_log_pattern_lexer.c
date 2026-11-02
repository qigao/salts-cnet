#include <log_pattern_lexer.h>
#include <string.h>
#include <tinytest.h>
spec("Original log-pattern lexer") {
  it("preserves tokens, unknown placeholders and bounded input") {
  const char *src="[{time_ms}] {level} {component}: {message} {bogus}";
  const char *cursor=src,*start=0;
  size_t n=0;
  const log_token_t tokens[] = {
    LOG_TOKEN_TEXT, LOG_TOKEN_TIME_MS, LOG_TOKEN_TEXT,
    LOG_TOKEN_LEVEL, LOG_TOKEN_TEXT, LOG_TOKEN_COMPONENT,
    LOG_TOKEN_TEXT, LOG_TOKEN_MESSAGE, LOG_TOKEN_TEXT,
    LOG_TOKEN_UNKNOWN, LOG_TOKEN_END
  };
  for(size_t i=0;i<sizeof(tokens)/sizeof(tokens[0]);++i) {
    check(log_pattern_scan(&cursor,&start,&n)==tokens[i]);
    if(tokens[i]==LOG_TOKEN_UNKNOWN)
      check(n==7 && memcmp(start,"{bogus}",7)==0);
    if(tokens[i]==LOG_TOKEN_TIME_MS)
      check(n==0);
  }
  const char raw[]={'a','{','f','i','l','e','}','{','x'};
  cursor=raw;
  check(log_pattern_scan_n(&cursor,raw+sizeof(raw),&start,&n)==LOG_TOKEN_TEXT);
  check(n==1 && start==raw);
  check(log_pattern_scan_n(&cursor,raw+sizeof(raw),&start,&n)==LOG_TOKEN_FILE);
  check(log_pattern_scan_n(&cursor,raw+sizeof(raw),&start,&n)==LOG_TOKEN_TEXT);
  check(n==1 && *start=='{');
  check(log_pattern_scan_n(&cursor,raw+sizeof(raw),&start,&n)==LOG_TOKEN_TEXT);
  check(n==1 && *start=='x');
  check(log_pattern_scan_n(&cursor,raw+sizeof(raw),&start,&n)==LOG_TOKEN_END);
  cursor="{x{y}";
  check(log_pattern_scan(&cursor,&start,&n)==LOG_TOKEN_UNKNOWN);
  check(n==5 && memcmp(start,"{x{y}",5)==0);
  }
}
