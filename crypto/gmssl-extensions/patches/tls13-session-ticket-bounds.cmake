# SPDX-License-Identifier: Apache-2.0
# Crypto #42: bounded TLS1.3 NewSessionTicket serialization in the sole
# pinned GmSSL static source. Test-only additive overlay; not published.
#
# GmSSL 3.2.0#14 previously serialized arbitrary length opaque tickets
# into uint8_t session[512] WITHOUT a capacity argument. Python stdlib ssl
# can send certificate-bound TLS1.3 resumption tickets exceeding 512 bytes;
# that would overwrite the native C stack while reading application data.
#
# tls13_session_to_bytes() already supports a NULL output size query.
# Require a bounded, accurate preflight length before the real write.
# Keep normal two-ticket Python server behavior; NEVER silently disable
# tickets to make the interoperability test pass. Oversize tickets fail
# closed with an explicit error, never partial/truncated serialization.
if(NOT COMMAND gmssl_replace_once)
    message(FATAL_ERROR "Pinned GmSSL source adaptation engine is required")
endif()
if(NOT DEFINED SOURCE_PATH OR NOT EXISTS "${SOURCE_PATH}/src/tls_psk.c")
    message(FATAL_ERROR "Pinned GmSSL TLS1.3 PSK source must exist")
endif()
set(_mtls_tls_psk "${SOURCE_PATH}/src/tls_psk.c")
gmssl_replace_once(
    "${_mtls_tls_psk}"
[==[
	uint8_t session[512];
	uint8_t *p = session;
	size_t sessionlen = 0;

	uint32_t ticket_issue_time = (uint32_t)time(NULL);

	if (tls13_session_to_bytes(conn->protocol, conn->cipher_suite, pre_shared_key, 32,
		ticket_issue_time, ticket_lifetime, ticket_age_add, ticket, ticketlen,
		&p, &sessionlen) != 1) {
		error_print();
		return -1;
	}
]==]
[==[
	/* One explicit per-ticket upper bound. Never call the unbounded
	 * serializer before an exact size query succeeds. Stack ownership
	 * remains bounded and no extra static/provider instance is created.
	 */
	uint8_t session[4096];
	uint8_t *p = session;
	size_t sessionlen = 0;
	size_t session_required = 0;

	uint32_t ticket_issue_time = (uint32_t)time(NULL);

	if (tls13_session_to_bytes(conn->protocol, conn->cipher_suite, pre_shared_key, 32,
		ticket_issue_time, ticket_lifetime, ticket_age_add, ticket, ticketlen,
		NULL, &session_required) != 1
		|| session_required == 0 || session_required > sizeof(session)) {
		error_print();
		return -1;
	}
	if (tls13_session_to_bytes(conn->protocol, conn->cipher_suite, pre_shared_key, 32,
		ticket_issue_time, ticket_lifetime, ticket_age_add, ticket, ticketlen,
		&p, &sessionlen) != 1 || sessionlen != session_required) {
		error_print();
		return -1;
	}
]==]
)
unset(_mtls_tls_psk)
