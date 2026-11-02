# SPDX-License-Identifier: Apache-2.0
# Crypto #42: source-only candidate for the exact GmSSL 3.2.0#14 TLS 1.2
# CertificateRequest implementation. Applied ONLY by the isolated M5
# qualification workflow to an ephemeral vcpkg overlay source build.
#
# RFC 5246 section 7.4.4 allows an empty certificate_authorities vector:
# that means the TLS server states no preferred issuing CAs. It does NOT
# disable the server's client certificate verification, nor the client's
# independent server certificate/SAN validation.
#
# The original GmSSL code rejects an empty list unconditionally. Keep
# verification of all NONEMPTY authority lists exactly as before; only
# allow selecting an explicitly configured, bounded client identity when
# the server's presented CA-name list is empty.
#
# Do not silently apply to production #14, merge, release or change a TLS
# provider. The final source owner and SDK CI must be re-qualified.
if(NOT COMMAND gmssl_replace_once)
    message(FATAL_ERROR "The pinned GmSSL strict source patch engine is required")
endif()
if(NOT DEFINED SOURCE_PATH OR
   NOT EXISTS "${SOURCE_PATH}/src/tls12.c")
    message(FATAL_ERROR "The pinned GmSSL TLS1.2 source must be present")
endif()
set(_mtls_tls12 "${SOURCE_PATH}/src/tls12.c")
gmssl_replace_once(
    "${_mtls_tls12}"
[==[
	if (tls_authorities_issued_certificate(ca_names, ca_names_len,
		conn->client_certs, conn->client_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unsupported_certificate);
		return -1;
	}
	if (x509_certs_get_cert_by_index(conn->client_certs, conn->client_certs_len,
]==]
[==[
	/* RFC 5246 section 7.4.4: a zero-length acceptable-CA vector imposes
	 * no issuer preference. A nonempty vector must still match exactly.
	 * The server independently verifies client trust and CertificateVerify.
	 */
	if (ca_names_len != 0
		&& tls_authorities_issued_certificate(ca_names, ca_names_len,
			conn->client_certs, conn->client_certs_len) != 1) {
		error_print();
		tls_send_alert(conn, TLS_alert_unsupported_certificate);
		return -1;
	}
	if (x509_certs_get_cert_by_index(conn->client_certs, conn->client_certs_len,
]==]
)
unset(_mtls_tls12)
