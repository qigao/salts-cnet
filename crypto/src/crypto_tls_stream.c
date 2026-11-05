#include <crypto/tls_stream.h>

#if defined(CRYPTO_TLS_STREAM_TESTING)
  #include "crypto_tls_stream_test.h"
#endif


#include <gmssl/tls.h>
#include <gmssl/digest.h>
#include <gmssl/oid.h>
#include <gmssl/x509_cer.h>
#include <gmssl/x509_ext.h>
#include <gmssl/asn1.h>
#include <gmssl/pem.h>

#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_tls_memory_test.h"
#if defined(CRYPTO_TLS_STREAM_TESTING)
static _Thread_local crypto_tls_test_memory_stats crypto_tls_test_memory;

static void crypto_tls_test_add(uint64_t *value, uint64_t amount) {
  if (amount > UINT64_MAX - *value) {
    *value = UINT64_MAX;
    crypto_tls_test_memory.overflow = true;
  } else *value += amount;
}
bool crypto_tls_stream_test_memory_snapshot(crypto_tls_test_memory_stats *out) {
  if (out == NULL) return false;
  *out = crypto_tls_test_memory;
#if defined(SALTSCORE_GMSSL_COPY_PROFILE)
  if (!salts_gmssl_copy_snapshot(&out->provider)) return false;
  out->provider_copy_profile = true;
#endif
  return true;
}
static void crypto_tls_test_allocation(size_t bytes, const void *result) {
  crypto_tls_test_add(&crypto_tls_test_memory.allocation_calls, 1u);
  crypto_tls_test_add(&crypto_tls_test_memory.requested_bytes, (uint64_t)bytes);
  if (result != NULL) crypto_tls_test_add(&crypto_tls_test_memory.successful_bytes, (uint64_t)bytes);
  else crypto_tls_test_add(&crypto_tls_test_memory.failures, 1u);
}
static void *crypto_tls_stream_malloc(size_t bytes) {
  void *result = malloc(bytes);
  crypto_tls_test_allocation(bytes, result);
  return result;
}
static void *crypto_tls_stream_calloc(size_t count, size_t bytes) {
  void *result = calloc(count, bytes);
  if (count != 0u && bytes > SIZE_MAX / count) {
    crypto_tls_test_memory.overflow = true;
    crypto_tls_test_allocation(SIZE_MAX, result);
  } else crypto_tls_test_allocation(count * bytes, result);
  return result;
}
static void *crypto_tls_stream_realloc(void *old, size_t bytes) {
  void *result = realloc(old, bytes);
  crypto_tls_test_allocation(bytes, result);
  return result;
}
static void crypto_tls_stream_free(void *value) {
  if (value != NULL) crypto_tls_test_add(&crypto_tls_test_memory.releases, 1u);
  free(value);
}
static void *crypto_tls_stream_copy(crypto_tls_test_copy_kind kind, void *to, const void *from, size_t bytes) {
  void *result = memcpy(to, from, bytes);
  crypto_tls_test_add(&crypto_tls_test_memory.copy_calls[kind], 1u);
  crypto_tls_test_add(&crypto_tls_test_memory.copied_bytes[kind], (uint64_t)bytes);
  return result;
}
#else
#define crypto_tls_stream_malloc malloc
#define crypto_tls_stream_calloc calloc
#define crypto_tls_stream_realloc realloc
#define crypto_tls_stream_free free
#define crypto_tls_stream_copy(kind, to, from, bytes) memcpy((to), (from), (bytes))
#endif

#if defined(_WIN32)
  #include <winsock2.h>
  #include <windows.h>
  #include <wincrypt.h>
  #include <ws2tcpip.h>
#elif defined(__APPLE__)
  #include <arpa/inet.h>
  #include <dirent.h>
  #include <TargetConditionals.h>
  #include <CoreFoundation/CoreFoundation.h>
  #include <Security/Security.h>
#else
  #include <arpa/inet.h>
  #include <dirent.h>
#endif

enum {
  CRYPTO_TLS_STREAM_PATH_MAX_BYTES = 4095,
  CRYPTO_TLS_STREAM_PASSWORD_MAX_BYTES = 1023,
  CRYPTO_TLS_STREAM_TRUST_MAX_BYTES = 16 * 1024 * 1024,
  CRYPTO_TLS_STREAM_CERT_MAX_BYTES = 64 * 1024,
  CRYPTO_TLS_STREAM_PATH_BUFFER_BYTES = CRYPTO_TLS_STREAM_PATH_MAX_BYTES + 512
};

struct crypto_tls_stream {
  crypto_tls_stream_context *context;
  void *engine;
  /* Reserved for transport receive through terminal completion, never plaintext. */
  unsigned char *read_buffer;
  unsigned char *write_buffer;
  size_t io_buffer_bytes;
  size_t negotiated_alpn_size;
  unsigned char negotiated_alpn[CRYPTO_TLS_STREAM_ALPN_NAME_MAX_BYTES];
  bool server;
  bool handshake_started;
  bool handshake_complete;
  int handshake_error;
  int terminal_error;
  bool peer_close_notify;
  bool shutdown_started;
  bool close_notify_started;
};


typedef enum crypto_tls_stream_variant {
  CRYPTO_TLS_STREAM_VARIANT_RANGE = 0,
  CRYPTO_TLS_STREAM_VARIANT_1_2 = 1,
  CRYPTO_TLS_STREAM_VARIANT_1_3 = 2,
  CRYPTO_TLS_STREAM_VARIANT_SHANGMI_TLS13 = 3,
  CRYPTO_TLS_STREAM_VARIANT_TLCP11 = 4,
  CRYPTO_TLS_STREAM_VARIANT_COUNT = 5
} crypto_tls_stream_variant;

struct crypto_tls_stream_context {
  TLS_CTX tls[CRYPTO_TLS_STREAM_VARIANT_COUNT];
  bool tls_ready[CRYPTO_TLS_STREAM_VARIANT_COUNT];
  char **alpn_protocols;
  size_t alpn_protocol_count;
  char client_server_name[CRYPTO_TLS_STREAM_SERVER_NAME_CAPACITY];
  atomic_size_t references;
  bool server;
  bool verify_peer;
  bool native_system_trust;
  crypto_tls_stream_security_profile security_profile;
  crypto_tls_stream_peer_policy peer_policy;
};

typedef struct crypto_tls_stream_gmssl_state {
  TLS_CONNECT connection;
  TLS_IO io;
  unsigned char *cipher_input;
  unsigned char *cipher_output;
  unsigned char *plaintext;
  size_t capacity;
  size_t input_head;
  size_t input_size;
  size_t output_head;
  size_t output_size;
#if defined(CRYPTO_TLS_STREAM_TESTING)
  size_t diagnostic_send_calls;
  size_t diagnostic_send_requested;
  size_t diagnostic_send_accepted;
#endif
  size_t plaintext_pending_offset;
  size_t plaintext_pending_size;
  const unsigned char *write_source;
  size_t write_size;
  size_t write_offset;
  crypto_tls_stream_variant variant;
  bool connection_ready;
  char server_name[CRYPTO_TLS_STREAM_SERVER_NAME_CAPACITY];
} crypto_tls_stream_gmssl_state;

typedef struct crypto_tls_stream_der_bundle {
  unsigned char *data;
  size_t size;
  size_t capacity;
} crypto_tls_stream_der_bundle;

#define CRYPTO_TLS_STREAM_ENGINE(state) ((crypto_tls_stream_gmssl_state *)((state)->engine))
#define CRYPTO_TLS_STREAM_CONNECTION(state)   (CRYPTO_TLS_STREAM_ENGINE(state) != NULL ? &CRYPTO_TLS_STREAM_ENGINE(state)->connection : NULL)

static bool crypto_tls_stream_bounded_string(const char *value, size_t max_bytes, size_t *out_size) {
  size_t size;
  if (value == NULL) {
    if (out_size != NULL) *out_size = 0u;
    return true;
  }
  for (size = 0u; size <= max_bytes; ++size) {
    if (value[size] == '\0') {
      if (out_size != NULL) *out_size = size;
      return true;
    }
  }
  return false;
}

static bool crypto_tls_stream_optional_path_valid(const char *value) {
  size_t size = 0u;
  return crypto_tls_stream_bounded_string(value, CRYPTO_TLS_STREAM_PATH_MAX_BYTES, &size) &&
         (value == NULL || size != 0u);
}

static int crypto_tls_stream_der_bundle_required_size(size_t current, size_t appended,
                                             size_t *out_required) {
  if (out_required == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  *out_required = 0u;
  if (appended == 0u) return CRYPTO_TLS_STREAM_EINVAL;
  if (appended > CRYPTO_TLS_STREAM_TRUST_MAX_BYTES || current > CRYPTO_TLS_STREAM_TRUST_MAX_BYTES - appended)
    return CRYPTO_TLS_STREAM_ERANGE;
  *out_required = current + appended;
  return CRYPTO_TLS_STREAM_OK;
}

#if defined(CRYPTO_TLS_STREAM_TESTING)
int crypto_tls_stream_test_der_bundle_required_size(size_t current, size_t appended, size_t *out_required) {
  return crypto_tls_stream_der_bundle_required_size(current, appended, out_required);
}
#endif

#if !defined(_WIN32) && !defined(__APPLE__)
static bool crypto_tls_stream_file_readable(const char *path) {
  FILE *file;
  if (path == NULL || path[0] == '\0') return false;
  file = fopen(path, "rb");
  if (file == NULL) return false;
  (void)fclose(file);
  return true;
}
#endif

static int crypto_tls_stream_der_bundle_append(crypto_tls_stream_der_bundle *bundle,
                                      const unsigned char *data, size_t size) {
  unsigned char *next;
  size_t capacity;
  size_t required;
  int status;
  if (bundle == NULL || data == NULL || size == 0u) return CRYPTO_TLS_STREAM_EINVAL;
  status = crypto_tls_stream_der_bundle_required_size(bundle->size, size, &required);
  if (status != CRYPTO_TLS_STREAM_OK) return status;
  if (required <= bundle->capacity) {
    crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_METADATA, bundle->data + bundle->size, data, size);
    bundle->size = required;
    return CRYPTO_TLS_STREAM_OK;
  }

  capacity = bundle->capacity != 0u ? bundle->capacity : 4096u;
  while (capacity < required) {
    if (capacity > CRYPTO_TLS_STREAM_TRUST_MAX_BYTES / 2u) {
      capacity = CRYPTO_TLS_STREAM_TRUST_MAX_BYTES;
      break;
    }
    capacity *= 2u;
  }
  if (capacity < required) return CRYPTO_TLS_STREAM_ERANGE;
  next = (unsigned char *)crypto_tls_stream_realloc(bundle->data, capacity);
  if (next == NULL) return CRYPTO_TLS_STREAM_ENOMEM;
  bundle->data = next;
  bundle->capacity = capacity;
  crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_METADATA, bundle->data + bundle->size, data, size);
  bundle->size = required;
  return CRYPTO_TLS_STREAM_OK;
}

static void crypto_tls_stream_der_bundle_dispose(crypto_tls_stream_der_bundle *bundle) {
  if (bundle == NULL) return;
  crypto_tls_stream_free(bundle->data);
  memset(bundle, 0, sizeof(*bundle));
}

static bool crypto_tls_stream_ca_hash_name(const char *name) {
  size_t index;
  if (name == NULL) return false;
  for (index = 0u; index < 8u; ++index) {
    const char ch = name[index];
    if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
          (ch >= 'A' && ch <= 'F')))
      return false;
  }
  if (name[8] != '.') return false;
  index = 9u;
  if (name[index] < '0' || name[index] > '9') return false;
  while (name[index] >= '0' && name[index] <= '9') ++index;
  return name[index] == '\0';
}

static int crypto_tls_stream_pem_seek_entry(FILE *file) {
  int ch;
  if (file == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  for (;;) {
    ch = fgetc(file);
    if (ch == EOF) return feof(file) ? CRYPTO_TLS_STREAM_EOF : CRYPTO_TLS_STREAM_EIO;
    if (ch == '\0' || ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
      continue;
    if (ungetc(ch, file) == EOF) return CRYPTO_TLS_STREAM_EIO;
    return CRYPTO_TLS_STREAM_OK;
  }
}

static int crypto_tls_stream_append_pem_cert_file(crypto_tls_stream_der_bundle *bundle,
                                         const char *path,
                                         size_t *out_count) {
  unsigned char certificate[CRYPTO_TLS_STREAM_CERT_MAX_BYTES];
  FILE *file;
  size_t count = 0u;
  int status = CRYPTO_TLS_STREAM_OK;

  if (bundle == NULL || path == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  file = fopen(path, "rb");
  if (file == NULL) return CRYPTO_TLS_STREAM_EIO;
  for (;;) {
    size_t size = 0u;
    int result;

    status = crypto_tls_stream_pem_seek_entry(file);
    if (status == CRYPTO_TLS_STREAM_EOF) {
      status = CRYPTO_TLS_STREAM_OK;
      break;
    }
    if (status != CRYPTO_TLS_STREAM_OK) break;

    result = pem_read(file, "CERTIFICATE", certificate, &size,
                      sizeof(certificate));
    if (result <= 0 || size == 0u) {
      status = CRYPTO_TLS_STREAM_EIO;
      break;
    }
    status = crypto_tls_stream_der_bundle_append(bundle, certificate, size);
    if (status != CRYPTO_TLS_STREAM_OK) break;
    ++count;
  }
  (void)fclose(file);
  memset(certificate, 0, sizeof(certificate));
  if (status == CRYPTO_TLS_STREAM_OK && count == 0u) status = CRYPTO_TLS_STREAM_EIO;
  if (out_count != NULL) *out_count = count;
  return status;
}

static int crypto_tls_stream_tlcp_certificate_roles_valid(const char *path) {
  unsigned char certificate[CRYPTO_TLS_STREAM_CERT_MAX_BYTES];
  FILE *file;
  unsigned int role;
  int status = CRYPTO_TLS_STREAM_OK;

  if (path == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  file = fopen(path, "rb");
  if (file == NULL) return CRYPTO_TLS_STREAM_EIO;
  for (role = 0u; role < 2u; ++role) {
    const unsigned char *extensions = NULL;
    size_t extensions_size = 0u;
    const unsigned char *encoded_usage = NULL;
    size_t encoded_usage_size = 0u;
    const unsigned char *cursor;
    size_t remaining;
    size_t certificate_size = 0u;
    int critical = 0;
    int usage = 0;

    status = crypto_tls_stream_pem_seek_entry(file);
    if (status != CRYPTO_TLS_STREAM_OK ||
        pem_read(file, "CERTIFICATE", certificate, &certificate_size,
                 sizeof(certificate)) != 1 ||
        certificate_size == 0u ||
        x509_cert_get_exts(certificate, certificate_size,
                           &extensions, &extensions_size) != 1 ||
        x509_exts_get_ext_by_oid(extensions, extensions_size,
                                 OID_ce_key_usage, &critical,
                                 &encoded_usage, &encoded_usage_size) != 1) {
      status = CRYPTO_TLS_STREAM_EIO;
      break;
    }
    cursor = encoded_usage;
    remaining = encoded_usage_size;
    if (x509_key_usage_from_der(&usage, &cursor, &remaining) != 1 ||
        remaining != 0u ||
        (role == 0u &&
         ((usage & X509_KU_DIGITAL_SIGNATURE) == 0 ||
          (usage & X509_KU_KEY_ENCIPHERMENT) != 0)) ||
        (role == 1u &&
         ((usage & X509_KU_KEY_ENCIPHERMENT) == 0 ||
          (usage & X509_KU_DIGITAL_SIGNATURE) != 0))) {
      status = CRYPTO_TLS_STREAM_EIO;
      break;
    }
  }
  (void)fclose(file);
  memset(certificate, 0, sizeof(certificate));
  return status;
}

static int crypto_tls_stream_append_ca_path(crypto_tls_stream_der_bundle *bundle,
                                   const char *directory,
                                   size_t *out_count) {
  size_t count = 0u;
  int status = CRYPTO_TLS_STREAM_OK;
  if (bundle == NULL || directory == NULL || directory[0] == '\0')
    return CRYPTO_TLS_STREAM_EINVAL;
#if defined(_WIN32)
  {
    WIN32_FIND_DATAA data;
    HANDLE search;
    char pattern[CRYPTO_TLS_STREAM_PATH_BUFFER_BYTES];
    int length = snprintf(pattern, sizeof(pattern), "%s\\*", directory);
    if (length < 0 || (size_t)length >= sizeof(pattern)) return CRYPTO_TLS_STREAM_ERANGE;
    search = FindFirstFileA(pattern, &data);
    if (search == INVALID_HANDLE_VALUE) return CRYPTO_TLS_STREAM_EIO;
    do {
      char path[CRYPTO_TLS_STREAM_PATH_BUFFER_BYTES];
      size_t file_count = 0u;
      if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
          !crypto_tls_stream_ca_hash_name(data.cFileName))
        continue;
      length = snprintf(path, sizeof(path), "%s\\%s", directory, data.cFileName);
      if (length < 0 || (size_t)length >= sizeof(path)) {
        status = CRYPTO_TLS_STREAM_ERANGE;
        break;
      }
      status = crypto_tls_stream_append_pem_cert_file(bundle, path, &file_count);
      if (status != CRYPTO_TLS_STREAM_OK) break;
      count += file_count;
    } while (FindNextFileA(search, &data) != 0);
    (void)FindClose(search);
  }
#else
  {
    DIR *dir = opendir(directory);
    struct dirent *entry;
    if (dir == NULL) return CRYPTO_TLS_STREAM_EIO;
    while ((entry = readdir(dir)) != NULL) {
      char path[CRYPTO_TLS_STREAM_PATH_BUFFER_BYTES];
      size_t file_count = 0u;
      int length;
      if (!crypto_tls_stream_ca_hash_name(entry->d_name)) continue;
      length = snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
      if (length < 0 || (size_t)length >= sizeof(path)) {
        status = CRYPTO_TLS_STREAM_ERANGE;
        break;
      }
      status = crypto_tls_stream_append_pem_cert_file(bundle, path, &file_count);
      if (status != CRYPTO_TLS_STREAM_OK) break;
      count += file_count;
    }
    (void)closedir(dir);
  }
#endif
  if (status == CRYPTO_TLS_STREAM_OK && count == 0u) status = CRYPTO_TLS_STREAM_EIO;
  if (out_count != NULL) *out_count = count;
  return status;
}

static int crypto_tls_stream_load_explicit_trust(TLS_CTX *tls,
                                        const char *ca_file,
                                        const char *ca_path) {
  crypto_tls_stream_der_bundle bundle = {0};
  size_t count = 0u;
  int status = CRYPTO_TLS_STREAM_OK;

  if (tls == NULL || (ca_file == NULL && ca_path == NULL)) return CRYPTO_TLS_STREAM_EINVAL;
  if (ca_file != NULL) {
    size_t file_count = 0u;
    status = crypto_tls_stream_append_pem_cert_file(&bundle, ca_file, &file_count);
    if (status == CRYPTO_TLS_STREAM_OK) count += file_count;
  }
  if (status == CRYPTO_TLS_STREAM_OK && ca_path != NULL) {
    size_t path_count = 0u;
    status = crypto_tls_stream_append_ca_path(&bundle, ca_path, &path_count);
    if (status == CRYPTO_TLS_STREAM_OK) count += path_count;
  }
  if (status == CRYPTO_TLS_STREAM_OK && count == 0u) status = CRYPTO_TLS_STREAM_EIO;
  if (status == CRYPTO_TLS_STREAM_OK &&
      tls_ctx_set_ca_certificates_der(tls, bundle.data, bundle.size,
                                      TLS_DEFAULT_VERIFY_DEPTH) != 1)
    status = CRYPTO_TLS_STREAM_EIO;
  crypto_tls_stream_der_bundle_dispose(&bundle);
  return status;
}

#if defined(_WIN32)
static int crypto_tls_stream_append_windows_store(crypto_tls_stream_der_bundle *bundle, const char *name) {
  HCERTSTORE store;
  PCCERT_CONTEXT certificate = NULL;
  int status = CRYPTO_TLS_STREAM_OK;

  if (bundle == NULL || name == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  store = CertOpenSystemStoreA(0u, name);
  if (store == NULL) return CRYPTO_TLS_STREAM_EIO;
  while ((certificate = CertEnumCertificatesInStore(store, certificate)) != NULL) {
    status = crypto_tls_stream_der_bundle_append(bundle, certificate->pbCertEncoded,
                                        (size_t)certificate->cbCertEncoded);
    if (status != CRYPTO_TLS_STREAM_OK) break;
  }
  (void)CertCloseStore(store, 0u);
  return status;
}
#endif

#if defined(__APPLE__) && TARGET_OS_OSX
static int crypto_tls_stream_load_apple_anchors(crypto_tls_stream_der_bundle *bundle) {
  CFArrayRef anchors = NULL;
  CFIndex index;
  CFIndex count;
  OSStatus result;
  int status = CRYPTO_TLS_STREAM_OK;

  if (bundle == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  result = SecTrustCopyAnchorCertificates(&anchors);
  if (result != errSecSuccess || anchors == NULL) return CRYPTO_TLS_STREAM_EIO;
  count = CFArrayGetCount(anchors);
  for (index = 0; index < count; ++index) {
    SecCertificateRef certificate =
        (SecCertificateRef)CFArrayGetValueAtIndex(anchors, index);
    CFDataRef der;
    if (certificate == NULL) continue;
    der = SecCertificateCopyData(certificate);
    if (der == NULL) {
      status = CRYPTO_TLS_STREAM_EIO;
      break;
    }
    status = crypto_tls_stream_der_bundle_append(
        bundle, (const unsigned char *)CFDataGetBytePtr(der),
        (size_t)CFDataGetLength(der));
    CFRelease(der);
    if (status != CRYPTO_TLS_STREAM_OK) break;
  }
  CFRelease(anchors);
  return status;
}
#endif

static int crypto_tls_stream_load_system_trust(TLS_CTX *tls) {
#if defined(_WIN32)
  crypto_tls_stream_der_bundle bundle = {0};
  /* Windows ROOT is the trust-anchor store. CA holds intermediates for
   * path building and is NOT an independent trusted-anchor source.
   * tls_ctx_set_ca_certificates_der treats every supplied DER certificate
   * as an anchor candidate: including CA would silently promote an
   * untrusted intermediate into a root authority. Never merge stores. */
  int status = crypto_tls_stream_append_windows_store(&bundle, "ROOT");
  if (status == CRYPTO_TLS_STREAM_OK && bundle.size == 0u) status = CRYPTO_TLS_STREAM_EIO;
  if (status == CRYPTO_TLS_STREAM_OK &&
      tls_ctx_set_ca_certificates_der(tls, bundle.data, bundle.size,
                                      TLS_DEFAULT_VERIFY_DEPTH) != 1)
    status = CRYPTO_TLS_STREAM_EIO;
  crypto_tls_stream_der_bundle_dispose(&bundle);
  return status;
#elif defined(__APPLE__)
  #if TARGET_OS_OSX
    crypto_tls_stream_der_bundle bundle = {0};
    int status = crypto_tls_stream_load_apple_anchors(&bundle);
    if (status == CRYPTO_TLS_STREAM_OK && bundle.size == 0u) status = CRYPTO_TLS_STREAM_EIO;
    if (status == CRYPTO_TLS_STREAM_OK &&
        tls_ctx_set_ca_certificates_der(tls, bundle.data, bundle.size,
                                        TLS_DEFAULT_VERIFY_DEPTH) != 1)
      status = CRYPTO_TLS_STREAM_EIO;
    crypto_tls_stream_der_bundle_dispose(&bundle);
    return status;
  #else
    /*
     * iOS does not expose a public system-root enumeration API equivalent to
     * macOS SecTrustCopyAnchorCertificates(). Keep GmSSL's certificate/identity
     * checks active, but delegate only trust-anchor/path validation to the
     * Security.framework bridge after the provider handshake.
     */
    return tls_ctx_enable_external_trust(tls, 1) == 1
               ? CRYPTO_TLS_STREAM_OK
               : CRYPTO_TLS_STREAM_EIO;
  #endif
#elif defined(__ANDROID__)
  return crypto_tls_stream_load_explicit_trust(
      tls, NULL, "/system/etc/security/cacerts");
#else
  static const char *const paths[] = {
      "/etc/ssl/certs/ca-certificates.crt",
      "/etc/pki/tls/certs/ca-bundle.crt",
      "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
      "/etc/ssl/ca-bundle.pem"};
  const char *environment = getenv("SSL_CERT_FILE");
  size_t index;

  if (environment != NULL && environment[0] != '\0' &&
      crypto_tls_stream_file_readable(environment))
    return crypto_tls_stream_load_explicit_trust(tls, environment, NULL);
  for (index = 0u; index < sizeof(paths) / sizeof(paths[0]); ++index) {
    if (crypto_tls_stream_file_readable(paths[index]))
      return crypto_tls_stream_load_explicit_trust(tls, paths[index], NULL);
  }
  return CRYPTO_TLS_STREAM_EIO;
#endif
}

static void crypto_tls_stream_alpn_dispose(crypto_tls_stream_context *context) {
  size_t index;
  if (context == NULL || context->alpn_protocols == NULL) return;
  for (index = 0u; index < context->alpn_protocol_count; ++index)
    crypto_tls_stream_free(context->alpn_protocols[index]);
  crypto_tls_stream_free(context->alpn_protocols);
  context->alpn_protocols = NULL;
  context->alpn_protocol_count = 0u;
}

static int crypto_tls_stream_alpn_copy(crypto_tls_stream_context *context,
                              const char *const *protocols, size_t count) {
  size_t index;
  size_t wire_size = 0u;

  if (context == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  if (count == 0u) return protocols == NULL ? CRYPTO_TLS_STREAM_OK : CRYPTO_TLS_STREAM_EINVAL;
  if (protocols == NULL) return CRYPTO_TLS_STREAM_EINVAL;

  for (index = 0u; index < count; ++index) {
    size_t length = 0u;
    if (protocols[index] == NULL ||
        !crypto_tls_stream_bounded_string(protocols[index],
                                 CRYPTO_TLS_STREAM_ALPN_NAME_MAX_BYTES, &length) ||
        length == 0u)
      return CRYPTO_TLS_STREAM_EINVAL;
    if (wire_size > UINT16_MAX - 1u - length) return CRYPTO_TLS_STREAM_ERANGE;
    wire_size += 1u + length;
  }

  if (count > SIZE_MAX / sizeof(char *)) return CRYPTO_TLS_STREAM_ERANGE;
  context->alpn_protocols = (char **)crypto_tls_stream_calloc(count, sizeof(char *));
  if (context->alpn_protocols == NULL) return CRYPTO_TLS_STREAM_ENOMEM;
  context->alpn_protocol_count = count;

  for (index = 0u; index < count; ++index) {
    size_t length = strlen(protocols[index]);
    context->alpn_protocols[index] = (char *)crypto_tls_stream_malloc(length + 1u);
    if (context->alpn_protocols[index] == NULL) {
      crypto_tls_stream_alpn_dispose(context);
      return CRYPTO_TLS_STREAM_ENOMEM;
    }
    crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_METADATA, context->alpn_protocols[index], protocols[index], length + 1u);
  }
  return CRYPTO_TLS_STREAM_OK;
}

static int crypto_tls_stream_variant_protocol(crypto_tls_stream_variant variant) {
  if (variant == CRYPTO_TLS_STREAM_VARIANT_1_2) return TLS_protocol_tls12;
  if (variant == CRYPTO_TLS_STREAM_VARIANT_TLCP11) return TLS_protocol_tlcp;
  return TLS_protocol_tls13;
}

static int crypto_tls_stream_configure_variant(crypto_tls_stream_context *context,
                                      crypto_tls_stream_variant variant,
                                      const char *ca_file,
                                      const char *ca_path,
                                      const char *cert_file,
                                      const char *key_file,
                                      const char *key_password,
                                      crypto_tls_stream_client_auth client_auth,
                                      uint32_t key_update_record_limit,
                                      uint32_t peer_key_update_limit) {
  static const int range_ciphers[] = {
      TLS_cipher_aes_128_gcm_sha256,
      TLS_cipher_ecdhe_rsa_with_aes_128_gcm_sha256,
      TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256};
  static const int tls13_ciphers[] = {TLS_cipher_aes_128_gcm_sha256};
  static const int shangmi_ciphers[] = {TLS_cipher_sm4_gcm_sm3};
  static const int tlcp_ciphers[] = {TLS_cipher_ecc_sm4_gcm_sm3};
  static const int shangmi_signatures[] = {TLS_sig_sm2sig_sm3};
  static const int shangmi_groups[] = {TLS_curve_sm2p256v1};
  static const int tls12_ciphers[] = {
      TLS_cipher_ecdhe_rsa_with_aes_128_gcm_sha256,
      TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256};
  static const int range_signatures[] = {
      TLS_sig_rsa_pss_rsae_sha256,
      TLS_sig_rsa_pkcs1_sha256,
      TLS_sig_ecdsa_secp256r1_sha256,
      TLS_sig_ecdsa_secp384r1_sha384};
  static const int tls13_signatures[] = {
      TLS_sig_rsa_pss_rsae_sha256,
      TLS_sig_rsa_pkcs1_sha256,
      TLS_sig_ecdsa_secp256r1_sha256,
      TLS_sig_ecdsa_secp384r1_sha384};
  static const int tls12_signatures[] = {
      TLS_sig_rsa_pkcs1_sha256,
      TLS_sig_ecdsa_secp256r1_sha256,
      TLS_sig_ecdsa_secp384r1_sha384};
  static const int groups[] = {TLS_curve_secp256r1};
  const int *selected_groups = groups;
  size_t group_count = sizeof(groups) / sizeof(groups[0]);
  TLS_CTX *tls;
  const int *ciphers;
  const int *signatures;
  size_t cipher_count;
  size_t signature_count;
  int mode;
  int status = CRYPTO_TLS_STREAM_OK;

  if (context == NULL || variant < 0 || variant >= CRYPTO_TLS_STREAM_VARIANT_COUNT)
    return CRYPTO_TLS_STREAM_EINVAL;
  tls = &context->tls[variant];
  mode = context->server ? TLS_server_mode : TLS_client_mode;
  if (tls_ctx_init(tls, crypto_tls_stream_variant_protocol(variant), mode) != 1)
    return CRYPTO_TLS_STREAM_EIO;
  context->tls_ready[variant] = true;

  if (variant == CRYPTO_TLS_STREAM_VARIANT_SHANGMI_TLS13) {
    /* Exact provider admission must happen before any other TLS_CTX policy.
     * Never retry or fall back to the standard TLS1.2/1.3 configuration. */
    if (tls_ctx_set_strict_protocol(tls, TLS_protocol_tls13) != 1)
      return CRYPTO_TLS_STREAM_EIO;
    ciphers = shangmi_ciphers;
    cipher_count = sizeof(shangmi_ciphers) / sizeof(shangmi_ciphers[0]);
    signatures = shangmi_signatures;
    signature_count = sizeof(shangmi_signatures) / sizeof(shangmi_signatures[0]);
    selected_groups = shangmi_groups;
    group_count = sizeof(shangmi_groups) / sizeof(shangmi_groups[0]);
  } else if (variant == CRYPTO_TLS_STREAM_VARIANT_TLCP11) {
    /* TLCP is an explicit protocol, not a TLS version range. Pin its modern
     * AEAD suite and never admit the provider's CBC alternative. */
    if (tls_ctx_set_strict_protocol(tls, TLS_protocol_tlcp) != 1)
      return CRYPTO_TLS_STREAM_EIO;
    ciphers = tlcp_ciphers;
    cipher_count = sizeof(tlcp_ciphers) / sizeof(tlcp_ciphers[0]);
    signatures = shangmi_signatures;
    signature_count = sizeof(shangmi_signatures) / sizeof(shangmi_signatures[0]);
    selected_groups = shangmi_groups;
    group_count = sizeof(shangmi_groups) / sizeof(shangmi_groups[0]);
  } else if (variant == CRYPTO_TLS_STREAM_VARIANT_RANGE) {
    if (tls_ctx_set_protocol_range(tls, TLS_protocol_tls12,
                                   TLS_protocol_tls13) != 1)
      return CRYPTO_TLS_STREAM_EIO;
    ciphers = range_ciphers;
    cipher_count = sizeof(range_ciphers) / sizeof(range_ciphers[0]);
    signatures = range_signatures;
    signature_count = sizeof(range_signatures) / sizeof(range_signatures[0]);
  } else if (variant == CRYPTO_TLS_STREAM_VARIANT_1_2) {
    ciphers = tls12_ciphers;
    cipher_count = sizeof(tls12_ciphers) / sizeof(tls12_ciphers[0]);
    signatures = tls12_signatures;
    signature_count = sizeof(tls12_signatures) / sizeof(tls12_signatures[0]);
  } else {
    ciphers = tls13_ciphers;
    cipher_count = sizeof(tls13_ciphers) / sizeof(tls13_ciphers[0]);
    signatures = tls13_signatures;
    signature_count = sizeof(tls13_signatures) / sizeof(tls13_signatures[0]);
  }

  if (tls_ctx_set_cipher_suites(tls, ciphers, cipher_count) != 1 ||
      tls_ctx_set_supported_groups(tls, selected_groups, group_count) != 1 ||
      tls_ctx_set_signature_algorithms(tls, signatures, signature_count) != 1)
    return CRYPTO_TLS_STREAM_EIO;

  if (key_update_record_limit != 0u &&
      (tls13_ctx_enable_key_update(tls, 1) != 1 ||
       tls13_ctx_set_key_update_seq_num_limit(tls, key_update_record_limit) != 1))
    return CRYPTO_TLS_STREAM_EIO;
  if (peer_key_update_limit != 0u &&
      tls13_ctx_set_peer_key_update_limit(tls, peer_key_update_limit) != 1)
    return CRYPTO_TLS_STREAM_EIO;

  /* RFC 5746 initial-handshake secure renegotiation is mandatory for
   * TLS1.2, including when the normal public context negotiates TLS12/13.
   * This is never permission to renegotiate or downgrade an established TLS
   * session, and pure TLS1.3/TLCP profiles remain unchanged. */
  if (variant == CRYPTO_TLS_STREAM_VARIANT_1_2 ||
      (variant == CRYPTO_TLS_STREAM_VARIANT_RANGE && context->server)) {
    if (context->server) {
      if (tls12_ctx_set_renegotiation_info(tls, 1) != 1)
        return CRYPTO_TLS_STREAM_EIO;
    } else if (tls12_ctx_set_empty_renegotiation_info_scsv(tls, 1) != 1) {
      return CRYPTO_TLS_STREAM_EIO;
    }
  }

  if (context->alpn_protocol_count != 0u &&
      tls_ctx_set_application_layer_protocol_negotiation(
          tls, context->alpn_protocols, context->alpn_protocol_count) != 1)
    return CRYPTO_TLS_STREAM_EIO;

  if (context->verify_peer) {
    status = (ca_file != NULL || ca_path != NULL)
                 ? crypto_tls_stream_load_explicit_trust(tls, ca_file, ca_path)
                 : crypto_tls_stream_load_system_trust(tls);
    if (status != CRYPTO_TLS_STREAM_OK) return status;
  }

  if (cert_file != NULL) {
    int certificate_result;
    if (variant == CRYPTO_TLS_STREAM_VARIANT_TLCP11 && context->server) {
      if (crypto_tls_stream_tlcp_certificate_roles_valid(cert_file) != CRYPTO_TLS_STREAM_OK)
        return CRYPTO_TLS_STREAM_EIO;
      certificate_result = tls_ctx_set_tlcp_server_certificate_and_keys(
          tls, cert_file, key_file,
          key_password != NULL ? key_password : "");
    } else {
      certificate_result = tls_ctx_set_certificate_and_key(
          tls, cert_file, key_file,
          key_password != NULL ? key_password : "");
    }
    if (certificate_result != 1)
      return CRYPTO_TLS_STREAM_EIO;
  }

  if (context->server && client_auth == CRYPTO_TLS_STREAM_CLIENT_AUTH_REQUIRED &&
      tls_ctx_enable_certificate_request(tls, 1) != 1)
    return CRYPTO_TLS_STREAM_EIO;

  return CRYPTO_TLS_STREAM_OK;
}

static void crypto_tls_stream_context_dispose(crypto_tls_stream_context *context) {
  size_t index;
  if (context == NULL) return;
  for (index = 0u; index < CRYPTO_TLS_STREAM_VARIANT_COUNT; ++index) {
    if (context->tls_ready[index]) tls_ctx_cleanup(&context->tls[index]);
  }
  crypto_tls_stream_alpn_dispose(context);
  if (context->peer_policy.release != NULL)
    context->peer_policy.release(context->peer_policy.context);
  crypto_tls_stream_free(context);
}

void crypto_tls_stream_context_retain(crypto_tls_stream_context *context) {
  if (context != NULL)
    (void)atomic_fetch_add_explicit(&context->references, 1u,
                                    memory_order_relaxed);
}

void crypto_tls_stream_context_release(crypto_tls_stream_context *context) {
  if (context != NULL &&
      atomic_fetch_sub_explicit(&context->references, 1u,
                                memory_order_acq_rel) == 1u)
    crypto_tls_stream_context_dispose(context);
}

static int crypto_tls_stream_context_create_common(
    bool server, bool verify_peer, const char *ca_file, const char *ca_path,
    const char *cert_file, const char *key_file, const char *key_password,
    crypto_tls_stream_client_auth client_auth, const char *const *alpn_protocols,
    size_t alpn_protocol_count, crypto_tls_stream_security_profile security_profile,
    const crypto_tls_stream_peer_policy *peer_policy,
    uint32_t key_update_record_limit,
    uint32_t peer_key_update_limit,
    crypto_tls_stream_context **out_context) {
  crypto_tls_stream_context *context;
  size_t index;
  int status;

  if (out_context == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  *out_context = NULL;

  if (key_update_record_limit > CRYPTO_TLS_STREAM_KEY_UPDATE_RECORD_LIMIT_MAX)
    return CRYPTO_TLS_STREAM_EINVAL;
  if ((key_update_record_limit != 0u || peer_key_update_limit != 0u) &&
      security_profile != CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13)
    return CRYPTO_TLS_STREAM_ENOTSUP;

  if (peer_policy != NULL &&
      (!verify_peer || peer_policy->check == NULL ||
       peer_policy->retain == NULL || peer_policy->release == NULL))
    return CRYPTO_TLS_STREAM_EINVAL;

  if (peer_policy != NULL) {
    const uint32_t known_profiles = CRYPTO_TLS_PEER_POLICY_STANDARD |
        CRYPTO_TLS_PEER_POLICY_SHANGMI_TLS13 | CRYPTO_TLS_PEER_POLICY_TLCP11;
    const uint32_t known_roles = CRYPTO_TLS_PEER_POLICY_CLIENT | CRYPTO_TLS_PEER_POLICY_SERVER;
    const uint32_t peer_role = server ? CRYPTO_TLS_PEER_POLICY_CLIENT : CRYPTO_TLS_PEER_POLICY_SERVER;
    if ((peer_policy->supported_profiles & ~known_profiles) != 0u ||
        (peer_policy->supported_peer_roles & ~known_roles) != 0u)
      return CRYPTO_TLS_STREAM_EINVAL;
    if ((peer_policy->supported_profiles != 0u &&
         (peer_policy->supported_profiles & (1u << security_profile)) == 0u) ||
        (peer_policy->supported_peer_roles != 0u &&
         (peer_policy->supported_peer_roles & peer_role) == 0u))
      return CRYPTO_TLS_STREAM_ENOTSUP;
  }

  context = (crypto_tls_stream_context *)crypto_tls_stream_calloc(1u, sizeof(*context));
  if (context == NULL) return CRYPTO_TLS_STREAM_ENOMEM;
  context->server = server;
  context->verify_peer = verify_peer;
  context->security_profile = security_profile;
#if defined(__APPLE__) && !TARGET_OS_OSX
  context->native_system_trust =
      !server && verify_peer && ca_file == NULL && ca_path == NULL;
#else
  context->native_system_trust = false;
#endif
  atomic_init(&context->references, 1u);

  status = crypto_tls_stream_alpn_copy(context, alpn_protocols, alpn_protocol_count);
  if (status != CRYPTO_TLS_STREAM_OK) {
    crypto_tls_stream_context_dispose(context);
    return status;
  }

  for (index = 0u; index < CRYPTO_TLS_STREAM_VARIANT_COUNT; ++index) {
    if (security_profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13 &&
        index != CRYPTO_TLS_STREAM_VARIANT_SHANGMI_TLS13) continue;
    if (security_profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD &&
        (index == CRYPTO_TLS_STREAM_VARIANT_SHANGMI_TLS13 ||
         index == CRYPTO_TLS_STREAM_VARIANT_TLCP11)) continue;
    if (security_profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11 &&
        index != CRYPTO_TLS_STREAM_VARIANT_TLCP11) continue;
    status = crypto_tls_stream_configure_variant(
        context, (crypto_tls_stream_variant)index, ca_file, ca_path, cert_file, key_file,
        key_password, client_auth, key_update_record_limit, peer_key_update_limit);
    if (status != CRYPTO_TLS_STREAM_OK) {
      crypto_tls_stream_context_dispose(context);
      return status;
    }
  }

  if (peer_policy != NULL) {
    context->peer_policy = *peer_policy;
    context->peer_policy.retain(context->peer_policy.context);
  }
  *out_context = context;
  return CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_stream_client_context_create(const crypto_tls_stream_client_config *config,
                                   crypto_tls_stream_context **out_context) {
  crypto_tls_stream_client_config defaults = {sizeof(defaults)};
  crypto_tls_stream_context *context = NULL;
  int status;

  if (out_context == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  *out_context = NULL;
  if (config == NULL) config = &defaults;
  if (config->size != sizeof(*config) ||
      !crypto_tls_stream_optional_path_valid(config->ca_file) ||
      !crypto_tls_stream_optional_path_valid(config->ca_path) ||
      !crypto_tls_stream_optional_path_valid(config->cert_file) ||
      !crypto_tls_stream_optional_path_valid(config->key_file) ||
      !crypto_tls_stream_bounded_string(config->key_password,
                               CRYPTO_TLS_STREAM_PASSWORD_MAX_BYTES, NULL) ||
      !crypto_tls_stream_bounded_string(config->server_name,
                               CRYPTO_TLS_STREAM_SERVER_NAME_CAPACITY - 1u, NULL) ||
      (config->server_name != NULL && config->server_name[0] == '\0') ||
      ((config->cert_file == NULL) != (config->key_file == NULL)) ||
      (config->cert_file == NULL && config->key_password != NULL) ||
      (config->security_profile != CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD &&
       config->security_profile != CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13 &&
       config->security_profile != CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11))
    return CRYPTO_TLS_STREAM_EINVAL;
  if (config->security_profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11 &&
      config->cert_file != NULL)
    return CRYPTO_TLS_STREAM_ENOTSUP;

  status = crypto_tls_stream_context_create_common(
      false, true, config->ca_file, config->ca_path, config->cert_file,
      config->key_file, config->key_password, CRYPTO_TLS_STREAM_CLIENT_AUTH_NONE,
      config->alpn_protocols, config->alpn_protocol_count,
      config->security_profile, config->peer_policy, config->key_update_record_limit,
      config->peer_key_update_limit, &context);
  if (status != CRYPTO_TLS_STREAM_OK) return status;
  if (config->server_name != NULL)
    crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_METADATA, context->client_server_name, config->server_name,
           strlen(config->server_name) + 1u);
  *out_context = context;
  return CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_stream_server_context_create(const crypto_tls_stream_server_config *config,
                                     crypto_tls_stream_context **out_context) {
  crypto_tls_stream_context *context = NULL;
  int status;

  if (out_context == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  *out_context = NULL;
  if (config == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  if (config->size != sizeof(*config) ||
      !crypto_tls_stream_optional_path_valid(config->cert_file) ||
      !crypto_tls_stream_optional_path_valid(config->key_file) ||
      config->cert_file == NULL || config->key_file == NULL ||
      !crypto_tls_stream_optional_path_valid(config->ca_file) ||
      !crypto_tls_stream_optional_path_valid(config->ca_path) ||
      !crypto_tls_stream_bounded_string(config->key_password,
                               CRYPTO_TLS_STREAM_PASSWORD_MAX_BYTES, NULL) ||
      (config->client_auth != CRYPTO_TLS_STREAM_CLIENT_AUTH_NONE &&
       config->client_auth != CRYPTO_TLS_STREAM_CLIENT_AUTH_REQUIRED) ||
      (config->client_auth == CRYPTO_TLS_STREAM_CLIENT_AUTH_REQUIRED &&
       config->ca_file == NULL && config->ca_path == NULL) ||
      (config->client_auth == CRYPTO_TLS_STREAM_CLIENT_AUTH_NONE &&
       (config->ca_file != NULL || config->ca_path != NULL)) ||
      (config->security_profile != CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD &&
       config->security_profile != CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13 &&
       config->security_profile != CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11))
    return CRYPTO_TLS_STREAM_EINVAL;
  if (config->security_profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11 &&
      config->client_auth == CRYPTO_TLS_STREAM_CLIENT_AUTH_REQUIRED)
    return CRYPTO_TLS_STREAM_ENOTSUP;

  status = crypto_tls_stream_context_create_common(
      true, config->client_auth == CRYPTO_TLS_STREAM_CLIENT_AUTH_REQUIRED,
      config->ca_file, config->ca_path, config->cert_file, config->key_file,
      config->key_password, config->client_auth, config->alpn_protocols,
      config->alpn_protocol_count, config->security_profile, config->peer_policy,
      config->key_update_record_limit, config->peer_key_update_limit, &context);
  if (status != CRYPTO_TLS_STREAM_OK) return status;
  *out_context = context;
  return CRYPTO_TLS_STREAM_OK;
}

static size_t crypto_tls_stream_ring_write(crypto_tls_test_copy_kind kind, unsigned char *buffer, size_t capacity,
                                  size_t head, size_t size,
                                  const unsigned char *data, size_t length) {
  size_t tail;
  size_t first;
  (void)kind;
  if (buffer == NULL || data == NULL || capacity == 0u ||
      size >= capacity || length == 0u)
    return 0u;
  if (length > capacity - size) length = capacity - size;
  tail = (head + size) % capacity;
  first = capacity - tail;
  if (first > length) first = length;
  crypto_tls_stream_copy(kind, buffer + tail, data, first);
  if (length > first) crypto_tls_stream_copy(kind, buffer, data + first, length - first);
  return length;
}

static size_t crypto_tls_stream_ring_read(crypto_tls_test_copy_kind kind, unsigned char *buffer, size_t capacity,
                                 size_t *head, size_t *size,
                                 unsigned char *data, size_t length) {
  size_t first;
  (void)kind;
  if (buffer == NULL || head == NULL || size == NULL || data == NULL ||
      capacity == 0u || *size == 0u || length == 0u)
    return 0u;
  if (length > *size) length = *size;
  first = capacity - *head;
  if (first > length) first = length;
  crypto_tls_stream_copy(kind, data, buffer + *head, first);
  if (length > first) crypto_tls_stream_copy(kind, data + first, buffer, length - first);
  *head = (*head + length) % capacity;
  *size -= length;
  return length;
}

static size_t crypto_tls_stream_ring_peek(const unsigned char *buffer, size_t capacity,
                                 size_t head, size_t size,
                                 unsigned char *data, size_t length) {
  size_t first;
  if (buffer == NULL || data == NULL || capacity == 0u ||
      size == 0u || length == 0u)
    return 0u;
  if (length > size) length = size;
  first = capacity - head;
  if (first > length) first = length;
  crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_RECORD_HEADER, data, buffer + head, first);
  if (length > first) crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_RECORD_HEADER, data + first, buffer, length - first);
  return length;
}

static int crypto_tls_stream_cipher_record_ready(const crypto_tls_stream_gmssl_state *engine,
                                        bool *out_ready) {
  unsigned char header[TLS_RECORD_HEADER_SIZE];
  size_t record_size;
  if (engine == NULL || out_ready == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  *out_ready = false;
  /*
   * TLS 1.3 can consume one post-handshake control record and immediately
   * begin reading the next record inside a single tls13_recv() call. On
   * WANT_READ its provider recv_state/record_offset already own that next
   * record's header or payload. The ciphertext ring then starts with a *suffix*
   * of that record, not a fresh TLS header. Parsing the suffix as a header
   * (or requiring five new bytes) can strand the authenticated connection
   * until its peer closes. Let the single provider resume its own partial
   * frame; the provider still validates the entire authenticated record.
   */
  if (engine->connection.protocol == TLS_protocol_tls13 &&
      (engine->connection.recv_state == TLS_state_recv_record_header ||
       engine->connection.recv_state == TLS_state_recv_record_data ||
       engine->connection.datalen != 0u)) {
    *out_ready = engine->input_size != 0u ||
                 engine->connection.datalen != 0u;
    return CRYPTO_TLS_STREAM_OK;
  }
  if (engine->input_size < TLS_RECORD_HEADER_SIZE) return CRYPTO_TLS_STREAM_OK;
  if (crypto_tls_stream_ring_peek(engine->cipher_input, engine->capacity,
                         engine->input_head, engine->input_size,
                         header, sizeof(header)) != sizeof(header))
    return CRYPTO_TLS_STREAM_EIO;
  record_size = TLS_RECORD_HEADER_SIZE +
                (((size_t)header[3] << 8u) | (size_t)header[4]);
  if (record_size < TLS_RECORD_HEADER_SIZE ||
      record_size > TLS_MAX_RECORD_SIZE ||
      record_size > engine->capacity)
    return CRYPTO_TLS_STREAM_EPROTO;
  *out_ready = engine->input_size >= record_size;
  return CRYPTO_TLS_STREAM_OK;
}

#if defined(CRYPTO_TLS_STREAM_TESTING)
/* Reproduce the host's real receive gate with provider-owned TLS1.3 progress.
 * The caller supplies only inert bytes; no certificate or plaintext is read
 * and no second TLS engine is instantiated by this regression. */
int crypto_tls_stream_test_receive_record_gate(unsigned phase, const uint8_t *cipher,
                                      size_t size, bool *out_ready) {
  unsigned char ring[32] = {0};
  crypto_tls_stream_gmssl_state engine = {0};
  if (out_ready == NULL || cipher == NULL || size > sizeof(ring) || phase > 3u)
    return CRYPTO_TLS_STREAM_EINVAL;
  crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_METADATA, ring, cipher, size);
  engine.cipher_input = ring;
  engine.capacity = sizeof(ring);
  engine.input_size = size;
  engine.connection.protocol = TLS_protocol_tls13;
  if (phase == 1u) engine.connection.recv_state = TLS_state_recv_record_header;
  if (phase == 2u) engine.connection.recv_state = TLS_state_recv_record_data;
  if (phase == 3u) engine.connection.datalen = 1u;
  return crypto_tls_stream_cipher_record_ready(&engine, out_ready);
}
#endif

static tls_ret_t crypto_tls_stream_io_send(void *user, const void *buffer, size_t length,
                                  int flags) {
  crypto_tls_stream_gmssl_state *engine = (crypto_tls_stream_gmssl_state *)user;
  size_t written;
  (void)flags;
  if (engine == NULL || buffer == NULL || length == 0u)
    return TLS_ERROR_SYSCALL;
#if defined(CRYPTO_TLS_STREAM_TESTING)
  ++engine->diagnostic_send_calls;
  engine->diagnostic_send_requested += length;
#endif
  written = crypto_tls_stream_ring_write(
      CRYPTO_TLS_TEST_COPY_PROVIDER_SEND, engine->cipher_output, engine->capacity, engine->output_head,
      engine->output_size, (const unsigned char *)buffer, length);
  if (written == 0u) return TLS_ERROR_SEND_AGAIN;
  engine->output_size += written;
#if defined(CRYPTO_TLS_STREAM_TESTING)
  engine->diagnostic_send_accepted += written;
#endif
  return (tls_ret_t)written;
}

static tls_ret_t crypto_tls_stream_io_recv(void *user, void *buffer, size_t length,
                                  int flags) {
  crypto_tls_stream_gmssl_state *engine = (crypto_tls_stream_gmssl_state *)user;
  size_t read_size;
  (void)flags;
  if (engine == NULL || buffer == NULL || length == 0u)
    return TLS_ERROR_SYSCALL;
  read_size = crypto_tls_stream_ring_read(
      CRYPTO_TLS_TEST_COPY_PROVIDER_RECEIVE, engine->cipher_input, engine->capacity, &engine->input_head,
      &engine->input_size, (unsigned char *)buffer, length);
  if (read_size == 0u) return TLS_ERROR_RECV_AGAIN;
  return (tls_ret_t)read_size;
}

static int crypto_tls_stream_ip_literal_bytes(const char *name,
                                     unsigned char output[16],
                                     size_t *out_size) {
  if (name == NULL || output == NULL || out_size == NULL) return 0;
  if (inet_pton(AF_INET, name, output) == 1) {
    *out_size = 4u;
    return 1;
  }
  if (inet_pton(AF_INET6, name, output) == 1) {
    *out_size = 16u;
    return 1;
  }
  *out_size = 0u;
  return 0;
}

static bool crypto_tls_stream_ip_literal(const char *name) {
  unsigned char bytes[16];
  size_t size = 0u;
  return crypto_tls_stream_ip_literal_bytes(name, bytes, &size) == 1;
}

static int crypto_tls_stream_verify_ip_subject_alt_name(const TLS_CONNECT *connection,
                                                const char *name) {
  unsigned char expected[16];
  size_t expected_size = 0u;
  const unsigned char *cert = NULL;
  size_t cert_size = 0u;
  const unsigned char *exts = NULL;
  size_t exts_size = 0u;
  const unsigned char *encoded_names = NULL;
  size_t encoded_names_size = 0u;
  const unsigned char *names = NULL;
  size_t names_size = 0u;
  const unsigned char *cursor;
  const unsigned char *value = NULL;
  size_t value_size = 0u;
  int critical = 0;
  int result;

  if (connection == NULL ||
      crypto_tls_stream_ip_literal_bytes(name, expected, &expected_size) != 1)
    return CRYPTO_TLS_STREAM_EINVAL;

  result = tls_get_peer_certificate(connection, &cert, &cert_size);
  if (result < 0) return CRYPTO_TLS_STREAM_EIO;
  if (result == 0 || cert == NULL || cert_size == 0u)
    return CRYPTO_TLS_STREAM_ECONNABORTED;

  result = x509_cert_get_exts(cert, cert_size, &exts, &exts_size);
  if (result < 0) return CRYPTO_TLS_STREAM_EIO;
  if (result == 0) return CRYPTO_TLS_STREAM_ECONNABORTED;

  result = x509_exts_get_ext_by_oid(
      exts, exts_size, OID_ce_subject_alt_name, &critical,
      &encoded_names, &encoded_names_size);
  if (result < 0) return CRYPTO_TLS_STREAM_EIO;
  if (result == 0) return CRYPTO_TLS_STREAM_ECONNABORTED;

  if (asn1_sequence_from_der(&names, &names_size,
                             &encoded_names, &encoded_names_size) != 1 ||
      encoded_names_size != 0u)
    return CRYPTO_TLS_STREAM_EPROTO;

  cursor = names;
  for (;;) {
    result = x509_general_names_get_next(
        names, names_size, &cursor, X509_gn_ip_address, &value, &value_size);
    if (result < 0) return CRYPTO_TLS_STREAM_EPROTO;
    if (result == 0) return CRYPTO_TLS_STREAM_ECONNABORTED;
    if (value_size == expected_size &&
        memcmp(value, expected, expected_size) == 0)
      return CRYPTO_TLS_STREAM_OK;
  }
}

static int crypto_tls_stream_engine_init_connection(crypto_tls_stream *state,
                                           crypto_tls_stream_variant variant) {
  crypto_tls_stream_gmssl_state *engine;
  TLS_CTX *tls;
  if (state == NULL || state->context == NULL ||
      (engine = CRYPTO_TLS_STREAM_ENGINE(state)) == NULL)
    return CRYPTO_TLS_STREAM_EINVAL;
  if (variant < 0 || variant >= CRYPTO_TLS_STREAM_VARIANT_COUNT ||
      !state->context->tls_ready[variant])
    return CRYPTO_TLS_STREAM_EINVAL;
  if (engine->input_size != 0u || engine->output_size != 0u ||
      engine->plaintext_pending_size != 0u)
    return CRYPTO_TLS_STREAM_EBUSY;

  if (engine->connection_ready) {
    tls_cleanup(&engine->connection);
    memset(&engine->connection, 0, sizeof(engine->connection));
    engine->connection_ready = false;
  }

  tls = &state->context->tls[variant];
  if (tls_init(&engine->connection, tls) != 1) return CRYPTO_TLS_STREAM_EIO;
  engine->connection_ready = true;
  engine->variant = variant;
  engine->io.user = engine;
  engine->io.send = crypto_tls_stream_io_send;
  engine->io.recv = crypto_tls_stream_io_recv;

  if (!state->server) {
    if (engine->server_name[0] == '\0') return CRYPTO_TLS_STREAM_EINVAL;
    if (!crypto_tls_stream_ip_literal(engine->server_name) &&
        (tls_set_hostname(&engine->connection, engine->server_name) != 1 ||
         tls_set_server_name(&engine->connection) != 1))
      return CRYPTO_TLS_STREAM_EIO;
  }
  if (tls_set_io(&engine->connection, &engine->io) != 1)
    return CRYPTO_TLS_STREAM_EIO;
  return CRYPTO_TLS_STREAM_OK;
}

static int crypto_tls_stream_init(crypto_tls_stream *state, crypto_tls_stream_context *context,
                        bool server, const char *server_name,
                        size_t io_buffer_bytes) {
  crypto_tls_stream_gmssl_state *engine = NULL;
  unsigned char *read_buffer = NULL;
  unsigned char *write_buffer = NULL;
  size_t ring_capacity;
  size_t allocation_size;
  int status;

  if (state == NULL || context == NULL || context->server != server ||
      io_buffer_bytes < CRYPTO_TLS_STREAM_MIN_IO_BUFFER_BYTES ||
      (!server &&
       (server_name == NULL || server_name[0] == '\0' ||
        !crypto_tls_stream_bounded_string(server_name,
                                 CRYPTO_TLS_STREAM_SERVER_NAME_CAPACITY - 1u, NULL))))
    return CRYPTO_TLS_STREAM_EINVAL;
  if (state->engine != NULL || state->context != NULL) return CRYPTO_TLS_STREAM_EALREADY;

  ring_capacity = io_buffer_bytes < (size_t)TLS_MAX_RECORD_SIZE
                      ? (size_t)TLS_MAX_RECORD_SIZE
                      : io_buffer_bytes;
  if (ring_capacity >
      (SIZE_MAX - sizeof(crypto_tls_stream_gmssl_state)) / 2u)
    return CRYPTO_TLS_STREAM_ERANGE;

  allocation_size = sizeof(crypto_tls_stream_gmssl_state) + ring_capacity * 2u;
  if (io_buffer_bytes > SIZE_MAX - allocation_size) return CRYPTO_TLS_STREAM_ERANGE;
  allocation_size += io_buffer_bytes;
  engine = (crypto_tls_stream_gmssl_state *)crypto_tls_stream_calloc(1u, allocation_size);
  read_buffer = (unsigned char *)crypto_tls_stream_malloc(io_buffer_bytes);
  write_buffer = (unsigned char *)crypto_tls_stream_malloc(io_buffer_bytes);
  if (engine == NULL || read_buffer == NULL || write_buffer == NULL) {
    crypto_tls_stream_free(write_buffer);
    crypto_tls_stream_free(read_buffer);
    crypto_tls_stream_free(engine);
    return CRYPTO_TLS_STREAM_ENOMEM;
  }

  engine->capacity = ring_capacity;
  engine->cipher_input = (unsigned char *)(engine + 1);
  engine->cipher_output = engine->cipher_input + ring_capacity;
  /* NativeIO owns state->read_buffer until the receive completion is consumed.
   * Provider reads/probes and pending plaintext must not alias that storage. */
  engine->plaintext = engine->cipher_output + ring_capacity;
  if (!server)
    crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_METADATA, engine->server_name, server_name, strlen(server_name) + 1u);

  state->context = context;
  state->engine = engine;
  state->read_buffer = read_buffer;
  state->write_buffer = write_buffer;
  state->io_buffer_bytes = io_buffer_bytes;
  state->server = server;

  status = crypto_tls_stream_engine_init_connection(
      state, context->security_profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13
                 ? CRYPTO_TLS_STREAM_VARIANT_SHANGMI_TLS13
             : context->security_profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11
                 ? CRYPTO_TLS_STREAM_VARIANT_TLCP11
                 : CRYPTO_TLS_STREAM_VARIANT_RANGE);
  if (status != CRYPTO_TLS_STREAM_OK) {
    state->context = NULL;
    state->engine = NULL;
    state->read_buffer = NULL;
    state->write_buffer = NULL;
    state->io_buffer_bytes = 0u;
    state->server = false;
    if (engine->connection_ready) tls_cleanup(&engine->connection);
    crypto_tls_stream_free(write_buffer);
    crypto_tls_stream_free(read_buffer);
    crypto_tls_stream_free(engine);
    return status;
  }
  return CRYPTO_TLS_STREAM_OK;
}

void crypto_tls_stream_destroy(crypto_tls_stream *state) {
  crypto_tls_stream_context *context;
  crypto_tls_stream_gmssl_state *engine;
  if (state == NULL) return;
  context = state->context;
  engine = CRYPTO_TLS_STREAM_ENGINE(state);
  if (engine != NULL && engine->connection_ready)
    tls_cleanup(&engine->connection);
  crypto_tls_stream_free(engine);
  crypto_tls_stream_free(state->write_buffer);
  crypto_tls_stream_free(state->read_buffer);
  memset(state, 0, sizeof(*state));
  crypto_tls_stream_context_release(context);
  crypto_tls_stream_free(state);
}

static bool crypto_tls_stream_retryable(int result) {
  return result == TLS_ERROR_RECV_AGAIN || result == TLS_ERROR_SEND_AGAIN;
}

#if defined(__APPLE__) && !TARGET_OS_OSX
static int crypto_tls_stream_verify_apple_system_trust(
    const crypto_tls_stream_gmssl_state *engine) {
  crypto_tls_stream_peer_certificate_chain chain = {0};
  CFMutableArrayRef certificates = NULL;
  SecPolicyRef policy = NULL;
  SecTrustRef trust = NULL;
  CFErrorRef error = NULL;
  size_t index;
  int status;

  if (engine == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  status = crypto_tls_stream_peer_certificate_chain_parse(
      engine->connection.peer_cert_chain,
      engine->connection.peer_cert_chain_len,
      &chain);
  if (status != CRYPTO_TLS_STREAM_OK) return status;

  certificates = CFArrayCreateMutable(
      kCFAllocatorDefault, (CFIndex)chain.count,
      &kCFTypeArrayCallBacks);
  if (certificates == NULL) return CRYPTO_TLS_STREAM_ENOMEM;

  for (index = 0u; index < chain.count; ++index) {
    CFDataRef data = CFDataCreate(
        kCFAllocatorDefault,
        chain.certificates[index].data,
        (CFIndex)chain.certificates[index].size);
    SecCertificateRef certificate;
    if (data == NULL) {
      status = CRYPTO_TLS_STREAM_ENOMEM;
      goto cleanup;
    }
    certificate = SecCertificateCreateWithData(
        kCFAllocatorDefault, data);
    CFRelease(data);
    if (certificate == NULL) {
      status = CRYPTO_TLS_STREAM_EPROTO;
      goto cleanup;
    }
    CFArrayAppendValue(certificates, certificate);
    CFRelease(certificate);
  }

  /*
   * Crypto/GmSSL already owns peer identity validation, including the explicit
   * IP-SAN path. Security.framework is used here only for native system
   * trust-anchor/path validation so platform policy cannot change the host's
   * hostname/IP semantics.
   */
  policy = SecPolicyCreateBasicX509();
  if (policy == NULL) {
    status = CRYPTO_TLS_STREAM_EIO;
    goto cleanup;
  }
  if (SecTrustCreateWithCertificates(
          certificates, policy, &trust) != errSecSuccess ||
      trust == NULL) {
    status = CRYPTO_TLS_STREAM_EIO;
    goto cleanup;
  }
  if (!SecTrustEvaluateWithError(trust, &error)) {
    status = CRYPTO_TLS_STREAM_ECONNABORTED;
    goto cleanup;
  }
  status = CRYPTO_TLS_STREAM_OK;

cleanup:
  if (error != NULL) CFRelease(error);
  if (trust != NULL) CFRelease(trust);
  if (policy != NULL) CFRelease(policy);
  if (certificates != NULL) CFRelease(certificates);
  return status;
}
#endif

/* GmSSL TLS1.2 stores a server's authenticated client chain separately
 * from TLS1.3 and from the client-side peer chain. Keep that distinction
 * inside this backend adapter for verification and public metadata alike. */
static int crypto_tls_stream_peer_chain(const TLS_CONNECT *connection,
                                const uint8_t **chain, size_t *size) {
  int complete = 0;
  if (tls_get_handshake_complete(connection, &complete) != 1) return -1;
  if (!complete) return 0;
  if (!connection->is_client && connection->protocol == TLS_protocol_tls12) {
    *chain = connection->client_certs;
    *size = connection->client_certs_len;
    return *size != 0u ? 1 : 0;
  }
  return tls_get_peer_certificate_chain(connection, chain, size);
}

static int crypto_tls_stream_peer_leaf(const TLS_CONNECT *connection,
                               const uint8_t **certificate, size_t *size) {
  const uint8_t *chain = NULL;
  size_t chain_size = 0u;
  int result = crypto_tls_stream_peer_chain(connection, &chain, &chain_size);
  if (result != 1) return result;
  return x509_certs_get_cert_by_index(chain, chain_size, 0, certificate, size);
}

static int crypto_tls_stream_finish_handshake(crypto_tls_stream *state,
                                     bool *out_complete) {
  crypto_tls_stream_gmssl_state *engine = CRYPTO_TLS_STREAM_ENGINE(state);
  int complete = 0;
  int verify_result = X509_verify_ok;
  const char *alpn = NULL;
  size_t alpn_size = 0u;
  int result;

  if (tls_get_handshake_complete(&engine->connection, &complete) != 1)
    return CRYPTO_TLS_STREAM_EIO;
  if (!complete) return CRYPTO_TLS_STREAM_OK;
  if (state->context->security_profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13 &&
      (engine->connection.protocol != TLS_protocol_tls13 ||
       engine->connection.cipher_suite != TLS_cipher_sm4_gcm_sm3))
    return CRYPTO_TLS_STREAM_EPROTO;
  if (state->context->security_profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11 &&
      (engine->connection.protocol != TLS_protocol_tlcp ||
       engine->connection.cipher_suite != TLS_cipher_ecc_sm4_gcm_sm3))
    return CRYPTO_TLS_STREAM_EPROTO;

  if (state->context->verify_peer) {
    result = tls_get_verify_result(&engine->connection, &verify_result);
    if (result != 1 || verify_result != X509_verify_ok)
      return CRYPTO_TLS_STREAM_ECONNABORTED;
    if (state->server) {
      /* REQUIRED client authentication must have a real, already verified
       * peer certificate before the host can publish CONNECTED. TLS1.2 stores
       * client certs separately from TLS1.3; the canonical getter covers both. */
      const uint8_t *peer_cert = NULL;
      size_t peer_cert_size = 0u;
      result = crypto_tls_stream_peer_leaf(
          &engine->connection, &peer_cert, &peer_cert_size);
      if (result != 1 || peer_cert == NULL || peer_cert_size == 0u)
        return CRYPTO_TLS_STREAM_ECONNABORTED;
    }
    if (!state->server && crypto_tls_stream_ip_literal(engine->server_name)) {
      result = crypto_tls_stream_verify_ip_subject_alt_name(
          &engine->connection, engine->server_name);
      if (result != CRYPTO_TLS_STREAM_OK) return result;
    }
#if defined(__APPLE__) && !TARGET_OS_OSX
    if (state->context->native_system_trust) {
      result = crypto_tls_stream_verify_apple_system_trust(engine);
      if (result != CRYPTO_TLS_STREAM_OK) return result;
    }
#endif
  }

  result = tls_get_selected_alpn(&engine->connection, &alpn, &alpn_size);
  if (result < 0) return CRYPTO_TLS_STREAM_EPROTO;
  if (result == 1) {
    if (alpn_size == 0u || alpn_size > CRYPTO_TLS_STREAM_ALPN_NAME_MAX_BYTES)
      return CRYPTO_TLS_STREAM_EPROTO;
    crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_METADATA, state->negotiated_alpn, alpn, alpn_size);
    state->negotiated_alpn_size = alpn_size;
  }

  if (state->context->peer_policy.check != NULL) {
    const uint8_t *der = NULL;
    size_t size = 0u;
    crypto_tls_stream_peer_certificate_chain chain;
    if (crypto_tls_stream_peer_chain(&engine->connection, &der, &size) != 1 ||
        crypto_tls_stream_peer_certificate_chain_parse(der, size, &chain) != CRYPTO_TLS_STREAM_OK ||
        chain.count == 0u ||
        state->context->peer_policy.check(state->context->peer_policy.context,
            &chain, !state->server, state->context->security_profile) != CRYPTO_TLS_STREAM_OK)
      return CRYPTO_TLS_STREAM_ECONNABORTED;
  }

  state->handshake_complete = true;
  *out_complete = true;
  return CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_stream_handshake(crypto_tls_stream *state, bool *out_complete) {
  crypto_tls_stream_gmssl_state *engine;
  int result;
  int status;
  if (state == NULL || out_complete == NULL ||
      (engine = CRYPTO_TLS_STREAM_ENGINE(state)) == NULL ||
      !engine->connection_ready)
    return CRYPTO_TLS_STREAM_EINVAL;
  *out_complete = false;
  if (state->terminal_error != CRYPTO_TLS_STREAM_OK) return state->terminal_error;
  *out_complete = state->handshake_complete;
  if (state->handshake_complete) return CRYPTO_TLS_STREAM_OK;
  if (state->handshake_error != CRYPTO_TLS_STREAM_OK) return state->handshake_error;

  state->handshake_started = true;
  result = tls_do_handshake(&engine->connection);
  if (result != 1 && !crypto_tls_stream_retryable(result)) {
    state->handshake_error = CRYPTO_TLS_STREAM_ECONNABORTED;
    return state->handshake_error;
  }
  status = crypto_tls_stream_finish_handshake(state, out_complete);
  if (status != CRYPTO_TLS_STREAM_OK) state->handshake_error = status;
  return status;
}

bool crypto_tls_stream_handshake_complete(const crypto_tls_stream *state) {
  return state != NULL && state->handshake_complete &&
         state->terminal_error == CRYPTO_TLS_STREAM_OK;
}

static int crypto_tls_stream_select_variant(crypto_tls_stream_protocol_version minimum,
                                   crypto_tls_stream_protocol_version maximum,
                                   crypto_tls_stream_variant *out_variant) {
  crypto_tls_stream_protocol_version effective_min = minimum;
  crypto_tls_stream_protocol_version effective_max = maximum;
  if (out_variant == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  if (minimum != CRYPTO_TLS_STREAM_PROTOCOL_VERSION_DEFAULT &&
      minimum != CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_2 &&
      minimum != CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3)
    return CRYPTO_TLS_STREAM_EINVAL;
  if (maximum != CRYPTO_TLS_STREAM_PROTOCOL_VERSION_DEFAULT &&
      maximum != CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_2 &&
      maximum != CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3)
    return CRYPTO_TLS_STREAM_EINVAL;

  if (effective_min == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_DEFAULT)
    effective_min = CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_2;
  if (effective_max == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_DEFAULT)
    effective_max = CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3;
  if (effective_min > effective_max) return CRYPTO_TLS_STREAM_EINVAL;

  if (effective_min == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_2 &&
      effective_max == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_2)
    *out_variant = CRYPTO_TLS_STREAM_VARIANT_1_2;
  else if (effective_min == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3 &&
           effective_max == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3)
    *out_variant = CRYPTO_TLS_STREAM_VARIANT_1_3;
  else
    *out_variant = CRYPTO_TLS_STREAM_VARIANT_RANGE;
  return CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_stream_set_protocol_range(crypto_tls_stream *state,
                                      crypto_tls_stream_protocol_version minimum,
                                      crypto_tls_stream_protocol_version maximum) {
  crypto_tls_stream_variant variant;
  int status;
  if (state == NULL || CRYPTO_TLS_STREAM_ENGINE(state) == NULL ||
      state->handshake_started)
    return CRYPTO_TLS_STREAM_EINVAL;
  if (state->context->security_profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13) {
    /* A configured SM-only TLS 1.3 connection can never switch to range/TLS1.2. */
    return ((minimum == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_DEFAULT &&
             maximum == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_DEFAULT) ||
            (minimum == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3 &&
             maximum == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_1_3))
               ? CRYPTO_TLS_STREAM_OK : CRYPTO_TLS_STREAM_EINVAL;
  }
  if (state->context->security_profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11) {
    /* TLCP is not representable by the TLS 1.2/1.3 range enum. */
    return minimum == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_DEFAULT &&
                   maximum == CRYPTO_TLS_STREAM_PROTOCOL_VERSION_DEFAULT
               ? CRYPTO_TLS_STREAM_OK : CRYPTO_TLS_STREAM_EINVAL;
  }
  status = crypto_tls_stream_select_variant(minimum, maximum, &variant);
  if (status != CRYPTO_TLS_STREAM_OK) return status;
  if (CRYPTO_TLS_STREAM_ENGINE(state)->variant == variant) return CRYPTO_TLS_STREAM_OK;
  state->negotiated_alpn_size = 0u;
  memset(state->negotiated_alpn, 0, sizeof(state->negotiated_alpn));
  return crypto_tls_stream_engine_init_connection(state, variant);
}

void *crypto_tls_stream_read_buffer(crypto_tls_stream *state) {
  return state != NULL ? state->read_buffer : NULL;
}

void *crypto_tls_stream_write_buffer(crypto_tls_stream *state) {
  return state != NULL ? state->write_buffer : NULL;
}

size_t crypto_tls_stream_io_buffer_bytes(const crypto_tls_stream *state) {
  return state != NULL ? state->io_buffer_bytes : 0u;
}

size_t crypto_tls_stream_cipher_input_capacity(const crypto_tls_stream *state) {
  const crypto_tls_stream_gmssl_state *engine =
      state != NULL ? CRYPTO_TLS_STREAM_ENGINE(state) : NULL;
  return engine != NULL && engine->input_size <= engine->capacity
             ? engine->capacity - engine->input_size
             : 0u;
}

bool crypto_tls_stream_cipher_output_empty(const crypto_tls_stream *state) {
  const crypto_tls_stream_gmssl_state *engine =
      state != NULL ? CRYPTO_TLS_STREAM_ENGINE(state) : NULL;
  return engine != NULL && engine->output_size == 0u;
}

int crypto_tls_stream_feed_cipher(crypto_tls_stream *state, const void *data, size_t size) {
  crypto_tls_stream_gmssl_state *engine;
  size_t written;
  if (state == NULL || data == NULL || size == 0u ||
      (engine = CRYPTO_TLS_STREAM_ENGINE(state)) == NULL)
    return CRYPTO_TLS_STREAM_EINVAL;
  if (size > engine->capacity - engine->input_size) return CRYPTO_TLS_STREAM_ENOBUFS;
  written = crypto_tls_stream_ring_write(
      CRYPTO_TLS_TEST_COPY_CIPHER_INPUT, engine->cipher_input, engine->capacity, engine->input_head,
      engine->input_size, (const unsigned char *)data, size);
  if (written != size) return CRYPTO_TLS_STREAM_EIO;
  engine->input_size += written;
  return CRYPTO_TLS_STREAM_OK;
}

#if defined(CRYPTO_TLS_STREAM_TESTING)
int crypto_tls_stream_diagnostic_send_stats(const crypto_tls_stream *state,
                                   size_t *calls, size_t *requested,
                                   size_t *accepted, size_t *queued) {
  const crypto_tls_stream_gmssl_state *engine =
      state != NULL ? CRYPTO_TLS_STREAM_ENGINE(state) : NULL;
  if (engine == NULL || calls == NULL || requested == NULL ||
      accepted == NULL || queued == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  *calls = engine->diagnostic_send_calls;
  *requested = engine->diagnostic_send_requested;
  *accepted = engine->diagnostic_send_accepted;
  *queued = engine->output_size;
  return CRYPTO_TLS_STREAM_OK;
}
#endif

int crypto_tls_stream_take_cipher(crypto_tls_stream *state, void *buffer,
                         size_t capacity, size_t *out_size) {
  crypto_tls_stream_gmssl_state *engine;
  size_t read_size;
  if (out_size == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  *out_size = 0u;
  if (state == NULL || buffer == NULL || capacity == 0u ||
      (engine = CRYPTO_TLS_STREAM_ENGINE(state)) == NULL)
    return CRYPTO_TLS_STREAM_EINVAL;
  if (engine->output_size == 0u) return CRYPTO_TLS_STREAM_ENOENT;
  read_size = crypto_tls_stream_ring_read(
      CRYPTO_TLS_TEST_COPY_CIPHER_OUTPUT, engine->cipher_output, engine->capacity, &engine->output_head,
      &engine->output_size, (unsigned char *)buffer, capacity);
  if (read_size == 0u) return CRYPTO_TLS_STREAM_EIO;
  *out_size = read_size;
  return CRYPTO_TLS_STREAM_OK;
}

/* Owner-only terminal transition. Release logical borrows, not native storage:
 * transport buffers and queued ciphertext remain valid until the host drains
 * actual native completions and destroys the stream. No provider reentry after
 * this point, even when the caller retries through a different progress API. */
static int crypto_tls_stream_fail(crypto_tls_stream *state, int status) {
  crypto_tls_stream_gmssl_state *engine = CRYPTO_TLS_STREAM_ENGINE(state);
  if (state->terminal_error == CRYPTO_TLS_STREAM_OK) state->terminal_error = status;
  engine->write_source = NULL;
  engine->write_size = engine->write_offset = 0u;
  engine->plaintext_pending_size = engine->plaintext_pending_offset = 0u;
  return state->terminal_error;
}

int crypto_tls_stream_write(crypto_tls_stream *state, const void *data, size_t size,
                   bool *out_complete) {
  crypto_tls_stream_gmssl_state *engine;
  const unsigned char *bytes = (const unsigned char *)data;
  if (state == NULL || data == NULL || size == 0u ||
      out_complete == NULL ||
      (engine = CRYPTO_TLS_STREAM_ENGINE(state)) == NULL)
    return CRYPTO_TLS_STREAM_EINVAL;
  *out_complete = false;
  if (state->terminal_error != CRYPTO_TLS_STREAM_OK) return state->terminal_error;
  if (!state->handshake_complete || state->shutdown_started)
    return CRYPTO_TLS_STREAM_ENOTCONN;

  if (engine->write_size == 0u) {
    engine->write_source = bytes;
    engine->write_size = size;
    engine->write_offset = 0u;
  } else if (engine->write_source != bytes || engine->write_size != size ||
             engine->write_offset >= engine->write_size) {
    return CRYPTO_TLS_STREAM_EBUSY;
  }

  while (engine->write_offset < engine->write_size) {
    size_t sent_size = 0u;
    size_t remaining = engine->write_size - engine->write_offset;
    int result = tls_send(&engine->connection,
                          engine->write_source + engine->write_offset,
                          remaining, &sent_size);
    if (result == 1) {
      if (sent_size == 0u || sent_size > remaining)
        return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_EPROTO);
      engine->write_offset += sent_size;
      continue;
    }
    if (crypto_tls_stream_retryable(result)) return CRYPTO_TLS_STREAM_OK;
    return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_EPROTO);
  }

  engine->write_source = NULL;
  engine->write_size = 0u;
  engine->write_offset = 0u;
  *out_complete = true;
  return CRYPTO_TLS_STREAM_OK;
}

static int crypto_tls_stream_read_pending(crypto_tls_stream *state, void *buffer,
                                 size_t capacity, size_t *out_size) {
  crypto_tls_stream_gmssl_state *engine = CRYPTO_TLS_STREAM_ENGINE(state);
  size_t available;
  size_t size;
  if (engine == NULL || engine->plaintext_pending_size == 0u)
    return CRYPTO_TLS_STREAM_ENOENT;
  available =
      engine->plaintext_pending_size - engine->plaintext_pending_offset;
  size = capacity < available ? capacity : available;
  crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_PENDING_PLAINTEXT, buffer, engine->plaintext + engine->plaintext_pending_offset, size);
  engine->plaintext_pending_offset += size;
  if (engine->plaintext_pending_offset == engine->plaintext_pending_size) {
    engine->plaintext_pending_offset = 0u;
    engine->plaintext_pending_size = 0u;
  }
  *out_size = size;
  return CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_stream_read(crypto_tls_stream *state, void *buffer, size_t capacity,
                  size_t *out_size, bool *out_peer_closed) {
  crypto_tls_stream_gmssl_state *engine;
  size_t received_size = 0u;
  size_t copy_size;
  bool record_ready = false;
  int result;
  int status;
  if (out_size == NULL || out_peer_closed == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  *out_size = 0u;
  *out_peer_closed = false;
  if (state == NULL || buffer == NULL || capacity == 0u ||
      (engine = CRYPTO_TLS_STREAM_ENGINE(state)) == NULL)
    return CRYPTO_TLS_STREAM_EINVAL;
  if (state->terminal_error != CRYPTO_TLS_STREAM_OK) return state->terminal_error;
  if (!state->handshake_complete) return CRYPTO_TLS_STREAM_ENOTCONN;
  if (state->peer_close_notify) {
    *out_peer_closed = true;
    return CRYPTO_TLS_STREAM_OK;
  }

  status = crypto_tls_stream_read_pending(state, buffer, capacity, out_size);
  if (status == CRYPTO_TLS_STREAM_OK) return CRYPTO_TLS_STREAM_OK;
  if (status != CRYPTO_TLS_STREAM_ENOENT) return status;

  /*
   * GmSSL uses one TLS_CONNECT record scratch for both tls_send() and
   * tls_recv(). A retryable application write can leave a partially emitted
   * provider record in that scratch after crypto_tls_stream_write() returns
   * incomplete. Do not enter provider receive until that logical write has
   * been completely accepted; encrypted peer records remain bounded in the
   * the host input ring and are consumed after the write finishes.
   */
  if (engine->write_size != 0u) return CRYPTO_TLS_STREAM_OK;

  status = crypto_tls_stream_cipher_record_ready(engine, &record_ready);
  if (status != CRYPTO_TLS_STREAM_OK) return crypto_tls_stream_fail(state, status);
  if (!record_ready) return CRYPTO_TLS_STREAM_OK;

  result = tls_recv(&engine->connection, engine->plaintext,
                    state->io_buffer_bytes, &received_size);
  if (result == 1) {
    if (received_size > state->io_buffer_bytes)
      return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_EPROTO);
    copy_size = capacity < received_size ? capacity : received_size;
    if (copy_size != 0u) crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_PLAINTEXT, buffer, engine->plaintext, copy_size);
    *out_size = copy_size;
    if (copy_size < received_size) {
      engine->plaintext_pending_offset = copy_size;
      engine->plaintext_pending_size = received_size;
    }
    return CRYPTO_TLS_STREAM_OK;
  }
  if (result == 0 || result == TLS_ERROR_TCP_CLOSED) {
    int received = 0;
    if (tls_get_peer_close_notify(&engine->connection, &received) != 1)
      return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_EIO);
    if (received != 1) return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_ECONNABORTED);
    state->peer_close_notify = true;
    *out_peer_closed = true;
    return CRYPTO_TLS_STREAM_OK;
  }
  if (crypto_tls_stream_retryable(result)) return CRYPTO_TLS_STREAM_OK;
  return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_EPROTO);
}

int crypto_tls_stream_probe_peer_close(crypto_tls_stream *state, bool *out_peer_closed,
                              bool *out_plaintext_pending) {
  crypto_tls_stream_gmssl_state *engine;
  size_t received_size = 0u;
  int result;
  int received = 0;

  if (out_peer_closed == NULL || out_plaintext_pending == NULL)
    return CRYPTO_TLS_STREAM_EINVAL;
  *out_peer_closed = false;
  *out_plaintext_pending = false;
  if (state == NULL || (engine = CRYPTO_TLS_STREAM_ENGINE(state)) == NULL)
    return CRYPTO_TLS_STREAM_EINVAL;
  if (state->terminal_error != CRYPTO_TLS_STREAM_OK) return state->terminal_error;
  if (!state->handshake_complete) return CRYPTO_TLS_STREAM_ENOTCONN;
  if (state->peer_close_notify) {
    *out_peer_closed = true;
    return CRYPTO_TLS_STREAM_OK;
  }
  if (engine->plaintext_pending_size != 0u) {
    *out_plaintext_pending = true;
    return CRYPTO_TLS_STREAM_OK;
  }
  if (engine->write_size != 0u) return CRYPTO_TLS_STREAM_OK;

  {
    bool record_ready = false;
    int status = crypto_tls_stream_cipher_record_ready(engine, &record_ready);
    if (status != CRYPTO_TLS_STREAM_OK) return crypto_tls_stream_fail(state, status);
    if (!record_ready) return CRYPTO_TLS_STREAM_OK;
  }

  result = tls_recv(&engine->connection, engine->plaintext,
                    state->io_buffer_bytes, &received_size);
  if (result == 1 && received_size != 0u) {
    if (received_size > state->io_buffer_bytes)
      return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_EPROTO);
    engine->plaintext_pending_offset = 0u;
    engine->plaintext_pending_size = received_size;
    *out_plaintext_pending = true;
    return CRYPTO_TLS_STREAM_OK;
  }
  if (result == 0 || result == TLS_ERROR_TCP_CLOSED) {
    if (tls_get_peer_close_notify(&engine->connection, &received) != 1)
      return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_EIO);
    if (received != 1) return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_ECONNABORTED);
    state->peer_close_notify = true;
    *out_peer_closed = true;
    return CRYPTO_TLS_STREAM_OK;
  }
  if (!crypto_tls_stream_retryable(result) && result != 1)
    return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_EPROTO);

  if (tls_get_peer_close_notify(&engine->connection, &received) != 1)
    return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_EIO);
  if (received) {
    state->peer_close_notify = true;
    *out_peer_closed = true;
  }
  return CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_stream_shutdown(crypto_tls_stream *state, bool *out_notify_generated,
                      bool *out_peer_notify_received) {
  crypto_tls_stream_gmssl_state *engine;
  size_t output_before;
  int received = 0;
  int result;
  if (state == NULL || out_notify_generated == NULL ||
      out_peer_notify_received == NULL ||
      (engine = CRYPTO_TLS_STREAM_ENGINE(state)) == NULL)
    return CRYPTO_TLS_STREAM_EINVAL;
  *out_notify_generated = false;
  *out_peer_notify_received = false;
  if (state->terminal_error != CRYPTO_TLS_STREAM_OK) return state->terminal_error;
  *out_notify_generated = state->close_notify_started;
  if (!state->handshake_complete) return CRYPTO_TLS_STREAM_ENOTCONN;
  /* tls_shutdown shares the provider's record scratch with tls_send.
   * Never let it flush an application record as if it were close_notify. */
  if (engine->write_size != 0u) return CRYPTO_TLS_STREAM_EBUSY;

  state->shutdown_started = true;
  output_before = engine->output_size;
  result = tls_shutdown(&engine->connection);
  if (engine->output_size > output_before) state->close_notify_started = true;
  *out_notify_generated = state->close_notify_started;

  if (result != 1 && result != TLS_ERROR_TCP_CLOSED &&
      !crypto_tls_stream_retryable(result))
    return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_EPROTO);

  /* The TLS protocol owner alone authenticates close_notify. GmSSL may
   * complete its shutdown API after raw TCP closure, but EOF cannot count
   * as a reciprocal close_notify when our local application initiated it.
   * Do not infer authentication from output flushing or socket status. */
  if (tls_get_peer_close_notify(&engine->connection, &received) != 1)
    return crypto_tls_stream_fail(state, CRYPTO_TLS_STREAM_EIO);
  if (received) state->peer_close_notify = true;
  *out_peer_notify_received = received != 0;
  return CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_stream_get_negotiated_alpn(const crypto_tls_stream *state,
                                 const unsigned char **out_data,
                                 size_t *out_size) {
  if (out_data == NULL || out_size == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  *out_data = NULL;
  *out_size = 0u;
  if (state == NULL || CRYPTO_TLS_STREAM_ENGINE(state) == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  if (!state->handshake_complete) return CRYPTO_TLS_STREAM_ENOTCONN;
  if (state->negotiated_alpn_size == 0u) return CRYPTO_TLS_STREAM_ENOENT;
  *out_data = state->negotiated_alpn;
  *out_size = state->negotiated_alpn_size;
  return CRYPTO_TLS_STREAM_OK;
}

static int crypto_tls_stream_copy_session_string(const crypto_tls_stream *state,
                                              const char *value,
                                              char *buffer, size_t capacity,
                                              size_t *out_size) {
  size_t size;
  if (out_size == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  *out_size = 0u;
  if (state == NULL || buffer == NULL || capacity == 0u)
    return CRYPTO_TLS_STREAM_EINVAL;
  buffer[0] = '\0';
  if (CRYPTO_TLS_STREAM_ENGINE(state) == NULL || !state->handshake_complete)
    return CRYPTO_TLS_STREAM_ENOTCONN;
  if (value == NULL || value[0] == '\0') return CRYPTO_TLS_STREAM_ENOENT;
  size = strlen(value);
  if (capacity <= size) return CRYPTO_TLS_STREAM_EMSGSIZE;
  crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_METADATA, buffer, value, size + 1u);
  *out_size = size;
  return CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_stream_negotiated_version(const crypto_tls_stream *state,
                                      char *buffer, size_t capacity,
                                      size_t *out_size) {
  int protocol = 0;
  int result;
  const char *name = NULL;
  if (state == NULL || CRYPTO_TLS_STREAM_ENGINE(state) == NULL)
    return crypto_tls_stream_copy_session_string(state, NULL, buffer, capacity,
                                              out_size);
  if (!state->handshake_complete)
    return crypto_tls_stream_copy_session_string(state, NULL, buffer, capacity,
                                              out_size);
  result = tls_get_negotiated_protocol(
      &CRYPTO_TLS_STREAM_ENGINE(state)->connection, &protocol);
  if (result < 0) return CRYPTO_TLS_STREAM_EIO;
  if (result == 0) return CRYPTO_TLS_STREAM_ENOENT;
  if (protocol == TLS_protocol_tls12)
    name = "TLSv1.2";
  else if (protocol == TLS_protocol_tls13)
    name = "TLSv1.3";
  else if (protocol == TLS_protocol_tlcp)
    name = "TLCPv1.1";
  else
    return CRYPTO_TLS_STREAM_EPROTO;
  return crypto_tls_stream_copy_session_string(state, name, buffer, capacity,
                                            out_size);
}

int crypto_tls_stream_negotiated_cipher(const crypto_tls_stream *state,
                                     char *buffer, size_t capacity,
                                     size_t *out_size) {
  const char *name = NULL;
  int result;
  if (state == NULL || CRYPTO_TLS_STREAM_ENGINE(state) == NULL)
    return crypto_tls_stream_copy_session_string(state, NULL, buffer, capacity,
                                              out_size);
  if (!state->handshake_complete)
    return crypto_tls_stream_copy_session_string(state, NULL, buffer, capacity,
                                              out_size);
  result = tls_get_negotiated_cipher_name(
      &CRYPTO_TLS_STREAM_ENGINE(state)->connection, &name);
  if (result < 0) return CRYPTO_TLS_STREAM_EIO;
  if (result == 0) return CRYPTO_TLS_STREAM_ENOENT;
  return crypto_tls_stream_copy_session_string(state, name, buffer, capacity,
                                            out_size);
}

int crypto_tls_stream_peer_certificate_sha256(
    const crypto_tls_stream *state,
    char buffer[CRYPTO_TLS_STREAM_PEER_CERTIFICATE_SHA256_CAPACITY]) {
  static const char hex[] = "0123456789abcdef";
  uint8_t digest_bytes[32];
  const uint8_t *certificate = NULL;
  size_t certificate_size = 0u, digest_size = 0u;
  size_t index;
  int result;

  if (state == NULL || buffer == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  buffer[0] = '\0';
  if (CRYPTO_TLS_STREAM_ENGINE(state) == NULL || !state->handshake_complete)
    return CRYPTO_TLS_STREAM_ENOTCONN;
  result = crypto_tls_stream_peer_leaf(
      &CRYPTO_TLS_STREAM_ENGINE(state)->connection, &certificate, &certificate_size);
  if (result < 0) return CRYPTO_TLS_STREAM_EIO;
  if (result == 0) return CRYPTO_TLS_STREAM_ENOENT;
  if (digest(DIGEST_sha256(), certificate, certificate_size, digest_bytes,
             &digest_size) != 1 || digest_size != sizeof(digest_bytes))
    return CRYPTO_TLS_STREAM_EIO;
  for (index = 0u; index < sizeof(digest_bytes); ++index) {
    buffer[index * 2u] = hex[digest_bytes[index] >> 4u];
    buffer[index * 2u + 1u] = hex[digest_bytes[index] & 0x0fu];
  }
  buffer[sizeof(digest_bytes) * 2u] = '\0';
  return CRYPTO_TLS_STREAM_OK;
}

static const DIGEST *crypto_tls_stream_server_end_point_digest(int signature_algor) {
  switch (signature_algor) {
    case OID_rsasign_with_md5:
    case OID_rsasign_with_sha1:
    case OID_ecdsa_with_sha1:
      return DIGEST_sha256();
    case OID_rsasign_with_sha224:
    case OID_ecdsa_with_sha224:
      return DIGEST_sha224();
    case OID_rsasign_with_sha256:
    case OID_ecdsa_with_sha256:
      return DIGEST_sha256();
    case OID_rsasign_with_sha384:
    case OID_ecdsa_with_sha384:
      return DIGEST_sha384();
    case OID_rsasign_with_sha512:
    case OID_ecdsa_with_sha512:
      return DIGEST_sha512();
    case OID_rsasign_with_sm3:
    case OID_sm2sign_with_sm3:
      return DIGEST_sm3();
    default:
      return NULL;
  }
}

int crypto_tls_stream_server_end_point_binding_from_certificate(
    const uint8_t *certificate, size_t certificate_size,
    uint8_t *output, size_t capacity, size_t *out_size) {
  uint8_t digest_bytes[DIGEST_MAX_SIZE];
  const DIGEST *digest_algor;
  size_t digest_size = 0u;
  int signature_algor = OID_undef;
  size_t clear_size;

  if (output == NULL || capacity == 0u || out_size == NULL ||
      certificate == NULL || certificate_size == 0u)
    return CRYPTO_TLS_STREAM_EINVAL;
  clear_size = capacity < CRYPTO_TLS_STREAM_SERVER_END_POINT_MAX_BYTES
                   ? capacity
                   : CRYPTO_TLS_STREAM_SERVER_END_POINT_MAX_BYTES;
  memset(output, 0, clear_size);
  *out_size = 0u;

  if (x509_cert_get_signature_algor(certificate, certificate_size,
                                    &signature_algor) != 1)
    return CRYPTO_TLS_STREAM_EPROTO;
  digest_algor = crypto_tls_stream_server_end_point_digest(signature_algor);
  if (digest_algor == NULL ||
      digest_algor->digest_size > CRYPTO_TLS_STREAM_SERVER_END_POINT_MAX_BYTES)
    return CRYPTO_TLS_STREAM_ENOTSUP;

  *out_size = digest_algor->digest_size;
  if (capacity < digest_algor->digest_size) return CRYPTO_TLS_STREAM_EMSGSIZE;
  if (digest(digest_algor, certificate, certificate_size, digest_bytes,
             &digest_size) != 1 ||
      digest_size != digest_algor->digest_size) {
    memset(digest_bytes, 0, sizeof(digest_bytes));
    return CRYPTO_TLS_STREAM_EIO;
  }
  crypto_tls_stream_copy(CRYPTO_TLS_TEST_COPY_METADATA, output, digest_bytes, digest_size);
  memset(digest_bytes, 0, sizeof(digest_bytes));
  return CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_stream_server_end_point_binding(
    const crypto_tls_stream *state, uint8_t *output, size_t capacity,
    size_t *out_size) {
  const uint8_t *certificate = NULL;
  size_t certificate_size = 0u;
  size_t clear_size;
  int result;

  if (output == NULL || capacity == 0u || out_size == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  clear_size = capacity < CRYPTO_TLS_STREAM_SERVER_END_POINT_MAX_BYTES
                   ? capacity
                   : CRYPTO_TLS_STREAM_SERVER_END_POINT_MAX_BYTES;
  memset(output, 0, clear_size);
  *out_size = 0u;
  if (state == NULL || CRYPTO_TLS_STREAM_ENGINE(state) == NULL ||
      !state->handshake_complete)
    return CRYPTO_TLS_STREAM_ENOTCONN;

  if (state->server) {
    const TLS_CONNECT *connection = &CRYPTO_TLS_STREAM_ENGINE(state)->connection;
    /* This is the selected local chain used by the handshake, not the
     * client's mTLS identity or the first configured certificate. */
    result = connection->cert_chain != NULL && connection->cert_chain_len != 0u
        ? x509_certs_get_cert_by_index(connection->cert_chain,
              connection->cert_chain_len, 0, &certificate, &certificate_size)
        : 0;
  } else {
    result = crypto_tls_stream_peer_leaf(&CRYPTO_TLS_STREAM_ENGINE(state)->connection,
                                        &certificate, &certificate_size);
  }
  if (result < 0) return CRYPTO_TLS_STREAM_EIO;
  if (result == 0) return CRYPTO_TLS_STREAM_ENOENT;
  return crypto_tls_stream_server_end_point_binding_from_certificate(
      certificate, certificate_size, output, capacity, out_size);
}

int crypto_tls_stream_peer_certificate_chain_parse(
    const uint8_t *data, size_t size,
    crypto_tls_stream_peer_certificate_chain *out_chain) {
  crypto_tls_stream_peer_certificate_chain candidate = {0};
  size_t count = 0u;
  size_t index;
  size_t total = 0u;

  if (out_chain == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  memset(out_chain, 0, sizeof(*out_chain));
  if (data == NULL || size == 0u) return CRYPTO_TLS_STREAM_ENOENT;
  if (size > CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_BYTES) return CRYPTO_TLS_STREAM_ERANGE;

  if (x509_certs_get_count(data, size, &count) != 1)
    return CRYPTO_TLS_STREAM_EPROTO;
  if (count == 0u) return CRYPTO_TLS_STREAM_EPROTO;
  if (count > CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_CERTIFICATES)
    return CRYPTO_TLS_STREAM_ERANGE;

  for (index = 0u; index < count; ++index) {
    const uint8_t *cert = NULL;
    size_t cert_size = 0u;
    size_t offset;
    if (x509_certs_get_cert_by_index(
            data, size, index, &cert, &cert_size) != 1 ||
        cert == NULL || cert_size == 0u ||
        cert < data || cert > data + size)
      return CRYPTO_TLS_STREAM_EPROTO;
    offset = (size_t)(cert - data);
    if (cert_size > size - offset || total > size - cert_size)
      return CRYPTO_TLS_STREAM_EPROTO;
    candidate.certificates[index].data = cert;
    candidate.certificates[index].size = cert_size;
    total += cert_size;
  }

  if (total != size) return CRYPTO_TLS_STREAM_EPROTO;
  candidate.count = count;
  candidate.total_bytes = total;
  *out_chain = candidate;
  return CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_stream_get_peer_certificate_chain(
    const crypto_tls_stream *state,
    crypto_tls_stream_peer_certificate_chain *out_chain) {
  const crypto_tls_stream_gmssl_state *engine;
  const uint8_t *chain = NULL;
  size_t chain_size = 0u;
  int result;
  if (out_chain == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  memset(out_chain, 0, sizeof(*out_chain));
  if (state == NULL || (engine = CRYPTO_TLS_STREAM_ENGINE(state)) == NULL)
    return CRYPTO_TLS_STREAM_EINVAL;
  if (!state->handshake_complete) return CRYPTO_TLS_STREAM_ENOTCONN;
  result = crypto_tls_stream_peer_chain(&engine->connection, &chain, &chain_size);
  if (result < 0) return CRYPTO_TLS_STREAM_EIO;
  if (result == 0) return CRYPTO_TLS_STREAM_ENOENT;
  if (chain_size > CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_BYTES)
    return CRYPTO_TLS_STREAM_ERANGE;
  return crypto_tls_stream_peer_certificate_chain_parse(
      chain, chain_size, out_chain);
}

int crypto_tls_stream_export_channel_binding(
    const crypto_tls_stream *state,
    uint8_t output[CRYPTO_TLS_STREAM_CHANNEL_BINDING_BYTES]) {
  static const char exporter_label[] = "EXPORTER-Channel-Binding";
  if (output == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  memset(output, 0, CRYPTO_TLS_STREAM_CHANNEL_BINDING_BYTES);
  if (state == NULL || CRYPTO_TLS_STREAM_ENGINE(state) == NULL ||
      !state->handshake_complete)
    return CRYPTO_TLS_STREAM_ENOTCONN;
  return tls_export_keying_material(
             &CRYPTO_TLS_STREAM_ENGINE(state)->connection, output,
             CRYPTO_TLS_STREAM_CHANNEL_BINDING_BYTES, exporter_label, NULL, 0u, 1) == 1
             ? CRYPTO_TLS_STREAM_OK
             : CRYPTO_TLS_STREAM_EIO;
}

const char *crypto_tls_stream_context_server_name(const crypto_tls_stream_context *context) {
  return context != NULL && context->client_server_name[0] != '\0'
      ? context->client_server_name : NULL;
}

int crypto_tls_stream_create(crypto_tls_stream_context *context, bool server,
    const char *server_name, size_t io_buffer_bytes, crypto_tls_stream **out_stream) {
  crypto_tls_stream *stream;
  int status;
  if (out_stream == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  *out_stream = NULL;
  if (context == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  stream = crypto_tls_stream_calloc(1u, sizeof(*stream));
  if (stream == NULL) return CRYPTO_TLS_STREAM_ENOMEM;
  status = crypto_tls_stream_init(stream, context, server, server_name, io_buffer_bytes);
  if (status != CRYPTO_TLS_STREAM_OK) { crypto_tls_stream_free(stream); return status; }
  crypto_tls_stream_context_retain(context);
  *out_stream = stream;
  return CRYPTO_TLS_STREAM_OK;
}
