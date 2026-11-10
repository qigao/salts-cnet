/* Provider diagnostic contract: compare with serialized libc ctime before
 * starting workers. Each worker owns its DER, expected text and FILE; only
 * the one-time start gate is shared. The process TZ is never mutated here. */
enum { VALIDITY_PRINT_WORKERS = 16, VALIDITY_PRINT_ITERATIONS = 128 };

typedef struct validity_print_case {
  uint8_t der[64];
  const uint8_t *content;
  size_t content_size;
  char expected[160];
  size_t expected_size;
} validity_print_case;

static int validity_print_prepare(validity_print_case *sample, unsigned id) {
  const time_t before = (time_t)(INT64_C(1577836800) + id * INT64_C(86400));
  const time_t after = (time_t)(INT64_C(2524608000) + id * INT64_C(86400) + 3670);
  const uint8_t *cursor;
  uint8_t *out = sample->der;
  size_t size = 0u;
  char first[32], last[32];
  const char *text;
  int written;
  if (x509_validity_to_der(before, after, &out, &size) != 1) return __LINE__;
  cursor = sample->der;
  if (asn1_sequence_from_der(&sample->content, &sample->content_size,
                            &cursor, &size) != 1 || size != 0u) return __LINE__;
  text = ctime(&before);
  if (!text || strlen(text) >= sizeof(first)) return __LINE__;
  memcpy(first, text, strlen(text) + 1u);
  text = ctime(&after);
  if (!text || strlen(text) >= sizeof(last)) return __LINE__;
  memcpy(last, text, strlen(text) + 1u);
  written = snprintf(sample->expected, sizeof(sample->expected),
      "  validity\n      notBefore: %s      notAfter: %s", first, last);
  if (written < 0 || (size_t)written >= sizeof(sample->expected)) return __LINE__;
  sample->expected_size = (size_t)written;
  return 0;
}

static int validity_print_matches(FILE *fp, const validity_print_case *sample) {
  char actual[sizeof(sample->expected)];
  size_t size;
  if (fseek(fp, 0, SEEK_SET) != 0) return __LINE__;
  if (x509_validity_print(fp, 0, 2, "validity", sample->content,
                          sample->content_size) != 1) return __LINE__;
  if (fflush(fp) != 0 || fseek(fp, 0, SEEK_SET) != 0) return __LINE__;
  size = fread(actual, 1u, sizeof(actual), fp);
  if (ferror(fp) || size != sample->expected_size ||
      memcmp(actual, sample->expected, size) != 0) return __LINE__;
  return 0;
}

static int validity_print_serial(void) {
  validity_print_case sample = {0};
  FILE *fp = tmpfile();
  int status = fp ? 0 : __LINE__;
  for (unsigned i = 0u; fp && !status && i < VALIDITY_PRINT_WORKERS; ++i) {
    status = validity_print_prepare(&sample, i);
    if (!status) status = validity_print_matches(fp, &sample);
  }
  if (fp && fclose(fp) != 0 && !status) status = __LINE__;
  return status;
}

typedef struct validity_print_worker {
  validity_print_case sample;
  atomic32 *start;
  int status; /* Worker-owned until joined. */
} validity_print_worker;

static void validity_print_on_worker(void *arg) {
  validity_print_worker *worker = (validity_print_worker *)arg;
  uint32_t started = 0u;
  FILE *fp;
  while (!started) {
    if (atomic32_load(worker->start, SALTS_MEMORY_ACQUIRE, &started) != SALTS_OK) {
      worker->status = __LINE__;
      return;
    }
    if (!started) sync_thread_yield();
  }
  fp = tmpfile();
  if (!fp) { worker->status = __LINE__; return; }
  for (unsigned i = 0u; i < VALIDITY_PRINT_ITERATIONS; ++i) {
    worker->status = validity_print_matches(fp, &worker->sample);
    if (worker->status) break;
    sync_thread_yield();
  }
  if (fclose(fp) != 0 && !worker->status) worker->status = __LINE__;
}

static int validity_print_concurrent(void) {
  validity_print_worker workers[VALIDITY_PRINT_WORKERS] = {0};
  sync_thread_t threads[VALIDITY_PRINT_WORKERS] = {0};
  atomic32 start;
  unsigned created = 0u;
  int status = 0;
  if (atomic32_init(&start, 0u) != SALTS_OK) return __LINE__;
  /* All libc ctime expectations are copied before any worker can enter. */
  for (unsigned i = 0u; i < VALIDITY_PRINT_WORKERS; ++i) {
    status = validity_print_prepare(&workers[i].sample, i);
    if (status) return status;
    workers[i].start = &start;
  }
  for (; created < VALIDITY_PRINT_WORKERS; ++created) {
    if (sync_thread_create(&threads[created], validity_print_on_worker,
                            &workers[created]) != SALTS_OK) {
      status = __LINE__;
      break;
    }
  }
  /* A partial creation still releases/joins every live worker before return.
   * Gate/join invariant failure cannot leave live entrants on this stack. */
  if (atomic32_store(&start, 1u, SALTS_MEMORY_RELEASE) != SALTS_OK) abort();
  for (unsigned i = 0u; i < created; ++i) {
    if (sync_thread_join(&threads[i]) != SALTS_OK) abort();
    if (workers[i].status && !status) status = workers[i].status;
  }
  return status;
}

static int validity_print_malformed(void) {
  validity_print_case sample = {0};
  FILE *fp;
  int result;
  int status = validity_print_prepare(&sample, 0u);
  if (status) return status;
  fp = tmpfile();
  if (!fp) return __LINE__;
  result = x509_validity_print(fp, 0, 2, "validity", sample.content,
                               sample.content_size - 1u);
  status = result == -1 ? 0 : __LINE__;
  if (fclose(fp) != 0 && !status) status = __LINE__;
  return status;
}

#if defined(_WIN32)
static int validity_print_unsupported_crt_date(void) {
  const uint8_t content[] = "\x18\x0f" "40000101000000Z"
                            "\x18\x0f" "40010101000000Z";
  FILE *fp = tmpfile();
  int result, status;
  if (!fp) return __LINE__;
  result = x509_validity_print(fp, 0, 2, "validity", content, sizeof(content) - 1u);
  status = result == -1 ? 0 : __LINE__;
  if (fclose(fp) != 0 && !status) status = __LINE__;
  return status;
}
#endif
