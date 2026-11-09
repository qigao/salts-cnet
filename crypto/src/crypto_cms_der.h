#ifndef CRYPTO_CMS_DER_H
#define CRYPTO_CMS_DER_H
/* Private bounded CMS schema composition; canonical TLV encoding/validation
 * remains owned by Salts ASN1. Never handles cryptographic arithmetic. */
#include <salts/asn1.h>
#include "crypto_internal.h"
#include <string.h>
typedef struct cms_writer { uint8_t *data; size_t size, capacity; int failed; } cms_writer;
typedef struct cms_span { const uint8_t *data; size_t size; } cms_span;

static inline void raw(cms_writer *w, const void *data, size_t n) {
  if (w->failed) return;
  if (n > w->capacity - w->size) { w->failed = 1; return; }
  if (n) memcpy(w->data + w->size, data, n);
  w->size += n;
}
static inline void put(cms_writer *w, unsigned cls, unsigned constructed, unsigned tag,
    const void *data, size_t n) {
  size_t written = 0u;
  if (w->failed) return;
  if (asn1_encode_tlv((uint8_t)cls, (uint8_t)constructed, tag, data, n,
      SALTS_ASN1_DER, 0u, w->data + w->size, w->capacity - w->size, &written) != SALTS_ASN1_OK)
    w->failed = 1;
  else w->size += written;
}
static inline void wrap(cms_writer *w, unsigned cls, unsigned tag, const cms_writer *child) {
  if (child->failed) w->failed = 1;
  else put(w, cls, 1u, tag, child->data, child->size);
}
static inline void oid(cms_writer *w, const void *value, size_t n) { put(w, 0u, 0u, 6u, value, n); }
static inline int compare(cms_span a, cms_span b) {
  size_t n = a.size < b.size ? a.size : b.size;
  int result = n ? memcmp(a.data, b.data, n) : 0;
  return result ? result : a.size < b.size ? -1 : a.size > b.size ? 1 : 0;
}
static inline int same(cms_span a, cms_span b) { return a.size == b.size && (!a.size || !memcmp(a.data, b.data, a.size)); }
static inline int disjoint(const void *out, size_t bound, const size_t *written, const void *in, size_t n) {
  return !salts_crypto_overlap(out, bound, in, n) && !salts_crypto_overlap(written, sizeof(*written), in, n);
}
static inline int output_valid(const void *out, size_t cap, size_t bound, const size_t *written) {
  return out && cap >= bound && written && !salts_crypto_overlap(out, bound, written, sizeof(*written));
}
static inline int done(const asn1_reader *r) { return r->offset == r->size; }
static inline int take(asn1_reader *r, unsigned cls, unsigned constructed, unsigned tag, asn1_tlv *v) {
  return asn1_reader_next(r,v) == SALTS_ASN1_OK && v->tag_class == cls &&
      v->constructed == constructed && v->tag_number == tag;
}
static inline int enter(asn1_reader *r, unsigned cls, unsigned tag, asn1_reader *out) {
  asn1_tlv v;
  return take(r,cls,1u,tag,&v) && asn1_reader_open_children(r,&v,out) == SALTS_ASN1_OK;
}
static inline int root(const void *data, size_t size, asn1_reader *out) {
  asn1_reader r;
  return asn1_reader_init(&r,data,size,SALTS_ASN1_DER) == SALTS_ASN1_OK && enter(&r,0u,16u,out) && done(&r);
}
static inline int is_oid(const asn1_tlv *v, const void *data, size_t size) {
  return v->content_size == size && !memcmp(v->content,data,size);
}
#endif
