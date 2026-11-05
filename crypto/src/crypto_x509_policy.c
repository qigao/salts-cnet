#include "crypto_x509_policy.h"

static int tag(const salts_asn1_tlv *v, uint32_t number, unsigned constructed) {
  return !v->tag_class && v->tag_number == number && v->constructed == constructed;
}
static int next(salts_asn1_reader *r, salts_asn1_tlv *v, uint32_t number, unsigned constructed) {
  return salts_asn1_reader_next(r, v) == SALTS_ASN1_OK && tag(v, number, constructed);
}
static int end(const salts_asn1_reader *r) { return r->offset == r->size; }
static int sequence(const void *data, size_t n, salts_asn1_reader *r) {
  salts_asn1_reader top; salts_asn1_tlv v;
  return salts_asn1_reader_init(&top, data, n, SALTS_ASN1_DER) == SALTS_ASN1_OK &&
      next(&top, &v, 16, 1) && end(&top) &&
      salts_asn1_reader_open_children(&top, &v, r) == SALTS_ASN1_OK;
}
static unsigned decimal(const uint8_t *p, size_t n) {
  unsigned value = 0;
  while (n--) value = value*10u + *p++ - '0';
  return value;
}
static int leap(unsigned y) { return y%4u == 0u && (y%100u != 0u || y%400u == 0u); }
int salts_crypto_x509_date(const salts_asn1_tlv *v, int64_t *out) {
  static const unsigned days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
  size_t digits = v->tag_number == 23u ? 12u : 14u, k;
  if (v->tag_class || v->constructed || (v->tag_number != 23u && v->tag_number != 24u) ||
      v->content_size != digits+1 || v->content[digits] != 'Z') return 0;
  for (size_t i=0; i<digits; ++i) if (v->content[i] < '0' || v->content[i] > '9') return 0;
  k = digits-10u;
  unsigned y = decimal(v->content, k), m = decimal(v->content+k, 2), d = decimal(v->content+k+2, 2);
  unsigned h = decimal(v->content+k+4, 2), min = decimal(v->content+k+6, 2), sec = decimal(v->content+k+8, 2);
  if (k == 2) y += y >= 50u ? 1900u : 2000u;
  else if (y < 2050u) return 0; /* RFC5280 uses UTCTime through 2049. */
  if (m < 1 || m > 12 || d < 1 || d > days[m-1]+(unsigned)(m == 2 && leap(y)) || h > 23 || min > 59 || sec > 59) return 0;
  /* Gregorian days before Jan 1 y, relative to Jan 1 1970; bounded by year9999. */
  int64_t before = (int64_t)(y-1u)*365 + (y-1u)/4u - (y-1u)/100u + (y-1u)/400u - 719162;
  for (unsigned i=1; i<m; ++i) before += days[i-1]+(unsigned)(i == 2 && leap(y));
  *out = (before+d-1)*86400 + h*3600 + min*60 + sec;
  return 1;
}
int salts_crypto_x509_valid_time(const crypto_x509_der_view *v, int64_t now) {
  salts_asn1_reader r; salts_asn1_tlv first, last; int64_t a, b;
  return sequence(v->validity_der, v->validity_size, &r) &&
      salts_asn1_reader_next(&r, &first) == SALTS_ASN1_OK &&
      salts_asn1_reader_next(&r, &last) == SALTS_ASN1_OK && end(&r) &&
      salts_crypto_x509_date(&first, &a) && salts_crypto_x509_date(&last, &b) && a <= b && a <= now && now <= b;
}
int salts_crypto_x509_valid_name(const void *der, size_t n) {
  salts_asn1_reader rdns, attrs, fields; salts_asn1_tlv rdn, attr, oid, value;
  if (!sequence(der, n, &rdns) || end(&rdns)) return 0;
  while (!end(&rdns)) {
    if (!next(&rdns, &rdn, 17, 1) || salts_asn1_reader_open_children(&rdns, &rdn, &attrs) != SALTS_ASN1_OK || end(&attrs)) return 0;
    while (!end(&attrs)) {
      if (!next(&attrs, &attr, 16, 1) || salts_asn1_reader_open_children(&attrs, &attr, &fields) != SALTS_ASN1_OK ||
          !next(&fields, &oid, 6, 0) || salts_asn1_reader_next(&fields, &value) != SALTS_ASN1_OK ||
          value.tag_class || value.constructed || !value.content_size || !end(&fields)) return 0;
    }
  }
  return 1;
}
