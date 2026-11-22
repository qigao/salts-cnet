#ifndef SALTS_CRYPTO_EXPORT_H
#define SALTS_CRYPTO_EXPORT_H

/* The shared-library target supplies the private build definition. */
#if defined(_WIN32) && defined(SALTS_CRYPTO_BUILD)
#  define SALTS_CRYPTO_EXPORT __declspec(dllexport)
#else
#define SALTS_CRYPTO_EXPORT
#endif

#endif
