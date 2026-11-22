#ifndef SALTS_CNET_EXPORT_H
#define SALTS_CNET_EXPORT_H

/* The shared-library target supplies the private build definition. */
#if defined(_WIN32) && defined(SALTS_CNET_BUILD)
#  define SALTS_CNET_EXPORT __declspec(dllexport)
#else
#define SALTS_CNET_EXPORT
#endif

#endif
