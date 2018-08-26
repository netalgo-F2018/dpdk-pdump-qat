#ifndef _QZIP_COOKIE_H
#define _QZIP_COOKIE_H

#define _GNU_SOURCE     // To enable fopencookie()
#define _POSIX_C_SOURCE // To enable fileno()
#include <stdio.h>

#define QC_PRINT(fmt, args...) { printf(" INFO: " fmt, ##args); }
#define QC_ERROR(fmt, args...) { printf("ERROR: " fmt, ##args); }

#ifdef QZ_COOKIE_DEBUG
#define QC_DEBUG(fmt, args...) { printf("DEBUG: " fmt, ##args); }
#else
#define QC_DEBUG(...)
#endif

FILE * gzip_fopen(const char *fname, const char *mode);

// TODO: you should implement this API in qzip_cookie.c.
FILE * qzip_fopen(const char *fname, const char *mode);

#endif  // _QZIP_COOKIE_H
