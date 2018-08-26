// vim: set sw=4 ts=4 sts=4 et tw=78

#include "qzip_cookie.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <zlib.h>
#include "qatzip.h"

// \begin gzip cookie
// Details of cookie can refer to `man fopencookie`.
// zlib related APIs can refer to https://www.zlib.net/manual.html.
static ssize_t
gzip_cookie_write(void *cookie, const char *buf, size_t size)
{
    return gzwrite((gzFile)cookie, (voidpc)buf, (unsigned int)size);
}
static int
gzip_cookie_close(void *cookie)
{
    return gzclose((gzFile)cookie);
}

static cookie_io_functions_t gzip_write_funcs = {
    .write = gzip_cookie_write,
    .close = gzip_cookie_close
};

FILE *
gzip_fopen(const char *fname, const char *mode)
{
    FILE *cookie_fp = NULL;
    int rc;

    // We only care about write mode
    rc = strcmp(mode, "w");
    assert(rc == 0);

    // Compressed data will be written into stderr if `fname` is not given
    gzFile zfp = (fname == NULL) ? gzdopen(fileno(stderr), mode) :
                    gzopen(fname, mode);
    assert(zfp != NULL);

    cookie_fp = fopencookie(zfp, mode, gzip_write_funcs);
    // Disable cookie_fp's stream buffer to eliminate unnecessary memory copy
    // References:
    //  - http://www.pixelbeat.org/programming/stdio_buffering/
    //  - https://en.wikibooks.org/wiki/C_Programming/stdio.h/setvbuf
    rc = setvbuf(cookie_fp, NULL, _IONBF, 0);
    assert(0 == rc);

    return cookie_fp;
}
// \end gzip cookie

// \begin qzip cookie
typedef struct {
    QzSession_T       qz_sess;
    QzSessionParams_T qz_sess_params;
    FILE              *fp;
} qzip_cookie_t;

static ssize_t
qzip_cookie_write(void *cookie, const char *buf, size_t size)
{
    qzip_cookie_t *qz_cookie = (qzip_cookie_t *)(cookie);
    QzSession_T *qz_sess     = &(qz_cookie->qz_sess);

    // TODO: your code here.
    // References:
    //  - code example: QATzip/utils/qzip.c: doProcessFile(...)

    // Fake
    return size;
}

static int
qzip_cookie_close(void *cookie)
{
    qzip_cookie_t *qz_cookie = (qzip_cookie_t *)(cookie);
    QzSession_T *qz_sess     = &(qz_cookie->qz_sess);

    fclose(qz_cookie->fp);
    qzTeardownSession(qz_sess);
    qzClose(qz_sess);
    free(qz_cookie);

    return 0;
}

static cookie_io_functions_t qzip_write_funcs = {
    .write = qzip_cookie_write,
    .close = qzip_cookie_close
};

FILE *
qzip_fopen(const char *fname, const char *mode)
{
    qzip_cookie_t *qz_cookie = (qzip_cookie_t *)calloc(1, sizeof(qzip_cookie_t));
    int rc;

    // We only care about write mode
    rc = strcmp(mode, "w");
    assert(rc == 0);

    // \begin initialization and setup for QAT's compression service
    QzSession_T   *qz_sess = &(qz_cookie->qz_sess);
    QzSessionParams_T *qz_sess_params = &(qz_cookie->qz_sess_params);

    // For simplicity, initializations and setup function calls are not required
    // to obtain compression services. If the initialization and setup functions
    // are not called before compression or decompression requests, then they
    // will be called with default arguments from within the compression or
    // decompression functions. This results in serveral legal calling scenarios,
    // see QATzip/include/qatzip.h for more details. For better understanding,
    // we use scenario 1 here, described blow.
    //
    // Scenario 1 - all functions explicilty invoked by caller, with all arguments
    // provided
    //
    // qzInit(&sess_c, sw_backup);
    // qzSetupSession(&sess_c, &params);
    // qzCompress(&sess, src, &src_len, dest, &dest_len, 1);
    // qzDecompress(&sess, src, &src_len, dest, &dest_len);
    // qzTeardownSession(&sess);
    // qzClose(&sess);

    // Parameter 1 means use software as backup when QAT hardware is unavailable
    rc = qzInit(qz_sess, 1);
    assert(rc == QZ_OK);

    // Default parameters:
    // - dynamic or static huffman headers: fully dynamic
    // - compression or decompression: both
    // - deflate, deflate with GZip or deflate with GZip ext: Gzip ext
    // - Compression level 1..9: 1. Level 1 is twice faster than others and just
    //   have a little loss of compression ratio.
    // - Nanosleep between poll [0..100] (0 means no sleep): 10
    // - Maximum forks permitted in current thread (0 means no forking permitted): 3
    // - Use software as backup or not: yes
    // - Default buffer size (power of 2 - 4K, 8K, 16K, 32K, 64K, 128K): 64KB
    // - Stream buffer size (1K..2M-5K): 64KB
    // - Default threshold of compression service's input size: 1KB
    //   For SW failover, if the size of input request less than the threshold,
    //   QATzip will route the request to software.
    // - req_cnt_thrshold (1..4): 4
    // - wait_cnt_thrshold: 8. When previous try (call icp_sal_userStartProcess in qzInit)
    //   failed, wait for specific number of call before retry device open.
    rc = qzGetDefaults(qz_sess_params);
    assert(rc == QZ_OK);

    rc = qzSetupSession(qz_sess, qz_sess_params);
    assert(rc == QZ_OK);
    // \end initialization and setup for QAT's compression service

    qz_cookie->fp = (fname == NULL) ? stderr : fopen(fname, mode);
    assert(qz_cookie->fp != NULL);

    FILE *cookie_fp = fopencookie(qz_cookie, mode, qzip_write_funcs);
    assert(cookie_fp != NULL);
    // Disable cookie_fp's stream buffer
    rc = setvbuf(cookie_fp, NULL, _IONBF, 0);
    assert(rc == 0);

    return cookie_fp;
}
// \end qzip cookie
