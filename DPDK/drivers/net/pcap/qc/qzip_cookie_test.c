// vim: set sw=4 ts=4 sts=4 et tw=78
//
// ATTENTION: Just check if API is runnable but not check it's correctness.
//

#include "qzip_cookie.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>

#include "qatzip.h"

#define MAXPATH 1024

typedef struct {
    struct timeval time_s;
    struct timeval time_e;
} run_time_t;

// Refer to QATzip/utils/qzip.c: displayStats(...)
void display_stats(run_time_t *run_time, unsigned int insize)
{
    unsigned long us_begin = 0;
    unsigned long us_end   = 0;
    double us_diff         = 0;

    us_begin = run_time->time_s.tv_sec * 1e6 + run_time->time_s.tv_usec;
    us_end   = run_time->time_e.tv_sec * 1e6 + run_time->time_e.tv_usec;
    us_diff  = (us_end - us_begin);

    assert(0 != us_diff);
    assert(0 != insize);
    double throughput = ((double)insize * 8) / us_diff;     // in MBit/s

    printf("Time taken:     %9.3lf ms\n", us_diff / 1000);
    printf("Throughput:     %9.3lf Mbit/s\n", throughput);
}

void display_speedup(run_time_t *run_time_old, run_time_t *run_time_new)
{
    unsigned long us_begin_old, us_end_old;
    unsigned long us_begin_new, us_end_new;
    double us_diff_old, us_diff_new;

    us_begin_old = run_time_old->time_s.tv_sec * 1e6 + run_time_old->time_s.tv_usec;
    us_end_old   = run_time_old->time_e.tv_sec * 1e6 + run_time_old->time_e.tv_usec;
    us_diff_old  = (us_end_old - us_begin_old);

    us_begin_new = run_time_new->time_s.tv_sec * 1e6 + run_time_new->time_s.tv_usec;
    us_end_new   = run_time_new->time_e.tv_sec * 1e6 + run_time_new->time_e.tv_usec;
    us_diff_new  = (us_end_new - us_begin_new);

    assert(us_diff_old > 0);
    assert(us_diff_new > 0);
    double speedup = (us_diff_old / us_diff_new);

    printf("Speedup:        %9.3lf x\n", speedup);
}

off_t file_size(const char *fpath)
{
    struct stat fstat;

    int rc = stat(fpath, &fstat);
    assert(rc == 0);

    return fstat.st_size;
}

char *map_file(const char *fpath)
{
    int fd = open(fpath, O_RDONLY);
    assert(fd >= 0);

    size_t fsize = file_size(fpath);
    assert(fsize > 0);

    // Use mmap to eliminate overhead of kernel-to-user memory copy
    char *addr = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    assert(addr != NULL);

    return addr;
}

inline void def(char *buf, size_t size, FILE *fout, int chunk_size)
{
    size_t bytes_to_write, bytes_written, off;

    for (off = 0; off < size; off += chunk_size) {
        bytes_to_write = ((size - off) < chunk_size) ? (size - off) : chunk_size;
        bytes_written  = fwrite(buf + off, 1, bytes_to_write, fout);
        assert(bytes_written == bytes_to_write);
    }
}

static run_time_t rtime;

void test_gzip(const char *fin_path, const char *fout_path, int chunk_size)
{
    char *addr = map_file(fin_path);
    assert(addr != NULL);

    size_t fsize = file_size(fin_path);
    assert(fsize > 0);

    FILE *fout = gzip_fopen(fout_path, "w");
    assert(fout != NULL);

    gettimeofday(&rtime.time_s, NULL);
    def(addr, fsize, fout, chunk_size);
    fclose(fout);
    gettimeofday(&rtime.time_e, NULL);

    munmap(addr, fsize);

    printf("===Test gzip done\n");
    display_stats(&rtime, fsize);
}

void test_qzip(const char *fin_path, const char *fout_path, int chunk_size)
{
    char *addr = map_file(fin_path);
    assert(addr != NULL);

    size_t fsize = file_size(fin_path);
    assert(fsize > 0);

    FILE *fout = qzip_fopen(fout_path, "w");
    assert(fout != NULL);

    gettimeofday(&rtime.time_s, NULL);
    def(addr, fsize, fout, chunk_size);
    fclose(fout);
    gettimeofday(&rtime.time_e, NULL);

    munmap(addr, fsize);

    printf("===Test qzip done\n");
    display_stats(&rtime, fsize);
}

// This function will write compressed data to stderr
void bench_qzip(const char *fin_path, int chunk_size)
{
    run_time_t gzip_rtime;
    run_time_t qzip_rtime;

    char *addr = map_file(fin_path);
    assert(addr != NULL);

    size_t fsize = file_size(fin_path);
    assert(fsize > 0);

    // \begin bench baseline
    // `qzip_hook` has disabled IO stream's internal buffer so that call to `fwrite`
    // will directly deliver data-to-write to `qzip_write` and then processed by QAT
    FILE *gz_fout = gzip_fopen(NULL, "w");
    assert(gz_fout != NULL);

    gettimeofday(&gzip_rtime.time_s, NULL);
    def(addr, fsize, gz_fout, chunk_size);
    fclose(gz_fout);
    gettimeofday(&gzip_rtime.time_e, NULL);

    display_stats(&gzip_rtime, fsize);
    // \end bench baseline

    // \begin bench my version
    FILE *qz_fout = qzip_fopen(NULL, "w");
    assert(qz_fout != NULL);

    gettimeofday(&qzip_rtime.time_s, NULL);
    def(addr, fsize, qz_fout, chunk_size);
    fclose(qz_fout);
    gettimeofday(&qzip_rtime.time_e, NULL);

    display_stats(&qzip_rtime, fsize);
    // \end bench my version

    munmap(addr, fsize);

    display_speedup(&gzip_rtime, &qzip_rtime);
}

void print_usage(const char *progname)
{
    printf("Usage: %s [options] <input_file>\n", progname);
    printf("Program options:\n");
    printf("    -c  --case <INT>            Test specified cookie API (default 0 that means all)\n");
    printf("    -s  --chunk-size <INT>      Size of chunk to compress a time (default 64KB)\n");
    printf("    -o  --output-file <PATH>    File to save output data\n");
    printf("    -h  --help                  This message\n");
}

int main(int argc, char **argv)
{
    int  test_case  = 0;
    int  chunk_size = (64*1024);    // 64 KB
    char *fin_path  = NULL;
    char *fout_path = NULL;

    // \begin parse commandline args
    int opt;

    static struct option long_options[] = {
        {"case",        required_argument, 0, 'c'},
        {"chunk-size",  required_argument, 0, 's'},
        {"output-file", required_argument, 0, 'o'},
        {"help",        no_argument,       0, 'h'},
        {0,             0,                 0,  0 }
    };

    while ((opt = getopt_long(argc, argv, "c:s:o:h", long_options, NULL)) != -1) {

        switch (opt) {
            case 'c':
                test_case = atoi(optarg);
                break;
            case 's':
                chunk_size = atoi(optarg);
                assert(chunk_size > 0);
                break;
            case 'o':
                fout_path = calloc(1, sizeof(MAXPATH));
                assert(fout_path != NULL);
                strcpy(fout_path, optarg);
                break;
            case 'h':
            case '?':
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        fin_path = calloc(1, sizeof(MAXPATH));
        assert(fin_path != NULL);
        strcpy(fin_path, argv[optind++]);
    } else {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    // \end parse commandline args

    switch (test_case) {
        case 1:
            test_gzip(fin_path, fout_path, chunk_size);
            break;
        case 2:
            test_qzip(fin_path, fout_path, chunk_size);
            break;
        case 3:
            bench_qzip(fin_path, chunk_size);
            break;
        case 0:
        default:
            test_gzip(fin_path, fout_path, chunk_size);
            test_qzip(fin_path, fout_path, chunk_size);
            break;
    }

    // Whatever
    //free(fin_path);
    //free(fout_path);

    return 0;
}
