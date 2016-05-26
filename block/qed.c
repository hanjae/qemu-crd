/*
 * QEMU Block driver for Compressed Ramdisk Device
 *
 * Copyright (C) 2016 Jaehyun Han <jhhan@dcslab.snu.ac.kr>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include <sys/mman.h>
#include "block/block_int.h"
#include "qemu/option.h"
#include "block/aio.h"
#include "block/thread-pool.h"

#include <lzo/lzo1x.h>

#define CRD_SIZE            512
#define PAGE_SIZE           4096
#define PAGE_ZERO_FILLED    0
#define PAGE_COMPRESSED     1
#define PAGE_UNCOMPRESSED   2

static QemuOptsList runtime_opts = {
    .name = "null",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = "filename",
            .type = QEMU_OPT_STRING,
            .help = "",
        },
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "size of the null block",
        },
        { /* end of list */ }
    },
};

typedef struct PageEntity {
    void *ptr_crd;
    uint8_t page_status;
    int page_compressed_size;
} PageEntity;
    
typedef struct BDRVCrdState {
    /* Coroutine. */
    CoMutex lock;
    PageEntity p_table[131072];
    lzo_bytep wrkmem;
    uint8_t *buf_out;
    int *buffer;
} BDRVCrdState;
void *first_fit_4kb(BDRVCrdState *s);
void free_buffer(int *ptr);
void alloc_buffer(int *ptr, int byte_size);

void *first_fit_4kb(BDRVCrdState *s) {
    int *buffer = s->buffer;
    while (*buffer < 1024 || *buffer < 0) {
        buffer += (*(int *)buffer & ~(1<<31));
        buffer++;
    }
    //printf("found %ld\n", (long)(buffer + 1));
    return buffer + 1;
}
void free_buffer(int *ptr) {
    int *size_ptr = ptr-1;
    int size = *size_ptr & (1 << 31);
    //munlock(ptr, size);
    if (*(size_ptr + size) >= 0) {
        *size_ptr = size + *(size_ptr + size + 1);
    } else {
        *size_ptr = size;
    }
    //printf("free %ld\n", (long)ptr);
}

void alloc_buffer(int *ptr, int byte_size) {
    int new_size = ((byte_size - 1) >> 2) + 1;
    int *size_ptr = ptr-1;
    int size = *size_ptr;
    //printf("alloc bytes %d %d %d\n", byte_size, new_size, size);
    *(size_ptr + new_size + 1) = size - new_size;
    *size_ptr = new_size | (1 << 31);
    //mlock(ptr, new_size);
    //printf("alloc %ld, %d %d\n", (long)ptr, byte_size, *(ptr-1));
}


static int page_zero_filled(void *ptr)
{
        unsigned int pos;
        unsigned long *page;

        page = (unsigned long *)ptr;

        for (pos = 0; pos != PAGE_SIZE / sizeof(*page); pos++) {
                if (page[pos])
                        return 0;
        }

        return 1;
}

static int coroutine_fn crd_co_readv(BlockDriverState *bs, int64_t sector_num,
                                     int nb_sectors, QEMUIOVector *qiov)
{
    BDRVCrdState *s = bs->opaque;
    int ret = 0;
    uint8_t *buf;
    //size_t offset;
    size_t copied;
    int i;
    struct iovec *iov;
    PageEntity *e;

    int page_num;
    //int page_offset;
    size_t iov_len;
    //size_t size = nb_sectors * BDRV_SECTOR_SIZE;

    lzo_uint size_out;
    
    //offset = sector_num * BDRV_SECTOR_SIZE;
    page_num = sector_num >> 3; // sector_size = 512 & page_size 4096


    copied = 0;
    for (i = 0; i < qiov->niov; i++) {
        iov = &qiov->iov[i];
        iov_len = iov->iov_len;
        buf = iov->iov_base;
        while (iov_len > 0) {
            if (unlikely(iov_len < PAGE_SIZE)) {
                /* fix this I ignore this since there's no request matches to PAGE_SIZE */

                memset(buf, 0, iov_len);
                /*
                if (s->page_mapped[page_num] == 0) {
                    memset(buf, 0, iov_len);
                } else {
                    memcpy(buf, s->ptr_crd[page_num], iov_len);
                }
                */
                iov_len = 0;
            } else {
                e = &s->p_table[page_num];
                switch (e->page_status) {
                    case PAGE_ZERO_FILLED:
                        memset(buf, 0, PAGE_SIZE);
                        break;
                    case PAGE_UNCOMPRESSED:
                        memcpy(buf, e->ptr_crd, PAGE_SIZE);
                        break;
                    case PAGE_COMPRESSED:
                        size_out = PAGE_SIZE;
                        if (lzo1x_decompress_safe(e->ptr_crd, e->page_compressed_size, buf, &size_out, s->wrkmem) != LZO_E_OK) {
                           printf("Decompression failed! %d %d\n", page_num, e->page_compressed_size);
                           /*
                            printf("failed ptr %ld\n", (long)e->ptr_crd);
                            int err = lzo1x_decompress_safe(e->ptr_crd, e->page_compressed_size, s->buf_out, &size_out, s->wrkmem);
                           printf("ERRNO %d -  %s\n", err, strerror(errno));
                           */
                        /*    int err =
                           lzo1x_decompress_safe(s->ptr_crd[page_num], s->page_compressed_size[page_num], s->buf_out, &size_out, s->wrkmem);
                           printf("ERRNO %d -  %s\n", err, strerror(errno));
                        } else {
                            //printf("Decompression success %d\n", page_num); */
                        }
                        break;
                    default:
                        printf("switch: default - fail!\n");
                }

                iov_len -= PAGE_SIZE;
                buf += PAGE_SIZE;
            }
            page_num++;
        }
        copied += iov->iov_len;
    }
    /*
    for (i = 0; i < qiov->niov; i++) {
        printf("read iovnum %d, len %lu\n", i, iov->iov_len);
    }
    */


    return ret;
}

static int coroutine_fn crd_co_writev(BlockDriverState *bs, int64_t sector_num,
                                      int nb_sectors, QEMUIOVector *qiov)
{
    BDRVCrdState *s = bs->opaque;
    int ret = 0;
    uint8_t *buf;
    //size_t offset;
    size_t copied;
    int i;
    struct iovec *iov;

    int page_num;
    //int page_offset;
    size_t iov_len;
    //size_t size = nb_sectors * BDRV_SECTOR_SIZE;
    PageEntity *e;
    void *comp_buffer;

    lzo_uint size_out;

    //offset = sector_num * BDRV_SECTOR_SIZE;
    page_num = sector_num >> 3; // sector_size = 512 & page_size 4096


    copied = 0;
    for (i = 0; i < qiov->niov; i++) {
        iov = &qiov->iov[i];
        iov_len = iov->iov_len;
        buf = iov->iov_base;
        while (iov_len > 0) {
            /* TODO implement
            if (unlikely(iov_len < PAGE_SIZE)) {
                if (s->page_mapped[page_num] == 1) {
                    free(s->ptr_crd[page_num]);
                }
                s->ptr_crd[page_num] = malloc(PAGE_SIZE);
                s->page_mapped[page_num] = 1;
                memcpy(s->ptr_crd[page_num], buf, iov_len);
                iov_len = 0;
            } else {
            */
                e = &s->p_table[page_num];
                // 1 or 2
                if (unlikely(e->page_status == PAGE_UNCOMPRESSED)) {
                    free_buffer(e->ptr_crd);
                } else if (e->page_status == PAGE_COMPRESSED) {
                    free_buffer(e->ptr_crd);
                }
                comp_buffer = first_fit_4kb(s);

                if (page_zero_filled(buf)) {
                    e->page_status = PAGE_ZERO_FILLED;
                    //printf("Not Compressed page_num %d - zero filled\n", page_num);
                } else {
                    /////compress here
                    if (lzo1x_1_compress(buf, PAGE_SIZE, comp_buffer, &size_out, s->wrkmem) != LZO_E_OK) {
                       //printf("Compression failed!\n");
                    }
                    if (size_out > PAGE_SIZE) {
                        //use uncompressed
                        e->page_status = PAGE_UNCOMPRESSED;
                        e->ptr_crd = comp_buffer;
                        memcpy(e->ptr_crd, buf, PAGE_SIZE);
                        alloc_buffer(comp_buffer, PAGE_SIZE);
                    } else {
                        e->page_status = PAGE_COMPRESSED;
                        e->ptr_crd = comp_buffer;
                        e->page_compressed_size = size_out;
                        alloc_buffer(comp_buffer, size_out);
                    }
                }
                iov_len -= PAGE_SIZE;
                buf += PAGE_SIZE;
            /*}*/
            page_num++;
        }
        copied += iov->iov_len;
    }
    /*
    for (i = 0; i < qiov->niov; i++) {
        printf("write iovnum %d, len %lu\n", i, iov->iov_len);
    }
    */


    return ret;
}

static int64_t crd_getlength(BlockDriverState *bs)
{
    return CRD_SIZE * 1024 * 1024;
}

static int crd_has_zero_init(BlockDriverState *bs)
{
    return 0;
}

static int crd_file_open(BlockDriverState *bs, QDict *options, int bdrv_flags,
                         Error **errp)
{
    BDRVCrdState *s = bs->opaque;
    QemuOpts *opts;
    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &error_abort);
    qemu_opts_del(opts);


    memset(s->p_table, 0, 131072 * sizeof(PageEntity));
    
    s->wrkmem = g_malloc(LZO1X_1_MEM_COMPRESS);
    if (mlock(s->wrkmem, LZO1X_1_MEM_COMPRESS)) {
        fprintf(stderr, "hanjae mlock failed 1 %s %s %d\n", __func__, strerror(errno), LZO1X_1_MEM_COMPRESS);
    }

    if (lzo_init() != LZO_E_OK) {
        error_setg(errp, "failed to initialize the LZO library");
    }
    s->buf_out = g_malloc(4200);
    if (mlock(s->buf_out, 4200)) {
        fprintf(stderr, "hanjae mlock failed 2 %s %s\n", __func__, strerror(errno));
    }
    s->buffer = g_malloc(256 * 1024 * 1024);
    if (mlock(s->buffer, 256 * 1024 * 1024)) {
        fprintf(stderr, "hanjae mlock buffer failed %s\n", strerror(errno));
    }
    *(int *)s->buffer = 256 * 1024 * 1024 - 4;


    //s->ptr_crd = malloc(CRD_SIZE * 1024 * 1024);
    /*
    s->ptr_crd = mmap(0, CRD_SIZE * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (s->ptr_crd == (void *)-1) {
        fprintf(stderr, "malloc failed\n");
        return -1;
    }
    memset(s->ptr_crd, 0, CRD_SIZE * 1024 * 1024);
    if (mlock(s->ptr_crd, CRD_SIZE * 1024 * 1024)) {
        fprintf(stderr, "hanjae mlock failed %s\n", __func__);
    }
    */
    return 0;
}

static void crd_close(BlockDriverState *bs)
{
    BDRVCrdState *s = bs->opaque;
    int i;

    int nz = 0;
    int nf = 0;
    int nc = 0;
    unsigned long sum = 0;
    PageEntity *e;

    for (i = 0; i < 131072; i++) {
        e = &s->p_table[i];
        if (e->page_status == PAGE_ZERO_FILLED) {
            nz++;
        } else if (e->page_status == PAGE_UNCOMPRESSED) {
            nf++;
            munlock(e->ptr_crd, PAGE_SIZE);
            free(e->ptr_crd);
        } else {
            nc++;
            sum += e->page_compressed_size;
            munlock(e->ptr_crd, e->page_compressed_size);
            free(e->ptr_crd);
        }
    }
    printf("nz %d nf %d nc %d average compression %d\n", nz, nf, nc, (int)(sum / nc));

    fprintf(stderr, "hanjae test %s\n", __func__);
    munlock(s->wrkmem, LZO1X_1_MEM_COMPRESS);
    g_free(s->wrkmem);
    munlock(s->buf_out, 4200);
    g_free(s->buf_out);
    munlock(s->buffer, 256 * 1024 * 1024);
    g_free(s->buffer);
    //munlock(s->ptr_crd, CRD_SIZE * 1024 * 1024);
    //free(s->ptr_crd);
    //munmap(s->ptr_crd, CRD_SIZE * 1024 * 1024);
}

static coroutine_fn int crd_co_flush(BlockDriverState *bs)
{
        fprintf(stderr, "hanjae test %s\n", __func__);
    return 0;
}

static int crd_reopen_prepare(BDRVReopenState *reopen_state,
                               BlockReopenQueue *queue, Error **errp)
{
        fprintf(stderr, "hanjae test %s\n", __func__);
    return 0;
}


BlockDriver bdrv_crd = {
    .format_name           = "qed",
    .protocol_name         = "qed",
    .instance_size         = sizeof(BDRVCrdState),
    
    .bdrv_file_open        = crd_file_open,
    .bdrv_close            = crd_close,
    .bdrv_getlength        = crd_getlength,

    .bdrv_co_readv         = crd_co_readv,
    .bdrv_co_writev        = crd_co_writev,
    .bdrv_co_flush_to_disk = crd_co_flush,

    .bdrv_has_zero_init    = crd_has_zero_init,
    .bdrv_reopen_prepare   = crd_reopen_prepare,
};

static void bdrv_crd_init(void)
{
    bdrv_register(&bdrv_crd);
}

block_init(bdrv_crd_init);
