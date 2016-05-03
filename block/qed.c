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

typedef struct BDRVCrdState {
    /* Coroutine. */
    CoMutex lock;
    void *ptr_crd[131072];
    uint8_t page_mapped[131072];
    int page_compressed_size[131072];
    lzo_bytep wrkmem;
    uint8_t *buf_out;
} BDRVCrdState;

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

    int page_num;
    //int page_offset;
    size_t iov_len;
    //size_t size = nb_sectors * BDRV_SECTOR_SIZE;

    lzo_uint size_out;
    
    //offset = sector_num * BDRV_SECTOR_SIZE;
    page_num = sector_num >> 3; // sector_size = 512 & page_size 4096

    //qemu_co_mutex_lock(&s->lock);

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
                if (s->page_mapped[page_num] == PAGE_ZERO_FILLED) {
                    memset(buf, 0, PAGE_SIZE);
                    //printf("Decompression - zero filled %d\n", page_num);
                } else if (s->page_mapped[page_num] == PAGE_UNCOMPRESSED) {
                    memcpy(buf, s->ptr_crd[page_num], PAGE_SIZE);
                    //printf("Decompression - not compressed %d\n", page_num);
                } else if (s->page_mapped[page_num] == PAGE_COMPRESSED) {
                    size_out = PAGE_SIZE;
                    if (lzo1x_decompress_safe(s->ptr_crd[page_num], s->page_compressed_size[page_num], s->buf_out, &size_out, s->wrkmem) != LZO_E_OK) {
                       printf("Decompression failed! %d %d\n", page_num, s->page_compressed_size[page_num]);
                    /*    int err =
                       lzo1x_decompress_safe(s->ptr_crd[page_num], s->page_compressed_size[page_num], s->buf_out, &size_out, s->wrkmem);
                       printf("ERRNO %d -  %s\n", err, strerror(errno));
                    } else {
                        //printf("Decompression success %d\n", page_num); */
                    }
                    memcpy(buf, s->buf_out, PAGE_SIZE);
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

    //qemu_co_mutex_unlock(&s->lock);

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

    lzo_uint size_out;

    //offset = sector_num * BDRV_SECTOR_SIZE;
    page_num = sector_num >> 3; // sector_size = 512 & page_size 4096

    //qemu_co_mutex_lock(&s->lock);

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
                // 1 or 2
                if (s->page_mapped[page_num] == PAGE_UNCOMPRESSED) {
                    munlock(s->ptr_crd[page_num], PAGE_SIZE);
                    free(s->ptr_crd[page_num]);
                } else if (s->page_mapped[page_num] == PAGE_COMPRESSED) {
                    munlock(s->ptr_crd[page_num], s->page_compressed_size[page_num]);
                    free(s->ptr_crd[page_num]);
                }
                if (page_zero_filled(buf)) {
                    s->page_mapped[page_num] = PAGE_ZERO_FILLED;
                    //printf("Not Compressed page_num %d - zero filled\n", page_num);
                } else {
                    /////compress here
                    if (lzo1x_1_compress(buf, PAGE_SIZE, s->buf_out, &size_out, s->wrkmem) != LZO_E_OK) {
                       //printf("Compression failed!\n");
                    }
                    if (size_out > PAGE_SIZE) {
                        //use uncompressed
                        s->page_mapped[page_num] = PAGE_UNCOMPRESSED;
                        s->ptr_crd[page_num] = malloc(PAGE_SIZE);
                        mlock(s->ptr_crd[page_num], PAGE_SIZE);
                        //printf("Not Compressed page_num %d\n", page_num);
                        memcpy(s->ptr_crd[page_num], buf, PAGE_SIZE);
                    } else {
                        s->page_mapped[page_num] = PAGE_COMPRESSED;
                        s->ptr_crd[page_num] = malloc(size_out);
                        mlock(s->ptr_crd[page_num], size_out);
                        s->page_compressed_size[page_num] = size_out;
                        //printf("Compressed page_num %d compressed_size %lu\n", page_num, size_out);
                        memcpy(s->ptr_crd[page_num], s->buf_out, size_out);
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

    //qemu_co_mutex_unlock(&s->lock);

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

    memset(s->page_mapped, 0, 128 * 1024);
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
    qemu_co_mutex_init(&s->lock);
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

    for (i = 0; i < 131072; i++) {
        if (s->page_mapped[i] == PAGE_ZERO_FILLED) {
            nz++;
        } else if (s->page_mapped[i] == PAGE_UNCOMPRESSED) {
            nf++;
        } else {
            nc++;
            sum += s->page_compressed_size[i];
        }
    }
    printf("nz %d nf %d nc %d average compression %d\n", nz, nf, nc, (int)(sum / nc));

    fprintf(stderr, "hanjae test %s\n", __func__);
    g_free(s->wrkmem);
    g_free(s->buf_out);
    //munlock(s->ptr_crd, CRD_SIZE * 1024 * 1024);
    //free(s->ptr_crd);
    //munmap(s->ptr_crd, CRD_SIZE * 1024 * 1024);
}

static coroutine_fn int crd_co_flush(BlockDriverState *bs)
{
        fprintf(stderr, "hanjae test %s\n", __func__);
    return 0;
}

typedef struct {
    BlockAIOCB common;
    QEMUBH *bh;
    QEMUIOVector *qiov;

    int64_t sector_num;
    int nb_sectors;

    size_t start;
    size_t end;
    /* 0 : write
     * 1 : read
     * 2 : flush
     */
    int type;
} CrdAIOCB;

static const AIOCBInfo crd_aiocb_info = {
    .aiocb_size = sizeof(CrdAIOCB),
};


static void crd_readv_bh_cb(void *p)
{
    CrdAIOCB *acb = p;
    BDRVCrdState *s = acb->common.bs->opaque;
    uint8_t *buf;
    size_t copied;
    int i;
    struct iovec *iov;
    int page_num;
    size_t iov_len;
    lzo_uint size_out;
    page_num = acb->sector_num >> 3; // sector_size = 512 & page_size 4096

    qemu_bh_delete(acb->bh);
    acb->bh = NULL;

    copied = 0;
    for (i = 0; i < acb->qiov->niov; i++) {
        iov = &acb->qiov->iov[i];
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
                if (s->page_mapped[page_num] == PAGE_ZERO_FILLED) {
                    memset(buf, 0, PAGE_SIZE);
                    //printf("Decompression - zero filled %d\n", page_num);
                } else if (s->page_mapped[page_num] == PAGE_UNCOMPRESSED) {
                    memcpy(buf, s->ptr_crd[page_num], PAGE_SIZE);
                    //printf("Decompression - not compressed %d\n", page_num);
                } else if (s->page_mapped[page_num] == PAGE_COMPRESSED) {
                    size_out = PAGE_SIZE;
                    if (lzo1x_decompress_safe(s->ptr_crd[page_num], s->page_compressed_size[page_num], s->buf_out, &size_out, s->wrkmem) != LZO_E_OK) {
                       printf("Decompression failed! %d %d\n", page_num, s->page_compressed_size[page_num]);
                    /*    int err =
                       lzo1x_decompress_safe(s->ptr_crd[page_num], s->page_compressed_size[page_num], s->buf_out, &size_out, s->wrkmem);
                       printf("ERRNO %d -  %s\n", err, strerror(errno));
                    } else {
                        //printf("Decompression success %d\n", page_num); */
                    }
                    memcpy(buf, s->buf_out, PAGE_SIZE);
                }
                iov_len -= PAGE_SIZE;
                buf += PAGE_SIZE;
            }
            page_num++;
        }
        copied += iov->iov_len;
    }
    acb->common.cb(acb->common.opaque, 0);
    qemu_aio_unref(acb);
}

static BlockAIOCB *crd_aio_readv(BlockDriverState *bs,
                                  int64_t sector_num, QEMUIOVector *qiov,
                                  int nb_sectors,
                                  BlockCompletionFunc *cb,
                                  void *opaque)
{
    CrdAIOCB *acb;

    acb = qemu_aio_get(&crd_aiocb_info, bs, cb, opaque);

    acb->qiov = qiov;
    acb->sector_num = sector_num;
    acb->nb_sectors = nb_sectors;

    acb->bh = aio_bh_new(bdrv_get_aio_context(bs), crd_readv_bh_cb, acb);
    qemu_bh_schedule(acb->bh);
    return &acb->common;
}

static void crd_writev_bh_cb(void *p)
{
    CrdAIOCB *acb = p;
    BDRVCrdState *s = acb->common.bs->opaque;
    uint8_t *buf;
    size_t copied;
    int i;
    struct iovec *iov;
    int page_num;
    size_t iov_len;
    lzo_uint size_out;

    page_num = acb->sector_num >> 3; // sector_size = 512 & page_size 4096

    qemu_bh_delete(acb->bh);
    acb->bh = NULL;

    copied = 0;
    for (i = 0; i < acb->qiov->niov; i++) {
        iov = &acb->qiov->iov[i];
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
                // 1 or 2
                if (s->page_mapped[page_num] == PAGE_UNCOMPRESSED) {
                    munlock(s->ptr_crd[page_num], PAGE_SIZE);
                    free(s->ptr_crd[page_num]);
                } else if (s->page_mapped[page_num] == PAGE_COMPRESSED) {
                    munlock(s->ptr_crd[page_num], s->page_compressed_size[page_num]);
                    free(s->ptr_crd[page_num]);
                }
                if (page_zero_filled(buf)) {
                    s->page_mapped[page_num] = PAGE_ZERO_FILLED;
                    //printf("Not Compressed page_num %d - zero filled\n", page_num);
                } else {
                    /////compress here
                    if (lzo1x_1_compress(buf, PAGE_SIZE, s->buf_out, &size_out, s->wrkmem) != LZO_E_OK) {
                       //printf("Compression failed!\n");
                    }
                    if (size_out > PAGE_SIZE) {
                        //use uncompressed
                        s->page_mapped[page_num] = PAGE_UNCOMPRESSED;
                        s->ptr_crd[page_num] = malloc(PAGE_SIZE);
                        mlock(s->ptr_crd[page_num], PAGE_SIZE);
                        //printf("Not Compressed page_num %d\n", page_num);
                        memcpy(s->ptr_crd[page_num], buf, PAGE_SIZE);
                    } else {
                        s->page_mapped[page_num] = PAGE_COMPRESSED;
                        s->ptr_crd[page_num] = malloc(size_out);
                        mlock(s->ptr_crd[page_num], size_out);
                        s->page_compressed_size[page_num] = size_out;
                        //printf("Compressed page_num %d compressed_size %lu\n", page_num, size_out);
                        memcpy(s->ptr_crd[page_num], s->buf_out, size_out);
                    }
                }
                iov_len -= PAGE_SIZE;
                buf += PAGE_SIZE;
            /*}*/
            page_num++;
        }
        copied += iov->iov_len;
    }
    acb->common.cb(acb->common.opaque, 0);
    qemu_aio_unref(acb);
}

static BlockAIOCB *crd_aio_writev(BlockDriverState *bs,
                                   int64_t sector_num, QEMUIOVector *qiov,
                                   int nb_sectors,
                                   BlockCompletionFunc *cb,
                                   void *opaque)
{
    CrdAIOCB *acb;

    acb = qemu_aio_get(&crd_aiocb_info, bs, cb, opaque);

    acb->qiov = qiov;
    acb->sector_num = sector_num;
    acb->nb_sectors = nb_sectors;

    acb->bh = aio_bh_new(bdrv_get_aio_context(bs), crd_writev_bh_cb, acb);
    qemu_bh_schedule(acb->bh);
    return &acb->common;
}

static void crd_flushv_bh_cb(void *p)
{
    CrdAIOCB *acb = p;
    qemu_bh_delete(acb->bh);
    acb->common.cb(acb->common.opaque, 0);
    qemu_aio_unref(acb);
        fprintf(stderr, "hanjae test %s\n", __func__);
}
static BlockAIOCB *crd_aio_flush(BlockDriverState *bs,
                                  BlockCompletionFunc *cb,
                                  void *opaque)
{
    CrdAIOCB *acb;

    acb = qemu_aio_get(&crd_aiocb_info, bs, cb, opaque);

    acb->bh = aio_bh_new(bdrv_get_aio_context(bs), crd_flushv_bh_cb, acb);
    qemu_bh_schedule(acb->bh);
    return &acb->common;
}

static int crd_reopen_prepare(BDRVReopenState *reopen_state,
                               BlockReopenQueue *queue, Error **errp)
{
        fprintf(stderr, "hanjae test %s\n", __func__);
    return 0;
}


BlockDriver bdrv_crd = {
    .format_name           = "qed-co",
    .protocol_name         = "qed-co",
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

BlockDriver bdrv_crd_aio = {
    .format_name           = "qed",
    .protocol_name         = "qed",
    .instance_size         = sizeof(BDRVCrdState),
    
    .bdrv_file_open        = crd_file_open,
    .bdrv_close            = crd_close,
    .bdrv_getlength        = crd_getlength,

    .bdrv_aio_readv        = crd_aio_readv,
    .bdrv_aio_writev       = crd_aio_writev,
    .bdrv_aio_flush        = crd_aio_flush,

    .bdrv_has_zero_init    = crd_has_zero_init,
    .bdrv_reopen_prepare   = crd_reopen_prepare,
};

static void bdrv_crd_init(void)
{
    bdrv_register(&bdrv_crd);
    bdrv_register(&bdrv_crd_aio);
}

block_init(bdrv_crd_init);
