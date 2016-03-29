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

#define CRD_SIZE 512

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
    void *ptr_crd;
} BDRVCrdState;

static int coroutine_fn crd_co_readv(BlockDriverState *bs, int64_t sector_num,
                                     int nb_sectors, QEMUIOVector *qiov)
{
    BDRVCrdState *s = bs->opaque;
    int ret = 0;
    uint8_t *buf;
    size_t offset, copied;
    int i;
    struct iovec *iov;
    //size_t size = nb_sectors * BDRV_SECTOR_SIZE;
    
    offset = sector_num * BDRV_SECTOR_SIZE;

    qemu_co_mutex_lock(&s->lock);

    copied = 0;
    for (i = 0; i < qiov->niov; i++) {
        iov = &qiov->iov[i];
        buf = iov->iov_base;
        memcpy(buf, s->ptr_crd + offset + copied, iov->iov_len);
        copied += iov->iov_len;
    }

    qemu_co_mutex_unlock(&s->lock);

    return ret;
}

static int coroutine_fn crd_co_writev(BlockDriverState *bs, int64_t sector_num,
                                      int nb_sectors, QEMUIOVector *qiov)
{
    BDRVCrdState *s = bs->opaque;
    int ret = 0;
    uint8_t *buf;
    size_t offset, copied;
    int i;
    struct iovec *iov;
    //size_t size = nb_sectors * BDRV_SECTOR_SIZE;

    offset = sector_num * BDRV_SECTOR_SIZE;

    qemu_co_mutex_lock(&s->lock);

    copied = 0;
    for (i = 0; i < qiov->niov; i++) {
        iov = &qiov->iov[i];
        buf = iov->iov_base;
        memcpy(s->ptr_crd + offset + copied, buf, iov->iov_len);
        copied += iov->iov_len;
    }

    qemu_co_mutex_unlock(&s->lock);

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

    //s->ptr_crd = malloc(CRD_SIZE * 1024 * 1024);
    s->ptr_crd = mmap(0, CRD_SIZE * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (s->ptr_crd == (void *)-1) {
        fprintf(stderr, "malloc failed\n");
        return -1;
    }
    memset(s->ptr_crd, 0, CRD_SIZE * 1024 * 1024);
    if (mlock(s->ptr_crd, CRD_SIZE * 1024 * 1024)) {
        fprintf(stderr, "hanjae mlock failed %s\n", __func__);
    }
    qemu_co_mutex_init(&s->lock);
    return 0;
}

static void crd_close(BlockDriverState *bs)
{
    BDRVCrdState *s = bs->opaque;
        fprintf(stderr, "hanjae test %s\n", __func__);
    munlock(s->ptr_crd, CRD_SIZE * 1024 * 1024);
    //free(s->ptr_crd);
    munmap(s->ptr_crd, CRD_SIZE * 1024 * 1024);
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
    .format_name           = "crd",
    .protocol_name         = "crd",
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
