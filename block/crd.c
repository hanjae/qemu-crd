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

#include "block/block_int.h"
#include "qemu/option.h"

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
    int64_t offset;
    size_t size;
    struct iovec *i;
    
    offset = sector_num * BDRV_SECTOR_SIZE;
    size = nb_sectors * BDRV_SECTOR_SIZE;
        fprintf(stderr, "hanjae test %s -1 sector_num %ld nb_sectors %d offset %ld size %lu\n", __func__, sector_num, nb_sectors, offset, size);

    qemu_co_mutex_lock(&s->lock);

    /* from block/ssh.c
     */
    /* This keeps track of the current iovec element ('i'), where we
     * will write to next ('buf'), and the end of the current iovec
     * ('end_of_vec').
     */
    i = &qiov->iov[0];
    buf = i->iov_base;

    memcpy(buf, s->ptr_crd + offset, size);
        fprintf(stderr, "hanjae test %s -2\n", __func__);

    qemu_co_mutex_unlock(&s->lock);
        fprintf(stderr, "hanjae test %s -3\n", __func__);

    return ret;
}

static int coroutine_fn crd_co_writev(BlockDriverState *bs, int64_t sector_num,
                                      int nb_sectors, QEMUIOVector *qiov)
{
    BDRVCrdState *s = bs->opaque;
    int ret = 0;
    int64_t offset;
    size_t size;

    char *buf;
    struct iovec *i;
        fprintf(stderr, "hanjae test %s\n", __func__);

    offset = sector_num * BDRV_SECTOR_SIZE;
    size = nb_sectors * BDRV_SECTOR_SIZE;

    qemu_co_mutex_lock(&s->lock);

    i = &qiov->iov[0];
    buf = i->iov_base;

    memcpy(s->ptr_crd + offset, buf, size);

    qemu_co_mutex_unlock(&s->lock);

    return ret;
}

static int64_t crd_getlength(BlockDriverState *bs)
{
        fprintf(stderr, "hanjae test %s\n", __func__);
    return 512 * 1024 * 1024;
}

static int crd_has_zero_init(BlockDriverState *bs)
{
        fprintf(stderr, "hanjae test %s\n", __func__);
    return 0;
}

static int crd_file_open(BlockDriverState *bs, QDict *options, int bdrv_flags,
                         Error **errp)
{
        fprintf(stderr, "hanjae test %s\n", __func__);
    BDRVCrdState *s = bs->opaque;
    QemuOpts *opts;
    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &error_abort);
    qemu_opts_del(opts);

    s->ptr_crd = malloc(512 * 1024 * 1024);
    if (s->ptr_crd == NULL)
        fprintf(stderr, "malloc failed\n");
    memset(s->ptr_crd, 0, 512 * 1024 * 1024);
    qemu_co_mutex_init(&s->lock);
    return 0;
}

static void crd_close(BlockDriverState *bs)
{
    BDRVCrdState *s = bs->opaque;
        fprintf(stderr, "hanjae test %s\n", __func__);
    free(s->ptr_crd);
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
