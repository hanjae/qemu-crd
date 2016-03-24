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
    
        fprintf(stderr, "hanjae test %s\n", __func__);
    offset = sector_num * BDRV_SECTOR_SIZE;
    size = nb_sectors * BDRV_SECTOR_SIZE;

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

    qemu_co_mutex_unlock(&s->lock);

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
    return 512 * 1024;
}

static int crd_has_zero_init(BlockDriverState *bs)
{
        fprintf(stderr, "hanjae test %s\n", __func__);
    return 0;
}

static int crd_file_open(BlockDriverState *bs, QDict *options, int bdrv_flags,
                         Error **errp)
{
    BDRVCrdState *s = bs->opaque;
    s->ptr_crd = malloc(512 * 1024 * 1024);
    qemu_co_mutex_init(&s->lock);
    return 0;
}

static void crd_close(BlockDriverState *bs)
{
    //BDRVCrdState *s = bs->opaque;
    //free(s);
}

static void crd_parse_filename(const char *filename, QDict *options,
                               Error **errp)
{
    return;
}

BlockDriver bdrv_crd = {
    .format_name          = "crd",
    .protocol_name        = "crd",
    .instance_size        = sizeof(BDRVCrdState),
    .bdrv_parse_filename  = crd_parse_filename,
    .bdrv_file_open       = crd_file_open,
    .bdrv_close           = &crd_close,
    .bdrv_co_readv        = &crd_co_readv,
    .bdrv_co_writev       = &crd_co_writev,
    .bdrv_getlength       = &crd_getlength,
    .bdrv_has_zero_init   = &crd_has_zero_init
};

static void bdrv_crd_init(void)
{
    bdrv_register(&bdrv_crd);
}

block_init(bdrv_crd_init);
