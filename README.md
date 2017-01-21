# QEMU with experimental Compressed Ramdisk block device.
Compressed ramdisk block device driver is added to QEMU 2.4.1 code. Compressed ramdisk is a ramdisk provided by the hypervisor, and the hypervisor compresses its contents online using an lzo algorithm. To improve the performance of a guest, the guest could use that block device as a swap device. This mechanism is same as [zram](https://en.wikipedia.org/wiki/Zram). With compressed ramdisk, [memory compression feature](https://en.wikipedia.org/wiki/Virtual_memory_compression) could be deployed OSes even not yet support that feature (Such as FreeBSD).

## Build
```
$ ./configure --target-list=x86_64-softmmu
$ make
```

## Run
```
# x86_64-softmmu/qemu-system-x86_64 --enable-kvm -m 512 rootdisk.img -drive format=qed,file,if=virtio -k en-us -nographic
```

## Limitations
Currently, [QED](http://wiki.qemu.org/Features/QED) format is disabled and Compressed Ramdisk is implemented as `qed` format. This is intentional in order to use the compressed ramdisk in `libvirt`. If we create a new format, syntax checker in `libvirt` will fail due to unknown block device format.

