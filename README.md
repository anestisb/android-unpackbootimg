unpackbootimg
=============

unpackbootimg & mkbootimg to work with Android boot images.

Since image tools are not part of Android SDK, this standalone port of AOSP system/core aims to avoid complex building chains.

```
$ make
$ ./unpackbootimg
usage: unpackbootimg
  -i|--input boot.img
  [ -o|--output output_directory]
  [ -p|--pagesize <size-in-hexadecimal> ]
$ ./mkbootimg
usage: mkbootimg
       --kernel <filename>
       [ --ramdisk <filename> ]
       [ --second <2ndbootloader-filename> ]
       [ --cmdline <kernel-commandline> ]
       [ --board <boardname> ]
       [ --base <address> ]
       [ --pagesize <pagesize> ]
       [ --dt <filename> ]
       [ --kernel_offset <base offset> ]
       [ --ramdisk_offset <base offset> ]
       [ --second_offset <base offset> ]
       [ --tags_offset <base offset> ]
       [ --os_version <A.B.C version> ]
       [ --os_patch_level <YYYY-MM-DD date> ]
       [ --hash <sha1(default)|sha256> ]
       [ --id ]
       -o|--output <filename>
$ ./mkbootimg.py
usage: mkbootimg.py [-h] --kernel KERNEL [--ramdisk RAMDISK] [--second SECOND]
                    [--cmdline CMDLINE] [--base BASE]
                    [--kernel_offset KERNEL_OFFSET]
                    [--ramdisk_offset RAMDISK_OFFSET]
                    [--second_offset SECOND_OFFSET] [--os_version OS_VERSION]
                    [--os_patch_level OS_PATCH_LEVEL]
                    [--tags_offset TAGS_OFFSET] [--board BOARD]
                    [--pagesize {2048,4096,8192,16384}] [--id] -o OUTPUT
```

Credits to [@osm0sis](https://github.com/osm0sis/mkbootimg) for maintaining
most of the unpackbootimg logic that is no longer present in AOSP.
