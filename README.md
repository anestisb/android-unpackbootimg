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
       --ramdisk <filename>
       [ --second <2ndbootloader-filename> ]
       [ --cmdline <kernel-commandline> ]
       [ --board <boardname> ]
       [ --base <address> ]
       [ --pagesize <pagesize> ]
       [ --ramdiskaddr <address> ]
       -o|--output <filename>
```
