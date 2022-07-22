
# Jodel Keyhack v2

Tested with IDA 7.7 (hexrays decompiler required) and Jodel 8.0.1 arm64-v8a

### What this is
This is just a small IDA script, extracting the HMAC key from the library and decoding it as [cfib90s](https://bitbucket.org/cfib90/) script was broken for me.

The approach of this script is scraping the bare `mov` instructions, stripping the key from them and unscrambling it. 
As the key is somehow XORed with a scrambled version of the APKs signature the decrypt.py (ported by tm, based on the OJOC-Keyhack) unscrambles and XORs it. 

This script was developed and tested with IDA 7.7 but should also work on other versions.

### Requirements
- IDA Pro version 7.0 or higher
- Any version of the Jodel APK
- Hexrays decompiler license

### How to use
- Clone this repo or download the `jodel.py` and `decrypt.py`
- Fire up IDA 7.0 or later
- Feed it with the latest libhmac.so (arm64)
  - Open the APK with 7-Zip or simmilar
  - Extract the file /lib/x86/libX.so where X is a random lowercase character
  - The correct library file is around 200 kb
- Wait for the initial IDA analysis to finish
- Hit <kbd>ALT</kbd>+<kbd>F7</kbd> or choose `File -> Script File`
- A file explorer should open, choose the `jodel.py` file
- The IDA console should display the extracted HMAC key

### Example output
```
---------------------------------------------------------------------------------------------
Python 3.9.7 (tags/v3.9.7:1016ef3, Aug 30 2021, 20:19:38) [MSC v.1929 64 bit (AMD64)] 
IDAPython 64-bit v7.4.0 final (serial 0) (c) The IDAPython Team <idapython@googlegroups.com>
---------------------------------------------------------------------------------------------
Found function with pattern  Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_init  at  54624
C6DEAEB09FFCCE3AB116032DB95617381927B96672E02A271F5957B2AF7CD400C67A97378BCF34B4
Derived key of length 40 from library, now decrypting it...
Got raw key array: [198, 222, 174, 176, 159, 252, 206, 58, 177, 22, 3, 45, 185, 86, 23, 56, 25, 39, 185, 102, 114, 224, 42, 39, 31, 89, 87, 178, 175, 124, 212, 0, 198, 122, 151, 55, 139, 207, 52, 180]
Got decrypted key: b'PohIBVvuWFhSLydTFZSjDMWmHrpRQuEGEBPfgIxB'
```
