
# Jodel Keyhack v2

Tested with 
- IDA 7.7
  - Python3 support is required
  - The Android version requires a hexrays decompiler license
- Jodel 8.0.1 arm64-v8a (Android) 
- Jodel version 4.139 and version 7.51 (iOS)

## iOS
Just a small script to use with IDA to extract the HMAC key from a decrypted binary. The key extraction the script performs is pretty straightforward:
- Locating the `+[JDLCrypto convertNSStringToCString:]` function
- Decompile the function AFTER the `+[JDLCrypto convertNSStringToCString:]` function (usually `sub_10004F2E8` or simmilar), here a reference to the XORed key is present
- Look for the first MOV instruction (which contains the reference to the XORed key) and extract the address of the XORed key
- XOR the key with the static value `ed25b40c912702e08c2b2a06eae635e03f475cc3` (extracted from the app)

#### How to use
- Save the `jodel_ios.py` file somewhere to your local drive
- Fire up IDA and load a **DECRYPTED** Jodel binary into it
- Wait for the initial IDA analysis to finish
- Hit <kbd>ALT</kbd>+<kbd>F7</kbd> or choose `File -> Script File`
  - Choose the `jodel_ios.py` file
- Profit

Running the script should provide the following output:

```
[...]
Found function  +[JDLCrypto convertNSStringToCString:]  at  4295128280
Found function with pattern convertNSStringToCString at 4295128424
Found function  +[JDLCrypto convertNSStringToCString:]  at  4295128280
Got raw key: 3c21795415577f264e4b5b505f4413677d2559206436607f16062d5e5d7c235d552b40515f3a2f60
Decrypted key: YEKawcOEwzigovvWEFkBVWPIsgHhnIFmfMtfjYLS
```

## Android

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
