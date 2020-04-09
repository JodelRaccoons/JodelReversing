
# Jodel Keyhack v2

Tested with IDA 7.0 and Jodel 5.40.0

### What this is
This is just a small IDA script, extracting the HMAC key from the library and decoding it as [cfib90s](https://bitbucket.org/cfib90/) script was broken for me.

The approach of this script is scraping the bare `mov` instructions, stripping the key from them and unscrambling it. 
As the key is somehow XORed with a scrambled version of the APKs signature the decrypt.py (ported by tm, based on the OJOC-Keyhack) unscrambles and XORs it. 

This script was developed and tested with IDA 7.0 but should also work on other versions.

### Requirements
- IDA installed on your PC (with Python support)
- Any version of the Jodel APK

### How to use
- Clone this repo
- Fire up IDA
- Feed it with the latest libhmac.so (x86) (Isnt named libhmac.so anymore, just try the smallest x86 lib, as of today aroud 200kb) from the Jodel.apk
- Wait for the analysis to finish
- Hit <kbd>ALT</kbd>+<kbd>F7</kbd> or choose File -> Script File
- Choose the script and let it run
- Output should be printed in IDA console

