
# Jodel Keyhack v2

Tested with IDA 7.0 and Jodel 5.77.0

### What this is
This is just a small IDA script, extracting the HMAC key from the library and decoding it as [cfib90s](https://bitbucket.org/cfib90/) script was broken for me.

The approach of this script is scraping the bare `mov` instructions, stripping the key from them and unscrambling it. 
As the key is somehow XORed with a scrambled version of the APKs signature the decrypt.py (ported by tm, based on the OJOC-Keyhack) unscrambles and XORs it. 

This script was developed and tested with IDA 7.0 but should also work on other versions.

### Requirements
- IDA Pro version 7.0 or higher
- Any version of the Jodel APK
- **Installed idascript**
  - Clone the repo https://github.com/devttys0/idascript
  - `PS (Administrator) C:\Windows\system32> C:\Python27\python.exe .\install.py`
  - Follow the install script (enter absolute IDA path e.g. C:\Program Files\IDA 7.0)

### How to use
- Clone this repo or download the `jodel.py` and `decrypt.py`
- Fire up IDA 7.0 or later **(with installed idascript)**
- Feed it with the latest libhmac.so (x86)
  - Open the APK with 7-Zip or simmilar
  - Extract the file /lib/x86/libX.so where X is a random lowercase character
  - The correct library file is around 200 kb
- Wait for the initial IDA analysis to finish
- Hit <kbd>ALT</kbd>+<kbd>F7</kbd> or choose `File -> Script File`
- A file explorer should open, choose the `jodel.py` file
- The IDA console should display the extracted HMAC key

