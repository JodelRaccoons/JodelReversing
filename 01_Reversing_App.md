## Analysis of the application

### The APK-File
Only a few details here:
- The app is most probably obfuscated using [DexGuard](https://www.guardsquare.com/en/products/dexguard)
- Ressource names are scrambled and in raw apk (not packed in asrc file)
    - Filenames are in non-ASCII characters
    - Extracting the APK under windows os will result in errors as windows makes no difference between unicode 
    spaces like `U+0020` (Unicode space) and `U+00A0` (Unicode non-breaking space) and so on. This results in filename collisions and owerwriting of files.
    - Resource ids were mostly stripped out of the xml file, no chance of recovering them
- The application itself (smali code) is obfuscated using dexguard. This includes:
    - Heavy control-flow obfuscation by stub math operations
    - Heavy method name obfuscation, method names are not human readable anymore, mostly special characters or weired white-spaces

### Unpacking / Repacking
- Unpacking / repacking should work using latest version of [apktool](https://ibotpeaches.github.io/Apktool/) under linux-based OS
- Simply re-signing the APK will result in a [HMAC signature error](#HMAC-signature-error). This is caused by a invalid signature used by the libhmac.so to decrypt the HMAC-Key (see the HMAC-reversing). A possible workaroud is implementing the HMAC-routine on your own [like in JodelPatched](https://github.com/JodelRaccoons/JodelPatched/blob/master/patched/src/main/java/com/jodelapp/jodelandroidv3/api/HmacInterceptor.java). Process would be as follows:
    1. Compile or grab 'latest' JodelPatched apk
    2. Decompile the JodelPatched apk to smali code
    3. Extract the classes*.dex from the original Jodel APK 
    4. Convert it to smali using latest [baksmali](https://bitbucket.org/JesusFreke/smali/downloads/) (Steps 3 and 4 are to circumvent problems with the scrambled ressources)
    5. Edit HmacInterceptor.smali by copy&pasting the modified methods from the decompiled JodelPatched apk. Double check syntax and registers used to avoid complications with the smalivm.
    6. Recompile dex with [smali](https://bitbucket.org/JesusFreke/smali/downloads/), pack into apk, sign with [dex2jar-apk-sign.sh](https://github.com/pxb1988/dex2jar) and install on device
    7. If you did all correct: profit!!!

##### HMAC signature error
```
com.tellm.android.app A/art: art/runtime/java_vm_ext.cc:410] JNI DETECTED ERROR IN APPLICATION: input is not valid Modified UTF-8: illegal start byte 0x8e
com.tellm.android.app A/art: art/runtime/java_vm_ext.cc:410]     string: '��M�L�n�@�}[
com.tellm.android.app A/art: art/runtime/java_vm_ext.cc:410] )Ί;0=�m��H|�c`}��'
com.tellm.android.app A/art: art/runtime/java_vm_ext.cc:410]     in call to NewStringUTF
com.tellm.android.app A/art: art/runtime/java_vm_ext.cc:410]     from byte[] com.jodelapp.jodelandroidv3.api.HmacInterceptor.sign(java.lang.String, java.lang.String, byte[])
```
    
