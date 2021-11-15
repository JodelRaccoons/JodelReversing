# Jodel Keyhack using Frida

##### Requirements: 

- python
- pip
- adb
- root on Android device
- SELinux permissive kernel!

##### Download and references
[Frida for Android reference](https://www.frida.re/docs/android/)
[frida-server releases](https://github.com/frida/frida/releases)
- Download frida-server-[latest]-android-[arch_of_your_phone].xz and unpack

##### Bring it to work:
```
pip install frida frida-tools
adb push frida-server-[latest]-android-[arch_of_your_phone] /data/local/tmp/ 
adb shell
        cd /data/local/tmp
        su
        chmod +x frida-server-[latest]-android-[arch_of_your_phone]
        ./frida-server-[latest]-android-[arch_of_your_phone] &  

```

#### Run it
To begin, start Jodel on your Android device. Afterwards start the python script:

```bash
$ python extract_hmac.py
Version: 7.25.8
HMAC-Key: mNnKgrObHerZMdpPffBMbKvYZxNDpQYGDWzzsyjH
```

Or run the javascript file directly with frida:

```bash
frida -U -l extract_hmac.js -f com.tellm.android.app --no-pause
     ____
    / _  |   Frida 15.0.8 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
Spawned `com.tellm.android.app`. Resuming main thread!
[Pixel::com.tellm.android.app]->
Version: 7.25.8
HMAC-Key: mNnKgrObHerZMdpPffBMbKvYZxNDpQYGDWzzsyjH
```

