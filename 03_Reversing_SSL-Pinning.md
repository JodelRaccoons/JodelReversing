## Bypass SSL-Pinning
In the following, bypassing SSL/TLS-Pinning within the Jodel app is described.

### Android
This script is for use with [frida](https://frida.re/). As Jodel is heavily obfuscated, bypassing the TLS pinning needs to be done a little different. Method names in the Jodel app are unicode characters which are not directly usable in frida. A possible workaround is shown below. Just copy & paste the unicode character method name of your current Jodel version in the script and run it. This also circumvents certificate validation. 

Due to the obfuscation, finding the correct class and method is not always easy. Therefore you might want to try to search for the strings contained in the method, e.g. `unsupported hashAlgorithm: ` (see [here](https://github.com/square/okhttp/blob/3ad1912f783e108b3d0ad2c4a5b1b89b827e4db9/okhttp/src/jvmMain/kotlin/okhttp3/CertificatePinner.kt#L177)). Just check the source file for more strings if something changes over time. 

The method can be easily identified as it is the only method accepting a `String` and `Function0` (Kotlin) as parameters.

```
import frida, sys, time

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(function () {
    let b = Java.use("okhttp3.b");
    b["b"].overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function (str, function0) {
        console.log('OkHTTP 3.x check() called. Not throwing an exception.');
    };
})
"""

pid = frida.get_usb_device().spawn('com.tellm.android.app')
frida.get_usb_device().resume(pid)
#time.sleep(1) #Without it Java.perform silently fails
session = frida.get_usb_device().attach(pid)
script = session.create_script(jscode)
script.on('message', on_message)
print('Running...')
script.load()
sys.stdin.read()
```

Keep in mind that Android version 7 and above only accepts certificates installed in the system CA store (and ignores the one installed by the user). To circumvent this restriction patching the NetworkSecurityConfig is one possibility, another is utilizing [this Magisk module](https://github.com/NVISO-BE/MagiskTrustUserCerts) to move user certificates to the system store. 

### iOS
For iOS, TLS pinning is done by using the respecitve system APIs. Multiple Cydia packages exist to circumvent such pinning mechanisms. The package [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2) should do the trick here.

Alternatively you can use the [objection](https://github.com/sensepost/objection) frameworks command `ios sslpinning disable` which should have the same effect.
