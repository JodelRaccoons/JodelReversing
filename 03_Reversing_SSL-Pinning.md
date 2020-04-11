### Bypass SSL-Pinning
This script is for use with [frida](https://frida.re/). As Jodel is heavily obfuscated, bypassing the TLS pinning needs to be done a little different. Method names in the Jodel app are unicode characters which are not directly usable in frida. A possible workaround is shown below. Just copy & paste the unicode character method name of your current Jodel version in the script and run it. This also circumvents certificate validation. 

```
import frida, sys, time

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(function() {
	var ByteString = Java.use('okhttp3.CertificatePinner');

	console.log('OkHTTP 3.x Found');

	ByteString['Ӏ'].overload('java.lang.String', 'java.util.List').implementation = function(b) {
		console.log('OkHTTP 3.x check() called. Not throwing an exception.');
	}
});
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
