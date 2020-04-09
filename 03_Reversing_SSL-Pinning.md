### Bypass SSL-Pinning
This script is for use with [frida](https://frida.re/). As Jodel is heavily obfuscated, hooking the Jodels enableSslPinning method is nearly impossible. 
But: Jodel is using the `okhttp3.CertificatePinner$Pin` which utilizes `okio.ByteString#equals` to compare the certificates. By letting `equals` always return `true`, any ServerCertificate, provided by you will get accepted. 

```
import frida, sys, time

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(function () {
	var ByteString = Java.use('okio.ByteString');
	
	ByteString.equals.overload('java.lang.Object').implementation = function(obj) {
		send('SSLPinning bypassed!');
		return true;
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
