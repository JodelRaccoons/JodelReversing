import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
const DEBUG = false;

function stringFromByteArray(bArray) {
    const extraByteMap = [ 1, 1, 1, 1, 2, 2, 3, 0 ];
		var count = bArray.length;
		var str = "";
		
		for (var index = 0;index < count;)
		{
		  var ch = bArray[index++];
		  if (ch & 0x80)
		  {
			var extra = extraByteMap[(ch >> 3) & 0x07];
			if (!(ch & 0x40) || !extra || ((index + extra) > count))
			  return null;
			
			ch = ch & (0x3F >> extra);
			for (;extra > 0;extra -= 1)
			{
			  var chx = bArray[index++];
			  if ((chx & 0xC0) != 0x80)
				return null;
			  
			  ch = (ch << 6) | (chx & 0x3F);
			}
		  }
		  
		  str += String.fromCharCode(ch);
		}
        return str;
}

Java.perform(function () {

    var alreadyPrinted = false;

    Java.use('com.jodelapp.jodelandroidv3.JodelApp').onCreate.overload().implementation = function() {
        this.onCreate();
        console.log("Version: " + this.getPackageManager().getPackageInfo(this.getPackageName(), 0).versionName.value);
    }

    Java.use('javax.crypto.Mac').init.overload('java.security.Key').implementation = function (v) {
		if (!alreadyPrinted) {
            console.log("HMAC-Key: " + stringFromByteArray(v.getEncoded()));
            alreadyPrinted = true;
        }
		
		return this.init(v);
    };

    if (DEBUG)
        Java.use('javax.crypto.Mac').doFinal.overload('[B').implementation = function(toBeHmaced) {
            console.log("To be HMACed: " + stringFromByteArray(toBeHmaced));
            return this.doFinal(toBeHmaced);
        }
});
"""

try:
    device = frida.get_usb_device()
    pid = device.spawn(['com.tellm.android.app'])
    session = device.attach(pid)
    script = session.create_script(jscode)
    script.on('message', on_message)
    device.resume(pid)
    script.load()
    sys.stdin.read()
except Exception as e:
    print(e)
