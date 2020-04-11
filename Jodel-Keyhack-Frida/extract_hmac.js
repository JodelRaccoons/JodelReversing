Java.perform(function () {
    // Class of the HMAC Implementation 
    var Mac = Java.use('javax.crypto.Mac');
    // Whenever Mac.init(Key key); is called
    Mac.init.overload('java.security.Key').implementation = function (v) {
	
		var bArray = v.getEncoded();
		
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
	
		console.log("HMAC-Key: "+str);
		
		return this.init(v);
    };
});