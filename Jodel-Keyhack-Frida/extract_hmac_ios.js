Interceptor.attach(ObjC.classes.JDLAPIRequestHMACHashBuilder['- secretKey'].implementation, {
  onLeave: function (retval) {
    console.log('[+] HMAC-Key: ', new ObjC.Object(ptr(retval)).toString());
    console.log('[+] Version: ' + ObjC.classes.NSBundle.mainBundle().objectForInfoDictionaryKey_("CFBundleShortVersionString").UTF8String())
  },
});
