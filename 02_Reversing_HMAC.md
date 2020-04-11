## How does the HMAC-Signing in Jodel work?

First of all read [this](https://en.wikipedia.org/wiki/HMAC)! It's important to understand what HMAC is used for in order to understand what Jodel is doing there.

Each version of the Jodel app has a version-specific HMAC key. It is used to sign requests, the signature is checked by the Jodel API server. HMAC (Keyed-Hash Message Authentication Code) is a mechanism that generates a signature of given data (in our case HTTP request data) in combination with a key. Without knowledge of the HMAC key, it is impossible to sign requests and therefore it is impossible to use the Jodel API.

### Locating the HMAC signing library

Since the HMAC key is an important measure to prevent attacks on the Jodel API, the HMAC key is well hidden in the application. Jodel follows best practices (see MASVS) and hides the key in a shared library bundled with the APK file. The name of the shared library responsible for generating the HMAC key is renamed in each build (<apk>/lib/\<arch\>/libX.so), determining which is the correct one is only possible based on file sizes:

|  architecture 	|   approx. size	|
|---	|---	|
|  x86 	|  194 KB 	|
|   x86-64	|  219 KB 	|
|   armeabi-v7a	|   102 KB	|
|   arm64-v8a	|   199 KB	|

(as of 09.04.2020, Jodel version 5.77.0, libb.so)

### What's inside
The signing inside the Jodel application works as follows:
	
The class `com.jodelapp.jodelandroidv3.api.HmacInterceptor` is used for signing the requests. It has three methods which calls the shared library using the Java native interface:
```
- private native void init();
- private native synchronized void register(String str);
- private native synchronized byte[] sign(String str, String str2, byte[] bArr);
```

### The shared library
Method names in the shared library are (as of v. 5.77.0) generated during runtime. Therefore a static analysis  using tools like IDA does not reveal the method names. Looking at older versions of the Jodel app shows the following methods:

##### private native void init();
This method calls the native method `sym.Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_init` in the corresponding shared object. The native method generates the HMAC-Key at runtime.

Reading the assembler code (of the x86 binary) looks similar to this:
```
<snip>
mov byte [eax + 0x198], 0x95
mov dword [eax + 0x194], 0x9f8effc2
mov byte [eax + 0x19d], 4
mov dword [eax + 0x199], 0x8c0dd9e9
<snip>
```

Thinking of `eax` as the address of a bytearray, the assembler code just initializes a byte array with given values. The values can be considered the _"encrypted"_  (XORed with the applications signature) key.

##### private native synchronized void register(String str);
This method calls the native method  `sym.Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_register`. It takes one string parameter which describes what kind of request is going to be signed in one of the next `sign()` calls. These strings look like the following example:

```
GET@/api/v3/user/config
```

This could be the implementation of a queue. A signing request is passed and queued in a std::map<string,int>. The signing routine uses the values of the map to locate the signing request.

#### private native synchronized byte[] sign(String sig, String method, byte[] payload);
The `sign()` method of the HmacInterceptor class performs the signing itself. It calls the native method  `sym.Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_sign`. It takes three arguments:
```
sig: The APKs SHA1 signature: a4a8d4d7b09736a0f65596a868cc6fd620920fb0 (should be always this value!)
method: Same string which gets called to register(String str): GET@/api/v3/user/recommendedChannels
payload: GET%api.go-tellm.com%443%/api/v3/posts/location/combo%39422506-d25adbe9-4c85ef1a-1dca-4771-abd7-249e4eb16047%49.6679;9.9074%2019-01-12T12:03:32Z%channels%true%home%false%lat%49.667938232421875%lng%9.907393455505371%radius%true%skipHometown%false%stickies%true%
```


The pseudo code of the `sign()` function looks like this:

```
int Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_sign(JNIEnv *env, jobject jobj, char *sig_1, char *key_in_map, char *hmac_input) {
	secretKey = signature ^ xor_key; //a little more complicated, see the decryption routine
	
	// this Java calls are done from the shared library, this is only the Java part of it
	SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
	Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
	mac.init(signingKey);
	return toHexString(mac.doFinal(data.getBytes()));
}
```

---

### Extracting the HMAC-Key
There are multiple methods extracting the HMAC key:

#### Good old static way
	- Extracting the hmac-key the static way requires the hmac-signing library (as the base key is in there) and some decryption magic. There are several projects doing this, some of them work, some dont. The ones i'm aware of are: 
		- [ojoc-keyhack by cfib90](https://bitbucket.org/cfib90/ojoc-keyhack) (the original one, utilizing objdump)
		- [Jodel-Keyhack-v2](https://github.com/Unbrick/Jodel-Keyhack-v2) utilizing IDA Pro 7.x
		- [Jodel-Keyhack-v3](https://github.com/Unbrick/Jodel-Keyhack-v3) this project, utilizing radare2
- Dynamic (runtime hooking ftw!)
	- As the native library is NOT implementing their own HMAC-Signing function, they are using the one javax.crypto classes. Hooking them using librarys like frida is [pretty easy](https://gist.github.com/Unbrick/c7151e44c4abf37cc0a6bc9d850b6a4a) (See comment for instructions)

---


As of that, i wrote a python script which disassembles the shared object, collects the bytes and decrypts it (credits for the decryption magic to [cfib90](https://bitbucket.org/cfib90/ojoc-keyhack)). To make it look better i developed this keyhack with fancy angular gui.

---


## How to get the key
- lokalisieren der funktionen
  - Funktionsnamen sind obfuskiert
  - string suche nach (Ljava/lang/String;)Ljavax/crypto/Mac;
  - xrefs auf (Ljava/lang/String;)Ljavax/crypto/Mac; finden, funktion ist sign()
  - funktionslayout ist init, register, sign -> zwei funktionen weiter oben ist init() mit dem hmac key
- Statische analyse und mir skript entschlüsseln
  - Link zu skript
- Native library weist 
  - Java funktion für HMAC wird aufgerufen
  - Frida-Skript auf gist.github.com
