## How does the HMAC-Signing in Jodel work?
First of all read [this](https://en.wikipedia.org/wiki/HMAC)! It's important to understand what HMAC is used for in order to understand what Jodel is doing there.

Each version of the Jodel app has a version-specific HMAC key. It is used to sign requests, the signature is checked by the Jodel API server. HMAC (Keyed-Hash Message Authentication Code) is a mechanism that generates a signature of given data (in our case HTTP request data) in combination with a key. Without knowledge of the HMAC key, it is impossible to sign requests and therefore it is impossible to use the Jodel API.

Since the HMAC key is an important measure to prevent attacks on the Jodel API, the HMAC key is well hidden in the application. Jodel follows best practices (see MASVS) and hides the key in a shared library bundled with the APK file. The name of the shared library responsible for generating the HMAC key is renamed in each build (<apk>/lib/<arch>/libX.so), determining which is the correct one is only possible based on file sizes:

|  architecture 	|   size	|
|---	|---	|
|  x86 	|  194 KB 	|
|   x86-64	|  219 KB 	|
|   Arm	|   102 KB	|
|   Arm64	|   199 KB	|

(as of 09.04.2020, Jodel version 5.77.0, libb.so)

The signing inside the jodel application works as follows:
	
The class `com.jodelapp.jodelandroidv3.api.HmacInterceptor` is responsible for the signing. It has three methods which refer to JNI:
```
- private native void init();
- private native synchronized void register(String str);
- private native synchronized byte[] sign(String str, String str2, byte[] bArr);
```

---

### Extracting the HMAC-Key
There are multiple methods extracting the hmac-key:
- Good old static way
	- Extracting the hmac-key the static way requires the hmac-signing library (as the base key is in there) and some decryption magic. There are several projects doing this, some of them work, some dont. The ones i'm aware of are: 
		- [ojoc-keyhack by cfib90](https://bitbucket.org/cfib90/ojoc-keyhack) (the original one, utilizing objdump)
		- [Jodel-Keyhack-v2](https://github.com/Unbrick/Jodel-Keyhack-v2) utilizing IDA Pro 7.x
		- [Jodel-Keyhack-v3](https://github.com/Unbrick/Jodel-Keyhack-v3) this project, utilizing radare2
- Dynamic (runtime hooking ftw!)
	- As the native library is NOT implementing their own HMAC-Signing function, they are using the one javax.crypto classes. Hooking them using librarys like frida is [pretty easy](https://gist.github.com/Unbrick/c7151e44c4abf37cc0a6bc9d850b6a4a) (See comment for instructions)

---

#### private native void init();
This method generates the HMAC-Key in ram. It refers to `sym.Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_init` in the corresponding shared object.

Reading the assembler code (of the x86 binary) looks like this:
```
<snip>
mov byte [eax + 0x198], 0x95
mov dword [eax + 0x194], 0x9f8effc2
mov byte [eax + 0x19d], 4
mov dword [eax + 0x199], 0x8c0dd9e9
<snip>
```

Thinking of `eax` as the start of a byte[], the assembler code just fills a byte array.

#### private native synchronized void register(String str);
This method refers to `sym.Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_register`. It takes one String parameter which describes what kind of request is going to be signed. For instance:
```
GET@/api/v3/user/config
```

Seems like this realizes some kind of a queue. A signing request is coming in and getting queued in a std::map<string,int>. The sign routine uses the values of the map to locate the signing request. Pseudocode of the register-function looks like this:

```
void Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_register(JNIEnv env, jobject jobj, char *reg)
{
    char *reg_utf;
    int *index_in_map;
    std::map<std::string, int> queue = (std::map<std::string,int>) &dword_xxxx;

    reg_utf = env->GetStringUTFChars(env, reg);
    index_in_map = queue[reg_utf];
    ++*index_in_map;
    env->ReleaseStringUTFChars(env, reg);
    //do some deallocation
}
```

#### private native synchronized byte[] sign(String sig, String method, byte[] payload);
Sign refers to `sym.Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_sign`. It takes three arguments:
```
sig: The APKs SHA1 signature: a4a8d4d7b09736a0f65596a868cc6fd620920fb0 (should be always this value!)
method: Same string which gets called to register(String str): GET@/api/v3/user/recommendedChannels
payload: GET%api.go-tellm.com%443%/api/v3/posts/location/combo%39422506-d25adbe9-4c85ef1a-1dca-4771-abd7-249e4eb16047%49.6679;9.9074%2019-01-12T12:03:32Z%channels%true%home%false%lat%49.667938232421875%lng%9.907393455505371%radius%true%skipHometown%false%stickies%true%
```


The pseudocode of this function looks like this:

```
int Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_sign(JNIEnv *env, jobject jobj, char *sig_1, char *key_in_map, char *hmac_input){
	secretKey = signature ^ xor_key; //a little more complicated but basically this
	
	//do java calls from C, java code would look like this
	SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
	Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
	mac.init(signingKey);
	return toHexString(mac.doFinal(data.getBytes()));
}
```

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
