# Android account validation (by mail)

- Validation is performed using E-Mail address
- Process used is [Google Firebase Authentication using E-Mail links](https://firebase.google.com/docs/auth/android/email-link-auth)

### Step 1: Requesting login

- Request login using Firebase

```HTTP
POST /identitytoolkit/v3/relyingparty/getOobConfirmationCode?key=AIzaSyDFUC30aJbUREs-vKefE6QmvoVL0qqOv60 HTTP/2
Host: www.googleapis.com
Content-Type: application/json
X-Android-Package: com.tellm.android.app
X-Android-Cert: A4A8D4D7B09736A0F65596A868CC6FD620920FB0
Accept-Language: en-US
X-Client-Version: Android/Fallback/X21000001/FirebaseCore-Android
Content-Length: 236
Connection: Keep-Alive
Accept-Encoding: gzip, deflate

{
    "requestType": 6,
    "email": "<your@mail.here>",
    "androidInstallApp": true,
    "canHandleCodeInApp": true,
    "continueUrl": "https:\/\/jodel.com\/app\/magic-link-fallback",
    "androidPackageName": "com.tellm.android.app",
    "androidMinimumVersion": "5.116.0"
}
```

- Response simply contains confirmation of success

```
HTTP/2 200 OK
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: Mon, 01 Jan 1990 00:00:00 GMT
Content-Type: application/json; charset=UTF-8
Vary: Origin
Vary: X-Origin
Vary: Referer
Server: ESF
Content-Length: 94
X-Xss-Protection: 0
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff

{
  "kind": "identitytoolkit#GetOobConfirmationCodeResponse",
  "email": "<your@mail.here>"
}
```

### Step 1½: Extracting oobCode from link

- The mail sent to the target address contains the "magic" link
- The link itself already contains the required oobCode (out-of-band code)

```
https://ae3ts.app.goo.gl/?link=https://tellm-android.firebaseapp.com/__/auth/action?apiKey%3DAIzaSyBC5AfciIsT15NSwrfhLhsLG5UtFisbeSA%26mode%3DsignIn%26oobCode%3DXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX%26continueUrl%3Dhttps://jodel.com/app/magic-link-fallback%26lang%3Den&apn=com.tellm.android.app&amv=5.116.0
=> URL Decode
https://ae3ts.app.goo.gl/?link=https://tellm-android.firebaseapp.com/__/auth/action?apiKey=AIzaSyBC5AfciIsT15NSwrfhLhsLG5UtFisbeSA&mode=signIn&oobCode=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX&continueUrl=https://jodel.com/app/magic-link-fallback&lang=en&apn=com.tellm.android.app&amv=5.116.0
=> extract URL parameter
oobCode=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Step 2: Redeeming oobCode

- The code needs to be redeemed with the corresponding mail address
- Creates a new Jodel Firebase user 

```
POST /identitytoolkit/v3/relyingparty/emailLinkSignin?key=AIzaSyDFUC30aJbUREs-vKefE6QmvoVL0qqOv60 HTTP/2
Host: www.googleapis.com
Content-Type: application/json
X-Android-Package: com.tellm.android.app
X-Android-Cert: A4A8D4D7B09736A0F65596A868CC6FD620920FB0
Accept-Language: en-US
X-Client-Version: Android/Fallback/X21000001/FirebaseCore-Android
Content-Length: 95
Connection: Keep-Alive
Accept-Encoding: gzip, deflate

{
    "email": "<your@mail.here>",
    "oobCode": "<oobCode>"
}
```

- Response contains `idToken` as well as `refreshToken`
- Maybe the `idToken` can already be used to register a Jodel user and save us the token refresh?

```
HTTP/2 200 OK
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Expires: Mon, 01 Jan 1990 00:00:00 GMT
Pragma: no-cache
Content-Type: application/json; charset=UTF-8
Vary: Origin
Vary: X-Origin
Vary: Referer
Server: ESF
Content-Length: 1351
X-Xss-Protection: 0
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff

{
  "kind": "identitytoolkit#EmailLinkSigninResponse",
  "idToken": "<idToken>",
  "email": "<your@mail.here>",
  "refreshToken": "<refreshToken>",
  "expiresIn": "3600",
  "localId": "<localId>",
  "isNewUser": false
}
```

### Step 3: Refreshing tokens

- Not sure whether this step is neccessary
- Token refresh is performed using the `refreshToken` provided in the previous response

```
POST /v1/token?key=AIzaSyDFUC30aJbUREs-vKefE6QmvoVL0qqOv60 HTTP/2
Host: securetoken.googleapis.com
Content-Type: application/json
X-Android-Package: com.tellm.android.app
X-Android-Cert: A4A8D4D7B09736A0F65596A868CC6FD620920FB0
Accept-Language: en-US
X-Client-Version: Android/Fallback/X21000001/FirebaseCore-Android
Content-Length: 273
Connection: Keep-Alive
Accept-Encoding: gzip, deflate

{
    "grantType": "refresh_token",
    "refreshToken": "<refreshToken>"
}
```

- Response contains `access_token` and `id_token` which happened to be identical
- `refresh_token` can be used to get fresh access tokens for the Firebase user

```
HTTP/2 200 OK
Pragma: no-cache
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Expires: Mon, 01 Jan 1990 00:00:00 GMT
Content-Type: application/json; charset=UTF-8
Vary: Origin
Vary: X-Origin
Vary: Referer
Server: ESF
Content-Length: 2237
X-Xss-Protection: 0
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff

{
  "access_token": "<firebaseJWT>",
  "expires_in": "3600",
  "token_type": "Bearer",
  "refresh_token": "<refreshToken>",
  "id_token": "<firebaseJWT>",
  "user_id": "<userId>",
  "project_id": "425112442765"
}
```

### Step 4: Creating account using firebaseJWT

- Account is created using a `device_uid` as well as the `firebaseJWT` (`access_token` or `id_token` from previous response)
- Request requires HMAC signing


```
POST /api/v2/users/ HTTP/1.1
Host: api.jodelapis.com
X-Client-Type: android_x.x.x
X-Api-Version: 0.2
X-Timestamp: 2022-XX-XXTXX:XX:XXZ
X-Authorization: HMAC 8DECAECD87546C899E6F8865AF3D61DA7F99D6C6
Content-Type: application/json; charset=UTF-8
Content-Length: 1711
Accept-Encoding: gzip, deflate
Connection: close

{
    "firebase_uid": "jtNECbcwmfPGgQVuyKVPpsW8UIE3", // not sure whether neccesary
    "device_uid": "<deviceUid>", // can probably be random
    "firebaseJWT": "<firebaseJWT>", // from previous request
    "client_id": "81e8a76e-1e02-4d17-9ba0-8a7020261b26",
    "iid": "", // installation id, should be ok if omitted
    "iid_provider": "google",
    "location": {
        "city": "Town",
        "country": "DE",
        "loc_coordinates": {
            "lat": <lat>,
            "lng": <lng>
        },
        "loc_accuracy": <acc>
    },
    "language": "en-US",
    "registration_data": {
        "provider": "branch.io",
        "channel": "",
        "campaign": "",
        "feature": "",
        "referrer_id": "",
        "referrer_branch_id": ""
    },
    "registration_type": "signup",
    "adId": "",
    "dId": ""
}
```

- Response indicates successful user registration
- User is **NOT** blocked
- `access_` and `refresh_token` can be used for further API requests as usual

```
HTTP/1.1 200 OK
Server: nginx/1.13.12 (this version is from 2018 with HIGH CVEs (CVE-2021-23017)??? might consider patching...)
Content-Type: application/json; charset=utf-8
Connection: close
Vary: Accept-Encoding
Vary: X-HTTP-Method-Override
Access-Control-Allow-Origin: *
X-User-Blocked: false
X-Feed-Internationalizable: false
X-Feed-Internationalized: false
Content-Length: 2080

{
    "access_token": "...",
    "refresh_token": "...",
    "token_type": "bearer",
    "expires_in": 604800,
    [...]
```
