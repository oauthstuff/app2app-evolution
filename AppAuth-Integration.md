# AppAuth Integration

To easily implement the mechanics that are 
described in the ``app2app-evolution`` document
we propose two new functions for the [AppAuth-Android](https://github.com/openid/AppAuth-Android)
library: One to redirect the user from the RP to the 
IDP and one method to redirect the user from the IDP
back to the RP. The only parameter these functions
need to securely redirect the user is a URI.

## Requirements

1. Configure the ``/.well-known/assetlinks.json`` file for [Android App Links](https://developer.android.com/training/app-links/verify-site-associations). 
    Example:

    1. RP domain:
        ```json
        [{
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "com.example.relyingparty",
                "sha256_cert_fingerprints":
                ["4F:69:88:01:42:FE:D7:0B:26:1C:00:E3:3E:2A:02:DA:B8:E0:20:75:51:4C:30:14:D5:DE:C3:BE:65:E4:62:88"]
        }
        }]
        ```
    2. IDP domain:
        ```json
        [{
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {
                "namespace": "android_app",
                "package_name": "com.example.openidprovider",
                "sha256_cert_fingerprints":
                ["F4:C4:24:1F:2C:64:99:A0:22:55:B6:89:26:3E:86:8C:05:93:9A:18:7A:60:A4:A9:DC:1E:59:39:83:DB:17:0D"]
            }
        }]
        ```

    This file can easily be generated with the ``App Links Assistant``
    in Android Studio (``Tools | App Links Assistant | Open Digital Asset 
    Links File Generator | Generate Digital Asset Links file``)

2. The apps need to register an ``intent-filter`` for their URL
    in their ``AndroidManifest.xml`` file. Example:
    
    1. IDP app: 
        ```xml
        <intent-filter>
            <action android:name="android.intent.action.VIEW" />

            <category android:name="android.intent.category.DEFAULT" />
            <category android:name="android.intent.category.BROWSABLE" />

            <data
                android:host="openidprovider.intranet"
                android:scheme="http"
                android:path="/c2id-login" />
        </intent-filter>
    2. RP app:
        ```xml
        <intent-filter>
            <action android:name="android.intent.action.VIEW" />

            <category android:name="android.intent.category.DEFAULT" />
            <category android:name="android.intent.category.BROWSABLE" />

            <data
                android:scheme="http"
                android:host="relyingparty.intranet"
                android:pathPattern="/complete" />
        </intent-filter>
        ```

3. On Android 11 and later the apps need to register
    which Intents they want to use in their ``AndroidManifest.xml`` file
    ([Package visibility in Android 11](https://developer.android.com/preview/privacy/package-visibility)).

    1. RP app:
        ```xml
        <queries>
            <intent>
                <action android:name="android.intent.action.VIEW" />

                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />

                <data
                    android:scheme="http"
                    android:host="openidprovider.intranet" />
            </intent>
        </queries>
        ```
    2. IDP app:
        ```xml
        <queries>
            <intent>
                <action android:name="android.intent.action.VIEW" />

                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />

                <data
                    android:scheme="http"
                    android:host="relyingparty.intranet" />
            </intent>
        </queries>
        ```

## API Usage

If the apps and the domain fulfill the requirements, you can
securely redirect from one app to another app or the browser 
if the app is not installed, with the following code:
```kotlin
import com.example.redirection.secureRedirection

// Example redirection from RP to IDP
val uri = Uri.parse("http://openidprovider.intranet/c2id-login")
secureRedirection(this, uri)
```

**Note:** If the ``/.well-known/assetlinks.json`` file is not
available for the target domain, this function will
automatically redirect the user to his default browser.
