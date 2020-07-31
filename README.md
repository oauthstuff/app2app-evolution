# app2app-evolution

OAuth flows on mobile devices can benefit a lot from native apps.
With native apps, for example, it is possible to use already existing 
sessions and biometric authentication features. While apps improve
the user experience they also bring new security challenges to 
OAuth. This document describes the challenge of app2app, app2web
and web2app redirection on Android and iOS.

## Problem Formulation

On mobile OSs contrary to a browser we cannot simply use a URL
to redirect the user to the OpenID Provider (IDP).
Android, for example, permit's arbitrary apps to claim that they
handle a specific domain. Although it is possible to verify a 
domain-app association ([Android App Link](https://developer.android.com/training/app-links)) 
this does not help if the app is not installed on
the device. In case the IDP app is not installed the user would
have to choose from a menu with which app he wants to open the URL.

<img src="images/app_chooser_dialog.png" width=300px/>

As we can see in the picture a malicious OpenID Provider app also
claims to handle the domain. In this case, the user could choose the
malicious app instead of the browser. 

Another problem on Android is the redirection back from the browser 
to the Relying Party app. If the RP app uses an Android
App Link and the user was redirected to the Chrome browser, the user
can be sent back to the app by simply being redirected to the Android
App Link. However, this does not work in every other browser. To be
browser independent it is necessary to use a custom URL scheme.
But this implicates that arbitrary apps can register themselves
to handle this custom scheme which makes it susceptible to redirect
hijacking.

On iOS the situation is different. There, an app can only claim to
handle an http:// scheme URL if it can verify an association with the domain ([Universal Links](https://developer.apple.com/ios/universal-links/)).
Custom schemes, again, can be claimed by every app but the OS will
not display a selection menu. Instead, it launches the app that
claimed the scheme for the first time.

## Attacker Model

This is a short summary of the attacker model which is by no 
means comprehensive.

The attacker has the following capabilities:

- can install apps that register the same custom scheme as an honest
app
- cannot install apps that verify an app association with a domain 
he does not own
- cannot manipulate the operating system


On Android:
- cannot install apps through the Play Store with the same 
applicationID as an honest app in the Play Store
- can install apps with the same applicationID as an honest 
app through a third-party app store
- cannot sign an APK with a certificate he does not own

## Goals

1. If the required app is installed on the device,
the app should always be opened. 

2. If the required app is
not installed, the website of the app owner should be opened
inside the user's default browser.

3. The user should never have to choose between multiple apps
   (dialog can be seen in the picture above).

## Solution on iOS
On iOS, we can use Universal Links to redirect the user from one
app to another. The good thing hereby is that we can set a flag
called: ``.universalLinksOnly: true``. This will only redirect
the user if the app that handles this link is installed.

```Swift
// if bank’s app is present & supports app2app, open it
UIApplication.shared.open(authorizationEndpointUrl, options: [.universalLinksOnly: true]) { (success) in
    if !success {
    // launching bank app failed: app does not support universal links or
    // bank’s app is not installed – open an in app browser tab instead
    <…continue as app did before app2app…>
}
```
Source: [Blog post by Joseph Heenan](https://openid.net/2019/10/21/guest-blog-implementing-app-to-app-authorisation-in-oauth2-openid-connect/)

In case the app is not installed we can launch an
[ASWebAuthenticationSession](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession)
that opens an in-app browser session powered by Safari.
Hereby it is possible to use existing session cookies from the
Safari browser. To redirect back to the app, the app specifies a
custom scheme before launching the browser. If the browser is 
redirected to the custom scheme the browser will exit and give
the URL back to the app.

## App2App and App2Web Solutions on Android

1. Open app via HTTPS link
   ```kotlin
    val uri =  Uri.parse("https://app2app.unsicher.ovh?request_uri=Hello_World")

    val browserIntent = Intent(Intent.ACTION_VIEW, uri)
    startActivity(browserIntent)
   ```
   If the app of the domain owner is installed and supports
   [Android App Links](https://developer.android.com/training/app-links) 
   the right app will always be opened. If the domain owner
   app is not installed, the OS will display an app chooser
   dialog (can be seen in the picture above). Since every
   app can claim to handle the domain name, the user could
   choose an app from an attacker.

2. Open the web browser with an intent that has the category *CATEGORY_APP_BROWSER* set
   ```kotlin
   val uri =  Uri.parse("https://app2app.unsicher.ovh?request_uri=Hello_World")

   val browserIntent = Intent.makeMainSelectorActivity(Intent.ACTION_MAIN, Intent.CATEGORY_APP_BROWSER)
   browserIntent.data = uri
   startActivity(browserIntent)
   ```
   This code forces the OS to open the link inside a web browser
   and not in an app that just claims to open this domain name.
   If the user has multiple browsers installed he still has to
   choose between them.

3. Use Custom Chrome Tabs
   ```kotlin
   val uri =  Uri.parse("https://app2app.unsicher.ovh?request_uri=Hello_World")

   val builder = CustomTabsIntent.Builder()
   val customTabsIntent = builder.build()
   customTabsIntent.launchUrl(this, uri)
   ```
   This code opens a [Custom Chrome Tab](https://developer.chrome.com/multidevice/android/customtabs). 
   The problem hereby is that if the user does not 
   have a default browser (unlikely) he has to choose
   between all installed browsers. Additionally, if a
   malicious app is installed the user has to 
   choose between this app and the browser. It is a
   similar problem as in solution 1. 
   
   But the good thing is that if the user chooses a browser 
   that does not support Custom Tabs, the browser application
   will launch.

4. Set default browser as package in the Intent
   ```kotlin
   val uri =  Uri.parse("https://app2app.unsicher.ovh?request_uri=Hello_World")

   val builder = CustomTabsIntent.Builder()
   val customTabsIntent = builder.build()
   val defaultBrowser = getDefaultBrowserPackageName()
   customTabsIntent.intent.setPackage(defaultBrowser)
   customTabsIntent.launchUrl(this, uri)

   private fun getDefaultBrowserPackageName(): String {
   /*
      Source: https://stackoverflow.com/questions/23611548/how-to-find-default-browser-set-on-android-device
   */
      val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("http://"))
      val resolveInfo = packageManager.resolveActivity(browserIntent, PackageManager.MATCH_DEFAULT_ONLY)

      // This is the default browser's packageName
      return resolveInfo!!.activityInfo.packageName
   }
   ```
   To prevent that the user has to choose
   between multiple apps, an intent can be explicitly
   told which package it should use to execute
   the intent. In this example a Chrome Custom
   Tab is initialized and the 
   `getDefaultBrowserPackageName()` method
   checks what the package name of the user's
   default browser is.

   A problem with the Chrome Custom Tabs is that if the
   user clicks on `Open in Chrome` and the OpenID Provider
   app is not installed but a malicious app is installed
   the user has to choose between Chrome and the malicious app.

### Problem with Solution 2 and 4
Solutions 2 and 4 have the problem that they will
open a web browser even if the app of the domain
owner is installed on the device. To open the
app if the app is installed it is necessary to
first check whether the app is installed. The
code for this can be seen below. The app must, of
course, register the domain name as an Android
App Link.
```kotlin
val packageName = "com.example.openidprovider"

if (isAppInstalled(packageName)) {
   // Solution 1 -> will open the installed app because of the Android App Link
} else {
   // Solution 4 -> will open the website in a Chrome Custom Tab with the user's default browser
} 

private fun isAppInstalled(packageName: String): Boolean {
   /*
      Source: https://stackoverflow.com/questions/3922606/detect-an-application-is-installed-or-not
   */
   try {
      packageManager.getPackageInfo(
            packageName,
            PackageManager.GET_ACTIVITIES
      )
      return true
   } catch (e: PackageManager.NameNotFoundException) {
      return false
   }
}
```

**Note:** Since the applicationID of the app
is needed, it would be necessary to include it in
the OpenID Provider's metadata ([RFC 8414](https://tools.ietf.org/html/rfc8414#section-2)) or download it from 
``/.well-known/assetlinks.json``.


### Problem with Android App Links
If an IDP app is responsible for several hundred domains,
the app has to register an Android App Link for every single
domain. If one of these registrations fails none of them would be valid.
Additionally, the IDP app has to download a document from every
single domain. This could be a problem in mobile networks.

To solve this the Relying Party could add the applicationID to the
intent that opens the redirect URL. This would ensure that the 
correct app opens without Android App Links. It is also a good 
solution since we already have the applicationID of the IDP
to check whether the app is installed or not.

```kotlin
val uri =  Uri.parse("https://app2app.unsicher.ovh?request_uri=Hello_World")
val packageName = "com.example.openidprovider"

val redirectIntent = Intent(Intent.ACTION_VIEW, uri)
redirectIntent.setPackage(packageName)
startActivity(redirectIntent)
```

### Problem with Alternative App Stores
Since Android is an open system it is possible to install apps 
from other sources than the Play Store. While it is guaranteed 
that the applicationID of apps from the Play Store is unique this 
does not apply to apps installed from other sources. One possibility
to overcome this security thread is to check the signing certificate
of the app, we want to open. This can be done in the ``isAppInstalled``
method in the following way:

```kotlin
private fun isAppInstalled(packageName: String): Boolean {
   try {
      // Try to query the signing certificates of the
      // IDP app. If the IDP app is not installed this
      // operation will throw an error.
      val signingInfo: SigningInfo = packageManager.getPackageInfo(
         packageName,
         PackageManager.GET_SIGNING_CERTIFICATES
      ).signingInfo
      val signatures: Array<Signature> = signingInfo.signingCertificateHistory

      // calculate the hashes of the signing certificates
      val signatureStrings = generateSignatureHashes(signatures)

      // Compare the hashes with a predefined list of
      // certificate hashes for the app.
      return matchHashes(signatureStrings, IDP_SIGNATURE_HASHES)
   } catch (e: PackageManager.NameNotFoundException) {
      return false
   }
}
```

For this solution, we need besides the applicationID additionally
the hashes of the certificates that were used to sign the APK.
This can be either put into the discovery document or if the
IDP app uses Android App Links the hash can be found in the
``/.well-known/assetlinks.json`` file.


### App2App Backwards Redirection

To redirect back from the OpenID Provider app to the calling
activity in the Relying Party app we can use the method
``startActivityForResult()``. This has two advantages: First
the OpenID Provider app can get the applicationID of the calling
app with ``callingActivity?.packageName`` and second the IDP  app
can redirect to the calling app with the ``setResult()`` method.

Nevertheless, should the IDP app check if the redirect_uri from the AS, the applicationID and the certificate fingerprint of the calling app
matches.

```
domain := getDomain(redirect_uri)
assetLinks := request.get("https://{domain}/.well-known/assetlink.json")

applicationID := callingActivity?.packageName
cert_fingerprints := getCertFingerprint(applicationID)

if (applicationID == assetLinks[0].target.package_name
   && cert_fingerprints == assetLinks[0].target.sha256_cert_fingerprints) {
   // everything fine
} else {
   // something malicious is going on
}
```

### User's Default Browser Selection Considerations
The selection of any browser that the user has set as the default 
browser bears risks for user experience and security. 

**For example:**

**DuckDuckGo and Puffin:** If the browser is redirected to a URL
with a custom scheme that opens another app, the
browser warns the user.

<img src="images/DuckDuckGo_Browser_Redirect_Warning.png" width=300px/>

#### Save Browsers
The following browsers generate the intended 
user experience:

1. **Chrome** (especially Chrome Custom Tabs)
2. **Firefox** (also supports Custom Tabs)
3. **Opera** 

## Web2App Solutions on Android

1. Use Android App Links
   ```html
   <a href="https://app2app.unsicher.ovh/?code=foo_bar">To app via HTTPS</a>
   ```
   If an app is installed that has the domain name
   registered via [Android App Link](https://developer.android.com/training/app-links)
   and the website was opened in the Chrome browser
   the user will be redirected to the app without an
   app selection dialog. If no app with Android App
   Link is installed the URL will open in the Chrome
   browser. If the website was opened in another browser,
   the user will be redirected to the website and not
   the app.

   Another problem arises if the IDP website is opened in a
   Firefox Custom Tab and the user is redirected to the RP website
   inside the Custom Tab. Now he decides to click on "Open in Firefox".
   If the right app with an Android App Link is not installed he
   has to possible choose between the Firefox browser and
   a malicious app that has registered itself for the
   domain name. 

2. Use a custom scheme
   ```html 
   <a href="com.example.relyingparty://completed/?code=foo_bar">To app via custom scheme</a>
   ```
   This solution has the advantage that every 
   browser will open the app that supports the
   scheme. The disadvantage is that every app
   can register itself for the scheme. So an
   adversary could install an app for that scheme
   and then the user has to choose between apps.

3. Use the intent scheme
   ```html
   <!-- Source: https://developer.chrome.com/multidevice/android/intents -->
   <a href="intent://relyingparty.intranet/?code=foo_bar#Intent;scheme=http;package=com.example.relyingparty;S.browser_fallback_url=https://app2app.unsicher.ovh/?code=foo_bar;end">To app via intent scheme</a>
   ```
   This scheme will open the correct app in
   any browser since it is handled as an intent
   that has the app's package name set. This assures
   that always the same app will open.

   The problem with this scheme and OAuth 2.0
   is that the intent specification is in the
   fragment part of the URL. Since OAuth 2.0 just
   uses the redirect_url and appends the 
   parameters it is not directly possible to use
   this type of URL. But if we redirect the 
   browser first to a backend endpoint that
   redirects the browser to a URL with the intent
   scheme it is possible to use existing AS
   without modifications.


## Complete Solution on Android

-- Description Following --

```plantuml
title Relying Party App to OpenID Provider

box "Relying Party" #LightBlue
participant "Relying Party Backend" as rpb
participant "Relying Party Website" as rpw
participant "Relying Party App" as rpa
end box
participant "OS" as os
box "OpenID Provider" #LightGreen
participant "OpenID Provider App" as opa
participant "OpenID Provider Website" as opw
participant "Authorization Server" as as
end box

rpa -> os: isAppInstalled(applicationID)
rpa <-- os: return (installed, cert_fingerprint)

alt installed == true && verification successful
   rpa -> rpa: verify cert_fingerprint
   rpa ->> os: Intent(URL).setPackage(applicationID)
   os ->> opa: Intent(URL).setPackage(applicationID)
else
   rpa -> os: checkIfAppWithAppIDisInstalled(applicationID)
   rpa <-- os: return(installed)
   alt installed == true
      rpa -> rpa: Abort or warn the user
   end
   rpa -> os: getDefaultBrowserApplicationID()
   rpa <-- os: return (browserApplicationID, cert_fingerprint)
   rpa -> rpa: verify cert_fingerprint
   rpa ->> os: Intent(URL).setPackage(browserApplicationID)
   os ->> opw: Intent(URL).setPackage(browserApplicationID)
end
```

-- Description Following --

```plantuml
title OpenID Provider App to Relying Party

box "Relying Party" #LightBlue
participant "Relying Party Backend" as rpb
participant "Relying Party Website" as rpw
participant "Relying Party App" as rpa
end box
participant "OS" as os
box "OpenID Provider" #LightGreen
participant "OpenID Provider App" as opa
participant "OpenID Provider Website" as opw
participant "Authorization Server" as as
end box

alt callingActivity?.packageName != null
   os <- opa: getCertificate(callingActivity?.packageName)
   os --> opa: return (cert_fingerprint)
   opa -> opa: verify cert_fingerprint and redirect_uri
   os <<- opa: setResult(intent)
   rpa <<- os: setResult(intent)
else
   os <- opa: getDefaultBrowserApplicationID()
   os --> opa: return (browserApplicationID, cert_fingerprint)
   opa -> opa: verify cert_fingerprint
   os <<- opa: Intent(URL).setPackage(browserApplicationID)
   rpw <<- os: Intent(URL).setPackage(browserApplicationID)
end
```

-- Description Following --

```plantuml
title OpenID Provider Web to Relying Party

box "Relying Party" #LightBlue
participant "Relying Party Backend" as rpb
participant "Relying Party Website" as rpw
participant "Relying Party App" as rpa
end box
participant "OS" as os
box "OpenID Provider" #LightGreen
participant "OpenID Provider App" as opa
participant "OpenID Provider Website" as opw
participant "Authorization Server" as as
end box

opw <- as: Authorization Response (code)
rpb <- opw: Authorization Response (code)
rpb -> rpb: change url to intent:// scheme
rpb -> os: intent://...?code=...#Intent;scheme=https;package=...;end
rpa <- os: Intent(URL).setPackage(...)
```
