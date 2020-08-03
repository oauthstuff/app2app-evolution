Author: Fabian Hauck (yes.com)

# app2app-evolution

OAuth flows on mobile devices can benefit a lot from native apps.
With native apps, for example, it is possible to use already existing 
sessions and biometric authentication features. While apps improve
the user experience they also bring new security challenges to 
OAuth. This document describes the challenge of app2app, app2web
and web2app redirection on Android and iOS.

## Problem Statement

Since OAuth is used to issue access tokens for accessing protected
resources it is crucial to secure the issuance process. Therefore,
it is important that the Authorization Request and the Authorization
Response does not get hijacked by an adversary. 

If, for example, the
Authorization Response gets hijacked and the client does not use
PKCE, the adversary could inject the authorization code into his 
session to get access to the victim's protected resources ([Code Injection](https://tools.ietf.org/id/draft-ietf-oauth-security-topics-14.html#rfc.section.4.5)). PKCE can help to protect the Authorization Response. But if
the Authorization Request gets also hijacked, the attacker can 
modify it and use the authorization code despite PKCE. Using a
Pushed Authorization Request (PAR) or signing the Authorization Request
will also not mitigate the attacks that are possible if the
OAuth redirection gets hijacked. Therefore, it is critical to
properly secure the redirection to the OpenID Provider (IDP). 

In a browser, it is secure to redirect the user using a URL,
but this is not secure on most mobile operating systems.
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
not display a selection menu, but instead launch the app that
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

1. If the user is redirected from the RP to the IDP, he should
either go to the legit app or to the default browser. If the 
default browser supports Android Custom Tabs, the website 
should be opened in a Custom Tab. There should never be a
menu where the user has to choose between multiple apps.

2. If the user is redirected from the IDP back to the RP,
he should either go directly to the legit app or to the 
default browser.

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


## Proposed Solution on Android

After seeing so many possible solutions for Android you probably ask
yourself what are the best techniques for Android. This section 
describes the best current practice solution for Android. It is 
divided into the redirection from the RP app to the IDP, the IDP app to the RP, and the IDP website to the RP. This solution will not use
Android App Links, but instead set the package name of the apps
explicitly to the Android Intent.

### RP App to IDP

To redirect from the RP app to the IDP, the RP app has to check whether 
the IDP app is installed. It does this by requesting the certificate
with which the IDP app was signed from the Android Package Manager. If the
app is not installed, the Package Manager will throw an exception.
After this, the certificate hash has to be compared with the hash that is
found in the ``/.well-known/assetlinks.json`` file. If they are the same,
the RP app can redirect the user to the IDP app with an Android Intent
that has the package name of the IDP app set. The Intent has to be started
with the method ``startActivityForResult()``. 

If the IDP app is not
installed, the RP app has to determine the user's default browser
and compare the certificate hash of this browser with a hardcoded hash.
If this is successful, the RP app can open the browser with an Android
Intent that has the package name of the default browser set.

<img src="https://www.plantuml.com/plantuml/proxy?fmt=svg&src=https://raw.githubusercontent.com/oauthstuff/app2app-evolution/master/plantuml/rp_to_idp.plantuml?token=AMDSJA3FU2H3J4VKXC6W2TS7FBVL4" style="background-color: white">

### IDP App to RP

The IDP app has to check whether the variable 
``callingActivity?.packageName`` is not null. If the variable is not null,
the app knows that it was called with the method ``startActivityForResult()``
and the IDP app also knows the package name of the RP app. With the 
package name, the IDP app can get the signing certificate of the
RP app. This information can be compared with the values that are 
stored in the  ``/.well-known/assetlinks.json`` file of the redirect_uri 
domain for the package name and the certificate. If these values are the
same, the IDP app can redirect the user back to the RP app with the 
method ``setResult()``.

If the IDP app was not
started via the ``startActivityForResult()`` method the RP app is not 
installed or the user did not use the app. In this case, we have to
redirect the user back to the default browser with the same mechanic
as in the **RP App to IDP** solution.

<img src="https://www.plantuml.com/plantuml/proxy?fmt=svg&src=https://raw.githubusercontent.com/oauthstuff/app2app-evolution/master/plantuml/idp_app_to_rp.plantuml?token=AMDSJA2XDC2EZJPAX4LUK7K7FBXAM" style="background-color: white">

### IDP Web to RP

The redirect_uri should depend on whether the user starts a flow
on the web or the Android app. If the user started on the web, the normal
web OAuth flow should happen without any app. This diagram shows the case
where the user started in the RP app but was redirected to the web 
because the IDP app was not installed. In this case, the redirect_uri
should point to an endpoint of the RP that takes the parameters from
the Authorization Response and redirects the browser to a URL that uses
the intent:// scheme. In this intent:// scheme the RP can set the package
name of the RP app. Since we started the flow inside the RP app the user
will be redirected to the legit app.

<img src="https://www.plantuml.com/plantuml/proxy?fmt=svg&src=https://raw.githubusercontent.com/oauthstuff/app2app-evolution/master/plantuml/idp_web_to_rp.plantuml?token=AMDSJA6HHNMJRU2V6AWO77S7FBXB2" style="background-color: white">
