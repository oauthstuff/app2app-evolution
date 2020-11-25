Authors:\
Fabian Hauck (yes.com)\
Daniel Fett (yes.com)\
Joseph Heenan (Authlete)

# Improving OAuth App-to-App Security

OAuth flows on mobile devices can benefit a lot from native apps. With native
apps, for example, it is possible to use already existing sessions and biometric
authentication features. While apps improve the user experience, they also bring
new security challenges to OAuth, especially for services like open banking.
This document describes the challenges redirections between native apps and web
application on Android and iOS and recommends solutions based on currently
available features of the mobile operating systems and browsers.

## Problem Statement

When using OAuth to authorize the access to protected resources or OpenID
Connect for authentication, it is crucial to secure the issuance process of the
access token or ID token. Above all, it is important that the Authorization
Request and the Authorization Response do not get hijacked by an adversary. 

If, for example, an OAuth Authorization Response is hijacked and the client does not
use [PKCE](https://tools.ietf.org/html/rfc7636), the adversary could inject the
stolen authorization code into his own session to get access to the victim's
protected resources ([Code
Injection](https://tools.ietf.org/id/draft-ietf-oauth-security-topics-14.html#rfc.section.4.5)).
PKCE can help to protect against Code Injection, but if the Authorization
Request is hijacked as well, the attacker can modify it and use the resulting
authorization code despite PKCE. This attack is similar to the one described
[here](https://web-in-security.blogspot.com/2017/01/pkce-what-cannot-be-protected.html).

Even using [Pushed Authorization
Requests](https://tools.ietf.org/html/draft-ietf-oauth-par) (PAR) or [signing
the Authorization Request](https://tools.ietf.org/html/draft-ietf-oauth-jwsreq)
will not mitigate all of the attacks that are possible if the OAuth redirection
gets hijacked: For example, an attacker who can intercept the authorization
request and response on a victim's device could replace the whole authorization
request (containing the PAR request URI or JAR signed request) with an
authorization request generated using a client under his control. Then, after
the victim authorized the access, the attacker could read the authorization
response and use the authorization code on his own device, gaining access to the
victim's resources. Therefore, it is critical to properly secure the redirection
to the OpenID Connect Identity Provider (IDP) (or OAuth authorization server)
and back in terms of integrity and secrecy. 

In a browser, it is generally secure to redirect the user using a URL, assuming
that the URL is not under the attacker's control, but on mobile operating
systems, the situation is much more complicated.

Android, for example, permits arbitrary apps to claim that they handle a
specific domain - even of other apps installed from the Google Play Store.
Although it is possible to verify a domain-app association ([Android App
Link](https://developer.android.com/training/app-links)) this mechanism is not
active if the app belonging to the domain is not installed on the device. In
case the IDP app is not installed, the user would have to choose from a menu
with which app he wants to open the URL.

<img src="images/app_chooser_dialog.png" width=300px/>

As we can see in the picture, a malicious OpenID Provider app also claims to
handle the authorization server's domain. In this case, the user could choose
the malicious app instead of the browser. 

Another problem on Android is the redirection back from the IDP website loaded in the browser to the Relying Party (RP) app. If the RP app uses an Android
App Link and the user was redirected to the Chrome browser, the user
can be sent back to the app by simply being redirected to the Android
App Link. This does not, however, work in most of the other browsers. To be
browser independent, it is necessary to use a custom URL scheme.
Arbitrary apps, however, can register themselves
to handle the same custom scheme, making this technique susceptible to redirect
hijacking.

On iOS the situation is different. There, an app can only claim to
handle an `http://` or `https://` scheme URL if it can verify an association 
with the domain ([Universal Links](https://developer.apple.com/ios/universal-links/)).
Custom schemes can be claimed, like on Android, by every app, but the OS will
not display a selection menu - it will instead arbitrarily pick one of the apps.

In the following, we will distinguish the following cases:

 * app2app: Both RP or OAuth client and the IDP or OAuth authorization server
   have a native app installed on the user's device.
 * app2web: The RP or OAuth client is a native app, but the IDP/server app is
   not installed. A web application is to be used instead.
 * web2app: The RP or OAuth client is a web site, but an IDP or OAuth server app
   is installed.

The web2web case is (more or less) classic OAuth/OIDC and therefore not
considered in this document.

## Attacker Model

When talking about a class of security problems, it is always helpful to have a
rough idea of the types of attackers that are considered relevant and those that
are out of scope. Here, the attacker model could be outlined as follows:

We assume that attackers ...

- ... can install apps that register the same custom scheme as an honest app.
- ... cannot install apps that verify an app association with a domain they do
  not control.
- ... cannot manipulate the operating system.

Specifically on Android, the following distinctions are important as well:

We assume that attackers ...

- ... cannot install apps through the Play Store with the same applicationID as
  an honest app in the Play Store.
- ... can install apps with the same applicationID as an honest app through a
  third-party app store or sideloading.
- ... cannot sign an APK with a certificate they do not control.

## Security Goals

Under the attacker model outlined above, what are the goals that a good solution should achieve?

1. When the user is redirected from the RP to the IDP, he should either go to
   the legit app or to the default browser to ensure integrity and secrecy of
   the authorization request. Ideally, an in-app browser that shares cookies
   with the system's default browser is opened (on Android, if supported, an
   Android Custom Tab; on iOS `ASWebAuthenticationSession`). There should never
   be a menu where the user has to choose between multiple apps.

2. When the user is redirected from the IDP back to the RP, he should be sent
   back to the app/browser where he started the process.

## Solution on iOS
On iOS, we can use Universal Links to redirect the user from one app to another.
The good thing here is that we can set a flag called `.universalLinksOnly:
true`. This will only redirect the user if an app that has claimed this link is
installed and the link has been verified by the OS for the domain.

```Swift
// if bank’s app is present & supports app2app, open it
UIApplication.shared.open(authorizationEndpointUrl, options: [.universalLinksOnly: true]) { (success) in
    if !success {
        // launching bank app failed: app does not support universal links or
        // bank’s app is not installed – open an in app browser tab instead
        <…continue as app did before app2app…>
    }
}
```
(Source: [Blog post by Joseph
Heenan](https://openid.net/2019/10/21/guest-blog-implementing-app-to-app-authorisation-in-oauth2-openid-connect/).)

In case the app is not installed, we can launch an
[ASWebAuthenticationSession](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession)
that opens an in-app browser session powered by Safari. With this, it is
possible to use existing session cookies from the Safari browser. To redirect
back to the app, the app specifies a claimed https url before launching the
browser. If the browser is redirected to the claimed https url the browser will
exit and give the URL back to the app.

### Limitations on iOS

If the user normally uses a browser other than the system Safari, it is at best difficult to return them to that browser in the web2app flow, and to send them to that browser in the app2web flow.

iOS14 improves this situation by adding a [system level preference where the user can select an alternative browser](https://developer.apple.com/documentation/xcode/allowing_apps_and_websites_to_link_to_your_content/preparing_your_app_to_be_the_default_browser_or_email_client) - however the alternative browser will not be able to share cookies/sessions with the system Safari, and it is currently believed that `ASWebAuthenticationSession` will always be handled by the system Safari. Unfortunately the rules for 
alternate browsers do not currently seem to require them to implement Universal Links, nor to provide a similar user experience to Safari if they do support them.

iOS requires apps are signed using an extra permission that is manually granted by Apple before they can become the default browser, so it seems we can trust that the default browser is generally not malicious. 

For the OAuth client (OIDC relying party), if flows starting in both app and mobile web are supported, it's probably best to use different redirect uris depending on whether the flow starts in the app or in the mobile web browser, so there is a higher chance the flow ends up back where the user started. (By contrast, the OAuth server / OpenID Provider should generally not use different urls for its authorization endpoint for the web vs app flows, as there is no standard way to publish the alternative URL.)


## Solution for Android

For Android, we will first look at the challenges of the app2app/app2web case
and the web2app case separately. Afterwards, we will provide a recommendation
for a  robust solution.

### App2App and App2Web Solutions on Android

How could we approach the problem on Android?

1. **Open app via HTTPS link**
   ```kotlin
    val uri =  Uri.parse("https://app2app.unsicher.ovh?request_uri=Hello_World")

    val browserIntent = Intent(Intent.ACTION_VIEW, uri)
    startActivity(browserIntent)
   ```

   If the app of the domain owner is installed and supports [Android App
   Links](https://developer.android.com/training/app-links), the legit app will
   always be opened. If the domain owner app is not installed, the OS will
   display an app chooser dialog (as can be seen in the screenshot above). Since
   any app can claim to handle the domain name, the user could choose an app
   from an attacker. This is not a good solution.

2. **Open the web browser with an intent that has the category *CATEGORY_APP_BROWSER* set**
   ```kotlin
   val uri =  Uri.parse("https://app2app.unsicher.ovh?request_uri=Hello_World")

   val browserIntent = Intent.makeMainSelectorActivity(Intent.ACTION_MAIN, Intent.CATEGORY_APP_BROWSER)
   browserIntent.data = uri
   startActivity(browserIntent)
   ```
   This code forces the OS to open the link inside a web browser and not in an
   app that just claims to open this domain name. If the user has multiple
   browsers installed, he still has to choose between them.

   But is a browser automatically trustworthy? In the Google Play Store is it
   not clear (for us) how hard it is to publish an app that provides
   CATEGORY_APP_BROWSER, whereas on iOS, a signing permission manually granted
   by Apple is required for an app to be selectable as the default browser. 


3. **Use Android Custom Tabs**
   ```kotlin
   val uri =  Uri.parse("https://app2app.unsicher.ovh?request_uri=Hello_World")

   val builder = CustomTabsIntent.Builder()
   val customTabsIntent = builder.build()
   customTabsIntent.launchUrl(this, uri)
   ```
   This code opens an [Android Custom Tab](https://developer.chrome.com/multidevice/android/customtabs). 
   The problem here is that if the user does not 
   have a default browser (unlikely), he has to choose
   between all installed browsers. Additionally, if a
   malicious app is installed the user has to 
   choose between this app and the browser. It is a
   similar problem as in solution 1. 
   
   However a positive side is that if the user chooses a browser 
   that does not support Custom Tabs, the browser application
   will launch.

4. **Set default browser as package in the Intent**
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
   To prevent the user from having to choose between multiple apps, an intent
   can be explicitly told which package it should use to execute the intent. In
   this example an Android Custom Tab is initialized and the
   `getDefaultBrowserPackageName()` method finds out what the package name of
   the user's default browser is.

   A problem with Chrome Custom Tabs is that if the user clicks on `Open in
   Chrome` and the OpenID Provider app is not installed but a malicious app is
   installed, the user has to choose between Chrome and the malicious app.

#### Can we do Better?
Solutions 2 and 4 have the problem that they will open a web browser even if the
app of the domain owner is installed on the device. To open the app if it is
installed, it is necessary to first check whether the app is installed at all.
The code for this can be seen below. The app must, of course, register the
domain name as an Android App Link.
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

How do we get the package name? Two mechanisms are conceivable: We take the
issuer URL (or authorization server URL) and then either take the package name
from ``https://issuer/.well-known/assetlinks.json`` or include it in the
OAuth/OpenID Connect server metadata ([RFC
8414](https://tools.ietf.org/html/rfc8414#section-2)). For the latter, a new
metadata element would need to be standardized. 

From Android 11, the [app will need to request extra
permissions](https://developer.android.com/preview/privacy/package-visibility)
to use the package manager APIs.

Does this solve all our problems? No!


#### Challenge: Hundreds of Android App Links

The [yes® ecosystem](https://www.yes.com) consists of more than 1000 IDPs, that
is, OpenID Connect issuers from independent domains. However, several hundred of
these IDPs belong to the same banking group using the same mobile app.
Therefore, this app is responsible for several hundred domains, each of which
the app would need to register an Android App Link for. If only one of these
registrations fails, none of them would be accepted by the OS. Not to speak of
the huge performance problems, both on the client and server sides, when each app
download would trigger the download of a document from several hundred domains. 

To solve this, the Relying Party could add the package name to the
intent that opens the redirect URL. This would ensure that the 
correct app opens without Android App Links. It is also a good 
solution since we already need to have have the package name of the IDP
app to use the `isAppInstalled` function.

```kotlin
val uri =  Uri.parse("https://app2app.unsicher.ovh?request_uri=Hello_World")
val packageName = "com.example.openidprovider"

val redirectIntent = Intent(Intent.ACTION_VIEW, uri)
redirectIntent.setPackage(packageName)
startActivity(redirectIntent)
```

Are we done here? Not yet: This is not a sufficient replacement for Android
AppLinks - for the app2app use case, the main difference is the application
signature is not verified using this method.

#### Challenge: Alternative App Stores
Since Android is an open system, it is possible to install apps from other
sources than the Play Store. While it is guaranteed that the package name of
apps from the Play Store is unique, this does not apply to apps installed from
other sources. One possibility to overcome this security threat is to check the
signing certificate of the app we want to open. This can be done in the
``isAppInstalled`` method in the following way:

```kotlin
private fun isAppLegit(packageName: String): Boolean {
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
The `generateSignatureHashes` method is found in [AppAuth-Android](https://github.com/openid/AppAuth-Android/blob/0875455b1390c49c4d6b2aaeee01a3cbf93d3407/library/java/net/openid/appauth/browser/BrowserDescriptor.java#L159).

For this solution, as well as the package name, we also need
the hashes of the certificates that were used to sign the APK.
This can either be put into the OAuth/OpenID Discovery document or if the
IDP app uses Android App Links the hash can be found in the
``/.well-known/assetlinks.json`` file.

Now we have solved one direction. How do we get back from the OpenID Provider
app to the calling activity in the Relying Party? 


#### Challenge: App2App Backwards Redirection
We can use the method ``startActivityForResult()``. This has two advantages:
First, the OpenID Provider app can get the package name of the calling app with
``callingActivity?.packageName`` and second, the IDP  app can redirect to the
calling app with the ``setResult()`` method.

Nevertheless, the IDP app should check if the redirect_uri from the AS, 
the package name, and the certificate fingerprint of the calling app
matches. This should be done like this:

```kotlin
val foundPackageName: String? = callingActivity?.packageName

val (basePackageName, baseCertFingerprints) = getAssetLinksJsonFile(uri)
val foundCertFingerprints = getSigningCertificates(foundPackageName)

if (matchHashes(foundCertFingerprints, baseCertFingerprints)
   && foundPackageName == basePackageName) {
   // Everything is fine call setResult()
} else {
   // Something is wrong with the installed app.
   // Redirect the user to the browser.
}
```
A small caveat remains: When an activity is launched with
`startActivityForResult()` care is required when the iDP app launches further
activities, such as sub-activities to request login or 2-factor authentication.


### Web2App Solutions on Android

What can we do to secure the web2app case?

1. **Use Android App Links**
   ```html
   <a href="https://app2app.unsicher.ovh/?code=foo_bar">To app via HTTPS</a>
   ```
   If an app is installed that has the domain name registered via an [Android
   App Link](https://developer.android.com/training/app-links) and the website
   was opened in the Chrome browser, the user will be redirected to the app
   without an app selection dialog. If no app with Android App Link is
   installed, the session will continue in Chrome browser.
   
   If the website was opened in another browser, the user will be redirected to
   the website and not the app.

2. **Use a custom scheme**
   ```html 
   <a href="com.example.relyingparty://completed/?code=foo_bar">To app via custom scheme</a>
   ```
   This solution has the advantage that every browser will open the app that
   supports the scheme. The disadvantage is that any app can register itself for
   the scheme. So an adversary could install an app for that scheme and then the
   user has to choose between apps.

   Implementing a fallback if the app is not installed is possible but a little involved.

3. **Use the intent scheme**
   ```html
   <!-- Source: https://developer.chrome.com/multidevice/android/intents -->
   <a href="intent://relyingparty.intranet/?code=foo_bar#Intent;scheme=http;package=com.example.relyingparty;S.browser_fallback_url=https://app2app.unsicher.ovh/?code=foo_bar;end">To app via intent scheme</a>
   ```
   The [intent scheme](https://developer.chrome.com/multidevice/android/intents)
   will use the package name to find an app to open the URL. This scheme is
   essentially handled as an Android Intent by the system and works in every
   browser. If no app with the package name is found, the user will be
   redirected to the URL specified in the ``S.browser_fallback_url`` parameter.

   Since we can only specify the package name, a malicious app from another app
   store could hijack this kind of redirection. To prevent this, we would need a
   feature to specify the signing certificate hash of the target app. But this
   feature is not available.

   The problem with the intent scheme and OAuth 2.0 is that the intent
   specification is in the fragment part of the URL. Since OAuth 2.0 just uses
   the redirect_uri and appends the parameters, it is not directly possible to
   use this type of URL. In fact, it is explicitly forbidden by RFC6749. We can
   circumvent this by redirecting the browser to a backend endpoint that
   redirects the browser to a URL with the intent scheme. This enables us to use
   an existing authorization server implementation without modifications.

   **Note:** Since the Intent scheme is handled the same as a normal custom
   scheme outside of Android, it is important that the endpoint that redirects
   the user tries to determine whether the request came from a browser running
   on Android that supports the `intent://` scheme or another browser. This is
   due to the fact that custom schemes introduce security risks to the OAuth
   flow. If the endpoint detects any other device, it should display an error
   message.


#### User's Default Browser Selection Considerations
The selection of the browser has implications for the user experience and security:


**Google Chrome:**
   - supports Android App Links, Intent schemes and custom schemes
   - does not ask the user whether he wants to switch the app (see below)

**Mozilla Firefox:**
   - has an option to open links in external apps (disabled by default)
   - does not correctly validate Android App Links (relevant if the previous
     option is enabled)
   - despite the external app option it always opens Intent scheme in an app if
     there is no fallback url provided
     (``S.browser_fallback_url=[encoded_full_url]`` SHOULD NOT be used in the
     Intent scheme)

**Samsung Internet Browser:**
   - also has an option to open links in external apps (disabled by default)
   - does correctly open Intent schemes even if a fallback url is provided
     (without enabling the previous option)
   - handles Android App Links correctly if the first option is enabled

**DuckDuckGo and Puffin:** 
   - support Intent schemes and custom schemes
   - if the browser is redirected to a URL with a custom scheme that opens
     another app, the browser warns the user.

      <img src="images/DuckDuckGo_Browser_Redirect_Warning.png" width=300px/>


### Proposed Solution on Android

After seeing so many possible solutions for Android, what are the best
techniques for Android? This section describes (what we think is) the best
solution achievable for Android. This description is divided into the
redirection from the RP app to the IDP, the IDP app to the RP, and the IDP
website to the RP. This solution will not use Android App Links due to the
problems noted above, but will instead set the package name of the apps
explicitly to the Android Intent.

#### RP App to IDP

To redirect from the RP app to the IDP, the RP app has to check whether the IDP
app is installed. It does this by requesting the certificate with which the IDP
app was signed from the Android Package Manager. If the app is not installed,
the Package Manager will throw an exception. After this, the certificate hash
has to be compared to the hash that is found in the
``/.well-known/assetlinks.json`` file. If they are the same, the RP app can
redirect the user to the IDP app with an Android Intent that has the package
name of the IDP app set. The Intent can either be started with the method
``startActivity()`` or ``startActivityForResult()``. 

If the IDP app is not
installed, the RP app has to determine the user's default browser
and compare the certificate hash of this browser with a hardcoded hash.
If this is successful, the RP app can open the browser with an Android
Intent that has the package name of the default browser set.

<img src="https://www.plantuml.com/plantuml/proxy?fmt=svg&src=https://raw.githubusercontent.com/oauthstuff/app2app-evolution/master/plantuml/rp_to_idp.plantuml" style="background-color: white">

**Example Code:**

```kotlin
// use methods from the AppAuth-Android project: https://github.com/openid/AppAuth-Android
import net.openid.appauth.browser.BrowserAllowList
import net.openid.appauth.browser.BrowserSelector
import net.openid.appauth.browser.VersionedBrowserMatcher

/**
* Main method to do the redirection
*/
fun secureRedirection(uri: Uri) {
   // A full, generic implementation of this is more complex - the assetlinks.json may list
   // multiple apps, only some of which the user has installed, and only some of which handle
   // the path for the authorization endpoint
   val (basePackageName, baseCertFingerprints) = getAssetLinksJsonFile(uri)

   if (isAppLegit(basePackageName, baseCertFingerprints)) {
      val redirectionIntent = Intent(Intent.ACTION_VIEW, uri)
      redirectionIntent.setPackage(basePackageName)
      startActivity(redirectionIntent)
   } else {
      redirectToWeb(uri)
   }
}

fun redirectToWeb(uri: Uri) {
    val builder = CustomTabsIntent.Builder()
    val customTabsIntent = builder.build()

    // find a suitable browser to open the URL
    val browserDescriptor = BrowserSelector.select(
        context, 
        BrowserAllowList(
            VersionedBrowserMatcher.CHROME_CUSTOM_TAB,
            VersionedBrowserMatcher.CHROME_BROWSER,
            VersionedBrowserMatcher.FIREFOX_CUSTOM_TAB,
            VersionedBrowserMatcher.FIREFOX_BROWSER,
            VersionedBrowserMatcher.SAMSUNG_CUSTOM_TAB,
            VersionedBrowserMatcher.SAMSUNG_BROWSER
        )    
    )

    if (browserDescriptor != null) {
        customTabsIntent.intent.apply {
            setPackage(browserDescriptor.packageName)
        }
        customTabsIntent.launchUrl(context, uri)
    } else {
        Toast.makeText(context, "Could not find a browser", Toast.LENGTH_SHORT).show()
    }
}

fun isAppLegit(
    packageName: String,
    baseCertFingerprints: Set<String>
): Boolean {
    val foundCertFingerprints = getSigningCertificates(packageName)
    if (foundCertFingerprints != null) {
        return matchHashes(baseCertFingerprints, foundCertFingerprints)
    }
    return false
}

fun matchHashes(certHashes0: Set<String>, certHashes1: Set<String>): Boolean {
    if (certHashes0.containsAll(certHashes1)
        && certHashes0.size == certHashes1.size
    ) {
        return true
    }
    return false
}

fun getSigningCertificates(packageName: String): Set<String>? {
    try {
        // Try to query the signing certificates of the
        // IDP app. If the IDP app is not installed this
        // operation will throw an error.
        val signatures: Array<Signature>?
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            val signingInfo = packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNING_CERTIFICATES
            ).signingInfo
            signatures = signingInfo.signingCertificateHistory
        } else {
            signatures = packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNATURES
            ).signatures
        }

        // calculate the hashes of the signing certificates
        val foundCertFingerprints = generateSignatureHashes(signatures)

        return foundCertFingerprints
    } catch (e: PackageManager.NameNotFoundException) {
        return null
    }
}
```

#### IDP App to RP

Concerning this redirection, we have two cases that depend on whether the
method ``startActivityForResult()`` is used to start the IDP app.

**Case 1:** `getCallingActivity()` is null

`startActivityForResult()` was not used from the RP app to the IDP app

In this case we can use the exact same method from above (``secureRedirection(uri: Uri)``).

As noted for iOS, the RP native app may want to use a different redirect url to the web app if the user may start the flow from the system browser despite having the RP app installed.

**Case 2:**  `getCallingActivity()` is not null

This means `startActivityForResult()` was used.

In this case the IDP app knows the package name of the calling app. With the 
package name, the IDP app can get the signing certificate of the
calling app. This information can be compared with the values that are 
stored in the  ``/.well-known/assetlinks.json`` file of the redirect_uri 
domain. If all these values match and the redirect_uri is a registered one for that RP, 
the IDP app can redirect the user back to the RP app with the 
method ``setResult()``.

<img src="https://www.plantuml.com/plantuml/proxy?fmt=svg&src=https://raw.githubusercontent.com/oauthstuff/app2app-evolution/master/plantuml/idp_app_to_rp.plantuml" style="background-color: white">

**Example Code:**

```kotlin
/**
* Method to redirect back to the RP app if the IDP app 
* is started with 'startActivityForResult()'.
*/
fun secureRedirectionBackwards(uri: Uri) {
   val foundPackageName: String? = callingActivity?.packageName
   if (foundPackageName != null) {
      val (basePackageName, baseCertFingerprints) = getAssetLinksJsonFile(uri)
      val foundCertFingerprints = getSigningCertificates(foundPackageName)

      if (foundCertFingerprints != null
         && matchHashes(foundCertFingerprints, baseCertFingerprints)
         && foundPackageName == basePackageName
      ) {
         val redirectionIntent = Intent(Intent.ACTION_VIEW, uri)
         setResult(0, redirectionIntent)
         finish()
      } else {
         redirectToWeb(uri)
      }

   } else {
      redirectToWeb(uri)
   }
}
```


#### IDP Web to RP

The redirect_uri should depend on whether the user starts a flow on the web or
in the Android app. This diagram shows the case where the user started in the RP
app but was redirected to the web because the IDP app was not installed. In this
case, the redirect_uri should point to an endpoint of the RP's website that
takes the parameters from the Authorization Response and redirects the browser
to a URL that uses the `intent://` scheme. In this `intent://` scheme the RP can set
the package name of the RP app. If the flow is started from the genuine RP app,
the user will be returned to the same app. (The user or an attacker could have
installed a different app with same package name as the genuine app, it is up to
the RP to defend itself against rogue apps accessing its service.)

<img src="https://www.plantuml.com/plantuml/proxy?fmt=svg&src=https://raw.githubusercontent.com/oauthstuff/app2app-evolution/master/plantuml/idp_web_to_rp.plantuml" style="background-color: white">

**Example Code:**

```kotlin
/**
* Example Java Spring rest controller endpoint to
* rewrite the URL.
*/
@GetMapping("/complete")
fun complete(@RequestParam code: String): RedirectView {
   val redirection = RedirectView()
   val codeEncoded = URLEncoder.encode(code, StandardCharsets.UTF_8)
   redirection.url = "intent://relyingparty.intranet/complete?code=${codeEncoded}#Intent;scheme=http;package=com.example.relyingparty;S.browser_fallback_url=http://relyingpart.intranet/website;end"
   return redirection
}
```

### Limitations on Android

While redirecting from app2app and app2web can be secured really well on
Android, it is difficult to secure the web2app redirection. There are two
essential problems. First, Android App Links are only supported by the Chrome
browser and second, it is not possible to set the certificate hash of the target
app in the intent scheme. If either of these problems would be solved, we could
safely redirect from the web to an app. So at the moment there are two options:
Either the user is only allowed to use the Chrome browser (which is not possible
if he starts the flow in another browser) or we have to accept the risk that the
redirection could get hijacked by an app that was installed from an alternative
app store with the same package name.

To solve this, we strongly recommend that alternate browsers are enhanced to
support app links in the same way Chrome does.
