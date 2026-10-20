# AdShield

A lightweight Android app that blocks ads, trackers, pop-ups and malicious redirects
in every app and browser on your phone, while using very little battery.

## How it works

AdShield sets up a local "VPN" on the phone, but only DNS lookups go through it.
All your normal traffic (videos, downloads, browsing) goes straight to the internet
untouched, and nothing is sent to an outside server.

- When an app or website looks up an ad, tracker, pop-up or scam/redirect domain,
  AdShield answers `0.0.0.0`, so the ad or redirect never loads.
- Every other lookup is passed on to your network's normal DNS server
  (falling back to Cloudflare `1.1.1.1` and Quad9 `9.9.9.9`).

### Why it's light on battery

- Only DNS lookups (a few bytes each) go through the app. Bulk traffic never does.
- No timers, polling or wake locks. The app sleeps until a lookup arrives.
- The ~330,000 blocked domains are stored as a sorted array of hashes (about 3 MB).
  A check takes less than a microsecond, and the list reloads in about 30 ms.
- Block lists update every 3 days, only on Wi-Fi (unless a list is missing), and only
  when the network changes. No background timer checks for updates.

## Block lists

| List | Default | What it blocks |
| --- | --- | --- |
| [HaGeZi Pro](https://github.com/hagezi/dns-blocklists) | on | Ads, trackers, analytics |
| HaGeZi Pop-Up Ads | on | Pop-ups, pop-unders and redirect ad networks |
| HaGeZi Threat Intelligence (mini) | on | Scam, phishing and malware redirects |
| StevenBlack unified hosts | off | Extra ads and malware coverage |

You can also add your own **Never block** and **Always block** sites in the app.

## Install

1. In this repo on GitHub, open **Releases** and pick the newest **AdShield build**.
2. Download `AdShield.apk` on your phone and open it. If Android asks, allow your browser
   to "Install unknown apps".
3. Open AdShield and tap **Turn on**, then accept the VPN request.
4. Recommended: tap **Open VPN settings**, tap the gear next to AdShield and turn on
   **Always-on VPN**. Android then keeps it running and restarts it after a reboot.

Every push to the repo builds a new APK automatically
(see `.github/workflows/build.yml`).

### Installing updates

By default, CI builds are signed with a temporary key. If Android won't install a new
build over the old one, uninstall the old one first. To keep the same key across builds,
create a keystore once and add these repository secrets:

```sh
keytool -genkeypair -v -keystore release.jks -alias adshield -keyalg RSA -keysize 2048 -validity 10000
base64 -w0 release.jks   # paste the output into the KEYSTORE_BASE64 secret
```

The other secrets are `KEYSTORE_PASSWORD`, `KEY_ALIAS` (`adshield`) and `KEY_PASSWORD`.

## Limits (what DNS blocking can't do)

- **YouTube, Instagram, Facebook and TikTok ads** come from the same servers as the
  videos and posts, so a DNS blocker can't remove them without breaking the app.
- **Redirects built into a site's own code** (not from an ad network) can still happen.
  For the most complete blocking in a browser, also use Firefox with uBlock Origin.
- **Private DNS:** if Settings › Network › Private DNS is set to a provider hostname, Android
  skips AdShield. Set it to "Off" or "Automatic".
- **Only one VPN app can run at a time on Android.** If you use Surfshark (or another
  VPN), turning one on disconnects the other. AdShield warns you before taking over and
  tells you if Surfshark replaced it. While Surfshark is connected, turn on Surfshark's
  **CleanWeb** setting to keep blocking ads.

### iPhone?

This app is Android-only. On an iPhone, the equivalent with no battery cost is a DNS
blocking profile, for example AdGuard DNS or NextDNS, installed under
Settings › General › VPN & Device Management.

## Building locally

Needs JDK 17 and the Android SDK.

```sh
./gradlew testDebugUnitTest assembleRelease
# APK: app/build/outputs/apk/release/app-release.apk
```
