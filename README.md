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

## Home screen widget

Long-press your home screen, tap **Widgets** and add **AdShield**. Like a VPN app's widget,
it shows:

- **Location:** where your internet traffic appears to come from, with its flag (for example
  🇨🇦 Canada - Toronto). AdShield doesn't change your location, so this is your real
  location, or your VPN server's when Surfshark (or another VPN) is on. Tap it to re-check.
  The check uses [ipinfo.io](https://ipinfo.io) and only runs when you tap it, when
  blocking turns on or off, or when your network changes while AdShield is on.
- Whether ad blocking is on, and how many lookups it has blocked.
- A big **Turn on / Turn off** button. If Surfshark is connected, it asks first.

The widget has no update timer, so it costs no battery while it sits there.

## Block lists

| List | Default | What it blocks |
| --- | --- | --- |
| [HaGeZi Pro](https://github.com/hagezi/dns-blocklists) | on | Ads, trackers, analytics |
| HaGeZi Pop-Up Ads | on | Pop-ups, pop-unders and redirect ad networks |
| HaGeZi Threat Intelligence (mini) | on | Scam, phishing and malware redirects |
| HaGeZi Samsung Tracker | on | Samsung phones sending usage data to Samsung |
| StevenBlack fake news | on | Known fake news and clickbait sites |
| StevenBlack unified hosts | off | Extra ads and malware coverage |

You can also add your own **Never block** and **Always block** sites in the app.

## Install

1. In this repo on GitHub, open **Releases** and pick the newest **AdShield build**.
2. Download `AdShield.apk` on your phone and open it. If Android asks, allow your browser
   to "Install unknown apps".
3. Open AdShield and tap **Turn on**, then accept the VPN request.
4. AdShield turns itself back on after a reboot. If you don't use another VPN, you can
   also turn on **Always-on VPN** for it (VPN settings, gear next to AdShield).

Every push to the repo builds a new APK automatically
(see `.github/workflows/build.yml`).

### Installing updates

Every build is signed with the same key (`app/adshield.jks`), so a new APK installs
over the old one. If you installed build 1, 2 or 3, uninstall it once first; those
used a temporary key.

The key is committed to this public repo, so anyone could sign an app with it. Only
install AdShield from this repo's Releases page. To use a private key instead, add the
repository secrets `KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS` and `KEY_PASSWORD`.

## Limits (what DNS blocking can't do)

- **YouTube, Instagram, Facebook and TikTok ads** come from the same servers as the
  videos and posts, so a DNS blocker can't remove them without breaking the app.
- **Redirects built into a site's own code** (not from an ad network) can still happen.
  For the most complete blocking in a browser, also use Firefox with uBlock Origin.
- **Private DNS:** if Settings › Network › Private DNS is set to a provider hostname, Android
  skips AdShield. Set it to "Off" or "Automatic".
- **Only one VPN app can run at a time on Android.** With Surfshark (or another VPN),
  you can switch freely: connecting Surfshark pauses AdShield, and AdShield turns itself
  back on about 5 seconds after Surfshark disconnects (it waits briefly so switching
  servers doesn't trigger it). While Surfshark is on, turn on its **CleanWeb** setting to
  keep blocking ads. Don't use "Always-on VPN" for either app, since it stops the other
  one from connecting.

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
