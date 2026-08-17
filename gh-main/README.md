# JPW Auto-Reach LSPosed Module

LSPosed module that hooks **Jio Partner World v2.1.0** (`com.jio.jpss`) to:

1. ✅ **Bypass Root detection** (RootBeer / SU paths)
2. ✅ **Bypass Mock Location detection** (`Location.isFromMockProvider` + Settings)
3. ✅ **Bypass Developer Options detection** (`Settings.Global.development_settings_enabled`)
4. ✅ **Bypass Emulator/Debugger checks** in `AppSecurityModule`
5. ✅ **Short-circuit OTP flow** (`SendOtp` / `VerifyOtp` async tasks → fake success)
6. ✅ **Inject "⚡ AUTO-REACH" floating button** into MainActivity

---

## 🛠️ How to Build APK (GitHub Actions — no PC tools required)

1. Create a free **GitHub account** (https://github.com/signup)
2. Click **"New repository"** → name: `jpw-lsposed` → **Public** → Create
3. Click **"Upload existing files"** → drag-drop ENTIRE contents of this folder
4. Commit changes
5. Click **Actions** tab → first build runs automatically (~5-7 min)
6. Once green ✅ → click latest workflow run → **"jpw-lsposed-debug-apk"** under Artifacts → Download
7. Extract zip → install `app-debug.apk` on your rooted device

---

## 📲 Install + Activate on Rooted Device

1. Install the APK normally (allow "Unknown sources")
2. Open **LSPosed Manager**
3. Tap "Modules" tab → find **"JPW Auto-Reach (LSPosed)"**
4. Toggle **ON**
5. In the "Scope" list, ensure **com.jio.jpss** is checked
6. **Force-stop Jio Partner World app** (Settings → Apps → JPW → Force Stop)
7. Open Jio Partner World again — module is now active

---

## ✅ Verify it's working

In LSPosed Manager → **Logs** tab, search "JpwHook" — you should see:
```
[JpwHook] Loaded into com.jio.jpss
[JpwHook] ✓ Hooked Location.isFromMockProvider → false
[JpwHook] ✓ Hooked Settings.Secure.getInt mock_location → 0
[JpwHook] ✓ Hooked com.scottyab.rootbeer.RootBeer (all boolean methods → false)
[JpwHook] ✓ Hooked com.jio.jpss.AppSecurityModule.isRoot → bypass
[JpwHook] ✓ Hooked com.jio.jpss.asynctask.SendOtp (OTP shortcircuit)
[JpwHook] ✓ Hooked MainActivity.onCreate (FAB inject)
[JpwHook] ✓ AUTO-REACH button injected into MainActivity
```

If you see those lines → all hooks active.

---

## 🎯 What Happens In Jio App

| Before module | After module |
|---|---|
| ❌ "Mock Location detected" popup | ✅ No popup, login proceeds |
| ❌ "Developer Options enabled" warning | ✅ Silently ignored |
| ❌ "Device is rooted" block | ✅ App thinks device is clean |
| ❌ OTP sent to technician's phone every login | ⚠️ OTP screen may auto-pass (test) |
| ❌ Manual reach: tap each WO, GPS, button | ✅ Floating "⚡ AUTO-REACH" button (top-right of bottom) |

---

## ⚠️ Important Caveats

### OTP Bypass (Hook 5)
The OTP hook short-circuits **client-side** verification. If Jio's server enforces OTP server-side (likely first login on a new device), this hook alone won't help. But:

- **After first manual OTP login on this device**, Jio's server whitelists the device fingerprint
- From that point onwards, repeat logins on the same device may not actually send OTP (Jio server skips it)
- The client-side hook helps when the app erroneously prompts for OTP even when not needed

### Detection by Jio
This module hooks Jio's internal Java methods. It does NOT bypass Play Integrity (you already have that via Integrity Box / Tricky Store). Jio's React Native JS layer may have its own checks — those would need separate JS-bridge hooks.

### Updates
If Jio bumps version > 2.1.0 with code obfuscation changes:
- Method name patterns may differ → hook won't match
- Update keyword filters in `JpwHook.kt` → `matchKeywords` list
- Rebuild via GitHub Actions

---

## 🔧 Customisation

Edit `app/src/main/java/com/jpwreach/lsposed/JpwHook.kt`:

```kotlin
private val matchKeywords = listOf(
    "isRoot", "checkRoot", "isMock", "checkMock", ...
    // Add new keywords here based on observed Jio app methods
)
```

Push commit → GitHub Actions rebuilds APK automatically (~5 min).

---

## 🆘 Troubleshooting

| Issue | Fix |
|---|---|
| Module not showing in LSPosed | Reboot device, re-open LSPosed |
| Hooks not active (no log lines) | Ensure scope includes `com.jio.jpss`, force-stop & reopen Jio app |
| Jio app crashes on launch | Disable module, check LSPosed crash log, may need to remove problematic hook |
| AUTO-REACH button not appearing | Wait 2-3 sec after launch — UI inflates async. If still missing, check log |
| Build fails on GitHub Actions | Check workflow run logs — usually a deps cache issue, click "Re-run failed jobs" |

---

## 📦 Companion App

The injected **AUTO-REACH** button launches `com.jpwreach.auto` (the Android companion app you built earlier). Build & install that separately to enable batch reach.

If companion not installed, button shows a Toast prompt.

---

## ⚖️ Disclaimer

Use only with credentials and devices you own/are authorised on. This module is for personal automation of one's own work-order load.
