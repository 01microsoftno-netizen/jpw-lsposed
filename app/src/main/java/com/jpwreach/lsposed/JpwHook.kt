package com.jpwreach.lsposed

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.location.Location
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.Toast

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONArray
import org.json.JSONObject
import java.util.TreeMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import android.util.Base64

/**
 * JPW Auto-Reach LSPosed module.
 *
 * Hooks on com.jio.jpss (Jio Partner World v2.1.0) to bypass:
 *   1. Root detection (RootBeer + manual SU checks)
 *   2. Mock location detection (Location.isFromMockProvider + Settings.Secure)
 *   3. Developer Options detection (Settings.Global.development_settings_enabled)
 *   4. OTP step (SendOtp / VerifyOtp asynctasks force-success)
 *
 * Bonus: injects "AUTO-REACH ALL" floating button into MainActivity.
 */
class JpwHook : IXposedHookLoadPackage {

    companion object {
        private const val TAG = "JpwHook"
        private const val TARGET_PKG = "com.jio.jpss"
        private fun log(s: String) = XposedBridge.log("[$TAG] $s")
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != TARGET_PKG) return
        log("Loaded into ${lpparam.packageName}")

        val cl = lpparam.classLoader

        // ── 1. Mock-Location & Dev-Settings system-level bypass ──
        bypassMockLocation()
        bypassDeveloperSettings()

        // ── 2. RootBeer / SU detection bypass ──
        bypassRootBeer(cl)

        // ── 3. AppSecurityModule check methods bypass ──
        bypassAppSecurityModule(cl)

        // ── 4. OTP flow bypass (SendOtp / VerifyOtp) ──
        bypassOtpFlow(cl)

        // ── 5. Inject Auto-Reach FAB into MainActivity ──
        injectAutoReachButton(cl)

        // ── 6. SIM verification bypass (TelephonyManager) ──
        bypassSimVerification(cl)

        // ── 7. App signature + integrity check bypass ──
        bypassSignatureAndIntegrity(cl)

        // ── 8. Auto-capture cookies from all HTTP responses ──
        hookHttpCookieCapture(cl)

        // ── 9. Broadcast trigger for headless REACH (adb shell am broadcast ...) ──
        registerBroadcastTrigger(cl)
    }

    // ─── 1. Mock location → always false ───
    private fun bypassMockLocation() {
        try {
            XposedHelpers.findAndHookMethod(
                Location::class.java, "isFromMockProvider",
                XC_MethodReplacement.returnConstant(false)
            )
            log("✓ Hooked Location.isFromMockProvider → false")
        } catch (t: Throwable) { log("✗ isFromMockProvider: $t") }

        try {
            XposedHelpers.findAndHookMethod(
                Location::class.java, "isMock",
                XC_MethodReplacement.returnConstant(false)
            )
            log("✓ Hooked Location.isMock → false")
        } catch (_: Throwable) {}

        // Settings.Secure.getInt with "mock_location" / "ALLOW_MOCK_LOCATION" → 0
        try {
            XposedHelpers.findAndHookMethod(
                Settings.Secure::class.java,
                "getInt",
                android.content.ContentResolver::class.java, String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(p: MethodHookParam) {
                        val k = p.args[1] as String?
                        if (k == "mock_location" || k == "ALLOW_MOCK_LOCATION") {
                            p.result = 0
                        }
                    }
                }
            )
            log("✓ Hooked Settings.Secure.getInt mock_location → 0")
        } catch (t: Throwable) { log("✗ Settings.Secure 2-arg: $t") }

        try {
            XposedHelpers.findAndHookMethod(
                Settings.Secure::class.java,
                "getInt",
                android.content.ContentResolver::class.java, String::class.java, Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(p: MethodHookParam) {
                        val k = p.args[1] as String?
                        if (k == "mock_location" || k == "ALLOW_MOCK_LOCATION") {
                            p.result = 0
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
    }

    // ─── 2. Developer options & ADB → 0 ───
    private fun bypassDeveloperSettings() {
        val hook = object : XC_MethodHook() {
            override fun beforeHookedMethod(p: MethodHookParam) {
                val k = p.args[1] as String?
                if (k == "development_settings_enabled" || k == "adb_enabled") {
                    p.result = 0
                }
            }
        }
        for (klass in listOf(Settings.Global::class.java, Settings.Secure::class.java, Settings.System::class.java)) {
            for (sig in listOf(
                arrayOf(android.content.ContentResolver::class.java, String::class.java),
                arrayOf(android.content.ContentResolver::class.java, String::class.java, Int::class.javaPrimitiveType),
            )) {
                try { XposedHelpers.findAndHookMethod(klass, "getInt", *sig, hook) } catch (_: Throwable) {}
            }
        }
        log("✓ Hooked Settings.*.getInt dev/adb → 0")
    }

    // ─── 3. RootBeer + SU checks → false ───
    private fun bypassRootBeer(cl: ClassLoader) {
        val rootBeerNames = listOf(
            "com.scottyab.rootbeer.RootBeer",
            "com.scottyab.rootbeer.RootBeerNative",
        )
        for (clsName in rootBeerNames) {
            try {
                val cls = XposedHelpers.findClass(clsName, cl)
                // Hook every public method returning boolean → false
                cls.declaredMethods.forEach { m ->
                    if (m.returnType == Boolean::class.javaPrimitiveType) {
                        try {
                            XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(false))
                        } catch (_: Throwable) {}
                    }
                }
                log("✓ Hooked $clsName (all boolean methods → false)")
            } catch (_: Throwable) {
                log("ℹ $clsName not present")
            }
        }
    }

    // ─── 4. AppSecurityModule check methods bypass ───
    private fun bypassAppSecurityModule(cl: ClassLoader) {
        val classes = listOf(
            "com.jio.jpss.AppSecurityModule",
            "com.jio.jpss.AppSecurityModule\$Companion",
        )
        val matchKeywords = listOf(
            "isRoot", "checkRoot", "isMock", "checkMock", "isDevelop", "checkDevelop",
            "isEmulator", "checkEmulator", "isDebugger", "checkDebugger",
            "verifyOtp", "isOtpRequired", "needOtp", "isVerified", "checkOtp"
        )
        for (clsName in classes) {
            try {
                val cls = XposedHelpers.findClass(clsName, cl)
                cls.declaredMethods.forEach { m ->
                    val name = m.name
                    val matches = matchKeywords.any { name.contains(it, ignoreCase = true) }
                    if (!matches) return@forEach
                    try {
                        val rt = m.returnType
                        val replacement = when {
                            rt == Boolean::class.javaPrimitiveType ->
                                // verify/isVerified should be true; everything else false
                                if (name.contains("verify", true) || name.contains("isVerified", true))
                                    XC_MethodReplacement.returnConstant(true)
                                else XC_MethodReplacement.returnConstant(false)
                            rt == Int::class.javaPrimitiveType ->
                                XC_MethodReplacement.returnConstant(0)
                            rt == String::class.java ->
                                XC_MethodReplacement.returnConstant("")
                            else -> XC_MethodReplacement.returnConstant(null)
                        }
                        XposedBridge.hookMethod(m, replacement)
                        log("✓ Hooked $clsName.$name → bypass")
                    } catch (_: Throwable) {}
                }
            } catch (_: Throwable) {
                log("ℹ $clsName not present")
            }
        }
    }

    // ─── 5. OTP flow short-circuit ───
    private fun bypassOtpFlow(cl: ClassLoader) {
        // Force VerifyOtp / SendOtp asynctasks to silently succeed without server call.
        val targets = listOf(
            "com.jio.jpss.asynctask.SendOtp",
            "com.jio.jpss.asynctask.VerifyOtp",
        )
        for (t in targets) {
            try {
                val cls = XposedHelpers.findClass(t, cl)
                // Override doInBackground to return a fake-success object
                cls.declaredMethods.forEach { m ->
                    if (m.name == "doInBackground") {
                        try {
                            XposedBridge.hookMethod(m, object : XC_MethodReplacement() {
                                override fun replaceHookedMethod(p: MethodHookParam): Any? {
                                    log("OTP shortcircuit: $t.doInBackground returning fake-success")
                                    // Return a JSONObject string the app probably expects
                                    return """{"IsSuccessful":true,"Status":"VERIFIED","Message":"OK"}"""
                                }
                            })
                        } catch (_: Throwable) {}
                    }
                    if (m.name == "onPostExecute") {
                        try {
                            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                                override fun beforeHookedMethod(p: MethodHookParam) {
                                    log("OTP onPostExecute called for $t — letting through")
                                }
                            })
                        } catch (_: Throwable) {}
                    }
                }
                log("✓ Hooked $t (OTP shortcircuit)")
            } catch (_: Throwable) {
                log("ℹ $t not present")
            }
        }
    }

    // ─── 6. Inject Auto-Reach floating button ───
    private fun injectAutoReachButton(cl: ClassLoader) {
        try {
            val mainCls = XposedHelpers.findClass("com.jio.jpss.MainActivity", cl)
            XposedHelpers.findAndHookMethod(
                mainCls, "onCreate", Bundle::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(p: MethodHookParam) {
                        val act = p.thisObject as Activity
                        addFab(act)
                    }
                }
            )
            log("✓ Hooked MainActivity.onCreate (FAB inject)")
        } catch (t: Throwable) {
            log("✗ FAB inject failed: $t")
        }
    }

    private fun addFab(activity: Activity) {
        try {
            activity.window.decorView.post {
                val root = activity.findViewById<FrameLayout>(android.R.id.content)
                if (root == null || root.findViewWithTag<View>("jpw_auto_reach_fab") != null) return@post

                val ctx = activity
                val fab = android.widget.Button(ctx).apply {
                    text = "⚡ AUTO-REACH"
                    setTextColor(android.graphics.Color.WHITE)
                    textSize = 13f
                    setPadding(dp(ctx, 16), dp(ctx, 10), dp(ctx, 16), dp(ctx, 10))
                    background = makeRedGradient(ctx)
                    elevation = dp(ctx, 8).toFloat()
                    tag = "jpw_auto_reach_fab"
                    setOnClickListener { onAutoReachClicked(ctx) }
                }
                val lp = FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    gravity = Gravity.BOTTOM or Gravity.END
                    rightMargin = dp(ctx, 16)
                    bottomMargin = dp(ctx, 24)
                }
                root.addView(fab, lp)
                log("✓ AUTO-REACH button injected into MainActivity")
            }
        } catch (t: Throwable) {
            log("addFab failed: $t")
        }
    }

    private fun onAutoReachClicked(ctx: Context) {
        val prefs = ctx.getSharedPreferences("com.jio.jpss_preferences", Context.MODE_PRIVATE)
        val savedPass = prefs.getString("password", "") ?: prefs.getString("Password", "") ?: ""
        val savedTechId = prefs.getString("technician_id", "") ?: ""
        if (savedPass.isEmpty() || savedTechId.isEmpty()) {
            if (ctx is Activity) {
                val lp = android.widget.LinearLayout(ctx).apply {
                    orientation = android.widget.LinearLayout.VERTICAL
                    setPadding(48, 24, 48, 16)
                }
                val techIdField = android.widget.EditText(ctx).apply {
                    hint = "Enter Technician ID"
                    inputType = android.text.InputType.TYPE_CLASS_TEXT
                    if (savedTechId.isNotEmpty()) setText(savedTechId)
                }
                val passField = android.widget.EditText(ctx).apply {
                    hint = "Enter JPW password"
                    inputType = android.text.InputType.TYPE_CLASS_TEXT or
                                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
                    if (savedPass.isNotEmpty()) setText(savedPass)
                }
                lp.addView(techIdField)
                lp.addView(passField)
                android.app.AlertDialog.Builder(ctx)
                    .setTitle("Login Required")
                    .setMessage("Enter Technician ID and JPW password:")
                    .setView(lp)
                    .setPositiveButton("Save & Run") { _, _ ->
                        val id = techIdField.text.toString().trim()
                        val pass = passField.text.toString().trim()
                        if (id.isNotEmpty() && pass.isNotEmpty()) {
                            prefs.edit().putString("technician_id", id).putString("password", pass).apply()
                            Toast.makeText(ctx, "Credentials saved! Starting REACH…", Toast.LENGTH_SHORT).show()
                            Thread {
                                try { autoReach(ctx) } catch (t: Throwable) {
                                    log("autoReach error: $t")
                                    showToast(ctx, "REACH failed: ${t.message}")
                                }
                            }.start()
                        } else {
                            Toast.makeText(ctx, "Both Technician ID and Password are required", Toast.LENGTH_SHORT).show()
                        }
                    }
                    .setNegativeButton("Cancel", null)
                    .show()
            }
            return
        }
        Toast.makeText(ctx, "Auto-Reach: running inside JPW process…", Toast.LENGTH_SHORT).show()
        Thread {
            try {
                autoReach(ctx)
            } catch (t: Throwable) {
                log("autoReach error: $t")
                showToast(ctx, "REACH failed: ${t.message}")
            }
        }.start()
    }

    private val REACH_URL = "https://jpw.jio.com/lco/api/workorder-maintenance/WorkOrder/UpdateWorkOrder"
    private val WO_URL = "https://jpw.jio.com/lco/api/workorder-inquiry/WorkOrder/GetWorkOrderList"
    private val LOGIN_URL = "https://jpw.jio.com/api/login/SAML/UserLogin"
    private val PREF_NAME = "jpwreach_lsposed_prefs"
    private val APP_VERSION = "2.1.0"
    private val DEVICE_ID = "ffae0907fcc794e3"
    private val FCM_ID = "eXVTratwRhW6CXT6phHtuD:APA91bGQ2Q4nGz9W6haWztTixJB98ZcLxoi7UUO8pV26f-UAj0-OYRQPUb8WVhxTlXglmJDW57j0FuFhl0bXUOhk9a5cvhLEcNwiGWgHISlRQ45GK11OHBI"

    private val HMAC_SECRET = "2f41ab9cd96ef54252ea0185be4e6e87"
    private val CUST_PLAN_KEY = "NWg0ZHkwM2MyN2JkNDRiNTg0MTUxOWFkZjRlMzk0Y2FkMThiYTIyMTA5NEck"
    private val CUST_PLAN_IV = "MmU4YTk4ZGUtZGQ1OC00NWY2LWFlYjgtNzMyODIyYTE3NDRm"
    private val CUST_PLAN_HARDCODED = "YGNyzBQYJRQy/Qa9bN1uyTkeuJ8d5v1KIkSK/hKK7KJntzp+rDEBIB1NZ0VUTpr40HqAKt3FZlTbsut9QHECWsMdwiu/0hW6BsMxx08YqLE="

    private val sessionCookies = mutableMapOf<String, String>()

    private fun autoReach(ctx: Context) {
        showToast(ctx, "Step 1/4: Getting session…")

        // First try to load cookies from persistent storage (captured during login)
        loadCookies(ctx)

        val prefs = ctx.getSharedPreferences("com.jio.jpss_preferences", Context.MODE_PRIVATE)
        val jioCenterId = prefs.getString("jio_center_id", "") ?: ""
        val techId = prefs.getString("user_id", "") ?:
                    prefs.getString("UserID", "") ?:
                    prefs.getString("technician_id", "") ?:
                    prefs.getString("TechnicianID", "") ?: ""
        log("Cookies: ${sessionCookies.size} items, JioCenter: $jioCenterId, TechId: $techId")

        // If no cookies, try to login using stored credentials
        var loggedIn = false
        if (sessionCookies.isEmpty() && techId.isNotEmpty()) {
            val techPass = prefs.getString("password", "") ?:
                          prefs.getString("Password", "") ?: ""
            if (techPass.isNotEmpty()) {
                showToast(ctx, "No session. Logging in...")
                loggedIn = doLogin(ctx, techId, techPass)
            }
        }

        if (sessionCookies.isEmpty()) {
            showToast(ctx, "No session — login failed or missing. Check credentials.")
            return
        }

        // Step 2: Fetch work orders
        showToast(ctx, "Step 2/4: Fetching WOs…")
        val woPayload = JSONObject()
        woPayload.put("TechnicianID", techId)
        woPayload.put("IsHSOUser", false)
        woPayload.put("WorkOrderStatus", JSONArray().put(""))
        woPayload.put("PageSize", 200)
        woPayload.put("offsetValue", 0)
        woPayload.put("TechnicianDesignationType", "Technician")

        val woHeaders = mutableMapOf("Referer" to "https://jpw.jio.com/v1/workOrderListV3")
        if (jioCenterId.isNotEmpty()) woHeaders["X-JioCenterId"] = jioCenterId
        val woResult = httpPostNoSig(WO_URL, woPayload.toString(), woHeaders)
        log("WO response: ${woResult.substring(0, minOf(500, woResult.length))}")

        val woJson = try { JSONObject(woResult) } catch (e: Exception) {
            log("WO JSON parse error: $e, raw: $woResult")
            showToast(ctx, "WO fetch failed! Empty response. Login first.")
            return
        }
        if (!woJson.optBoolean("IsSuccessful", false)) {
            val err = woJson.optString("Message", "unknown")
            showToast(ctx, "WO fetch failed: $err")
            return
        }
        val orders = woJson.optJSONArray("lstWorkOrders") ?: JSONArray()
        val total = orders.length()
        showToast(ctx, "Step 3/4: REACHing $total WOs…")

        // Step 3: REACH each WO (matches Burp capture exactly)
        var success = 0
        var fail = 0
        for (i in 0 until total) {
            val wo = orders.getJSONObject(i)
            val woId = wo.optString("WorkOrderID", "")
            if (woId.isEmpty()) continue
            val subType = wo.optString("WorkOrderSubType", "22")
            val woType = wo.optString("WorkOrderType", "ZFVO")
            val address = wo.optJSONObject("CustomerDetails")?.optJSONObject("Address") ?: JSONObject()
            val buildingId = address.optString("BuildingID", "")
            val lat = address.optDouble("Latitude", 23.950524158)
            val lng = address.optDouble("Longitude", 87.676930303)
            val custPlan = wo.optString("CustomerPlan", "")

            val reachPayload = JSONObject()
            reachPayload.put("ActionCode", "ZA26")
            reachPayload.put("BuildingID", buildingId)
            reachPayload.put("StatusCode", "CL09")
            reachPayload.put("TechnicianLatitude", lat.toString())
            reachPayload.put("TechnicianLongitude", lng.toString())
            reachPayload.put("UpdatedBy", techId)
            reachPayload.put("WorkOrderID", woId)
            reachPayload.put("WorkOrderSubType", subType)
            reachPayload.put("WorkOrderType", woType)
            reachPayload.put("woForC6Customer", subType in listOf("13", "15"))
            reachPayload.put("CustomerPlan", if (custPlan.isNotEmpty()) custPlan else CUST_PLAN_HARDCODED)

            val reachHeaders = mutableMapOf(
                "Referer" to "https://jpw.jio.com/retailv1/workOrderV3/reached",
            )
            if (jioCenterId.isNotEmpty()) reachHeaders["X-JioCenterId"] = jioCenterId
            try {
                val bodyStr = toSortedJsonString(reachPayload)
                reachHeaders["X-Signature"] = generateSignature(bodyStr)
                val resp = httpPostNoSig(REACH_URL, bodyStr, reachHeaders)
                val rj = JSONObject(resp)
                if (rj.optBoolean("IsSuccessful", false)) success++ else {
                    fail++
                    log("REACH fail for $woId: $resp")
                }
            } catch (e: Exception) {
                fail++
                log("REACH error for $woId: $e")
            }
        }

        showToast(ctx, "Done! REACHED: $success, Failed: $fail out of $total")
    }

    private fun doLogin(ctx: Context, techId: String, techPass: String): Boolean {
        showToast(ctx, "Logging in as $techId...")
        val payload = JSONObject()
        payload.put("UserName", techId)
        payload.put("Password", techPass)
        payload.put("Handset", "android")
        payload.put("FCMID", FCM_ID)
        payload.put("DeviceId", DEVICE_ID)
        payload.put("AppVersion", APP_VERSION)

        val loginHeaders = mutableMapOf("Referer" to "https://jpw.jio.com/v1/OIDLOGIN")
        val response = httpPostNoSig(LOGIN_URL, payload.toString(), loginHeaders)
        return try {
            val json = JSONObject(response)
            val ok = json.optBoolean("IsSuccessful", false)
            if (ok) {
                showToast(ctx, "Login OK! Session: ${json.optString("sessionId","")}")
                log("Login successful, sessionId: ${json.optString("sessionId","")}")
                // Also set JPSSSessionID cookie from login response
                val sid = json.optString("sessionId", "")
                if (sid.isNotEmpty() && !sessionCookies.containsKey("JPSSSessionID")) {
                    sessionCookies["JPSSSessionID"] = sid
                }
                saveCookies(ctx)
                true
            } else {
                val err = json.optJSONObject("ErrorInfo")
                val msg = err?.optString("UserMessage", err?.optString("Reason", "unknown")) ?: "unknown"
                showToast(ctx, "Login failed: $msg")
                false
            }
        } catch (e: Exception) {
            log("Login parse error: $e, raw: $response")
            showToast(ctx, "Login failed: ${e.message}")
            false
        }
    }

    private fun saveCookies(ctx: Context) {
        try {
            val prefs = ctx.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            val cookieStr = sessionCookies.entries.joinToString("||") { "${it.key}=${it.value}" }
            prefs.edit().putString("saved_cookies", cookieStr).apply()
            log("Saved ${sessionCookies.size} cookies")
        } catch (t: Throwable) { log("saveCookies error: $t") }
    }

    private fun loadCookies(ctx: Context) {
        try {
            val prefs = ctx.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            val cookieStr = prefs.getString("saved_cookies", "") ?: ""
            if (cookieStr.isNotEmpty()) {
                cookieStr.split("||").forEach { pair ->
                    val parts = pair.split("=", limit = 2)
                    if (parts.size == 2) sessionCookies[parts[0].trim()] = parts[1].trim()
                }
                log("Loaded ${sessionCookies.size} saved cookies")
            }
        } catch (t: Throwable) { log("loadCookies error: $t") }
    }

    private fun toSortedJsonString(obj: JSONObject): String {
        val sorted = TreeMap<String, Any?>()
        obj.keys().forEach { key ->
            val value = obj.get(key)
            when (value) {
                is JSONObject -> sorted[key] = toSortedJsonString(value)
                is JSONArray -> {
                    val arr = mutableListOf<Any?>()
                    for (i in 0 until value.length()) {
                        val v = value[i]
                        arr.add(if (v is JSONObject) toSortedJsonString(v) else v)
                    }
                    sorted[key] = arr
                }
                is String -> sorted[key] = value
                is Number -> sorted[key] = value
                is Boolean -> sorted[key] = value
                else -> if (value == JSONObject.NULL) sorted[key] = null else sorted[key] = value.toString()
            }
        }
        val sb = StringBuilder("{")
        sorted.entries.forEachIndexed { idx, (k, v) ->
            if (idx > 0) sb.append(",")
            sb.append("\"$k\":")
            when (v) {
                null -> sb.append("null")
                is String -> sb.append("\"${v.replace("\\", "\\\\").replace("\"", "\\\"")}\"")
                is Number -> sb.append(v.toString())
                is Boolean -> sb.append(v.toString())
                else -> sb.append(v.toString())
            }
        }
        sb.append("}")
        return sb.toString()
    }

    private fun generateSignature(body: String): String {
        return try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(HMAC_SECRET.toByteArray(Charsets.UTF_8), "HmacSHA256"))
            Base64.encodeToString(mac.doFinal(body.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
        } catch (e: Exception) {
            log("generateSignature error: $e")
            ""
        }
    }

    private fun httpPostNoSig(urlStr: String, body: String, extraHeaders: Map<String, String>): String {
        val url = URL(urlStr)
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.doInput = true
        conn.connectTimeout = 30000
        conn.readTimeout = 30000
        conn.setRequestProperty("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("Accept", "*/*")
        conn.setRequestProperty("Origin", "https://jpw.jio.com")
        conn.setRequestProperty("Referer", "https://jpw.jio.com/retailv1/workOrderV3/reached")
        conn.setRequestProperty("Sec-Fetch-Site", "same-origin")
        conn.setRequestProperty("Sec-Fetch-Mode", "cors")
        conn.setRequestProperty("Sec-Fetch-Dest", "empty")
        conn.setRequestProperty("Sec-Ch-Ua", "\"Not-A.Brand\";v=\"24\", \"Chromium\";v=\"146\"")
        conn.setRequestProperty("Sec-Ch-Ua-Mobile", "?0")
        conn.setRequestProperty("Sec-Ch-Ua-Platform", "\"Windows\"")
        conn.setRequestProperty("Accept-Language", "en-US,en;q=0.9")

        val cookieStr = sessionCookies.entries.joinToString("; ") { "${it.key}=${it.value}" }
        if (cookieStr.isNotEmpty()) conn.setRequestProperty("Cookie", cookieStr)
        extraHeaders.forEach { (k, v) -> conn.setRequestProperty(k, v) }

        OutputStreamWriter(conn.outputStream).use { it.write(body) }

        val responseCode = conn.responseCode
        val responseBody = try {
            conn.inputStream.bufferedReader().readText()
        } catch (_: Exception) {
            conn.errorStream?.bufferedReader()?.readText() ?: ""
        }
        log("HTTP $responseCode for $urlStr, body len=${responseBody.length}")

        conn.headerFields?.forEach { (key, values) ->
            if (key != null && key.equals("Set-Cookie", ignoreCase = true)) {
                values.forEach { cookieStr ->
                    val parts = cookieStr.split(";")[0].split("=", limit = 2)
                    if (parts.size == 2) sessionCookies[parts[0].trim()] = parts[1].trim()
                }
            }
        }
        conn.disconnect()
        return responseBody
    }

    private fun showToast(ctx: Context, msg: String) {
        try {
            Handler(Looper.getMainLooper()).post { Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show() }
        } catch (_: Throwable) {}
    }

    private fun dp(ctx: Context, v: Int): Int =
        (v * ctx.resources.displayMetrics.density).toInt()

    // ─── 7. App signature + Play Integrity bypass ───
    private fun bypassSignatureAndIntegrity(cl: ClassLoader) {
        // 1. CommonUtility.checkAPKInstallationValidation → false (not cloned)
        try {
            XposedHelpers.findAndHookMethod(
                "com.jio.jpss.utils.CommonUtility",
                cl, "checkAPKInstallationValidation",
                Context::class.java,
                XC_MethodReplacement.returnConstant(false)
            )
            log("✓ Hooked CommonUtility.checkAPKInstallationValidation → false")
        } catch (t: Throwable) { log("✗ checkAPKInstallation: $t") }

        // 2. CommonUtility.checkIfAppCloned → false
        try {
            XposedHelpers.findAndHookMethod(
                "com.jio.jpss.utils.CommonUtility",
                cl, "checkIfAppCloned",
                Context::class.java, String::class.java,
                XC_MethodReplacement.returnConstant(false)
            )
            log("✓ Hooked CommonUtility.checkIfAppCloned → false")
        } catch (t: Throwable) { log("✗ checkIfAppCloned: $t") }

        // 3. AppSignatureHelper.getAppSignatures → null (bypass hash check)
        try {
            XposedHelpers.findAndHookMethod(
                "com.jio.jpss.AppSignatureHelper",
                cl, "getAppSignatures",
                XC_MethodReplacement.returnConstant(null)
            )
            log("✓ Hooked AppSignatureHelper.getAppSignatures → null")
        } catch (t: Throwable) { log("✗ AppSignatureHelper: $t") }

        // 4. CommonUtility.getSigningCertSha256 → return expected hash
        try {
            XposedHelpers.findAndHookMethod(
                "com.jio.jpss.utils.CommonUtility",
                cl, "getSigningCertSha256",
                Context::class.java,
                XC_MethodReplacement.returnConstant(
                    "dba24e5c252891027c96b8d21b1659dad47219f5d4e0be0bd898640509ca380c"
                )
            )
            log("✓ Hooked getSigningCertSha256 → original Jio cert hash")
        } catch (t: Throwable) { log("✗ getSigningCertSha256: $t") }

        // 5. ValidateAppCheckAsyncTask → neutralized (sends clone metadata to server)
        try {
            val vac = XposedHelpers.findClass("com.jio.jpss.asynctask.ValidateAppCheckAsyncTask", cl)
            vac.declaredMethods.forEach { m ->
                if (m.name == "doInBackground") {
                    XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(null))
                }
                if (m.name == "onPostExecute") {
                    XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(null))
                }
            }
            log("✓ Hooked ValidateAppCheckAsyncTask → neutralized")
        } catch (t: Throwable) { log("✗ ValidateAppCheckAsyncTask: $t") }

        // 6. getAppIntegrityToken → left unhooked (app needs real token for its own operations)
        log("ℹ getAppIntegrityToken left unhooked — app uses real Google Play Integrity")
    }

    // ─── 8. SIM verification bypass ───
    private fun bypassSimVerification(cl: ClassLoader) {
        // Hook TelephonyManager methods → Jio cannot fingerprint your SIM
        try {
            val tm = Class.forName("android.telephony.TelephonyManager")
            val noopFalse = XC_MethodReplacement.returnConstant(false)
            val noopNull  = XC_MethodReplacement.returnConstant(null)
            val noopZero  = XC_MethodReplacement.returnConstant(0)
            val noopEmpty = XC_MethodReplacement.returnConstant("")

            // Methods returning sensitive identifiers — neutralise them
            val emptyStringMethods = listOf(
                "getSubscriberId",         // IMSI
                "getLine1Number",          // Phone number
                "getSimSerialNumber",      // ICCID
                "getDeviceId",             // IMEI
                "getImei",                 // IMEI (newer)
                "getMeid",                 // CDMA MEID
                "getSimOperator",
                "getSimOperatorName",
                "getNetworkOperator",
                "getNetworkOperatorName",
                "getSimCountryIso",
                "getNetworkCountryIso",
            )
            for (mName in emptyStringMethods) {
                tm.declaredMethods.filter { it.name == mName }.forEach { m ->
                    try {
                        XposedBridge.hookMethod(m, noopEmpty)
                    } catch (_: Throwable) {}
                }
            }
            // Methods returning booleans about SIM state → false
            val booleanMethods = listOf("hasIccCard", "isNetworkRoaming", "isDataEnabled")
            for (mName in booleanMethods) {
                tm.declaredMethods.filter { it.name == mName }.forEach { m ->
                    try { XposedBridge.hookMethod(m, noopFalse) } catch (_: Throwable) {}
                }
            }
            // getSimState → 5 (SIM_STATE_READY) so the app thinks SIM is fine
            try {
                tm.declaredMethods.filter { it.name == "getSimState" }.forEach { m ->
                    XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(5))
                }
            } catch (_: Throwable) {}

            log("✓ TelephonyManager SIM identifiers spoofed")
        } catch (t: Throwable) {
            log("✗ SIM bypass setup: $t")
        }

        // Also hook Jio app's internal SIM verification methods (keyword-based)
        val simKeywords = listOf(
            "verifySim", "validateSim", "isSimValid", "checkSim", "matchSim",
            "isSimRegistered", "validatePhone", "verifyPhone", "isPhoneValid",
            "isMobileMatched", "matchPhoneNumber", "phoneVerification"
        )
        val candidateClasses = listOf(
            "com.jio.jpss.AppSecurityModule",
            "com.jio.jpss.AppSecurityModule\$Companion",
            "com.jio.jpss.utility.SimVerifier",
            "com.jio.jpss.utility.PhoneVerifier",
            "com.jio.jpss.NativeHandler",
        )
        for (clsName in candidateClasses) {
            try {
                val cls = XposedHelpers.findClass(clsName, cl)
                cls.declaredMethods.forEach { m ->
                    val matches = simKeywords.any { m.name.contains(it, ignoreCase = true) }
                    if (!matches) return@forEach
                    try {
                        val rt = m.returnType
                        val replacement = when (rt) {
                            Boolean::class.javaPrimitiveType ->
                                XC_MethodReplacement.returnConstant(true)
                            Int::class.javaPrimitiveType ->
                                XC_MethodReplacement.returnConstant(0)
                            String::class.java ->
                                XC_MethodReplacement.returnConstant("")
                            else -> XC_MethodReplacement.returnConstant(null)
                        }
                        XposedBridge.hookMethod(m, replacement)
                        log("✓ Hooked $clsName.${m.name} → SIM bypass")
                    } catch (_: Throwable) {}
                }
            } catch (_: Throwable) {
                // class not present in this build — ignore
            }
        }
    }

    // ─── 8. Auto-capture cookies from the app's own HTTP responses ───
    private fun hookHttpCookieCapture(cl: ClassLoader) {
        // Hook URLConnection.getHeaderField() to capture Set-Cookie headers.
        // URLConnection is the parent of HttpURLConnection, and this method is virtual.
        try {
            XposedBridge.hookAllMethods(
                java.net.URLConnection::class.java, "getHeaderField",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(p: MethodHookParam) {
                        try {
                            val conn = p.thisObject as? java.net.HttpURLConnection ?: return
                            val url = conn.url?.toString() ?: return
                            if (!url.contains("jpw.jio.com")) return
                            val key = p.args.getOrNull(0) as? String ?: return
                            if (key.equals("Set-Cookie", ignoreCase = true)) {
                                val value = (p.result as? String) ?: return
                                val parts = value.split(";")[0].split("=", limit = 2)
                                if (parts.size == 2) {
                                    sessionCookies[parts[0].trim()] = parts[1].trim()
                                    log("Cookie: ${parts[0]}")
                                }
                            }
                        } catch (_: Throwable) {}
                    }
                }
            )
            log("✓ Hooked URLConnection.getHeaderField for Set-Cookie")
        } catch (t: Throwable) { log("ℹ URLConnection hook: $t") }

        // Also hook HttpURLConnection.getHeaderFields which returns the full header map
        try {
            XposedBridge.hookAllMethods(
                java.net.HttpURLConnection::class.java, "getHeaderFields",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(p: MethodHookParam) {
                        try {
                            val conn = p.thisObject as java.net.HttpURLConnection
                            val url = conn.url?.toString() ?: return
                            if (!url.contains("jpw.jio.com")) return
                            @Suppress("UNCHECKED_CAST")
                            val headers = p.result as? Map<String, MutableList<String>> ?: return
                            var n = 0
                            headers.forEach { (key, values) ->
                                if (key != null && key.equals("Set-Cookie", ignoreCase = true)) {
                                    values.forEach { cookieStr ->
                                        val parts = cookieStr.split(";")[0].split("=", limit = 2)
                                        if (parts.size == 2) {
                                            sessionCookies[parts[0].trim()] = parts[1].trim()
                                            n++
                                        }
                                    }
                                }
                            }
                            if (n > 0) log("Cookies: $n from $url")
                        } catch (_: Throwable) {}
                    }
                }
            )
            log("✓ Hooked HttpURLConnection.getHeaderFields")
        } catch (t: Throwable) { log("ℹ getHeaderFields: $t") }

        // Fallback: okhttp3.CookieJar if present in this RN version
        try {
            val jarCls = XposedHelpers.findClass("okhttp3.CookieJar", cl)
            XposedBridge.hookAllMethods(jarCls, "saveFromResponse", object : XC_MethodHook() {
                override fun afterHookedMethod(p: MethodHookParam) {
                    try {
                        @Suppress("UNCHECKED_CAST")
                        val cookies = p.args[1] as? List<Any> ?: return
                        var n = 0
                        for (cookie in cookies) {
                            val parts = cookie.toString().split(";")[0].split("=", limit = 2)
                            if (parts.size == 2) { sessionCookies[parts[0].trim()] = parts[1].trim(); n++ }
                        }
                        if (n > 0) log("Cookies: $n via okhttp3")
                    } catch (_: Throwable) {}
                }
            })
            log("✓ Hooked okhttp3.CookieJar")
        } catch (t: Throwable) { log("ℹ okhttp3.CookieJar: $t") }
    }

    // ─── 9. Broadcast trigger for headless REACH (adb shell am broadcast ...) ───
    private fun registerBroadcastTrigger(cl: ClassLoader) {
        try {
            val mainCls = XposedHelpers.findClass("com.jio.jpss.MainActivity", cl)
            XposedHelpers.findAndHookMethod(
                mainCls, "onCreate", Bundle::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(p: MethodHookParam) {
                        try {
                            val act = p.thisObject as Activity
                            val ctx = act.applicationContext
                            val filter = IntentFilter("com.jpwreach.TRIGGER_REACH")
                            ctx.registerReceiver(object : BroadcastReceiver() {
                                override fun onReceive(context: Context?, intent: Intent?) {
                                    try {
                                        val techId = intent?.getStringExtra("techId") ?: return
                                        val password = intent?.getStringExtra("password") ?: return
                                        log("Broadcast REACH triggered for $techId")
                                        sessionCookies.clear()
                                        // Save credentials into module's prefs
                                        val prefs = ctx.getSharedPreferences("com.jio.jpss_preferences", Context.MODE_PRIVATE)
                                        prefs.edit().putString("technician_id", techId).putString("user_id", techId)
                                            .putString("password", password).putString("Password", password).apply()
                                        autoReach(ctx)
                                    } catch (t: Throwable) {
                                        log("Broadcast REACH handler error: $t")
                                    }
                                }
                            }, filter)
                            log("✓ Broadcast receiver registered: com.jpwreach.TRIGGER_REACH")
                        } catch (t: Throwable) {
                            log("✗ Broadcast register error: $t")
                        }
                    }
                }
            )
        } catch (t: Throwable) { log("✗ registerBroadcastTrigger: $t") }
    }

    private fun makeRedGradient(ctx: Context): android.graphics.drawable.GradientDrawable {
        val d = android.graphics.drawable.GradientDrawable(
            android.graphics.drawable.GradientDrawable.Orientation.TL_BR,
            intArrayOf(0xFFe60012.toInt(), 0xFFff3a44.toInt())
        )
        d.cornerRadius = dp(ctx, 28).toFloat()
        return d
    }
}
