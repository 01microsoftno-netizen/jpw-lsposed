package com.jpwreach.auto

import android.os.Bundle
import android.widget.*
import android.widget.LinearLayout
import androidx.appcompat.app.AppCompatActivity
import com.google.gson.Gson
import kotlinx.coroutines.*
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import android.util.Base64

class MainActivity : AppCompatActivity() {

    private val SECRET_KEY = "2f41ab9cd96ef54252ea0185be4e6e87"
    private val HMAC_ALGO = "HmacSHA256"
    private val BASE = "https://jpw.jio.com/lco/api/workorder-maintenance/WorkOrder/UpdateWorkOrder"
    private val gson = Gson()
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private lateinit var statusText: TextView
    private lateinit var idField: EditText
    private lateinit var passField: EditText
    private lateinit var goBtn: Button
    private lateinit var resultText: TextView

    private var sessionCookies = mutableMapOf<String, String>()
    private var jioCenterId = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val prefs = getSharedPreferences("jpw_auto", MODE_PRIVATE)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }

        statusText = TextView(this).apply { text = "JPW Auto-Reach Companion"; textSize = 18f; setPadding(0,0,0,24) }
        root.addView(statusText)

        root.addView(TextView(this).apply { text = "Technician ID" })
        idField = EditText(this).apply {
            hint = "0691039428"
            setText(prefs.getString("tech_id", ""))
        }
        root.addView(idField)

        root.addView(TextView(this).apply { text = "Password" })
        passField = EditText(this).apply {
            hint = "password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            setText(prefs.getString("tech_pass", ""))
        }
        root.addView(passField)

        goBtn = Button(this).apply {
            text = "AUTO-REACH ALL WOs"
            setOnClickListener { startReach() }
        }
        root.addView(goBtn)

        resultText = TextView(this).apply {
            textSize = 12f
            setPadding(0, 16, 0, 0)
        }
        root.addView(resultText)

        setContentView(root)

        // Check if launched from LSPosed with extras (credentials or cookies)
        intent?.let {
            val cookiesStr = it.getStringExtra("cookies")
            if (cookiesStr != null) {
                // Parse cookie string from JPW app's WebView
                cookiesStr.split(";").forEach { pair ->
                    val parts = pair.trim().split("=", limit = 2)
                    if (parts.size == 2) sessionCookies[parts[0].trim()] = parts[1].trim()
                }
            }
            val jioId = it.getStringExtra("jio_center_id")
            if (jioId != null) jioCenterId = jioId

            val id = it.getStringExtra("tech_id") ?: prefs.getString("tech_id", "") ?: ""
            val pass = it.getStringExtra("tech_pass") ?: prefs.getString("tech_pass", "") ?: ""
            if (id.isNotEmpty() && pass.isNotEmpty()) {
                idField.setText(id)
                passField.setText(pass)
                startReach()
            } else if (sessionCookies.isNotEmpty()) {
                // No credentials but we have cookies - try using them
                startReachWithCookies()
            }
        }
    }

    private fun startReachWithCookies() {
        val techId = idField.text.toString().trim()
        if (techId.isEmpty()) {
            toast("Enter Technician ID first!")
            return
        }
        goBtn.isEnabled = false
        resultText.text = ""
        scope.launch { doReach(techId, "") }
    }

    private fun startReach() {
        val techId = idField.text.toString().trim()
        val techPass = passField.text.toString().trim()
        if (techId.isEmpty() || techPass.isEmpty()) {
            toast("Enter ID and Password first!")
            return
        }
        getSharedPreferences("jpw_auto", MODE_PRIVATE).edit().apply {
            putString("tech_id", techId)
            putString("tech_pass", techPass)
            apply()
        }
        goBtn.isEnabled = false
        resultText.text = ""
        scope.launch { doReach(techId, techPass) }
    }

    private suspend fun doReach(techId: String, techPass: String) = withContext(Dispatchers.IO) {
        showStatus("Logging in...")
        try {
            // Step 1: Login
            val loginPayload = mapOf(
                "UserName" to techId,
                "Password" to techPass,
                "Handset" to "android",
                "FCMID" to "eXVTratwRhW6CXT6phHtuD:APA91bGQ2Q4nGz9W6haWztTixJB98ZcLxoi7UUO8pV26f-UAj0-OYRQPUb8WVhxTlXglmJDW57j0FuFhl0bXUOhk9a5cvhLEcNwiGWgHISlRQ45GK11OHBI",
                "DeviceId" to "ffae0907fcc794e3",
                "AppVersion" to "2.1.0"
            )
            val loginUrl = "https://jpw.jio.com/api/login/SAML/UserLogin"
            val loginResult = httpPost(loginUrl, loginPayload, mapOf("Referer" to "https://jpw.jio.com/v1/OIDLOGIN"))
            sessionCookies.clear()
            sessionCookies.putAll(loginResult.cookies)
            val loginData = gson.fromJson(loginResult.body, Map::class.java)
            if (loginData["IsSuccessful"] != true) {
                val err = (loginData["ErrorInfo"] as? Map<*,*>)?.get("UserMessage") ?: "Login failed"
                showStatus("Login failed: $err")
                enableBtn()
                return@withContext
            }
            showStatus("Login OK! Getting JioCenterId...")

            // Step 2: Get JioCenterId
            val checkPayload = mapOf("DeviceID" to "ffae0907fcc794e3", "UserID" to techId, "Version" to "2.1.0")
            val checkUrl = "https://jpw.jio.com/api/login/SAML/Auth/IsValidOJETSession"
            val checkResult = httpPost(checkUrl, checkPayload, mapOf("Referer" to "https://jpw.jio.com/v1/OrderModule?JPSS_ID=" + Base64.encodeToString(techId.toByteArray(), Base64.NO_WRAP)))
            sessionCookies.putAll(checkResult.cookies)
            val checkData = gson.fromJson(checkResult.body, Map::class.java)
            if (checkData["IsSuccessful"] == true) {
                val profile = checkData["UserProfile"] as? Map<*,*>
                jioCenterId = profile?.get("JioCenterID") as? String ?: ""
                showStatus("JioCenter: $jioCenterId")
            } else {
                showStatus("JioCenter lookup failed, continuing...")
            }

            // Step 3: Get WOs
            showStatus("Fetching WOs...")
            val woPayload = mapOf(
                "TechnicianID" to techId,
                "IsHSOUser" to false,
                "WorkOrderStatus" to listOf(""),
                "PageSize" to 200,
                "offsetValue" to 0,
                "TechnicianDesignationType" to "Technician"
            )
            val woUrl = "https://jpw.jio.com/lco/api/workorder-inquiry/WorkOrder/GetWorkOrderList"
            val woHeaders = mutableMapOf("Referer" to "https://jpw.jio.com/v1/workOrderListV3")
            if (jioCenterId.isNotEmpty()) woHeaders["X-JioCenterId"] = jioCenterId
            val woResult = httpPost(woUrl, woPayload, woHeaders)
            sessionCookies.putAll(woResult.cookies)
            val woData = gson.fromJson(woResult.body, Map::class.java)
            if (woData["IsSuccessful"] != true) {
                showStatus("WO fetch failed!")
                enableBtn()
                return@withContext
            }
            val orders = (woData["lstWorkOrders"] as? List<*>) ?: emptyList<Any>()
            showStatus("Found ${orders.size} WOs. REACHing...")

            // Step 4: REACH each WO
            var successCount = 0
            var failCount = 0
            for (order in orders) {
                val wo = order as Map<*,*>
                val woId = wo["WorkOrderID"] as? String ?: continue
                val status = wo["strStatus"] as? String ?: ""

                showStatus("WO $woId ($status)...")

                val address = wo["CustomerDetails"]?.let { 
                    (it as? Map<*,*>)?.get("Address") as? Map<*,*>
                } ?: emptyMap<Any, Any>()
                val subType = (wo["WorkOrderSubType"] ?: "22").toString()
                val woType = (wo["WorkOrderType"] ?: "ZFVO").toString()
                val buildingId = (address["BuildingID"] ?: "").toString()
                val lat = (address["Latitude"] ?: "23.950524158").toString()
                val lng = (address["Longitude"] ?: "87.676930303").toString()

                val reachPayload = linkedMapOf(
                    "ActionCode" to "ZA26",
                    "BuildingID" to buildingId,
                    "StatusCode" to "CL09",
                    "TechnicianLatitude" to lat,
                    "TechnicianLongitude" to lng,
                    "UpdatedBy" to techId,
                    "WorkOrderID" to woId,
                    "WorkOrderSubType" to subType,
                    "WorkOrderType" to woType,
                    "woForC6Customer" to (subType in listOf("13","15"))
                )

                val reachHeaders = mutableMapOf(
                    "Referer" to "https://jpw.jio.com/retailv1/workOrderV3/reached",
                    "X-JioCenterId" to jioCenterId
                )
                val reachResult = httpPost(BASE, reachPayload, reachHeaders)
                sessionCookies.putAll(reachResult.cookies)
                val reachData = gson.fromJson(reachResult.body, Map::class.java)
                if (reachData["IsSuccessful"] == true) {
                    successCount++
                } else {
                    failCount++
                }
            }

            showStatus("Done! REACHED: $successCount, Failed: $failCount out of ${orders.size}")
        } catch (e: Exception) {
            showStatus("Error: ${e.message}")
        }
        enableBtn()
    }

    data class HttpResult(val statusCode: Int, val body: String, val cookies: Map<String, String>)

    private fun httpPost(urlStr: String, payload: Any, extraHeaders: Map<String, String>): HttpResult {
        val url = URL(urlStr)
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.doInput = true
        conn.connectTimeout = 30000
        conn.readTimeout = 30000

        // Build headers
        conn.setRequestProperty("User-Agent",
            "Mozilla/5.0 (Linux; Android 14; OnePlus Nord 2 5G Build/AP1A.240505.005; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/149.0.7827.91 Mobile Safari/537.36")
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("X-Requested-With", "com.jio.jpss")
        conn.setRequestProperty("Accept", "*/*")
        conn.setRequestProperty("Origin", "https://jpw.jio.com")
        conn.setRequestProperty("sec-ch-ua", "\"Android WebView\";v=\"149\", \"Chromium\";v=\"149\", \"Not)A;Brand\";v=\"24\"")
        conn.setRequestProperty("sec-ch-ua-mobile", "?1")
        conn.setRequestProperty("sec-ch-ua-platform", "\"Android\"")

        // Session cookies
        val cookieStr = sessionCookies.entries.joinToString("; ") { "${it.key}=${it.value}" }
        if (cookieStr.isNotEmpty()) conn.setRequestProperty("Cookie", cookieStr)
        extraHeaders.forEach { (k, v) -> conn.setRequestProperty(k, v) }

        // Sign the body
        val bodyStr = gson.toJson(payload)
        val sig = generateSignature(bodyStr)
        conn.setRequestProperty("X-Signature", sig)

        // Write body
        OutputStreamWriter(conn.outputStream).use { it.write(bodyStr) }

        val responseCode = conn.responseCode
        val responseBody = try {
            conn.inputStream.bufferedReader().readText()
        } catch (_: Exception) {
            conn.errorStream?.bufferedReader()?.readText() ?: ""
        }

        // Parse Set-Cookie headers
        val newCookies = mutableMapOf<String, String>()
        conn.headerFields?.forEach { (key, values) ->
            if (key != null && key.equals("Set-Cookie", ignoreCase = true)) {
                values.forEach { cookieStr ->
                    val parts = cookieStr.split(";")[0].split("=", limit = 2)
                    if (parts.size == 2) newCookies[parts[0].trim()] = parts[1].trim()
                }
            }
        }
        sessionCookies.putAll(newCookies)

        conn.disconnect()
        return HttpResult(responseCode, responseBody, newCookies)
    }

    private fun generateSignature(body: String): String {
        val mac = Mac.getInstance(HMAC_ALGO)
        mac.init(SecretKeySpec(SECRET_KEY.toByteArray(Charsets.UTF_8), HMAC_ALGO))
        return Base64.encodeToString(mac.doFinal(body.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
    }

    private fun showStatus(msg: String) {
        runOnUiThread { statusText.text = msg }
    }

    private fun toast(msg: String) {
        runOnUiThread { Toast.makeText(this, msg, Toast.LENGTH_LONG).show() }
    }

    private fun enableBtn() {
        runOnUiThread { goBtn.isEnabled = true }
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }
}
