package dev.synapse.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.util.Log
import java.util.concurrent.Executors

/**
 * Reference foreground service hosting the exec-mode daemon.
 *
 * Copy it into your app and adjust the notification. Manifest requirements are in
 * android/snippets/AndroidManifest.xml.
 *
 * Notes:
 *  * Holds a Wi-Fi MulticastLock: many devices drop LAN broadcast/multicast packets
 *    (used by peer discovery) for apps that do not hold one.
 *  * On Android 15+, `dataSync` foreground services are limited to ~6 h per 24 h;
 *    [onTimeout] stops cleanly when the system asks. Schedule a WorkManager job to
 *    resume if you need continuous sync.
 */
class SynapseSyncService : Service() {

    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "synapse-service").apply { isDaemon = true }
    }
    private lateinit var daemon: SynapseDaemon
    private var multicastLock: WifiManager.MulticastLock? = null

    override fun onCreate() {
        super.onCreate()
        daemon = SynapseDaemon(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startInForeground("Starting sync engine...")
        acquireMulticastLock()
        executor.execute {
            try {
                val info = daemon.start()
                Log.i(TAG, "Synapse Core ${info.version} ready at ${info.apiUrl}")
                getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putString(KEY_API_URL, info.apiUrl)
                    .apply()
                updateNotification("Sync active")
            } catch (e: Exception) {
                Log.e(TAG, "Synapse Core failed to start", e)
                updateNotification("Sync failed: ${e.message?.lineSequence()?.firstOrNull()}")
                stopSelf()
            }
        }
        return START_STICKY
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        Log.w(TAG, "Foreground service time limit reached; stopping")
        stopSelf()
    }

    override fun onDestroy() {
        executor.execute { daemon.stop() }
        executor.shutdown()
        multicastLock?.takeIf { it.isHeld }?.release()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun acquireMulticastLock() {
        if (multicastLock?.isHeld == true) return
        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        multicastLock = wifi?.createMulticastLock("synapse-discovery")?.apply {
            setReferenceCounted(false)
            runCatching { acquire() }
                .onFailure { Log.w(TAG, "MulticastLock unavailable; LAN discovery may be degraded", it) }
        }
    }

    private fun startInForeground(text: String) {
        val notification = buildNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            ?.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm?.getNotificationChannel(CHANNEL_ID) == null) {
                nm?.createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, "File sync", NotificationManager.IMPORTANCE_LOW)
                )
            }
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("Synapse")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "SynapseSync"
        private const val CHANNEL_ID = "synapse_sync"
        private const val NOTIFICATION_ID = 0x5715
        const val PREFS = "synapse"
        const val KEY_API_URL = "api_url"

        fun start(context: Context) {
            val intent = Intent(context, SynapseSyncService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, SynapseSyncService::class.java))
        }
    }
}
