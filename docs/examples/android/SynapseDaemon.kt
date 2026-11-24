package dev.synapse.core

import android.content.Context
import android.os.Build
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream

/**
 * Runs Synapse Core in **exec mode**: the daemon executable is packaged as
 * `jniLibs/<abi>/libsynapse.so`, extracted by the installer into
 * [android.content.pm.ApplicationInfo.nativeLibraryDir] (the only app-owned location
 * Android 10+ allows to execute), and spawned as a child process.
 *
 * Requirements (see docs/android.md):
 *  * `packaging { jniLibs { useLegacyPackaging = true } }` in the app module, otherwise
 *    the file is never extracted and [start] fails with "libsynapse.so not found".
 *  * `INTERNET` permission, otherwise every socket call fails with EACCES.
 *
 * Process hygiene built in:
 *  * stdout/stderr are drained on a background thread into `logs/console.log`, so the
 *    pipe can never fill up and stall the daemon.
 *  * The daemon is started with `--exit-on-stdin-close --exit-with-parent`: if this app
 *    process dies for any reason the daemon exits within ~1 s, freeing its ports.
 *  * [start] blocks until the daemon publishes `runtime.json` (API bound and ready) and
 *    turns failures into a [SynapseStartException] carrying the daemon's own message.
 *
 * All methods block; call them from a background thread (e.g. `Dispatchers.IO`).
 */
class SynapseDaemon(
    context: Context,
    private val config: Config = Config(),
) {
    data class Config(
        /** API port; `0` lets the OS pick a free one (read it from [RuntimeInfo.apiPort]). */
        val apiPort: Int = 0,
        /** QUIC P2P port; `null` keeps the engine default (9190). */
        val p2pPort: Int? = null,
        val deviceName: String? = null,
        /** API auth token; passed via environment, never argv (argv is world-readable). */
        val token: String? = null,
        /** RUST_LOG-style filter, e.g. "info" or "synapse_core=debug". */
        val logLevel: String = "info",
        val readyTimeoutMs: Long = 15_000,
    )

    data class RuntimeInfo(
        val pid: Int,
        val version: String,
        val deviceId: String,
        val deviceName: String,
        val apiUrl: String,
        val apiPort: Int,
        val p2pPort: Int,
    )

    class SynapseStartException(message: String, val exitCode: Int? = null) : IOException(message)

    private val appContext = context.applicationContext
    val homeDir: File = File(appContext.filesDir, "synapse")
    val logDir: File = File(homeDir, "logs")
    private val runtimeFile = File(homeDir, "runtime.json")

    @Volatile private var process: Process? = null
    private var stdin: OutputStream? = null

    /** Path of the packaged daemon, validated with an actionable error message. */
    fun binary(): File {
        val dir = appContext.applicationInfo.nativeLibraryDir
        val bin = File(dir, BINARY_NAME)
        if (!bin.exists()) {
            throw SynapseStartException(
                "$BINARY_NAME not found in $dir. Enable " +
                    "`packaging { jniLibs { useLegacyPackaging = true } }` (or " +
                    "android:extractNativeLibs=\"true\") and make sure the APK contains " +
                    "an ABI this device supports: ${Build.SUPPORTED_ABIS.joinToString()}."
            )
        }
        if (!bin.canExecute()) {
            throw SynapseStartException("$bin exists but is not executable.")
        }
        return bin
    }

    val isRunning: Boolean
        get() = process?.isAliveCompat() == true

    /** Starts the daemon (idempotent) and waits until its API is accepting requests. */
    @Synchronized
    @Throws(SynapseStartException::class)
    fun start(): RuntimeInfo {
        if (isRunning) readRuntime()?.let { return it }

        repeat(2) { attempt ->
            try {
                return launch()
            } catch (e: SynapseStartException) {
                // A daemon from a previous (killed) app process may still be shutting
                // down; it exits within ~1 s thanks to --exit-with-parent.
                if (e.exitCode != EXIT_ALREADY_RUNNING || attempt == 1) throw e
                Thread.sleep(1_500)
            }
        }
        error("unreachable")
    }

    private fun launch(): RuntimeInfo {
        val bin = binary()
        homeDir.mkdirs()
        logDir.mkdirs()
        runtimeFile.delete()

        val cmd = mutableListOf(
            bin.absolutePath,
            "--home", homeDir.absolutePath,
            "--port", config.apiPort.toString(),
            "--log-dir", logDir.absolutePath,
            "--log-level", config.logLevel,
            "--quiet",
            "--exit-on-stdin-close",
            "--exit-with-parent",
        )
        config.p2pPort?.let { cmd += listOf("--p2p-port", it.toString()) }
        cmd += listOf("--device-name", config.deviceName ?: defaultDeviceName())

        val pb = ProcessBuilder(cmd)
            .directory(homeDir)
            .redirectErrorStream(true)
        pb.environment().apply {
            put("SYNAPSE_HOME", homeDir.absolutePath)
            put("NO_COLOR", "1")
            val token = config.token
            if (token != null) put("SYNAPSE_TOKEN", token) else remove("SYNAPSE_TOKEN")
        }

        val consoleLog = File(logDir, "console.log")
        val proc = try {
            pb.start()
        } catch (e: IOException) {
            throw SynapseStartException("Cannot execute $bin: ${e.message}")
        }
        process = proc
        stdin = proc.outputStream // keep open: closing it asks the daemon to stop
        drain(proc, consoleLog)

        val deadline = System.currentTimeMillis() + config.readyTimeoutMs
        while (System.currentTimeMillis() < deadline) {
            readRuntime()?.let { return it }
            proc.exitValueOrNull()?.let { code ->
                process = null
                throw SynapseStartException(describeExit(code, consoleLog), code)
            }
            Thread.sleep(50)
        }
        stop()
        throw SynapseStartException(
            "Synapse Core did not become ready within ${config.readyTimeoutMs} ms. " +
                tail(consoleLog)
        )
    }

    /** Graceful stop: close stdin, then SIGTERM, then SIGKILL. Safe to call anytime. */
    @Synchronized
    fun stop(timeoutMs: Long = 5_000) {
        val proc = process ?: return
        runCatching { stdin?.close() }
        if (!proc.waitForCompat(timeoutMs)) {
            proc.destroy() // SIGTERM -> graceful shutdown in the daemon
            if (!proc.waitForCompat(2_000) && Build.VERSION.SDK_INT >= 26) {
                proc.destroyForcibly()
            }
        }
        process = null
        stdin = null
        runtimeFile.delete()
    }

    fun readRuntime(): RuntimeInfo? = runCatching {
        if (!runtimeFile.isFile) return null
        val j = JSONObject(runtimeFile.readText())
        val addr = j.getString("api_addr")
        RuntimeInfo(
            pid = j.getInt("pid"),
            version = j.getString("version"),
            deviceId = j.getString("device_id"),
            deviceName = j.getString("device_name"),
            apiUrl = j.getString("api_url"),
            apiPort = addr.substringAfterLast(':').toInt(),
            p2pPort = j.getInt("p2p_port"),
        )
    }.getOrNull()

    private fun describeExit(code: Int, consoleLog: File): String {
        val reason = when (code) {
            EXIT_CONFIG -> "configuration error"
            EXIT_ALREADY_RUNNING -> "another instance is using ${homeDir.absolutePath}"
            EXIT_BIND -> "API port ${config.apiPort} is already in use"
            126, 127 -> "binary could not be executed (wrong ABI or not an Android build?)"
            else -> "exited with code $code"
        }
        return "Synapse Core failed to start: $reason. ${tail(consoleLog)}"
    }

    private fun defaultDeviceName(): String =
        listOf(Build.MANUFACTURER, Build.MODEL).filter { it.isNotBlank() }
            .joinToString(" ").ifBlank { "Android" }

    companion object {
        const val BINARY_NAME = "libsynapse.so"
        const val EXIT_CONFIG = 3
        const val EXIT_ALREADY_RUNNING = 4
        const val EXIT_BIND = 5

        private fun drain(proc: Process, into: File) {
            Thread({
                runCatching {
                    FileOutputStream(into, true).use { out ->
                        proc.inputStream.use { it.copyTo(out) }
                    }
                }
            }, "synapse-console").apply { isDaemon = true }.start()
        }

        private fun tail(file: File, lines: Int = 5): String = runCatching {
            file.readLines().takeLast(lines).joinToString("\n").let {
                if (it.isBlank()) "" else "Last output:\n$it"
            }
        }.getOrDefault("")

        private fun Process.exitValueOrNull(): Int? =
            try { exitValue() } catch (_: IllegalThreadStateException) { null }

        private fun Process.isAliveCompat(): Boolean = exitValueOrNull() == null

        /** `Process.waitFor(timeout, unit)` needs API 26; poll for older devices. */
        private fun Process.waitForCompat(timeoutMs: Long): Boolean {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                if (!isAliveCompat()) return true
                Thread.sleep(25)
            }
            return !isAliveCompat()
        }
    }
}
