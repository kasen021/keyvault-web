package com.keyvault.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.security.MessageDigest
import javax.crypto.KeyGenerator

class KeyVaultVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var running = false
    private val CHANNEL = "kv_vpn"
    private val TAG = "KeyVaultVPN"
    private var thread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            startForeground(2, buildNotif())
            startVpn()
        } catch (e: Exception) {
            Log.e(TAG, "crash: ${e.stackTraceToString()}")
            stopSelf()
        }
        return START_STICKY
    }

    private fun buildNotif(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Key Vault NOS VPN", NotificationManager.IMPORTANCE_LOW))
        return NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle("Key Vault NOS VPN — ${Session.getTier(this).name}")
            .setContentText("Serpent-256 + AES-256-GCM aktif")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true).build()
    }

    private fun deriveKey(): ByteArray {
        val p = getSharedPreferences("kv_vpn_key", MODE_PRIVATE)
        val stored = p.getString("key", null)
        if (stored != null) return android.util.Base64.decode(stored, android.util.Base64.DEFAULT)
        val kg = KeyGenerator.getInstance("AES")
        kg.init(256)
        val key = kg.generateKey().encoded
        p.edit().putString("key", android.util.Base64.encodeToString(key, android.util.Base64.DEFAULT)).apply()
        return key
    }

    private fun startVpn() {
        if (running) return
        try {
            val builder = Builder()
                .setSession("Key Vault NOS VPN")
                .addAddress("10.99.0.1", 32)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addRoute("0.0.0.0", 0)
                .setMtu(1400)
                .setBlocking(true)
            val selected = SelectedApps.load(this)
            if (selected.isNotEmpty()) for (pkg in selected) try { builder.addAllowedApplication(pkg) } catch (_: Exception) {}
            tun = builder.establish() ?: throw IllegalStateException("Izin VPN belum diberikan")
            running = true
            val cipher = PacketCipher(deriveKey())
            thread = Thread({ relay(cipher) }, "kv-relay").also { it.isDaemon = true; it.start() }
            Log.i(TAG, "VPN started tier=${Session.getTier(this).name}")
        } catch (e: Exception) {
            Log.e(TAG, "startVpn gagal: ${e.stackTraceToString()}")
            running = false; tun?.close(); stopSelf()
        }
    }

    private fun relay(cipher: PacketCipher) {
        val input = FileInputStream(tun!!.fileDescriptor)
        val buf = ByteArray(32767)
        val relayDns = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9")
        while (running) {
            try {
                val len = input.read(buf)
                if (len > 0) {
                    val encrypted = cipher.encrypt(buf.copyOf(len))
                    val socket = DatagramSocket()
                    protect(socket)
                    val target = relayDns.random()
                    val pkt = DatagramPacket(encrypted, encrypted.size, InetAddress.getByName(target), 443)
                    socket.send(pkt)
                    socket.close()
                }
            } catch (e: Exception) {
                if (running) Log.e(TAG, "relay: ${e.message}")
                break
            }
        }
    }

    override fun onDestroy() {
        running = false; thread?.interrupt()
        try { tun?.close() } catch (_: Exception) {}
        tun = null; super.onDestroy()
    }
}
