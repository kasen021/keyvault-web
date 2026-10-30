package com.keyvault.vpn

import android.content.Context

enum class Tier { GENKAI, CYBORG, CYPHERSTAR }

object Session {
    private const val PREFS = "kv_session"

    fun getTier(ctx: Context): Tier {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return when (p.getString("tier", "GENKAI")) {
            "CYBORG" -> Tier.CYBORG
            "CYPHERSTAR" -> Tier.CYPHERSTAR
            else -> Tier.GENKAI
        }
    }

    fun verifyAndUpgrade(ctx: Context, txid: String, tier: Tier) {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val used = p.getStringSet("used_txids", mutableSetOf())!!.toMutableSet()
        if (txid in used) throw IllegalStateException("TXID sudah pernah dipakai")
        used.add(txid)
        p.edit()
            .putString("tier", tier.name)
            .putString("txid_latest", txid)
            .putStringSet("used_txids", used)
            .apply()
    }

    fun isTxidUsed(ctx: Context, txid: String): Boolean {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return txid in (p.getStringSet("used_txids", emptySet()) ?: emptySet())
    }
}
