package com.adshield;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.util.Log;

/** Turns blocking back on after a reboot or app update if it was on before. */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (!new Prefs(context).isEnabled() || VpnService.prepare(context) != null) return;
        try {
            context.startForegroundService(
                new Intent(context, BlockerVpnService.class).setAction(BlockerVpnService.ACTION_START));
        } catch (IllegalStateException e) {
            Log.w("AdShield", "could not start after boot", e);
        }
    }
}
