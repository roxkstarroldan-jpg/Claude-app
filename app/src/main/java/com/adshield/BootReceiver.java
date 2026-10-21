package com.adshield;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/** Turns blocking back on after a reboot or app update if it was on before. */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        AdShieldWidget.refresh(context);
        // No VpnService.prepare() check here: it would disconnect Surfshark if that's already on.
        // The service checks for that first.
        if (!new Prefs(context).isEnabled()) return;
        try {
            context.startForegroundService(
                new Intent(context, BlockerVpnService.class).setAction(BlockerVpnService.ACTION_AUTO_START));
        } catch (IllegalStateException e) {
            Log.w("AdShield", "could not start after boot", e);
        }
    }
}
