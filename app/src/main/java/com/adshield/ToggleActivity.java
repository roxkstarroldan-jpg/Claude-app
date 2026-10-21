package com.adshield;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.Toast;

/**
 * Turns blocking on or off, from the app's button or the home screen widget. It has no
 * screen of its own; it only shows the "another VPN is on" warning or Android's VPN
 * permission prompt when needed, then closes.
 */
public class ToggleActivity extends Activity {
    private static final int REQUEST_VPN = 1;

    static Intent intent(Context context) {
        return new Intent(context, ToggleActivity.class);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (savedInstanceState != null) return; // recreated while the prompt is showing

        if (BlockerVpnService.running) {
            startService(serviceIntent(BlockerVpnService.ACTION_STOP));
            finish();
        } else if (BlockerVpnService.otherVpnActive(this)) {
            new AlertDialog.Builder(this)
                .setTitle(R.string.other_vpn_title)
                .setMessage(R.string.other_vpn_message)
                .setPositiveButton(R.string.turn_on_anyway, (d, w) -> startBlocking())
                .setNegativeButton(R.string.keep_other_vpn, (d, w) -> finish())
                .setOnCancelListener(d -> finish())
                .show();
        } else {
            startBlocking();
        }
    }

    private void startBlocking() {
        Intent consent = VpnService.prepare(this);
        if (consent != null) {
            startActivityForResult(consent, REQUEST_VPN);
        } else {
            onActivityResult(REQUEST_VPN, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_VPN) return;
        if (resultCode == RESULT_OK) {
            Prefs prefs = new Prefs(this);
            prefs.setEnabled(true);
            prefs.setReplacedByOtherVpn(false);
            startForegroundService(serviceIntent(BlockerVpnService.ACTION_START));
        } else {
            Toast.makeText(this, R.string.permission_needed, Toast.LENGTH_LONG).show();
        }
        finish();
    }

    private Intent serviceIntent(String action) {
        return new Intent(this, BlockerVpnService.class).setAction(action);
    }
}
