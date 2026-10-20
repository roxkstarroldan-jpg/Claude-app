package com.adshield;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.util.List;

public class MainActivity extends Activity {
    private static final int REQUEST_VPN = 1;

    private Prefs prefs;
    private Button toggle;
    private TextView status;
    private TextView stats;
    private TextView listInfo;
    private TextView recent;
    private EditText allowEdit;
    private EditText blockEdit;

    // Refreshes the counters once a second, only while the screen is visible.
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable refresher = new Runnable() {
        @Override
        public void run() {
            updateUi();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        prefs = new Prefs(this);

        toggle = findViewById(R.id.toggle);
        status = findViewById(R.id.status);
        stats = findViewById(R.id.stats);
        listInfo = findViewById(R.id.list_info);
        recent = findViewById(R.id.recent);
        allowEdit = findViewById(R.id.allow_edit);
        blockEdit = findViewById(R.id.block_edit);

        toggle.setOnClickListener(v -> {
            if (BlockerVpnService.running) {
                startService(serviceIntent(BlockerVpnService.ACTION_STOP));
            } else if (otherVpnActive()) {
                new AlertDialog.Builder(this)
                    .setTitle(R.string.other_vpn_title)
                    .setMessage(R.string.other_vpn_message)
                    .setPositiveButton(R.string.turn_on_anyway, (d, w) -> startBlocking())
                    .setNegativeButton(R.string.keep_other_vpn, null)
                    .show();
            } else {
                startBlocking();
            }
        });

        LinearLayout sources = findViewById(R.id.sources);
        for (BlocklistStore.Source s : BlocklistStore.SOURCES) {
            CheckBox cb = new CheckBox(this);
            cb.setText(s.title);
            cb.setChecked(prefs.isSourceEnabled(s));
            cb.setOnCheckedChangeListener((v, checked) -> {
                prefs.setSourceEnabled(s, checked);
                sendIfRunning(BlockerVpnService.ACTION_RELOAD);
            });
            sources.addView(cb);
        }

        findViewById(R.id.update).setOnClickListener(v -> {
            if (sendIfRunning(BlockerVpnService.ACTION_UPDATE)) {
                Toast.makeText(this, R.string.updating, Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, R.string.turn_on_first, Toast.LENGTH_SHORT).show();
            }
        });

        allowEdit.setText(prefs.allowedText());
        blockEdit.setText(prefs.blockedText());
        findViewById(R.id.save).setOnClickListener(v -> {
            prefs.setDomainLists(allowEdit.getText().toString(), blockEdit.getText().toString());
            sendIfRunning(BlockerVpnService.ACTION_RELOAD);
            Toast.makeText(this, R.string.saved, Toast.LENGTH_SHORT).show();
        });

        findViewById(R.id.always_on).setOnClickListener(v -> startActivity(new Intent(Settings.ACTION_VPN_SETTINGS)));

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] {Manifest.permission.POST_NOTIFICATIONS}, 0);
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

    /** True if another VPN app, like Surfshark, is connected. Only one VPN can run at a time. */
    private boolean otherVpnActive() {
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        NetworkCapabilities caps = cm.getNetworkCapabilities(cm.getActiveNetwork());
        return caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_VPN) return;
        if (resultCode == RESULT_OK) {
            prefs.setEnabled(true);
            prefs.setReplacedByOtherVpn(false);
            startForegroundService(serviceIntent(BlockerVpnService.ACTION_START));
        } else {
            Toast.makeText(this, R.string.permission_needed, Toast.LENGTH_LONG).show();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(refresher);
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(refresher);
        super.onPause();
    }

    private Intent serviceIntent(String action) {
        return new Intent(this, BlockerVpnService.class).setAction(action);
    }

    private boolean sendIfRunning(String action) {
        if (!BlockerVpnService.running) return false;
        startService(serviceIntent(action));
        return true;
    }

    private void updateUi() {
        boolean on = BlockerVpnService.running;
        toggle.setText(on ? R.string.turn_off : R.string.turn_on);
        status.setText(on ? R.string.status_on
            : prefs.wasReplacedByOtherVpn() ? R.string.status_replaced : R.string.status_off);
        if (on) {
            stats.setText(getString(R.string.stats,
                BlockerVpnService.blockedCount.get(), BlockerVpnService.queryCount.get()));
            listInfo.setText(BlockerVpnService.listStatus);
        } else {
            stats.setText("");
            listInfo.setText("");
        }
        List<String> blocked = BlockerVpnService.recentBlocked();
        recent.setText(blocked.isEmpty() ? getString(R.string.nothing_yet) : String.join("\n", blocked));
    }
}
