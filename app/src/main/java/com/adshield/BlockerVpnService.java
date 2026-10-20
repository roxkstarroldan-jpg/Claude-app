package com.adshield;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.graphics.drawable.Icon;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import android.util.Log;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A local, DNS-only "VPN". Only traffic to a fake DNS server address is routed into the
 * app; everything else goes straight to the network untouched. Each DNS lookup for an ad,
 * tracker or malicious redirect domain is answered with 0.0.0.0, and every other lookup is
 * forwarded to a real DNS server.
 *
 * Battery: no wake locks, no timers and no polling. The packet loop sleeps in poll() until a
 * DNS query arrives, and the forwarding threads exit after 30 s of inactivity.
 */
public class BlockerVpnService extends VpnService {
    static final String ACTION_START = "com.adshield.START";
    static final String ACTION_STOP = "com.adshield.STOP";
    static final String ACTION_RELOAD = "com.adshield.RELOAD";
    static final String ACTION_UPDATE = "com.adshield.UPDATE";

    private static final String TAG = "AdShield";
    // 198.18.0.0/15 is reserved for benchmarking, so it won't clash with real networks.
    private static final String VPN_ADDRESS = "198.18.0.1";
    private static final String VPN_DNS = "198.18.0.53";
    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL_ID = "status";
    private static final int UPSTREAM_TIMEOUT_MS = 2500;
    private static final int RECENT_MAX = 30;

    // Status for the UI.
    static volatile boolean running;
    static volatile String listStatus = "";
    static final AtomicLong blockedCount = new AtomicLong();
    static final AtomicLong queryCount = new AtomicLong();
    private static final ArrayDeque<String> recentBlocked = new ArrayDeque<>();

    private static final List<InetAddress> FALLBACK_DNS = fallbackDns();

    private volatile Blocklist blocklist = Blocklist.EMPTY;
    private volatile Set<String> allowed = Collections.emptySet();
    private volatile List<InetAddress> networkDns = Collections.emptyList();

    private Prefs prefs;
    private BlocklistStore store;
    private final ExecutorService background = Executors.newSingleThreadExecutor();
    private ThreadPoolExecutor forwarder;
    private ConnectivityManager.NetworkCallback networkCallback;
    private ParcelFileDescriptor tun;
    private FileOutputStream tunOut;
    private FileDescriptor stopSignal;
    private Thread loopThread;

    static synchronized List<String> recentBlocked() {
        return new ArrayList<>(recentBlocked);
    }

    private static synchronized void recordBlocked(String domain) {
        recentBlocked.remove(domain);
        recentBlocked.addFirst(domain);
        if (recentBlocked.size() > RECENT_MAX) recentBlocked.removeLast();
    }

    @Override
    public void onCreate() {
        super.onCreate();
        prefs = new Prefs(this);
        store = new BlocklistStore(new File(getFilesDir(), "lists"));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // A null intent or the VpnService action means a restart by the system or always-on VPN.
        String action = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            prefs.setEnabled(false);
            shutdown();
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
            return START_NOT_STICKY;
        }

        showForegroundNotification();
        if (!running && !startVpn()) {
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_RELOAD.equals(action)) {
            background.execute(() -> {
                loadLists();
                refreshLists(false);
            });
        } else if (ACTION_UPDATE.equals(action)) {
            background.execute(() -> refreshLists(true));
        }
        return START_STICKY;
    }

    @Override
    public void onRevoke() {
        // Another VPN app (e.g. Surfshark) took over, or the user turned us off in system settings.
        // Android allows only one VPN at a time.
        prefs.setEnabled(false);
        prefs.setReplacedByOtherVpn(true);
        shutdown();
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        shutdown();
        background.shutdownNow();
        super.onDestroy();
    }

    private boolean startVpn() {
        Builder b = new Builder()
            .setSession(getString(R.string.app_name))
            .addAddress(VPN_ADDRESS, 32)
            .addDnsServer(VPN_DNS)
            .addRoute(VPN_DNS, 32)
            .setBlocking(false)
            .setConfigureIntent(openAppIntent());
        try {
            // Our own downloads and upstream lookups must not loop back through ourselves.
            b.addDisallowedApplication(getPackageName());
        } catch (PackageManager.NameNotFoundException impossible) {
            throw new AssertionError(impossible);
        }
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false); // inherit the real network's metered state

        try {
            tun = b.establish();
        } catch (RuntimeException e) {
            Log.w(TAG, "establish failed", e);
            tun = null;
        }
        if (tun == null) return false; // VPN permission missing or revoked

        FileDescriptor stopRead;
        try {
            FileDescriptor[] pipe = Os.pipe();
            stopRead = pipe[0];
            stopSignal = pipe[1];
        } catch (ErrnoException e) {
            Log.w(TAG, "pipe failed", e);
            closeQuietly(tun);
            tun = null;
            return false;
        }

        running = true;
        blockedCount.set(0);
        queryCount.set(0);
        tunOut = new FileOutputStream(tun.getFileDescriptor());
        forwarder = new ThreadPoolExecutor(0, 16, 30, TimeUnit.SECONDS, new SynchronousQueue<>());

        ParcelFileDescriptor loopTun = tun;
        loopThread = new Thread(() -> runLoop(loopTun, stopRead), "dns-loop");
        loopThread.start();

        background.execute(this::loadLists);
        watchNetwork();
        AdShieldWidget.refresh(this);
        return true;
    }

    private void shutdown() {
        if (!running) return;
        running = false;
        if (networkCallback != null) {
            getSystemService(ConnectivityManager.class).unregisterNetworkCallback(networkCallback);
            networkCallback = null;
        }
        try {
            Os.close(stopSignal); // wakes the packet loop, which then closes the VPN interface
        } catch (ErrnoException ignored) {
        }
        try {
            loopThread.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        forwarder.shutdownNow();
        tun = null;
        tunOut = null;
        AdShieldWidget.refresh(this);
    }

    // ---- packet loop ------------------------------------------------------------------------

    private void runLoop(ParcelFileDescriptor tun, FileDescriptor stopRead) {
        FileDescriptor fd = tun.getFileDescriptor();
        StructPollfd tunPoll = new StructPollfd();
        tunPoll.fd = fd;
        tunPoll.events = (short) OsConstants.POLLIN;
        StructPollfd stopPoll = new StructPollfd();
        stopPoll.fd = stopRead;
        stopPoll.events = (short) OsConstants.POLLIN;
        StructPollfd[] polls = {tunPoll, stopPoll};
        byte[] buf = new byte[32767];
        FileOutputStream out = tunOut;

        try {
            while (true) {
                tunPoll.revents = 0;
                stopPoll.revents = 0;
                try {
                    Os.poll(polls, -1); // sleeps until a packet arrives or we are stopped
                } catch (ErrnoException e) {
                    if (e.errno == OsConstants.EINTR) continue;
                    throw e;
                }
                if (stopPoll.revents != 0) break;
                if ((tunPoll.revents & OsConstants.POLLIN) != 0) {
                    int n;
                    while ((n = readPacket(fd, buf)) > 0) handlePacket(buf, n, out);
                }
                if ((tunPoll.revents & (OsConstants.POLLERR | OsConstants.POLLHUP | OsConstants.POLLNVAL)) != 0) break;
            }
        } catch (ErrnoException | IOException e) {
            Log.w(TAG, "packet loop stopped", e);
        } finally {
            try {
                Os.close(stopRead);
            } catch (ErrnoException ignored) {
            }
            closeQuietly(tun);
        }
    }

    /** Reads one packet, or returns 0 when none is waiting. */
    private static int readPacket(FileDescriptor fd, byte[] buf) throws ErrnoException, InterruptedIOException {
        try {
            return Os.read(fd, buf, 0, buf.length);
        } catch (ErrnoException e) {
            if (e.errno == OsConstants.EAGAIN || e.errno == OsConstants.EINTR) return 0;
            throw e;
        }
    }

    private void handlePacket(byte[] buf, int len, FileOutputStream out) {
        DnsPacket query = DnsPacket.parse(buf, len);
        if (query == null) return;
        queryCount.incrementAndGet();

        if (!isAllowed(query.name) && blocklist.matches(query.name)) {
            blockedCount.incrementAndGet();
            recordBlocked(query.name);
            write(out, query.blockedResponse());
            return;
        }
        try {
            forwarder.execute(() -> forward(query, out));
        } catch (RejectedExecutionException ignored) {
            // Too many lookups in flight or shutting down; the app will retry.
        }
    }

    private boolean isAllowed(String domain) {
        Set<String> a = allowed;
        if (a.isEmpty()) return false;
        int start = 0;
        while (true) {
            if (a.contains(start == 0 ? domain : domain.substring(start))) return true;
            int dot = domain.indexOf('.', start);
            if (dot < 0) return false;
            start = dot + 1;
        }
    }

    /** Sends the query to the network's DNS server (falling back to public ones) and relays the answer. */
    private void forward(DnsPacket query, FileOutputStream out) {
        byte[] request = query.dnsPayload();
        byte[] response = new byte[4096];
        List<InetAddress> servers = new ArrayList<>(networkDns);
        servers.addAll(FALLBACK_DNS);
        for (InetAddress server : servers) {
            try (DatagramSocket socket = new DatagramSocket()) {
                protect(socket);
                socket.setSoTimeout(UPSTREAM_TIMEOUT_MS);
                socket.connect(server, 53);
                socket.send(new DatagramPacket(request, request.length));
                DatagramPacket reply = new DatagramPacket(response, response.length);
                socket.receive(reply);
                if (reply.getLength() < 12 || response[0] != request[0] || response[1] != request[1]) continue;
                write(out, query.response(response, reply.getLength()));
                return;
            } catch (IOException e) {
                // Try the next server.
            }
        }
    }

    private static void write(FileOutputStream out, byte[] packet) {
        try {
            synchronized (out) {
                out.write(packet);
            }
        } catch (IOException ignored) {
            // The interface is closing.
        }
    }

    // ---- block lists ------------------------------------------------------------------------

    private void loadLists() {
        listStatus = "Loading block lists…";
        Blocklist list = store.load(prefs.enabledSources(), prefs.blockedText());
        allowed = prefs.allowedDomains();
        blocklist = list;
        listStatus = String.format("%,d domains blocked", list.size());
    }

    /** Downloads lists that are missing, or stale ones when on Wi-Fi (or always when forced). */
    private void refreshLists(boolean force) {
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        boolean metered = cm.isActiveNetworkMetered();
        boolean changed = false;
        int failed = 0;
        for (BlocklistStore.Source s : prefs.enabledSources()) {
            boolean wanted = force || !store.isDownloaded(s) || (store.isStale(s) && !metered);
            if (!wanted) continue;
            listStatus = "Downloading " + s.title + "…";
            try {
                store.download(s);
                changed = true;
            } catch (IOException e) {
                Log.w(TAG, "download failed: " + s.url, e);
                failed++;
            }
        }
        if (changed) loadLists();
        String size = String.format("%,d domains blocked", blocklist.size());
        listStatus = failed == 0 ? size : size + " (" + failed + " list(s) failed to download)";
    }

    private void watchNetwork() {
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                background.execute(() -> refreshLists(false));
                AdShieldWidget.refresh(BlockerVpnService.this); // the location may have changed
            }

            @Override
            public void onLinkPropertiesChanged(Network network, LinkProperties lp) {
                List<InetAddress> dns = new ArrayList<>();
                for (InetAddress a : lp.getDnsServers()) {
                    if (!a.getHostAddress().equals(VPN_DNS)) dns.add(a);
                }
                networkDns = dns;
            }

            @Override
            public void onLost(Network network) {
                networkDns = Collections.emptyList();
            }
        };
        // Our app is excluded from the VPN, so this tracks the real underlying network.
        getSystemService(ConnectivityManager.class).registerDefaultNetworkCallback(networkCallback);
    }

    // ---- notification -----------------------------------------------------------------------

    private void showForegroundNotification() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel channel = new NotificationChannel(
            CHANNEL_ID, getString(R.string.channel_name), NotificationManager.IMPORTANCE_MIN);
        channel.setShowBadge(false);
        nm.createNotificationChannel(channel);

        PendingIntent stop = PendingIntent.getService(this, 1,
            new Intent(this, BlockerVpnService.class).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE);
        Notification n = new Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(getString(R.string.notification_title))
            .setContentIntent(openAppIntent())
            .addAction(new Notification.Action.Builder((Icon) null, getString(R.string.turn_off), stop).build())
            .setOngoing(true)
            .setShowWhen(false)
            .build();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, n);
        }
    }

    private PendingIntent openAppIntent() {
        return PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
    }

    private static List<InetAddress> fallbackDns() {
        try {
            return List.of(
                InetAddress.getByAddress(new byte[] {1, 1, 1, 1}),  // Cloudflare
                InetAddress.getByAddress(new byte[] {9, 9, 9, 9})); // Quad9
        } catch (UnknownHostException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static void closeQuietly(ParcelFileDescriptor pfd) {
        try {
            pfd.close();
        } catch (IOException ignored) {
        }
    }
}
