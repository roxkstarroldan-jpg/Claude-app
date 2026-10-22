package com.adshield;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Downloads block lists, caches them on disk and compiles them into a {@link Blocklist}. */
final class BlocklistStore {

    static final class Source {
        final String id;
        final String title;
        final String url;
        final boolean enabledByDefault;

        Source(String id, String title, String url, boolean enabledByDefault) {
            this.id = id;
            this.title = title;
            this.url = url;
            this.enabledByDefault = enabledByDefault;
        }
    }

    static final Source[] SOURCES = {
        new Source("hagezi_pro", "Ads & trackers (HaGeZi Pro)",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt", true),
        new Source("hagezi_popup", "Pop-up & redirect ads (HaGeZi Pop-Up Ads)",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt", true),
        new Source("hagezi_tif_mini", "Scam, malware & phishing redirects (HaGeZi Threat mini)",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt", true),
        new Source("hagezi_samsung", "Samsung phone tracking (HaGeZi Samsung Tracker)",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.samsung-onlydomains.txt", true),
        new Source("fakenews", "Fake news & clickbait sites (StevenBlack fake news)",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts", true),
        new Source("stevenblack", "Extra: StevenBlack unified hosts",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", false),
    };

    /** Always blocked, so the app does something useful before the first download finishes. */
    private static final String[] BUILT_IN = {
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com",
        "pagead2.googlesyndication.com", "googletagservices.com", "adnxs.com", "adsrvr.org",
        "taboola.com", "outbrain.com", "criteo.com", "criteo.net", "amazon-adsystem.com",
        "popads.net", "popcash.net", "propellerads.com", "adsterra.com", "exoclick.com",
        "juicyads.com", "trafficjunky.net", "hilltopads.net", "admaven.com", "ad-maven.com",
        "onclickads.net", "clickadu.com", "mgid.com", "revcontent.com", "zedo.com",
        "moatads.com", "scorecardresearch.com", "unityads.unity3d.com", "applovin.com",
        "ads.yahoo.com", "advertising.com", "media.net", "pubmatic.com", "rubiconproject.com",
        "openx.net", "smartadserver.com", "yieldmo.com", "app-measurement.com",
    };

    private static final long MAX_AGE_MS = 3L * 24 * 60 * 60 * 1000;

    private final File dir;

    BlocklistStore(File dir) {
        this.dir = dir;
        dir.mkdirs();
    }

    private File listFile(Source s) {
        return new File(dir, s.id + ".txt");
    }

    private File compiledFile() {
        return new File(dir, "compiled.bin");
    }

    boolean isDownloaded(Source s) {
        return listFile(s).isFile();
    }

    boolean isStale(Source s) {
        File f = listFile(s);
        return !f.isFile() || System.currentTimeMillis() - f.lastModified() > MAX_AGE_MS;
    }

    /** Downloads one list, replacing the cached copy only if the download completes. */
    void download(Source s) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(s.url).openConnection();
        c.setConnectTimeout(15_000);
        c.setReadTimeout(30_000);
        try {
            if (c.getResponseCode() != 200) throw new IOException("HTTP " + c.getResponseCode() + " for " + s.url);
            File tmp = new File(dir, s.id + ".download");
            try (InputStream in = c.getInputStream(); OutputStream out = new FileOutputStream(tmp)) {
                byte[] buf = new byte[1 << 16];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            }
            if (!tmp.renameTo(listFile(s))) throw new IOException("rename failed");
        } finally {
            c.disconnect();
        }
    }

    /**
     * Returns the compiled block list for these settings, reusing the cached compiled file
     * when nothing changed and rebuilding it from the downloaded lists otherwise.
     */
    Blocklist load(List<Source> enabled, String customBlocked) {
        StringBuilder sig = new StringBuilder("v1|").append(customBlocked.hashCode());
        for (Source s : enabled) sig.append('|').append(s.id).append('@').append(listFile(s).lastModified());
        String signature = sig.toString();

        Blocklist cached = Blocklist.readFrom(compiledFile(), signature);
        if (cached != null) return cached;

        Blocklist.Builder b = new Blocklist.Builder();
        for (String d : BUILT_IN) b.add(d);
        for (Source s : enabled) {
            File f = listFile(s);
            if (!f.isFile()) continue;
            try (InputStream in = new FileInputStream(f)) {
                b.addAll(new InputStreamReader(in, StandardCharsets.UTF_8));
            } catch (IOException ignored) {
                // A damaged cache file is replaced at the next download.
            }
        }
        try {
            b.addAll(new StringReader(customBlocked));
        } catch (IOException impossible) {
            throw new AssertionError(impossible);
        }
        Blocklist list = b.build();
        try {
            list.writeTo(compiledFile(), signature);
        } catch (IOException ignored) {
            // Only a cache; we'll recompile next time.
        }
        return list;
    }
}
