package com.adshield;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Reader;
import java.util.Arrays;
import java.util.Locale;

/**
 * An immutable set of blocked domains stored as a sorted array of 64-bit hashes.
 *
 * Several hundred thousand domains fit in a few MB of memory this way (instead of
 * ~50 MB as Java Strings), and a lookup is a handful of binary searches.
 * A domain is blocked if it, or any parent domain, is in the set.
 */
final class Blocklist {
    private static final int FILE_MAGIC = 0x41445331; // "ADS1"

    static final Blocklist EMPTY = new Blocklist(new long[0]);

    private final long[] hashes;

    private Blocklist(long[] sortedUniqueHashes) {
        this.hashes = sortedUniqueHashes;
    }

    int size() {
        return hashes.length;
    }

    /** True if {@code domain} (lower case, no trailing dot) or one of its parents is listed. */
    boolean matches(String domain) {
        if (hashes.length == 0) return false;
        int start = 0;
        while (true) {
            if (Arrays.binarySearch(hashes, hash(domain, start)) >= 0) return true;
            int dot = domain.indexOf('.', start);
            if (dot < 0) return false;
            start = dot + 1;
        }
    }

    /** 64-bit FNV-1a with a final mix, over {@code s.substring(start)}. */
    static long hash(String s, int start) {
        long h = 0xcbf29ce484222325L;
        for (int i = start, n = s.length(); i < n; i++) {
            h ^= s.charAt(i);
            h *= 0x100000001b3L;
        }
        h ^= h >>> 33;
        h *= 0xff51afd7ed558ccdL;
        h ^= h >>> 33;
        return h;
    }

    // ---- building -------------------------------------------------------------------------

    static final class Builder {
        private long[] buf = new long[1 << 16];
        private int n;

        void add(String domain) {
            if (n == buf.length) buf = Arrays.copyOf(buf, n * 2);
            buf[n++] = hash(domain, 0);
        }

        /** Adds every domain found in a hosts file, plain domain list or simple adblock list. */
        void addAll(Reader reader) throws IOException {
            BufferedReader r = new BufferedReader(reader, 1 << 16);
            String line;
            while ((line = r.readLine()) != null) {
                String d = parseLine(line);
                if (d != null) add(d);
            }
        }

        Blocklist build() {
            long[] a = Arrays.copyOf(buf, n);
            Arrays.sort(a);
            int u = 0;
            for (int i = 0; i < a.length; i++) {
                if (u == 0 || a[i] != a[u - 1]) a[u++] = a[i];
            }
            return new Blocklist(u == a.length ? a : Arrays.copyOf(a, u));
        }
    }

    /**
     * Extracts the domain from one line of a block list, or returns null.
     * Understands "0.0.0.0 example.com", "example.com", "*.example.com" and "||example.com^".
     */
    static String parseLine(String line) {
        int hashIdx = line.indexOf('#');
        if (hashIdx >= 0) line = line.substring(0, hashIdx);
        line = line.trim();
        if (line.isEmpty() || line.charAt(0) == '!' || line.charAt(0) == '[') return null;

        if (line.startsWith("||")) {
            if (!line.endsWith("^")) return null; // a rule with options or paths; not a pure domain
            line = line.substring(2, line.length() - 1);
        } else {
            String[] parts = line.split("\\s+");
            if (parts.length >= 2 && isIpAddress(parts[0])) {
                line = parts[1];
            } else if (parts.length == 1) {
                line = parts[0];
            } else {
                return null;
            }
        }
        if (line.startsWith("*.")) line = line.substring(2);
        if (line.endsWith(".")) line = line.substring(0, line.length() - 1);
        return normalizeDomain(line);
    }

    /** Lower-cases and validates a user- or list-provided domain, or returns null if invalid. */
    static String normalizeDomain(String s) {
        s = s.trim().toLowerCase(Locale.ROOT);
        if (s.isEmpty() || s.length() > 253 || s.indexOf('.') < 0) return null;
        if (s.charAt(0) == '.' || s.charAt(s.length() - 1) == '.' || s.contains("..")) return null;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_';
            if (!ok) return null;
        }
        if (s.equals("localhost.localdomain") || s.equals("0.0.0.0") || s.equals("127.0.0.1")) return null;
        return s;
    }

    private static boolean isIpAddress(String s) {
        if (s.indexOf(':') >= 0) return true; // IPv6, e.g. "::" or "::1"
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '.' && (c < '0' || c > '9')) return false;
        }
        return !s.isEmpty();
    }

    // ---- persistence (so restarts don't re-parse megabytes of text) -------------------------

    void writeTo(File file, String signature) throws IOException {
        File tmp = new File(file.getPath() + ".tmp");
        try (DataOutputStream out = new DataOutputStream(
                new BufferedOutputStream(new FileOutputStream(tmp), 1 << 16))) {
            out.writeInt(FILE_MAGIC);
            out.writeUTF(signature);
            out.writeInt(hashes.length);
            for (long h : hashes) out.writeLong(h);
        }
        if (!tmp.renameTo(file)) throw new IOException("rename failed: " + file);
    }

    /** Returns the stored list if it was written with the same signature, else null. */
    static Blocklist readFrom(File file, String signature) {
        if (!file.isFile()) return null;
        try (DataInputStream in = new DataInputStream(
                new BufferedInputStream(new FileInputStream(file), 1 << 16))) {
            if (in.readInt() != FILE_MAGIC) return null;
            if (!signature.equals(in.readUTF())) return null;
            long[] a = new long[in.readInt()];
            for (int i = 0; i < a.length; i++) a[i] = in.readLong();
            return new Blocklist(a);
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }
}
