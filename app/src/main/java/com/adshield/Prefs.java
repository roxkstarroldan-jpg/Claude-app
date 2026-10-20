package com.adshield;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** User settings, stored in SharedPreferences. */
final class Prefs {
    private static final String ENABLED = "enabled";
    private static final String ALLOWED = "allowed_domains";
    private static final String BLOCKED = "blocked_domains";
    private static final String SOURCE_PREFIX = "source_";

    private final SharedPreferences p;

    Prefs(Context context) {
        p = context.getSharedPreferences("settings", Context.MODE_PRIVATE);
    }

    /** Whether the user wants blocking on (used to restart after a reboot or update). */
    boolean isEnabled() {
        return p.getBoolean(ENABLED, false);
    }

    void setEnabled(boolean enabled) {
        p.edit().putBoolean(ENABLED, enabled).apply();
    }

    boolean isSourceEnabled(BlocklistStore.Source s) {
        return p.getBoolean(SOURCE_PREFIX + s.id, s.enabledByDefault);
    }

    void setSourceEnabled(BlocklistStore.Source s, boolean enabled) {
        p.edit().putBoolean(SOURCE_PREFIX + s.id, enabled).apply();
    }

    List<BlocklistStore.Source> enabledSources() {
        List<BlocklistStore.Source> out = new ArrayList<>();
        for (BlocklistStore.Source s : BlocklistStore.SOURCES) {
            if (isSourceEnabled(s)) out.add(s);
        }
        return out;
    }

    String allowedText() {
        return p.getString(ALLOWED, "");
    }

    String blockedText() {
        return p.getString(BLOCKED, "");
    }

    void setDomainLists(String allowed, String blocked) {
        p.edit().putString(ALLOWED, allowed).putString(BLOCKED, blocked).apply();
    }

    /** The allow list as a set of normalized domains. */
    Set<String> allowedDomains() {
        Set<String> out = new HashSet<>();
        for (String line : allowedText().split("\n")) {
            String d = Blocklist.parseLine(line);
            if (d != null) out.add(d);
        }
        return out;
    }
}
