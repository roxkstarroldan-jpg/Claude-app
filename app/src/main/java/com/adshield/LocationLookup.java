package com.adshield;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.IllformedLocaleException;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds where this phone's internet traffic appears to come from, using the public IP
 * address. With a VPN like Surfshark on, that's the VPN server's location.
 *
 * Free lookup services rate-limit by IP address, and mobile carriers put many phones behind
 * one address, so several services are tried in turn.
 */
final class LocationLookup {
    private static final String[] JSON_SERVICES = {
        "https://ipinfo.io/json",                   // {"city": "Pune", "country": "IN"}
        "https://get.geojs.io/v1/ip/geo.json",      // {"city": "Pune", "country_code": "IN"}
        "https://ipapi.co/json/",                   // {"city": "Pune", "country_code": "IN"}
    };
    // Plain text with a "loc=IN" line; country only, but very reliable.
    private static final String CLOUDFLARE_TRACE = "https://www.cloudflare.com/cdn-cgi/trace";

    static final class Result {
        final String flag;
        final String name;

        Result(String flag, String name) {
            this.flag = flag;
            this.name = name;
        }
    }

    /** Returns the location, or null if it couldn't be found (e.g. offline). */
    static Result lookup() {
        for (String url : JSON_SERVICES) {
            String body = fetch(url);
            Result r = body == null ? null : fromJson(body);
            if (r != null) return r;
        }
        String trace = fetch(CLOUDFLARE_TRACE);
        return trace == null ? null : fromTrace(trace);
    }

    /** Returns the response body, or null on any failure (offline, rate-limited, ...). */
    private static String fetch(String url) {
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(4000);
            c.setReadTimeout(4000);
            c.setRequestProperty("Accept", "application/json");
            c.setRequestProperty("User-Agent", "AdShield");
            try {
                if (c.getResponseCode() != 200) return null;
                try (InputStream in = c.getInputStream()) {
                    ByteArrayOutputStream body = new ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = in.read(buf)) > 0 && body.size() < 64 * 1024) body.write(buf, 0, n);
                    return body.toString(StandardCharsets.UTF_8.name());
                }
            } finally {
                c.disconnect();
            }
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** Parses Cloudflare's trace output, which has a "loc=IN" line. */
    static Result fromTrace(String trace) {
        for (String line : trace.split("\n")) {
            if (line.startsWith("loc=")) return fromCodes(line.substring(4), "");
        }
        return null;
    }

    /** Parses a lookup service's JSON, e.g. {"city": "Toronto", "country": "CA", ...}. */
    static Result fromJson(String json) {
        try {
            String cc = jsonString(json, "country_code");
            if (cc.isEmpty()) cc = jsonString(json, "country"); // ipinfo puts the code here
            return fromCodes(cc, jsonString(json, "city"));
        } catch (RuntimeException e) { // malformed escape
            return null;
        }
    }

    /** Reads a top-level string field from a small flat JSON object, or returns "". */
    private static String jsonString(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        if (!m.find()) return "";
        String s = m.group(1);
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch != '\\' || i + 1 >= s.length()) {
                out.append(ch);
            } else if (s.charAt(i + 1) == 'u' && i + 5 < s.length()) {
                out.append((char) Integer.parseInt(s.substring(i + 2, i + 6), 16));
                i += 5;
            } else {
                out.append(s.charAt(++i));
            }
        }
        return out.toString();
    }

    /** E.g. ("CA", "Toronto") gives 🇨🇦 "Canada - Toronto". */
    static Result fromCodes(String countryCode, String city) {
        String cc = countryCode.trim().toUpperCase(Locale.ROOT);
        if (cc.length() != 2 || !Character.isLetter(cc.charAt(0)) || !Character.isLetter(cc.charAt(1))) return null;
        String country;
        try {
            country = new Locale.Builder().setRegion(cc).build().getDisplayCountry();
        } catch (IllformedLocaleException e) {
            country = cc;
        }
        if (country.isEmpty()) country = cc;
        String name = city.trim().isEmpty() ? country : country + " - " + city.trim();
        return new Result(flagEmoji(cc), name);
    }

    private static String flagEmoji(String cc) {
        return new String(Character.toChars(0x1F1E6 + cc.charAt(0) - 'A'))
            + new String(Character.toChars(0x1F1E6 + cc.charAt(1) - 'A'));
    }
}
