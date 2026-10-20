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
 */
final class LocationLookup {
    private static final String LOOKUP_URL = "https://ipinfo.io/json";

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
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(LOOKUP_URL).openConnection();
            c.setConnectTimeout(5000);
            c.setReadTimeout(5000);
            c.setRequestProperty("Accept", "application/json");
            try (InputStream in = c.getInputStream()) {
                ByteArrayOutputStream body = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) > 0 && body.size() < 64 * 1024) body.write(buf, 0, n);
                return fromJson(body.toString(StandardCharsets.UTF_8.name()));
            } finally {
                c.disconnect();
            }
        } catch (IOException | RuntimeException e) { // offline, blocked, or a malformed reply
            return null;
        }
    }

    /** Parses ipinfo.io's response, e.g. {"city": "Toronto", "country": "CA", ...}. */
    static Result fromJson(String json) {
        return fromCodes(jsonString(json, "country"), jsonString(json, "city"));
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
