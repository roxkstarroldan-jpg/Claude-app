package com.adshield;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Locale;
import org.junit.Before;
import org.junit.Test;

public class LocationLookupTest {

    @Before
    public void englishNames() {
        Locale.setDefault(Locale.US);
    }

    @Test
    public void parsesIpinfoResponse() {
        String json = "{\n  \"ip\": \"203.0.113.7\",\n  \"city\": \"Toronto\",\n  \"region\": \"Ontario\",\n"
            + "  \"country\": \"CA\",\n  \"loc\": \"43.7,-79.4\"\n}";
        LocationLookup.Result r = LocationLookup.fromJson(json);
        assertEquals("🇨🇦", r.flag); // 🇨🇦
        assertEquals("Canada - Toronto", r.name);
    }

    @Test
    public void parsesGeojsAndIpapiResponses() {
        LocationLookup.Result r = LocationLookup.fromJson(
            "{\"country\":\"India\",\"country_code\":\"IN\",\"city\":\"Pune\",\"ip\":\"203.0.113.7\"}");
        assertEquals("\uD83C\uDDEE\uD83C\uDDF3", r.flag); // 🇮🇳
        assertEquals("India - Pune", r.name);
    }

    @Test
    public void parsesCloudflareTrace() {
        LocationLookup.Result r = LocationLookup.fromTrace("fl=1f\nh=www.cloudflare.com\nip=203.0.113.7\ncolo=BOM\nloc=IN\ntls=TLSv1.3\n");
        assertEquals("India", r.name);
        assertNull(LocationLookup.fromTrace("<html>blocked</html>"));
    }

    @Test
    public void decodesEscapedCityNames() {
        LocationLookup.Result r = LocationLookup.fromJson("{\"city\":\"Montr\\u00e9al\",\"country\":\"CA\"}");
        assertEquals("Canada - Montréal", r.name);
    }

    @Test
    public void countryOnlyWhenNoCity() {
        LocationLookup.Result r = LocationLookup.fromCodes("us", "");
        assertEquals("🇺🇸", r.flag); // 🇺🇸
        assertEquals("United States", r.name);
    }

    @Test
    public void rejectsBadResponses() {
        assertNull(LocationLookup.fromJson("{\"error\": \"rate limited\"}"));
        assertNull(LocationLookup.fromCodes("C1", ""));
        assertNull(LocationLookup.fromCodes("CAN", ""));
    }
}
