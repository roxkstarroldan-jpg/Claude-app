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
