package com.adshield;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.StringReader;
import org.junit.Test;

public class BlocklistTest {

    @Test
    public void parsesCommonListFormats() {
        assertEquals("ads.example.com", Blocklist.parseLine("0.0.0.0 ads.example.com"));
        assertEquals("ads.example.com", Blocklist.parseLine("127.0.0.1\tAds.Example.com # comment"));
        assertEquals("ads.example.com", Blocklist.parseLine(":: ads.example.com"));
        assertEquals("ads.example.com", Blocklist.parseLine("ads.example.com"));
        assertEquals("example.com", Blocklist.parseLine("*.example.com"));
        assertEquals("example.com", Blocklist.parseLine("||example.com^"));
        assertNull(Blocklist.parseLine("||example.com^$third-party"));
        assertNull(Blocklist.parseLine("# comment"));
        assertNull(Blocklist.parseLine("! adblock comment"));
        assertNull(Blocklist.parseLine("127.0.0.1 localhost"));
        assertNull(Blocklist.parseLine("0.0.0.0 0.0.0.0"));
        assertNull(Blocklist.parseLine("not a domain"));
        assertNull(Blocklist.parseLine(""));
    }

    @Test
    public void matchesDomainAndSubdomainsOnly() throws Exception {
        Blocklist.Builder b = new Blocklist.Builder();
        b.addAll(new StringReader("0.0.0.0 doubleclick.net\nads.example.com\n"));
        Blocklist list = b.build();

        assertEquals(2, list.size());
        assertTrue(list.matches("doubleclick.net"));
        assertTrue(list.matches("stats.g.doubleclick.net"));
        assertTrue(list.matches("ads.example.com"));
        assertTrue(list.matches("x.ads.example.com"));
        assertFalse(list.matches("example.com"));
        assertFalse(list.matches("notdoubleclick.net"));
        assertFalse(list.matches("net"));
    }

    @Test
    public void deduplicatesAndRoundTripsThroughFile() throws Exception {
        Blocklist.Builder b = new Blocklist.Builder();
        for (int i = 0; i < 100_000; i++) b.add("host" + i + ".example");
        b.add("host1.example");
        Blocklist list = b.build();
        assertEquals(100_000, list.size());

        File f = File.createTempFile("blocklist", ".bin");
        try {
            list.writeTo(f, "sig-1");
            assertNull(Blocklist.readFrom(f, "sig-2"));
            Blocklist loaded = Blocklist.readFrom(f, "sig-1");
            assertEquals(100_000, loaded.size());
            assertTrue(loaded.matches("www.host99999.example"));
            assertFalse(loaded.matches("host100000.example"));
        } finally {
            f.delete();
        }
    }
}
