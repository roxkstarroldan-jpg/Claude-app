package com.adshield;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayOutputStream;
import org.junit.Test;

public class DnsPacketTest {
    private static final byte[] CLIENT = {(byte) 198, 18, 0, 1};
    private static final byte[] SERVER = {(byte) 198, 18, 0, 53};

    /** A DNS query for {@code name} wrapped in IPv4/UDP, as an app would send it. */
    private static byte[] query(String name, int qtype) {
        ByteArrayOutputStream dns = new ByteArrayOutputStream();
        dns.writeBytes(new byte[] {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0});
        for (String label : name.split("\\.")) {
            dns.write(label.length());
            dns.writeBytes(label.getBytes());
        }
        dns.write(0);
        dns.writeBytes(new byte[] {0, (byte) qtype, 0, 1});
        byte[] d = dns.toByteArray();
        return DnsPacket.buildIpv4Udp(CLIENT, SERVER, 40000, 53, d, d.length);
    }

    @Test
    public void parsesQuery() {
        byte[] p = query("Ads.Example.COM", DnsPacket.TYPE_A);
        DnsPacket q = DnsPacket.parse(p, p.length);
        assertEquals("ads.example.com", q.name);
        assertEquals(DnsPacket.TYPE_A, q.qtype);
        assertEquals(0x12, q.dnsPayload()[0]);
    }

    @Test
    public void ignoresNonDnsPackets() {
        byte[] p = query("example.com", DnsPacket.TYPE_A);
        p[9] = 6; // TCP
        assertNull(DnsPacket.parse(p, p.length));
        byte[] notPort53 = DnsPacket.buildIpv4Udp(CLIENT, SERVER, 40000, 443, new byte[20], 20);
        assertNull(DnsPacket.parse(notPort53, notPort53.length));
        assertNull(DnsPacket.parse(new byte[10], 10));
    }

    @Test
    public void blockedAResponseIsZeroAddress() {
        byte[] p = query("ads.example.com", DnsPacket.TYPE_A);
        byte[] r = DnsPacket.parse(p, p.length).blockedResponse();

        assertArrayEquals(SERVER, slice(r, 12, 4));       // from the fake DNS server
        assertArrayEquals(CLIENT, slice(r, 16, 4));       // back to the app
        assertEquals(53, u16(r, 20));
        assertEquals(40000, u16(r, 22));
        assertEquals(0, ipChecksum(r));

        int dns = 28;
        assertEquals(0x1234, u16(r, dns));                // same transaction id
        assertEquals(0x8180, u16(r, dns + 2));            // response, RD, RA, no error
        assertEquals(1, u16(r, dns + 6));                 // one answer
        int rdLen = u16(r, r.length - 6);
        assertEquals(4, rdLen);
        assertArrayEquals(new byte[4], slice(r, r.length - 4, 4));
    }

    @Test
    public void blockedOtherTypeHasNoAnswers() {
        byte[] p = query("ads.example.com", 65);
        byte[] r = DnsPacket.parse(p, p.length).blockedResponse();
        assertEquals(0, u16(r, 28 + 6));
        assertEquals(p.length, r.length);
    }

    @Test
    public void relaysUpstreamResponse() {
        byte[] p = query("example.com", DnsPacket.TYPE_A);
        byte[] upstream = {0x12, 0x34, (byte) 0x81, (byte) 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 9, 9};
        byte[] r = DnsPacket.parse(p, p.length).response(upstream, 12);
        assertEquals(20 + 8 + 12, r.length);
        assertArrayEquals(slice(upstream, 0, 12), slice(r, 28, 12));
        assertEquals(0, ipChecksum(r));
    }

    private static byte[] slice(byte[] b, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(b, off, out, 0, len);
        return out;
    }

    private static int u16(byte[] b, int off) {
        return (b[off] & 0xFF) << 8 | (b[off + 1] & 0xFF);
    }

    private static int ipChecksum(byte[] p) {
        long s = 0;
        for (int i = 0; i < 20; i += 2) s += u16(p, i);
        while ((s >> 16) != 0) s = (s & 0xFFFF) + (s >> 16);
        return (int) (~s & 0xFFFF);
    }
}
