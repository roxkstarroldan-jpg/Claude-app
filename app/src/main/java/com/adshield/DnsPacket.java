package com.adshield;

import java.util.Arrays;

/**
 * A DNS query that arrived on the VPN interface as a raw IPv4/UDP packet, plus helpers
 * to build the IPv4/UDP packets that carry the answer back.
 */
final class DnsPacket {
    static final int TYPE_A = 1;
    static final int TYPE_AAAA = 28;

    private static final int IP_HEADER_LEN = 20;
    private static final int UDP_HEADER_LEN = 8;
    private static final int DNS_HEADER_LEN = 12;
    private static final int BLOCKED_TTL = 300;

    private final byte[] packet;
    private final int dnsOffset;
    private final int dnsLength;
    private final int questionEnd; // offset of the first byte after the first question
    final String name;
    final int qtype;

    private DnsPacket(byte[] packet, int dnsOffset, int dnsLength, int questionEnd, String name, int qtype) {
        this.packet = packet;
        this.dnsOffset = dnsOffset;
        this.dnsLength = dnsLength;
        this.questionEnd = questionEnd;
        this.name = name;
        this.qtype = qtype;
    }

    /** Parses an IPv4/UDP/DNS query, or returns null for anything else. Copies {@code buf}. */
    static DnsPacket parse(byte[] buf, int len) {
        if (len < IP_HEADER_LEN + UDP_HEADER_LEN + DNS_HEADER_LEN) return null;
        if ((buf[0] >> 4 & 0xF) != 4) return null;
        int ihl = (buf[0] & 0xF) * 4;
        if (ihl < IP_HEADER_LEN || buf[9] != 17) return null; // UDP only
        int totalLen = u16(buf, 2);
        if (totalLen > len || totalLen < ihl + UDP_HEADER_LEN + DNS_HEADER_LEN) return null;
        if ((u16(buf, 6) & 0x3FFF) != 0) return null; // fragmented
        if (u16(buf, ihl + 2) != 53) return null;

        int dns = ihl + UDP_HEADER_LEN;
        int dnsLen = totalLen - dns;
        if ((buf[dns + 2] & 0x80) != 0) return null; // not a query
        if ((buf[dns + 2] & 0x78) != 0) return null; // not a standard query
        if (u16(buf, dns + 4) < 1) return null;

        StringBuilder sb = new StringBuilder(64);
        int p = dns + DNS_HEADER_LEN;
        int end = dns + dnsLen;
        while (true) {
            if (p >= end) return null;
            int labelLen = buf[p++] & 0xFF;
            if (labelLen == 0) break;
            if ((labelLen & 0xC0) != 0 || p + labelLen > end || sb.length() + labelLen > 253) return null;
            if (sb.length() > 0) sb.append('.');
            for (int i = 0; i < labelLen; i++) {
                char c = (char) (buf[p + i] & 0xFF);
                sb.append(c >= 'A' && c <= 'Z' ? (char) (c + 32) : c);
            }
            p += labelLen;
        }
        if (p + 4 > end) return null;
        int qtype = u16(buf, p);
        return new DnsPacket(Arrays.copyOf(buf, totalLen), dns, dnsLen, p + 4, sb.toString(), qtype);
    }

    /** The DNS message to send to the upstream server. */
    byte[] dnsPayload() {
        return Arrays.copyOfRange(packet, dnsOffset, dnsOffset + dnsLength);
    }

    /** An IPv4 packet answering this query with the given DNS message. */
    byte[] response(byte[] dns, int len) {
        int ihl = dnsOffset - UDP_HEADER_LEN;
        byte[] srcIp = Arrays.copyOfRange(packet, 16, 20); // query destination becomes our source
        byte[] dstIp = Arrays.copyOfRange(packet, 12, 16);
        return buildIpv4Udp(srcIp, dstIp, u16(packet, ihl + 2), u16(packet, ihl), dns, len);
    }

    /** An IPv4 packet answering this query with 0.0.0.0 / :: (or no records for other types). */
    byte[] blockedResponse() {
        int questionLen = questionEnd - dnsOffset;
        int rdLen = qtype == TYPE_A ? 4 : qtype == TYPE_AAAA ? 16 : -1;
        int answerLen = rdLen < 0 ? 0 : 12 + rdLen;
        byte[] dns = new byte[questionLen + answerLen];
        System.arraycopy(packet, dnsOffset, dns, 0, questionLen);
        dns[2] = (byte) (0x80 | (dns[2] & 0x79)); // QR=1, keep opcode and RD
        dns[3] = (byte) 0x80;                     // RA=1, RCODE=0
        put16(dns, 4, 1);                         // one question
        put16(dns, 6, rdLen < 0 ? 0 : 1);         // answers
        put16(dns, 8, 0);
        put16(dns, 10, 0);
        if (rdLen >= 0) {
            int a = questionLen;
            dns[a] = (byte) 0xC0;                 // name: pointer to the question
            dns[a + 1] = DNS_HEADER_LEN;
            put16(dns, a + 2, qtype);
            put16(dns, a + 4, 1);                 // class IN
            put16(dns, a + 6, 0);
            put16(dns, a + 8, BLOCKED_TTL);
            put16(dns, a + 10, rdLen);            // rdata stays all zeros
        }
        return response(dns, dns.length);
    }

    static byte[] buildIpv4Udp(byte[] srcIp, byte[] dstIp, int srcPort, int dstPort, byte[] data, int len) {
        int total = IP_HEADER_LEN + UDP_HEADER_LEN + len;
        byte[] p = new byte[total];
        p[0] = 0x45;
        put16(p, 2, total);
        p[6] = 0x40; // don't fragment
        p[8] = 64;   // TTL
        p[9] = 17;   // UDP
        System.arraycopy(srcIp, 0, p, 12, 4);
        System.arraycopy(dstIp, 0, p, 16, 4);
        put16(p, 10, checksum(0, p, 0, IP_HEADER_LEN));

        int u = IP_HEADER_LEN;
        put16(p, u, srcPort);
        put16(p, u + 2, dstPort);
        put16(p, u + 4, UDP_HEADER_LEN + len);
        System.arraycopy(data, 0, p, u + UDP_HEADER_LEN, len);
        long pseudo = sum(p, 12, 8) + 17 + UDP_HEADER_LEN + len;
        int udpSum = checksum(pseudo, p, u, UDP_HEADER_LEN + len);
        put16(p, u + 6, udpSum == 0 ? 0xFFFF : udpSum);
        return p;
    }

    private static long sum(byte[] b, int off, int len) {
        long s = 0;
        for (int i = 0; i + 1 < len; i += 2) s += u16(b, off + i);
        if ((len & 1) != 0) s += (b[off + len - 1] & 0xFF) << 8;
        return s;
    }

    private static int checksum(long initial, byte[] b, int off, int len) {
        long s = initial + sum(b, off, len);
        while ((s >> 16) != 0) s = (s & 0xFFFF) + (s >> 16);
        return (int) (~s & 0xFFFF);
    }

    private static int u16(byte[] b, int off) {
        return (b[off] & 0xFF) << 8 | (b[off + 1] & 0xFF);
    }

    private static void put16(byte[] b, int off, int v) {
        b[off] = (byte) (v >> 8);
        b[off + 1] = (byte) v;
    }
}
