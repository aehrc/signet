/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import {
  classifyIpAddress,
  isFetchableAddress,
  parseIpv4,
  parseIpv6,
} from "./addresses.js";

describe("parseIpv4", () => {
  it("parses a dotted quad", () => {
    expect(parseIpv4("192.0.2.1")).toEqual(new Uint8Array([192, 0, 2, 1]));
  });

  it("accepts a zero octet", () => {
    expect(parseIpv4("0.0.0.0")).toEqual(new Uint8Array([0, 0, 0, 0]));
  });

  it.each([
    ["too few octets", "127.0.1"],
    ["too many octets", "1.2.3.4.5"],
    ["an octet above 255", "256.0.0.1"],
    ["a leading zero", "010.0.0.1"],
    ["a hex octet", "0x7f.0.0.1"],
    ["a decimal integer", "2130706433"],
    ["an empty octet", "127..0.1"],
    ["whitespace", " 127.0.0.1"],
    ["a trailing dot", "127.0.0.1."],
  ])("refuses %s", (_name, value) => {
    expect(parseIpv4(value)).toBeUndefined();
  });
});

describe("parseIpv6", () => {
  it("parses a fully written address", () => {
    const bytes = parseIpv6("2001:0db8:0000:0000:0000:0000:0000:0001");
    expect(bytes?.[0]).toBe(0x20);
    expect(bytes?.[15]).toBe(1);
  });

  it("expands an elision", () => {
    expect(parseIpv6("::1")).toEqual(
      new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    );
    expect(parseIpv6("::")).toEqual(new Uint8Array(16));
    expect(parseIpv6("fe80::")?.[0]).toBe(0xfe);
  });

  it("accepts brackets, as a URL host carries them", () => {
    expect(parseIpv6("[::1]")).toEqual(parseIpv6("::1"));
  });

  it("rewrites an embedded IPv4 tail", () => {
    const bytes = parseIpv6("::ffff:127.0.0.1");
    expect((bytes ?? new Uint8Array()).slice(10)).toEqual(
      new Uint8Array([0xff, 0xff, 127, 0, 0, 1]),
    );
  });

  it("accepts an embedded IPv4 tail with no elision", () => {
    const bytes = parseIpv6("1:2:3:4:5:6:1.2.3.4");
    expect((bytes ?? new Uint8Array()).slice(12)).toEqual(
      new Uint8Array([1, 2, 3, 4]),
    );
  });

  it.each([
    ["two elisions", "1::2::3"],
    ["too few groups", "1:2"],
    ["too many groups", "1:2:3:4:5:6:7:8:9"],
    ["a group that is too long", "12345::1"],
    ["a non-hex group", "zzzz::1"],
    ["a leading single colon", ":1:2:3:4:5:6:7"],
    ["a zone identifier", "fe80::1%eth0"],
    ["an empty string", ""],
    ["a bare IPv4 address", "127.0.0.1"],
    ["a malformed embedded IPv4 tail", "::ffff:127.0.0.256"],
    ["eight written groups plus an elision", "1:2:3:4:5:6:7:8::"],
  ])("refuses %s", (_name, value) => {
    expect(parseIpv6(value)).toBeUndefined();
  });
});

describe("classifyIpAddress", () => {
  it.each([
    ["93.184.216.34", "public"],
    ["8.8.8.8", "public"],
    ["0.0.0.0", "unspecified"],
    ["0.1.2.3", "reserved"],
    ["10.0.0.1", "private"],
    ["172.16.0.1", "private"],
    ["172.31.255.255", "private"],
    ["172.32.0.1", "public"],
    ["172.15.0.1", "public"],
    ["192.168.1.1", "private"],
    ["127.0.0.1", "loopback"],
    ["127.255.255.255", "loopback"],
    ["100.64.0.1", "shared"],
    ["100.127.255.255", "shared"],
    ["100.128.0.1", "public"],
    ["169.254.169.254", "link-local"],
    ["192.0.0.1", "reserved"],
    ["192.0.2.5", "documentation"],
    ["198.18.0.1", "benchmarking"],
    ["198.19.255.255", "benchmarking"],
    ["198.51.100.5", "documentation"],
    ["203.0.113.5", "documentation"],
    ["224.0.0.1", "multicast"],
    ["239.255.255.255", "multicast"],
    ["240.0.0.1", "reserved"],
    ["255.255.255.255", "reserved"],
  ] as const)("classifies %s as %s", (address, expected) => {
    expect(classifyIpAddress(address)).toBe(expected);
  });

  it.each([
    ["::", "unspecified"],
    ["::1", "loopback"],
    ["2606:2800:220:1:248:1893:25c8:1946", "public"],
    ["fc00::1", "unique-local"],
    ["fd12:3456::1", "unique-local"],
    ["fe80::1", "link-local"],
    ["febf::1", "link-local"],
    ["fec0::1", "public"],
    ["ff02::1", "multicast"],
    ["2001:db8::1", "documentation"],
    ["2002::1", "reserved"],
    ["2001::1", "reserved"],
    ["::ffff:127.0.0.1", "loopback"],
    ["::ffff:10.0.0.1", "private"],
    ["::ffff:169.254.169.254", "link-local"],
    ["::ffff:93.184.216.34", "public"],
    ["::10.0.0.1", "private"],
  ] as const)("classifies %s as %s", (address, expected) => {
    expect(classifyIpAddress(address)).toBe(expected);
  });

  it("reports a DNS name as unclassifiable", () => {
    expect(classifyIpAddress("fhir.example.org")).toBeUndefined();
    expect(classifyIpAddress("localhost")).toBeUndefined();
  });
});

describe("isFetchableAddress", () => {
  it("permits a public address", () => {
    expect(isFetchableAddress("93.184.216.34")).toBe(true);
  });

  it("refuses the cloud metadata address", () => {
    expect(isFetchableAddress("169.254.169.254")).toBe(false);
  });

  it("refuses loopback in either family, however it is spelled", () => {
    expect(isFetchableAddress("127.0.0.1")).toBe(false);
    expect(isFetchableAddress("::1")).toBe(false);
    expect(isFetchableAddress("::ffff:127.0.0.1")).toBe(false);
  });

  it("refuses a value it cannot parse", () => {
    expect(isFetchableAddress("fhir.example.org")).toBe(false);
    expect(isFetchableAddress("")).toBe(false);
  });
});
