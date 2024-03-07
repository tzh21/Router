/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017 Alexander Afanasyev
 * Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "utils.hpp"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

namespace simple_router {

uint16_t
cksum(const void* _data, int len)
{
  const uint8_t* data = reinterpret_cast<const uint8_t*>(_data);
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(const uint8_t* buf) {
  ethernet_hdr *ehdr = (ethernet_hdr *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(const uint8_t* buf) {
  ip_hdr *iphdr = (ip_hdr *)(buf);
  return iphdr->ip_p;
}


std::string
macToString(const Buffer& macAddr)
{
  char s[18]; // 12 digits + 5 separators + null terminator
  char sep = ':';

  // - apparently gcc-4.6 does not support the 'hh' type modifier
  // - std::snprintf not found in some environments
  //   https://redmine.named-data.net/issues/2299 for more information
  snprintf(s, sizeof(s), "%02x%c%02x%c%02x%c%02x%c%02x%c%02x",
           macAddr.at(0), sep, macAddr.at(1), sep, macAddr.at(2), sep,
           macAddr.at(3), sep, macAddr.at(4), sep, macAddr.at(5));

  return std::string(s);
}

std::string
ipToString(uint32_t ip)
{
  in_addr addr;
  addr.s_addr = ip;
  return ipToString(addr);
}

std::string
ipToString(const in_addr& address)
{
  char s[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, s, INET_ADDRSTRLEN) == nullptr) {
    throw std::runtime_error("Error while converting IP address to string");
  }
  return std::string(s);
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(const uint8_t* addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

void print_addr_ip_int(uint32_t ip)
{
  in_addr addr;
  addr.s_addr = ntohl(ip);
  print_addr_ip(addr);
}

/* Prints out fields in Ethernet header. */
void
print_hdr_eth(const uint8_t* buf) {
  const ethernet_hdr *ehdr = (const ethernet_hdr *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(const uint8_t* buf) {
  const ip_hdr *iphdr = (const ip_hdr *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(const uint8_t* buf) {
  const icmp_hdr *hdr = reinterpret_cast<const icmp_hdr*>(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(const uint8_t* buf) {
  const arp_hdr *hdr = reinterpret_cast<const arp_hdr*>(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(hdr->arp_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(hdr->arp_pro));
  fprintf(stderr, "\thardware address length: %d\n", hdr->arp_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", hdr->arp_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(hdr->arp_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(hdr->arp_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(hdr->arp_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(hdr->arp_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(hdr->arp_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(const uint8_t* buf, uint32_t length) {

  /* Ethernet */
  size_t minlength = sizeof(ethernet_hdr);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(ip_hdr);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(ethernet_hdr));
    uint8_t ip_proto = ip_protocol(buf + sizeof(ethernet_hdr));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(icmp_hdr);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(arp_hdr);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(ethernet_hdr));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

void print_hdrs(const Buffer& buffer)
{
  print_hdrs(buffer.data(), buffer.size());
}

bool debugOut(std::string msg) {
  printf("%s%s\n", hDebug.c_str(), msg.c_str());
  return true;
}

bool errorOut(std::string msg) { 
  printf("%s%s\n", hError.c_str(), msg.c_str());
  return true;
}

bool assembleArpPacket(
  Buffer& packet,
  const uint16_t arp_op,
  const uint8_t *source_address, const uint32_t source_ip,
  const uint8_t *target_address, const uint32_t target_ip
) {
  // 大小为 42B = 14B 以太网头部 + 28B ARP 头部
  packet.resize(sizeof(ethernet_hdr) + sizeof(arp_hdr), 0);
  
  // 构造以太网头部
  ethernet_hdr e_header;
  memcpy(e_header.ether_dhost, target_address, sizeof(e_header.ether_dhost));
  memcpy(e_header.ether_shost, source_address, sizeof(e_header.ether_shost));
  e_header.ether_type = htons(ethertype_arp);
  memcpy(packet.data(), &e_header, sizeof(e_header));

  // arp header
  arp_hdr arp_header;
  arp_header.arp_hrd = htons(arp_hrd_ethernet);
  arp_header.arp_pro = htons(0x0800); // ipv4
  arp_header.arp_hln = 6;
  arp_header.arp_pln = 4;
  arp_header.arp_op = htons(arp_op);
  memcpy(arp_header.arp_sha, source_address, sizeof(arp_header.arp_sha));
  arp_header.arp_sip = source_ip;
  memcpy(arp_header.arp_tha, target_address, sizeof(arp_header.arp_tha));
  arp_header.arp_tip = target_ip;
  memcpy(packet.data() + sizeof(ethernet_hdr), &arp_header, sizeof(arp_header));

  return true;
}

bool assembleArpRequestPacket(
  Buffer& packet,
  const uint8_t *source_address, const uint32_t source_ip,
  const uint8_t *target_address, const uint32_t target_ip
) {
  return assembleArpPacket(
    packet,
    arp_op_request,
    source_address, source_ip,
    target_address, target_ip
  );
}

bool assembleArpReplyPacket(
  Buffer& packet,
  const uint8_t *source_address, const uint32_t source_ip,
  const uint8_t *target_address, const uint32_t target_ip
) {
  return assembleArpPacket(
    packet,
    arp_op_reply,
    source_address, source_ip,
    target_address, target_ip
  );
}

// 优化函数参数和函数名称
bool reassembleForwardedPacket(
  Buffer& sendingPacket, const Buffer& originalPacket,
  const uint8_t* source_mac, const uint8_t* target_mac,
  bool isPending
) {
  const size_t packet_size = originalPacket.size();
  sendingPacket.resize(packet_size, 0);

  // 组装 ethernet header
  ethernet_hdr sending_eth_header;
  memcpy(sending_eth_header.ether_dhost, target_mac, sizeof(sending_eth_header.ether_dhost));
  memcpy(sending_eth_header.ether_shost, source_mac, sizeof(sending_eth_header.ether_shost));
  sending_eth_header.ether_type = htons(ethertype_ip);
  memcpy(sendingPacket.data(), &sending_eth_header, sizeof(sending_eth_header));

  // 组装 ip 数据包
  memcpy(
    sendingPacket.data() + sizeof(ethernet_hdr),
    originalPacket.data() + sizeof(ethernet_hdr),
    packet_size - sizeof(ethernet_hdr)
  );
  
  // IMPORTANT 更新 ttl 和 checksum

  // 更新 ttl
  // 非挂起包需要更新 ttl，挂起包不需要
  if (! isPending) {
    uint8_t ttl;
    memcpy(&ttl, sendingPacket.data() + idx_ipHeader + 8, sizeof(ip_hdr::ip_ttl));
    ttl--;
    memcpy(sendingPacket.data() + idx_ipHeader + 8, &ttl, sizeof(ip_hdr::ip_ttl));
  }

  // 更新 checksum
  fillChecksum_ip(sendingPacket);

  return true;
}

// 输入 ethernet frame
bool fillChecksum_ip(Buffer& packet) {
  memcpy(packet.data() + idx_ipHeader + 10, "\x00\x00", sizeof(ip_hdr::ip_sum));
  uint16_t ip_checksum = cksum(packet.data() + idx_ipHeader, sizeof(ip_hdr)); // cksum 已经转换过字节序
  // uint16_t ip_checksum = cksum(packet.data() + idx_ipHeader, (int)packet.size() - (int)idx_ipHeader);
  memcpy(packet.data() + idx_ipHeader + 10, &ip_checksum, sizeof(ip_hdr::ip_sum));
  return true;
}

// 输入 ethernet frame
bool fillChecksum_icmp(Buffer& packet) {
  memcpy(packet.data() + idx_icmpHeader + 2, "\x00\x00", sizeof(icmp_hdr::icmp_sum));
  uint16_t icmp_checksum = cksum(packet.data() + idx_icmpHeader, (int)packet.size() - (int)idx_icmpHeader);
  memcpy(packet.data() + idx_icmpHeader + 2, &icmp_checksum, sizeof(icmp_hdr::icmp_sum));
  return true;
}

bool reassembleIcmpReplyPacket(
  Buffer& reassembledPacket, const Buffer& originalPacket,
  const ip_hdr& original_ipHeader, const ethernet_hdr& original_ethHeader,
  const Interface* sendingInterface,
  const uint8_t icmp_type, const uint8_t icmp_code
) {
  if (originalPacket.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr)) {
    errorOut("Packet size is too small.");
    return false;
  }

  // time exceeded reply and unreachable reply
  if (icmp_type == 0x03 || icmp_type == 0x0b) {
    reassembledPacket.resize(70, 0); // ethernet header 14 + ip header 20 + icmp header 8 + ip header 20 + original datagram 8 = 70
    memcpy(reassembledPacket.data() + idx_icmpHeader + 8, originalPacket.data() + idx_ipHeader, 28); // original ip header and 64b of original datagram
  }
  // echo reply
  else if (icmp_type == 0x00) {
    reassembledPacket.resize(originalPacket.size(), 0); // ethernet header 14 + ip header 20 + icmp header 8 = 42
    memcpy(reassembledPacket.data() + idx_icmpHeader + 4, originalPacket.data() + idx_icmpHeader + 4, originalPacket.size() - idx_icmpHeader - 4); // id + seq + original data (echo request)
  }

  // ICMP header
  icmp_hdr reassembled_icmpHeader;
  reassembled_icmpHeader.icmp_type = icmp_type;
  reassembled_icmpHeader.icmp_code = icmp_code;
  memcpy(reassembledPacket.data() + idx_icmpHeader, &reassembled_icmpHeader, sizeof(icmp_hdr));
  fillChecksum_icmp(reassembledPacket);

  // IP header
  ip_hdr reassembled_ipHeader(original_ipHeader);
	reassembled_ipHeader.ip_len = htons(reassembledPacket.size() - idx_ipHeader);
  reassembled_ipHeader.ip_ttl = 64;
  reassembled_ipHeader.ip_p = 0x01;
  reassembled_ipHeader.ip_src = sendingInterface->ip; // echo reply: 可以为接收接口的 ip，也可以为目标接口的 ip
  reassembled_ipHeader.ip_dst = original_ipHeader.ip_src;
  memcpy(reassembledPacket.data() + idx_ipHeader, &reassembled_ipHeader, sizeof(ip_hdr));
  fillChecksum_ip(reassembledPacket);

  // Ethernet layer
  ethernet_hdr reassembled_ethHeader;
  memcpy(reassembled_ethHeader.ether_dhost, original_ethHeader.ether_shost, sizeof(ethernet_hdr::ether_dhost));
  memcpy(reassembled_ethHeader.ether_shost, sendingInterface->addr.data(), sizeof(ethernet_hdr::ether_shost));
  reassembled_ethHeader.ether_type = htons(ethertype_ip);
  memcpy(reassembledPacket.data() + idx_ethHeader, &reassembled_ethHeader, sizeof(ethernet_hdr));

  return true;
}

bool reassembleEchoReplyPacket(
  Buffer& reassembledPacket, const Buffer& originalPacket,
  const ip_hdr& original_ipHeader, const ethernet_hdr& original_ethHeader,
  const Interface* sendingInterface
) {
  return reassembleIcmpReplyPacket(
    reassembledPacket, originalPacket,
    original_ipHeader, original_ethHeader,
    sendingInterface, 0x00
  );
}

bool reassembleTimeExceededPacket(
  Buffer& reassembledPacket, const Buffer& originalPacket,
  const ip_hdr& original_ipHeader, const ethernet_hdr& original_ethHeader,
  const Interface* sendingInterface
) {
  return reassembleIcmpReplyPacket(
    reassembledPacket, originalPacket,
    original_ipHeader, original_ethHeader,
    sendingInterface, 0x0b
  );
}

bool reassembleUnreachablePacket(
  Buffer& reassembledPacket, const Buffer& originalPacket,
  const ip_hdr& original_ipHeader, const ethernet_hdr& original_ethHeader,
  const Interface* sendingInterface
) {
  return reassembleIcmpReplyPacket(
    reassembledPacket, originalPacket,
    original_ipHeader, original_ethHeader,
    sendingInterface, 0x03, 0x03
  );
}

bool getEthernetHeader(const Buffer &packet, ethernet_hdr &e_hdr) {
  if (packet.size() < sizeof(e_hdr)) {
    errorOut("Packet size is too small.");
    return false;
  }

  memcpy(&e_hdr, packet.data(), sizeof(e_hdr));

  return true;
}

bool getArpHeader(const Buffer& packet, arp_hdr& arp_header) {
  // ethernet header 大小为 14 字节，有 6 字节的目的地址，6 字节的源地址，2 字节的类型
  // arp header 大小为 28 字节，有 2 字节的硬件类型，2 字节的协议类型，1 字节的硬件地址长度，1 字节的协议地址长度，2 字节的操作码，6 字节的源硬件地址，4 字节的源协议地址，6 字节的目的硬件地址，4 字节的目的协议地址
  if (packet.size() < sizeof(ethernet_hdr) + sizeof(arp_header)) {
    errorOut("Packet size is too small.");
    return false;
  }

  memcpy(&arp_header, packet.data() + sizeof(ethernet_hdr), sizeof(arp_header));

  return true;
}

bool getIpHeader(const Buffer& packet, ip_hdr& ip_header)
{
  if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_header)) {
    errorOut("Packet size is too small.");
    return false;
  }

  memcpy(&ip_header, packet.data() + sizeof(ethernet_hdr), sizeof(ip_header));

  return true;
}

bool getIcmpHeader(const Buffer& packet, icmp_hdr& icmp_header) {
  if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_header)) {
    errorOut("Packet size is too small.");
    return false;
  }

  memcpy(
    &icmp_header,
    packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), sizeof(icmp_header)
  );

  return true;
}


} // namespace simple_router
