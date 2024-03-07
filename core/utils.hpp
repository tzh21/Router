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

#ifndef SIMPLE_ROUTER_CORE_UTILS_HPP
#define SIMPLE_ROUTER_CORE_UTILS_HPP

#include "protocol.hpp"
#include "interface.hpp"

namespace simple_router {

uint16_t cksum(const void* data, int len);
uint16_t ethertype(const uint8_t* buf);
uint8_t ip_protocol(const uint8_t* buf);

// 高亮字符串，用于日志输出
const std::string hDebug = "\033[1;34mDEBUG\033[0m: ";
const std::string hError = "\033[1;31mERROR\033[0m: ";

const size_t idx_ethHeader = 0;
const size_t idx_ipHeader = idx_ethHeader + sizeof(ethernet_hdr);
const size_t idx_icmpHeader = idx_ipHeader + sizeof(ip_hdr);

/**
 * Get formatted Ethernet address, e.g. 00:11:22:33:44:55
 */
std::string
macToString(const Buffer& macAddr);

std::string
ipToString(uint32_t ip);

std::string
ipToString(const in_addr& address);

void print_hdr_eth(const uint8_t* buf);
void print_hdr_ip(const uint8_t* buf);
void print_hdr_icmp(const uint8_t* buf);
void print_hdr_arp(const uint8_t* buf);

/* prints all headers, starting from eth */
void print_hdrs(const uint8_t* buf, uint32_t length);

void print_hdrs(const Buffer& buffer);

bool debugOut(std::string msg);
bool errorOut(std::string msg);

bool assembleArpPacket(
  Buffer& packet,
  const uint16_t arp_op,
  const uint8_t *arp_sha, const uint32_t arp_sip,
  const uint8_t *arp_tha, const uint32_t arp_tip
);

bool assembleArpRequestPacket(
  Buffer& packet,
  const uint8_t *source_address, const uint32_t source_ip,
  const uint8_t *target_address, const uint32_t target_ip
);

bool assembleArpReplyPacket(
  Buffer& packet,
  const uint8_t *source_address, const uint32_t source_ip,
  const uint8_t *target_address, const uint32_t target_ip
);

bool reassembleForwardedPacket(
  Buffer& sendingPacket, const Buffer& pendingPacket,
  const uint8_t* source_mac, const uint8_t* target_mac,
  bool isPending
);

bool fillChecksum_ip(Buffer& packet);
bool fillChecksum_icmp(Buffer& packet);

bool reassembleIcmpReplyPacket(
  Buffer& reassembledPacket, const Buffer& originalPacket,
  const ip_hdr& original_ipHeader, const ethernet_hdr& original_ethHeader,
  const Interface* myInterface,
  const uint8_t icmp_type, const uint8_t icmp_code = 0x00
);

bool reassembleEchoReplyPacket(
  Buffer& reassembledPacket, const Buffer& originalPacket,
  const ip_hdr& original_ipHeader, const ethernet_hdr& original_ethHeader,
  const Interface* myInterface
);

bool reassembleTimeExceededPacket(
  Buffer& reassembledPacket, const Buffer& originalPacket,
  const ip_hdr& original_ipHeader, const ethernet_hdr& original_ethHeader,
  const Interface* myInterface
);

bool reassembleUnreachablePacket(
  Buffer& reassembledPacket, const Buffer& originalPacket,
  const ip_hdr& original_ipHeader, const ethernet_hdr& original_ethHeader,
  const Interface* myInterface
);

bool getEthernetHeader(const Buffer &packet, ethernet_hdr &e_hdr);
bool getArpHeader(const Buffer& packet, arp_hdr& arp_header);
bool getIpHeader(const Buffer& packet, ip_hdr& ip_header);
bool getIcmpHeader(const Buffer& packet, icmp_hdr& icmp_header);

} // namespace simple_router

#endif // SIMPLE_ROUTER_CORE_UTILS_HPP
