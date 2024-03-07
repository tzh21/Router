/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

#define DEBUG_MODE

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

/// @brief 处理 ethernet packet
/// @param packet 
/// @param inIface 
void SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  debugOut("got packet of size " + std::to_string(packet.size()) + " on interface " + inIface);
  
  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    errorOut("Unknown interface");
    return;
  }

  // FILL THIS IN
  // 解析 ethernet packet 的头部
  ethernet_hdr ether_hdr;
  if (! getEthernetHeader(packet, ether_hdr)) {
    return;
  }

  // 根据包的类型进行分类处理
  if (ether_hdr.ether_type == htons(ethertype_arp)) { // ARP packet
    if (! handleArpPacket(packet, ether_hdr, iface)) {
      return;
    }
  } else if (ether_hdr.ether_type == htons(ethertype_ip)) { // IP packet
    if (! handleIpPacket(packet, ether_hdr, iface)) {
      return;
    }
  }
}

// 在处理 ARP 包时，不能只使用 ARP header，需要用到 ethernet header，因为有时 ARP header 中会出现 00:00:00:00:00:00，不能解析
bool SimpleRouter::handleArpPacket(const Buffer& received_packet, const ethernet_hdr& received_e_hdr, const Interface* inInterface) {
  // 解析 ARP 包的头部
  arp_hdr received_arp_header;
  if (! getArpHeader(received_packet, received_arp_header)) {
    return false;
  }

  // 将 ARP 请求的源 IP 地址加入 ARP 缓存表
  const bool is_lookupNotFound = (m_arp.lookup(received_arp_header.arp_sip) == nullptr);
  std::shared_ptr<ArpRequest> arp_req = nullptr;
  if (is_lookupNotFound) {
    debugOut("source ip is not in cache. Insert it");
    Buffer source_mac(sizeof(ethernet_hdr::ether_shost), 0);
    memcpy(source_mac.data(), received_packet.data() + sizeof(ethernet_hdr::ether_dhost), sizeof(ethernet_hdr::ether_shost));
    arp_req = m_arp.insertArpEntry(source_mac, received_arp_header.arp_sip);
  }

  // 类型为 request
  if (received_arp_header.arp_op == htons(arp_op_request)) {
    debugOut("receive an ARP request");

    // 如果请求的对象是自己，则发送回复
    const Interface* myInterface = findIfaceByIp(received_arp_header.arp_tip);
    if (myInterface != nullptr) {
      debugOut("ARP request for me");
      Buffer replyPacket;
      // 组装 ARP 回复包
      assembleArpReplyPacket(
        replyPacket,
        myInterface->addr.data(),
        myInterface->ip,
        received_e_hdr.ether_shost,
        received_arp_header.arp_sip
      );
      // 发送 ARP 回复包
      debugOut("send an ARP reply packet through " + inInterface->name);
      sendPacket(replyPacket, inInterface->name);
      return true;
    }
    // 如果请求对象不是自己，则忽视
    else {
      debugOut("ARP request not for me.");
      return true;
    }
  }
  // 类型为 reply
  else if (received_arp_header.arp_op == htons(arp_op_reply)) {
    debugOut("receive an ARP reply");
    // 自身的 ARP 请求队列中有和该 reply 关联的，需要发送挂起的数据包
    if (arp_req != nullptr) {
      m_arp.sendPendingIpPackets(
        received_arp_header.arp_sip,
        received_e_hdr.ether_dhost,
        received_e_hdr.ether_shost
      );
    }
  }

  return true;
}

bool SimpleRouter::handleIpPacket(const Buffer& received_packet, const ethernet_hdr& received_e_hdr, const Interface* inInterface) {
  ip_hdr received_ip_header;
  getIpHeader(received_packet, received_ip_header);
  
  // 224.0.0.251 是一个广播 ip，不是作业的内容，直接丢弃
  if (received_ip_header.ip_dst == inet_addr("224.0.0.251")) {
    debugOut("Router receives a packet to 224.0.0.251 and discards it");
    return true;
  }

  // ip 校验
  if (cksum(&received_ip_header, sizeof(received_ip_header)) != 0xffff) {
    errorOut("ip checksum error");
    return true;
  }

  // 更新 ARP 缓存
  if (m_arp.lookup(received_ip_header.ip_src) == nullptr) {
    debugOut("source ip is not in cache. Insert it");
    Buffer source_mac(sizeof(ethernet_hdr::ether_shost), 0);
    memcpy(source_mac.data(), received_packet.data() + sizeof(ethernet_hdr::ether_dhost), sizeof(ethernet_hdr::ether_shost));
    m_arp.insertArpEntry(source_mac, received_ip_header.ip_src);
  }

  const uint8_t currentTTL = received_ip_header.ip_ttl - 1;
  const Interface *dstInterface = findIfaceByIp(received_ip_header.ip_dst);

	// 若 traceroute && 目标为自己，则发送type 3 icmp
	if (received_ip_header.ip_p == 0x11 && dstInterface != nullptr) {
		debugOut("receive a traceroute udp to me");
		print_hdrs(received_packet);
		Buffer unreachablePacket;
		reassembleUnreachablePacket(
      unreachablePacket, received_packet,
      received_ip_header, received_e_hdr,
      inInterface
		);
		debugOut("send an unreachable packet through " + inInterface->name);
		print_hdrs(unreachablePacket);
		sendPacket(unreachablePacket, inInterface->name);
		return true;
	}

  // 若超时，则发送 time exceeded
  if (currentTTL <= 0) {
    debugOut("receive a time exceeded packet");
    print_hdrs(received_packet);
    Buffer timeExceededPacket;
    reassembleTimeExceededPacket(
      timeExceededPacket, received_packet,
      received_ip_header, received_e_hdr,
      inInterface
    );
    debugOut("send a reply to time exceeded packet through " + inInterface->name);
    print_hdrs(timeExceededPacket);
    sendPacket(timeExceededPacket, inInterface->name);
    return true;
  }

  // 目标 ip 为自身时，对 ICMP echo 做出回应
  if (dstInterface != nullptr) {
    // ICMP
    if (received_ip_header.ip_p == 0x01) {
      // ICMP 校验
      const size_t idx_icmpHeader = sizeof(ethernet_hdr) + sizeof(ip_hdr);
      if (cksum(received_packet.data() + idx_icmpHeader, (int)sizeof(received_packet) - (int)idx_icmpHeader) != 0xffff) {
        errorOut("ICMP checksum error");
        return true;
      }

      icmp_hdr received_icmp_header;
      getIcmpHeader(received_packet, received_icmp_header);

      // 接收到 echo
      // 发送 echo reply
      if (received_icmp_header.icmp_type == 0x08) {
        debugOut("receive an ICMP echo for me");
        print_hdrs(received_packet);
        Buffer replyPacket;
        reassembleEchoReplyPacket(
          replyPacket, received_packet,
          received_ip_header, received_e_hdr,
          inInterface
        );
        debugOut("send an echo reply packet through " + inInterface->name);
        print_hdrs(replyPacket);
        sendPacket(replyPacket, inInterface->name);
        return true;
      }
      else {
        debugOut("ICMP packet for me, but not echo");
        return true;
      }
    }
    // traceroute 使用的协议（UDP）
    // traceroute 终点为自己，因此发送 time exceeded
    else {
      debugOut("IP packet for me, but with unrecognized IP protocal");
      print_hdrs(received_packet);
      return true;
    }
  }
  // 目标 ip 不为自身，将其转发
  else {
    debugOut("receive a forwarded IP packet");
    // 在 arp cache 中能找到目标 ip 对应的 mac 地址时，直接发送
    auto targetArpEntry = m_arp.lookup(received_ip_header.ip_dst);
    auto routingTableEntry = m_routingTable.lookup(received_ip_header.ip_dst);
    auto outInterface = findIfaceByName(routingTableEntry.ifName);
    if (targetArpEntry != nullptr) {
      debugOut("ARP cache hit");
      Buffer forwardedPacket;
      reassembleForwardedPacket(
        forwardedPacket, received_packet,
        outInterface->addr.data(), targetArpEntry->mac.data(), false
      );
      debugOut("send a forwarded packet through " + outInterface->name);
      print_hdrs(forwardedPacket);
      sendPacket(forwardedPacket, outInterface->name);
      return true;
    }
    // 找不到 mac 地址时，将数据包挂载到 arp request 上，等待 arp reply
    else {
      debugOut("ARP cache miss. Pending for ARP reply.");
      debugOut("pending packet");
      print_hdrs(received_packet);
      m_arp.queueRequest(received_ip_header.ip_dst, received_packet, outInterface->name);
      return true;
    }
  }

  return true;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

} // namespace simple_router {
