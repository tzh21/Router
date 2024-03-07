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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

#ifndef DEBUG_MODE
#define DEBUG_MODE

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

// 在路由器插入一个新的 ARP cache entry 时触发
// 发送和新 ip 关联的挂起数据包
// TODO source 和 dest 未必为自身
bool ArpCache::sendPendingIpPackets(
  const uint32_t dst_ip,
  const uint8_t* source_address,
  const uint8_t* target_address
) {
  debugOut("handle pending IP packets");

  // 在 m_arpRequests 队列中找到和 dst_ip 关联的请求
  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [dst_ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == dst_ip);
                           });
  // 发送挂起的数据包，然后移除请求
  if (request != m_arpRequests.end()) {
    for (const auto& pendingPacket : (*request)->packets) {
      Buffer sendingPacket;
      if (
        ! reassembleForwardedPacket(
          sendingPacket, pendingPacket.packet,
          source_address, target_address, true
        )
      ) {
        errorOut("cannot reassemble pending packet");
        return false;
      }
      const Interface* outInterface = m_router.findIfaceByName(m_router.getRoutingTable().lookup(dst_ip).ifName);
      if (outInterface == nullptr) {
        errorOut("cannot find interface");
        return false;
      }
      debugOut("send pending packet through " + outInterface->name);
      print_hdrs(sendingPacket);
      m_router.sendPacket(sendingPacket, outInterface->name);
    }
    // 需要考虑应该使用 erase 还是 remove，即是否需要真的从 m_arpRequests 中删除请求
    // 实际上，因为 dst_ip 是有限的（在本作业中不到 10 个），即使不删除也没有什么影响
    removeRequest(*request);
    // m_arpRequests.erase(request);
  } else {
    debugOut("no corresponding pending packets");
    return true;
  }

  return true;
}

// bool assembleUnreachablePacket();

bool ArpCache::handleArpRequest(std::shared_ptr<ArpRequest> req, bool& shouldRemove) {
  if (steady_clock::now() - req->timeSent > seconds(1)) {
    if (req->nTimesSent >= MAX_SENT_TIME) {
      debugOut("times sent exceed 5");
      
      // TODO 发送 ICMP host unreachable 给所有等待该请求的数据包的源地址
      for (const auto& pendingPacket : req->packets) {
        Buffer sendingPacket;
        ethernet_hdr ethHeader;
        getEthernetHeader(pendingPacket.packet, ethHeader);
        ip_hdr ipHeader;
        getIpHeader(pendingPacket.packet, ipHeader);
        reassembleUnreachablePacket(
          sendingPacket, pendingPacket.packet,
          ipHeader, ethHeader,
          m_router.findIfaceByName(pendingPacket.iface)
        );
        debugOut("send ICMP host unreachable through " + pendingPacket.iface);
        print_hdrs(sendingPacket);
        m_router.sendPacket(sendingPacket, pendingPacket.iface);
      }

      shouldRemove = true;
      return true;
    }
    else {
      debugOut("times sent is " + std::to_string(req->nTimesSent) + "; last sent ");

      shouldRemove = false;

      // 发送 ARP request
      const uint8_t* broadcast_addr = (uint8_t*)"\xff\xff\xff\xff\xff\xff";
      const Interface* outInterface = m_router.findIfaceByName(m_router.getRoutingTable().lookup(req->ip).ifName); // 根据网络接口名称找到网络接口
      if (outInterface == nullptr) {
        std::cerr << "error: cannot find interface" << std::endl;
        return false;
      }
      Buffer sentPacket;
      assembleArpRequestPacket(
        sentPacket,
        outInterface->addr.data(), outInterface->ip,
        broadcast_addr, req->ip
      );
      debugOut("send an ARP request through " + outInterface->name);
      print_hdrs(sentPacket);
      m_router.sendPacket(sentPacket, outInterface->name);

      // 更新请求的发送时间和重传次数
      req->timeSent = steady_clock::now();
      req->nTimesSent++;

      return true;
    }  
  }
  return true;
}

void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // FILL THIS IN

  // 处理队列中的所有 request，进行重发和删除
  for (auto iter = m_arpRequests.begin(); iter != m_arpRequests.end(); ){
    bool shouldRemove = false;
    if (! handleArpRequest(*iter, shouldRemove)) {
      break;
    }
    if (shouldRemove) {
      iter = m_arpRequests.erase(iter);
    }
    else {
      ++iter;
    }
  }
  
  // 删除 ARP cache 中的过期的 entry
  for (auto iter = m_cacheEntries.begin(); iter != m_cacheEntries.end(); ) {
    if (! (*iter)->isValid) {
      iter = m_cacheEntries.erase(iter);
    }
    else {
      ++iter;
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router

#endif