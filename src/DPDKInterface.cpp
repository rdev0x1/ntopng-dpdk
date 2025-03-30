/*
 *
 * (C) 2013-25 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include "ntop_includes.h"

#ifdef HAVE_DPDK
#include <map>
#include "libl2fwd.h"

/* **************************************************** */

static std::map<int, DPDKInterface *> port_to_iface;

static void dpdk_packet_handler(const uint8_t *packet, uint16_t len,
                                uint16_t port, void *userdata) {
  pcap_pkthdr hdr;

  auto it = port_to_iface.find(port);
  if (it == port_to_iface.end()) {
    // Not yet registered or invalid port
    return;
  }

  DPDKInterface *iface = it->second;
  if (iface == NULL) {
    // Should not happen
    return;
  }

  gettimeofday(&hdr.ts, NULL);
  hdr.caplen = hdr.len = len;

  try {
    u_int16_t eth_type;
    Host *srcHost = NULL, *dstHost = NULL;
    Flow *flow = NULL;

    iface->dissectPacket(UNKNOWN_PKT_IFACE_IDX, DUMMY_BRIDGE_INTERFACE_ID,
                         iface->get_datalink(), true /* ingress */, NULL, &hdr,
                         packet, &eth_type, &srcHost, &dstHost, &flow);
  } catch (std::bad_alloc &ba) {
    static bool oom_warning_sent = false;
    if (!oom_warning_sent) {
      ntop->getTrace()->traceEvent(TRACE_WARNING, "Not enough memory");
      oom_warning_sent = true;
    }
  }
}

/* **************************************************** */

DPDKInterface::DPDKInterface(const char *_name) : NetworkInterface(_name) {
  set_datalink(DLT_EN10MB);
}

/* **************************************************** */

DPDKInterface::~DPDKInterface() { shutdown(); }

/* **************************************************** */

void DPDKInterface::initAllDPDKInterfaces() {
  const uint16_t max_ports = 16;
  uint16_t ports[max_ports];

  libl2fwd_config_t cfg = {.packet_handler = dpdk_packet_handler,
                           .packet_handler_userdata = NULL,
                           .enabled_port_mask = 0x01,
                           .promiscuous_mode = 1,
                           .mac_updating = 1};

  const char *argv[] = {"ntopng", "-l", "0-3", "-n", "4", "--", "-p", "3"};
  int argc = sizeof(argv) / sizeof(argv[0]);
  static bool dpdk_initialized = false;

  if (!dpdk_initialized) {
    if (libl2fwd_init(&cfg, argc, const_cast<char **>(argv)) != 0) {
      ntop->getTrace()->traceEvent(TRACE_ERROR, "libl2fwd_init failed");
      throw std::runtime_error("libl2fwd initialization failed");

      printf("********debug");
    }

    dpdk_initialized = true;
  }

  uint16_t num_ports = libl2fwd_get_port_ids(ports, max_ports);

  for (uint16_t i = 0; i < num_ports; i++) {
    uint16_t port_id = ports[i];

    if (!initAndRegister(port_id)) {
      ntop->getTrace()->traceEvent(TRACE_ERROR,
                                   "Could not register DPDK port %u", port_id);
      continue;
    }

    ntop->getTrace()->traceEvent(
        TRACE_NORMAL, "DPDK port %u successfully registered.", port_id);
  }
}

bool DPDKInterface::initAndRegister(uint16_t port_id) {
  struct rte_ether_addr mac_addr;

  printf("**** dpdk\n");

  int ret = libl2fwd_get_mac_addr(port_id, &mac_addr);
  if (ret != 0) {
    ntop->getTrace()->traceEvent(TRACE_ERROR, "Invalid DPDK port %u", port_id);
    return false;
  }

  char ifname[32];
  snprintf(ifname, sizeof(ifname), "dpdk%d", port_id);
  printf("**** dpdk %s\n", ifname);

  // We check if map already has this port
  auto it = port_to_iface.find(port_id);
  if (it != port_to_iface.end()) {
    ntop->getTrace()->traceEvent(
        TRACE_ERROR, "Tried to register dpdk port=%u more than once", port_id);
    return false;
  }

  DPDKInterface *iface = new DPDKInterface(ifname);
  if (iface == NULL) {
    ntop->getTrace()->traceEvent(
        TRACE_ERROR, "No memory. Cannot register dpdk port=%d", port_id);
    return false;
  }

  port_to_iface[port_id] = iface;
  ntop->registerInterface(iface);

  ntop->getTrace()->traceEvent(
      TRACE_NORMAL,
      "Registered DPDK interface %s with MAC %02X:%02X:%02X:%02X:%02X:%02X",
      ifname, mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
      mac_addr.addr_bytes[2], mac_addr.addr_bytes[3], mac_addr.addr_bytes[4],
      mac_addr.addr_bytes[5]);

  return true;
}

/* **************************************************** */

void DPDKInterface::singlePacketPollLoop() { libl2fwd_start(); }

/* **************************************************** */

void DPDKInterface::multiPacketPollLoop() {
  singlePacketPollLoop();  // Same as single packet loop for now
}

/* **************************************************** */

static void *packetPollLoop(void *ptr) {
  DPDKInterface *iface = (DPDKInterface *)ptr;

  /* Wait until initialization completes */
  while (iface->isStartingUp()) sleep(1);

  while (iface->idle()) {
    if (ntop->getGlobals()->isShutdown()) return (NULL);
    iface->purgeIdle(time(NULL));
    sleep(1);
  }

  iface->singlePacketPollLoop();

  ntop->getTrace()->traceEvent(TRACE_NORMAL, "Terminated packet polling for %s",
                               iface->get_name());
  return (NULL);
}

/* **************************************************** */

void DPDKInterface::startPacketPolling() {
  if (libl2fwd_start() != 0) {
    ntop->getTrace()->traceEvent(TRACE_ERROR, "libl2fwd_start failed");
    throw std::runtime_error("libl2fwd start failed");
  }

  NetworkInterface::startPacketPolling();
}

/* **************************************************** */

void DPDKInterface::shutdown() {
  libl2fwd_stop();
  libl2fwd_cleanup();
  NetworkInterface::shutdown();
}

/* **************************************************** */

void DPDKInterface::updatePacketsStats() {
  libl2fwd_stats_t stats;
  u_int32_t dropped = 0;

  if (libl2fwd_get_stats(0, &stats) == 0) {
    dropped = stats.dropped_packets;
  }

  dropped_packets = dropped;
}

/* **************************************************** */

u_int32_t DPDKInterface::getNumDroppedPackets() { return dropped_packets; }

/* **************************************************** */

bool DPDKInterface::set_packet_filter(char *filter) {
  ntop->getTrace()->traceEvent(
      TRACE_WARNING, "DPDK interface does not support BPF filtering.");
  return false;
}

/* **************************************************** */

#endif /* HAVE_DPDK */
