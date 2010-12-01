"""
Copyright 2010 Google Inc. All Rights Reserved.

Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.


Parse UDP packet for DNS queries and timings.

TODO(lsong): A detailed description of dns.
"""

__author__ = 'lsong@google.com (Libo Song)'

import sys
import dpkt
import logging

__dns_timing__ = {}
__hostname_start__ = {}


def check_dns(timestamp, ip_packet):
  """Check is a packet is DNS packet, and record DNS timing.
  return True if it is DNS packet.
  """
  if isinstance(ip_packet.data, dpkt.udp.UDP):
    udp = ip_packet.data
    if udp.sport != 53 and udp.dport != 53:
      logging.debug("Unknow UDP port s:%d->d%d", udp.sport, udp.dport)
      return False
    dns = dpkt.dns.DNS(udp.data)
    if len(dns.qd) != 1:
      logging.error("DNS query size > 1: %d", len(dns.qd))
      raise
    qd = dns.qd[0]
    dns_an = getattr(dns, 'an')
    if len(dns_an) == 0:
      # Query only
      if qd.name not in __hostname_start__:
        __hostname_start__[qd.name] = {}
        __hostname_start__[qd.name]['start'] = timestamp
        __hostname_start__[qd.name]['connected'] = 0
    for an in dns_an:
      if hasattr(an, "ip"):
        __dns_timing__[an.ip] = {}
        __dns_timing__[an.ip]['start'] = __hostname_start__[qd.name]['start']
        __hostname_start__[qd.name]['end'] = timestamp
        __dns_timing__[an.ip]['end'] = timestamp
        __dns_timing__[an.ip]['connected'] = 0
        logging.debug("DNS %s: %.3f", qd.name,
                      timestamp - __dns_timing__[an.ip]['start'])
    return True
  return False


def dsn_time_of_connect_to_ip(dst):
  """Get DNS qurey time for resoulting IP address.

  Note: If multiple DNS queries resulted the same IP address, the latest query
  time overrrides the pervious times.
  """
  dns_start_ts = -1
  if (dst in __dns_timing__ and __dns_timing__[dst]['connected'] == 0):
    __dns_timing__[dst]['connected'] = 1
    dns_start_ts = __dns_timing__[dst]['start']
  return dns_start_ts


def dsn_time_of_connect_to_host(host):
  """Get DNS qurey time for host.

  Note: If multiple DNS queries for the same hostname, the latest query
  time overrrides the pervious times.
  """
  dns_start_ts = -1
  if (host in __hostname_start__ and
      __hostname_start__[host]['connected'] == 0):
    __hostname_start__[host]['connected'] = 1
    dns_start_ts = __hostname_start__[host]['start']
  return dns_start_ts



def main(dummy=None):
  """ Test main. """
  pass


if __name__ == '__main__':
  sys.exit(main())
