import dns
import dpkt
import logging
import StringIO
import tcp
from pcaputil import ModifiedReader


class TCPFlowAccumulator:
  '''
  Takes a list of TCP packets and organizes them into distinct
  connections, or flows. It does this by organizing packets into a
  dictionary indexed by their socket (the tuple
  ((srcip, sport), (dstip,dport)), possibly the other way around).

  Members:
  flowdict = {socket: tcp.Flow}, the list of tcp.Flow's organized by socket
  '''

  def __init__(self, pcap_reader, options):
    '''
    scans the pcap_reader for TCP packets, and adds them to the tcp.Flow
    they belong to, based on their socket

    Args:
    pcap_reader = pcaputil.ModifiedReader
    '''
    self.flowdict = {}
    self.options = options
    self.options.dns = dns.DNS()
    debug_pkt_count = 0

    # Determine the packet type.
    if (pcap_reader.datalink() == dpkt.pcap.DLT_EN10MB):
      PacketClass = dpkt.ethernet.Ethernet
    elif (pcap_reader.datalink() == dpkt.pcap.DLT_LINUX_SLL):
      PacketClass = dpkt.sll.SLL
    elif pcap_reader.datalink() == 0:
      # Loopback packet
      PacketClass = dpkt.loopback.Loopback
    elif pcap_reader.datalink() == 101:
      # RAW packet
      PacketClass = None
    else:
      raise Exception("Unkown packet type: %d" % reader.datalink())

    try:
      for pkt in pcap_reader:
        debug_pkt_count += 1
        # logging.debug("Processing packet %d", debug_pkt_count)
        # discard incomplete packets
        header = pkt[2]
        if header.caplen != header.len:
          # packet is too short
          logging.warning('discarding incomplete packet')
        # parse packet
        if PacketClass:
          packet = PacketClass(pkt[1])
          ip_packet = packet.data
        else:
          packet = dpkt.ip.IP(pkt[1])
          ip_packet = packet

        try:
          if isinstance(ip_packet, dpkt.ip.IP):
            if self.options.dns.check_dns(pkt[0], ip_packet):
              continue
            if isinstance(ip_packet.data, dpkt.tcp.TCP):
              # then it's a TCP packet process it
              tcppkt = tcp.Packet(pkt[0], ip_packet, ip_packet.data)
              self.process_packet(tcppkt) # organize by socket
        except dpkt.Error, error:
          logging.warning(error)
    except dpkt.dpkt.NeedData, error:
      logging.warning(error)
      logging.warning('A packet in the pcap file was too short, '
                  'debug_pkt_count=%d', debug_pkt_count)
    # finish all tcp flows
    map(tcp.Flow.finish, self.flowdict.itervalues())

  def process_packet(self, pkt):
    '''
    adds the tcp packet to flowdict. pkt is a TCPPacket
    '''
    #try both orderings of src/dst socket components
    #otherwise, start a new list for that socket
    src, dst = pkt.socket
    srcip, srcport = src
    dstip, dstport = dst
    if (srcport == 5223 or dstport == 5223):
      logging.debug("hpvirtgrp packets are ignored.")
      return
    if (srcport == 5228 or dstport == 5228):
      logging.debug("hpvroom packets are ignored.")
      return
    if (srcport == 443 or dstport == 443):
      logging.debug("HTTPS packets are ignored.")
      return
    if (srcport == 53 or dstport == 53):
      logging.debug("DNS TCP packets are ignored.")
      return

    if (src, dst) in self.flowdict:
      self.flowdict[(src, dst)].add(pkt)
    elif (dst, src) in self.flowdict:
      self.flowdict[(dst, src)].add(pkt)
    else:
      # log.debug("New flow: s:%d -> d:%d", srcport, dstport)
      newflow = tcp.Flow(self.options)
      newflow.add(pkt)
      self.flowdict[(src, dst)] = newflow

def TCPFlowsFromString(buf, options):
  '''
  helper function for getting a TCPFlowAccumulator from a pcap buf.
  buffer in, flows out.
  '''
  f = StringIO.StringIO(buf)
  reader = ModifiedReader(f)
  return TCPFlowAccumulator(reader, options)
