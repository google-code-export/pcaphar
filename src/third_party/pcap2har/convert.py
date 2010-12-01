#!/usr/bin/python

'''
Main program that converts pcaps to HAR's.
'''

import pcap
import optparse
import logging
import sys
import http
import httpsession
import har
import simplejson as json

def convert(pcap_in, har_out):
  flows = pcap.TCPFlowsFromString(pcap_in)

  # generate HTTP Flows
  httpflows = []
  flow_count = 0
  for flow in flows.flowdict.itervalues():
    try:
      httpflows.append(http.Flow(flow))
      flow_count += 1
    except http.Error, error:
      logging.warning(error)

  pairs = reduce(lambda x, y: x+y.pairs, httpflows, [])
  logging.info("Flow=%d HTTP=%d", flow_count, len(pairs))

  # parse HAR stuff
  session = httpsession.HTTPSession(pairs)

  json.dump(session, har_out, cls=har.JsonReprEncoder, indent=2,
            encoding='utf8')
