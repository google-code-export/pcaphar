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

def main(argv=None):
  """The main."""

  if argv is None:
    argv = sys.argv

  # TODO(lsong): get cmdline args/options. For log level, log file?
  parser = optparse.OptionParser(
      usage='usage: %prog inputfile outputfile [options]')
  dummy, args = parser.parse_args()

  # setup logs
  logging.basicConfig(level=logging.INFO)

  # get filenames, or bail out with usage error
  if len(args) == 2:
    inputfile, outputfile = args[0:2]
  else:
    parser.print_help()
    sys.exit()

  logging.info("Processing %s", inputfile)
  flows = pcap.TCPFlowsFromFile(inputfile)

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

  try:
    outf = open(outputfile, 'w')
  except:
    logging.error("File open filed. %s", outputfile)
    outf = False
  if outf:
    json.dump(session, outf, cls=har.JsonReprEncoder, indent=2, encoding='utf8')


if __name__ == '__main__':
  sys.exit(main())
