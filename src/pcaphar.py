# Copyright 2010 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
Google AppEngine service to convert PCAP file to HAR format.

This is the entry point of pcaphar app engine. A user can upload a PCAP file,
pcaphar then converted the file to HAR format. The resoult is show on the page
as well was a download link.
"""

__author__ = 'lsong@google.com (Libo Song)'

import os
import sys

# add third_party directory to sys.path for global import
path = os.path.join(os.path.dirname(__file__), "third_party")
sys.path.append(os.path.abspath(path))
dpkt_path = os.path.join(path, "dpkt")
sys.path.append(os.path.abspath(dpkt_path))
simplejson_path = os.path.join(path, "simplejson")
sys.path.append(os.path.abspath(simplejson_path))



import cgi
import hashlib
import heapq
import logging
import StringIO
import time
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template
from pcap2har import convert

# hash -> pcap input
har_out_str_hash = {}

# priority queue (time, hash), used to remove stale data.
hash_queue = []

class MainPage(webapp.RequestHandler):
  def get(self):
    template_values = {}
    index_path = os.path.join(os.path.dirname(__file__), 'index.html')
    self.response.out.write(template.render(index_path, template_values))
class Converter(webapp.RequestHandler):
  """
  Convert the uploaded file in PCAP to HAR.
  """
  def post(self):
    """
    Process the uploaded PCAP file.
    """
    global har_out_str_hash
    pcap_in = self.request.get('upfile')
    if not pcap_in or pcap_in == "":
      self.response.out.write('<html><body>')
      self.response.out.write('Empty file to convert.')
      self.response.out.write('</body></html>')
      return

    # Compute the hash
    md5 = hashlib.md5()
    md5.update(pcap_in)
    hash_str = md5.hexdigest()

    url =  self.request.url
    request_path = self.request.path
    pos = url.find(request_path)
    host = ""
    if pos != -1:
      host = url[0:pos]
    har_out = StringIO.StringIO()
    options = convert.Options()
    logging.info("REMOVE COOKIE")
    logging.info(self.request.get('removecookies'))
    if not self.request.get('removecookies'):
      options.remove_cookies = False
    convert.convert(pcap_in, har_out, options)
    har_out_str = har_out.getvalue()
    har_out_str_hash[hash_str] = har_out_str
    time_now = time.time()
    heapq.heappush(hash_queue, (time_now, hash_str))
    self.response.out.write('<html><body>\n')
    self.response.out.write('<a href=/ >home</a>\n')
    download_link = '<a href=/download/d/' + hash_str+ '>download</a>\n'
    self.response.out.write(download_link)
    harviewer_url = "/harviewer/index.html?inputUrl="
    inline_harp = host + "/download/i/"+hash_str
    self.response.out.write('<a href=')
    self.response.out.write(harviewer_url + inline_harp)
    self.response.out.write('>HarViewer</a>')
    self.response.out.write('<hr>')
    self.response.out.write('<pre>')
    self.response.out.write(cgi.escape(har_out_str))
    self.response.out.write('</pre></body></html>')

  def get(self):
    """
    If request of GET, e.g., typed URL in browser, redirect it to root.
    """
    self.redirect("/")

class Download(webapp.RequestHandler):
  """
  Dowland handler.

  The converted HAR is shared across requests. Latest convert for the same pcap
  file will overwrite the content.
  """
  def get(self, download, hash_str):
    """
    Process the download.
    """
    global har_out_str_hash

    # Discard saved result older than one hour.
    time_now = time.time()
    logging.info("hash[0].ts=%f now=%f", hash_queue[0][0], time_now)
    while hash_queue[0][0] + 3600 < time_now:
      time_save, that_hash = heapq.heappop(hash_queue)
      del har_out_str_hash[that_hash]

    logging.info("hash=%s", hash_str)
    if len(har_out_str_hash) == 0 or hash_str not in har_out_str_hash:
      self.response.out.write('<html><body>')
      self.response.out.write('Empty')
      self.response.out.write('<hr>return <a href=/ >home</a>')
      self.response.out.write('</body></html>')
      return

    logging.info("path=%s", self.request.path)
    if download == "i":
      har_out_str = har_out_str_hash[hash_str]
      self.response.out.write("onInputData(")
      self.response.out.write(har_out_str)
      self.response.out.write(");")
    else:
      har_out_str = har_out_str_hash[hash_str]
      headers = self.response.headers
      headers['Content-Type'] = 'text/plain'
      headers['Content-disposition'] = 'attachment; filename=har.har'
      self.response.out.write(har_out_str)


def main():
  """
  The real main function.
  """
  application = webapp.WSGIApplication(
      [('/', MainPage),
       ('/convert', Converter),
       (r'/download/(.*)/(.*)', Download),
       ],
      debug=True)
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
