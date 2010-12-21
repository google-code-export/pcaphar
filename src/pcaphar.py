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

# hash -> cached time
cache_time_hash = {}

# # special har_urls
# example_urls = {}
# example_urls['-1'] = '/harviewer/examples/en-wikipedia-org.har'
# example_urls['-2'] = '/harviewer/examples/www-sina-com-cn.har'

class MainPage(webapp.RequestHandler):
  def get(self):
    template_values = {}
    index_path = os.path.join(os.path.dirname(__file__), 'index.html')
    self.response.out.write(template.render(index_path, template_values))

class Pagespeed(webapp.RequestHandler):
  def get(self):
    url =  self.request.url
    pos = url.find(self.request.path)
    host = ""
    if pos != -1:
      host = url[0:pos]

    har_url = self.request.get('harurl')
    if not har_url:
      hash_str = self.request.get('hash_str')
      har_url = host + "/download/d/"+hash_str
    else:
      hash_str = "0"

    template_values = {
      'hash_str': hash_str,
      'har_url': har_url,
    }

    pagespeed_path = os.path.join(os.path.dirname(__file__), 'pagespeed.html')
    self.response.out.write(template.render(pagespeed_path, template_values))

class View(webapp.RequestHandler):
  def get(self):
    url =  self.request.url
    pos = url.find(self.request.path)
    host = ""
    if pos != -1:
      host = url[0:pos]
    hash_str = self.request.get('hash_str')
    har_url = host + "/download/i/"+hash_str

    template_values = {
      'hash_str': hash_str,
      'har_url': har_url,
    }

    harview_path = os.path.join(os.path.dirname(__file__), 'harview.html')
    self.response.out.write(template.render(harview_path, template_values))



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
      self.response.out.write('Please choose a PCAP file first.')
      self.response.out.write('</body></html>')
      return

    upfile_name = self.request.POST['upfile'].filename

    # Compute the hash
    md5 = hashlib.md5()
    md5.update(pcap_in)
    hash_str = md5.hexdigest()

    url =  self.request.url
    pos = url.find(self.request.path)
    host = ""
    if pos != -1:
      host = url[0:pos]
    har_out = StringIO.StringIO()
    options = convert.Options()
    logging.info("REMOVE COOKIE: %s", self.request.get('removecookies'))
    if not self.request.get('removecookies'):
      options.remove_cookies = False

    error_happened = False
    try:
      convert.convert(pcap_in, har_out, options)
    except:
      error_happened = True

    if error_happened:
      template_values = {
        'upfile_name': upfile_name,
      }
      error_path = os.path.join(os.path.dirname(__file__), 'convert_error.html')
      self.response.out.write(template.render(error_path, template_values))
      return

    har_out_str = har_out.getvalue()
    har_out_str_hash[hash_str] = (upfile_name, har_out_str)
    time_now = time.time()
    heapq.heappush(hash_queue, (time_now, hash_str))
    har_url = host + "/download/i/"+hash_str

    template_values = {
      'hash_str': hash_str,
      'har_url': har_url,
    }
    convert_path = os.path.join(os.path.dirname(__file__), 'harview.html')
    self.response.out.write(template.render(convert_path, template_values))

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
    while len(hash_queue) > 0 and hash_queue[0][0] + 3600 < time_now:
      time_and_hash = heapq.heappop(hash_queue)
      del har_out_str_hash[time_and_hash[1]]

    logging.info("hash=%s", hash_str)
    if len(har_out_str_hash) == 0 or hash_str not in har_out_str_hash:
      self.response.out.write('<html><body>')
      self.response.out.write('Empty')
      self.response.out.write('<hr>return <a href=/ >home</a>')
      self.response.out.write('</body></html>')
      return

    logging.info("path=%s", self.request.path)
    headers = self.response.headers
    if download == "i":
      upfile_name, har_out_str = har_out_str_hash[hash_str]
      headers['Content-Type'] = 'text/javascript'
      self.response.out.write("onInputData(")
      self.response.out.write(har_out_str)
      self.response.out.write(");")
    else:
      upfile_name, har_out_str = har_out_str_hash[hash_str]
      headers['Content-Type'] = 'text/plain'
      download_name = upfile_name + ".har"
      headers['Content-disposition'] = 'attachment; filename=' + download_name
      self.response.out.write(har_out_str)

class Cache(webapp.RequestHandler):
  """
  Generate a cached script for given size.
  """
  def get(self, size_str, name):
    headers = self.response.headers
    headers['Cache-Control'] = 'max-age=36000'
    size = int(size_str)
    if name[-2:] == 'js':
      headers['Content-Type'] = 'text/javascript'
      js_top = "// Copyright 2010 Google Inc. All Rights Reserved.\n"
      js_top += "// A dummy script of size file\n"
      js_top += "function script"+size_str+"() {};\n"
      comment = "\n// comment";
      while len(js_top) + len(comment) < size:
        js_top += comment
      while len(js_top) < size:
        js_top += "/"

      self.response.out.write(js_top)
    elif name[-4:] == 'html':
      self.response.out.write('<html><head>')
      self.response.out.write('<script type=text/javascript src=/cache/' +
                              size_str + '/b.js></script>')
      self.response.out.write('</head><body>')
      self.response.out.write('test size='+size_str)
      self.response.out.write('<hr>return <a href=/ >home</a>')
      self.response.out.write('</body></html>')

    else:
      self.response.out.write('<html><body>')
      self.response.out.write('Unknow type')
      self.response.out.write('<hr>return <a href=/ >home</a>')
      self.response.out.write('</body></html>')

class CheckCache(webapp.RequestHandler):
  """
  Check is a ginve cache id was requested.
  """
  def get(self):
    headers = self.response.headers
    cache_id = self.request.get('cache_id')
    if True:
      headers['Content-Type'] = 'text/javascript'
      self.response.out.write("document.write(cache_id);")



def main():
  """
  The real main function.
  """
  application = webapp.WSGIApplication(
      [('/', MainPage),
       ('/convert', Converter),
       ('/pagespeed', Pagespeed),
       ('/view', View),
       ('/checkcache', CheckCache),
       (r'/cache/(.*)/(.*)', Cache),
       (r'/download/(.*)/(.*)', Download),
       ],
      debug=True)
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
