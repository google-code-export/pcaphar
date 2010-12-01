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
sys.path.insert(0, os.path.abspath(path))
dpkt_path = os.path.join(path, "dpkt")
sys.path.insert(0, os.path.abspath(dpkt_path))


import StringIO
import cgi
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app

from pcap2har import convert

har_out_str = ""
class MainPage(webapp.RequestHandler):
  def get(self):
    self.response.out.write("""
<html>
<body>
<form method='POST' enctype='multipart/form-data' action='/convert'>
File to upload: <input type=file name=upfile><br>
<br>
<input type=submit value=Convert>
</body>
</html>""")

class Converter(webapp.RequestHandler):
  """
  Convert the uploaded file in PCAP to HAR.
  """
  def post(self):
    """
    Process the uploaded PCAP file.
    """
    global har_out_str
    pcap_in = self.request.get('upfile')
    if not pcap_in or pcap_in == "":
      self.response.out.write('<html><body>')
      self.response.out.write('Empty file to convert.')
      self.response.out.write('</body></html>')
      return

    har_out = StringIO.StringIO()
    convert.convert(pcap_in, har_out)
    har_out_str = har_out.getvalue()
    self.response.out.write('<html><body>')
    self.response.out.write('HAR')
    self.response.out.write('<a href=/download>download</a>')
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
  
  TODO(lsong): The converted HAR is shared across requests. Latest convert will
  overwrite the content. Find a way to save the content for a session.
  """
   
  def get(self):
    """
    Process the download.
    """
    global har_out_str
    if har_out_str == "":
      self.response.out.write('<html><body>')
      self.response.out.write('Empty')
      self.response.out.write('</body></html>')
    else:
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
       ('/download', Download),],
      debug=True)
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
