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
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

from google.appengine.dist import use_library
use_library('django', '1.2')

import sys
# add third_party directory to sys.path for global import
path = os.path.join(os.path.dirname(__file__), "third_party")
sys.path.append(os.path.abspath(path))
dpkt_path = os.path.join(path, "dpkt")
sys.path.append(os.path.abspath(dpkt_path))
simplejson_path = os.path.join(path, "simplejson")
sys.path.append(os.path.abspath(simplejson_path))

import logging
import hashlib
import StringIO
import time
import zlib

from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template
from pcap2har import convert

class TimingRecord(db.Model):
  date = db.DateTimeProperty(auto_now_add=True)
  hash_str = db.StringProperty()
  upload = db.FloatProperty()
  savepcap = db.FloatProperty()
  convert = db.FloatProperty()
  savehar = db.FloatProperty()
  loadhar = db.FloatProperty()
  total = db.FloatProperty()

class DataRecord(db.Model):
  hash_str = db.StringProperty()
  index = db.IntegerProperty()
  data = db.BlobProperty()

class PcapHarInfo(db.Model):
  date = db.DateTimeProperty(auto_now_add=True)
  hash_str = db.StringProperty()
  pcapname = db.StringProperty()
  data_count = db.IntegerProperty()

def GetPcapHarInfo(hash_str):
  query = "WHERE hash_str = :1 ORDER BY date DESC LIMIT 1"
  records = PcapHarInfo.gql(query, hash_str).fetch(1)
  if len(records) == 0:
    return None
  return records[0]

def GetDataRecord(hash_str, idx):
  query = DataRecord.all()
  query.filter("hash_str =", hash_str)
  query.filter("index = ", idx)
  records = query.fetch(1)
  if len(records) == 1:
    return records[0]
  else:
    return None

def GetRequestHostName(request):
  pos = request.url.find(request.path)
  host = ""
  if pos != -1:
    host = request.url[0:pos]
  return host

def SaveData(kind, hash_str, pcapname, data):
  start_time = time.time()
  # Compress the data before save.
  compressed_data = zlib.compress(data)
  # Calculate the count of records.
  size = len(compressed_data)
  chunk_size = 1000000
  data_count = int(size / chunk_size) + 1
  data_hash = ':'.join([kind, hash_str])

  # Save info
  info = GetPcapHarInfo(data_hash)
  if not info:
    info = PcapHarInfo()
    info.hash_str = data_hash
  info.data_count = data_count
  info.pcapname = pcapname
  info.put()

  # Create each data record and save it.
  for idx in range(data_count):
    record = GetDataRecord(data_hash, idx)
    if not record:
      record = DataRecord()
      record.hash_str = data_hash
      record.index = idx
    start = idx*chunk_size
    end = (idx+1)*chunk_size
    if size < end:
      end = size
    record.data = compressed_data[start:end]
    record.put()
  return time.time() - start_time

def LoadData(kind, hash_str):
  start_time = time.time()
  data_hash = ':'.join([kind, hash_str])
  info = GetPcapHarInfo(data_hash)
  if not info:
    return None, None
  data_a = []
  logging.info("Data count:" + str(info.data_count))
  for idx in range(info.data_count):
    record = GetDataRecord(data_hash, idx)
    if not record:
      logging.error("Not found: " + data_hash + " -- " + str(idx))
      return None, None
    data_a.append(record.data)
  data = zlib.decompress(''.join(data_a))
  duration = time.time() - start_time
  return info.pcapname, data, duration

class MainPage(webapp.RequestHandler):
  def get(self):
    template_values = {}
    index_path = os.path.join(os.path.dirname(__file__),
                              'templates/index.html')
    self.response.out.write(template.render(index_path, template_values))

class Pagespeed(webapp.RequestHandler):
  def get(self):
    host = GetRequestHostName(self.request)
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

    pagespeed_path = os.path.join(os.path.dirname(__file__),
                                  'templates/pagespeed.html')
    self.response.out.write(template.render(pagespeed_path, template_values))

class View(webapp.RequestHandler):
  def get(self):
    host = GetRequestHostName(self.request)
    hash_str = self.request.get('hash_str')
    har_url = host + "/download/i/"+hash_str

    template_values = {
      'hash_str': hash_str,
      'har_url': har_url,
    }

    harview_path = os.path.join(os.path.dirname(__file__),
                                'templates/harview.html')
    self.response.out.write(template.render(harview_path, template_values))



class Converter(webapp.RequestHandler):
  """
  Convert the uploaded file in PCAP to HAR.
  """
  def __init__(self):
    self.perf_record = TimingRecord()

  def GetUploadFile(self):
    start = time.time()
    upload_input = self.request.get('upfile')
    self.perf_record.upload = time.time() - start

    if not upload_input or upload_input == "":
      self.response.out.write('<html><body>')
      self.response.out.write('Please choose a PCAP file first.')
      self.response.out.write('</body></html>')
      return None
    return upload_input

  def ConvertPcapToHar(self, pcap_input, har_out, pcap_input_name):
    options = convert.Options()
    logging.info("Remove Cookie: %s", self.request.get('removecookies'))
    if not self.request.get('removecookies'):
      options.remove_cookies = False

    try:
      start_time = time.time()
      convert.convert(pcap_input, har_out, options)
      self.perf_record.convert = time.time() - start_time
    except:
      template_values = {
        'upfile_name': pcap_input_name,
      }
      error_path = os.path.join(os.path.dirname(__file__),
                                'templates/convert_error.html')
      self.response.out.write(template.render(error_path, template_values))
      return False
    return True

  def post(self):
    """
    Process the uploaded PCAP file.
    """
    total_time_start = time.time()
    pcap_input = self.GetUploadFile()
    if not pcap_input:
      return

    pcap_input_name = self.request.POST['upfile'].filename

    # Compute the hash
    md5 = hashlib.md5()
    md5.update(pcap_input)
    pcap_hash_str = md5.hexdigest()
    # Save the pcap data.
    duration = SaveData('pcap', pcap_hash_str, pcap_input_name, pcap_input)
    self.perf_record.savepcap = duration

    if pcap_input_name[-4:] == '.har':
        har_out_str = pcap_input
    else:
        har_out = StringIO.StringIO()
        if not self.ConvertPcapToHar(pcap_input, har_out, pcap_input_name):
            return
        har_out_str = har_out.getvalue()

    # Save the har data.
    duration = SaveData('har ', pcap_hash_str, pcap_input_name, har_out_str)
    self.perf_record.savehar = duration

    # Show the waterfall view.
    self.redirect("/view?hash_str=" + pcap_hash_str)
    self.perf_record.total = time.time() - total_time_start
    logging.info("Total time:" + str(self.perf_record.total))
    self.perf_record.hash_str = pcap_hash_str
    self.perf_record.put()


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
  def __init__(self):
    self.perf_record = TimingRecord()

  def get(self, download, hash_str):
    """
    Process the download.
    """
    total_time_start = time.time()
    name, data, duration = LoadData('har ', hash_str)
    self.perf_record.loadhar = duration
    if not name:
      self.response.out.write('<html><body>')
      self.response.out.write('Empty')
      self.response.out.write('<hr>return <a href=/ >home</a>')
      self.response.out.write('</body></html>')
      return

    logging.info("path=%s", self.request.path)
    headers = self.response.headers
    if download == "i":
      headers['Content-Type'] = 'text/javascript'
      self.response.out.write("onInputData(")
      self.response.out.write(data)
      self.response.out.write(");")
    else:
      headers['Content-Type'] = 'text/plain'

      if name[-4:] == '.har':
        download_name = name
      else:
        download_name = name + '.har'
      headers['Content-disposition'] = 'attachment; filename=' + download_name
      self.response.out.write(data)
    self.perf_record.total = time.time() - total_time_start
    logging.info("Total time:" + str(self.perf_record.total))
    self.perf_record.hash_str = hash_str
    self.perf_record.put()


class Timing(webapp.RequestHandler):
  """
  Show timing info.
  """
  def get(self):
    time_start = time.time()
    self.response.out.write('<table><tr>\n')
    self.response.out.write('<th>date')
    self.response.out.write('<th>upload')
    self.response.out.write('<th>savepcap')
    self.response.out.write('<th>convert')
    self.response.out.write('<th>savehar')
    self.response.out.write('<th>loadhar')
    self.response.out.write('<th>total')
    self.response.out.write('<th>hash')
    self.response.out.write('\n</tr>\n')

    query = TimingRecord.all().order("-date")
    results = query.fetch(1000)
    for record in results:
      self.response.out.write('<tr><td>')
      self.response.out.write(str(record.date))
      self.response.out.write(' <td> ')
      self.response.out.write(str(record.upload or ""))
      self.response.out.write(' <td> ')
      self.response.out.write(str(record.savepcap or ""))
      self.response.out.write(' <td> ')
      self.response.out.write(str(record.convert or ""))
      self.response.out.write(' <td> ')
      self.response.out.write(str(record.savehar or ""))
      self.response.out.write(' <td> ')
      self.response.out.write(str(record.loadhar  or ""))
      self.response.out.write(' <td> ')
      self.response.out.write(str(record.total or ""))
      #self.response.out.write(' <td> ')
      #self.response.out.write(record.hash_str)
      self.response.out.write('\n<tr>\n')
    self.response.out.write('</table>\n')
    time_end = time.time()
    self.response.out.write('<hr>')
    self.response.out.write('Timing: ' + '%f'%time_start
                            + ' - ' + '%f'%time_end)

def main():
  """
  The real main function.
  """
  application = webapp.WSGIApplication(
      [('/', MainPage),
       ('/convert', Converter),
       ('/pagespeed', Pagespeed),
       ('/view', View),
       ('/timing', Timing),
       (r'/download/(.*)/(.*)', Download),
       ],
      debug=True)
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
