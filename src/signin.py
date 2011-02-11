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
import logging
import zlib

# add third_party directory to sys.path for global import
third_path_path = os.path.join(os.path.dirname(__file__), "third_party")
sys.path.append(os.path.abspath(third_path_path))
dpkt_path = os.path.join(third_path_path, "dpkt")
sys.path.append(os.path.abspath(dpkt_path))
simplejson_path = os.path.join(third_path_path, "simplejson")
sys.path.append(os.path.abspath(simplejson_path))


logging.info(sys.path)
import hashlib
import heapq
import StringIO
import time
from google.appengine.api import users
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template
from pcap2har import convert

class PcapRecord(db.Model):
  date = db.DateTimeProperty(auto_now_add=True)
  hash_str = db.StringProperty()
  pcapname = db.StringProperty()
  pcap = db.BlobProperty()

class HarRecord(db.Model):
  date = db.DateTimeProperty(auto_now_add=True)
  user = db.UserProperty()
  hash_str = db.StringProperty()
  pcapname = db.StringProperty()
  har = db.BlobProperty()

def GetHarRecord(hash_str):
  query = "WHERE hash_str = :1 ORDER BY date DESC LIMIT 1"
  records = HarRecord.gql(query, hash_str).fetch(1);
  if len(records) == 0:
    return None
  return records[0]

def GetPcapRecord(hash_str):
  query = "WHERE hash_str = :1 ORDER BY date DESC LIMIT 1"
  records = PcapRecord.gql(query, hash_str).fetch(1);
  if len(records) == 0:
    return None
  return records[0]

def GetRecordsOfUser(user, limit):
  query = "WHERE user = :1 ORDER BY date DESC"
  return HarRecord.gql(query, user).fetch(limit);

class MainPage(webapp.RequestHandler):
  def get(self):
    user = users.get_current_user();
    user_name = ""
    url_text = "sign in"
    recent_records = []
    if user:
      signurl = users.create_logout_url(self.request.uri)
      user_name = user.nickname()
      url_text = "sign out"
      recent_records = GetRecordsOfUser(user, 10)
    else:
      signurl = users.create_login_url(self.request.uri)


    template_values = {
      'user_name': user_name,
      'url_text': url_text,
      'sign_url': signurl,
      'has_records': len(recent_records) > 0,
      'recent_records': recent_records,
    }
    index_path = os.path.join(os.path.dirname(__file__),
                              'templates/signin-index.html')
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
      har_url = host + "/signin/download/d/"+hash_str
    else:
      hash_str = "0"

    template_values = {
      'hash_str': hash_str,
      'har_url': har_url,
    }

    pagespeed_path = os.path.join(os.path.dirname(__file__),
                                  'templates/signin-pagespeed.html')
    self.response.out.write(template.render(pagespeed_path, template_values))

class View(webapp.RequestHandler):
  def get(self):
    url =  self.request.url
    pos = url.find(self.request.path)
    host = ""
    if pos != -1:
      host = url[0:pos]
    hash_str = self.request.get('hash_str')
    har_url = host + "/signin/download/i/"+hash_str

    template_values = {
      'hash_str': hash_str,
      'har_url': har_url,
    }

    harview_path = os.path.join(os.path.dirname(__file__),
                                'templates/signin-harview.html')
    self.response.out.write(template.render(harview_path, template_values))



class Converter(webapp.RequestHandler):
  """
  Convert the uploaded file in PCAP to HAR.
  """
  def post(self):
    """
    Process the uploaded PCAP file.
    """

    user = users.get_current_user()
    if not user:
      self.redirect("/")

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
      error_path = os.path.join(os.path.dirname(__file__),
                                'templates/convert_error.html')
      self.response.out.write(template.render(error_path, template_values))
      return

    har_out_str = har_out.getvalue()
    time_now = time.time()

    if user:
      har_view_html = "templates/signin-harview.html"
      har_url = host + "/signin/download/i/"+hash_str
      # Save to the Datastore.
      har_record = GetHarRecord(hash_str)
      if not har_record:
        har_record = HarRecord()
      har_record.user = user
      har_record.hash_str = hash_str
      har_record.pcapname = upfile_name
      har_record.har = zlib.compress(har_out_str)
      har_record.put()

      pcap_record = GetPcapRecord(hash_str)
      if not pcap_record:
        pcap_record = PcapRecord()
        pcap_record.hash_str = hash_str
        pcap_record.pcap = pcap_in
        pcap_record.put()
    else:
      har_view_html = "templates/harview.html"
      har_url = host + "/download/i/"+hash_str

    template_values = {
      'hash_str': hash_str,
      'har_url': har_url,
    }
    convert_path = os.path.join(os.path.dirname(__file__), har_view_html)
    self.response.out.write(template.render(convert_path, template_values))

  def get(self):
    """
    If request of GET, e.g., typed URL in browser, redirect it to root.
    """
    self.redirect("/")

class List(webapp.RequestHandler):
  """
  List HAR files.
  """
  def get(self):
    """
    Process the list.
    """
    user = users.get_current_user()
    if user:
      #records = HarRecord.gql("WHERE user = :user ORDER BY date", user=user)
      records = HarRecord.all()
      records.filter("user =", user)
      records.order("-date")
      records = records.fetch(1000)
    else:
      records = [];

    template_values = {
      'has_records': len(records) > 0,
      'records': records,
    }
    convert_path = os.path.join(os.path.dirname(__file__),
                               'templates/signin-list.html')
    self.response.out.write(template.render(convert_path, template_values))


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
    logging.info("hash=%s", hash_str)
    record = GetHarRecord(hash_str)
    if not record:
      self.response.out.write('<html><body>\n')
      self.response.out.write('Empty for hash_str='+hash_str)
      self.response.out.write('\n<hr>return <a href=/ >home</a>')
      self.response.out.write('\n</body></html>')
      return

    logging.info("path=%s", self.request.path)
    headers = self.response.headers
    if download == "i":
      headers['Content-Type'] = 'text/javascript'
      self.response.out.write("onInputData(")
      self.response.out.write(zlib.decompress(record.har))
      self.response.out.write(");")
    else:
      headers['Content-Type'] = 'text/plain'
      download_name = record.pcapname + ".har"
      headers['Content-disposition'] = 'attachment; filename=' + download_name
      self.response.out.write(zlib.decompress(record.har))

def main():
  """
  The real main function.
  """
  application = webapp.WSGIApplication(
      [('/signin/', MainPage),
       ('/signin', MainPage),
       ('/signin/list', List),
       ('/signin/convert', Converter),
       ('/signin/pagespeed', Pagespeed),
       ('/signin/view', View),
       (r'/signin/download/(.*)/(.*)', Download),
       ],
      debug=True)
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
