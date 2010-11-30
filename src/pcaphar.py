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

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app

class MainPage(webapp.RequestHandler):
  """
  The main page.
  """
  def get(self):
    """
    Serve the GET request.
    """
    self.response.out.write("""
<html>
<head>
<title>pcaphar -- Convert PCAP to HAR</title>
</head>

<body>
Coming soon ...
</body>
</html>""")

def main():
  """
  The application main.
  """
  application = webapp.WSGIApplication(
      [('/', MainPage),
      ],
      debug=True)
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
