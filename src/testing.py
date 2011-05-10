import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

from google.appengine.dist import use_library
use_library('django', '1.2')

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template

class FastButton(webapp.RequestHandler):
  def get(self):
    template_values = {
    }
    index_path = os.path.join(os.path.dirname(__file__),
                              'templates/fastbutton.html')
    self.response.out.write(template.render(index_path, template_values))

application = webapp.WSGIApplication(
    [ ('/fastbutton', FastButton),
    ], debug = True)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()

