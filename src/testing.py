import os
import webapp2

import jinja2
jinja_environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))

class FastButton(webapp2.RequestHandler):
  def get(self):
    template_values = {
    }
    template = jinja_environment.get_template('templates/fastbutton.html')
    self.response.out.write(template.render(template_values))

app = webapp2.WSGIApplication(
    [ ('/fastbutton', FastButton),
    ], debug = True)

