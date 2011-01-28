import sys
import os
import logging

from datetime import datetime, timedelta
from hashlib import sha1
from hmac import new as hmac
from os.path import dirname, join as join_path
from random import getrandbits
from time import time
from urllib import urlencode, quote as urlquote
from uuid import uuid4
from wsgiref.handlers import CGIHandler

from google.appengine.api.urlfetch import fetch as urlfetch, GET, POST
from google.appengine.ext import db
from google.appengine.ext.webapp import RequestHandler, WSGIApplication
from google.appengine.api import users
from google.appengine.ext.webapp import template

#--------
# pull in the connections to the oauth data model and utilitiy functions 
#--------

from oauth_utilities import *
from oauth_model import *



class MainHandler(RequestHandler):
    def get(self):
    
        if users.get_current_user():
            user = users.get_current_user()
            nickname = user.nickname()
            url = users.create_logout_url(self.request.uri)
            url_linktext = 'Logout'
            
            user_record = get_this_user_record()
            if user_record:
                salutation = 'Welcome back ' + nickname  
                services = user_record.services
                if services:                   
                    service_status = 'you have tried making connections to: ' + ', '.join(services)
                else:
                    service_status = "you have not connected to any services yet"               
            else:
                new_user = UserRecord()
                new_user.user = user 
                new_user.put()
                salutation = 'Hello ' + nickname + " to get started look behind you!"                
                service_status = 'try connecting to one of these services:'

        else:
            salutation = None 
            service_status = None 
            url = users.create_login_url(self.request.uri)
            url_linktext = 'Login'

        # create homepage
        template_values = {
            'url': url,
            'url_linktext': url_linktext,
            'salutation' : salutation,
            'service_status' : service_status 
            }

        path = os.path.join(os.path.dirname(__file__), 'index.html')
        self.response.out.write(template.render(path, template_values))

# ------------------------------------------------------------------------------
# self runner -- gae cached main() function
# ------------------------------------------------------------------------------

def main():
    application = WSGIApplication([
       ('/', MainHandler)
       ], debug=True)

    CGIHandler().run(application)

if __name__ == '__main__':
    main()
