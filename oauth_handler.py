
"""
Twitter OAuth Support for Google App Engine Apps.

Using this in your app should be relatively straightforward:

* Edit the configuration section below with the CONSUMER_KEY and CONSUMER_SECRET
  from Twitter.

* Modify to reflect your App's domain and set the callback URL on Twitter to:

    http://your-app-name.appspot.com/oauth/twitter/callback

* Use the demo in ``MainHandler`` as a starting guide to implementing your app.

Note: You need to be running at least version 1.1.9 of the App Engine SDK.

-- 
I hope you find this useful, tav


TODO: rename token objects as token objects, rather than calling them tokens
TODO: merge token access code, as the code is the same for both access functions
TODO: clean out all of the cookie code 
TODO: make appropriate functions take user as an argument

"""

# Released into the Public Domain by tav@espians.com

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

sys.path.insert(0, join_path(dirname(__file__), 'lib')) # extend sys.path

from google.appengine.api.urlfetch import fetch as urlfetch, GET, POST
from google.appengine.ext import db
from google.appengine.ext.webapp import RequestHandler, WSGIApplication
from google.appengine.api import users
from google.appengine.ext.webapp import template

# ------------------------------------------------------------------------------
# configuration -- SET THESE TO SUIT YOUR APP!!
# ------------------------------------------------------------------------------

from oauth_service_config import OAUTH_APP_SETTINGS
STATIC_OAUTH_TIMESTAMP = 12345 # a workaround for clock skew/network lag

# ------------------------------------------------------------------------------
# utility functions
# ------------------------------------------------------------------------------

def get_services(user):
    "lists the names of the services a user has connected to"
    user_record = get_this_user_record()
    if user_record:
        services = user_record.services
        return services
    else:
        return None

def get_service_access_token(user, service):
    """ get the last connection record for that user and service """
    try:
        recent_connection = get_recent_connection(service) # this assumes that in the scope of the call we already have the user
        this_token_key = recent_connection.access_token_object
        this_token = db.get(db.Key(this_token_key))
        access_token = this_token.oauth_token
        return access_token
    except:
        return None
     
def get_service_auth_token(user, service):
    # get the last connection record for that user and service 
    try:
        recent_connection = get_recent_connection(service) # this assumes that in the scope of the call we already have the user
        this_token_key = recent_connection.request_token_object
        this_token = db.get(db.Key(this_token_key))
        auth_token = this_token.oauth_token
        return auth_token
    except:
        return None 

def get_service_key(service, cache={}):
    if service in cache: return cache[service]
    return cache.setdefault(
        service, "%s&" % encode(OAUTH_APP_SETTINGS[service]['consumer_secret'])
        )

def get_this_user_record():
    """ for the logged in user get the record that stores which services they have tried to connect to """
    user = users.get_current_user()
    query = UserRecord.all()
    query.filter('user =', user)
    if query.fetch(1):
        user_record = query.fetch(1)[0]
        return user_record
    else:
        return None 
        
def create_new_connection(service):
    """ every time the user connects to a service create a record  """
    user = users.get_current_user()
    new_connection = ConnectionRecord()
    new_connection.user = user 
    new_connection.service = service
    new_connection.put()

def get_recent_connection(service):
    """ we assume the last attempt to connect to a service for the user is the most relevant one """
    user = users.get_current_user()
    query = ConnectionRecord().all()
    query.filter('user =', user).filter('service =', service).order('created')
    if query.fetch(1):
        recent_connection = query.fetch(1)[0]
        return recent_connection
    else:
        return None 
    
def create_uuid():
    return 'id-%s' % uuid4()

def encode(text):
    return urlquote(str(text), '')

# ------------------------------------------------------------------------------
# db entities
# ------------------------------------------------------------------------------

class UserRecord(db.Model):
    """ a user and services that he has created connections for """
    
    user = db.UserProperty()
    services = db.StringListProperty()
    created = db.DateTimeProperty(auto_now_add=True)


class ConnectionRecord(db.Model):
    """ recored of a users's connection to a service """
    
    user = db.UserProperty()
    service = db.StringProperty()
    request_token_object = db.StringProperty() 
    access_token_object = db.StringProperty() 
    created = db.DateTimeProperty(auto_now_add=True)


class OAuthRequestToken(db.Model):
    """OAuth Request Token."""

    service = db.StringProperty()
    oauth_token = db.TextProperty()
    oauth_token_secret = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)


class OAuthAccessToken(db.Model):
    """OAuth Access Token."""
    
    service = db.StringProperty()
    specifier = db.StringProperty()
    oauth_token = db.TextProperty()
    oauth_token_secret = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

# ------------------------------------------------------------------------------
# oauth client
# ------------------------------------------------------------------------------

class OAuthClient(object):

    __public__ = ('callback', 'cleanup', 'login', 'logout')
    """ 
    we insert the callback parameter as one of the request params dicts
    
    """

    def __init__(self, service, handler, oauth_callback=None, **request_params):
        self.service = service
        self.service_info = OAUTH_APP_SETTINGS[service]
        self.service_key = None
        self.handler = handler
        self.request_params = request_params
        self.oauth_callback = oauth_callback
        self.token = None

    # public methods

    def get(self, api_method, http_method='GET', expected_status=(200,), **extra_params):

        if not (api_method.startswith('http://') or api_method.startswith('https://')):
            api_method = '%s%s%s' % (
                self.service_info['default_api_prefix'], api_method,
                self.service_info['default_api_suffix']
                )

        if self.token is None:
            self.token = OAuthAccessToken.get_by_key_name(self.get_cookie())

        fetch = urlfetch(self.get_signed_url(
            api_method, self.token, http_method, **extra_params
            ))

        if fetch.status_code not in expected_status:
            raise ValueError(
                "Error calling... Got return status: %i [%r]" %
                (fetch.status_code, fetch.content)
                )

        return decode_json(fetch.content)

    def post(self, api_method, http_method='POST', expected_status=(200,), **extra_params):

        if not (api_method.startswith('http://') or api_method.startswith('https://')):
            api_method = '%s%s%s' % (
                self.service_info['default_api_prefix'], api_method,
                self.service_info['default_api_suffix']
                )

        if self.token is None:
            self.token = OAuthAccessToken.get_by_key_name(self.get_cookie())

        fetch = urlfetch(url=api_method, payload=self.get_signed_body(
            api_method, self.token, http_method, **extra_params
            ), method=http_method)

        if fetch.status_code not in expected_status:
            raise ValueError(
                "Error calling... Got return status: %i [%r]" %
                (fetch.status_code, fetch.content)
                )

        return decode_json(fetch.content)

    # oauth workflow

    def get_request_token(self):
        """
        send a request to request_token_url
        create a OAuthRequestToken
        make a ConnectionObject        
        redirect user to remote service user_auth_url, include a callback
        the remove service should return us to the callback url
        """
    
        service = self.service 
        self.oauth_callback = self.service_info['callback_url']
        kwargs = {"oauth_callback":self.oauth_callback}
        token_info = self.get_data_from_signed_url(
            self.service_info['request_token_url'], **kwargs
            )

        token = OAuthRequestToken(
            service=service,
            **dict(token.split('=') for token in token_info.split('&'))
            )

        token.put()
        
        # if we have a request token, make a new connection object
        recent_connection = get_recent_connection(service)
        recent_connection.request_token_object = str(token.key())
        recent_connection.put()

        # I still have no idea what this code here is for
        if self.oauth_callback:
            oauth_callback = {'oauth_callback': self.oauth_callback}
        else:
            oauth_callback = {}

        # after we have got a token we have to redirect the user to
        self.handler.redirect(self.get_signed_url(
            self.service_info['user_auth_url'], token, **oauth_callback
            ))     

    def callback(self, return_to='/'):
        # for a specific token I need to find the secret
        oauth_token = self.handler.request.get("oauth_token")
        oauth_verifier = self.handler.request.get("oauth_verifier")        
        service = self.service
        recent_connection = get_recent_connection(service)
        this_token_key = recent_connection.request_token_object
        this_token = db.get(db.Key(this_token_key))

        kwargs = {"oauth_token": oauth_token, "oauth_verifier": oauth_verifier}
        token_info = self.get_data_from_signed_url(
            self.service_info['access_token_url'], 
                                this_token, 
                                **kwargs
        )

        # need to include the following:
        #
        # as extra parameters
        #
        # oauth_verifier
        # oauth_token
        # oauth_signature
        #
        # the following are built in at the url request level:
        #
        # oauth_consumer_key
        # oauth_signature_method
        # oauth_timestamp
        # oauth_nonce
        # oauth_version (optional but a good idea)

        # if we get it, we create an access token object with an auto generated uuid
        key_name = create_uuid()
        self.token = OAuthAccessToken(
            key_name=key_name, service=self.service,
            **dict(token.split('=') for token in token_info.split('&'))
        )
        self.token.put()
        recent_connection.access_token_object = str(self.token.key())
        recent_connection.put()
        # now we need to stash a reference to the access token in the ConnectionRecord
        self.handler.redirect(return_to)
        
    # request marshalling
    def get_data_from_signed_url(self, __url, __token=None, __meth='GET', **extra_params):
        remote_response = urlfetch(self.get_signed_url(
            __url, __token, __meth, **extra_params
            )).content
        logging.info("remote response is")
        logging.info(remote_response)
        logging.info("-*-"*30)                
        return remote_response

    def get_signed_url(self, __url, __token=None, __meth='GET',**extra_params):
        logging.info("about to generate get_signed_url")
        #logging.info(__token)        
        logging.info('%s?%s'%(__url, self.get_signed_body(__url, __token, __meth,  **extra_params)))
        return '%s?%s'%(__url, self.get_signed_body(__url, __token, __meth, **extra_params))

    def get_signed_body(self, __url, __token=None, __meth='GET',**extra_params):
        service_info = self.service_info

        kwargs = {
            'oauth_consumer_key': service_info['consumer_key'],
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_version': '1.0',
            'oauth_timestamp': int(time()),
            'oauth_nonce': getrandbits(64)
            }

        kwargs.update(extra_params)

        if self.service_key is None:
            self.service_key = get_service_key(self.service)

        if __token is not None:
            kwargs['oauth_token'] = __token.oauth_token
            key = self.service_key + encode(__token.oauth_token_secret)
        else:
            key = self.service_key

        message = '&'.join(map(encode, [
            __meth.upper(), __url, '&'.join(
                '%s=%s' % (encode(k), encode(kwargs[k])) for k in sorted(kwargs)
                )
            ]))

        kwargs['oauth_signature'] = hmac(
            key, message, sha1
            ).digest().encode('base64')[:-1]

        return urlencode(kwargs)

    # cookie login/logout other cookie methods, should now be redundant, um, I think
    def login(self):
        # the important thing is that on login we send a request to get_request_token
        return self.get_request_token()

    def logout(self, return_to='/'):
        self.handler.redirect(self.handler.request.get("return_to", return_to))

# ------------------------------------------------------------------------------
# oauth handler
# ------------------------------------------------------------------------------

class OAuthHandler(RequestHandler):


    def get(self, service, action=''):
    
        logging.info("in oauth handler")
        logging.info(service)
        
        # update the user record with the service
        user_record = get_this_user_record()
        if user_record.services:
            services = user_record.services
        else:
            services = []
            user_record.services = services
        if service not in services: user_record.services.append(service)
        user_record.put()
                
        # create a connection record? 
        create_new_connection(service)

        if service not in OAUTH_APP_SETTINGS:
            return self.response.out.write(
                "Unknown OAuth Service Provider: %r" % service
                )

        client = OAuthClient(service, self)

        if action in client.__public__:
            self.response.out.write(getattr(client, action)())
        else:
            self.response.out.write(client.login())

# ------------------------------------------------------------------------------

class TestAPIHandler(RequestHandler):
    """Demo Twitter App."""

    def get(self):
        user = users.get_current_user()
        nickname = user.nickname
        
        services = get_services(user)
        access_tokens = {}
        for service in services:
            access_tokens[service] = get_service_access_token(user, service)
            
        template_values = {
            'nickname' : nickname,
            'services' : services,
            'tokens' : access_tokens
        }
        
        path = os.path.join(os.path.dirname(__file__), 'test.html')
        self.response.out.write(template.render(path, template_values))

# ------------------------------------------------------------------------------

class MainHandler(RequestHandler):
    """Demo Twitter App."""

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
       ('/oauth/(.*)/(.*)', OAuthHandler),
       ('/test/', TestAPIHandler),
       ('/', MainHandler)
       ], debug=True)

    CGIHandler().run(application)

if __name__ == '__main__':
    main()
