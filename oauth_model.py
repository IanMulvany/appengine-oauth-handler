from google.appengine.ext import db

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
