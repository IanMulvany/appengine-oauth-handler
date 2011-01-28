from google.appengine.api import users
from oauth_model import *
from oauth_service_config import OAUTH_APP_SETTINGS
from urllib import urlencode, quote as urlquote
   
def create_uuid():
    return 'id-%s' % uuid4()

def encode(text):
    return urlquote(str(text), '')

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
 