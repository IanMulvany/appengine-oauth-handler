# ------------------------------------------------------------------------------
# configuration -- SET THESE TO SUIT YOUR APP!!
# ------------------------------------------------------------------------------

OAUTH_APP_SETTINGS = {

    'twitter': {

        'consumer_key': 'key',
        'consumer_secret': 'key',

        'request_token_url': 'https://twitter.com/oauth/request_token',
        'access_token_url': 'https://twitter.com/oauth/access_token',
        'user_auth_url': 'http://twitter.com/oauth/authorize',

        'default_api_prefix': 'http://twitter.com',
        'default_api_suffix': '.json',
        
        'callback_url': 'http://mulvanysandbox.appspot.com/oauth/twitter/callback',

        },

    'mendeley': {

        'consumer_key': 'key',
        'consumer_secret': 'key',

        'request_token_url': 'http://www.mendeley.com/oauth/request_token',
        'access_token_url': 'http://www.mendeley.com/oauth/access_token',
        'user_auth_url': 'http://www.mendeley.com/oauth/authorize',

        'default_api_prefix': 'http://www.mendeley.com',
        'default_api_suffix': '.json',
        
        'callback_url': 'http://mulvanysandbox.appspot.com/oauth/mendeley/callback',

        },

    'yahoo': {

        'consumer_key': 'key',
        'consumer_secret': 'key',

        'request_token_url': 'https://api.login.yahoo.com/oauth/v2/get_request_token',
        'access_token_url': 'https://api.login.yahoo.com/oauth/v2/get_token',
        'user_auth_url': 'https://api.login.yahoo.com/oauth/v2/request_auth',

        'default_api_prefix': 'https://api.login.yahoo.com/',
        'default_api_suffix': '.json',
        
        'callback_url': 'http://mulvanysandbox.appspot.com/oauth/yahoo/callback',

        },

    }