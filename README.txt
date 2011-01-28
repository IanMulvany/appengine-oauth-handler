
based on https://github.com/tav/tweetapp/blob/master/standalone/twitter_oauth_handler.py but sufficiently different.

# Differences

- does not store authentication in cookies
- stores tokens in the google app engine DB 
- creates some utility classes to store records of a connection


# usage

- configure oauth_service_config_example.py with you oauth keys
- rename oauth_service_config_example.py to oauth_service_config.py
- upload to google app engine, and have fun


