__author__ = 'gmena'

import datetime

JWT_EXPIRE = datetime.timedelta(days=1)  # Time to expire
JWT_ALLOW_EXPIRE = False  # Expire token?
JWT_HEADER_PREFIX = 'Bearer'
JWT_RENEW = False  # Renew after expire?
JWS_LEEWAY = 0  # Delay

# Key settings
JWT_RSA_PRIVATE_KEY = 'privatekey.pem'
JWT_RSA_PUBLIC_KEY = 'publickey.pem'
JWT_OCT_KEY = 'octet.json'
