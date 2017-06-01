## Django JWT Middleware
 

*Configuration*

Set your settings in the JWTSettings file

Copy the jwtAuth package to the directory of your project or into a folder for utilities and set the following configuration with the relative directories

The except_jwt property allows you to bypass jwt checks in some views
ex:
```
url(r'^auth/$', Auth.as_view(), {'except_jwt': True}, name='api_auth'),
```


To set the active middleware should be added to your setting in django
ex:
```
MIDDLEWARE = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',

    '{my_dir}.jwtAuth.JWTMiddleware.JWTAuthMiddleware'

)
```


After this you must use the jwt helper library to authenticate into the system and generate the token that will be used in each request
ex:
```
from django.contrib.auth.models import User
from django.views.generic import View
from jwtAuth.helpers.jwt import jwt_login

class Auth(View):
    """
    The users api auth
    @return 400: bad request
    @return 403: forbidden
    @return 200: Ok
    """

    def post(self, request, *args, **kwargs):
        """
        Login
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        the_email = request.POST.get('email')
        the_password = request.POST.get('password')

        # Valid data?
        if not the_email or not the_password:
            # Bad request
            raise Response400(
                'Invalid password or email'
            )

        # Try login
        try:
            user = User.objects.get(email=the_email)
            if user.check_password(the_password):
                # Logged
                # OK
                return request.responseOk({
                    'token': jwt_login(user)
                })

        except User.DoesNotExist:
            pass

        # Rejected
        raise Response403(
            'Wrong password or email'
        )

```


The token must be saved to be sent at each request to the system
Then for each request to the system should be sent the __Bearer__ header
ex:
```
{
    url: _uri,
    method: 'get',
    headers: {'Authorization': 'Bearer {token}'}
}
```