import getpass
import logging
import urllib
from json import loads
from re import search

import requests

from api import APINamespace
from exceptions import ErrorCodes, VkAPIError, VkAuthError
from utils import stringify

logger = logging.getLogger(__name__)

GET_FRIENDS = 'friends.get'
GET_SHORT_LINK = 'utils.getShortLink'
GET_PHOTO = 'photos.getProfile'


class APIBase:
    METHOD_COMMON_PARAMS = {'v', 'lang', 'https', 'test_mode'}

    API_URL = 'https://api.vk.com/method/'

    def __new__(cls, *args, **kwargs):
        method_common_params = {
            key: kwargs.pop(key)
            for key in tuple(kwargs) if key in cls.METHOD_COMMON_PARAMS
        }

        api = object.__new__(cls)
        api.__init__(*args, **kwargs)

        return APINamespace(api, method_common_params)

    def __init__(self, timeout=10, proxy=None):
        self.timeout = timeout

        self.session = requests.Session()
        self.session.proxies = {'http': proxy, 'https': proxy}
        self.session.headers['Accept'] = 'application/json'
        self.session.headers['Content-Type'] = 'application/x-www-form-urlencoded'


    def sendGetPhoto(self, request):

        logger.debug('Prepare API Method request')

        self.prepare_request(request)

        request.method = GET_PHOTO

        method_url = self.API_URL + request.method
        response = self.session.post(method_url, request.method_params, timeout=self.timeout)

        response.raise_for_status()

        response_or_error = loads(response.text)
        request.response = response_or_error

        if 'response' in response_or_error:

            for error_data in response_or_error.get('execute_errors', ()):
                api_error = VkAPIError(error_data)
                logger.warning('Execute "%s" error: %s', api_error.method, api_error)

            return response_or_error['response']

        elif 'error' in response_or_error:
            request.api_error = VkAPIError(request.response['error'])
            return self.handle_api_error(request)


    def sendGetShortLink(self, request):

        logger.debug('Prepare API Method request')

        self.prepare_request(request)

        request.method = GET_SHORT_LINK

        method_url = self.API_URL + request.method
        response = self.session.post(method_url, request.method_params, timeout=self.timeout)

        response.raise_for_status()

        response_or_error = loads(response.text)
        request.response = response_or_error

        if 'response' in response_or_error:

            for error_data in response_or_error.get('execute_errors', ()):
                api_error = VkAPIError(error_data)
                logger.warning('Execute "%s" error: %s', api_error.method, api_error)

            return response_or_error['response']

        elif 'error' in response_or_error:
            request.api_error = VkAPIError(request.response['error'])
            return self.handle_api_error(request)


    def sendGetFriends(self, request):

        logger.debug('Prepare API Method request')

        self.prepare_request(request)

        request.method = GET_FRIENDS

        method_url = self.API_URL + request.method
        response = self.session.post(method_url, request.method_params, timeout=self.timeout)

        response.raise_for_status()

        response_or_error = loads(response.text)
        request.response = response_or_error

        if 'response' in response_or_error:

            for error_data in response_or_error.get('execute_errors', ()):
                api_error = VkAPIError(error_data)
                logger.warning('Execute "%s" error: %s', api_error.method, api_error)

            return response_or_error['response']

        elif 'error' in response_or_error:
            request.api_error = VkAPIError(request.response['error'])
            return self.handle_api_error(request)

    def prepare_request(self, request):
        pass

    def handle_api_error(self, request):
        logger.error('Handle API error: %s', request.api_error)

        api_error_handler_name = 'on_api_error_' + str(request.api_error.code)
        api_error_handler = getattr(self, api_error_handler_name, self.on_api_error)

        return api_error_handler(request)

    def on_api_error(self, request):
        raise request.api_error


class API(APIBase):
    def __init__(self, access_token=None, **kwargs):
        super().__init__(**kwargs)
        self.access_token = access_token

    def get_captcha_key(self, api_error):
        raise api_error

    def on_api_error_14(self, request):
        request.method_params['captcha_key'] = self.get_captcha_key(request.api_error)
        request.method_params['captcha_sid'] = request.api_error.captcha_sid

        return self.send(request)

    def prepare_request(self, request):
        request.method_params.setdefault('access_token', self.access_token)


class UserAPI(API):
    LOGIN_URL = 'https://oauth.vk.com'
    AUTHORIZE_URL = 'https://oauth.vk.com/authorize'

    def __init__(self, user_login=None, user_password=None, client_id=6121396, scope='offline', **kwargs):
        self.user_login = user_login
        self.user_password = user_password
        self.client_id = client_id
        self.scope = scope

        super().__init__(self.get_access_token(), **kwargs)

    @staticmethod
    def _get_form_action(response):
        form_action = search(r'<form[^>]* action="([^\"]+)"', response.text)
        if form_action:
            return form_action.group(1)
        raise VkAuthError(f'No form on page {response.url}')

    @staticmethod
    def _get_input_value(response, name):
        input_value = search(rf'<input type="hidden" name="{name}" value="([^\"]+)"', response.text)
        if input_value:
            return input_value.group(1)
        raise VkAuthError(f'No input with name `{name}` on page {response.url}')

    @staticmethod
    def _get_captcha_src(response):
        captcha_src = search(r'<img[^>]* src="(https://(m|api).vk.com/captcha.php[^\"]+)"', response.text)
        if captcha_src:
            return captcha_src.group(1)
        raise VkAuthError(f'No CAPTCHA on page {response.url}')

    @staticmethod
    def _get_url_queries(url):
        parsed_url = urllib.parse.urlparse(url)
        # We lose repeating keys values
        return dict(urllib.parse.parse_qsl(parsed_url.fragment or parsed_url.query))

    @staticmethod
    def _oauth_is_request_success(response):
        if not response.ok:
            if response.status_code == 401:
                description = response.json()['error_description']
                logger.error('OAuth authorization failed: %s', description)
                raise VkAuthError(description)
            response.raise_for_status()

    def get_access_token(self):
        auth_session = requests.Session()
        auth_session.headers['Origin'] = 'https://oauth.vk.com'

        if self.login(auth_session):
            return self.authorize(auth_session)

    def get_login_form_data(self, response):
        return {
            'ip_h': self._get_input_value(response, 'ip_h'),
            'lg_domain_h': self._get_input_value(response, 'lg_domain_h'),
            'to': self._get_input_value(response, 'to'),
            'email': self.user_login,
            'pass': self.user_password,
        }

    def login(self, auth_session, login_response=None):
        if not login_response:
            logger.debug('Start of the login process')
            # Get login page
            login_page_response = auth_session.get(self.AUTHORIZE_URL, params=self.get_auth_params())
            # Check if params for OAuth is enough
            self._oauth_is_request_success(login_page_response)
            # Get login form action
            login_action = self._get_form_action(login_page_response)
            # Login using user credentials
            login_response = auth_session.post(login_action, self.get_login_form_data(login_page_response))

        if 'remixsid' in auth_session.cookies or 'remixsid6' in auth_session.cookies:
            logger.debug('Successfully logged in')
            return True

        url_queries = self._get_url_queries(login_response.url)

        if 'sid' in url_queries:
            logger.debug('Auth captcha is needed')
            return self.auth_captcha_is_needed(auth_session, login_response)

        if url_queries.get('act') == 'authcheck':
            logger.debug('Auth check is needed')
            return self.auth_check_is_needed(auth_session, login_response)

        if 'security_check' in url_queries:
            logger.debug('Phone number is needed')
            return self.phone_number_is_needed(auth_session, login_response)

        logger.error('Unknown login error. Last URL: %s.', login_response.url)
        raise VkAuthError('Login error (e.g. incorrect password)')

    def _get_auth_captcha_data(self, response):
        # Return captcha data
        return (
            self._get_input_value(response, 'captcha_sid'),  # captcha_sid
            self._get_captcha_src(response)  # captcha_img
        )

    def _get_auth_captcha_error(self, captcha_sid, captcha_img):
        # Create a bogus error
        error_data = {
            'error_code': ErrorCodes.CAPTCHA_NEEDED,
            'error_msg': 'Captcha error occured during authorization',
            'captcha_sid': captcha_sid,
            'captcha_img': captcha_img
        }
        error = VkAPIError(error_data)

        return error

    def auth_captcha_is_needed(self, auth_session, response):
        # Get login form action
        login_action = self._get_form_action(response)

        captcha_error = self._get_auth_captcha_error(*self._get_auth_captcha_data(response))

        # Login again using user credentials and solved captcha
        login_form_data = {
            **self.get_login_form_data(response),
            'captcha_sid': captcha_error.captcha_sid,
            'captcha_key': self.get_captcha_key(captcha_error)
        }
        login_response = auth_session.post(login_action, login_form_data)

        # Re-login with solved captcha
        return self.login(auth_session, login_response)

    def get_auth_check_code(self):
        raise NotImplementedError

    def auth_check_is_needed(self, auth_session, response):
        auth_check_action = self.LOGIN_URL + self._get_form_action(response)
        login_response = auth_session.post(auth_check_action, {'code': self.get_auth_check_code()})

        # Re-login with auth check code
        return self.login(auth_session, login_response)

    def phone_number_is_needed(self, auth_session, response):  # noqa: U100
        raise NotImplementedError

    def get_auth_params(self):
        return {
            'client_id': self.client_id,
            'scope': self.scope,
            'display': 'mobile',
            'response_type': 'token',
        }

    def authorize(self, auth_session):
        logger.debug('Start of the OAuth authorization process')
        # Ask access
        ask_access_response = auth_session.post(self.AUTHORIZE_URL, self.get_auth_params())
        self._oauth_is_request_success(ask_access_response)
        url_queries = self._get_url_queries(ask_access_response.url)

        if 'authorize_url' not in url_queries:
            logger.debug('Grant access to app')
            # Grant access
            grant_access_action = self._get_form_action(ask_access_response)
            grant_access_response = auth_session.post(grant_access_action)
            url_queries = self._get_url_queries(grant_access_response.url)

        url_queries = self._get_url_queries(urllib.parse.unquote(url_queries['authorize_url']))

        self.expires_in = url_queries.get('expires_in')
        self.user_id = url_queries.get('user_id')

        for key in url_queries:
            if key.startswith('access_token'):
                logger.debug('Successfully authorized')
                return self._process_auth_url_queries(url_queries)

        logger.error('Unknown OAuth authorization error. URL queries = %s.', url_queries)
        raise VkAuthError('OAuth authorization failed')

    def _process_auth_url_queries(self, url_queries):
        self.expires_in = url_queries.get('expires_in')
        self.user_id = url_queries.get('user_id')
        return url_queries['access_token']


class DirectUserAPI(UserAPI):
    LOGIN_URL = 'https://m.vk.com'
    AUTHORIZE_URL = 'https://oauth.vk.com/token'

    def __init__(
            self,
            user_login=None,
            user_password=None,
            client_id=2274003,
            client_secret='hHbZxrka2uZ6jB1inYsH',
            scope='offline',
            **kwargs
    ):
        self.user_login = user_login
        self.user_password = user_password
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope

        API.__init__(self, self.get_access_token(), **kwargs)

    def login(self, auth_session):  # noqa: U100
        return True

    def _get_auth_params(self):
        return {
            'grant_type': 'password',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': self.user_login,
            'password': self.user_password,
            'scope': self.scope,
            '2fa_supported': 1
        }

    def authorize(self, auth_session):
        logger.debug('Start of the OAuth authorization process')
        auth_response = auth_session.post(self.AUTHORIZE_URL, self._get_auth_params())
        response_params = auth_response.json()

        if 'error' in response_params:
            if response_params['error'] == 'need_validation':
                return self.auth_check_is_needed(auth_session, response_params)

            if response_params['error'] == 'need_captcha':
                return self.auth_captcha_is_needed(auth_session, response_params)

        self._oauth_is_request_success(auth_response)
        logger.debug('Successfully authorized')
        return response_params['access_token']

    def auth_check_is_needed(self, auth_session, response_params):
        validation_page_response = auth_session.get(response_params['redirect_uri'])
        url_queries = self._get_url_queries(validation_page_response.url)

        # Resend auth check code until it's correct
        while url_queries.get('act') == 'authcheck':
            logger.debug('Auth check is needed')

            validation_action_url = self.LOGIN_URL + self._get_form_action(validation_page_response)

            auth_check_code = self.get_auth_check_code()
            validation_response = auth_session.post(validation_action_url, {'code': auth_check_code})
            url_queries = self._get_url_queries(validation_response.url)

            # CAPTCHA input required, resend until it's correct
            while url_queries.get('act') == 'authcheck_code':
                logger.debug('Auth captcha is needed (during 2FA)')

                captcha_action_url = self.LOGIN_URL + self._get_form_action(validation_page_response)
                captcha_error = self._get_auth_captcha_error(
                    *self._get_auth_captcha_data(validation_page_response)
                )

                captcha_check_response = auth_session.post(captcha_action_url, {
                    'code': auth_check_code,
                    'captcha_sid': captcha_error.captcha_sid,
                    'captcha_key': self.get_captcha_key(captcha_error)
                })
                url_queries = self._get_url_queries(captcha_check_response.url)

        return self._process_auth_url_queries(url_queries)

    def auth_captcha_is_needed(self, auth_session, response_params):
        while response_params.get('error') == 'need_captcha':
            logger.debug('Auth captcha is needed')

            captcha_error = self._get_auth_captcha_error(
                response_params['captcha_sid'],
                response_params['captcha_img']
            )

            response_params = auth_session.post(
                self.AUTHORIZE_URL,
                params={
                    'captcha_sid': captcha_error.captcha_sid,
                    'captcha_img': self.get_captcha_key(captcha_error),
                    **self._get_auth_params()
                }
            ).json()

        return response_params['access_token']

    def _process_auth_url_queries(self, url_queries):
        if 'fail' in url_queries:
            logger.error('Unknown OAuth authorization error (during 2FA). URL queries = %s.', url_queries)
            raise VkAuthError('OAuth authorization failed')

        self.user_id = url_queries.get('user_id')
        return url_queries['access_token']


class CommunityAPI(UserAPI):
    def __init__(
            self,
            user_login=None,
            user_password=None,
            group_ids=None,
            client_id=6121396,
            scope=None,
            **kwargs
    ):
        self.group_ids = group_ids
        self.default_group_id = None

        self.access_tokens = {}

        super().__init__(user_login, user_password, client_id, scope, **kwargs)

    def get_auth_params(self):
        auth_params = super().get_auth_params()
        auth_params['group_ids'] = stringify(self.group_ids)
        return auth_params

    def _process_auth_url_queries(self, url_queries):
        self.access_tokens = {}
        for key, value in url_queries.items():
            # access_token_GROUP-ID: ACCESS-TOKEN
            if key.startswith('access_token_'):
                group_id = int(key[len('access_token_'):])
                self.access_tokens[group_id] = value

        self.default_group_id = self.group_ids[0]

    def prepare_request(self, request):
        group_id = request.method_params.get('group_id', self.default_group_id)
        request.method_params.setdefault('access_token', self.access_tokens[group_id])


class InteractiveMixin:
    def __setattr__(self, name, value):
        attrs = dir(self.__class__)

        if name in attrs and not value:
            return

        if name in filter(lambda x: isinstance(getattr(self.__class__, x), property), attrs):
            return object.__setattr__(self, '_cached_' + name, value)

        return object.__setattr__(self, name, value)

    @property
    def user_login(self):
        if not hasattr(self, '_cached_user_login'):
            self._cached_user_login = input('VK user login: ')
        return self._cached_user_login

    @property
    def user_password(self):
        if not hasattr(self, '_cached_user_password'):
            self._cached_user_password = getpass.getpass('VK user password: ')
        return self._cached_user_password

    @property
    def access_token(self):
        if not hasattr(self, '_cached_access_token'):
            self._cached_access_token = input('VK API access token: ')
        return self._cached_access_token

    def get_captcha_key(self, api_error):
        print('Open CAPTCHA image url: ', api_error.captcha_img)
        return input('Enter CAPTCHA key: ')

    def get_auth_check_code(self):
        return input('Auth check code: ')
