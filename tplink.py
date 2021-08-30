'''
TP-Link TD-W9960 API client v0.1.1

Compatible (tested) with versions:
  Firmware: 1.2.0 0.8.0 v009d.0 Build 201016 Rel.78709n
  Hardware: TD-W9960 v1 00000000 (TD-W9960 V1.20 - blue case)

Copyright (c) 2021 Michal Chvila <dev@electry.sk>.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
'''
import requests
import binascii
import time
import random
import logging
import urllib
import re
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import MD5
from base64 import b64encode, b64decode

class LoginException(Exception):
    pass

class UserConflictException(LoginException):
    pass

class TPLinkClient:
    RSA_USE_PKCS_V1_5 = False # no padding for the W9960
    REQUEST_RETRIES = 3

    AES_KEY_LEN = 128 // 8
    AES_IV_LEN = 16

    HEADERS = {
        'Accept': '*/*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
        'Referer': 'http://192.168.1.1/' # updated on the fly
    }

    HTTP_RET_OK = 0
    HTTP_ERR_CGI_INVALID_ANSI = 71017
    HTTP_ERR_USER_PWD_NOT_CORRECT = 71233
    HTTP_ERR_USER_BAD_REQUEST = 71234

    ACT_GET = 1
    ACT_SET = 2
    ACT_ADD = 3
    ACT_DEL = 4
    ACT_GL = 5
    ACT_GS = 6
    ACT_OP = 7
    ACT_CGI = 8

    REGEX_TOKEN = '<script type="text\/javascript">var token="(.*)";<\/script>'
    REGEX_RETURN_VALUE = '\$\.ret=(.*);'
    REGEX_GET_PARM = 'var ee="(.*)";\nvar nn="(.*)";\nvar seq="(.*)";'
    REGEX_GET_BUSY = 'var isLogined=([01]);\nvar isBusy=([01]);'
    REGEX_PWD_NOT_CORRENT_INFO = 'var currAuthTimes=(.*);\nvar currForbidTime=(.*);'

    class ActItem:
        def __init__(self, type, oid, stack = '0,0,0,0,0,0', pstack = '0,0,0,0,0,0', attrs = []):
            self.type = type
            self.oid = oid
            self.stack = stack
            self.pstack = pstack
            self.attrs = attrs

    def __init__(self, host, log_level = logging.INFO):
        logging.basicConfig()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

        self.req = requests.Session()

        self.host = host
        self.token = None

        self.aes_key = None
        self.rsa_key = None
        self.seq = None

    def get_url(self, endpoint, params = {}, include_ts = True):
        # add timestamp param
        if include_ts:
            params['_'] = str(round(time.time() * 1000))

        # format params into a string
        params_arr = []
        for attr, value in params.items():
            params_arr.append('{}={}'.format(attr, value))

        # format url
        return 'http://{}/{}{}{}'.format(
            self.host,
            endpoint,
            '?' if len(params_arr) > 0 else '',
            '&'.join(params_arr)
        )

    def connect(self, password, logout_others = False):
        '''
        Establishes a login session to the host using provided credentials
        '''
        # hash the password
        self.md5_hash_pw = self.__hash_pw('admin', password)

        # request the RSA public key from the host
        (self.rsa_key, self.seq) = self.__req_rsa_key()

        # check busy status
        (is_logged_in, is_busy) = self.__req_check_busy()

        if logout_others is False and is_logged_in:
            raise UserConflictException('Login conflict. Someone else is logged in.')

        # TODO: Handle is_busy ...

        # generate AES key
        self.aes_key = self.__gen_aes_key()

        # authenticate
        self.__req_login('admin', password)

        # request TokenID
        self.token = self.__req_token()

    def logout(self):
        '''
        Logs out from the host
        '''
        if self.token is None:
            return False

        acts = [
            # 8\r\n[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n
            self.ActItem(self.ACT_CGI, '/cgi/logout')
        ]

        response, _ = self.__req_act(acts)
        ret_code = self.__parse_ret_val(response)

        if ret_code == self.HTTP_RET_OK:
            self.token = None
            return True

        return False

    def get_dsl_status(self):
        '''
        Obtains DSL status info from the host
        '''
        acts = [
            self.ActItem(self.ACT_GET, 'WAN_DSL_INTF_CFG', stack = '1,0,0,0,0,0', attrs = [
                'status',
                'modulationType',
                'X_TP_AdslModulationCfg',
                'upstreamCurrRate',
                'downstreamCurrRate',
                'X_TP_AnnexType',
                'upstreamMaxRate',
                'downstreamMaxRate',
                'upstreamNoiseMargin',
                'downstreamNoiseMargin',
                'upstreamAttenuation',
                'downstreamAttenuation',
                'X_TP_UpTime'
            ]),
            self.ActItem(self.ACT_GET, 'WAN_DSL_INTF_STATS_TOTAL', stack = '1,0,0,0,0,0', attrs = [
                'ATUCCRCErrors',
                'CRCErrors',
                'ATUCFECErrors',
                'FECErrors',
                'SeverelyErroredSecs',
                'X_TP_US_SeverelyErroredSecs',
                'erroredSecs',
                'X_TP_US_ErroredSecs'
            ])
        ]

        _, values = self.__req_act(acts)
        return values

    def __req_act(self, acts = []):
        '''
        Requests ACTs via the cgi_gdpr proxy
        '''
        act_types = []
        act_data = []

        for act in acts:
            act_types.append(str(act.type))
            act_data.append('[{}#{}#{}]{},{}\r\n{}\r\n'.format(
                act.oid,
                act.stack,
                act.pstack,
                len(act_types) - 1, # index, starts at 0
                len(act.attrs),
                '\r\n'.join(act.attrs)
            ))

        data = '&'.join(act_types) + '\r\n' + ''.join(act_data)

        url = self.get_url('cgi_gdpr')
        (code, response) = self.__request(url, data_str = data, encrypt = True)
        assert code == 200

        # TODO: Implement response parsing for other ACT types (not just ACT_GET)
        result = {}

        lines = response.split('\n')
        for l in lines:
            if '=' in l:
                keyval = l.split('=')
                assert len(keyval) == 2

                result[keyval[0]] = keyval[1]

        return (response, result)

    def __req_token(self):
        '''
        Requests the TokenID, used for CGI authentication (together with cookies)
            - token is inlined as JS var in the index (/) html page
              e.g.: <script type="text/javascript">var token="086724f57013f16e042e012becf825";</script>

        Return value:
            TokenID string
        '''
        url = self.get_url('')
        (code, response) = self.__request(url, method = 'GET')
        assert code == 200

        result = re.search(self.REGEX_TOKEN, response)
        assert result is not None
        assert result.group(1) != ''

        return result.group(1)

    def __req_rsa_key(self):
        '''
        Requests the RSA public key from the host

        Return value:
            ((n, e), seq) tuple
        '''
        url = self.get_url('cgi/getParm')
        (code, response) = self.__request(url)
        assert code == 200

        # assert return code
        assert self.__parse_ret_val(response) == self.HTTP_RET_OK

        # parse public key
        result = re.search(self.REGEX_GET_PARM, response)
        assert result is not None
        assert len(result.group(1)) == 6 # ee
        assert len(result.group(2)) == 128 # nn
        assert result.group(3).isnumeric() # seq

        return ((result.group(2), result.group(1)), int(result.group(3)))

    def __req_check_busy(self):
        '''
        Checks if the host is busy or someone else is logged in

        Return value:
            (is_logged_in, is_busy) boolean tuple
        '''
        url = self.get_url('cgi/getBusy')
        (code, response) = self.__request(url)
        assert code == 200

        # assert return code
        assert self.__parse_ret_val(response) == self.HTTP_RET_OK

        # parse the is_logged_in / is_busy values
        result = re.search(self.REGEX_GET_BUSY, response)
        assert result is not None
        assert int(result.group(1)) in [0, 1]
        assert int(result.group(2)) in [0, 1]

        return (int(result.group(1)) == 1, int(result.group(2)) == 1)

    def __req_login(self, username, password):
        '''
        Authenticates to the host
            - sets the session token after successful login
            - data/signature is passed as a GET parameter, NOT as a raw request data
              (unlike for regular encrypted requests to the /cgi_gdpr endpoint)

        Example session token (set as a cookie):
            {'JSESSIONID': '4d786fede0164d7613411c7b6ec61e'}
        '''
        # encrypt username + password
        encrypted_data = self.__encrypt_data(username + '\n' + password)

        # get encrypted signature
        signature = self.__get_signature(len(encrypted_data), True)
        assert len(signature) == 256

        data = {
            'data': urllib.parse.quote(encrypted_data, safe='~()*!.\''),
            'sign': signature,
            'Action': 1,
            'LoginStatus': 0,
            'isMobile': 0
        }

        url = self.get_url('cgi/login', data)
        (code, response) = self.__request(url)
        assert code == 200

        # parse and match return code
        ret_code = self.__parse_ret_val(response)

        if ret_code == self.HTTP_ERR_USER_PWD_NOT_CORRECT:
            info = re.search(self.REGEX_PWD_NOT_CORRENT_INFO, response)
            assert info is not None

            raise LoginException('Login failed, wrong password. Auth times: {}/5, Forbid time: {}'.format(info.group(1), info.group(2)))
        elif ret_code == self.HTTP_ERR_USER_BAD_REQUEST:
            raise LoginException('Login failed. Generic error code: {}'.format(ret_code))
        elif ret_code != self.HTTP_RET_OK:
            raise LoginException('Login failed. Unknown error code: {}'.format(ret_code))

        self.logger.debug('Login Cookies: {}'.format(self.req.cookies.get_dict()))
        return True

    def __request(self, url, method = 'POST', data_str = None, encrypt = False):
        '''
        Prepares and sends an HTTP request to the host
            - sets up the headers, handles token auth
            - encrypts/decrypts the data, if needed

        Return value:
            (status_code, response_text) tuple
        '''
        headers = self.HEADERS

        # add referer to request headers,
        # otherwise we get 403 Forbidden
        headers['Referer'] = 'http://{}/'.format(self.host)

        # add token to request headers,
        # used for CGI auth (together with JSESSIONID cookie)
        if self.token is not None:
            headers['TokenID'] = self.token

        # encrypt request data if needed (for the /cgi_gdpr endpoint)
        if encrypt:
            # encrypt the data
            encrypted_data = self.__encrypt_data(data_str)

            # get encrypted signature
            signature = self.__get_signature(len(encrypted_data), False)

            # format expected raw request data
            data = 'sign={}\r\ndata={}\r\n'.format(signature, encrypted_data)
        else:
            data = data_str

        retry = 0
        while retry < self.REQUEST_RETRIES:
            # send the request
            if method == 'POST':
                r = self.req.post(url, data = data, headers = headers)
            elif method == 'GET':
                r = self.req.get(url, data = data, headers = headers)
            else:
                raise Exception('Unsupported method ' + str(method))

            # sometimes we get 500 here, not sure why... just retry the request
            if r.status_code != 500:
                break

            time.sleep(0.05)
            retry += 1

        self.logger.debug('<Request  {}>'.format(r.url))
        self.logger.debug(r)
        self.logger.debug(r.text[:256])

        # decrypt the response, if needed
        if encrypt and (r.status_code == 200) and (r.text != ''):
            return (r.status_code, self.__decrypt_data(r.text))
        else:
            return (r.status_code, r.text)

    def __encrypt_data(self, data_str):
        '''
        Encrypts data string using AES
        '''
        # pad to a multiple of 16 with pkcs7
        data_padded = pad(data_str.encode('utf8'), 16, 'pkcs7')

        # encrypt the body
        aes_encryptor = self.__make_aes_cipher(self.aes_key)
        encrypted_data_bytes = aes_encryptor.encrypt(data_padded)

        # encode encrypted binary data to base64
        return b64encode(encrypted_data_bytes).decode('utf8')

    def __decrypt_data(self, data_str):
        '''
        Decrypts the raw response data string using AES
        '''
        # decode base64 string
        encrypted_response_data = b64decode(data_str)

        # decrypt the response using our AES key
        aes_decryptor = self.__make_aes_cipher(self.aes_key)
        response = aes_decryptor.decrypt(encrypted_response_data)

        # unpad using pkcs7
        return unpad(response, 16, 'pkcs7').decode('utf8')

    def __get_signature(self, body_data_len, is_login = False):
        '''
        Formats and encrypts the signature using the RSA pub key
            body_data_len: length of the encrypted body message
            is_login:      set to True for login request

        Return value:
            RSA encrypted signature as string
        '''
        if is_login:
            # on login we also send our AES key, which is subsequently
            # used for E2E encrypted communication
            aes_key, aes_iv = self.aes_key

            sign_data = 'key={}&iv={}&h={}&s={}'.format(aes_key, aes_iv, self.md5_hash_pw, self.seq + body_data_len)
        else:
            sign_data = 'h={}&s={}'.format(self.md5_hash_pw, self.seq + body_data_len)

        # set step based on whether PKCS padding is used
        rsa_byte_len = len(self.rsa_key[0]) // 2 # hexlen / 2 * 8 / 8
        step = (rsa_byte_len - 11) if self.RSA_USE_PKCS_V1_5 else rsa_byte_len

        # encrypt the signature using the RSA public key
        rsa_key = self.__make_rsa_pub_key(self.rsa_key)

        # make the PKCS#1 v1.5 cipher
        if self.RSA_USE_PKCS_V1_5:
            rsa = PKCS1_v1_5.new(rsa_key)

        signature = ''
        pos = 0

        while pos < len(sign_data):
            sign_data_bin = sign_data[pos : pos+step].encode('utf8')

            if self.RSA_USE_PKCS_V1_5:
                # encrypt using the PKCS#1 v1.5 padding
                enc = rsa.encrypt(sign_data_bin)
            else:
                # encrypt using NOPADDING
                # ... pad the end with zero bytes
                while len(sign_data_bin) < step:
                    sign_data_bin = sign_data_bin + b'\0'

                # step 3a (OS2IP)
                em_int = bytes_to_long(sign_data_bin)

                # step 3b (RSAEP)
                m_int = rsa_key._encrypt(em_int)

                # step 3c (I2OSP)
                enc = long_to_bytes(m_int, 1)

            # hexlify to string
            enc_str = binascii.hexlify(enc).decode('utf8')

            # add '0' hex char to the start if the length is not even
            if len(enc_str) % 2 != 0:
                enc_str = '0' + enc_str

            signature += enc_str
            pos = pos + step

        return signature

    def __parse_ret_val(self, response_text):
        '''
        Parses $.ret value from the response text

        Return value:
            return code (int)
        '''
        result = re.search(self.REGEX_RETURN_VALUE, response_text)
        assert result is not None
        assert result.group(1).isnumeric()

        return int(result.group(1))

    def __hash_pw(self, username = 'admin', password = None):
        '''
        Hashes the username and password using MD5

        Return value:
            hex string of the MD5 hash (len: 32)
        '''
        md5 = MD5.new()

        if password is not None:
            md5.update((username + password).encode('utf8'))
        else:
            md5.update(username)

        result = md5.hexdigest()
        assert len(result) == 32

        return result

    def __gen_aes_key(self):
        '''
        Generates a pseudo-random AES key

        Return value:
            (key, iv) tuple
        '''
        ts = str(round(time.time() * 1000))

        key = (ts + str(random.randint(100000000, 1000000000-1)))[:self.AES_KEY_LEN]
        iv = (ts + str(random.randint(100000000, 1000000000-1)))[:self.AES_IV_LEN]

        assert len(key) == self.AES_KEY_LEN
        assert len(iv) == self.AES_IV_LEN

        return (key, iv)

    def __make_aes_cipher(self, aes_key):
        '''
        Makes a new cipher from AES key tuple (key, iv)
        '''
        key, iv = aes_key

        # CBC mode, PKCS7 padding
        return AES.new(key.encode('utf8'), AES.MODE_CBC, iv = iv.encode('utf8'))

    def __make_rsa_pub_key(self, key):
        '''
        Makes a new RSA pub key from tuple (n, e)
        '''
        n = int('0x' + key[0], 16)
        e = int('0x' + key[1], 16)
        return RSA.construct((n, e))
