from time import sleep
from sys import exc_info
import requests
import json



class Antigate(object):
    def __init__(self, apikey = None, website_key = None,
                 website_url = None, proxy_address = None,
                 proxy_port = None, proxy_login = None,
                 proxy_password = None, useragent = None,
                 autorun = True, wait_limit = 10, send_limit = 15):
        self.apikey = apikey
        self.website_key = website_key
        self.website_url =  website_url
        self.proxy_address = proxy_address
        self.proxy_port = proxy_port
        self.proxy_login = proxy_login
        self.proxy_password = proxy_password
        self.useragent = useragent
        self.domain = "http://api.anti-captcha.com"
        self.captcha_id = None
        self.captcha_text = None
        self.session = requests.Session()
        self.wait_limit = wait_limit
        self.send_limit = send_limit
        self.current_wait = 0

        if autorun:
            self.autorun()
            
    def send(self):
        data = {
            "clientKey":self.apikey,
            "task":
                {
                    "websiteURL": self.website_url,
                    "websiteKey":self.website_key,
                    
                },
            "softId":0,
            "languagePool":"en"
            }

        if self.proxy_address:
            data['task'].update({'proxyAddress': self.proxy_address})
            data['task'].update({'proxyType': "http"})
            data['task'].update({'type': "NoCaptchaTask"})
        else:
            data['task'].update({'type': "NoCaptchaTaskProxyless"})

        if self.proxy_port:
            data['task'].update({'proxyPort': self.proxy_port})

        if self.useragent:
            data['task'].update({'userAgent': self.useragent})
            

        if self.proxy_password:
            data['task'].update({'proxyPassword': self.proxy_password})

        if self.proxy_login:
            data['task'].update({'proxyLogin': self.proxy_login})

        url = ("%s/createTask" % self.domain)
        json_data = json.JSONEncoder().encode(data)
        response = self.session.post(url, json_data)

        if response.json()['errorId'] == 0:
            self.captcha_id = response.json()['taskId']
            return self.captcha_id
        else:
            raise antigateError(response.content.decode())

    def get(self, captcha_id):
        url = ("%s/getTaskResult" % (self.domain))
        json_data = json.JSONEncoder().encode({'clientKey': self.apikey, 'taskId': captcha_id})

        response = self.session.post(url, json_data)

        if response.json()['errorId'] == 0:
            if response.json()['status'] == 'processing':
                raise antigateError('processing')

            self.captcha_text = response.json()['solution']['gRecaptchaResponse']
            return self.captcha_text
        else:
            raise antigateError(response.json()['errorCode'])

    def get_balance(self):
        url = ("%s/getBalance" % (self.domain))
        json_data = json.JSONEncoder().encode({'clientKey': self.apikey})
        response = self.session.post(url)

        if response.json()['errorId'] == 0:
            return response.json()['balance']
        else:
            return response.json()['errorDescription']

    def _send(self):
        try:
            captcha_id = self.send()
        except antigateError as ae:
            if "ERROR_NO_SLOT_AVAILABLE" in str(ae):
                print("ERROR_NO_SLOT_AVAILABLE")
                self.current_wait += 1
                if self.current_wait >= self.send_limit:
                    self.captcha_text = 'Wait limit'
                    return self.captcha_text
                sleep(15)
                return self._send()
            else:
                print(ae)
        except:
            print("send", exc_info())
            sleep(15)
            return self._send()
        else:
            self.current_wait = 0
            return captcha_id

    def _get(self, captcha_id):
        try:
            self.captcha_text = self.get(captcha_id = captcha_id)
        except antigateError as ae:
            if str(ae) == "processing":
                print("CAPCHA_NOT_READY")
                sleep(15)
                self.current_wait += 1
                if self.current_wait >= self.wait_limit:
                    self.captcha_text = 'Wait limit'
                    return self.captcha_text
                    
                self._get(captcha_id = captcha_id)
            else:
                print(ae)
        except:
            print("get", exc_info())
            sleep(5)
            self._get(captcha_id = captcha_id)
        else:
            return self.captcha_text

    def autorun(self):
        captcha_id = self._send()

        if captcha_id == 'Wait limit':
            return self.captcha_text

        sleep(30)

        self._get(captcha_id = captcha_id)
        return self.captcha_text

    def __str__(self):
        return self.captcha_text

class antigateError(Exception):
    """
    API errors
    """
