  
#!/usr/bin/python
# -*- coding= utf-8 -*-

from antigate2 import Antigate
from requests.exceptions import ConnectionError
from requests.packages.urllib3.exceptions import InsecureRequestWarning, SNIMissingWarning, InsecurePlatformWarning
import logging as log
import random
import re
import requests
import string
import sys,os
import time

basedir = os.path.dirname(__file__)
name = "upornia"
#### LOG SETTINGS
import logging
info_log =  name + '.log'
info_log = os.path.join(basedir, info_log)

logging.basicConfig()
formatter = logging.Formatter("[%(asctime)s] %(levelname)s ==> %(message)s",
                               "%d-%m-%Y %H:%M:%S")
log = logging.getLogger()
log.setLevel(logging.DEBUG)
req_log = logging.getLogger('requests.packages.urllib3')
req_log.setLevel(logging.DEBUG)
req_log.propagate = True
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(formatter)
log.addHandler(console)
i_handler = logging.FileHandler(info_log)
i_handler.setLevel(logging.INFO)
i_handler.setFormatter(formatter)
log.addHandler(i_handler)

def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    log.error("{}: uncaught".format(name))
    log.error("traceback:", exc_info=(exc_type, exc_value, exc_traceback))
sys.excepthook = handle_exception
########################################
site = 'https://upornia.com'
ua_rand = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Safari/537.36'
website_key = '6LcO84gUAAAAABo7-FXTRVBwn9GxPzoS4grX5Q9l'
antigate_key = "9aea3aba070433538020b025c60f53ef"


def login(username,password):
    log.info("{}: login to: {}:{}".format(name, username,password))
    url = 'https://member.upornia.com/login/'
    data= {
           'username': username,
           'pass': password,
           'action': 'login',
           'email_link': 'https://upornia.com/email/',
           'remember_me': '1',
           'format': 'json',
           'mode': 'async'
           }

    resp = s.post(url, data)
    if '"status":"success"' in resp.text:
        log.info("{}: login success: {}".format(name,resp.text))
        return True
    else:
        exit()

def upload_video(info):
    url = 'https://member.upornia.com/upload-video/'
    try:
        resp = s.get(url)
        log.info('{}: current url: {}'.format(name,resp.url))
    except Exception as e:
        log.error("{}: get upload page error: {}".format(name, e))
        return True


    dct = {}
    dct['filename'] = info['filename']
    dct['title'] = info['title']
    dct['video_data'] = get_file_data(info['video'])
    dct['filename_hash'] = '%s' % ''.join([random.choice('0123456789') for x in range(32)])
    dct['tags'] = info['tags']
    dct['category'] = '21'
    dct['description'] = info['description']


    log.info("{}: title: {}".format(name, dct['title']))
    log.info("{}: tags: {}".format(name, dct['tags']))
    log.info("{}: description: {}".format(name, dct['description']))
    log.info("{}: category: {}".format(name, dct['category']))


    #data = {
             #'content_source_id': '3487',
             #'url': '',
            # 'upload_option': 'file',
             #'action': 'upload_file',
             #'filename': dct['filename_hash'],
             #'format': 'json',
             #'mode': 'async'
           #}


    #files = {'content': (dct['filename'], open(info['video'], 'rb'), 'video/mp4')}



    data = '''-----------------------------1467566330624
Content-Disposition: form-data; name="content_source_id"
3487
-----------------------------1467566330624
Content-Disposition: form-data; name="content"; filename="{filename}"
Content-Type: video/mp4
{video_data}
-----------------------------1467566330624
Content-Disposition: form-data; name="url"
-----------------------------1467566330624
Content-Disposition: form-data; name="upload_option"
file
-----------------------------1467566330624
Content-Disposition: form-data; name="action"
upload_file
-----------------------------1467566330624
Content-Disposition: form-data; name="filename"
{filename_hash}
-----------------------------1467566330624
Content-Disposition: form-data; name="format"
json
-----------------------------1467566330624
Content-Disposition: form-data; name="mode"
async
-----------------------------1467566330624--'''.format(**dct)

    url = 'https://member.upornia.com/upload-video/?mode=async&format=json&action=upload_file&mode=async&format=json&action=upload_file'

    s.headers['Content-Type'] = 'multipart/form-data; boundary=---------------------------1467566330624'

    try:
        log.info("{}: start attach file".format(name))
        #resp = s.post(url, data = data, files = files)
        resp = s.post(url,data)
    except Exception as e:
        log.error("{}: attach file error: {}".format(name, e))
        return True

    if '"status":"success"' in resp.text:
        log.info("{}: file attach success: {}".format(name, resp.text))
    else:
        log.error("{}: file attach error".format(name))
        with open(os.path.join(basedir, 'upornia-attach-file-error.html'), 'wb') as files:
             files.write(resp.content)
        return True

    log.info('{}: current url after attach file: {}'.format(name, resp.url))
    url = 'https://member.upornia.com/upload-video/' + dct['filename_hash'] + '/'

    s.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    data = {'action': 'add_new_complete'}
    resp = s.post(url,data)

    log.info('{}: post {} status code: {}'.format(name, url, resp.status_code))

    #if 'g-recaptcha-response' in resp.text:
    log.info("{}: solving captcha".format(name))

    response_captcha = Antigate(
                                 apikey=antigate_key,
                                 website_key=website_key,
                                 website_url=url,
                                 useragent=ua_rand,
                                 wait_limit=10
                                 )

    hashf = dct['filename_hash'] + '.mp4'

    data = {
               'content_source_id': '3487',
               'title': dct['title'],
               'description': dct['description'],
               'screenshot': '',
               'category_ids[]': dct['category'],
               'tags': dct['tags'],
               'is_private': '0',
               'function': 'get_block',
               'block_id': 'video_edit_video_edit',
               'code': '',
               'g-recaptcha-response': response_captcha.captcha_text,
               'action': 'add_new_complete',
               'file': hashf,
               'file_hash': dct['filename_hash'],
               'format': 'json',
               'mode': 'async'
           }

    log.info('{}: video data: {}'.format(name, data))

    s.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    s.headers['X-Requested-With'] = 'XMLHttpRequest'

    resp = s.post(url, data)
    while 'The entered code is not valid, please try once again' in resp.text:
        print('The entered captcha is not valid, trying again')
        log.info('The entered captcha is not valid, trying receive new captcha')

        data['g-recaptcha-response'] = Antigate(
                                 apikey=antigate_key,
                                 website_key=website_key,
                                 website_url=url,
                                 useragent=ua_rand,
                                 wait_limit=10
                                 ).captcha_text
        resp = s.post(url, data)
    with open(os.path.join(basedir, 'upornia-upload-result.html'), 'wb') as files:
            files.write(resp.content)
    if 'Video has been created successfully' in resp.text:
        log.info("{}: upload success".format(name))

    else:
        log.error("{}: upload error: {}".format(name, resp.text))

    return True

def get_file_data(path):
    with open(path, 'rb') as f:
        fdata = f.read()
    return fdata.decode('latin-1')

def main():
    global s
    info = {}
    info['filename'] = 'test.mp4'
    info['video'] = 'test.mp4'
    info['title'] = 'Hot sex video'
    info['description'] = 'red gym shorts'
    info['tags'] = 'Dirty Talk,Sex,Hot'
    s = requests.Session()
    s.headers['User-Agent'] = ua_rand
    resp = s.get(site, verify = False)
    login('eve64warnock','RDBAv0tkF')
    upload_video(info)



if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(SNIMissingWarning)
    requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
    try:
        log.info("{}: <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< START".format(name))
        main()
        log.info("{}: >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> END".format(name))
    except SystemExit:
        log.info('{}: EXIT'.format(name))
    except:
        log.exception('{}: GLOBAL ERROR'.format(name))
        
