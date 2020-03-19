#!/usr/bin/python
# -*- coding= utf-8 -*-


#from lib.library import *
#from lib.orientation import *
#from lib.antigate2 import Antigate
#from lib.custommail import CustomMail
from requests.exceptions import ConnectionError
from requests.packages.urllib3.exceptions import InsecureRequestWarning, SNIMissingWarning, InsecurePlatformWarning
from urllib.parse import unquote, quote, urljoin, urlparse
import logging as log
import random
import re
import requests
import string
import sys,os
import time


basedir = os.path.dirname(__file__)
name = "spankbang"
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

ua_rand = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.116 Safari/537.36'
data_sitekey = '6LcoxXsUAAAAAGEox9WUa_lOTuPnOr6WxUH57ryQ'
site = 'https://spankbang.com'



def upload_video(info,_domain):
    dct = {}
    dct['filename'] = info['filename']
    dct['title'] = info['title']
    dct['orientation'] = '0'
    #cat = '{}'.format(make_category(info['tags'], spankbang_category))
    cat = '2,21'
    category = cat.split(',')
    dct['identifier'] = str(random.randint(100000000,900000000)) + '-' + re.sub('[\W]','',dct['filename'])

    log.info("{}: filename: {}".format(name, dct['filename']))

    log.info('{}: identifier: {}'.format(name, dct['identifier']))
    log.info("{}: title: {}".format(name, dct['title']))
    log.info("{}: tags: {}".format(name, info['tags']))
    log.info("{}: category: {}".format(name, category))


    s.headers.clear()
    url = urljoin(_domain, 'users/upload')
    log.info('{}: get {}'.format(name,url))
    _host = urlparse(_domain).hostname
    s.headers['User-Agent'] = ua_rand
    s.headers['Host'] = _host
    s.headers['Referer'] = _domain

    resp = s.get(url, verify=False)


    dct['video_data'] = get_file_data(info['video'])
    dct['filesize'] = len(dct['video_data'])
    log.info("{}: filesize: {}".format(name, dct['filesize']))

    for i in range(3):
        time.sleep(5)
        resp = s.get(resp.url)

        if 'Uploading has been disabled' in resp.text:
            log.error("{}: Uploading has been disabled. Account deleted".format(name))
            exit()

        server_num = re.findall('server_url = "https://(.+?).spankbang.com"', resp.text)[0]

        sb = requests.utils.dict_from_cookiejar(s.cookies)
        log.info('{}: session: {}'.format(name, sb))
        sb_csrf_session = sb['sb_session']

        data = {
            'data': '',
            'id': '',
            'sb_session': sb_csrf_session
            }

        url = 'https://spankbang.com/api/upload_token'
        log.debug("{}: data for upload token: {}".format(name, data))

        resp = s.post(url, data)
        log.debug("{}: upload token resp: {}".format(name, resp.text))
        if len(str(resp.text)) < 30:
            log.error("{}: post to {}, wrong upload token: {}".format(name, url, str(resp.text)))
            continue
        else:
            log.info("{}: upload token {}".format(name, resp.text))
            dct['upload_token'] = re.findall('"results":"(.+?)"', resp.text)[0]
            log.info("{}: post to {}, upload token: {}".format(name, url, dct['upload_token']))
            break
    else:
        return True


    part_count = int(dct['filesize'] / 1048576) + 1
    dct['part_count'] = part_count
    log.info("{}: part counts: {}".format(name, part_count))

    dct['resumableFilename'] = quote(dct['filename'])

    start_c = 0
    end_c = 1048576

    log.info('{}: start attach file'.format(name))
    for n in range(part_count):

        n_ = n + 1

        try:
            part_data = dct['video_data'][start_c:end_c]
        except:
            log.info("end_part_data".format(n_, len(part_data)))
            return True


        start_c += 1048576
        end_c += 1048576

        dct['resumableCurrentChunkSize'] = len(part_data)
        dct['n_'] = n_
        dct['part_data'] = part_data


        url = 'https://{}.spankbang.com/resumable_upload?' \
              'resumableChunkNumber={}&' \
              'resumableChunkSize=1048576&' \
              'resumableCurrentChunkSize={}&' \
              'resumableTotalSize={}&' \
              'resumableType=video%2Fmp4&' \
              'resumableIdentifier={}&' \
              'resumableFilename={}&' \
              'resumableRelativePath={}&' \
              'resumableTotalChunks={}&' \
              'upload_token={}'.format(server_num,
                                       n_,
                                       len(part_data),
                                       dct['filesize'],
                                       dct['identifier'],
                                       quote(dct['filename']),
                                       quote(dct['filename']),
                                       part_count,
                                       dct['upload_token'])

        data = '''-----------------------------27884144051004
Content-Disposition: form-data; name="resumableChunkNumber"

{n_}
-----------------------------27884144051004
Content-Disposition: form-data; name="resumableChunkSize"

1048576
-----------------------------27884144051004
Content-Disposition: form-data; name="resumableCurrentChunkSize"

{resumableCurrentChunkSize}
-----------------------------27884144051004
Content-Disposition: form-data; name="resumableTotalSize"

{filesize}
-----------------------------27884144051004
Content-Disposition: form-data; name="resumableType"

video/mp4
-----------------------------27884144051004
Content-Disposition: form-data; name="resumableIdentifier"

{identifier}
-----------------------------27884144051004
Content-Disposition: form-data; name="resumableFilename"

{resumableFilename}
-----------------------------27884144051004
Content-Disposition: form-data; name="resumableRelativePath"

{resumableFilename}
-----------------------------27884144051004
Content-Disposition: form-data; name="resumableTotalChunks"

{part_count}
-----------------------------27884144051004
Content-Disposition: form-data; name="upload_token"

{upload_token}
-----------------------------27884144051004
Content-Disposition: form-data; name="file"; filename="{filename}"
Content-Type: application/octet-stream

{part_data}
-----------------------------27884144051004--'''.format(**dct)


        s.headers['Content-Type'] = 'multipart/form-data; boundary=---------------------------27884144051004'
        s.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
        try:
           resp = s.post(url, data)
        except Exception as e:
           log.error("{}: upload exception: {}".format(name, e))
           return True

    log.info('{}: end attach file'.format(name))


    url = 'https://%s.spankbang.com/resumable_upload_data' % server_num
    #auto = 'https://%s.spankbang.com/resumable_upload_data_auto' % server_num

    data = {
             'auth_token': dct['upload_token'],
             'name': dct['title'],
             'description': info['description'],
             'channel': '0',
             'orientaion': dct['orientation'],
             'tags[]': info['tags'].split(','), # [dct['tag1'], dct['tag2'], dct['tag3']],
             'category[]': ['2', '21'] #[dct['cat1'], dct['cat2'], dct['cat3']]
             }

    log.info('{}: post to {} video data: {}'.format(name,url,data))

    s.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    s.headers['X-Requested-With'] = 'XMLHttpRequest'

    resp = s.post(url, data)

    if 'OK!' in resp.text:
        log.info("{}: upload success".format(name))
        return True
    else:
        log.error("{}: upload error".format(name))
        with open(os.path.join(basedir, 'spankbang-upload-error.html'), 'wb') as files:
            files.write(resp.content)
        return True

def login(username,password,_domain):


    log.info("{}: login to: {}:{}".format(name, username,password))

    url = urljoin(_domain, 'users/auth?ajax=1&login=1')

    resp = s.get(url)
    csrf = re.findall('name="csrf_token" type="hidden" value="(.+?)"', resp.text)[0]

    log.info("{}: csrf_token: {}".format(name, csrf))

    data = {
            'l_username': username,
            'l_password': password,
            'csrf_token': csrf
            }

    resp = s.post(url,data)

    if  'OK' in resp.text:
        log.info("{}: login success: {}".format(name,resp.text))
        return _domain
    else:
        log.info("{}: login error".format(name))
        with open(os.path.join(basedir,'log/spankbang-login-error.html'), 'wb') as files:
            files.write(resp.content)
        exit()

def get_file_data(path):
    with open(path, 'rb') as f:
        fdata = f.read()
    return fdata.decode('latin-1')

def main():
    global s
    s = requests.Session()
    s.headers['User-Agent'] = ua_rand
    s.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    s.headers['X-Requested-With'] = 'XMLHttpRequest'
    _d = s.get(site,verify = False)
    _domain = _d.url
    log.info('{}: domain: {}'.format(name, _domain))
    username = 'cepic76591'
    password = 's1234567'
    login(username,password,_domain)
    info = {}
    info['filename'] = 'test.mp4'
    info['video'] = 'test.mp4'
    info['title'] = 'Hot sex video'
    info['description'] = 'red gym shorts'
    info['tags'] = 'Dirty Talk,Sex,Hot'
    upload_video(info, _domain)



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
        if use_proxy:
            terminate()
    except:
        log.exception('{}: GLOBAL ERROR'.format(name))
        if use_proxy:
            terminate()
