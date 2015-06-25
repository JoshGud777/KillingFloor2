import requests
import re
import time

admin = 'Admin'
HOST = 'localhost'
PORT = '8080'
USERNAME = 'Admin'
PASSWORD = 'Admin'
URL = 'http://' + HOST + ':' + PORT + '/ServerAdmin/'
S = requests.Session()

def Login(username, password):
    token, sessionid = get_login_form()
    data = {'token' : token,
            'username': username,
            'password': password,
            #Running with hash is safer, hash = username+pass >>sha1
            #'password_hash': '$sha1$1f95ec61b6ef02b5d2b138654da138bfdbbc7f3c',
            'password_hash': '',
            'remember': '-1'}
    cookies = {'sessionid': sessionid,
               'chatwindowframe': 'False'}
               
    headers = {'Connection': 'keep-alive',
              'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
              'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",}
    
    resp = get_page(URL, data, headers, cookies)

    authheader = resp.headers['set-cookie']

    match = re.search('authcred=["\']([\d\w\=]*)["\']', authheader)
    cookies['authcred'] = match.group(1)

    resp = get_page(URL+'current/info', None, headers, cookies)
    match = re.search('Killing Floor 2 WebAdmin - Server Info', resp.text)
    if match:
        auth = True
    else:
        auth = False
    return auth, headers, cookies

def get_page(pageurl, data={}, header={}, cookies={}):
    
    resp = requests.request('POST', pageurl,
    data=data,
    headers=header,
    cookies=cookies,
    allow_redirects=False)
    
    #prepped = req.prepare()
    #resp = S.send(prepped)
    
    return resp

def get_login_form():
    resp = get_page(URL)
    page = resp.text
    match = re.search('token["\'] value=["\']([\w\d]+)["\']', page)
    token = match.group(1)
    header = resp.headers['set-cookie']
    match = re.search('sessionid=[\'"]?([\w\s]*)[\'"]?', str(header))
    sessionid = match.group(1)
    return token, sessionid

def test():
    
    header = {'Connection': 'keep-alive',
              'Cookie' : 'sessionid=' + 'test1' + '; chatwindowframe=False"; ' + 'sessionid2=' + 'test2' + '; chatwindowframe=False"',
              'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
              'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",}
    page = get_page('http://192.168.1.222/cgi.py', {}, header)
    print (page.text)

    
def get_chat_form(headers, cookies):
    resp = get_page(URL + 'current/chat', {}, headers, cookies)
    match = re.search('name=["\']rnd["\'] value=["\']([\d\w]+)', resp.text)
    rnd = match.group(1)
    return rnd


def send_msg(msg, headers, cookies):
    rnd = get_chat_form(headers, cookies)
    resp = get_page(URL + 'current/chat', {'rnd':rnd, 'message':msg}, headers, cookies)


def check_connection():
    auth, headers, cookies = Login(USERNAME, PASSWORD)
    if auth:
        try:
            send_msg('Python Script V1.0 Connected', headers, cookies)
            print('Python Connected')
            return headers, cookies
        except e:
            auth = False
            print('!!!ERROR!!!')
    else:
        print('!!!NO AUTH!!!')
    return False

def main(headers, cookies):
    starttime = time.time()
    while True:
        try:
            currenttime = time.time()
            msg = 'The current UNIX time is ' + str(currenttime)
            send_msg(msg, headers, cookies)
            print('Sent:',msg)
            time.sleep(60)
        except:
            end = time.time()
            print('---Error @', str(endtime), 'Started @', starttime)
            break
    s = m = h = d = 0
    s = int(time.time())
    while s > 60:
        s -= 60
        m += 1
    while m > 60:
        m -= 60
        h += 1
    while h > 24:
        h -= 24
        d += 1
    print('---Ran for:',d,'day(s),',h,'hour(s),',m,'min(s),',s,'seconds.')


def resp_dBug(resp):
    print(resp.text)
    print(resp._content)
    print(resp.status_code)
    print(resp.headers)
    print(resp.url)
    print(resp.history)
    print(resp.encoding)
    print(resp.reason)
    print(resp.cookies)
    print(resp.elapsed)
    print(resp.request)

if '__main__' == __name__:
    headers, cookies = check_connection()
    if headers:
              main(headers, cookies)
    print('Done.')

    
