
## PythonPwned

PythonPwned queries the HaveIBeenPwned's API to look for e-mails which might have been compromised in dumps or pastes.

### Features
- Basic queries, through single email or file
- Basic configuration: time, user-agent, proxy (when you get banned by HIBP servers)

### Usage
```
usage: pythPwned.py [-h] [-e email] [-f file] [-t time] [--user User-agent]
                    [--proxy proxy]

Python utility to query HaveIBeenPwned API

optional arguments:
  -h, --help         show this help message and exit
  -e email           Email to test for leakage/paste
  -f file            File with emails to test for leakage/paste
  -t time            Time to wait between requests (default: 2s.)
  --user User-agent  Change default user-agent (default: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0)
  --proxy proxy      Proxy to perform HTTP requests (ie.: http://localhost:8080, socks://localhost:8080)
```

## Thanks
- https://haveibeenpwned.com/
- https://github.com/thewhiteh4t/pwnedOrNot
