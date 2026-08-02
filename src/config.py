"""Endpoint and volume configuration for WebInject2026.

Four invariants live here, each closing a leak that a previous version shipped.
`validate_config()` enforces all four and is called at the top of every build.

  1. Every injectable parameter also has a benign generator on the same endpoint.
     v1 leaked `comment`, which carried 2,187 attacks and zero benign requests,
     so the parameter *name* predicted the label.
  2. Every endpoint declares at least one free-text-ish parameter. That parameter
     carries the benign "core" phrase whose id becomes the row's split group
     (see build.py); without it a row would have nowhere to put a groupable
     benign value and the tier would correlate with the path.
  3. Every attack family is reachable at >= MIN_ENDPOINTS_PER_FAMILY endpoints.
     In v2.1 all 204 XXE rows sat at one path, so path -> family mutual
     information was 0.55 and the secondary multi-class task was partly solvable
     from the URL alone.
  4. Every content type carries both benign and attack traffic, so
     `Content-Type` (which the detector inspects) cannot become a label proxy.
"""

VERSION = "3.0.0"
SEED = 42

# ---------------------------------------------------------------- volumes ----
# Benign traffic is split across three tiers (see DATASHEET.md).
#   routine        - ordinary navigation, alphanumeric-dominant
#   hard_negative  - punctuation-rich but provably non-injective
#   ambiguous      - text that is benign in context yet trips naive signatures
VOLUME = {
    "routine": 26_000,
    "hard_negative": 17_000,
    "ambiguous": 2_400,     # ~1/3 verbatim (irreducible floor), ~2/3 discussion
    "attack": 16_000,
}

SPLIT_FRACTIONS = {"train": 0.70, "val": 0.10, "test": 0.20}

# Share of attacks placed somewhere other than a query parameter.
BODY_INJECTION_RATE = 0.28
HEADER_INJECTION_RATE = 0.09

# Share of attacks rewritten by an evasion transform, and — of those — the share
# that get a second or third transform chained on top (v2.1 applied at most one).
EVASION_RATE = 0.35
EVASION_CHAIN_RATE = 0.30

# Probability that a request carries punctuation-rich headers (a browser Referer
# with a real search string, a `prefs` cookie, forwarding headers). Drawn
# INDEPENDENTLY of the label for every row.
#
# v2.1 gave every attack row hard-negative headers and gave routine benign rows
# plain ones, so a `prefs=` cookie — which has nothing to do with the attack —
# moved P(attack) from 17.6% to 44.9%. Headers are part of the inspected payload,
# so that was a free label signal. The `header_leak` gate now checks this.
HEADER_PUNCT_RATE = 0.45

# Requests are chunked into synthetic sessions (a shared PHPSESSID) so sequence
# and behavioural models have something to group on. Sessions are assigned after
# the split, so a session never spans two splits.
SESSION_LEN = (3, 12)

# A family is only allowed if it is reachable from at least this many endpoints;
# otherwise the URL predicts the family (invariant 3 above).
MIN_ENDPOINTS_PER_FAMILY = 6

# Parameter types that can carry a groupable benign phrase (invariant 2).
TEXT_TYPES = {"free_text", "search_query"}

# --------------------------------------------------------------- families ----
# Fourteen families: the ten from v2.1 plus four that dominate modern advisories
# and were entirely absent (JNDI/Log4Shell, insecure deserialization, prototype
# pollution, request smuggling / header injection).
FAMILIES = [
    "sqli", "xss", "cmdi", "traversal", "ssti", "nosqli", "ssrf", "crlf",
    "ldapi", "xxe", "jndi", "deser", "protopollute", "smuggle",
]

# Relative sampling weight per family. Roughly mirrors real-world prevalence
# (XSS and SQLi dominate; XXE is rare) while keeping every family above the
# volume it needs for >=12 held-out payload groups in the test split.
FAMILY_WEIGHTS = {
    "xss": 22.0, "sqli": 20.0, "ssti": 10.0, "ssrf": 8.0, "nosqli": 7.5,
    "traversal": 7.5, "cmdi": 7.0, "jndi": 4.0, "ldapi": 4.0,
    "protopollute": 3.5, "deser": 3.5, "crlf": 3.0, "smuggle": 3.0, "xxe": 2.5,
}

# Families that make sense injected into a header rather than a parameter.
HEADER_FAMILIES = ("xss", "sqli", "crlf", "ssti", "jndi", "smuggle")

# Shorthand family bundles, so endpoint declarations stay readable and every
# family lands on many different paths.
_TEXTUAL = ["xss", "ssti", "sqli", "nosqli", "jndi", "protopollute", "ldapi"]
_IDENT = ["sqli", "nosqli", "jndi", "deser", "protopollute"]
_RESOURCE = ["traversal", "ssrf", "xxe", "jndi", "deser"]
_ROUTING = ["ssrf", "crlf", "smuggle", "xss", "jndi"]
_DOCUMENT = ["xxe", "deser", "sqli", "ldapi", "protopollute", "ssti"]

# --------------------------------------------------------------- endpoints ---
# path/method  the request line
# ctype        body encoding: form | json | graphql | multipart (GET => unused)
# params       list of (name, field_type) used to synthesise benign values
# body         params delivered in the request body rather than the query string
# inject       subset of param names that may carry an attack payload
# families     attack families plausible at this endpoint
APPS = {
    "dvwa": {
        "base": "http://localhost:8080",
        "login": {
            "url": "/login.php",
            "data": {"username": "admin", "password": "password", "Login": "Login"},
            "token_re": r"user_token'\s*value='([^']+)'",
            "token_field": "user_token",
            "post_login": [
                ("/security.php", {"security": "low", "seclev_submit": "Submit"}),
            ],
        },
        "endpoints": [
            {
                "path": "/vulnerabilities/sqli/", "method": "GET",
                "params": [("id", "int_id"), ("Submit", "const:Submit"),
                           ("session", "session_id"), ("ref", "search_query")],
                "inject": ["id", "ref"],
                "families": _IDENT + ["xss", "ssti"],
            },
            {
                "path": "/vulnerabilities/xss_r/", "method": "GET",
                "params": [("name", "person_name"), ("token", "digits"),
                           ("note", "free_text")],
                "inject": ["name", "note"],
                "families": _TEXTUAL + ["cmdi"],
            },
            {
                "path": "/vulnerabilities/exec/", "method": "GET",
                "params": [("ip", "ip_or_host"), ("Submit", "const:Submit"),
                           ("comment", "free_text")],
                "inject": ["ip", "comment"],
                "families": ["cmdi", "xss", "ssrf", "jndi", "ssti", "smuggle"],
            },
            {
                "path": "/login.php", "method": "POST", "ctype": "form",
                "params": [("username", "username"), ("password", "password"),
                           ("Login", "const:Login"), ("redirect", "url_value"),
                           ("csrf", "token"), ("hint", "free_text")],
                "body": ["username", "password", "Login", "hint"],
                "inject": ["username", "password", "redirect", "hint"],
                "families": ["sqli", "ssrf", "crlf", "ldapi", "nosqli", "jndi"],
            },
            {
                "path": "/guestbook.php", "method": "POST", "ctype": "form",
                "params": [("txtName", "person_name"), ("mtxMessage", "free_text"),
                           ("btnSign", "const:Sign Guestbook")],
                "body": ["txtName", "mtxMessage", "btnSign"],
                "inject": ["txtName", "mtxMessage"],
                "families": _TEXTUAL + ["deser", "cmdi"],
            },
            {
                "path": "/vulnerabilities/upload/", "method": "POST",
                "ctype": "multipart",
                "params": [("file", "filename"), ("MAX_FILE_SIZE", "int_small"),
                           ("description", "free_text")],
                "body": ["file", "MAX_FILE_SIZE", "description"],
                "inject": ["file", "description"],
                "families": _RESOURCE + ["xss", "cmdi"],
            },
            {
                "path": "/vulnerabilities/fi/", "method": "GET",
                "params": [("page", "page_ref"), ("lang", "lang_code"),
                           ("q", "search_query")],
                "inject": ["page", "q"],
                "families": _RESOURCE + ["ssti", "protopollute"],
            },
            {
                "path": "/api/v1/notes", "method": "POST", "ctype": "json",
                "params": [("title", "search_query"), ("body", "free_text"),
                           ("authorId", "int_id"), ("tags", "field_list")],
                "body": ["title", "body", "authorId", "tags"],
                "inject": ["title", "body", "tags"],
                "families": _TEXTUAL + ["deser", "xxe"],
            },
            {
                "path": "/api/v1/notes", "method": "PATCH", "ctype": "json",
                "params": [("id", "int_id"), ("body", "free_text"),
                           ("pinned", "enum:true|false")],
                "body": ["id", "body", "pinned"],
                "inject": ["id", "body"],
                "families": _IDENT + ["xss", "ssti", "smuggle"],
            },
            {
                "path": "/api/v1/notes", "method": "DELETE", "ctype": "form",
                "params": [("id", "int_id"), ("reason", "free_text"),
                           ("confirm", "const:yes")],
                "inject": ["id", "reason"],
                "families": _IDENT + ["cmdi", "traversal"],
            },
        ],
    },

    "juice": {
        "base": "http://localhost:3000",
        "login": None,
        "endpoints": [
            {
                "path": "/rest/products/search", "method": "GET",
                "params": [("q", "search_query"), ("page", "int_small"),
                           ("sort", "enum:price|name|rating|newest")],
                "inject": ["q"],
                "families": _TEXTUAL + ["cmdi", "traversal"],
            },
            {
                "path": "/api/Products", "method": "GET",
                "params": [("id", "int_id"), ("limit", "int_small"),
                           ("fields", "field_list"), ("filter", "search_query")],
                "inject": ["id", "filter", "fields"],
                "families": _IDENT + ["ssti", "xss", "ldapi"],
            },
            {
                "path": "/rest/user/login", "method": "POST", "ctype": "json",
                "params": [("email", "email"), ("password", "password"),
                           ("remember", "enum:true|false"), ("hint", "free_text")],
                "body": ["email", "password", "remember", "hint"],
                "inject": ["email", "password", "hint"],
                "families": ["nosqli", "sqli", "ldapi", "jndi", "protopollute",
                             "deser"],
            },
            {
                "path": "/api/Feedbacks", "method": "POST", "ctype": "json",
                "params": [("rating", "int_tiny"), ("comment", "free_text"),
                           ("userId", "int_id")],
                "body": ["rating", "comment", "userId"],
                "inject": ["comment", "userId"],
                "families": _TEXTUAL + ["deser", "smuggle"],
            },
            {
                "path": "/rest/basket", "method": "GET",
                "params": [("productId", "int_id"), ("quantity", "int_tiny"),
                           ("basketId", "int_id"), ("coupon", "token"),
                           ("note", "free_text")],
                "inject": ["note", "coupon", "basketId"],
                "families": _TEXTUAL + ["cmdi", "deser"],
            },
            {
                "path": "/api/BasketItems", "method": "PUT", "ctype": "json",
                "params": [("BasketId", "int_id"), ("ProductId", "int_id"),
                           ("quantity", "int_tiny"), ("note", "free_text")],
                "body": ["BasketId", "ProductId", "quantity", "note"],
                "inject": ["BasketId", "note"],
                "families": _IDENT + ["xss", "ssti", "xxe"],
            },
            {
                "path": "/api/Addresss", "method": "POST", "ctype": "json",
                "params": [("city", "city"), ("zip", "postcode"),
                           ("street", "street"), ("country", "country_code"),
                           ("fullName", "person_name"), ("notes", "free_text")],
                "body": ["city", "zip", "street", "country", "fullName", "notes"],
                "inject": ["fullName", "street", "notes"],
                "families": _TEXTUAL + ["crlf", "deser"],
            },
            {
                "path": "/redirect", "method": "GET",
                "params": [("to", "url_value"), ("campaign", "search_query")],
                "inject": ["to", "campaign"],
                "families": _ROUTING + ["traversal"],
            },
            {
                "path": "/rest/track-order", "method": "GET",
                "params": [("id", "order_id"), ("note", "free_text")],
                "inject": ["id", "note"],
                "families": _IDENT + ["ssti", "traversal", "smuggle"],
            },
            {
                "path": "/graphql", "method": "POST", "ctype": "graphql",
                "params": [("search", "search_query"), ("first", "int_small"),
                           ("orderBy", "enum:price|name|rating")],
                "body": ["search", "first", "orderBy"],
                "inject": ["search"],
                "families": _TEXTUAL + ["deser", "xxe", "traversal"],
            },
            {
                "path": "/api/Complaints", "method": "POST", "ctype": "multipart",
                "params": [("message", "free_text"), ("file", "filename"),
                           ("userId", "int_id")],
                "body": ["message", "file", "userId"],
                "inject": ["message", "file"],
                "families": _RESOURCE + ["xss", "protopollute"],
            },
            {
                "path": "/api/Users", "method": "PATCH", "ctype": "json",
                "params": [("id", "int_id"), ("username", "username"),
                           ("bio", "free_text"), ("role", "enum:customer|deluxe")],
                "body": ["id", "username", "bio", "role"],
                "inject": ["id", "bio", "role"],
                "families": ["protopollute", "nosqli", "sqli", "xss", "deser",
                             "jndi", "ldapi"],
            },
            {
                "path": "/api/Products", "method": "DELETE", "ctype": "form",
                "params": [("id", "int_id"), ("reason", "free_text")],
                "inject": ["id", "reason"],
                "families": _IDENT + ["cmdi", "smuggle", "crlf"],
            },
        ],
    },

    "bwapp": {
        "base": "http://localhost:8081",
        "login": {
            "url": "/login.php",
            "data": {"login": "bee", "password": "bug",
                     "security_level": "0", "form": "submit"},
            "token_re": None, "token_field": None, "post_login": [],
        },
        "endpoints": [
            {
                "path": "/sqli_1.php", "method": "GET",
                "params": [("title", "search_query"), ("action", "const:search"),
                           ("limit", "int_small")],
                "inject": ["title"],
                "families": _TEXTUAL + ["cmdi", "deser"],
            },
            {
                "path": "/xss_get.php", "method": "GET",
                "params": [("firstname", "person_name"), ("lastname", "person_name"),
                           ("form", "const:submit"), ("message", "free_text")],
                "inject": ["firstname", "message"],
                "families": _TEXTUAL + ["crlf", "traversal"],
            },
            {
                "path": "/portal.php", "method": "GET",
                "params": [("city", "city"), ("ref", "token"),
                           ("lang", "lang_code"), ("q", "search_query"),
                           ("theme", "enum:light|dark|contrast")],
                "inject": ["lang", "ref", "q"],
                "families": _RESOURCE + ["xss", "smuggle", "crlf"],
            },
            {
                "path": "/commandi.php", "method": "GET",
                "params": [("target", "ip_or_host"), ("form", "const:submit"),
                           ("opts", "search_query")],
                "inject": ["target", "opts"],
                "families": ["cmdi", "ssrf", "jndi", "traversal", "xss", "deser"],
            },
            {
                "path": "/search.php", "method": "GET",
                "params": [("keyword", "search_query"), ("cat", "int_small"),
                           ("page", "int_small"), ("desc", "enum:asc|desc")],
                "inject": ["keyword", "cat"],
                "families": _TEXTUAL + ["traversal", "smuggle"],
            },
            {
                "path": "/user.php", "method": "POST", "ctype": "form",
                "params": [("login", "username"), ("token", "token"),
                           ("bio", "free_text")],
                "body": ["login", "bio"],
                "inject": ["login", "bio"],
                "families": _TEXTUAL + ["deser", "xxe"],
            },
            {
                "path": "/rlfi.php", "method": "GET",
                "params": [("language", "page_ref"), ("action", "const:go"),
                           ("q", "search_query")],
                "inject": ["language", "q"],
                "families": _RESOURCE + ["ssti", "cmdi"],
            },
            {
                "path": "/xmli_2.php", "method": "POST", "ctype": "form",
                "params": [("login", "username"), ("secret", "token"),
                           ("comment", "free_text")],
                "body": ["login", "secret", "comment"],
                "inject": ["login", "comment"],
                "families": _DOCUMENT + ["xss", "jndi"],
            },
            {
                "path": "/api/v2/users", "method": "PUT", "ctype": "json",
                "params": [("id", "int_id"), ("displayName", "person_name"),
                           ("about", "free_text"), ("locale", "lang_code")],
                "body": ["id", "displayName", "about", "locale"],
                "inject": ["id", "about", "displayName"],
                "families": ["protopollute", "sqli", "nosqli", "xss", "ssti",
                             "deser", "ldapi"],
            },
            {
                "path": "/upload.php", "method": "POST", "ctype": "multipart",
                "params": [("file", "filename"), ("caption", "free_text"),
                           ("album", "enum:public|private")],
                "body": ["file", "caption", "album"],
                "inject": ["file", "caption"],
                "families": _RESOURCE + ["cmdi", "smuggle"],
            },
            {
                "path": "/soap_service.php", "method": "POST", "ctype": "json",
                "params": [("doc", "free_text"), ("op", "enum:read|write|list"),
                           ("ref", "token")],
                "body": ["doc", "op", "ref"],
                "inject": ["doc", "ref"],
                "families": _DOCUMENT + ["jndi", "ssrf"],
            },
            {
                "path": "/notes.php", "method": "DELETE", "ctype": "form",
                "params": [("id", "int_id"), ("why", "free_text")],
                "inject": ["id", "why"],
                "families": _IDENT + ["cmdi", "crlf", "smuggle"],
            },
        ],
    },
}


# ------------------------------------------------------------- invariants ----
def endpoints():
    """Flat (app, endpoint) list."""
    return [(app, ep) for app, cfg in APPS.items() for ep in cfg["endpoints"]]


# Methods that carry a request body. GET and DELETE are modelled body-less, as
# they are in practice, so their parameters ride in the query string.
BODY_METHODS = ("POST", "PUT", "PATCH")


def content_type(ep):
    return ep.get("ctype", "form") if ep["method"] in BODY_METHODS else "query"


def validate_config():
    """Fail fast on the four invariants that keep metadata non-predictive."""
    problems = []
    fam_endpoints = {f: 0 for f in FAMILIES}
    ctype_families = {}

    for app, ep in endpoints():
        names = {n for n, _ in ep["params"]}
        types = {t for _, t in ep["params"]}
        where = f"{app}{ep['path']} [{ep['method']}]"

        for p in ep["inject"]:                                   # invariant 1
            if p not in names:
                problems.append(f"{where}: injectable param '{p}' has no benign generator")
        for p in ep.get("body", []):
            if p not in names:
                problems.append(f"{where}: body param '{p}' is not declared in params")
        if ep["method"] in BODY_METHODS and not ep.get("body"):
            problems.append(f"{where}: {ep['method']} endpoint declares no body params")
        if ep["method"] not in BODY_METHODS and ep.get("body"):
            problems.append(f"{where}: {ep['method']} endpoint cannot carry a body")

        if not (types & TEXT_TYPES):                             # invariant 2
            problems.append(f"{where}: no free-text param to carry a benign core")

        for f in ep["families"]:                                 # invariant 3
            if f not in fam_endpoints:
                problems.append(f"{where}: unknown family '{f}'")
            else:
                fam_endpoints[f] += 1
        ctype_families.setdefault(content_type(ep), set()).update(ep["families"])

    for f, n in fam_endpoints.items():
        if n < MIN_ENDPOINTS_PER_FAMILY:
            problems.append(
                f"family '{f}' reachable at only {n} endpoints "
                f"(min {MIN_ENDPOINTS_PER_FAMILY}) - the path would predict it")

    for ct, fams in ctype_families.items():                      # invariant 4
        if not fams:
            problems.append(f"content type '{ct}' carries no attack traffic")

    missing_w = [f for f in FAMILIES if f not in FAMILY_WEIGHTS]
    if missing_w:
        problems.append(f"families with no sampling weight: {missing_w}")

    if problems:
        raise ValueError("config invariant violated:\n  " + "\n  ".join(problems))
    return True


if __name__ == "__main__":
    validate_config()
    eps = endpoints()
    n_inj = sum(len(e["inject"]) for _, e in eps)
    cts = sorted({content_type(e) for _, e in eps})
    print(f"config OK: {len(APPS)} apps, {len(eps)} endpoints, {n_inj} injection "
          f"points, {len(FAMILIES)} families, content types {cts}")
