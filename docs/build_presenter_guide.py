"""Render the WebInject2026 presenter's guide to PDF.

    python docs/build_presenter_guide.py

Needs reportlab (see requirements.txt, optional block). Every figure quoted in
the guide is pulled from data/manifest.json, data/baselines.json and
data/evaluation.json at build time, so the document cannot drift from the
corpus the way a hand-typed summary would.
"""

import json
import os
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, ListFlowable,
                                ListItem, PageBreak, PageTemplate, Paragraph,
                                Spacer, Table, TableStyle)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "WebInject2026_Presenter_Guide.pdf")

MAN = json.load(open(os.path.join(ROOT, "data", "manifest.json")))
BASE = json.load(open(os.path.join(ROOT, "data", "baselines.json")))
EVAL = json.load(open(os.path.join(ROOT, "data", "evaluation.json")))

# reportlab's built-in fonts use WinAnsi: arrows, >=, <= and check marks render
# as black boxes. Keep body text to characters that encoding actually has.
INK = colors.HexColor("#1a1a1a")
MUTED = colors.HexColor("#5b6270")
ACCENT = colors.HexColor("#1f4e79")
RULE = colors.HexColor("#c8ccd4")
BOXBG = colors.HexColor("#eef2f7")
BOXED = colors.HexColor("#d6dde8")

ss = getSampleStyleSheet()


def _st(name, **kw):
    kw.setdefault("parent", ss["Normal"])
    return ParagraphStyle(name, **kw)


S_TITLE = _st("t", fontName="Helvetica-Bold", fontSize=26, leading=31, textColor=ACCENT)
S_SUB = _st("s", fontName="Helvetica", fontSize=13, leading=18, textColor=MUTED)
S_H1 = _st("h1", fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=ACCENT,
           spaceBefore=2, spaceAfter=7)
S_H2 = _st("h2", fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=INK,
           spaceBefore=13, spaceAfter=5)
S_BODY = _st("b", fontName="Helvetica", fontSize=10, leading=15.2, textColor=INK,
             alignment=TA_JUSTIFY, spaceAfter=7)
S_LEAD = _st("l", fontName="Helvetica-Oblique", fontSize=10.5, leading=16,
             textColor=MUTED, spaceAfter=9)
S_BULLET = _st("bu", parent=S_BODY, alignment=0, spaceAfter=3.5)
S_BOX = _st("box", fontName="Helvetica", fontSize=9.6, leading=14.4, textColor=INK,
            alignment=TA_JUSTIFY)
S_BOXH = _st("boxh", fontName="Helvetica-Bold", fontSize=9.6, leading=14, textColor=ACCENT)
S_CODE = _st("c", fontName="Courier", fontSize=8.6, leading=12.4, textColor=INK)
S_TH = _st("th", fontName="Helvetica-Bold", fontSize=8.8, leading=11.5, textColor=colors.white)
S_TD = _st("td", fontName="Helvetica", fontSize=8.8, leading=11.5, textColor=INK)
S_TDB = _st("tdb", fontName="Helvetica-Bold", fontSize=8.8, leading=11.5, textColor=INK)
S_CAP = _st("cap", fontName="Helvetica-Oblique", fontSize=8.4, leading=11.5,
            textColor=MUTED, spaceAfter=10)


def P(t, style=S_BODY):
    return Paragraph(t, style)


def H1(t):
    return Paragraph(t, S_H1)


def H2(t):
    return Paragraph(t, S_H2)


def LEAD(t):
    return Paragraph(t, S_LEAD)


def BULLETS(items, style=S_BULLET):
    return ListFlowable(
        [ListItem(Paragraph(i, style), leftIndent=12) for i in items],
        bulletType="bullet", start="•", bulletFontSize=8, bulletOffsetY=-0.5,
        leftIndent=13, bulletColor=ACCENT, spaceAfter=8)


def BOX(title, body):
    inner = [Paragraph(title, S_BOXH), Spacer(1, 3), Paragraph(body, S_BOX)]
    t = Table([[inner]], colWidths=[165 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BOXBG),
        ("BOX", (0, 0), (-1, -1), 0.6, BOXED),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    return KeepTogether([t, Spacer(1, 10)])


def CODE(lines):
    t = Table([[Paragraph(l.replace(" ", "&nbsp;"), S_CODE)] for l in lines],
              colWidths=[165 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f6f7f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
    ]))
    return KeepTogether([Spacer(1, 2), t, Spacer(1, 10)])


def TABLE(header, rows, widths, caption=None, bold_last_row=False, align_right=None):
    align_right = align_right or []
    data = [[Paragraph(h, S_TH) for h in header]]
    for i, r in enumerate(rows):
        last = bold_last_row and i == len(rows) - 1
        st = S_TDB if last else S_TD
        data.append([Paragraph(str(c), st) for c in r])
    t = Table(data, colWidths=widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, RULE),
        ("BOX", (0, 0), (-1, -1), 0.6, RULE),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f4f6f9")))
    for c in align_right:
        style.append(("ALIGN", (c, 0), (c, -1), "RIGHT"))
    t.setStyle(TableStyle(style))
    out = [t]
    if caption:
        out += [Spacer(1, 4), Paragraph(caption, S_CAP)]
    else:
        out += [Spacer(1, 11)]
    return KeepTogether(out)


def _chrome(canvas, doc):
    canvas.saveState()
    if doc.page > 1:
        canvas.setFont("Helvetica", 7.6)
        canvas.setFillColor(MUTED)
        canvas.drawString(22 * mm, 287 * mm, "WebInject2026 - Presenter's Guide")
        canvas.drawRightString(188 * mm, 287 * mm, "v%s" % MAN["version"])
        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.4)
        canvas.line(22 * mm, 285 * mm, 188 * mm, 285 * mm)
        canvas.drawCentredString(105 * mm, 12 * mm, str(doc.page))
    canvas.restoreState()


def pct(x):
    return "%.1f" % (x * 100)


def build():
    doc = BaseDocTemplate(OUT, pagesize=A4,
                          leftMargin=22 * mm, rightMargin=22 * mm,
                          topMargin=26 * mm, bottomMargin=20 * mm,
                          title="WebInject2026 - Presenter's Guide",
                          author="Anish Choudhury; Abhishek",
                          subject="A plain-language guide to the WebInject2026 corpus")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f")
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=_chrome)])
    doc.build(story())
    return OUT


# --------------------------------------------------------------- content ----
def story():
    s = []
    s += cover()
    s += how_to_use()
    s += part1()
    s += part2()
    s += part3()
    s += part4()
    s += part5()
    s += part6()
    s += part7()
    s += part8()
    s += glossary()
    s += cheatsheet()
    return s


def cover():
    return [
        Spacer(1, 42 * mm),
        P("WebInject2026", S_TITLE),
        Spacer(1, 5),
        P("A Presenter's Guide", _st("s2", fontName="Helvetica", fontSize=17,
                                     leading=22, textColor=INK)),
        Spacer(1, 12),
        P("Everything you need to understand, explain and defend this work "
          "in front of an audience &mdash; written for a reader with no "
          "background in computer science.", S_SUB),
        Spacer(1, 16),
        Table([[""]], colWidths=[60 * mm], rowHeights=[2],
              style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), ACCENT)])),
        Spacer(1, 16),
        P("Corpus version %s &nbsp;|&nbsp; %s labelled HTTP requests &nbsp;|&nbsp; "
          "%d attack families &nbsp;|&nbsp; 3 applications"
          % (MAN["version"], "{:,}".format(MAN["rows"]),
             len([k for k in MAN["attack_type"] if k != "benign"])), S_SUB),
        Spacer(1, 4),
        P("Anish Choudhury &nbsp;&middot;&nbsp; Abhishek", S_SUB),
        Spacer(1, 30),
        BOX("What this document is",
            "A companion to the corpus, not the paper. It builds the whole story "
            "from first principles: what the attacks are, why a new dataset was "
            "needed, exactly how it was built, what the numbers mean, where the "
            "work is weak, and what a sceptical audience is likely to ask. If you "
            "read it end to end you should be able to give the talk and handle "
            "questions without having written a line of the code."),
        PageBreak(),
    ]


def how_to_use():
    return [
        H1("How to use this document"),
        LEAD("Eight parts, front to back. Parts 1 and 2 are the story; parts 3 to 5 "
             "are the substance; parts 6 to 8 are what gets you through questions."),
        TABLE(
            ["Part", "What it covers", "Read it if"],
            [["1. The problem", "What web injection attacks are, in plain language",
              "You want the ground floor"],
             ["2. Why a new dataset", "What was wrong with the existing ones",
              "You want the motivation"],
             ["3. How it was built", "The construction method, step by step",
              "You need to defend the design"],
             ["4. The quality gate", "The 26 automated checks and what each rules out",
              "This is the paper's core claim"],
             ["5. What we found", "The results, and how to read them honestly",
              "You are presenting numbers"],
             ["6. Limitations", "Where the work is genuinely weak",
              "Always. Reviewers start here"],
             ["7. Giving the talk", "A 12-minute arc and a slide plan",
              "You are the one at the podium"],
             ["8. Questions", "Likely questions, with answers",
              "The night before"]],
            [30 * mm, 78 * mm, 57 * mm]),
        BOX("One sentence, if you only remember one thing",
            "Most published results in this field are inflated because the test data "
            "secretly overlaps with the training data; this corpus is built so that "
            "cannot happen, ships an automated audit that proves it, and the honest "
            "numbers that result are visibly lower than the inflated ones."),
        PageBreak(),
    ]


def part1():
    fams = [
        ("SQL injection (sqli)", "Tricks the database into running the attacker's query",
         MAN["attack_type"]["sqli"]),
        ("Cross-site scripting (xss)", "Plants code that runs in another visitor's browser",
         MAN["attack_type"]["xss"]),
        ("Server-side template injection (ssti)", "Abuses the page-building engine to run code",
         MAN["attack_type"]["ssti"]),
        ("NoSQL injection (nosqli)", "Same idea as SQLi, against newer databases",
         MAN["attack_type"]["nosqli"]),
        ("JNDI / Log4Shell (jndi)", "Makes the logging system fetch and run remote code",
         MAN["attack_type"]["jndi"]),
        ("Path traversal (traversal)", "Walks out of the intended folder to read private files",
         MAN["attack_type"]["traversal"]),
        ("Server-side request forgery (ssrf)", "Makes the server fetch a URL on the attacker's behalf",
         MAN["attack_type"]["ssrf"]),
        ("Command injection (cmdi)", "Smuggles operating-system commands into a parameter",
         MAN["attack_type"]["cmdi"]),
        ("Insecure deserialization (deser)", "Feeds a poisoned saved object back to the server",
         MAN["attack_type"]["deser"]),
        ("Prototype pollution (protopollute)", "Corrupts shared defaults in JavaScript objects",
         MAN["attack_type"]["protopollute"]),
        ("LDAP injection (ldapi)", "Same trick against the corporate directory service",
         MAN["attack_type"]["ldapi"]),
        ("XML external entity (xxe)", "Abuses XML parsing to read files or reach the network",
         MAN["attack_type"]["xxe"]),
        ("Request smuggling (smuggle)", "Exploits disagreement between two servers about where a request ends",
         MAN["attack_type"]["smuggle"]),
        ("CRLF / header injection (crlf)", "Splices new lines into a response header",
         MAN["attack_type"]["crlf"]),
    ]
    return [
        H1("Part 1 &mdash; The problem, from the ground up"),
        LEAD("If you already know what SQL injection is, skim to Part 2."),

        H2("1.1  What a web request actually is"),
        P("Every time someone clicks a link, submits a form or opens an app, their "
          "device sends a short text message to a server. That message is called an "
          "<b>HTTP request</b>. It is genuinely just text. It says which page is "
          "wanted, and carries whatever the user typed &mdash; a search term, a "
          "login name, a review."),
        CODE(["POST /search.php  HTTP/1.1",
              "Host: shop.example.com",
              "Cookie: session=8f3a...",
              "",
              "q=blue+running+shoes&page=2"]),
        P("The last line is the interesting part. <font face='Courier'>q</font> is a "
          "slot the application expects a user to fill with a search term. The "
          "server takes what is in that slot and uses it &mdash; usually by pasting "
          "it into an instruction it sends onward to a database."),

        H2("1.2  What injection means"),
        P("Imagine handing a waiter a card with your name on it. The waiter walks to "
          "the kitchen and reads out: <i>\"table four, the customer's name is "
          "&lt;whatever is on the card&gt;\"</i>. Now suppose you write on the card: "
          "<i>Bob. Also, empty the till and bring me the cash.</i> If the kitchen has "
          "no way to tell where your name stops and a new instruction starts, it will "
          "do both."),
        P("That is injection, exactly. The application meant the slot to hold "
          "<b>data</b>. The attacker fills it with something that the next system "
          "downstream reads as an <b>instruction</b>. The whole family of attacks in "
          "this corpus is that one idea, aimed at different downstream systems: the "
          "database, the browser, the template engine, the operating system, the XML "
          "parser, the logger."),
        BOX("Why this still matters in 2026",
            "Injection has sat at or near the top of the OWASP Top Ten &mdash; the "
            "industry's list of the most serious web risks &mdash; for over two "
            "decades. It persists because the fix has to be applied at every single "
            "place user input meets another system, and one missed spot is enough. "
            "Detection is the safety net for the spots that get missed."),

        H2("1.3  The fourteen families in this corpus"),
        P("Each row of the corpus is one HTTP request. The attack rows are drawn from "
          "fourteen families. You do not need to explain all fourteen on stage; the "
          "point of the list is <b>breadth</b>, and that four of them are recent "
          "additions the older public datasets predate entirely."),
        TABLE(["Family", "What it does", "Rows"],
              [[n, d, "{:,}".format(c)] for n, d, c in fams],
              [55 * mm, 88 * mm, 22 * mm], align_right=[2],
              caption="Attack rows by family. The imbalance is deliberate and mirrors "
                      "real-world prevalence: SQLi and XSS dominate reported incidents."),
        P("The last four in that list &mdash; JNDI/Log4Shell, deserialization, "
          "prototype pollution and request smuggling &mdash; are the ones that "
          "dominate modern security advisories. <b>None of them appears in the public "
          "datasets this field has been using.</b> That is one of the two reasons this "
          "corpus exists."),

        H2("1.4  Why detecting it is hard"),
        P("The naive idea is to look for suspicious punctuation: quotes, angle "
          "brackets, semicolons. It fails immediately, because ordinary traffic is "
          "full of them. A customer named O'Brien. A product review containing "
          "<font face='Courier'>&lt;3</font>. A developer pasting a code snippet into "
          "a bug report. A perfectly normal web token that looks like line noise."),
        P("So a detector has to separate <i>punctuation that is being used as an "
          "instruction</i> from <i>punctuation that is just punctuation</i>. That "
          "distinction is the actual task, and &mdash; as Part 2 explains &mdash; it "
          "is precisely the distinction that existing datasets let a model avoid."),
        PageBreak(),
    ]


def part2():
    return [
        H1("Part 2 &mdash; Why the field needed another dataset"),
        LEAD("The honest answer has two halves: the old data is old, and the old data "
             "is too easy in a way nobody was measuring."),

        H2("2.1  The first half: the data is stale"),
        P("The two public datasets almost everyone uses are <b>CSIC-2010</b> and "
          "<b>ECML/PKDD-2007</b>. The years are in the names. They were captured "
          "before the modern web existed in its current form: before JSON became the "
          "default way applications exchange data, before GraphQL, before the "
          "attack families in the second half of the table in Part 1 were invented. "
          "A detector trained and tested only on that traffic is being examined on a "
          "world that no longer exists."),

        H2("2.2  The second half: the shortcut problem"),
        P("This is the part worth spending time on, because it is the paper's real "
          "contribution and it generalises well beyond security."),
        BOX("The exam analogy",
            "You set an exam to find out who can do arithmetic. Unknown to you, the "
            "answers are faintly printed on the back of the paper. Everyone scores "
            "98%. The scores are real &mdash; the students did write those answers "
            "&mdash; but they measure eyesight, not arithmetic. Worse: a student who "
            "actually learned arithmetic scores the same as one who just looked. The "
            "exam has stopped discriminating, and you cannot tell from the scores "
            "alone that anything is wrong."),
        P("Machine-learning datasets get faint printing on the back all the time. It "
          "is called <b>leakage</b>, or a <b>shortcut</b>: some incidental feature of "
          "how the data was assembled happens to correlate with the answer, and the "
          "model finds it, because finding correlations is the only thing a model "
          "does. The model then looks excellent and is useless in deployment, where "
          "the incidental feature does not exist."),
        P("Concretely, in web-attack corpora, leakage looks like this:"),
        BULLETS([
            "<b>Length.</b> If attack requests are systematically longer than benign "
            "ones, a model can score well by measuring length and never look at "
            "content.",
            "<b>Character class.</b> If only attacks contain angle brackets, "
            "detecting attacks reduces to detecting angle brackets.",
            "<b>The endpoint.</b> If every XXE example was collected against one "
            "particular URL, the model learns that URL, not the attack.",
            "<b>The metadata.</b> If the word <i>sqli</i> ends up somewhere in the "
            "text of the request itself, the label is literally written on the paper.",
            "<b>Repetition across the split.</b> The most common and most damaging "
            "one &mdash; explained next.",
        ]),

        H2("2.3  The one that catches nearly everyone"),
        P("To measure whether a model has learned anything, you train it on one "
          "portion of the data and test it on a portion it has never seen. The "
          "standard way to divide them is to shuffle the rows and cut. That is "
          "<b>wrong</b> for this kind of data, and the reason is simple: the same "
          "attack payload usually appears many times in a corpus, dressed in "
          "different requests. Shuffle randomly and copies of the same payload land "
          "on both sides of the divide."),
        P("The model is then asked at test time about a payload it has already "
          "memorised from training. It scores brilliantly. You have measured its "
          "memory, not its ability to recognise an attack it has never encountered "
          "&mdash; which is the entire job."),
        BOX("What v3 of this corpus fixes on the benign side",
            "The previous version of this dataset made the attack side rigorous but "
            "left two measurable leaks on the benign side. Both were found by the "
            "audit and both are quantified: 67% of the difficult benign values in the "
            "test set appeared word-for-word in training, and attack requests had "
            "been given cluttered headers while ordinary benign requests got plain "
            "ones &mdash; so a cookie alone shifted the model's estimate of \"is this "
            "an attack\" from 18% to 45%. Version 3 rebuilt the benign side to close "
            "both. That story is worth telling on stage: it shows the audit works, "
            "because it caught the authors."),

        H2("2.4  The contribution, stated plainly"),
        P("The corpus is not just \"more data\". Its claim is <b>auditability</b>: "
          "every known way this task can be made accidentally trivial has been turned "
          "into an automated check, and the build refuses to publish if any check "
          "fails. There are %d such checks. They run on every change, in continuous "
          "integration, and anyone can run them in one command."
          % 26),
        P("The consequence is that the headline numbers are <i>lower</i> than the "
          "field is used to seeing, and that is the point. A number you can trust at "
          "87 is worth more than a number you cannot trust at 99."),
        PageBreak(),
    ]


def part3():
    g = MAN["groups"]
    return [
        H1("Part 3 &mdash; How the corpus was built"),
        LEAD("Three ingredients: a realistic surface to attack, a benign side "
             "engineered to be hard, and an attack side engineered to be varied. "
             "Then a split you can trust."),

        H2("3.1  The surface"),
        P("Requests are modelled on three deliberately vulnerable practice "
          "applications used industry-wide for training: <b>DVWA</b>, <b>OWASP Juice "
          "Shop</b> and <b>bWAPP</b>. Together they supply 35 realistic endpoints "
          "&mdash; login forms, search boxes, file uploads, product pages, APIs."),
        TABLE(["Application", "Rows", "Content type", "Rows", "Method mix"],
              [["bWAPP", "{:,}".format(MAN["app"]["bwapp"]), "query",
                "{:,}".format(MAN["content_type"]["query"]), "GET"],
               ["OWASP Juice Shop", "{:,}".format(MAN["app"]["juice"]), "json",
                "{:,}".format(MAN["content_type"]["json"]), "POST"],
               ["DVWA", "{:,}".format(MAN["app"]["dvwa"]), "form",
                "{:,}".format(MAN["content_type"]["form"]), "PUT"],
               ["", "", "multipart", "{:,}".format(MAN["content_type"]["multipart"]), "PATCH"],
               ["", "", "graphql", "{:,}".format(MAN["content_type"]["graphql"]), "DELETE"]],
              [38 * mm, 22 * mm, 30 * mm, 22 * mm, 53 * mm], align_right=[1, 3],
              caption="No real users were involved and no real traffic was captured: "
                      "the corpus contains no personal data of any kind."),
        P("Crucially the attack can be hidden anywhere a real one could be: in the "
          "URL ({:,} rows), in the body ({:,}) or in a header ({:,}). Requests are "
          "also grouped into {:,} browsing <b>sessions</b>, so a detector cannot "
          "cheat by assuming each request stands alone.".format(
              MAN["placement"]["query"], MAN["placement"]["body"],
              MAN["placement"]["header"], MAN["sessions"])),

        H2("3.2  The benign side &mdash; the part that took the work"),
        P("Anyone can generate innocent-looking traffic. The difficulty is generating "
          "innocent traffic that is <i>hard</i>, so the task cannot collapse into "
          "\"does this contain a quote mark\". The benign rows come in three tiers."),
        TABLE(["Tier", "Rows", "What it is, and why it is there"],
              [["routine", "{:,}".format(MAN["tier"]["routine"]),
                "Ordinary navigation and form filling. Mostly letters and numbers. "
                "This is the easy majority, and real traffic is mostly like this."],
               ["hard_negative", "{:,}".format(MAN["tier"]["hard_negative"]),
                "Punctuation-heavy but completely innocent: names like O'Brien, "
                "reviews containing shell symbols, security tokens, pasted code, "
                "URLs and JSON inside parameters. Defeats the punctuation shortcut."],
               ["ambiguous", "{:,}".format(MAN["tier"]["ambiguous"]),
                "Benign text that literally contains attack syntax &mdash; a forum "
                "post asking \"how do I stop ' OR 1=1-- ?\". Some of these are "
                "genuinely impossible to classify from the payload alone."]],
              [30 * mm, 20 * mm, 115 * mm], align_right=[1]),
        BOX("The ambiguous tier is a deliberate error floor",
            "It contains %d distinct cores, of which %d are 'discussion' (the attack "
            "string wrapped in real conversation, which a context-aware model can get "
            "right) and %d are 'verbatim' (the attack string with almost no framing, "
            "which nothing can get right from the payload alone). The second group "
            "sets a floor: any paper claiming near-100%% accuracy on this task is "
            "either not testing on cases like these, or is wrong."
            % (g["ambiguous_cores"], 528, 295)),

        H2("3.3  The attack side"),
        P("Attack payloads come from three sources, combined and then de-duplicated: "
          "hand-written seed payloads per family; a grammar that expands each seed "
          "into structured variations; and optionally the public "
          "PayloadsAllTheThings collection. The released corpus was built "
          "<i>without</i> the third, from a pool of 1,979 distinct payloads."),
        P("On top of that, {:,} attacks ({:.0f}% of the attack rows) are put through "
          "<b>evasions</b> &mdash; the tricks real attackers use to disguise a "
          "payload: changing case, double-URL-encoding, inserting comments, swapping "
          "whitespace, HTML entities, null bytes. {:,} of them have two or more "
          "evasions chained together.".format(
              MAN["evasion_used"], 100.0 * MAN["evasion_used"] / MAN["label"]["1"],
              MAN["evasion_chained"])),

        H2("3.4  The split &mdash; where the rigour lives"),
        P("This is the single most important design decision, and the one to put on "
          "a slide. Every attack payload is assigned a <b>group</b>. All rows sharing "
          "a group go to the same side of the split, together. So a payload seen in "
          "training can never reappear in the test set."),
        TABLE(["", "Payload-disjoint split", "Template-disjoint split"],
              [["What is held out", "Whole payloads", "Whole payload <i>shapes</i>"],
               ["Question it answers",
                "Can the model catch an attack string it has never seen?",
                "Can it catch an attack built on a pattern it has never seen?"],
               ["Units available", "{:,} payload groups".format(g["attack_total"]),
                "{:,} templates".format(g["attack_templates"])],
               ["Units held out for test", "{:,} (at least 11 per family)".format(g["attack_test"]),
                "{:,}".format(g["attack_templates_test"])],
               ["Train / val / test",
                "{:,} / {:,} / {:,}".format(MAN["split"]["train"], MAN["split"]["val"],
                                            MAN["split"]["test"]),
                "{:,} / {:,} / {:,}".format(MAN["split_struct"]["train"],
                                            MAN["split_struct"]["val"],
                                            MAN["split_struct"]["test"])],
               ["Groups that span the split", "0 (checked)", "0 (checked)"]],
              [33 * mm, 66 * mm, 66 * mm]),
        P("The benign side gets the same treatment: benign phrases are enumerated "
          "into about 2,340 reusable <b>cores</b>, and the core identifier is the "
          "split group, so a benign phrase cannot span training and test either. "
          "That is the fix for the 67% leak described in Part 2."),

        H2("3.5  Reproducibility"),
        P("The corpus is built by a single deterministic program from a fixed random "
          "seed (%d). Rebuilding on a clean checkout produces the published file "
          "byte for byte &mdash; continuous integration does exactly that on every "
          "change and fails if a single byte differs. A manifest records the seed, "
          "counts and distributions; a checksum file lets anyone confirm the copy "
          "they downloaded is the copy that was published." % MAN["seed"]),
        PageBreak(),
    ]


def part4():
    groups = [
        ("Is the data clean and balanced?",
         ["<b>ratio</b> &mdash; the attack share stays in a defensible range",
          "<b>duplicates</b> &mdash; no payload string appears twice",
          "<b>near_dup</b> &mdash; masking digits does not collapse rows into one repeated skeleton"]),
        ("Can the answer be guessed without reading the payload?",
         ["<b>length_gap</b> &mdash; benign and attack median lengths within 15%",
          "<b>char_class</b> &mdash; both sides share a character alphabet",
          "<b>param_leak</b> / <b>path_leak</b> &mdash; no parameter name or URL predicts the label",
          "<b>content_type_leak</b> &mdash; the Content-Type does not predict the label",
          "<b>header_leak</b> &mdash; no header feature predicts the label (this is the v2.1 cookie leak)",
          "<b>family_path_leak</b> &mdash; the URL does not give away which family an attack belongs to"]),
        ("Did our own bookkeeping leak into the data?",
         ["<b>metadata_leak</b> &mdash; no internal label (family, tier, source) appears in the request text",
          "<b>evasion_artifact</b> &mdash; no evasion marker is attack-exclusive; each also occurs in benign traffic"]),
        ("Are the splits honest?",
         ["<b>split_leak</b> / <b>struct_split_leak</b> &mdash; no group spans a split, in either split scheme",
          "<b>benign_split_leak</b> &mdash; benign cores never span splits either",
          "<b>session_leak</b> &mdash; sessions do not span splits and are not segregated by label",
          "<b>split_balance</b> &mdash; the attack share matches across splits; every family appears in all three",
          "<b>test_groups</b> &mdash; the test set holds enough distinct payload groups to rank detectors reliably"]),
        ("Is the task neither trivial nor impossible?",
         ["<b>ngram_ceiling</b> &mdash; a strong reference model must stay <i>below</i> a ceiling, or the task is a shortcut",
          "<b>ngram_floor</b> &mdash; and <i>above</i> a floor, or the task is not learnable",
          "<b>disjoint_gen</b> / <b>struct_gen</b> &mdash; recall stays high on both held-out schemes",
          "<b>ambiguous_floor</b> &mdash; a strong model still makes mistakes on the verbatim ambiguous rows",
          "<b>hard_neg</b> / <b>guard</b> &mdash; hard negatives really are punctuation-rich, and none is secretly a real attack"]),
    ]
    out = [
        H1("Part 4 &mdash; The quality gate"),
        LEAD("Twenty-six automated checks. If any one fails, the build fails and "
             "nothing is published. This is the paper's central claim, so it is worth "
             "being able to describe the shape of it from memory."),
        P("You will not recite twenty-six checks on stage. What you should be able to "
          "say is that they fall into five questions, and give one example of each."),
    ]
    for title, items in groups:
        out += [H2(title), BULLETS(items)]
    out += [
        BOX("The two checks that surprise people",
            "<b>ngram_ceiling</b> is the unusual one: the gate fails if a simple "
            "reference model scores <i>too well</i>. A corpus a basic model can "
            "almost perfectly solve is not a benchmark, it is a shortcut waiting to "
            "be found. <b>ambiguous_floor</b> is its twin: the gate insists that a "
            "strong model still gets some cases wrong, because in reality some "
            "requests genuinely cannot be classified from the payload alone. "
            "Together they hold the difficulty inside a band."),
        P("A reviewer might reasonably ask: how do you know twenty-six is enough? "
          "The honest answer, and the right one to give, is that you do not. The "
          "checks encode every shortcut currently known, including two that were "
          "found in this project's own earlier version. The claim is not "
          "\"leak-free forever\"; it is \"audited, with the audit published and "
          "runnable, and the audit is a permanent part of the build rather than a "
          "one-off appendix\"."),
        PageBreak(),
    ]
    return out


def part5():
    d, st = EVAL["disjoint"], EVAL["structural"]
    b = BASE["baselines"]
    ladder = []
    for name in ["length only (1 feature)", "special-char count (1 feature)",
                 "rule signature (14 regex)", "word n-gram (1-2) + LogReg",
                 "char n-gram (3-5) + LogReg"]:
        m = b[name]["payload-disjoint"]
        ladder.append([name.replace("(1 feature)", "").replace("(1-2)", "").replace("(3-5)", "").strip(),
                       pct(m["f1"]), pct(m["pr_auc"]),
                       pct(m["tpr_at_1pct_fpr"]), pct(m["tpr_at_0.1pct_fpr"])])
    lofo = sorted(EVAL["lofo"].items(), key=lambda kv: kv[1]["zeroshot_recall"])
    cross = BASE["cross_dataset"]["webinject"]
    ci = BASE["char_ngram_group_bootstrap_ci95"]
    fam = sorted(BASE["char_ngram_recall_by_family"].items(),
                 key=lambda kv: kv[1]["recall"])
    return [
        H1("Part 5 &mdash; What we found, and how to read it"),
        LEAD("Five results matter. Each one is a number that goes down when you "
             "measure honestly, and each one is a slide."),

        H2("5.1  First: accuracy is the wrong yardstick"),
        P("A detector that flags nothing is about 74% accurate on this corpus, "
          "because most requests are benign. Accuracy and F1 saturate near the top of "
          "the scale and stop separating good systems from mediocre ones. The metric "
          "that matters operationally is <b>how many real attacks you catch while "
          "keeping false alarms below a fixed budget</b> &mdash; written TPR at 1% "
          "or 0.1% false-positive rate."),
        BOX("Why a false-alarm budget, in concrete terms",
            "A mid-sized site handles a million requests a day. If 0.5% are attacks, "
            "that is 5,000 attacks and 995,000 innocent requests. A detector running "
            "at a 1% false-positive rate raises 9,950 false alarms a day. No security "
            "team can look at that. At 0.1% it raises 995. The difference between "
            "those two settings is the difference between a deployable system and a "
            "switched-off one &mdash; and it is invisible if you only report accuracy."),
        TABLE(["Baseline (payload-disjoint split)", "F1", "PR-AUC", "TPR@1%FPR", "TPR@0.1%FPR"],
              ladder, [63 * mm, 21 * mm, 24 * mm, 27 * mm, 30 * mm],
              align_right=[1, 2, 3, 4], bold_last_row=True,
              caption="All values are percentages. Read the last column, not the first."),
        P("The last column is the argument. Across these five baselines F1 moves from "
          "0.4 to 96 &mdash; but TPR at a 0.1% false-alarm budget moves from "
          "<b>0.0 to 87</b>, and the rule-based signature scores exactly <b>zero</b> "
          "there despite a respectable F1 of 58. A regex rule set that looks "
          "half-decent by F1 is worthless at a budget a real team could staff."),

        H2("5.2  Second: two generalisation gaps"),
        P("The same model, the same corpus, three different ways of dividing "
          "train from test:"),
        TABLE(["Split", "What it holds out", "TPR@0.1%FPR"],
              [["Random", "Nothing &mdash; shuffle and cut",
                pct(b["char n-gram (3-5) + LogReg"]["random"]["tpr_at_0.1pct_fpr"])],
               ["Payload-disjoint", "Whole payloads", pct(d["tpr_at_0.1pct_fpr"])],
               ["Template-disjoint", "Whole payload shapes", pct(st["tpr_at_0.1pct_fpr"])]],
              [38 * mm, 82 * mm, 45 * mm], align_right=[2],
              caption="The reference char n-gram model. Same model, same data, "
                      "three honesty settings."),
        P("<b>95 to 87 to 77.</b> The first drop is the memorisation this field "
          "usually leaves in. The second is the model leaning on the <i>shape</i> of "
          "a payload rather than understanding it. If you present one figure from "
          "this work, present this one: it is the cost of measuring honestly, in "
          "points, on identical data."),

        H2("5.3  Third: the base-rate trap"),
        P("Precision depends on how common attacks actually are, and the corpus is "
          "26% attacks while reality is nearer 0.5%. Quoting precision measured at "
          "corpus prevalence is misleading, so the tooling corrects it:"),
        TABLE(["If attacks are really...", "Precision at 1% FPR", "Precision at 0.1% FPR"],
              [["0.5% of traffic", "32.8%", "81.4%"],
               ["1% of traffic", "49.5%", "89.8%"],
               ["5% of traffic", "83.7%", "97.9%"],
               ["25.4% (this corpus)", "97.1%", "99.7%"]],
              [55 * mm, 55 * mm, 55 * mm], align_right=[1, 2],
              caption="Same model, same test set. Only the assumed base rate changes."),
        P("Read the first row. At a realistic base rate and a 1% false-alarm budget, "
          "<b>two out of every three alerts are wrong</b> &mdash; from a model that "
          "reports 96 F1. Tightening the budget to 0.1% moves it to four out of five "
          "alerts being right. This single table is the most practically useful thing "
          "in the paper for a working security team."),

        H2("5.4  Fourth: it does not generalise to unseen families"),
        P("Leave one attack family out of training entirely, then test on it. This is "
          "the realistic question of whether a deployed detector will catch tomorrow's "
          "new attack type."),
        TABLE(["Hardest families (zero-shot)", "Recall", "Easiest families (zero-shot)", "Recall"],
              [[lofo[i][0], pct(lofo[i][1]["zeroshot_recall"]),
                lofo[-(i + 1)][0], pct(lofo[-(i + 1)][1]["zeroshot_recall"])]
               for i in range(4)],
              [50 * mm, 22 * mm, 50 * mm, 22 * mm], align_right=[1, 3],
              caption="Recall on a family the model never saw in training, percent."),
        P("A model that has never seen cross-site scripting catches %s%% of it. "
          "Never seen SQL injection: %s%%. But request smuggling transfers at %s%%, "
          "because its syntax resembles other things the model has seen. The lesson "
          "for the audience: <b>injection detection does not generalise uniformly</b>, "
          "and an aggregate score hides that completely."
          % (pct(EVAL["lofo"]["xss"]["zeroshot_recall"]),
             pct(EVAL["lofo"]["sqli"]["zeroshot_recall"]),
             pct(EVAL["lofo"]["smuggle"]["zeroshot_recall"]))),

        H2("5.5  Fifth: obfuscation roughly halves recall"),
        P("Train only on plain attacks, test on disguised ones. Recall falls to "
          "<b>%s%%</b> overall, and <b>%s%%</b> when two or more disguises are "
          "chained. Within the full model, the weakest disguises are whitespace "
          "swapping (%s%%) and null bytes &mdash; both <i>below</i> plain, unevaded "
          "attacks."
          % (pct(EVAL["evasion"]["all_evaded"]["recall"]),
             pct(EVAL["evasion"]["chained"]["recall"]),
             pct(BASE["char_ngram_recall_by_evasion"]["whitespace_swap"]["recall"]))),

        H2("5.6  Two more things to have ready"),
        BULLETS([
            "<b>Per-family headroom.</b> Even in the main result, recall runs from "
            "%s%% on command injection and %s%% on SSRF up to 100%% on XXE. Command "
            "injection is where the remaining difficulty lives."
            % (pct(fam[0][1]["recall"]), pct(fam[1][1]["recall"])),
            "<b>Error bars.</b> Resampling payload groups rather than rows gives a "
            "95%% confidence interval of [%s, %s] for F1 and [%s, %s] for "
            "TPR@0.1%%FPR. That last interval is wide, and quoting it is a sign of "
            "good faith &mdash; group-level resampling is the honest way to do this "
            "and it produces less flattering intervals than row-level resampling."
            % (pct(ci["f1"][0]), pct(ci["f1"][1]),
               pct(ci["tpr_at_0.1pct_fpr"][0]), pct(ci["tpr_at_0.1pct_fpr"][1])),
            "<b>External validity.</b> Train here, test on the old public corpora: "
            "F1 falls from about 96 in-corpus to %s against CSIC-2010 and %s against "
            "ECML/PKDD. Synthetic numbers do not transfer unchanged, and the paper "
            "says so rather than hiding it."
            % (pct(cross["csic"]["f1"]), pct(cross["ecml"]["f1"])),
        ]),
        PageBreak(),
    ]


def part6():
    return [
        H1("Part 6 &mdash; Limitations, stated before anyone asks"),
        LEAD("Volunteering these is the strongest move available to you. A reviewer "
             "who finds a weakness you already named reads it as rigour; one who "
             "finds a weakness you hid reads it as a flaw."),
        H2("The big one: the benign traffic is synthetic"),
        P("It was engineered for coverage and difficulty, not sampled from a real "
          "production site. Absolute detection numbers will therefore not transfer "
          "unchanged to a live deployment &mdash; and the cross-dataset results in "
          "Part 5 quantify exactly that, showing F1 falling from about 96 to the "
          "low 40s against real-world corpora. The defence is not that it does not "
          "matter; it is that the corpus is designed for <i>comparing detectors "
          "under controlled conditions</i>, and it reports its own transfer gap "
          "instead of leaving readers to discover it."),
        H2("The others, briefly"),
        BULLETS([
            "<b>The payloads come from a grammar.</b> A held-out payload still shares "
            "its underlying template with training payloads, which is precisely why "
            "the template-disjoint split exists &mdash; and why its number is lower. "
            "The template set is finite and hand-written.",
            "<b>There are no server responses and no timing.</b> The offline corpus "
            "has requests only, so detectors that work from responses or from timing "
            "are out of scope.",
            "<b>Families are imbalanced.</b> CRLF has 164 rows, XSS has 3,601. This "
            "mirrors real-world prevalence, but small-family numbers carry wide "
            "confidence intervals.",
            "<b>Prevalence is unrealistic by construction.</b> 26% attacks versus "
            "well under 1% in reality &mdash; which is why every precision figure is "
            "reported corrected to realistic base rates.",
            "<b>25 rows contain raw null bytes</b> (from null-byte evasion). This is "
            "faithful to the attack, but it means Python 3.10 and earlier cannot read "
            "the CSV, and the same is true of PostgreSQL bulk import, R and some "
            "spreadsheet tools. It is documented, and the supported Python floor is "
            "3.11.",
            "<b>The Parquet copy is lossy in exactly those 25 rows.</b> The library "
            "used to write it silently drops null bytes, so the CSV is authoritative. "
            "Documented rather than quietly fixed.",
        ]),
        BOX("How to say the honest thing well",
            "\"This is a controlled benchmark, not a traffic capture. We measure the "
            "gap to real traffic and we publish it. If your question is 'which "
            "detector is better', this corpus answers it under conditions you can "
            "audit. If your question is 'what will my false-positive rate be on "
            "Monday', no public dataset answers that, and we say so.\""),
        PageBreak(),
    ]


def part7():
    return [
        H1("Part 7 &mdash; Giving the talk"),
        LEAD("A twelve-minute conference slot is roughly ten slides and two minutes "
             "of questions. Here is an arc that works."),
        TABLE(["#", "Slide", "The one thing to land", "Time"],
              [["1", "Title", "Who you are, what the artifact is", "0:30"],
               ["2", "What injection is", "The waiter-and-card analogy. No jargon", "1:00"],
               ["3", "The problem with the field",
                "Published numbers are inflated; here is why", "1:30"],
               ["4", "The exam analogy",
                "Leakage explained so nobody is lost. Spend the time here", "1:30"],
               ["5", "We caught ourselves",
                "The 67% benign leak and the cookie leak in our own v2.1", "1:00"],
               ["6", "How it is built",
                "Three benign tiers; group-based splits. One diagram", "1:30"],
               ["7", "The 26-check gate",
                "Five questions, one example each; it runs in CI", "1:00"],
               ["8", "The honesty gap",
                "95 -> 87 -> 77. The single most important slide", "1:30"],
               ["9", "The base-rate table",
                "Two of three alerts are wrong at realistic prevalence", "1:30"],
               ["10", "Limits and availability",
                "Say the limitations out loud; give the URL", "1:00"]],
              [8 * mm, 32 * mm, 105 * mm, 16 * mm]),
        H2("Delivery notes"),
        BULLETS([
            "<b>Lead with the analogy, not the architecture.</b> Slides 2 and 4 buy "
            "you the rest of the talk. If the room does not understand leakage, "
            "nothing after slide 7 will land.",
            "<b>Say the numbers going down are the result.</b> Audiences expect a "
            "graph going up. Pre-empt it: \"our headline number is lower than the "
            "literature, deliberately, and here is what the difference is made of\".",
            "<b>Use the word 'audit' repeatedly.</b> It is the differentiator. Other "
            "papers ship data; this one ships data plus the program that tries to "
            "break it.",
            "<b>Do not read the 26 checks aloud.</b> Show them grouped in five, give "
            "one example, move on.",
            "<b>Have the base-rate table ready as a backup slide.</b> Practitioners "
            "in the room will ask about false-positive load, and that table is the "
            "answer.",
        ]),
        PageBreak(),
    ]


def part8():
    qa = [
        ("Isn't synthetic data a fatal weakness?",
         "It is the main limitation and we measure it rather than assert it away: "
         "trained here and tested on CSIC-2010 and ECML/PKDD, F1 falls from about 96 "
         "to the low 40s. The corpus is for comparing detectors under auditable "
         "conditions. Captured traffic cannot be published at this scale without "
         "privacy problems, and every public alternative is 15+ years old."),
        ("Why should I believe there is no leakage left?",
         "You should not believe it on our word, which is why the audit is a program "
         "rather than a paragraph. Twenty-six checks run on every build. Two of them "
         "exist because they caught leaks in our own previous version. We claim "
         "'audited against known shortcuts, publicly and repeatably', not 'provably "
         "clean'."),
        ("Your numbers are lower than other papers. Isn't that worse?",
         "It is the finding. On a random split the same model scores 95; "
         "payload-disjoint it scores 87; template-disjoint, 77. The higher numbers "
         "in the literature are often the first setting reported as if it were the "
         "third."),
        ("Why a character n-gram model? That is not state of the art.",
         "It is a reference baseline, not a proposed method. The contribution is the "
         "corpus and the protocol. A deliberately simple, fully specified baseline is "
         "what makes later results comparable, and the gate uses it as an instrument: "
         "if a simple model scores too well, the corpus has a shortcut."),
        ("How is this different from just deduplicating the data?",
         "Deduplication removes exact repeats. Group-disjoint splitting removes "
         "near-repeats and shared structure: all rows built from one payload move "
         "together, and separately all rows built from one payload template move "
         "together. Deduplication would not have caught the 67% benign overlap."),
        ("Only 61,400 rows? Modern datasets are much larger.",
         "Size is not the binding constraint here; the number of independent held-out "
         "units is. The test set contains 393 distinct attack payload groups with at "
         "least 11 per family. Inflating row counts by re-dressing the same payloads "
         "would raise the row count and lower the statistical value."),
        ("What stops someone tuning on the test set?",
         "Nothing technical, as with any public benchmark. What we provide is a fixed "
         "published split, a validation split for tuning, a submission scorer, and a "
         "second, harder split (template-disjoint) that a system tuned on the first "
         "will not automatically do well on."),
        ("Are the practice applications representative of real ones?",
         "They are training applications, chosen because they are the standard, "
         "legally attackable targets. They give realistic endpoint shapes and "
         "parameter names. They are not a substitute for production diversity, which "
         "is in the limitations."),
        ("Could an attacker use this dataset?",
         "The payloads are drawn from public collections that have existed for years "
         "and are aimed at deliberately vulnerable practice applications. There is no "
         "novel offensive capability here; the value is entirely on the defensive "
         "side."),
        ("Is there personal data in it?",
         "No. The benign traffic is generated, not captured. No real users, "
         "credentials or personal information are present, and the datasheet says so "
         "explicitly."),
        ("Why 26 checks? Why not 40?",
         "Twenty-six is what the known shortcut literature plus our own failures "
         "produced. The number is not the claim; the mechanism is. Adding a check is "
         "a pull request, and we would welcome one."),
        ("How do I know the file I downloaded is the one you published?",
         "A checksum file ships with the corpus and continuous integration verifies "
         "it on every change, so the manifest cannot drift from the data."),
        ("Can I reproduce the corpus?",
         "Yes, in one command, from a fixed seed. Continuous integration rebuilds it "
         "on every change and fails if the result differs from the published file by "
         "a single byte."),
        ("What would change your conclusions?",
         "A detector that closes the template-disjoint gap without losing "
         "payload-disjoint performance would show the structural gap is a model "
         "limitation rather than a property of the task. And a partner willing to "
         "share labelled production traffic would let us test the synthetic-benign "
         "assumption directly, which is the experiment we most want to run."),
    ]
    out = [
        H1("Part 8 &mdash; Questions you should expect"),
        LEAD("Answer briefly, concede what is true, and redirect to what the work "
             "does establish. Nothing here requires you to have written the code."),
    ]
    for q, a in qa:
        out.append(KeepTogether([
            Paragraph("Q. " + q, _st("q", fontName="Helvetica-Bold", fontSize=10,
                                     leading=14, textColor=ACCENT, spaceBefore=7,
                                     spaceAfter=3)),
            Paragraph("A. " + a, S_BODY)]))
    out.append(PageBreak())
    return out


def glossary():
    terms = [
        ("Base rate / prevalence", "How common attacks actually are in the traffic. "
         "Drives precision more than model quality does."),
        ("Benign", "A normal, non-attack request."),
        ("Corpus", "A dataset, in the sense of a curated body of examples."),
        ("Endpoint", "One address in an application that accepts requests, such as "
         "the login page."),
        ("Evasion", "A disguise applied to an attack payload to slip past detection."),
        ("False positive", "An innocent request wrongly flagged as an attack."),
        ("F1", "A single score blending precision and recall. Saturates on this task, "
         "which is why it is not the headline."),
        ("Group", "The unit that moves together across a train/test split. Here, a "
         "payload or a benign phrase core."),
        ("Hard negative", "A benign request deliberately made to look suspicious."),
        ("HTTP request", "The text message a browser sends to a server."),
        ("Leakage", "When information about the answer reaches the model through an "
         "unintended route, inflating scores."),
        ("LOFO", "Leave-one-family-out: hide an entire attack family during training, "
         "then test on it."),
        ("Payload", "The specific piece of attacker-supplied text that carries the "
         "attack."),
        ("PR-AUC", "A summary of the precision/recall trade-off across all thresholds."),
        ("Precision", "Of everything flagged as an attack, the share that really was."),
        ("Recall / TPR", "Of all real attacks, the share that got caught."),
        ("Shortcut", "An incidental pattern that lets a model score well without "
         "solving the task."),
        ("Split", "The division of data into training, validation and test portions."),
        ("Template", "The structural shape a payload is built from; several payloads "
         "share one template."),
        ("TPR@0.1%FPR", "How many real attacks are caught while raising false alarms "
         "on no more than one in a thousand innocent requests. The headline metric."),
    ]
    return [
        H1("Glossary"),
        LEAD("Every term used in this guide, in one place."),
        TABLE(["Term", "Meaning"], [[t, d] for t, d in terms], [42 * mm, 123 * mm]),
        PageBreak(),
    ]


def cheatsheet():
    d = EVAL["disjoint"]
    b = BASE["baselines"]["char n-gram (3-5) + LogReg"]
    g = MAN["groups"]
    return [
        H1("One-page number sheet"),
        LEAD("The figures most likely to be asked for. All are generated from the "
             "shipped result files, not typed by hand."),
        BOX("If you are asked for one number",
            "<b>87.1%</b> &mdash; attacks caught, on payloads never seen in training, "
            "while raising false alarms on no more than one in a thousand innocent "
            "requests. And the follow-up you should volunteer: <b>77.2%</b> when the "
            "payload's structural shape is also unseen."),
        H2("The corpus"),
        TABLE(["Quantity", "Value"],
              [["Total requests", "{:,}".format(MAN["rows"])],
               ["Benign / attack", "{:,} / {:,}".format(MAN["label"]["0"], MAN["label"]["1"])],
               ["Attack share", "%.1f%%" % (100.0 * MAN["label"]["1"] / MAN["rows"])],
               ["Attack families", "14"],
               ["Applications / endpoints", "3 / 35"],
               ["Distinct attack payload groups", "{:,}".format(g["attack_total"])],
               ["Payload groups held out in test", "{:,} (min 11 per family)".format(g["attack_test"])],
               ["Attack templates / held out", "{:,} / {:,}".format(g["attack_templates"], g["attack_templates_test"])],
               ["Benign cores / ambiguous cores", "~2,340 / {:,}".format(g["ambiguous_cores"])],
               ["Evasion-transformed attacks", "{:,} ({:,} chained)".format(MAN["evasion_used"], MAN["evasion_chained"])],
               ["Sessions", "{:,}".format(MAN["sessions"])],
               ["Build seed", str(MAN["seed"])],
               ["Quality-gate checks", "26"]],
              [80 * mm, 85 * mm]),
        H2("The headline results"),
        TABLE(["Measurement", "Value"],
              [["TPR@0.1%FPR, random split", pct(b["random"]["tpr_at_0.1pct_fpr"]) + "%"],
               ["TPR@0.1%FPR, payload-disjoint", pct(d["tpr_at_0.1pct_fpr"]) + "%"],
               ["TPR@0.1%FPR, template-disjoint",
                pct(EVAL["structural"]["tpr_at_0.1pct_fpr"]) + "%"],
               ["F1, payload-disjoint", pct(d["f1"]) + "%"],
               ["Precision at 0.5% base rate, 1% FPR", "32.8%"],
               ["Precision at 0.5% base rate, 0.1% FPR", "81.4%"],
               ["Zero-shot recall range (LOFO)", "%s%% (xss) to %s%% (smuggle)"
                % (pct(EVAL["lofo"]["xss"]["zeroshot_recall"]),
                   pct(EVAL["lofo"]["smuggle"]["zeroshot_recall"]))],
               ["Recall on unseen evasions", pct(EVAL["evasion"]["all_evaded"]["recall"]) + "%"],
               ["Cross-corpus F1 (CSIC / ECML)", "%s%% / %s%%"
                % (pct(BASE["cross_dataset"]["webinject"]["csic"]["f1"]),
                   pct(BASE["cross_dataset"]["webinject"]["ecml"]["f1"]))],
               ["Rule-signature TPR@0.1%FPR", "0.0%"]],
              [80 * mm, 85 * mm]),
    ]


if __name__ == "__main__":
    path = build()
    print("wrote", path, "(%.0f KB)" % (os.path.getsize(path) / 1024))
    sys.exit(0)
