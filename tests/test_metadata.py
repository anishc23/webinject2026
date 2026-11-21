"""The deposit metadata files must agree with each other.

Zenodo reads `.zenodo.json` in preference to `CITATION.cff` and uses it
wholesale rather than merging the two, so a field corrected in one file and
forgotten in the other ships a wrong archive record on the next release --
silently, because neither file is validated by anything else. These tests make
that drift a red build instead.
"""

import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZENODO = os.path.join(ROOT, ".zenodo.json")
CFF = os.path.join(ROOT, "CITATION.cff")


def _zenodo():
    with open(ZENODO, encoding="utf-8") as fh:
        return json.load(fh)


def _cff_text():
    with open(CFF, encoding="utf-8") as fh:
        return fh.read()


def _cff_authors(text):
    """Surname, forenames for each author, in file order.

    Parsed with a regex rather than a YAML dependency: the block is flat and
    the test is about drift between two files, not about YAML conformance.
    """
    block = text.split("authors:", 1)[1].split("preferred-citation:", 1)[0]
    given = re.findall(r"^\s+-?\s*given-names:\s*(.+?)\s*$", block, re.M)
    family = re.findall(r"^\s+family-names:\s*(.+?)\s*$", block, re.M)
    assert len(given) == len(family), "every CITATION.cff author needs both names"
    return ["%s, %s" % (f, g) for g, f in zip(given, family)]


def test_zenodo_json_is_valid_and_complete():
    z = _zenodo()
    for field in ("upload_type", "title", "version", "creators",
                  "description", "license", "access_right"):
        assert field in z, "missing %s" % field
    assert z["upload_type"] == "dataset", (
        "Zenodo's GitHub webhook defaults new records to 'software'; this file "
        "exists to pin them to 'dataset'")
    assert z["access_right"] == "open"


def test_authors_match_between_deposit_files():
    z_names = [c["name"] for c in _zenodo()["creators"]]
    assert z_names == _cff_authors(_cff_text()), (
        ".zenodo.json creators and CITATION.cff authors disagree")


def test_every_creator_carries_an_affiliation():
    for c in _zenodo()["creators"]:
        assert c.get("affiliation"), "no affiliation for %s" % c["name"]


def test_title_and_version_match_between_deposit_files():
    z, cff = _zenodo(), _cff_text()
    for key in ("title", "version"):
        want = re.search(r'^%s:\s*"?(.+?)"?\s*$' % key, cff, re.M).group(1)
        assert str(z[key]) == want, "%s differs: %r vs %r" % (key, z[key], want)


def test_licence_matches_between_deposit_files():
    cff = re.search(r"^license:\s*(\S+)\s*$", _cff_text(), re.M).group(1)
    assert _zenodo()["license"].lower() == cff.lower().replace("_", "-"), (
        "licence differs between .zenodo.json and CITATION.cff")


def _orcid_check_digit_is_valid(orcid):
    """ISO 7064 Mod 11-2, the checksum built into every ORCID iD.

    A transposed or mistyped digit fails this, which a `len() == 19` check
    would not. It cannot tell us the iD belongs to the right person, only
    that it is a real iD.
    """
    digits = orcid.replace("-", "")
    if len(digits) != 16:
        return False
    total = 0
    for char in digits[:15]:
        if not char.isdigit():
            return False
        total = (total + int(char)) * 2
    remainder = (12 - total % 11) % 11
    return ("X" if remainder == 10 else str(remainder)) == digits[15]


def test_orcids_land_in_both_files_or_neither():
    """Either every author has an iD in both deposit files, or none does."""
    z_has = any("orcid" in c for c in _zenodo()["creators"])
    cff_has = bool(re.search(r"^\s+orcid:\s*\S", _cff_text(), re.M))
    assert z_has == cff_has, (
        "ORCIDs were added to one deposit file but not the other")


def test_orcids_match_between_deposit_files():
    """The iDs agree author-for-author, in order.

    .zenodo.json stores the bare identifier and CITATION.cff the resolving
    URL, so the comparison is on the identifier itself.
    """
    z_ids = [c.get("orcid") for c in _zenodo()["creators"]]
    block = _cff_text().split("authors:", 1)[1].split("preferred-citation:", 1)[0]
    cff_ids = re.findall(r'^\s+orcid:\s*"?(?:https?://orcid\.org/)?([0-9X-]+)"?\s*$',
                         block, re.M)
    assert z_ids == cff_ids, (
        "ORCID iDs differ between .zenodo.json and CITATION.cff: %r vs %r"
        % (z_ids, cff_ids))


def test_every_orcid_is_well_formed():
    """Each iD is 16 digits in 4 groups and passes its own check digit."""
    for creator in _zenodo()["creators"]:
        orcid = creator.get("orcid")
        if orcid is None:
            continue
        assert re.fullmatch(r"\d{4}-\d{4}-\d{4}-\d{3}[\dX]", orcid), (
            "malformed ORCID for %s: %r" % (creator["name"], orcid))
        assert _orcid_check_digit_is_valid(orcid), (
            "ORCID check digit fails for %s: %r -- likely a mistyped or "
            "transposed digit" % (creator["name"], orcid))


def test_the_papers_citation_entry_carries_the_orcids_too():
    """preferred-citation authors are exported separately, so they need them."""
    tail = _cff_text().split("preferred-citation:", 1)[1]
    n_authors = len(re.findall(r"^\s+-\s*given-names:", tail, re.M))
    n_orcids = len(re.findall(r"^\s+orcid:\s*\S", tail, re.M))
    assert n_authors == n_orcids, (
        "preferred-citation has %d authors but %d ORCIDs" % (n_authors, n_orcids))
