import pytest

from detector import analyze_url, build_model, evaluate, levenshtein, extract_urls


@pytest.fixture(scope="module")
def model():
    return build_model()[0]


def test_levenshtein():
    assert levenshtein("amazon", "amazon") == 0
    assert levenshtein("amaz0n", "amazon") == 1
    assert levenshtein("abc", "") == 3


def test_extract_urls():
    assert extract_urls("go to http://a.com/x, now") == ["http://a.com/x"]


@pytest.mark.parametrize("url", [
    "http://192.168.1.5/login",
    "http://bit.ly/abc",
    "http://amaz0n-prize.xyz",
    "http://paypa1.com/signin",
    "https://xn--pypal-4ve.com",
    "http://user@evil.example.top",
])
def test_bad_urls_flagged(url):
    assert analyze_url(url)["verdict"] != "SAFE"


@pytest.mark.parametrize("url", ["https://github.com/login", "https://www.amazon.in/", "https://www.google.com"])
def test_good_urls_safe(url):
    assert analyze_url(url)["verdict"] == "SAFE"


def test_scam_message(model):
    r = model.analyze("URGENT: Your SBI account is blocked. Verify KYC immediately at http://sbi-kyc-update.xyz")
    assert r["verdict"] == "PHISHING / SCAM"
    assert r["url_analysis"] and r["advice"]


def test_hinglish_scam(model):
    r = model.analyze("Turant apna KYC update karo warna khata band ho jayega http://bit.ly/kyc-now")
    assert r["verdict"] != "SAFE"


def test_safe_message(model):
    r = model.analyze("Hey, are we still meeting for lunch tomorrow at 1 pm?")
    assert r["verdict"] == "SAFE"
    assert r["top_terms"] == []


def test_evaluate_metrics_in_range():
    texts, labels = build_model()[1:]
    m = evaluate(texts, labels)
    assert 0 <= m["accuracy"] <= 100 and m["cv_accuracy"] > 70


def test_ioc_extraction(model):
    from detector import extract_iocs
    i = extract_iocs("mail help@sbi-kyc-help.xyz, pay ravi@ybl, call +91 9876543210, ip 45.33.32.156")
    assert i["emails"][0]["value"] == "help@sbi-kyc-help.xyz" and i["emails"][0]["flags"]
    assert i["upi_ids"] == ["ravi@ybl"] and i["ips"] == ["45.33.32.156"] and i["phones"]


def test_free_mail_brand_impersonation():
    from detector import email_flags
    assert email_flags("paypal.support@gmail.com")
    assert not email_flags("friend@gmail.com")
