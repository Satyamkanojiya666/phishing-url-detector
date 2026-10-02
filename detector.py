"""
Author : Satyam Kanojiya
License: MIT

Core detection engine - ML (TF-IDF + Logistic Regression) + rule-based risk
+ advanced URL analysis (typosquatting, punycode, IP hosts, shorteners ...).
Imported by app.py (web UI) and cli.py (command line).
"""
__author__ = "Satyam Kanojiya"

import csv
import math
import os
import re

import numpy as np
from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold, train_test_split

DATA = [
    ("URGENT: Your bank account has been suspended. Verify now at http://secure-bank-login.xyz/verify", 1),
    ("Dear customer, your KYC is expired. Update immediately or account will be blocked: http://bit.ly/kyc-upd8", 1),
    ("Congratulations! You have won a $1000 Amazon gift card. Click here to claim: http://amazon-prize.top/claim", 1),
    ("Your PayPal account is limited. Confirm your password here http://paypal.security-check.ru", 1),
    ("You won the lottery of 5,000,000 USD. Send your bank details and processing fee to receive funds", 1),
    ("Alert: unusual sign-in detected. Verify your identity within 24 hours or your account will be deleted http://192.168.44.12/login", 1),
    ("Your package could not be delivered. Pay a small fee of $1.99 to reschedule: http://tinyurl.com/delivery-fee", 1),
    ("Dear user, your SBI account is blocked. Click http://sbi-update-kyc.online to unblock immediately", 1),
    ("Final notice: IRS refund pending. Provide your SSN and card number to claim your tax refund now", 1),
    ("Hi, I am a prince and need your help to transfer funds. You will get 30% commission. Reply with account number", 1),
    ("Your OTP is 482913. Share this code with our agent to complete your refund", 1),
    ("Earn $500 daily working from home! No experience needed. Pay registration fee and start today", 1),
    ("Netflix: payment declined. Update your billing information now http://netflix-billing.click/update", 1),
    ("Security warning: your Apple ID has been locked. Login to restore access http://appleid-verify.info", 1),
    ("Congratulations, you are selected for a free iPhone 15. Just pay shipping charges. Limited offer, hurry!", 1),
    ("Your electricity will be disconnected tonight at 9:30 PM. Call this number immediately and pay the pending bill", 1),
    ("Dear Sir/Madam, your ATM card is deactivated. Enter your PIN and CVV to reactivate: http://atm-safe.cf", 1),
    ("Investment opportunity! Double your Bitcoin in 24 hours guaranteed. Send crypto to this wallet now", 1),
    ("HR notice: Your salary revision letter is attached. Login with your email password to view http://office365-docs.gq", 1),
    ("Act now! Your account will be terminated. Click the link to confirm your details http://goo.gl/xR2p9", 1),
    ("Your Amazon order of $899 was placed. If not you, call our refund helpline and share the OTP to cancel", 1),
    ("You have received a wire transfer. Confirm your username and password to accept the payment", 1),
    ("Government grant approved for you. Pay $50 processing fee via gift card to release your grant money", 1),
    ("Instagram: copyright violation on your account. Verify now or your page will be disabled http://insta-appeal.work", 1),
    ("Dear customer your SIM will be blocked in 2 hours. Complete KYC now by clicking this link", 1),
    ("Get a loan approved in 5 minutes without documents! Pay insurance fee first to receive amount", 1),
    ("WhatsApp Gold is here. Download the exclusive version now http://whatsapp-gold.download", 1),
    ("Unpaid toll notice: pay $6.40 immediately to avoid a late fee and legal action http://toll-pay.vip", 1),
    ("Your Microsoft account has suspicious activity. Call support at once and allow remote access to fix", 1),
    ("Claim your free gift! You are our lucky winner. Reply with your credit card details to receive prize", 1),
    ("Hey, are we still meeting for lunch tomorrow at 1 pm?", 0),
    ("Your Amazon order #114-2938 has shipped and will arrive on Thursday. Track it in the Amazon app.", 0),
    ("Reminder: your dentist appointment is on Monday at 10:30 AM. Reply C to confirm.", 0),
    ("Meeting moved to 3 PM in conference room B. Please bring the quarterly report.", 0),
    ("Thanks for your payment of $45.00 to Spotify. Your receipt is available in your account.", 0),
    ("Mom: Don't forget to pick up milk and bread on your way home.", 0),
    ("Your OTP for login is 738201. It is valid for 10 minutes. Do not share it with anyone.", 0),
    ("Happy birthday! Wishing you a wonderful year ahead. Let's catch up this weekend.", 0),
    ("Your monthly bank statement is ready. Log in through the official app to view it.", 0),
    ("Can you review my pull request when you get a chance? Thanks!", 0),
    ("The project deadline has been extended to Friday. Let me know if you need help.", 0),
    ("Your cab is arriving in 3 minutes. Driver: Ravi, vehicle KA-01-4432.", 0),
    ("Class notes for today's lecture are uploaded on the college portal.", 0),
    ("Your flight AI-202 departs at 18:45 from Terminal 2. Web check-in is now open.", 0),
    ("Dinner at 8 tonight? I booked a table at that Italian place you like.", 0),
    ("Your prescription is ready for pickup at the pharmacy counter.", 0),
    ("Team standup is at 10 AM. Agenda: sprint progress and blockers.", 0),
    ("Thank you for shopping with us. Your invoice is attached to this email.", 0),
    ("Your electricity bill of Rs. 1,240 is due on the 15th. Pay via the official website or app.", 0),
    ("Good luck for your exam tomorrow! You've got this.", 0),
    ("We received your job application and will get back to you within two weeks.", 0),
    ("Your library book is due in 2 days. Renew it online at the college library website.", 0),
    ("Hi, this is Priya from the admissions office. Your documents have been verified.", 0),
    ("Package delivered to your front door at 2:14 PM. Have a great day!", 0),
    ("Netflix: new episodes of your favourite show are now streaming.", 0),
    ("Please find attached the minutes of yesterday's meeting.", 0),
    ("Your password was changed successfully. If this wasn't you, contact support through our official app.", 0),
    ("Bro, send me the notes from the networking class when you're free.", 0),
    ("Reminder: parent-teacher meeting this Saturday at 11 AM.", 0),
    ("Your subscription renews on the 1st. Manage it anytime from account settings.", 0),
    # Hinglish (Hindi written in English letters) examples
    ("Aapka bank khata band ho jayega. Turant KYC update karo is link par http://kyc-update-sbi.top", 1),
    ("Badhai ho! Aapne 10 lakh ka inaam jeeta hai. Claim karne ke liye processing fee bhejo abhi", 1),
    ("Aapka OTP kisi ko mat batana. Ye sirf login ke liye hai.", 0),
    ("Kal shaam ko milte hain, mall ke bahar 6 baje.", 0),
    ("Bhai notes bhej dena jab free ho, kal exam hai.", 0),
    ("Aapka order kal tak deliver ho jayega. App me track kar sakte hain.", 0),
]

# Optional: drop your own labeled data in data/custom_dataset.csv (columns: text,label)
# label = 1 for phishing/scam, 0 for safe. It is merged automatically at start-up.
CUSTOM_DATASET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "custom_dataset.csv")

URGENCY = ["urgent", "immediately", "now", "hurry", "act now", "final notice", "within 24 hours",
           "expires", "limited", "asap", "last chance", "tonight", "in 2 hours", "at once",
           "turant", "jaldi", "abhi"]
SENSITIVE = ["password", "otp", "pin", "cvv", "ssn", "card number", "bank details", "account number",
             "credentials", "login", "verify your identity", "kyc"]
MONEY_BAIT = ["won", "winner", "lottery", "prize", "gift card", "free", "congratulations",
              "refund", "grant", "commission", "processing fee", "registration fee", "bitcoin",
              "crypto", "double your", "earn $", "inaam", "badhai ho"]
THREATS = ["suspended", "blocked", "locked", "terminated", "deleted", "disabled",
           "disconnected", "deactivated", "legal action", "limited", "band ho jayega",
           "block ho jayega", "khata band"]
SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "cutt.ly", "rb.gy"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".gq", ".cf", ".tk", ".ml", ".ga", ".online",
                   ".work", ".vip", ".info", ".download", ".ru", ".link"]
BRANDS = ["paypal", "amazon", "apple", "netflix", "microsoft", "google", "sbi", "hdfc",
          "icici", "instagram", "facebook", "whatsapp", "office365", "bank"]
# brands used for typosquatting checks ("bank" is too generic)
TYPO_BRANDS = [b for b in BRANDS if b != "bank"]
URL_KEYWORDS = ["login", "signin", "verify", "update", "secure", "account", "confirm", "banking", "wallet"]

URL_RE = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.I)
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

ADVICE = {
    "high": "Do NOT click any link, reply, or share OTP/PIN/passwords. Delete the message and, if it "
            "claims to be from your bank or a service, contact them using the official app or website.",
    "medium": "Be careful. Don't click links or share personal details until you verify the sender "
              "through an official channel.",
    "low": "No strong red flags found. Stay alert anyway: never share OTP/PIN/passwords with anyone.",
}


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def extract_urls(text):
    return [u.rstrip(".,);") for u in URL_RE.findall(text)]


def find_hits(text, words):
    t = text.lower()
    return [w for w in words if re.search(r"(?<![a-z])" + re.escape(w) + r"(?![a-z])", t)]


def count_hits(text, words):
    return len(find_hits(text, words))


def levenshtein(a, b):
    """Edit distance between two short strings."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def shannon_entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def main_label(host):
    """Registered-domain label, e.g. 'secure.amaz0n-prize.xyz' -> 'amaz0n-prize'."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "gov", "ac", "net"}:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


def is_legit_brand_domain(host):
    return bool(re.search(rf"(^|\.)({'|'.join(TYPO_BRANDS + ['bank'])})\.(com|in|co\.in|org)$", host))


# ----------------------------------------------------------------------------
# URL analysis
# ----------------------------------------------------------------------------
def _url_findings(url):
    """Return [(message, weight), ...] for one URL."""
    out = []
    u = url if url.lower().startswith("http") else "http://" + url
    try:
        p = urlparse(u)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return [("Malformed URL", 0.3)]
    low = u.lower()

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        out.append((f"URL uses a raw IP address ({host})", 0.45))
    if any(s == host or host.endswith("." + s) for s in SHORTENERS):
        out.append((f"Shortened link hides the real destination ({host})", 0.30))
    if any(host.endswith(t) for t in SUSPICIOUS_TLDS):
        out.append((f"Suspicious domain ending in '{host}'", 0.30))
    if host.count("-") >= 2 or host.count(".") >= 3:
        out.append((f"Odd domain structure ({host})", 0.15))
    if any(b in host for b in BRANDS) and not is_legit_brand_domain(host):
        out.append((f"Brand name used in a look-alike domain ({host})", 0.40))

    # typosquatting: amaz0n.com, paypa1.com, micros0ft.com ...
    label = main_label(host)
    for token in {label, *label.split("-")}:
        norm = token.translate(LEET)
        for brand in TYPO_BRANDS:
            if token != brand and len(brand) >= 4 and levenshtein(norm, brand) <= 1 and abs(len(token) - len(brand)) <= 1:
                out.append((f"Possible typosquatting: '{token}' imitates '{brand}'", 0.45))
                break
        else:
            continue
        break

    if "@" in p.netloc:
        out.append(("URL contains '@' (real destination is hidden after it)", 0.40))
    if "xn--" in host:
        out.append(("Punycode / look-alike (homograph) domain", 0.40))
    if len(url) > 100:
        out.append((f"Unusually long URL ({len(url)} characters)", 0.10))
    if len(re.findall(r"%[0-9a-f]{2}", low)) >= 3:
        out.append(("URL is heavily percent-encoded (obfuscation)", 0.15))
    if port not in (None, 80, 443):
        out.append((f"Unusual port number ({port})", 0.20))
    kws = [k for k in URL_KEYWORDS if k in low]
    if len(kws) >= 2 and not is_legit_brand_domain(host):
        out.append((f"Phishing-style keywords in URL [{', '.join(kws[:3])}]", 0.20))
    if len(label) >= 14 and shannon_entropy(label) > 3.6:
        out.append(("Random-looking domain name", 0.20))
    if low.startswith("http://"):
        out.append(("Link is not HTTPS", 0.15))
    return out


def url_flags(url):
    return [m for m, _ in _url_findings(url)]


def analyze_url(url):
    """Standalone URL risk report."""
    findings = _url_findings(url.strip())
    risk = min(sum(w for _, w in findings), 1.0)
    if risk >= 0.60:
        verdict, level = "PHISHING / SCAM", "high"
    elif risk >= 0.30:
        verdict, level = "SUSPICIOUS", "medium"
    else:
        verdict, level = "SAFE", "low"
    return {
        "url": url.strip(),
        "verdict": verdict,
        "level": level,
        "risk": round(risk * 100, 1),
        "flags": [m for m, _ in findings],
        "advice": ADVICE[level],
    }


# ----------------------------------------------------------------------------
# IOC (indicator of compromise) extraction + sender e-mail analysis
# ----------------------------------------------------------------------------
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
UPI_RE = re.compile(r"\b[\w.-]{2,}@(?:ok(?:sbi|hdfcbank|icici|axis)|ybl|paytm|upi|apl|ibl|axl|sbi)(?![\w-]|\.\w)", re.I)
PHONE_RE = re.compile(r"(?<![\w.@])(?:\+\d{1,3}[\s-]?\d{6,12}|(?:\+91[\s-]?)?[6-9]\d{9})(?!\d)")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CRYPTO_RE = re.compile(r"\b(?:0x[a-fA-F0-9]{40}|(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39})\b")
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "protonmail.com", "rediffmail.com"}


def email_flags(addr):
    local, _, domain = addr.lower().partition("@")
    flags = [m for m, _ in _url_findings("https://" + domain) if m != "Link is not HTTPS"]
    if domain in FREE_MAIL and any(b in local for b in BRANDS):
        flags.append(f"Brand impersonation from a free e-mail provider ({addr})")
    return flags


def extract_iocs(text):
    """Pull out every indicator an analyst would want to block or report."""
    def uniq(items):
        return list(dict.fromkeys(items))
    upis = uniq(UPI_RE.findall(text))
    emails = [e for e in uniq(EMAIL_RE.findall(text)) if e not in upis]
    return {
        "emails": [{"value": e, "flags": email_flags(e)} for e in emails],
        "upi_ids": upis,
        "phones": uniq(m.strip() for m in PHONE_RE.findall(text)),
        "ips": uniq(ip for ip in IP_RE.findall(text) if all(int(p) <= 255 for p in ip.split("."))),
        "crypto_wallets": uniq(CRYPTO_RE.findall(text)),
    }


# ----------------------------------------------------------------------------
# ML features
# ----------------------------------------------------------------------------
def handcrafted(text):
    urls = extract_urls(text)
    n_url_flags = sum(len(url_flags(u)) for u in urls)
    letters = [c for c in text if c.isalpha()]
    caps_ratio = sum(c.isupper() for c in letters) / max(len(letters), 1)
    return [
        len(urls),
        n_url_flags,
        count_hits(text, URGENCY),
        count_hits(text, SENSITIVE),
        count_hits(text, MONEY_BAIT),
        count_hits(text, THREATS),
        caps_ratio,
        text.count("!"),
        len(re.findall(r"[$€£₹]|\brs\.?\b|\busd\b", text.lower())),
        int(bool(re.search(r"\b\d{4,8}\b", text)) and "otp" in text.lower()),
    ]


def clean(text):
    text = URL_RE.sub(" URLTOKEN ", text.lower())
    text = re.sub(r"\d+", " NUM ", text)
    return re.sub(r"\s+", " ", text).strip()


class PhishingDetector:
    def __init__(self):
        self.word_vec = TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)
        self.char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)
        self.clf = LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")
        self.scale = None

    def _features(self, texts, fit=False):
        cleaned = [clean(t) for t in texts]
        hand = np.array([handcrafted(t) for t in texts], dtype=float)
        if fit:
            self.scale = np.maximum(hand.max(axis=0), 1.0)
            w = self.word_vec.fit_transform(cleaned)
            c = self.char_vec.fit_transform(cleaned)
        else:
            w = self.word_vec.transform(cleaned)
            c = self.char_vec.transform(cleaned)
        return hstack([w, c, csr_matrix(hand / self.scale)]).tocsr()

    def fit(self, texts, labels):
        self.clf.fit(self._features(texts, fit=True), labels)
        return self

    def ml_prob(self, texts):
        return self.clf.predict_proba(self._features(texts))[:, 1]

    def top_terms(self, text, k=5):
        """Words/phrases that pushed the ML model towards 'scam' (explainable AI)."""
        names = self.word_vec.get_feature_names_out()
        coef = self.clf.coef_[0][: len(names)]
        row = self.word_vec.transform([clean(text)]).tocoo()
        contrib = []
        for j, v in zip(row.col, row.data):
            term = names[j]
            if "urltoken" in term or "num" in term.split():
                continue
            contrib.append((term, float(v * coef[j])))
        contrib.sort(key=lambda x: -x[1])
        return [{"term": t, "weight": round(w, 3)} for t, w in contrib[:k] if w > 0]

    @staticmethod
    def rule_analysis(text):
        reasons, score = [], 0.0
        for u in extract_urls(text):
            for f in url_flags(u):
                reasons.append(f)
                score += 0.18
        for e in extract_iocs(text)["emails"]:
            for f in e["flags"]:
                reasons.append("Sender e-mail: " + f)
                score += 0.18
        checks = [
            (URGENCY, "Creates false urgency / pressure", 0.15),
            (SENSITIVE, "Asks for sensitive info (password/OTP/PIN/KYC/etc.)", 0.25),
            (MONEY_BAIT, "Offers money/prizes or asks for upfront fees", 0.20),
            (THREATS, "Threatens account suspension / blocking / legal action", 0.18),
        ]
        for words, msg, wgt in checks:
            hits = find_hits(text, words)
            if hits:
                reasons.append(f"{msg}  [{', '.join(hits[:3])}]")
                score += wgt
        low = text.lower()
        if "otp" in low and re.search(r"share|send|tell|give|provide", low) \
                and not re.search(r"do not share|don't share|never share|mat batana", low):
            reasons.append("Asks you to share an OTP (legit services never do)")
            score += 0.25
        letters = [c for c in text if c.isalpha()]
        if letters and sum(c.isupper() for c in letters) / len(letters) > 0.35 and len(letters) > 20:
            reasons.append("Excessive CAPITAL LETTERS")
            score += 0.08
        return min(score, 1.0), reasons

    def analyze(self, text):
        p_ml = float(self.ml_prob([text])[0])
        p_rule, reasons = self.rule_analysis(text)
        risk = 0.7 * p_ml + 0.3 * p_rule
        if risk >= 0.65:
            verdict, level = "PHISHING / SCAM", "high"
        elif risk >= 0.40:
            verdict, level = "SUSPICIOUS", "medium"
        else:
            verdict, level = "SAFE", "low"
        urls = extract_urls(text)
        return {
            "verdict": verdict,
            "level": level,
            "risk": round(risk * 100, 1),
            "ml": round(p_ml * 100, 1),
            "rule": round(p_rule * 100, 1),
            "reasons": reasons,
            "urls_found": urls,
            "url_analysis": [analyze_url(u) for u in urls],
            "iocs": extract_iocs(text),
            "top_terms": self.top_terms(text) if level != "low" else [],
            "advice": ADVICE[level],
        }


# ----------------------------------------------------------------------------
# dataset / model / evaluation
# ----------------------------------------------------------------------------
def load_dataset(custom_path=CUSTOM_DATASET):
    """Built-in samples + optional data/custom_dataset.csv (text,label)."""
    rows = list(DATA)
    if custom_path and os.path.exists(custom_path):
        with open(custom_path, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                text, label = (r.get("text") or "").strip(), (r.get("label") or "").strip()
                if text and label in {"0", "1"}:
                    rows.append((text, int(label)))
    return [t for t, _ in rows], [l for _, l in rows]


def build_model():
    texts, labels = load_dataset()
    return PhishingDetector().fit(texts, labels), texts, labels


def evaluate(texts, labels, seed=42):
    """Hold-out metrics + 5-fold cross-validated accuracy for the ML component."""
    Xtr, Xte, ytr, yte = train_test_split(texts, labels, test_size=0.25, random_state=seed, stratify=labels)
    model = PhishingDetector().fit(Xtr, ytr)
    pred = (model.ml_prob(Xte) >= 0.5).astype(int)
    prec, rec, f1, _ = precision_recall_fscore_support(yte, pred, average="binary", zero_division=0)

    arr, y = np.array(texts, dtype=object), np.array(labels)
    cv = []
    for tr, te in StratifiedKFold(5, shuffle=True, random_state=seed).split(arr, y):
        m = PhishingDetector().fit(list(arr[tr]), list(y[tr]))
        cv.append(accuracy_score(y[te], (m.ml_prob(list(arr[te])) >= 0.5).astype(int)))
    return {
        "accuracy": round(accuracy_score(yte, pred) * 100, 1),
        "precision": round(prec * 100, 1),
        "recall": round(rec * 100, 1),
        "f1": round(f1 * 100, 1),
        "cv_accuracy": round(float(np.mean(cv)) * 100, 1),
        "confusion_matrix": confusion_matrix(yte, pred).tolist(),
        "train_size": len(Xtr),
        "test_size": len(Xte),
    }
