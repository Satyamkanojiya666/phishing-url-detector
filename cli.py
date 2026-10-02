"""
PHISH//HUNTER - command-line version.   Author: Satyam Kanojiya (MIT License)

Examples:
    python cli.py                              # interactive mode
    python cli.py "Your account is blocked, verify at http://bit.ly/abc"
    python cli.py --url http://paypa1-login.xyz
    python cli.py --file messages.txt          # one message per line
    python cli.py --file messages.txt --json   # machine-readable output
    python cli.py --eval                       # show model metrics
"""
import argparse
import json
import sys

from detector import analyze_url, build_model, evaluate


def show(result, text):
    bar = "#" * int(result["risk"] / 100 * 30)
    print("\n" + "-" * 60)
    print(f"Message : {text[:110]}{'...' if len(text) > 110 else ''}")
    print(f"Verdict : {result['verdict']}")
    print(f"Risk    : {result['risk']}%  [{bar:<30}]")
    print(f"          (AI model {result['ml']}% | rule engine {result['rule']}%)")
    if result["reasons"]:
        print("Why flagged:")
        for r in result["reasons"]:
            print(f"  - {r}")
    else:
        print("No red flags found.")
    if result["top_terms"]:
        print("AI suspicious words: " + ", ".join(t["term"] for t in result["top_terms"]))
    print(f"Advice  : {result['advice']}")
    print("-" * 60)


def show_url(r):
    print(f"\nURL     : {r['url']}\nVerdict : {r['verdict']} ({r['risk']}%)")
    for f in r["flags"] or ["No suspicious traits found."]:
        print(f"  - {f}")
    print(f"Advice  : {r['advice']}")


def show_eval(texts, labels):
    m = evaluate(texts, labels)
    print("=" * 60 + "\n MODEL EVALUATION\n" + "=" * 60)
    print(f"Hold-out accuracy : {m['accuracy']}%   (train {m['train_size']} / test {m['test_size']})")
    print(f"5-fold CV accuracy: {m['cv_accuracy']}%")
    print(f"Precision {m['precision']}% | Recall {m['recall']}% | F1 {m['f1']}%")
    print(f"Confusion matrix [[TN, FP], [FN, TP]]: {m['confusion_matrix']}")


BANNER = """
+----------------------------------------------+
|   PHISH//HUNTER  -  AI Phishing Detector     |
|   created by Satyam Kanojiya                 |
+----------------------------------------------+
"""


def main():
    ap = argparse.ArgumentParser(description="AI phishing & scam detector (CLI)")
    ap.add_argument("message", nargs="*", help="message text to analyze")
    ap.add_argument("--url", help="scan a single URL")
    ap.add_argument("--file", help="text file with one message per line")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--eval", action="store_true", help="print model evaluation and exit")
    args = ap.parse_args()

    if args.url:
        r = analyze_url(args.url)
        print(json.dumps(r, indent=2) if args.json else "", end="")
        if not args.json:
            show_url(r)
        return

    model, texts, labels = build_model()

    if args.eval:
        show_eval(texts, labels)
        return

    if args.file:
        with open(args.file, encoding="utf-8") as f:
            msgs = [ln.strip() for ln in f if ln.strip()]
        results = [dict(model.analyze(m), text=m) for m in msgs]
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                show(r, r["text"])
        return

    if args.message:
        msg = " ".join(args.message)
        r = model.analyze(msg)
        print(json.dumps(r, indent=2) if args.json else "", end="")
        if not args.json:
            show(r, msg)
        return

    print(BANNER)
    print("Interactive mode. Type a message ('quit' to exit).")
    while True:
        try:
            msg = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if msg.lower() in {"quit", "exit", "q"}:
            break
        if msg:
            show(model.analyze(msg), msg)


if __name__ == "__main__":
    sys.exit(main())
