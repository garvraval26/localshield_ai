"""Show WHY the SMS model scores a message the way it does.

    python -m scripts.explain_sms "your message here"
Prints the words/character patterns that push the score towards scam (+) or
towards normal (-). Weights are the model's own numbers (tf-idf value x coefficient)."""
import sys

from detector.sms_detector import SmsDetector


def main():
    if len(sys.argv) < 2:
        raise SystemExit('Usage: python -m scripts.explain_sms "message text"')
    text = sys.argv[1]
    det = SmsDetector()
    r = det.analyze(text)
    union, clf = det.model.steps[0][1], det.model.steps[-1][1]
    names = union.get_feature_names_out()
    row = union.transform([text])
    contrib = row.multiply(clf.coef_[0]).toarray()[0]
    order = contrib.argsort()
    clean = lambda n: n.split("__", 1)[-1]
    print(f"score {r['score']:.2f}  level {r['risk_level']}  "
          f"(suspicious_at={det.meta['suspicious_at']})")
    print("\nPushing towards SCAM:")
    for i in order[::-1][:10]:
        if contrib[i] > 0:
            print(f"  +{contrib[i]:.3f}  {clean(names[i])!r}")
    print("\nPushing towards NORMAL:")
    for i in order[:6]:
        if contrib[i] < 0:
            print(f"  {contrib[i]:.3f}  {clean(names[i])!r}")


if __name__ == "__main__":
    main()