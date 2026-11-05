"""Measure the look-alike rules with real numbers.

    python -m scripts.check_lookalike

(a) FALSE ALARMS: real popular sites ranked just beyond the 'known real' list
    (rank 100,001 and up in Tranco). Any flagged one is a false alarm.
(b) CATCH RATE: fake names generated from the top brands (typos, doubled letters,
    swapped letters, garbled endings). Fake names that happen to be real known
    domains are skipped.
Needs data/raw/tranco.csv and models/brands.json (python -m scripts.build_brands)."""
import random

from detector.lookalike import _KNOWN, _TOP, data_status, find_lookalike
from detector.url_features import registered_domain
from scripts import build_brands

random.seed(1)


def load_ranked():
    out, seen = [], set()
    with build_brands.TRANCO.open(encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                d = registered_domain(parts[1].strip().lower())
                if d not in seen:
                    seen.add(d)
                    out.append(d)
    return out


def fakes(domain):
    label, suffix = domain.split(".", 1)
    if len(label) < 6:
        return {}
    i = random.randrange(1, len(label) - 1)
    return {
        "dropped letter": f"{label[:i] + label[i + 1:]}.{suffix}",
        "doubled letter": f"{label[:i] + label[i] + label[i:]}.{suffix}",
        "swapped letters": f"{label[:i] + label[i + 1] + label[i] + label[i + 2:]}.{suffix}",
        "garbled ending": f"{label}.{suffix}m" if len(suffix) <= 3 else f"{label}.{suffix}x",
        "digit for letter": f"{label.replace('o', '0', 1).replace('l', '1', 1)}.{suffix}",
    }


def main():
    st = data_status()
    if not st["loaded"]:
        raise SystemExit("models/brands.json not loaded. Run: python -m scripts.build_brands")
    print(f"Brand data: {st['top_brands']} brands, {st['known_real']} known-real domains\n")
    ranked = load_ranked()

    # (a) false alarms on real sites outside the allow-list
    pool = [d for d in ranked[build_brands.KNOWN_LEGIT:build_brands.KNOWN_LEGIT + 200_000]
            if d not in _KNOWN]
    flagged = [(d, find_lookalike(d)["sign"]) for d in pool if find_lookalike(d)]
    print(f"(a) False alarms: {len(flagged)} of {len(pool)} real sites "
          f"({100 * len(flagged) / max(1, len(pool)):.2f}%)")
    for d, sign in flagged[:40]:
        print(f"    {d:35s} {sign}")

    # (b) catch rate on generated fakes
    tested, caught, missed = {}, {}, []
    for d in _TOP[:300]:
        for kind, fake in fakes(d).items():
            if fake in _KNOWN or fake == d:
                continue
            tested[kind] = tested.get(kind, 0) + 1
            if find_lookalike(fake):
                caught[kind] = caught.get(kind, 0) + 1
            else:
                missed.append((kind, fake, d))
    print("\n(b) Catch rate on generated fake names (top 300 brands):")
    for kind, n in tested.items():
        c = caught.get(kind, 0)
        print(f"    {kind:18s} {c}/{n}  ({100 * c / n:.0f}%)")
    print("    examples not caught:")
    for kind, fake, real in random.sample(missed, min(15, len(missed))):
        print(f"      {fake:35s} (fake of {real}, {kind})")


if __name__ == "__main__":
    main()