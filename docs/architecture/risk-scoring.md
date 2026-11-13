# Risk scoring

DroidScope produces an **application risk summary**. It is not a CVSS score,
and the method string says so.

## The calculation

For each finding:

```
weight = severity_weight × confidence_multiplier × status_multiplier
```

| Severity | Weight | | Confidence | Multiplier | | Review status | Multiplier |
|---|---:|---|---|---:|---|---|---:|
| critical | 40 | | high | 1.00 | | confirmed | 1.25 |
| high | 20 | | medium | 0.65 | | open | 1.00 |
| medium | 8 | | low | 0.35 | | accepted risk | 0.25 |
| low | 2 | | | | | false positive | 0.00 |
| info | 0 | | | | | resolved | 0.00 |

The total is mapped onto 0–100 by a saturating curve:

```
score = 100 × (1 − e^(−total / 85))
```

## Why these choices

**Informational findings weigh nothing.** They are context — a launcher
activity being exported, a Firebase project being configured. Letting them move
the number would reward noise.

**Confidence scales the contribution.** A low-confidence critical finding
contributes 14, not 40. The detector's own uncertainty is part of the result
rather than something the reader has to apply themselves.

**The curve saturates.** Going from forty to eighty low findings barely moves
the score, because the second forty tell you little the first forty did not.

**Volume still counts.** Twenty medium findings can exceed one critical,
because this describes an application, not a single issue.

**Severity sets a floor on the band.** A critical finding with at least medium
confidence always lands in `elevated` or above, and a high finding in
`moderate` or above, regardless of the arithmetic. One serious issue in an
otherwise quiet application must not be averaged into "low". When the floor
applies, a caveat says so explicitly.

**Review decisions are respected.** Marking a finding a false positive removes
it from the score entirely; confirming one increases its weight.

## Bands

| Score | Band | Meaning |
|---|---|---|
| 0 | minimal | No scored findings from the analyzers that ran |
| 1–24 | low | Low severity or low confidence only |
| 25–49 | moderate | Medium severity findings present |
| 50–74 | elevated | High severity findings present |
| 75–100 | high | Critical or multiple high severity findings |

## Coverage is part of the result

Every summary carries:

- which analyzers completed;
- which did not, with their status and reason;
- a caveat per incomplete analyzer, stating that issues it would detect are not
  represented;
- a standing caveat that static analysis cannot observe runtime behaviour;
- when nothing scored, an explicit statement that this is **not** evidence the
  application is secure.

A scan where JADX was unavailable can easily score 0. Without the coverage
section that would read as a clean result, which would be false.

## Worked example

The vulnerable fixture, standard profile: 5 critical, 16 high, 18 medium,
9 low, 4 informational, mostly high confidence.

```
total ≈ 5×40 + 16×20×0.9 + 18×8×0.8 + 9×2×0.9  ≈ 525
score = 100 × (1 − e^(−525/85)) = 99.8 → band "high"
```

The secure fixture, same profile: 2 informational, 1 low → total 2 → score 2.3
→ band `low`, with the caveat that a quiet scan is not proof of security.
