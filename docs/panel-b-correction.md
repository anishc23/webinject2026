# Panel B: a correction to the deletion-vocabulary estimator

**Status: specification. Written and committed before the corrected experiment
was run.** The commit that adds this file is the record that the rule was fixed
in advance of seeing the outcome. Nothing below consults a corrected AUC,
because none had been computed when it was written.

## 1. The defect

Panel B derives its deletion vocabulary per corpus, from that corpus's own
training attacks, so that deletion *aggression* is matched rather than assumed.
`derive_vocab` in `src/syntax_ablation.py` deletes a token when

    P(token | attack row) >= VOCAB_LIFT * ((benign count + 1) / n_benign)

with `VOCAB_LIFT = 5.0`, presence-per-row rather than frequency.

A lift estimator asks whether a token discriminates attack from benign *in that
corpus*. This corpus deliberately breaks that assumption. It ships an
`ambiguous` benign tier built to contain literal attack syntax, plus
hard-negative `code` and `log` registers that carry more. The comparison corpora
have no equivalent tier. Measured with `vocab.is_injective`, which matches real
break-out syntax rather than mere punctuation:

| Corpus | benign rows | benign rows containing literal injection syntax |
|---|---|---|
| CSIC-2010 | 72,000 | 0 (0.0%) |
| ECML/PKDD-2007 | 34,388 | 24 (0.1%) |
| WebInject2026 | 45,400 | 2,022 (4.5%) |

So tokens such as `select`, `entity`, `jndi` and `proto` appear in benign rows
here and essentially nowhere in the benign side of the other two. The estimator
reads them as non-discriminative **on this corpus only** and declines to delete
them, while harvesting CSIC's and ECML's vocabularies unimpeded. The derived
vocabularies are 6,260 / 510 / 242 tokens respectively.

Panel B therefore does not measure what it claims. It claims to equalise
deletion; it applies an estimator whose recall is suppressed by a construction
property that only one of the three corpora has. That property is precisely the
one the corpus was built to have, so the panel penalises the corpus for its own
design.

### What the recall numbers do and do not show

Against the 404-token payload pool restricted to terms present in each corpus,
the current estimator recovers:

| Corpus | recall of derived vocabulary against ground truth |
|---|---|
| CSIC-2010 | 47.6% |
| ECML/PKDD-2007 | 35.5% |
| WebInject2026 | 57.8% |

**These three numbers are not directly comparable and must not be reported as
if they were.** For WebInject2026 the payload pool *is* ground truth, exactly
and by construction. For the other two it is a proxy: the pool can only name
attack words this corpus happens to know, so their true vocabularies are larger
than the measured denominator and their real recall is lower than shown. The
defect is evidenced by the benign-injective asymmetry in the first table, not by
a cross-corpus recall comparison.

## 2. The corrected rule

Exclude from the benign denominator any benign row containing literal injection
syntax, on the general principle that such a row is not evidence that a token is
non-injective. Implement with the existing `vocab.is_injective`
(`INJECTION_GUARD`), applied **identically to all three corpora**, with no
corpus-specific branch anywhere in the code path.

Expected effect, stated in advance: it should exclude almost nothing from
CSIC-2010 and ECML/PKDD-2007 (0 and 24 rows) and a material fraction from
WebInject2026 (2,022 rows). That asymmetry is a property of the corpora, and the
paper will say so rather than smoothing it.

The rule is fixed here. `VOCAB_LIFT` stays at 5.0 for the headline panel; the
sweep in section 4 is reported separately and is not used to select it.

## 3. The completeness metric

Deletion *aggression* (share of characters removed) is not deletion
*completeness* (share of the injection vocabulary actually removed). Panel B has
only ever matched the former. Add a completeness column to Table 4 for Panels A
and B:

- **WebInject2026**: recall of the derived vocabulary against the 404-token
  payload pool. Exact, because the pool is ground truth by construction.
- **CSIC-2010, ECML/PKDD-2007**: recall against the payload pool restricted to
  terms present in that corpus, reported as the proxy it is.

This turns the prose argument of Section 6.3 into an auditable number.

## 4. Lift sensitivity

Sweep `VOCAB_LIFT` over {2, 5, 10, 20} for all three corpora under the corrected
rule. One sentence of result in Section 6.3, the full curve in the artifact. If
the ranking is stable across the sweep, say so. If it flips at some threshold,
that is a finding and it gets reported.

## 5. Reporting commitment

**The result will be reported whichever way it falls.** Specifically:

- If the corrected Panel B still ranks WebInject2026 behind ECML/PKDD-2007, that
  stays in the abstract, the introduction, Section 6.3, Limitations and the
  conclusion, exactly as it stands today.
- If it no longer does, the abstract's "Against us:" sentence loses one of its
  four items and is allowed to shrink. No replacement adverse item will be
  hunted for to keep the count at four.
- Section 6.3 will state, in this order: the old rule, its measured recall
  against ground truth, the number it produced, the corrected rule, and the
  number the corrected rule produces.

The disclosure of the correction is the credibility, not the corrected number.

## 6. Out of scope

Anything that consults the resulting AUC when choosing the rule. The rule above
is final as of this commit. If it turns out to be wrong for some reason that is
visible only after running it, the fix is a further documented correction with
its own specification, not an edit to this one.
