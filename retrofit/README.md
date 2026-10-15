# RootBeer contract retrofit (experiment B)

Placeholder. Nothing is implemented yet.

## Goal

Show that the Evidence Contract is a portable abstraction by wrapping a third-party detector,
[RootBeer](https://github.com/scottyab/rootbeer) at the revision examined in the thesis (`de7bc7b`),
without changing its detection logic, and measure how many of its "clean" results do not hold.

RootBeer's `isRooted()` is the OR of nine checks, and a check that cannot read its source returns
`false`. The wrapper will change only how results are reported:

- each check reports `OBSERVED`, `NOT_OBSERVED` or `INCONCLUSIVE`, with the state of its channel;
- an exception, a permission denial or an unreadable source is reported as `INCONCLUSIVE`, never as
  `false`;
- following TamperProbe's concealable-negative rule, a `NOT_OBSERVED` that concealment could have
  produced is marked as such.

## Measurement (to be preregistered in `experiments/`)

Among the configurations where unmodified RootBeer reports a clean device, the share the contract
version reclassifies as `INCONCLUSIVE` or concealable, with the reason for each. This is a count
over fixed configurations, not a detection or false-positive rate.

## Open decisions

- Module form: a separate Gradle module that depends on RootBeer, or a wrapper inside the probe app.
- RootBeer's licence (Apache-2.0) must be respected if any of its code is vendored.
- Whether Overt or Duck-Detector checks get the same treatment.
