# Commons Governance Scenario Sandbox

This folder is a **toy simulation environment**, not a predictor of real people, courts, governments, or conflicts. Its purpose is to make Commons governance concepts executable enough to stress-test definitions and failure logic before field pilots.

## Current metrics

- **MMR — Maximum Malicious Reach:** modeled maximum harm exposed before independent containment.
- **MDB — Minimum Defensive Burden:** burden an ordinary person must supply before protection activates.
- **DIB — Defensive Interruption Burden:** repeated annual burden of having ordinary life interrupted by defensive work.
- **Boring Failure timing condition:** `T_detect + T_authorize + T_interrupt < T_irreversible_harm`.
- **Essentials continuity:** fraction of life-supporting services preserved during the simulated dispute.

## What the sandbox can do

`governance_sim.py` evaluates deterministic scenarios and seeded Monte Carlo perturbations. The first four scenarios represent bounded defection, slow oversight, a fast independent interlock, and captured oversight.

## What it cannot do

It cannot estimate real-world probabilities, predict human behavior, validate a political ideology, or replace empirical pilots. Parameters are dimensionless/normalized until a real domain supplies measurements.

## Validation rule

A simulation result may generate a **hypothesis** or reveal an internal inconsistency. It cannot promote a governance claim to “established” without observational or experimental evidence outside the model.

## Run

```bash
python sandbox/governance_sim.py
python -m unittest discover -s sandbox -p 'test_*.py'
```
