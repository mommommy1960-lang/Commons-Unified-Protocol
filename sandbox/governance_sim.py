"""Commons Boring-Failure governance sandbox.

This is a toy simulation for stress-testing governance timing and containment ideas.
It is not a predictor of real institutions and must not be used as one.
"""
from dataclasses import dataclass, asdict
from typing import Dict
import random

@dataclass(frozen=True)
class Scenario:
    name: str
    malicious_capacity: float = 100.0
    detect_time: float = 2.0
    authorize_time: float = 2.0
    interrupt_time: float = 2.0
    irreversible_harm_time: float = 10.0
    containment_fraction: float = 0.90
    ordinary_person_burden: float = 10.0
    interruptions_per_year: float = 2.0
    burden_per_interruption: float = 4.0
    essentials_continuity: float = 1.0

@dataclass(frozen=True)
class Outcome:
    scenario: str
    total_interrupt_latency: float
    boring_failure: bool
    maximum_malicious_reach: float
    minimum_defensive_burden: float
    defensive_interruption_burden: float
    essentials_continuity: float

def evaluate(s: Scenario) -> Outcome:
    if s.malicious_capacity < 0:
        raise ValueError("malicious_capacity must be non-negative")
    if not 0 <= s.containment_fraction <= 1:
        raise ValueError("containment_fraction must be within [0, 1]")
    if not 0 <= s.essentials_continuity <= 1:
        raise ValueError("essentials_continuity must be within [0, 1]")
    times = [s.detect_time, s.authorize_time, s.interrupt_time, s.irreversible_harm_time]
    if any(t < 0 for t in times):
        raise ValueError("times must be non-negative")

    latency = s.detect_time + s.authorize_time + s.interrupt_time
    boring = latency < s.irreversible_harm_time

    if boring:
        residual = 1.0 - s.containment_fraction
        time_fraction = 0 if s.irreversible_harm_time == 0 else min(1.0, latency / s.irreversible_harm_time)
        mmr = s.malicious_capacity * residual * time_fraction
    else:
        mmr = s.malicious_capacity

    mdb = max(0.0, s.ordinary_person_burden)
    dib = max(0.0, s.interruptions_per_year) * max(0.0, s.burden_per_interruption)

    return Outcome(
        scenario=s.name,
        total_interrupt_latency=latency,
        boring_failure=boring,
        maximum_malicious_reach=round(mmr, 6),
        minimum_defensive_burden=round(mdb, 6),
        defensive_interruption_burden=round(dib, 6),
        essentials_continuity=round(s.essentials_continuity, 6),
    )

def monte_carlo(base: Scenario, runs: int = 1000, jitter: float = 0.25, seed: int = 1960) -> Dict[str, float]:
    if runs <= 0:
        raise ValueError("runs must be positive")
    if jitter < 0:
        raise ValueError("jitter must be non-negative")
    rng = random.Random(seed)
    boring_count = 0
    reach_total = 0.0
    continuity_total = 0.0
    for i in range(runs):
        def j(v):
            return max(0.0, v * (1 + rng.uniform(-jitter, jitter)))
        s = Scenario(
            name=f"{base.name}#{i}",
            malicious_capacity=j(base.malicious_capacity),
            detect_time=j(base.detect_time),
            authorize_time=j(base.authorize_time),
            interrupt_time=j(base.interrupt_time),
            irreversible_harm_time=j(base.irreversible_harm_time),
            containment_fraction=min(1.0, max(0.0, base.containment_fraction + rng.uniform(-jitter/5, jitter/5))),
            ordinary_person_burden=j(base.ordinary_person_burden),
            interruptions_per_year=j(base.interruptions_per_year),
            burden_per_interruption=j(base.burden_per_interruption),
            essentials_continuity=min(1.0, max(0.0, base.essentials_continuity + rng.uniform(-jitter/10, jitter/10))),
        )
        o = evaluate(s)
        boring_count += int(o.boring_failure)
        reach_total += o.maximum_malicious_reach
        continuity_total += o.essentials_continuity
    return {
        "runs": runs,
        "boring_failure_rate": boring_count / runs,
        "mean_mmr": reach_total / runs,
        "mean_essentials_continuity": continuity_total / runs,
    }

def default_scenarios():
    return {
        "bounded_defection": Scenario(name="bounded_defection"),
        "slow_oversight": Scenario(name="slow_oversight", detect_time=4, authorize_time=4, interrupt_time=4, irreversible_harm_time=10),
        "fast_independent_interlock": Scenario(name="fast_independent_interlock", detect_time=0.5, authorize_time=0.25, interrupt_time=0.25, irreversible_harm_time=8, containment_fraction=0.98, ordinary_person_burden=2, interruptions_per_year=0.5, burden_per_interruption=1, essentials_continuity=0.99),
        "captured_oversight": Scenario(name="captured_oversight", detect_time=2, authorize_time=15, interrupt_time=2, irreversible_harm_time=10, containment_fraction=0.2, ordinary_person_burden=80, interruptions_per_year=12, burden_per_interruption=10, essentials_continuity=0.55),
    }

if __name__ == "__main__":
    for name, scenario in default_scenarios().items():
        print(asdict(evaluate(scenario)))
        print(monte_carlo(scenario, runs=1000))
