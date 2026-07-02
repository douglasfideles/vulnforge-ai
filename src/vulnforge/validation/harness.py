from vulnforge.models import EffectReport, ProbeResult


def decide_verdict(before: ProbeResult | None, after: ProbeResult | None, stats: dict) -> EffectReport:
    responsive_before = before.responsive if before else None
    responsive_after = after.responsive if after else None
    anomalies = list(stats.get("anomalies", []))
    if responsive_before is True and responsive_after is False:
        verdict = "valid"
    elif anomalies:
        verdict = "valid"
    elif responsive_before is True and responsive_after is True:
        verdict = "invalid"
    else:
        verdict = "inconclusive"
    return EffectReport(
        verdict=verdict, responsive_before=responsive_before, responsive_after=responsive_after,
        packets_out=stats.get("packets_out", 0), packets_in=stats.get("packets_in", 0),
        anomalies=anomalies, notes=stats.get("note", ""),
    )

