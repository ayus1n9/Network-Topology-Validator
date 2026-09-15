"""Format and print the security report."""


def generate_report(findings):
    """
    Print a formatted security report to stdout.

    Groups findings by severity (critical -> high -> medium -> low),
    prints a summary header, then each finding with its devices.

    Args:
        findings (list): List of finding dicts from validate_security_rules.

    Returns:
        None
    """
    print("=" * 60)
    print("  NETWORK TOPOLOGY SECURITY REPORT")
    print("=" * 60)

    if not findings:
        print("\n  [OK] No security design flaws detected.")
        print("=" * 60)
        return

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    total = len(findings)
    print(f"\n  Total findings: {total}")
    for severity in ("critical", "high", "medium", "low"):
        if severity in counts:
            print(f"    {severity.upper():<8} : {counts[severity]}")

    for severity in ("critical", "high", "medium", "low"):
        group = [f for f in findings if f["severity"] == severity]
        if not group:
            continue

        print("\n" + "-" * 60)
        print(f"  {severity.upper()} ({len(group)})")
        print("-" * 60)

        for i, f in enumerate(group, start=1):
            devices_str = ", ".join(f["devices"])
            print(f"\n  {i}. {f['message']}")
            print(f"     Affected devices: {devices_str}")

    print("\n" + "=" * 60)