"""
Security Service Prioritization — UNSW-NB15 Dataset Preparation

Purpose: Build datasets to answer which network services a mid-size enterprise
Network Security Engineer should prioritize for defensive resources (patching,
WAF deployment, MFA, vulnerability scanning, legacy decommissioning).

Problem: Limited budget and analyst capacity → prioritize services that are
most often targeted to reduce breach likelihood efficiently.

Output datasets:
  - combined_traffic.csv: Full concatenated training + testing traffic
  - service_risk_summary.csv: Per-service attack counts and attack rate
  - service_attack_matrix.csv: Service × attack category (which attacks target which services)
  - service_prioritization.csv: Ranked services for defensive prioritization
"""

import csv
import os
from collections import defaultdict


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAIN_CSV = os.path.join(BASE_DIR, "UNSW_NB15_training-set.csv")
TEST_CSV = os.path.join(BASE_DIR, "UNSW_NB15_testing-set.csv")
OUTPUT_DIR = BASE_DIR


def normalize_service(s: str) -> str:
    """Normalize service name (strip whitespace; treat '-' as 'unspecified')."""
    if s is None or (isinstance(s, str) and not s.strip()) or s.strip() == "-":
        return "unspecified"
    return s.strip()


def load_csv(path: str):
    """Yield rows as dicts from a CSV file."""
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield row


def get_header(path: str):
    """Return list of column names for a CSV."""
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return next(csv.reader(f))


def load_and_concatenate():
    """Load training and testing CSVs and return (rows, fieldnames)."""
    train_header = get_header(TRAIN_CSV)
    fieldnames = train_header + ["source"]
    rows = []
    for row in load_csv(TRAIN_CSV):
        row["source"] = "training"
        rows.append(row)
    for row in load_csv(TEST_CSV):
        row["source"] = "testing"
        rows.append(row)
    return rows, fieldnames


def build_combined_dataset(rows, fieldnames):
    """Add normalized service and return rows for combined_traffic.csv."""
    out_fieldnames = fieldnames + ["service_normalized"]
    out_rows = []
    for r in rows:
        r = dict(r)
        r["service_normalized"] = normalize_service(r.get("service", ""))
        out_rows.append(r)
    return out_rows, out_fieldnames


def build_service_risk_summary(rows):
    """
    Per-service: total_flows, attack_flows, normal_flows, attack_rate.
    """
    totals = defaultdict(lambda: {"total": 0, "attack": 0})
    for r in rows:
        svc = normalize_service(r.get("service", ""))
        totals[svc]["total"] += 1
        if str(r.get("label", "0")).strip() == "1":
            totals[svc]["attack"] += 1

    summary = []
    for svc, v in totals.items():
        total = v["total"]
        attack = v["attack"]
        rate = (attack / total) if total else 0
        summary.append({
            "service": svc,
            "total_flows": total,
            "attack_flows": attack,
            "normal_flows": total - attack,
            "attack_rate": round(rate, 4),
        })
    summary.sort(key=lambda x: x["attack_flows"], reverse=True)
    return summary


def build_service_attack_matrix(rows):
    """
    Service × attack_cat counts (only attack rows).
    """
    matrix = defaultdict(lambda: defaultdict(int))
    for r in rows:
        if str(r.get("label", "0")).strip() != "1":
            continue
        svc = normalize_service(r.get("service", ""))
        cat = (r.get("attack_cat") or "").strip() or "Unknown"
        matrix[svc][cat] += 1

    # Collect all attack categories
    all_cats = set()
    for cats in matrix.values():
        all_cats.update(cats.keys())
    all_cats = sorted(all_cats)

    out = []
    for svc in sorted(matrix.keys(), key=lambda s: (-sum(matrix[s].values()), s)):
        row = {"service": svc}
        for c in all_cats:
            row[c] = matrix[svc][c]
        out.append(row)
    return out, ["service"] + all_cats


def build_service_prioritization(risk_summary, attack_matrix_rows, matrix_columns):
    """
    Rank services by risk_score = 0.6 * (attack_volume_norm) + 0.4 * (attack_rate_norm).
    """
    max_vol = max((r["attack_flows"] for r in risk_summary), default=1)
    max_rate = max((r["attack_rate"] for r in risk_summary), default=1) or 1

    priority = []
    for r in risk_summary:
        vol_norm = r["attack_flows"] / max_vol
        rate_norm = r["attack_rate"] / max_rate
        risk_score = round(0.6 * vol_norm + 0.4 * rate_norm, 4)
        priority.append({
            "service": r["service"],
            "total_flows": r["total_flows"],
            "attack_flows": r["attack_flows"],
            "attack_rate": r["attack_rate"],
            "risk_score": risk_score,
        })

    priority.sort(key=lambda x: x["risk_score"], reverse=True)
    for i, p in enumerate(priority, start=1):
        p["priority_rank"] = i

    # Attach top attack categories per service
    cat_cols = [c for c in matrix_columns if c != "service"]
    matrix_by_svc = {row["service"]: row for row in attack_matrix_rows}
    for p in priority:
        row = matrix_by_svc.get(p["service"], {})
        top = sorted(
            [(c, row.get(c, 0)) for c in cat_cols],
            key=lambda x: -x[1],
        )[:3]
        p["top_attack_categories"] = ", ".join(
            f"{k}({int(v)})" for k, v in top if v
        )

    return priority


def write_csv(path, rows, fieldnames):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main():
    print("Loading and concatenating UNSW-NB15 training and testing sets...")
    rows, fieldnames = load_and_concatenate()
    combined_rows, combined_fields = build_combined_dataset(rows, fieldnames)

    # 1) Full combined dataset
    combined_path = os.path.join(OUTPUT_DIR, "combined_traffic.csv")
    write_csv(combined_path, combined_rows, combined_fields)
    print(f"  Written: {combined_path} ({len(combined_rows):,} rows)")

    # 2) Service risk summary
    risk_summary = build_service_risk_summary(combined_rows)
    risk_path = os.path.join(OUTPUT_DIR, "service_risk_summary.csv")
    write_csv(risk_path, risk_summary, ["service", "total_flows", "attack_flows", "normal_flows", "attack_rate"])
    print(f"  Written: {risk_path}")

    # 3) Service × attack category matrix
    attack_matrix_rows, matrix_columns = build_service_attack_matrix(combined_rows)
    matrix_path = os.path.join(OUTPUT_DIR, "service_attack_matrix.csv")
    write_csv(matrix_path, attack_matrix_rows, matrix_columns)
    print(f"  Written: {matrix_path}")

    # 4) Prioritization ranking
    prioritization = build_service_prioritization(
        risk_summary, attack_matrix_rows, matrix_columns
    )
    priority_path = os.path.join(OUTPUT_DIR, "service_prioritization.csv")
    prio_fields = ["service", "total_flows", "attack_flows", "attack_rate", "risk_score", "priority_rank", "top_attack_categories"]
    write_csv(priority_path, prioritization, prio_fields)
    print(f"  Written: {priority_path}")

    print("\n--- Service prioritization (top services to defend first) ---")
    for i, p in enumerate(prioritization[:15], start=1):
        print(f"  {p['priority_rank']:2}. {p['service']:12}  attacks={p['attack_flows']:6}  rate={p['attack_rate']:.4f}  score={p['risk_score']:.4f}  top: {p['top_attack_categories'][:60]}")
    print("\nDone. Use service_prioritization.csv and service_attack_matrix.csv for resource allocation decisions.")


if __name__ == "__main__":
    main()
