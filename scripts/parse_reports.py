import json
import os
from datetime import datetime, timezone

def parse_codeql_sarif(sarif_path):
    with open(sarif_path, 'r', encoding='utf-8') as f:
        sarif = json.load(f)

    tool_name = "CodeQL"
    results = []

    for run in sarif.get("runs", []):
        tool = run.get("tool", {})
        tool_info = run.get("tool", {}).get("driver", {}).get("name", "CodeQL")
        rules_map = {}

        # 1. 加载 driver 中的规则
        for rule in tool.get("driver", {}).get("rules", []):
            rules_map[rule.get("id")] = rule

        # 2. 加载 extensions 中的规则
        for ext in tool.get("extensions", []):
            for rule in ext.get("rules", []):
                rules_map[rule.get("id")] = rule  # 覆盖或新增

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            locations = result.get("locations", [])
            uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "") if locations else ""

            rule = rules_map.get(rule_id, {})
            short_desc = rule.get("shortDescription", {}).get("text", "")
            full_desc = rule.get("fullDescription", {}).get("text", "")
            help_markdown = rule.get("help", {}).get("markdown", "")
            help_uri = rule.get("helpUri", "")

            language_prefix = rule_id.split('/')[0] if '/' in rule_id else 'unknown'

            results.append({
                "tool": tool_info,
                "type": f"SAST-{language_prefix}",
                "rule_id": rule_id,
                "message": message,
                "short_description": short_desc,
                "full_description": full_desc,
                "remediation": help_markdown,
                "reference": help_uri,
                "file": uri,
            })

    if not results:
        return None

    return {
        "tool": tool_name,
        "type": "SAST",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": "source-code",
        "results": results
    }

# Collect and parse CodeQL SARIF files from the "codeql" directory
codeql_reports = []
for root, dirs, files in os.walk("codeql"):
    for file in files:
        if file.endswith(".sarif"):
            full_path = os.path.join(root, file)
            parsed = parse_codeql_sarif(full_path)
            if parsed:
                codeql_reports.append(parsed)

def parse_trivy_results(file_path, scan_type):
    if not os.path.exists(file_path):
        return {
            "tool": "Trivy",
            "type": scan_type,
            "results": [],
            "note": f"File {file_path} not found.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": "N/A"
        }

    with open(file_path, 'r') as f:
        sarif = json.load(f)

    results = []
    rules_map = {}

    # 尝试获取扫描目标
    target = sarif.get("runs", [{}])[0].get("originalUriBaseIds", {}).get("ROOTPATH", {}).get("uri", "Unknown")

    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = driver.get("rules", [])
        for rule in rules:
            rules_map[rule.get("id")] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            rule = rules_map.get(rule_id, {})
            help_text = rule.get("help", {}).get("markdown", "")

            # 尝试提取修复建议
            fix_info = ""
            if "|LOW|" in help_text or "|HIGH|" in help_text or "|CRITICAL|" in help_text:
                fix_info = help_text.split("\n")[-1].strip()

            results.append({
                "tool": "Trivy",
                "type": scan_type,
                "cve": rule.get("id"),
                "component": rule.get("help", {}).get("text", "").split("Package:")[-1].split("\n")[0].strip(),
                "severity": rule.get("properties", {}).get("security-severity", "N/A"),
                "description": rule.get("shortDescription", {}).get("text", ""),
                "remediation": fix_info,
                "reference": rule.get("helpUri", "")
            })

    return {
        "tool": "Trivy",
        "type": scan_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "results": results
    }

def parse_zap_results(zap_file_path):
    target = "N/A"
    if not os.path.exists(zap_file_path):
        return {
            "tool": "OWASP ZAP",
            "type": "DAST",
            "results": [],
            "note": f"File {zap_file_path} not found.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": "N/A"
        }

    with open(zap_file_path, 'r') as f:
        zap_json = json.load(f)

    results = []

    for site in zap_json.get("site", []):
        alerts = site.get("alerts", [])
        for alert in alerts:
            for instance in alert.get("instances", []):
                results.append({
                    "tool": "OWASP ZAP",
                    "type": "DAST",
                    "name": alert.get("name"),
                    "risk": alert.get("riskdesc"),
                    "description": alert.get("desc"),
                    "uri": instance.get("uri"),
                    "evidence": instance.get("evidence"),
                    "solution": alert.get("solution"),
                    "cwe": alert.get("cweid"),
                })

    return {
        "tool": "OWASP ZAP",
        "type": "DAST",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "results": results
    }

# ==== 主程序入口 ====
if __name__ == "__main__":
    merged_results = []

    merged_results.extend(codeql_reports)
    merged_results.append(parse_trivy_results("trivy-fs-results.sarif", scan_type="SCA File Scan"))
    merged_results.append(parse_trivy_results("trivy-results.sarif", scan_type="SCA Image Scan"))
    merged_results.append(parse_zap_results("report_json.json"))

    with open("merged-security-reports.json", "w") as f:
        json.dump(merged_results, f, indent=2)

    print("✅ Merged report written to merged-security-reports.json")
