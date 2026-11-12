#!/usr/bin/env python3
"""Convert advisory Odoo QA JSON findings to SARIF 2.1.0 and a readable summary."""
import argparse
import json
from pathlib import Path

FILES = ("architecture.json", "security.json", "security-critical.json",
         "security-deep.json", "runtime-guards.json", "regressions.json", "performance.json", "code-governance.json", "style.json", "modules.json")
LEVELS = {"error": "error", "critical": "error", "warning": "warning",
          "review": "note", "info": "note"}


def convert(directory):
    rules, results, counts = {}, [], {"error": 0, "warning": 0, "note": 0}
    for filename in FILES:
        path = directory / filename
        if not path.is_file():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload.get("findings", []) if isinstance(payload, dict) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            rule = str(item.get("rule", "QA_REVIEW"))
            level = LEVELS.get(str(item.get("severity", "review")).lower(), "note")
            message = str(item.get("detail") or item.get("message") or item.get("identifier") or rule)
            rules.setdefault(rule, {"id": rule, "shortDescription": {"text": rule}})
            result = {"ruleId": rule, "level": level, "message": {"text": message}}
            filename = item.get("file") or item.get("path")
            if filename:
                try:
                    line = max(1, int(item.get("line") or 1))
                except (TypeError, ValueError):
                    line = 1
                result["locations"] = [{"physicalLocation": {
                    "artifactLocation": {"uri": str(filename).replace("\\", "/")},
                    "region": {"startLine": line}}}]
            results.append(result)
            counts[level] += 1
    sarif = {"version": "2.1.0", "$schema":
             "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "Odoo Quality CI",
                                            "rules": list(rules.values())}},
                       "results": results}]}
    return sarif, counts


def readable_summary(directory, counts):
    """Show a project-specific, actionable overview without conflating advisory and gate counts."""
    audit_path = directory / "audit.json"
    if not audit_path.exists():
        return "## Resumen de auditoría\\n\\nNo se generó audit.json. Revisar logs del job.\\n"
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    repo = audit.get("repository", "Repositorio")
    version = audit.get("odoo_version", "desconocida")
    edition = audit.get("edition", "desconocida")
    items = audit.get("findings", [])
    severity = audit.get("severity", {})
    lines = [
        f"## Auditoría: {repo}",
        "",
        f"**Proyecto:** `{repo}` · **Odoo:** {version} ({edition}) · **Commit:** `{audit.get('commit', '?')[:12]}`",
        "",
        f"**Cobertura estática:** {audit.get('files_scanned', 0)} archivos · {len(items)} hallazgos del análisis general.",
        "",
        "### Severidad del análisis general",
        "",
        "| Crítica | Alta | Media | Baja |",
        "|---:|---:|---:|---:|",
        f"| {severity.get('critical', 0)} | {severity.get('high', 0)} | {severity.get('medium', 0)} | {severity.get('low', 0)} |",
        "",
        "### Módulos con más observaciones",
        "",
        "| Módulo | Hallazgos |",
        "|---|---:|",
    ]
    lines.extend(f"| `{name}` | {number} |" for name, number in
                 sorted(audit.get("modules", {}).items(), key=lambda x: -x[1])[:10])
    lines += ["", "### Observaciones prioritarias (revisión humana)", "",
              "| Gravedad | Módulo / archivo | Regla | Descripción |",
              "|---|---|---|---|"]
    for item in sorted(items, key=lambda x: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity"), 4),
                                              x.get("path", "")))[:15]:
        location = f"{item.get('path', '?')}:{item.get('line', 1)}"
        message = str(item.get("message", "")).replace("|", "/").replace("\\n", " ")[:130]
        lines.append(f"| {item.get('severity', '?')} | `{location}` | `{item.get('rule', '?')}` | {message} |")
    lines += [
        "", "### Diagnósticos de los controles especializados", "",
        f"- SARIF: {counts['error']} errores, {counts['warning']} advertencias y {counts['note']} notas.",
        "- Estas cifras provienen de herramientas distintas; **no deben sumarse** a los hallazgos del análisis general.",
        "- El resultado PASS significa que el umbral de bloqueo configurado se superó, **no que el código carezca de riesgos**.",
        "- Se trata de análisis estático: no sustituye instalación, actualización, pruebas funcionales ni revisión de permisos en ejecución.",
        "", "El artifact `shared-odoo-quality-report` contiene JSON, HTML y SARIF para consultar cada archivo y recomendación.",
        ""
    ]
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=Path("audit-report"))
    args = parser.parse_args()
    sarif, counts = convert(args.directory)
    args.directory.mkdir(parents=True, exist_ok=True)
    (args.directory / "quality.sarif").write_text(json.dumps(sarif, indent=2) + "\n")
    summary = ("## Odoo QA findings\n\n"
               "| Level | Findings |\n|---|---:|\n"
               + "".join(f"| {level} | {counts[level]} |\n"
                         for level in ("error", "warning", "note")))
    (args.directory / "quality-summary.md").write_text(summary)
    print(summary)
    detailed = readable_summary(args.directory, counts)
    (args.directory / "project-summary.md").write_text(detailed, encoding="utf-8")
    print(detailed)


if __name__ == "__main__":
    main()
