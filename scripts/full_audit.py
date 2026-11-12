#!/usr/bin/env python3
"""Generate a repository-wide, non-blocking Odoo code audit."""

import argparse
import ast
import collections
import csv
import datetime
import html
import json
import pathlib
import re
import subprocess
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SENSITIVE = {"account.move", "account.payment", "account.move.line", "stock.picking", "stock.move", "res.partner"}
OVERRIDES = {"create", "write", "unlink", "action_post", "action_confirm"}
ENTERPRISE = {"account_reports", "web_enterprise"}
findings = []
files_seen = set()


def report(path, line, category, severity, rule, message, recommendation, tool="odoo-audit"):
    findings.append({
        "path": path.as_posix(), "line": int(line), "category": category,
        "severity": severity, "rule": rule, "message": message,
        "recommendation": recommendation, "tool": tool,
    })


def relative(path):
    return path.relative_to(ROOT)


def scan_python(path):
    name = relative(path)
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(name))
    except (SyntaxError, UnicodeError) as exc:
        report(name, getattr(exc, "lineno", 1) or 1, "Python", "high", "PY-SYNTAX",
               str(exc), "Corregir la sintaxis y volver a validar.")
        return
    lines = source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", node.name):
                report(name, node.lineno, "Nomenclatura", "low", "NAM-CLASS",
                       f"Clase '{node.name}' fuera de PascalCase.",
                       "Revisar nomenclatura; preservar identificadores con dependencias existentes.")
            inherit = None
            for item in node.body:
                if isinstance(item, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == "_inherit"
                    for target in item.targets
                ) and isinstance(item.value, ast.Constant):
                    inherit = item.value.value
            if inherit in SENSITIVE:
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in OVERRIDES:
                        report(name, item.lineno, "Arquitectura", "medium", "ODOO-OVERRIDE",
                               f"Override sensible {inherit}.{item.name}().",
                               "Revisión humana: super(), permisos, transacciones y regresiones.")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not re.fullmatch(r"_?[a-z][a-z0-9_]*", node.name):
                report(name, node.lineno, "Nomenclatura", "low", "NAM-METHOD",
                       f"Función '{node.name}' fuera de snake_case.",
                       "Revisar compatibilidad antes de renombrar.")
            end = getattr(node, "end_lineno", node.lineno)
            if end - node.lineno + 1 > 90:
                report(name, node.lineno, "Complejidad", "low", "SIZE-FUNCTION",
                       f"Función de {end - node.lineno + 1} líneas (heurística).",
                       "Evaluar si puede simplificarse sin fragmentar innecesariamente.")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "sudo":
            report(name, node.lineno, "Seguridad", "medium", "SEC-SUDO",
                   "Uso de sudo() requiere revisar límites de acceso.",
                   "Verificar ACL, compañía, usuarios y alcance de registros.")
    # Flag direct SQL manipulation for human review; parameterized SQL can be valid.
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "cr"):
            report(name, node.lineno, "Seguridad", "medium", "SEC-SQL",
                   "Consulta SQL directa sobre cursor de Odoo.",
                   "Revisar parámetros, permisos, coherencia ORM y multiempresa.")
    if path.name.startswith("test_") or "tests" in path.parts:
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assert) and isinstance(node.test, ast.Constant)
                    and node.test.value is True):
                report(name, node.lineno, "Pruebas", "low", "TEST-TRIVIAL",
                       "Assert True no verifica comportamiento.",
                       "Sustituir por aserciones sobre resultados verificables.")
    if len(lines) > 600:
        report(name, 1, "Mantenibilidad", "low", "SIZE-FILE",
               f"Archivo de {len(lines)} líneas (heurística).",
               "Evaluar cohesión; no dividir archivos únicamente por longitud.")


def scan_xml(path):
    name = relative(path)
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, UnicodeError) as exc:
        report(name, 1, "XML", "high", "XML-PARSE", str(exc),
               "Corregir el XML inválido.")
        return
    for element in root.iter():
        if element.tag == "xpath" and element.attrib.get("position") == "replace":
            report(name, getattr(element, "sourceline", 1) or 1, "Vistas", "medium",
                   "VIEW-REPLACE", "XPath con position='replace'.",
                   "Revisar impacto en vistas base y compatibilidad con upgrades.")


def scan_manifest(path, odoo_version="20.0", edition="community"):
    name = relative(path)
    try:
        data = ast.literal_eval(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("El manifiesto no es un diccionario")
    except (SyntaxError, ValueError, UnicodeError) as exc:
        report(name, 1, "Manifiestos", "high", "MAN-PARSE", str(exc),
               "Corregir el manifiesto.")
        return
    if not str(data.get("version", "")).startswith(f"{odoo_version}."):
        report(name, 1, "Compatibilidad", "high", "MAN-VERSION",
               f"Versión distinta de Odoo {odoo_version}.", "Revisar version en el manifiesto.")
    depends = data.get("depends", [])
    if not isinstance(depends, (list, tuple)):
        report(name, 1, "Manifiestos", "high", "MAN-DEPENDS",
               "El campo depends no es una lista.", "Corregir depends en el manifiesto.")
        return
    for dep in sorted(ENTERPRISE.intersection(depends)) if edition == "community" else []:
        report(name, 1, "Compatibilidad", "high", "MAN-ENTERPRISE",
               f"Dependencia Enterprise: {dep}.", "Eliminar o sustituir la dependencia CE.")


def scan_csv(path):
    name = relative(path)
    if path.name not in ("ir.model.access.csv", "ir.access.csv"):
        return
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for number, record in enumerate(csv.DictReader(stream), 2):
            if not record.get("group_id:id") and record.get("perm_unlink") == "1":
                report(name, number, "Seguridad", "medium", "ACL-UNLINK",
                       "Permiso de eliminación sin grupo asignado.",
                       "Revisar si el acceso público a usuarios internos es intencional.")


def run_ruff():
    try:
        result = subprocess.run(["ruff", "check", "--output-format", "json", "."],
                                cwd=ROOT, text=True, capture_output=True, check=False)
    except FileNotFoundError:
        report(pathlib.Path("pyproject.toml"), 1, "Herramientas", "low", "TOOL-RUFF",
               "Ruff no disponible.", "Instalar Ruff para completar el análisis.")
        return
    if result.returncode not in (0, 1):
        raise RuntimeError(f"Ruff no pudo ejecutarse: {result.stderr[:500]}")
    for item in json.loads(result.stdout):
        path = relative(pathlib.Path(item["filename"]))
        if not (ROOT / path.parts[0] / "__manifest__.py").is_file():
            continue
        code = item["code"] or "RUFF"
        severity = "high" if code.startswith(("F82", "E9")) else "low"
        report(path, item["location"]["row"], "Python", severity, code,
               item["message"], "Revisar el diagnóstico de Ruff.", "ruff")


def render(output, repo, odoo_version="20.0", edition="community"):
    unique = {(f["path"], f["line"], f["rule"], f["message"]): f for f in findings}
    items = sorted(unique.values(), key=lambda f: (
        SEVERITY[f["severity"]], f["path"], f["line"], f["rule"]))
    counts = collections.Counter(f["severity"] for f in items)
    categories = collections.Counter(f["category"] for f in items)
    modules = collections.Counter(f["path"].split("/")[0] for f in items)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout.strip()
    payload = {
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "commit": sha, "repository": repo, "odoo_version": odoo_version, "edition": edition, "files_scanned": len(files_seen),
        "total": len(items), "severity": dict(counts),
        "categories": dict(categories), "modules": dict(modules),
        "findings": items,
        "limitations": [
            "Análisis estático: no demuestra fallos funcionales ni vulnerabilidades explotables.",
            "Duplicidad semántica, documentación excesiva y tests redundantes requieren revisión humana.",
            "Los avisos heurísticos no implican automáticamente errores.",
        ],
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "audit.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    header = "".join(f"<th>{html.escape(s)}</th>" for s in
                     ("Gravedad", "Categoría", "Regla", "Archivo / línea", "Descripción", "Recomendación"))
    rows = []
    for f in items:
        url = f"https://github.com/{repo}/blob/{sha}/{f['path']}#L{f['line']}"
        cells = [
            f["severity"], f["category"], f["rule"],
            f'<a href="{html.escape(url, quote=True)}">{html.escape(f["path"])}:{f["line"]}</a>',
            f["message"], f["recommendation"],
        ]
        rows.append("<tr>" + "".join(f"<td>{html.escape(c) if i != 3 else c}</td>"
                                      for i, c in enumerate(cells)) + "</tr>")
    stats = " · ".join(f"{key}: {counts[key]}" for key in SEVERITY)
    summary = "".join(f"<li>{html.escape(k)}: {v}</li>" for k, v in categories.most_common())
    page = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>Auditoría {html.escape(repo)} · Odoo {html.escape(odoo_version)} {html.escape(edition)}</title><style>
body{{font:15px system-ui;margin:2rem;color:#222}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:9px;text-align:left;vertical-align:top}}
th{{background:#f2f2f2}}tr:nth-child(even){{background:#fafafa}}
input{{padding:10px;width:90%;max-width:500px;margin:1rem 0}}
</style></head><body><h1>Auditoría {html.escape(repo)} · Odoo {html.escape(odoo_version)} {html.escape(edition)}</h1>
<p>Commit: <code>{html.escape(sha)}</code></p>
<h2>{len(items)} hallazgos · {len(files_seen)} archivos examinados</h2>
<p>{html.escape(stats)}</p><h3>Categorías</h3><ul>{summary}</ul>
<p><strong>Importante:</strong> los avisos requieren validación técnica. No son errores confirmados.</p>
<input id="filter" placeholder="Filtrar por archivo, regla o categoría" aria-label="Filtrar hallazgos">
<table id="findings"><thead><tr>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table>
<script>document.getElementById('filter').addEventListener('input',function(){{
const q=this.value.toLowerCase();document.querySelectorAll('#findings tbody tr').forEach(
r=>r.hidden=!r.textContent.toLowerCase().includes(q));}});</script></body></html>"""
    (output / "index.html").write_text(page, encoding="utf-8")
    markdown = [
        f"# Auditoría de {repo} · Odoo {odoo_version} {edition}", "",
        f"Commit: `{sha}`", f"Archivos examinados: {len(files_seen)}",
        f"Hallazgos: {len(items)}", "",
        "| Severidad | Cantidad |", "| --- | ---: |",
    ]
    markdown += [f"| {severity} | {counts[severity]} |" for severity in SEVERITY]
    markdown += ["", "## Por categoría", ""]
    markdown += [f"- {category}: {count}" for category, count in categories.most_common()]
    markdown += ["", "## Por módulo", ""]
    markdown += [f"- {module}: {count}" for module, count in modules.most_common()]
    markdown += ["", "Descargar el artifact para consultar el HTML y JSON completos.",
                 "Los hallazgos heurísticos requieren revisión humana."]
    (output / "summary.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    print("\n".join(markdown))
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="audit-report")
    parser.add_argument("--repo", default="repositorio-local")
    parser.add_argument("--odoo-version", default="20.0")
    parser.add_argument("--edition", choices=("community", "enterprise"), default="community")
    args = parser.parse_args()
    modules = sorted(path for path in ROOT.iterdir()
                     if path.is_dir() and (path / "__manifest__.py").is_file())
    for module in modules:
        if not module.is_dir():
            continue
        for path in sorted(module.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix not in (".py", ".xml", ".csv"):
                continue
            files_seen.add(relative(path).as_posix())
            if path.suffix == ".py":
                scan_python(path)
                if path.name == "__manifest__.py":
                    scan_manifest(path, args.odoo_version, args.edition)
            elif path.suffix == ".xml":
                scan_xml(path)
            elif path.suffix == ".csv":
                scan_csv(path)
    run_ruff()
    render(ROOT / args.output, args.repo, args.odoo_version, args.edition)


if __name__ == "__main__":
    main()
