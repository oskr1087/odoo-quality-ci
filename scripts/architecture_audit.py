#!/usr/bin/env python3
"""Conservative cross-module Odoo architecture audit; findings are review hints."""

import argparse
import ast
import collections
import hashlib
import json
import pathlib
import re
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
KNOWN_EXTERNAL = {
    "base", "account", "stock", "point_of_sale", "mail", "web", "contacts",
    "sale", "purchase", "product", "uom", "decimal_precision", "l10n_ec",
    "l10n_latam_base", "l10n_latam_invoice_document", "account_edi",
    "account_edi_ubl_cii",
}
CRITICAL = {"create", "write", "unlink", "action_post", "action_confirm"}
XML_REF = re.compile(r"(?<![\w.])([a-zA-Z_]\w*\.[a-zA-Z_]\w*)")
MODULE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
findings = []


def add(module, path, line, rule, message, severity="review"):
    findings.append({"module": module, "path": path.relative_to(ROOT).as_posix(),
                     "line": line, "rule": rule, "severity": severity, "message": message})


def modules():
    return {p.name: p for p in ROOT.iterdir()
            if p.is_dir() and (p / "__manifest__.py").is_file()}


def manifest(module, folder):
    path = folder / "__manifest__.py"
    try:
        data = ast.literal_eval(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Manifest must be a dictionary")
        return data
    except (ValueError, SyntaxError, UnicodeError) as exc:
        add(module, path, 1, "MANIFEST", str(exc), "error")
        return {}


def dependencies(folders, manifests):
    graph = {}
    for module, data in manifests.items():
        deps = data.get("depends", [])
        if not isinstance(deps, (list, tuple)):
            add(module, folders[module] / "__manifest__.py", 1, "DEP-TYPE",
                "depends must be a list or tuple", "error")
            deps = []
        graph[module] = sorted(set(deps).intersection(folders))
        for dep in deps:
            if not isinstance(dep, str) or not MODULE_RE.fullmatch(dep):
                add(module, folders[module] / "__manifest__.py", 1, "DEP-NAME",
                    f"Invalid dependency: {dep!r}", "error")
            elif dep not in folders and dep not in KNOWN_EXTERNAL:
                add(module, folders[module] / "__manifest__.py", 1, "DEP-EXTERNAL",
                    f"External dependency '{dep}' must exist in the target Odoo addons path")
    visited, active = set(), set()

    def visit(node, chain):
        if node in active:
            add(node, folders[node] / "__manifest__.py", 1, "DEP-CYCLE",
                "Local dependency cycle: " + " -> ".join(chain + [node]), "error")
            return
        if node in visited:
            return
        active.add(node)
        for child in graph[node]:
            visit(child, chain + [node])
        active.remove(node)
        visited.add(node)

    for module in sorted(graph):
        visit(module, [])
    return graph


def class_inherit(node):
    values = []
    for statement in node.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "_inherit"
            for target in statement.targets
        ):
            try:
                value = ast.literal_eval(statement.value)
                if isinstance(value, str):
                    values.append(value)
                elif isinstance(value, (list, tuple)):
                    values.extend(v for v in value if isinstance(v, str))
            except (ValueError, TypeError):
                pass
    return values


def super_calls(method):
    for node in ast.walk(method):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            if (isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Name)
                    and receiver.func.id == "super" and node.func.attr == method.name):
                return True
    return False


def scan_python(folders):
    signatures = collections.defaultdict(list)
    for module, folder in folders.items():
        for path in folder.rglob("*.py"):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (SyntaxError, UnicodeError):
                continue  # Existing syntax gate handles this.
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                inherited = class_inherit(node)
                for method in node.body:
                    if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    if inherited and method.name in CRITICAL and not super_calls(method):
                        add(module, path, method.lineno, "OVERRIDE-SUPER",
                            f"{method.name} overrides {', '.join(inherited)} without an explicit super().{method.name}() call; verify deliberate replacement")
                    if method.name.startswith("__"):
                        continue
                    normalized = ast.dump(ast.Module(body=method.body, type_ignores=[]),
                                          include_attributes=False)
                    if len(normalized) >= 180:
                        digest = hashlib.sha256(normalized.encode()).hexdigest()
                        signatures[digest].append((module, path, method.lineno, method.name))
    for occurrences in signatures.values():
        if len(occurrences) < 2:
            continue
        distinct = {(m, p.as_posix()) for m, p, _, _ in occurrences}
        if len(distinct) < 2:
            continue
        for module, path, line, method in occurrences:
            add(module, path, line, "DUP-BODY",
                f"Identical method body ({method}) in {len(distinct)} files; assess shared logic")


def scan_xml(folders, graph):
    defined = collections.defaultdict(set)
    referenced = []
    for module, folder in folders.items():
        for path in folder.rglob("*.xml"):
            try:
                root = ET.parse(path).getroot()
            except (ET.ParseError, UnicodeError):
                continue
            for element in root.iter():
                xml_id = element.attrib.get("id")
                if xml_id and element.tag in {"record", "template", "menuitem", "report"}:
                    defined[module].add(xml_id)
                for key in ("ref", "inherit_id", "parent", "action"):
                    value = element.attrib.get(key, "")
                    if value:
                        referenced.append((module, path, key, value))
                if element.tag == "field" and element.attrib.get("name") in {
                    "inherit_id", "view_id", "action_id", "binding_model_id"
                }:
                    value = element.attrib.get("ref")
                    if value:
                        referenced.append((module, path, "field-ref", value))
    for module, path, _key, value in referenced:
        if value.startswith("%(") or not XML_REF.fullmatch(value):
            continue
        target_module, target_id = value.split(".", 1)
        if target_module in folders:
            if target_module != module and target_module not in graph[module]:
                add(module, path, 1, "XML-DEP",
                    f"Reference {value} requires a declared dependency on {target_module}")
            if target_id not in defined[target_module]:
                add(module, path, 1, "XML-UNRESOLVED",
                    f"Reference {value} not found in local XML declarations; check CSV, generated IDs and data files")
        # External Odoo XML IDs cannot be verified without an Odoo registry.
    return {key: len(value) for key, value in defined.items()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="audit-report/architecture.json")
    args = parser.parse_args()
    folders = modules()
    manifests = {module: manifest(module, folder) for module, folder in folders.items()}
    graph = dependencies(folders, manifests)
    scan_python(folders)
    ids = scan_xml(folders, graph)
    ordered = sorted(findings, key=lambda f: (f["module"], f["path"], f["line"], f["rule"]))
    payload = {"modules": sorted(folders), "dependency_graph": graph, "xml_id_counts": ids,
               "total": len(ordered),
               "rules": dict(collections.Counter(f["rule"] for f in ordered)),
               "findings": ordered,
               "limitations": [
                   "Static heuristics: no registry, database or external addon validation.",
                   "super() may be delegated; identical bodies may be intentional.",
                   "XML references via eval, QWeb, Python and CSV are not exhaustively resolved.",
               ]}
    target = ROOT / args.output
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")
    summary = ["## Odoo architecture audit", "",
               f"Modules: {len(folders)} · Review findings: {len(ordered)}", "",
               "| Rule | Findings |", "| --- | ---: |"]
    summary.extend(f"| {rule} | {count} |" for rule, count in sorted(payload["rules"].items()))
    summary.extend(["", "Findings are advisory; validate with Odoo installation and upgrade tests."])
    (target.parent / "architecture-summary.md").write_text("\n".join(summary) + "\n",
                                                          encoding="utf-8")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
