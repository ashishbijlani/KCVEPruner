#!/usr/bin/env python3
        
"""         
Filter Linux kernel CVEs based on whether their vulnerable source paths
were compiled in a configured/built kernel tree.
    
Classification:
    true_positive:
        At least one vulnerable source path was compiled.

    false_positive:
        Vulnerable paths were identified, but none were compiled.
            
    unknown:
        No usable vulnerable paths were identified, or the paths cannot
        be mapped reliably to compiled objects.
    
Example:
    python3 filter_compiled_cves.py \
        cve_paths.csv \
        --kernel-build ~/linux \
        --output-dir cve_compiled_results
"""
    
from __future__ import annotations
    
import argparse
import ast
import csv
import json
import os
import re
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Iterable

import matplotlib.pyplot as plt
        
        
SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".s", 
    ".S",
    ".asm",
}   
    
NON_COMPILED_EXTENSIONS = {
    ".h",
    ".hpp",
    ".txt",
    ".rst",
    ".md",
    ".yaml",
    ".yml", 
    ".json",
    ".xml",
}           

def expand_path(path: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(path))).resolve()
    
def normalize_kernel_path(raw_path: str) -> str:
    """
    Normalize a path from the CVE CSV into a Linux source-tree-relative path.
    
    Handles examples such as:
        a/drivers/usb/core/config.c
        b/drivers/usb/core/config.c
        linux/drivers/usb/core/config.c
        ./drivers/usb/core/config.c
        drivers/usb/core/config.c:123
    """
    path = raw_path.strip().strip("'\"")

    if not path:
        return ""

    path = path.replace("\\", "/")

    # Remove URL-style fragments and query strings.
    path = path.split("#", 1)[0]
    path = path.split("?", 1)[0]

    # Remove a trailing source line number:
    # drivers/foo.c:123 or drivers/foo.c:123:45
    path = re.sub(
        r"(?i)(\.(?:c|cc|cpp|cxx|h|hpp|s|asm)):\d+(?::\d+)?$",
        r"\1",
        path,
    )

    while path.startswith("./"):
        path = path[2:]

    for prefix in ("a/", "b/"):
        if path.startswith(prefix):
            path = path[len(prefix):]

    # Strip common repository-name prefixes.
    for prefix in (
        "linux/",
        "linux-kernel/",
        "linux-stable/",
        "src/linux/",
    ):
        if path.startswith(prefix):
            path = path[len(prefix):]
            break

    # Reject obvious URLs.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", path):
        return ""

    # Prevent paths from escaping the kernel tree.
    normalized = str(PurePosixPath(path))

    if normalized in {"", "."}:
        return ""

    if normalized.startswith("../") or "/../" in normalized:
        return ""

    return normalized.lstrip("/")

def split_paths(value: str | None) -> list[str]:
    """
    Parse the CSV's paths field.

    Supported representations:
        drivers/foo.c;drivers/bar.c
        drivers/foo.c, drivers/bar.c
        ["drivers/foo.c", "drivers/bar.c"]
        'drivers/foo.c'
    """
    if value is None:
        return []

    text = str(value).strip()

    if not text or text.lower() in {"nan", "none", "null", "unknown"}:
        return []

    parsed_items: list[str] = []

    # First try JSON/Python list representations.
    if text.startswith("[") and text.endswith("]"):
        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(text)
                if isinstance(parsed, (list, tuple, set)):
                    parsed_items = [str(item) for item in parsed]
                    break
            except (json.JSONDecodeError, ValueError, SyntaxError):
                continue

    if not parsed_items:
        # Semicolon is preferred because CSV paths often use semicolon separators.
        if ";" in text:
            parsed_items = text.split(";")
        elif "|" in text:
            parsed_items = text.split("|")
        elif "\n" in text:
            parsed_items = text.splitlines()
        else:
            parsed_items = [text]

    result: list[str] = []
    seen: set[str] = set()

    for item in parsed_items:
        normalized = normalize_kernel_path(item)
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)

    return result

def source_to_object_path(source_path: str) -> str | None:
    """
    Convert a compilable source file path to its expected object path.

    Examples:
        drivers/usb/core/config.c -> drivers/usb/core/config.o
        arch/x86/entry/entry_64.S -> arch/x86/entry/entry_64.o
    """
    path = PurePosixPath(source_path)
    suffix = path.suffix

    if suffix not in SOURCE_EXTENSIONS:
        return None

    return str(path.with_suffix(".o"))


def load_manifest_paths(build_dir: Path, filename: str) -> set[str]:
    """
    Load paths from modules.order or modules.builtin.

    modules.order usually contains paths such as:
        drivers/usb/foo.ko

    modules.builtin may contain:
        kernel/drivers/usb/foo.ko
    """
    manifest = build_dir / filename
    paths: set[str] = set()

    if not manifest.is_file():
        return paths

    with manifest.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            item = line.strip().replace("\\", "/")
            if not item:
                continue

            if item.startswith("kernel/"):
                item = item[len("kernel/"):]

            paths.add(item)

    return paths

def load_cmd_targets(build_dir: Path) -> set[str]:
    """
    Inspect Kbuild .cmd files to find known compilation targets.

    This helps in cases where object-file checks alone are insufficient.
    """
    targets: set[str] = set()

    for cmd_file in build_dir.rglob(".*.cmd"):
        try:
            relative_cmd = cmd_file.relative_to(build_dir)
        except ValueError:
            continue

        name = relative_cmd.name

        # Example:
        #   drivers/usb/core/.config.o.cmd
        # becomes:
        #   drivers/usb/core/config.o
        if name.startswith(".") and name.endswith(".cmd"):
            target_name = name[1:-4]
            target = relative_cmd.parent / target_name
            targets.add(target.as_posix())

    return targets


def build_compilation_index(build_dir: Path) -> dict[str, set[str]]:
    """
    Build indexes used to identify compiled files.
    """
    print(f"Indexing compiled kernel tree: {build_dir}")

    object_paths: set[str] = set()

    for object_file in build_dir.rglob("*.o"):
        try:
            object_paths.add(object_file.relative_to(build_dir).as_posix())
        except ValueError:
            continue

    cmd_targets = load_cmd_targets(build_dir)
    modules_order = load_manifest_paths(build_dir, "modules.order")
    modules_builtin = load_manifest_paths(build_dir, "modules.builtin")

    print(f"  Object files:       {len(object_paths):,}")
    print(f"  Kbuild CMD targets: {len(cmd_targets):,}")
    print(f"  Ordered modules:    {len(modules_order):,}")
    print(f"  Built-in modules:   {len(modules_builtin):,}")

    return {
        "objects": object_paths,
        "cmd_targets": cmd_targets,
        "modules_order": modules_order,
        "modules_builtin": modules_builtin,
    }

def matching_module_paths(
    object_path: str,
    module_paths: Iterable[str],
) -> list[str]:
    """
    Find module manifest entries related to an object path.

    The direct mapping foo.o -> foo.ko is useful for simple modules.
    Composite modules are normally detected through their component .o files.
    """
    expected_ko = str(PurePosixPath(object_path).with_suffix(".ko"))

    return [
        module_path
        for module_path in module_paths
        if module_path == expected_ko
    ]

def check_source_path(
    source_path: str,
    build_dir: Path,
    source_dir: Path,
    index: dict[str, set[str]],
) -> dict[str, str | bool]:
    """
    Determine whether a vulnerable source path was compiled.
    """
    object_path = source_to_object_path(source_path)
    source_exists = (source_dir / source_path).is_file()

    result: dict[str, str | bool] = {
        "source_path": source_path,
        "source_exists": source_exists,
        "object_path": object_path or "",
        "compiled": False,
        "evidence": "",
        "reason": "",
    }

    suffix = PurePosixPath(source_path).suffix

    if object_path is None:
        if suffix in NON_COMPILED_EXTENSIONS:
            result["reason"] = (
                f"{suffix or 'non-source'} file cannot be mapped directly "
                "to a compilation unit"
            )
        elif not suffix:
            result["reason"] = "path has no recognized source-file extension"
        else:
            result["reason"] = f"unsupported source-file extension: {suffix}"
        return result

    object_on_disk = build_dir / object_path

    if object_path in index["objects"] or object_on_disk.is_file():
        result["compiled"] = True
        result["evidence"] = object_path
        result["reason"] = "corresponding object file exists"
        return result

    if object_path in index["cmd_targets"]:
        result["compiled"] = True
        result["evidence"] = f".{PurePosixPath(object_path).name}.cmd"
        result["reason"] = "Kbuild command file records object compilation"
        return result

    module_matches = matching_module_paths(
        object_path,
        index["modules_order"] | index["modules_builtin"],
    )

    if module_matches:
        result["compiled"] = True
        result["evidence"] = ";".join(module_matches)
        result["reason"] = "corresponding loadable or built-in module is listed"
        return result

    if not source_exists:
        result["reason"] = "source path is absent from this kernel source tree"
    else:
        result["reason"] = "source exists, but no compiled object was found"

    return result

def classify_cve(path_results: list[dict[str, str | bool]]) -> str:
    """
    Classify one CVE based on all of its vulnerable paths.
    """
    if not path_results:
        return "unknown"

    compilable_results = [
        result
        for result in path_results
        if bool(result.get("object_path"))
    ]

    if not compilable_results:
        return "unknown"

    if any(bool(result["compiled"]) for result in compilable_results):
        return "true_positive"

    return "false_positive"


def serialize_list(values: Iterable[str]) -> str:
    return ";".join(value for value in values if value)


def process_csv(
    input_csv: Path,
    detailed_csv: Path,
    summary_csv: Path,
    build_dir: Path,
    source_dir: Path,
    index: dict[str, set[str]],
) -> Counter:
    counts: Counter = Counter()

    with input_csv.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as input_handle:
        reader = csv.DictReader(input_handle)

        if not reader.fieldnames:
            raise ValueError("Input CSV has no header")

        if "cve" not in reader.fieldnames:
            raise ValueError("Input CSV must contain a 'cve' column")

        if "paths" not in reader.fieldnames:
            raise ValueError("Input CSV must contain a 'paths' column")

        original_fields = list(reader.fieldnames)

        summary_fields = original_fields + [
            "compiled_classification",
            "usable_path_count",
            "compiled_path_count",
            "uncompiled_path_count",
            "unmappable_path_count",
            "compiled_paths",
            "uncompiled_paths",
            "unmappable_paths",
            "compiled_objects",
            "compilation_evidence",
        ]

        detailed_fields = [
            "cve",
            "source_path",
            "source_exists",
            "object_path",
            "compiled",
            "evidence",
            "reason",
        ]

        with (
            summary_csv.open(
                "w",
                encoding="utf-8",
                newline="",
            ) as summary_handle,
            detailed_csv.open(
                "w",
                encoding="utf-8",
                newline="",
            ) as detailed_handle,
        ):
            summary_writer = csv.DictWriter(
                summary_handle,
                fieldnames=summary_fields,
                extrasaction="ignore",
            )
            detailed_writer = csv.DictWriter(
                detailed_handle,
                fieldnames=detailed_fields,
            )

            summary_writer.writeheader()
            detailed_writer.writeheader()

            for row in reader:
                cve = (row.get("cve") or "").strip()
                vulnerable_paths = split_paths(row.get("paths"))
                path_results = [
                    check_source_path(
                        source_path=path,
                        build_dir=build_dir,
                        source_dir=source_dir,
                        index=index,
                    )
                    for path in vulnerable_paths
                ]

                classification = classify_cve(path_results)
                counts[classification] += 1

                compiled_results = [
                    result
                    for result in path_results
                    if bool(result["compiled"])
                ]
                uncompiled_results = [
                    result
                    for result in path_results
                    if result["object_path"] and not bool(result["compiled"])
                ]
                unmappable_results = [
                    result
                    for result in path_results
                    if not result["object_path"]
                ]

                for result in path_results:
                    detailed_writer.writerow(
                        {
                            "cve": cve,
                            **result,
                        }
                    )

                output_row = dict(row)
                output_row.update(
                    {
                        "compiled_classification": classification,
                        "usable_path_count": len(
                            compiled_results + uncompiled_results
                        ),
                        "compiled_path_count": len(compiled_results),
                        "uncompiled_path_count": len(uncompiled_results),
                        "unmappable_path_count": len(unmappable_results),
                        "compiled_paths": serialize_list(
                            str(result["source_path"])
                            for result in compiled_results
                        ),
                        "uncompiled_paths": serialize_list(
                            str(result["source_path"])
                            for result in uncompiled_results
                        ),
                        "unmappable_paths": serialize_list(
                            str(result["source_path"])
                            for result in unmappable_results
                        ),
                        "compiled_objects": serialize_list(
                            str(result["object_path"])
                            for result in compiled_results
                        ),
                        "compilation_evidence": serialize_list(
                            str(result["evidence"])
                            for result in compiled_results
                        ),
                    }
                )

                summary_writer.writerow(output_row)

    return counts


def draw_pie_chart(
    counts: Counter,
    output_path: Path,
    include_unknown: bool,
) -> None:
    labels: list[str] = []
    values: list[int] = []

    chart_entries = [
        ("true_positive", "True positives"),
        ("false_positive", "False positives"),
    ]

    if include_unknown:
        chart_entries.append(("unknown", "Unknown / no usable path"))

    for key, label in chart_entries:
        count = counts.get(key, 0)
        if count > 0:
            labels.append(f"{label}\n(n={count:,})")
            values.append(count)

    if not values:
        print("No classified CVEs available for the pie chart.")
        return

    fig, ax = plt.subplots(figsize=(9, 7))

    ax.pie(
        values,
        labels=labels,
        autopct=lambda percentage: f"{percentage:.1f}%",
        startangle=90,
        counterclock=False,
        textprops={"fontsize": 12},
        wedgeprops={
            "linewidth": 1,
            "edgecolor": "white",
        },
    )

    title = "Kernel CVEs after compiled-path filtering"
    if not include_unknown and counts.get("unknown", 0):
        title += "\n(CVEs with unknown paths excluded)"

    ax.set_title(title, fontsize=15)
    ax.axis("equal")

    fig.tight_layout()
    fig.savefig(output_path, dpi=220, bbox_inches="tight")
    plt.close(fig)


def write_counts_csv(counts: Counter, output_path: Path) -> None:
    total = sum(counts.values())

    with output_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(["classification", "count", "percentage"])

        for classification in (
            "true_positive",
            "false_positive",
            "unknown",
        ):
            count = counts.get(classification, 0)
            percentage = (count / total * 100.0) if total else 0.0
            writer.writerow(
                [
                    classification,
                    count,
                    f"{percentage:.2f}",
                ]
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Filter Linux kernel CVEs based on whether vulnerable "
            "source paths were compiled."
        )
    )

    parser.add_argument(
        "input_csv",
        help="CSV containing at least the columns 'cve' and 'paths'",
    )
    parser.add_argument(
        "--kernel-build",
        default="~/linux",
        help="Compiled kernel tree or out-of-tree build directory",
    )
    parser.add_argument(
        "--kernel-source",
        default=None,
        help=(
            "Kernel source tree. Defaults to --kernel-build. "
            "Set this when using make O=/separate/build."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default="cve_compiled_results",
        help="Directory for CSV and chart outputs",
    )
    parser.add_argument(
        "--include-unknown-in-chart",
        action="store_true",
        help="Include CVEs without usable vulnerable paths in the pie chart",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    input_csv = expand_path(args.input_csv)
    build_dir = expand_path(args.kernel_build)
    source_dir = (
        expand_path(args.kernel_source)
        if args.kernel_source
        else build_dir
    )
    output_dir = expand_path(args.output_dir)

    if not input_csv.is_file():
        raise FileNotFoundError(f"Input CSV not found: {input_csv}")

    if not build_dir.is_dir():
        raise NotADirectoryError(
            f"Kernel build directory not found: {build_dir}"
        )

    if not source_dir.is_dir():
        raise NotADirectoryError(
            f"Kernel source directory not found: {source_dir}"
        )

    if not (build_dir / ".config").is_file():
        print(
            f"Warning: {build_dir / '.config'} does not exist. "
            "Verify that --kernel-build points to a compiled kernel tree."
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    summary_csv = output_dir / "cves_compiled_classification.csv"
    detailed_csv = output_dir / "cve_path_compilation_details.csv"
    counts_csv = output_dir / "classification_counts.csv"
    pie_chart = output_dir / "compiled_cve_pie_chart.png"

    index = build_compilation_index(build_dir)

    counts = process_csv(
        input_csv=input_csv,
        detailed_csv=detailed_csv,
        summary_csv=summary_csv,
        build_dir=build_dir,
        source_dir=source_dir,
        index=index,
    )

    write_counts_csv(counts, counts_csv)

    draw_pie_chart(
        counts=counts,
        output_path=pie_chart,
        include_unknown=args.include_unknown_in_chart,
    )

    evaluable = (
        counts.get("true_positive", 0)
        + counts.get("false_positive", 0)
    )

    print()
    print("Classification results")
    print("----------------------")
    print(f"True positives:  {counts.get('true_positive', 0):,}")
    print(f"False positives: {counts.get('false_positive', 0):,}")
    print(f"Unknown:         {counts.get('unknown', 0):,}")

    if evaluable:
        false_positive_rate = (
            counts.get("false_positive", 0) / evaluable * 100.0
        )
        print(
            f"False-positive pruning rate among evaluable CVEs: "
            f"{false_positive_rate:.2f}%"
        )

    print()
    print(f"Summary CSV:     {summary_csv}")
    print(f"Path details:    {detailed_csv}")
    print(f"Counts CSV:      {counts_csv}")
    print(f"Pie chart:       {pie_chart}")

    return 0


