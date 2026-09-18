#!/usr/bin/env python3

import argparse
import os
import re
from pathlib import Path


def required_match(pattern: str, text: str, description: str) -> re.Match[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if match is None:
        raise SystemExit(f"missing {description}")
    return match


parser = argparse.ArgumentParser()
parser.add_argument("log", type=Path)
parser.add_argument("case")
args = parser.parse_args()

text = args.log.read_text()
stack = required_match(
    r"FREEBSD_STACK_DIAGNOSTIC stack_base=(0x[0-9a-f]+) "
    r"stack_size=(0x[0-9a-f]+) pthread_guard_size=(0x[0-9a-f]+)",
    text,
    "pthread stack metadata",
)
rust_guard = required_match(
    r"FREEBSD_STACK_DIAGNOSTIC rust_recorded_guard="
    r"(0x[0-9a-f]+)\.\.(0x[0-9a-f]+)",
    text,
    "Rust guard interval",
)
kernel_guard = required_match(
    r"FREEBSD_STACK_DIAGNOSTIC kernel_guard_pages_result=0 "
    r"kernel_guard_pages=([0-9]+)",
    text,
    "kernel guard-page count",
)

stack_base = int(stack.group(1), 16)
stack_size = int(stack.group(2), 16)
pthread_guard_size = int(stack.group(3), 16)
rust_guard_start = int(rust_guard.group(1), 16)
rust_guard_end = int(rust_guard.group(2), 16)
kernel_guard_pages = int(kernel_guard.group(1))
page_size = os.sysconf("SC_PAGE_SIZE")

if rust_guard_start != stack_base - pthread_guard_size or rust_guard_end != stack_base:
    raise SystemExit("reported Rust guard interval does not match pthread metadata")
if kernel_guard_pages < 1:
    raise SystemExit("FreeBSD kernel stack guard is disabled")

memory_lines = re.findall(
    r"^0x[0-9a-f]+:\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s*$", text, re.MULTILINE
)
if len(memory_lines) < 3:
    raise SystemExit("missing raw siginfo memory dump")
fault_address = int(memory_lines[1][1], 16)

kernel_guard_end = stack_base + kernel_guard_pages * page_size
if not stack_base <= fault_address < kernel_guard_end:
    raise SystemExit(
        f"fault {fault_address:#x} is outside expected kernel guard "
        f"{stack_base:#x}..{kernel_guard_end:#x}"
    )
if rust_guard_start <= fault_address < rust_guard_end:
    raise SystemExit(f"fault {fault_address:#x} unexpectedly lies in Rust's recorded guard")

fault_mapping = None
for line in text.splitlines():
    fields = line.split()
    if len(fields) < 10 or not fields[1].startswith("0x"):
        continue
    try:
        start = int(fields[1], 16)
        end = int(fields[2], 16)
    except ValueError:
        continue
    if start <= fault_address < end:
        fault_mapping = fields
        break

if fault_mapping is None:
    raise SystemExit(f"procstat did not report a mapping for fault {fault_address:#x}")
if fault_mapping[3] != "---" or fault_mapping[9] != "gd":
    raise SystemExit(
        "fault mapping is not an inaccessible guard mapping: " + " ".join(fault_mapping)
    )

for marker in (
    "entered_wasmtime_trap_handler",
    "delegated_to_previous_handler",
    "entered_rust_stack_overflow_handler",
):
    if text.splitlines().count(f"FREEBSD_STACK_DIAGNOSTIC {marker}") != 1:
        raise SystemExit(f"expected exactly one {marker} marker")

required_match(
    r"Process [0-9]+ exited with status = 11 ", text, "final raw SIGSEGV status"
)

print(
    "FREEBSD_STACK_VERDICT "
    f"case={args.case!r} stack={stack_base:#x}..{stack_base + stack_size:#x} "
    f"rust_guard={rust_guard_start:#x}..{rust_guard_end:#x} "
    f"kernel_guard={stack_base:#x}..{kernel_guard_end:#x} "
    f"fault={fault_address:#x} mapping={fault_mapping[3]}/{fault_mapping[9]} "
    "handlers=wasmtime,delegate,rust result=SIGSEGV"
)
