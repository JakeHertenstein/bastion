#!/usr/bin/env python3
"""Test script for passkey_health module."""

import json
from bastion.passkey_health import (
    is_passkey_healthy, is_passkey_orphaned, has_any_passkey,
    get_passkey_status, transform_to_cli_format, get_item_info_from_export
)

# Load test files
with open('bastion/support/test - before.json') as f:
    before = json.load(f)
with open('bastion/support/test - after.json') as f:
    after = json.load(f)

print('=== test - before.json (healthy) ===')
print(f'  has_any_passkey: {has_any_passkey(before)}')
print(f'  is_passkey_healthy: {is_passkey_healthy(before)}')
print(f'  is_passkey_orphaned: {is_passkey_orphaned(before)}')
print(f'  status: {get_passkey_status(before)}')

print()
print('=== test - after.json (orphaned) ===')
print(f'  has_any_passkey: {has_any_passkey(after)}')
print(f'  is_passkey_healthy: {is_passkey_healthy(after)}')
print(f'  is_passkey_orphaned: {is_passkey_orphaned(after)}')
print(f'  status: {get_passkey_status(after)}')

print()
print('=== Item info ===')
print(f'  before: {get_item_info_from_export(before)}')
print(f'  after: {get_item_info_from_export(after)}')

print()
print('=== Transform to CLI format ===')
cli_json = transform_to_cli_format(after)
print(json.dumps(cli_json, indent=2))
