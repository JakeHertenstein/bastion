"""1Password CLI wrapper."""

import json
import platform
import re
import shlex
import subprocess
import time
from typing import Any

# Tag validation pattern: Bastion/Category/Value format only
TAG_PATTERN = re.compile(r'^Bastion/[A-Za-z0-9]+(/[A-Za-z0-9-]+)*$')

# Legacy patterns for migration detection
LEGACY_SAT_NESTED_PATTERN = re.compile(r'^Bastion/[A-Za-z0-9]+(/[A-Za-z0-9-]+)*$')
LEGACY_SAT_FLAT_PATTERN = re.compile(r'^sat-[a-z0-9-]+$')

# Auth error patterns in op CLI stderr
AUTH_ERROR_PATTERNS = [
    "authorization denied",
    "not signed in",
    "session expired",
    "authentication required",
    "connect: connection refused",
    "error initializing client",
    "connecting to desktop app timed out",
    "desktop app timed out",
]


class OPAuthError(Exception):
    """Raised when 1Password authentication is required.
    
    This exception is raised when the 1Password app is locked or
    the CLI session has expired. It should be caught to implement
    wait-for-unlock behavior.
    
    IMPORTANT: This exception message must NEVER contain sensitive data
    like entropy, passwords, or keys.
    """
    pass


def is_auth_error(stderr: str) -> bool:
    """Check if an error message indicates an authentication issue.
    
    Args:
        stderr: Error output from op CLI
        
    Returns:
        True if error indicates auth/lock issue
    """
    stderr_lower = stderr.lower()
    return any(pattern in stderr_lower for pattern in AUTH_ERROR_PATTERNS)


def is_authenticated() -> bool:
    """Check if 1Password is currently authenticated and unlocked.
    
    Returns:
        True if authenticated, False if locked or not signed in
    """
    try:
        result = subprocess.run(
            ["op", "account", "get", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return False


def send_notification(title: str, message: str) -> None:
    """Send a desktop notification.
    
    Args:
        title: Notification title
        message: Notification body
    """
    if platform.system() == "Darwin":
        # macOS notification via osascript
        script = f'display notification "{message}" with title "{title}"'
        try:
            subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                timeout=5,
            )
        except subprocess.SubprocessError:
            pass  # Notification is best-effort


def wait_for_auth(
    check_interval: int = 5,
    notify: bool = True,
    bell: bool = True,
) -> None:
    """Wait indefinitely for 1Password authentication.
    
    Polls for authentication status and blocks until 1Password is unlocked.
    Optionally sends notifications and terminal bell to alert the user.
    
    Args:
        check_interval: Seconds between auth checks (default 5)
        notify: Send desktop notification when waiting starts (default True)
        bell: Ring terminal bell when waiting starts (default True)
    """
    if is_authenticated():
        return
    
    # Alert user
    if bell:
        print("\a", end="", flush=True)  # Terminal bell
    
    if notify:
        send_notification(
            "Bastion: 1Password Locked",
            "Please unlock 1Password to continue entropy collection"
        )
    
    # Poll for auth
    while not is_authenticated():
        time.sleep(check_interval)
    
    # Second bell when unlocked
    if bell:
        print("\a", end="", flush=True)


def validate_tag(tag: str) -> bool:
    """Validate tag matches Bastion/* format.
    
    Args:
        tag: Tag string to validate
        
    Returns:
        True if valid Bastion tag, False otherwise
    """
    return bool(TAG_PATTERN.match(tag))


def is_legacy_tag(tag: str) -> bool:
    """Check if tag is a legacy Bastion format (needs migration).
    
    Args:
        tag: Tag string to check
        
    Returns:
        True if legacy Bastion/* or sat-* format
    """
    return bool(LEGACY_SAT_NESTED_PATTERN.match(tag) or LEGACY_SAT_FLAT_PATTERN.match(tag))


def sanitize_for_subprocess(value: str) -> str:
    """Sanitize a string value for safe use in subprocess calls.
    
    Args:
        value: String to sanitize
        
    Returns:
        Safely quoted string
    """
    return shlex.quote(value)


class OpClient:
    """Wrapper for op CLI commands."""

    def __init__(self) -> None:
        """Initialize and verify op CLI is available."""
        self._verify_cli()

    def _verify_cli(self) -> None:
        """Check op CLI is installed and authenticated."""
        try:
            result = subprocess.run(
                ["op", "--version"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.version = result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise RuntimeError(
                "1Password CLI (op) not found or not working. "
                "Install from: https://1password.com/downloads/command-line/"
            ) from e

        # Check authentication
        try:
            subprocess.run(
                ["op", "account", "list"],
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                "Not signed in to 1Password. Run: op signin"
            ) from e

    def list_items_by_tag(self, tag: str) -> list[dict[str, Any]]:
        """List all items with a specific tag."""
        try:
            result = subprocess.run(
                ["op", "item", "list", "--tags", tag, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
            )
            return json.loads(result.stdout) if result.stdout else []
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return []
    
    def list_items_with_prefix(self, prefix: str, vault: str | None = None) -> list[dict[str, Any]]:
        """List all items that have any tag starting with the given prefix.
        
        For nested tags like 'Bastion/', this will match 'Bastion/Type/Bank', 'Bastion/2FA/TOTP', etc.
        
        Args:
            prefix: Tag prefix to filter by
            vault: Optional vault name to filter by
        """
        try:
            # Get ALL items first
            cmd = ["op", "item", "list", "--format", "json"]
            if vault:
                cmd.extend(["--vault", vault])
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
            all_items = json.loads(result.stdout) if result.stdout else []
            
            # Filter for items with tags matching prefix
            filtered = []
            for item in all_items:
                tags = item.get("tags", [])
                if any(tag.startswith(prefix) for tag in tags):
                    filtered.append(item)
            
            return filtered
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return []
    
    def list_items_with_tag(self, tag: str, vault: str | None = None) -> list[dict[str, Any]]:
        """List all items with a specific tag (exact match).
        
        Uses the 1Password CLI's native --tags filter for efficiency.
        
        Args:
            tag: Exact tag to filter by (e.g., 'YubiKey/Token')
            vault: Optional vault name to filter by
            
        Returns:
            List of items with the specified tag
        """
        try:
            cmd = ["op", "item", "list", "--tags", tag, "--format", "json"]
            if vault:
                cmd.extend(["--vault", vault])
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
            return json.loads(result.stdout) if result.stdout else []
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return []
    
    def list_all_items(self, vault: str | None = None) -> list[dict[str, Any]]:
        """List all items in 1Password (no filtering).
        
        Args:
            vault: Optional vault name to filter by
        """
        try:
            cmd = ["op", "item", "list", "--format", "json"]
            if vault:
                cmd.extend(["--vault", vault])
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
            return json.loads(result.stdout) if result.stdout else []
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return []

    def get_item(self, uuid: str) -> dict[str, Any] | None:
        """Get full item details by UUID."""
        try:
            result = subprocess.run(
                ["op", "item", "get", uuid, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
            )
            return json.loads(result.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return None

    def get_items_batch(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Get full details for multiple items in a single CLI call.
        
        This is much more efficient than calling get_item() individually for each item.
        Uses `op item get -` which reads item references from stdin.
        
        Args:
            items: List of item dicts (from list_items_*) containing at least 'id' key
            
        Returns:
            List of full item details. Items that fail to fetch are omitted.
        """
        if not items:
            return []
        
        try:
            # Convert items to JSON for stdin (op reads 'id' field from each object)
            items_json = json.dumps(items)
            
            result = subprocess.run(
                ["op", "item", "get", "-", "--format", "json"],
                input=items_json,
                capture_output=True,
                text=True,
                check=True,
            )
            
            # op outputs concatenated JSON objects (not an array, not NDJSON)
            # e.g., {"id": "a", ...}\n{\n  "id": "b"...\n}
            # Use JSONDecoder.raw_decode to parse each object sequentially
            output = result.stdout.strip()
            if not output:
                return []
            
            results = []
            decoder = json.JSONDecoder()
            idx = 0
            while idx < len(output):
                # Skip whitespace
                while idx < len(output) and output[idx] in ' \t\n\r':
                    idx += 1
                if idx >= len(output):
                    break
                # Decode next JSON object - raw_decode returns (obj, end_position)
                # where end_position is the absolute index after the parsed object
                obj, end_idx = decoder.raw_decode(output, idx)
                results.append(obj)
                idx = end_idx  # Move to end of parsed object
            return results
            
        except subprocess.CalledProcessError as e:
            # Don't silently fallback - this would cause many auth prompts
            # Log the error and return empty (caller will see missing items)
            import sys
            print(f"Warning: Batch fetch failed: {e.stderr[:200] if e.stderr else 'unknown error'}", file=sys.stderr)
            return []
        except json.JSONDecodeError:
            return []

    def edit_item_tags(self, uuid: str, tags: list[str]) -> bool:
        """Set item tags (replaces all tags with provided list).
        
        Args:
            uuid: 1Password item UUID
            tags: List of tags to set (must be Bastion/* format or non-Bastion tags)
            
        Returns:
            True on success, error string on failure
            
        Raises:
            ValueError: If any Bastion-prefixed tag doesn't match valid format
        """
        # Validate Bastion tags (non-Bastion tags pass through)
        for tag in tags:
            if tag.startswith("Bastion/") and not validate_tag(tag):
                raise ValueError(
                    f"Invalid Bastion tag format: {tag}. "
                    f"Must match pattern: Bastion/Category/Value"
                )
            # Warn about legacy tags that need migration
            if is_legacy_tag(tag):
                # Allow for now but flag for migration
                pass
        
        # Deduplicate tags before sending to op CLI (case-insensitive)
        seen_lower = {}
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower not in seen_lower:
                seen_lower[tag_lower] = tag
        
        unique_tags = sorted(seen_lower.values())
        tags_str = ",".join(unique_tags)
        
        try:
            # Use assignment syntax (tags=value) which replaces instead of appends
            # UUID is from 1Password, tags_str is validated above
            result = subprocess.run(
                ["op", "item", "edit", uuid, f"tags={tags_str}"],
                capture_output=True,
                text=True,
                check=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            # Return error message for display
            return e.stderr.strip() if e.stderr else "Unknown error"

    def get_current_tags(self, uuid: str) -> list[str]:
        """Get current tags for an item."""
        item = self.get_item(uuid)
        if item and "tags" in item:
            return item.get("tags", [])
        return []
