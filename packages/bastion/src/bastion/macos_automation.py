"""macOS automation utilities for 1Password UI interaction.

This module provides functions to automate 1Password desktop app via
AppleScript/System Events for operations not available through the CLI,
such as opening items for manual "Copy as JSON" operations.

Requirements:
- macOS only
- 1Password 8 desktop app

Note: Full automation of "Copy as JSON" is fragile due to 1Password's UI.
This module focuses on reliably opening items so users can manually copy.
"""

from __future__ import annotations

import platform
import subprocess
import time


class MacOSAutomationError(Exception):
    """Raised when macOS automation fails."""
    pass


def is_macos() -> bool:
    """Check if running on macOS."""
    return platform.system() == "Darwin"


def run_applescript(script: str, timeout: int = 30) -> str:
    """Run an AppleScript and return the result.
    
    Args:
        script: AppleScript code to execute
        timeout: Maximum seconds to wait
        
    Returns:
        Script output as string
        
    Raises:
        MacOSAutomationError: If script fails or times out
    """
    if not is_macos():
        raise MacOSAutomationError("AppleScript only available on macOS")
    
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        if result.returncode != 0:
            error_msg = result.stderr.strip() or "Unknown AppleScript error"
            if "not allowed assistive access" in error_msg.lower():
                raise MacOSAutomationError(
                    "Accessibility permissions required. "
                    "Go to System Settings → Privacy & Security → Accessibility "
                    "and enable access for Terminal (or your IDE)."
                )
            raise MacOSAutomationError(f"AppleScript failed: {error_msg}")
        
        return result.stdout.strip()
    
    except subprocess.TimeoutExpired:
        raise MacOSAutomationError(f"AppleScript timed out after {timeout}s")
    except subprocess.SubprocessError as e:
        raise MacOSAutomationError(f"Failed to run AppleScript: {e}")


def is_1password_running() -> bool:
    """Check if 1Password app is running."""
    if not is_macos():
        return False
    
    script = '''
    tell application "System Events"
        return (name of processes) contains "1Password"
    end tell
    '''
    try:
        result = run_applescript(script)
        return result.lower() == "true"
    except MacOSAutomationError:
        return False


def activate_1password() -> None:
    """Bring 1Password app to foreground.
    
    Raises:
        MacOSAutomationError: If activation fails
    """
    script = '''
    tell application "1Password"
        activate
    end tell
    delay 0.3
    '''
    run_applescript(script)


def activate_terminal() -> bool:
    """Bring Terminal/iTerm/VS Code back to foreground.
    
    Detects and activates the terminal application, trying common ones
    in order: VS Code, Cursor, iTerm2, Terminal.app.
    
    Returns:
        True if a terminal was activated
    """
    if not is_macos():
        return False
    
    # Try to activate common terminal apps in order of preference
    terminal_apps = [
        "Code",           # VS Code
        "Cursor",         # Cursor IDE
        "iTerm2",         # iTerm
        "iTerm",          # iTerm (alt name)
        "Terminal",       # macOS Terminal
    ]
    
    for app_name in terminal_apps:
        script = f'''
        tell application "System Events"
            if exists (process "{app_name}") then
                tell application "{app_name}" to activate
                return "activated"
            end if
        end tell
        return "not found"
        '''
        try:
            result = run_applescript(script, timeout=5)
            if result == "activated":
                return True
        except MacOSAutomationError:
            continue
    
    return False


def get_1password_item_link(item_id: str) -> str | None:
    """Get the 1Password share link for an item using op CLI.
    
    Uses `op item get --share-link` to get the official internal link,
    which includes account, host, vault, and item IDs.
    
    Args:
        item_id: Item UUID
        
    Returns:
        Share link URL or None if failed
    """
    try:
        result = subprocess.run(
            ["op", "item", "get", item_id, "--share-link"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        pass
    return None


def open_1password_item(item_id: str, vault_id: str | None = None) -> bool:
    """Open 1Password directly to a specific item using URL scheme.
    
    Gets the official share link via op CLI and converts it to the
    onepassword:// URL scheme to open directly in the desktop app.
    
    Args:
        item_id: Item UUID
        vault_id: Optional vault UUID (unused, kept for API compatibility)
        
    Returns:
        True if URL was opened successfully
    """
    if not is_macos():
        return False
    
    # Get the official share link from op CLI
    # Format: https://start.1password.com/open/i?a=ACCOUNT&h=HOST&i=ITEM&v=VAULT
    share_link = get_1password_item_link(item_id)
    
    if share_link and share_link.startswith("https://start.1password.com/open/"):
        # Convert to onepassword:// scheme
        # https://start.1password.com/open/i?... -> onepassword://open/i?...
        url = share_link.replace("https://start.1password.com/", "onepassword://")
    else:
        # Fallback to simple format if op CLI fails
        if vault_id:
            url = f"onepassword://open-item?v={vault_id}&i={item_id}"
        else:
            url = f"onepassword://open-item?i={item_id}"
    
    try:
        subprocess.run(["open", url], check=True, timeout=5)
        return True
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return False


def open_item_and_prompt(item_id: str, vault_id: str | None = None) -> bool:
    """Open 1Password directly to a specific item for manual JSON copy.
    
    Opens 1Password directly to the item using its UUID, positioning
    the user to right-click and "Copy as JSON".
    
    Args:
        item_id: Item UUID
        vault_id: Optional vault UUID (improves reliability)
        
    Returns:
        True if 1Password was opened successfully
    """
    if not is_macos():
        return False
    
    # First try direct item URL scheme (most reliable)
    if open_1password_item(item_id, vault_id):
        # Give 1Password time to open the item
        time.sleep(0.8)
        return True
    
    # Fallback: just activate 1Password
    try:
        activate_1password()
        return True
    except MacOSAutomationError:
        return False


def show_notification(title: str, message: str, sound: bool = False) -> None:
    """Show a macOS notification.
    
    Args:
        title: Notification title
        message: Notification body
        sound: Whether to play notification sound
    """
    if not is_macos():
        return
    
    # Escape quotes for AppleScript
    title_escaped = title.replace('"', '\\"')
    message_escaped = message.replace('"', '\\"')
    
    sound_part = 'sound name "default"' if sound else ""
    script = f'''
    display notification "{message_escaped}" with title "{title_escaped}" {sound_part}
    '''
    
    try:
        run_applescript(script, timeout=5)
    except MacOSAutomationError:
        pass  # Notifications are best-effort


def ring_bell() -> None:
    """Ring the terminal bell."""
    print("\a", end="", flush=True)


def wait_for_clipboard_change(
    original_content: str,
    timeout: float = 60.0,
    check_interval: float = 0.5,
) -> str | None:
    """Wait for clipboard content to change.
    
    Polls the clipboard until content differs from original_content.
    
    Args:
        original_content: The content to compare against
        timeout: Maximum seconds to wait
        check_interval: Seconds between clipboard checks
        
    Returns:
        New clipboard content, or None if timeout
    """
    if not is_macos():
        return None
    
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        current = get_clipboard_content()
        if current != original_content:
            return current
        time.sleep(check_interval)
    
    return None


def get_clipboard_content() -> str:
    """Get current clipboard content as string.
    
    Returns:
        Clipboard content, or empty string if not text
    """
    if not is_macos():
        return ""
    
    try:
        result = subprocess.run(
            ["pbpaste"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout if result.returncode == 0 else ""
    except subprocess.SubprocessError:
        return ""


def clear_clipboard() -> bool:
    """Clear the clipboard content.
    
    Returns:
        True if successful
    """
    if not is_macos():
        return False
    
    try:
        # Set clipboard to empty string
        result = subprocess.run(
            ["pbcopy"],
            input="",
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except subprocess.SubprocessError:
        return False
