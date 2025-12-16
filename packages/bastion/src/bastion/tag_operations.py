"""Tag management helper functions."""

from typing import Callable

from .models import Account
from .op_client import OpClient


class TagOperations:
    """Helper class for bulk tag operations."""
    
    def __init__(self, op_client: OpClient):
        """Initialize with 1Password client."""
        self.op_client = op_client
    
    def add_tag(self, account: Account, tag: str) -> tuple[bool, str, list[str]]:
        """
        Add a tag to an account.
        
        Returns:
            (success, message, new_tags)
        """
        current_tags = account.tag_list.copy()
        
        # Check if tag already exists (case-insensitive)
        tag_lower = tag.lower()
        if any(t.lower() == tag_lower for t in current_tags):
            return False, f"Tag '{tag}' already exists", current_tags
        
        # Add new tag
        new_tags = current_tags + [tag]
        
        # Update in 1Password
        result = self.op_client.edit_item_tags(account.uuid, new_tags)
        if result is True:
            return True, f"Added tag '{tag}'", new_tags
        else:
            return False, f"Failed to add tag: {result}", current_tags
    
    def remove_tag(self, account: Account, tag: str) -> tuple[bool, str, list[str]]:
        """
        Remove a tag from an account.
        
        Returns:
            (success, message, new_tags)
        """
        current_tags = account.tag_list.copy()
        
        # Find and remove tag (case-insensitive)
        tag_lower = tag.lower()
        removed = False
        new_tags = []
        
        for t in current_tags:
            if t.lower() == tag_lower:
                removed = True
            else:
                new_tags.append(t)
        
        if not removed:
            return False, f"Tag '{tag}' not found", current_tags
        
        # Update in 1Password
        result = self.op_client.edit_item_tags(account.uuid, new_tags)
        if result is True:
            return True, f"Removed tag '{tag}'", new_tags
        else:
            return False, f"Failed to remove tag: {result}", current_tags
    
    def rename_tag(self, account: Account, old_tag: str, new_tag: str) -> tuple[bool, str, list[str]]:
        """
        Rename a tag in an account.
        
        Returns:
            (success, message, new_tags)
        """
        current_tags = account.tag_list.copy()
        
        # Find and replace tag (case-insensitive)
        old_tag_lower = old_tag.lower()
        renamed = False
        new_tags = []
        
        for t in current_tags:
            if t.lower() == old_tag_lower:
                new_tags.append(new_tag)
                renamed = True
            else:
                new_tags.append(t)
        
        if not renamed:
            return False, f"Tag '{old_tag}' not found", current_tags
        
        # Update in 1Password
        result = self.op_client.edit_item_tags(account.uuid, new_tags)
        if result is True:
            return True, f"Renamed tag '{old_tag}' to '{new_tag}'", new_tags
        else:
            return False, f"Failed to rename tag: {result}", current_tags
    
    def replace_tag(self, account: Account, old_tag: str, new_tag: str) -> tuple[bool, str, list[str]]:
        """
        Replace one tag with another (removes old, adds new).
        Alias for rename_tag.
        
        Returns:
            (success, message, new_tags)
        """
        return self.rename_tag(account, old_tag, new_tag)
    
    def bulk_add_tag(
        self,
        accounts: dict[str, Account],
        tag: str,
        filter_fn: Callable[[Account], bool] | None = None,
        dry_run: bool = False,
    ) -> dict[str, tuple[bool, str]]:
        """
        Add a tag to multiple accounts.
        
        Args:
            accounts: Dictionary of accounts by UUID
            tag: Tag to add
            filter_fn: Optional filter function to select accounts
            dry_run: If True, don't actually make changes
        
        Returns:
            Dictionary mapping UUID to (success, message)
        """
        results = {}
        
        for uuid, acc in accounts.items():
            # Apply filter if provided
            if filter_fn and not filter_fn(acc):
                continue
            
            if dry_run:
                # Check if tag would be added
                tag_lower = tag.lower()
                if any(t.lower() == tag_lower for t in acc.tag_list):
                    results[uuid] = (False, f"Tag '{tag}' already exists")
                else:
                    results[uuid] = (True, f"Would add tag '{tag}'")
            else:
                success, message, _ = self.add_tag(acc, tag)
                results[uuid] = (success, message)
        
        return results
    
    def bulk_remove_tag(
        self,
        accounts: dict[str, Account],
        tag: str,
        filter_fn: Callable[[Account], bool] | None = None,
        dry_run: bool = False,
    ) -> dict[str, tuple[bool, str]]:
        """
        Remove a tag from multiple accounts.
        
        Args:
            accounts: Dictionary of accounts by UUID
            tag: Tag to remove
            filter_fn: Optional filter function to select accounts
            dry_run: If True, don't actually make changes
        
        Returns:
            Dictionary mapping UUID to (success, message)
        """
        results = {}
        
        for uuid, acc in accounts.items():
            # Apply filter if provided
            if filter_fn and not filter_fn(acc):
                continue
            
            # Skip if tag doesn't exist
            tag_lower = tag.lower()
            if not any(t.lower() == tag_lower for t in acc.tag_list):
                continue
            
            if dry_run:
                results[uuid] = (True, f"Would remove tag '{tag}'")
            else:
                success, message, _ = self.remove_tag(acc, tag)
                results[uuid] = (success, message)
        
        return results
    
    def bulk_rename_tag(
        self,
        accounts: dict[str, Account],
        old_tag: str,
        new_tag: str,
        dry_run: bool = False,
    ) -> dict[str, tuple[bool, str]]:
        """
        Rename a tag across multiple accounts.
        
        Args:
            accounts: Dictionary of accounts by UUID
            old_tag: Tag to rename
            new_tag: New tag name
            dry_run: If True, don't actually make changes
        
        Returns:
            Dictionary mapping UUID to (success, message)
        """
        results = {}
        
        for uuid, acc in accounts.items():
            # Skip if old tag doesn't exist
            old_tag_lower = old_tag.lower()
            if not any(t.lower() == old_tag_lower for t in acc.tag_list):
                continue
            
            if dry_run:
                results[uuid] = (True, f"Would rename tag '{old_tag}' to '{new_tag}'")
            else:
                success, message, _ = self.rename_tag(acc, old_tag, new_tag)
                results[uuid] = (success, message)
        
        return results
