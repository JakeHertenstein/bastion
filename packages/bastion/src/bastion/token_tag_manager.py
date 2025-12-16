"""Token tag manager for automatic tag updates based on token operations."""

from typing import List, Tuple

from bastion.models import Account
from bastion.op_client import OpClient
from bastion.tag_operations import TagOperations
from bastion.token_analyzer import TokenAnalyzer


class TokenTagManager:
    """Manage automatic tag updates for token operations."""
    
    # Map token types to their corresponding tags
    TOKEN_TYPE_TAG_MAP = {
        "YubiKey": "Bastion/2FA/TOTP/YubiKey",
        "Phone App": "Bastion/2FA/TOTP/Phone-App",
        "SMS": "Bastion/2FA/TOTP/SMS",
        "WebAuthn Device": "Bastion/2FA/FIDO2-Hardware",
        "Hardware Token": "Bastion/2FA/Hardware-Token",
        "Biometric Key": "Bastion/2FA/Biometric",
    }
    
    BASE_TAGS = ["Bastion"]
    
    def __init__(self, op_client: OpClient, tag_ops: TagOperations):
        """
        Initialize tag manager.
        
        Args:
            op_client: 1Password client
            tag_ops: Tag operations handler
        """
        self.op_client = op_client
        self.tag_ops = tag_ops
    
    def auto_add_tags_for_token(
        self,
        account: Account,
        token_type: str
    ) -> Tuple[bool, List[str]]:
        """
        Auto-add appropriate tags when token is added.
        
        Args:
            account: Account object with current tags
            token_type: Token type being added
            
        Returns:
            (success, added_tags)
        """
        added_tags = []
        
        # Ensure base Bastion tag exists
        for base_tag in self.BASE_TAGS:
            if not any(t == base_tag for t in account.tag_list):
                success, msg, _ = self.tag_ops.add_tag(account, base_tag)
                if success:
                    added_tags.append(base_tag)
        
        # Add type-specific tag
        if token_type in self.TOKEN_TYPE_TAG_MAP:
            type_tag = self.TOKEN_TYPE_TAG_MAP[token_type]
            if not any(t == type_tag for t in account.tag_list):
                success, msg, _ = self.tag_ops.add_tag(account, type_tag)
                if success:
                    added_tags.append(type_tag)
        
        return (True, added_tags)
    
    def auto_remove_tags_for_token(
        self,
        account: Account,
        uuid: str,
        token_type: str
    ) -> Tuple[bool, List[str], List[str]]:
        """
        Auto-remove type tag if this is the last token of this type.
        
        Args:
            account: Account object
            uuid: Item UUID
            token_type: Token type being removed
            
        Returns:
            (success, removed_tags, warnings)
        """
        removed_tags = []
        warnings = []
        
        # Fetch current item state
        item = self.op_client.get_item(uuid)
        if not item:
            return (False, [], ["Could not fetch item for tag cleanup"])
        
        # Analyze tokens
        analyzer = TokenAnalyzer(item)
        token_counts = analyzer.count_tokens_by_type()
        
        # If no tokens of this type remain, remove type tag
        if token_counts.get(token_type, 0) == 0:
            type_tag = self.TOKEN_TYPE_TAG_MAP.get(token_type)
            if type_tag and type_tag in account.tag_list:
                success, msg, _ = self.tag_ops.remove_tag(account, type_tag)
                if success:
                    removed_tags.append(type_tag)
        
        # Warn if no TOTP/2FA tokens remain at all
        total_tokens = sum(token_counts.values())
        if total_tokens == 0:
            warnings.append(
                "This item has no remaining authenticator tokens. "
                "Consider reviewing 2FA setup."
            )
        
        return (True, removed_tags, warnings)
    
    def get_expected_tags_for_item(self, uuid: str) -> List[str]:
        """
        Calculate expected tags based on actual token structure.
        
        Args:
            uuid: Item UUID
            
        Returns:
            List of tags that should be present
        """
        expected_tags = []
        
        # Fetch item
        item = self.op_client.get_item(uuid)
        if not item:
            return expected_tags
        
        # Analyze tokens
        analyzer = TokenAnalyzer(item)
        token_counts = analyzer.count_tokens_by_type()
        
        # Base tag if any tokens exist
        if sum(token_counts.values()) > 0:
            expected_tags.extend(self.BASE_TAGS)
        
        # Type-specific tags
        for token_type, count in token_counts.items():
            if count > 0 and token_type in self.TOKEN_TYPE_TAG_MAP:
                type_tag = self.TOKEN_TYPE_TAG_MAP[token_type]
                if type_tag not in expected_tags:
                    expected_tags.append(type_tag)
        
        return expected_tags
    
    def sync_tags_to_tokens(self, account: Account, uuid: str) -> Tuple[bool, List[str], List[str]]:
        """
        Synchronize tags to match actual token structure.
        
        Adds missing tags and removes inappropriate tags.
        
        Args:
            account: Account object
            uuid: Item UUID
            
        Returns:
            (success, added_tags, removed_tags)
        """
        added_tags = []
        removed_tags = []
        
        # Get expected tags
        expected_tags = self.get_expected_tags_for_item(uuid)
        current_tags = set(account.tag_list)
        
        # Tags to add
        for tag in expected_tags:
            if tag not in current_tags:
                success, msg, _ = self.tag_ops.add_tag(account, tag)
                if success:
                    added_tags.append(tag)
        
        # Tags to remove (only remove token-type tags, not other tags)
        all_token_tags = set(self.TOKEN_TYPE_TAG_MAP.values())
        for tag in current_tags:
            if tag in all_token_tags and tag not in expected_tags:
                success, msg, _ = self.tag_ops.remove_tag(account, tag)
                if success:
                    removed_tags.append(tag)
        
        return (True, added_tags, removed_tags)
