#!/usr/bin/env python3
"""
1Password integration for Seeder using the official 1Password Python SDK.
Provides secure loading and saving of seed phrases through the 1Password SDK.
"""

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

# 1Password SDK imports
from onepassword import (
    Client,
    ItemCategory,
    ItemCreateParams,
    ItemField,
    ItemFieldType,
    ItemSection,
)

from ..core.exceptions import SeedCardError

# Use standard logging for now
logger = logging.getLogger(__name__)


class OnePasswordError(SeedCardError):
    """Raised when 1Password operations fail."""


@dataclass
class OnePasswordItem:
    """Represents a 1Password item with seed data."""
    id: str
    title: str
    vault: str
    seed_phrase: Optional[str] = None
    seed_type: Optional[str] = None  # BIP-39, SLIP-39, Simple
    card_id: Optional[str] = None
    created_at: Optional[str] = None
    tags: Optional[List[str]] = None


class OnePasswordManager:
    """Manager for 1Password SDK operations."""
    
    def __init__(self):
        self.client: Optional[Client] = None
        self.authenticated = False
    
    async def authenticate(self, 
                          token: Optional[str] = None,
                          integration_name: str = "Seed Card Generator", 
                          integration_version: str = "v1.0.0") -> None:
        """
        Authenticate with 1Password using service account token.
        
        Args:
            token: Service account token (if None, reads from OP_SERVICE_ACCOUNT_TOKEN env var)
            integration_name: Name of the integration
            integration_version: Version of the integration
            
        Raises:
            OnePasswordError: If authentication fails
        """
        try:
            if not token:
                token = os.getenv("OP_SERVICE_ACCOUNT_TOKEN")
                if not token:
                    raise OnePasswordError(
                        "No service account token provided. Set OP_SERVICE_ACCOUNT_TOKEN environment variable "
                        "or pass token parameter."
                    )
            
            self.client = await Client.authenticate(
                auth=token,
                integration_name=integration_name,
                integration_version=integration_version
            )
            self.authenticated = True
            logger.info("Successfully authenticated with 1Password SDK")
            
        except Exception as e:
            raise OnePasswordError(f"1Password authentication failed: {e}") from e
    
    def ensure_authenticated(self) -> None:
        """Ensure client is authenticated, raise error if not."""
        if not self.authenticated or not self.client:
            raise OnePasswordError(
                "Not authenticated with 1Password. Call authenticate() first."
            )
    
    async def list_vaults(self) -> List[Dict[str, str]]:
        """
        List available 1Password vaults.
        
        Returns:
            List of vault dictionaries with id, name
            
        Raises:
            OnePasswordError: If operation fails
        """
        self.ensure_authenticated()
        
        try:
            vaults = await self.client.vaults.list()
            return [{"id": vault.id, "name": vault.title} for vault in vaults]
            
        except Exception as e:
            raise OnePasswordError(f"Failed to list vaults: {e}") from e
    
    async def search_seed_items(self, vault_id: Optional[str] = None, tag: str = "seed-card") -> List[OnePasswordItem]:
        """
        Search for seed-related items in 1Password.
        
        Args:
            vault_id: Specific vault to search (optional, searches all vaults if None)
            tag: Tag to search for (default: "seed-card")
            
        Returns:
            List of OnePasswordItem objects
            
        Raises:
            OnePasswordError: If search fails
        """
        self.ensure_authenticated()
        
        try:
            items = []
            
            if vault_id:
                # Search specific vault
                vault_items = await self._search_vault_items(vault_id, tag)
                items.extend(vault_items)
            else:
                # Search all vaults
                vaults = await self.client.vaults.list()
                for vault in vaults:
                    vault_items = await self._search_vault_items(vault.id, tag)
                    items.extend(vault_items)
            
            logger.info("Found %d seed items in 1Password" % len(items))
            return items
            
        except OnePasswordError:
            raise  # Re-raise OnePasswordError as-is
        except Exception as e:
            raise OnePasswordError(f"Item search failed: {e}") from e
    
    async def _search_vault_items(self, vault_id: str, tag: str) -> List[OnePasswordItem]:
        """Search for seed items in a specific vault."""
        try:
            overviews = await self.client.items.list(vault_id)
            items = []
            
            for overview in overviews:
                # Check if item has the seed-card tag
                if tag in overview.tags:
                    item = OnePasswordItem(
                        id=overview.id,
                        title=overview.title,
                        vault=vault_id,
                        tags=overview.tags,
                        created_at=overview.created_at.isoformat()
                    )
                    items.append(item)
            
            return items
            
        except Exception as e:
            logger.warning(f"Failed to search vault {vault_id}: {e}")
            return []
    
    async def load_seed_phrase(self, vault_id: str, item_id: str) -> Tuple[str, str]:
        """
        Load seed phrase from a 1Password item.
        
        Args:
            vault_id: 1Password vault ID
            item_id: 1Password item ID
            
        Returns:
            Tuple of (seed_phrase, seed_type)
            
        Raises:
            OnePasswordError: If loading fails
        """
        self.ensure_authenticated()
        
        try:
            item = await self.client.items.get(vault_id, item_id)
            
            # Look for seed phrase and type in fields
            seed_phrase = None
            seed_type = "Simple"  # Default
            
            for field in item.fields:
                field_id = field.id.lower()
                field_title = field.title.lower()
                
                # Look for seed phrase (prioritize concealed fields)
                if (field_id == "seed_phrase" or "seed phrase" in field_title or 
                    field_id == "seed" or field_title == "seed"):
                    seed_phrase = field.value
                elif field.field_type == ItemFieldType.CONCEALED and not seed_phrase:
                    # If no explicit seed phrase field, use first concealed field
                    seed_phrase = field.value
                
                # Look for seed type
                if field_id == "seed_type" or "seed type" in field_title:
                    seed_type = field.value
            
            if not seed_phrase:
                raise OnePasswordError(f"No seed phrase found in item {item_id}")
            
            logger.info("Loaded %s seed from 1Password item" % seed_type)
            return seed_phrase, seed_type
            
        except Exception as e:
            raise OnePasswordError(f"Seed loading failed: {e}") from e
    
    async def save_seed_card(self, 
                            card_id: str,
                            seed_phrase: str, 
                            seed_type: str,
                            sha512_hash: str,
                            vault_id: str,
                            title: Optional[str] = None) -> str:
        """
        Save seed card data to 1Password.
        
        Note: Only stores the seed phrase and hash. Token grid is derivable
        from the seed and should be generated on-demand for security.
        
        Args:
            card_id: Unique card identifier
            seed_phrase: Seed phrase (will be stored securely)
            seed_type: Type of seed (BIP-39, SLIP-39, Simple)
            sha512_hash: SHA-512 hash for verification
            vault_id: Target vault ID
            title: Item title (optional, defaults to card_id)
            
        Returns:
            1Password item ID of created item
            
        Raises:
            OnePasswordError: If saving fails
        """
        self.ensure_authenticated()
        
        try:
            if not title:
                title = f"Seed Card {card_id}"
            
            # Create item parameters
            item_params = ItemCreateParams(
                title=title,
                category=ItemCategory.SECURENOTE,
                vaultId=vault_id,
                tags=["seed-card", "crypto", "generated"],
                notes=f"Seed Card {card_id} - Generated on {datetime.now().isoformat()}",
                fields=[
                    ItemField(
                        id="seed_phrase",
                        title="Seed Phrase",
                        fieldType=ItemFieldType.CONCEALED,
                        value=seed_phrase
                    ),
                    ItemField(
                        id="seed_type", 
                        title="Seed Type",
                        fieldType=ItemFieldType.TEXT,
                        value=seed_type
                    ),
                    ItemField(
                        id="card_id",
                        title="Card ID",
                        fieldType=ItemFieldType.TEXT,
                        value=card_id
                    ),
                    ItemField(
                        id="sha512_hash",
                        title="SHA-512 Hash",
                        fieldType=ItemFieldType.CONCEALED,
                        value=sha512_hash
                    )
                ],
                sections=[
                    ItemSection(id="", title="")
                ]
            )
            
            # Create the item
            created_item = await self.client.items.create(item_params)
            
            logger.info("Saved seed card %s to 1Password item %s" % (card_id, created_item.id))
            return created_item.id
            
        except Exception as e:
            raise OnePasswordError(f"Item saving failed: {e}") from e
    
    async def update_seed_card(self, 
                              vault_id: str,
                              item_id: str,
                              sha512_hash: str) -> None:
        """
        Update existing seed card with new hash.
        
        Args:
            vault_id: 1Password vault ID
            item_id: 1Password item ID to update
            sha512_hash: Updated SHA-512 hash
            
        Raises:
            OnePasswordError: If update fails
        """
        self.ensure_authenticated()
        
        try:
            # Get the existing item
            item = await self.client.items.get(vault_id, item_id)
            
            # Update the SHA-512 hash field
            for field in item.fields:
                if field.id.lower() == "sha512_hash" or "sha-512 hash" in field.title.lower():
                    field.value = sha512_hash
                    break
            
            # Update notes with timestamp
            item.notes = f"{item.notes.split(' - Updated')[0]} - Updated on {datetime.now().isoformat()}"
            
            # Save the updated item
            await self.client.items.put(item)
            
            logger.info("Updated 1Password item %s" % item_id)
            
        except Exception as e:
            raise OnePasswordError(f"Item update failed: {e}") from e
    
    async def get_card_metadata(self, vault_id: str, item_id: str) -> Dict[str, str]:
        """
        Get metadata (hash) from a seed card item.
        
        Args:
            vault_id: 1Password vault ID
            item_id: 1Password item ID
            
        Returns:
            Dictionary with sha512_hash and other metadata
            
        Raises:
            OnePasswordError: If loading fails
        """
        self.ensure_authenticated()
        
        try:
            item = await self.client.items.get(vault_id, item_id)
            metadata = {}
            
            # Extract concealed fields
            for field in item.fields:
                field_id = field.id.lower()
                field_title = field.title.lower()
                
                if field_id == "sha512_hash" or "sha-512 hash" in field_title:
                    metadata["sha512_hash"] = field.value
                elif field_id == "card_id" or "card id" in field_title:
                    metadata["card_id"] = field.value
                elif field_id == "seed_type" or "seed type" in field_title:
                    metadata["seed_type"] = field.value
            
            return metadata
            
        except Exception as e:
            raise OnePasswordError(f"Metadata loading failed: {e}") from e
    
    async def delete_seed_card(self, vault_id: str, item_id: str) -> None:
        """
        Delete a seed card item from 1Password.
        
        Args:
            vault_id: 1Password vault ID
            item_id: 1Password item ID to delete
            
        Raises:
            OnePasswordError: If deletion fails
        """
        self.ensure_authenticated()
        
        try:
            await self.client.items.delete(vault_id, item_id)
            logger.info("Deleted 1Password item %s" % item_id)
            
        except Exception as e:
            raise OnePasswordError(f"Item deletion failed: {e}") from e
    
    async def archive_seed_card(self, vault_id: str, item_id: str) -> None:
        """
        Archive a seed card item in 1Password.
        
        Args:
            vault_id: 1Password vault ID
            item_id: 1Password item ID to archive
            
        Raises:
            OnePasswordError: If archiving fails
        """
        self.ensure_authenticated()
        
        try:
            await self.client.items.archive(vault_id, item_id)
            logger.info("Archived 1Password item %s" % item_id)
            
        except Exception as e:
            raise OnePasswordError(f"Item archiving failed: {e}") from e


# Utility functions
def create_card_title(card_id: str, seed_type: str) -> str:
    """Create a descriptive title for 1Password item."""
    return f"Seed Card {card_id} ({seed_type})"


def validate_seed_for_1password(seed_phrase: Union[str, List[str]], seed_type: str) -> bool:
    """
    Validate that seed data is suitable for 1Password storage.
    
    Args:
        seed_phrase: Seed phrase to validate (string for BIP-39/Simple, list for SLIP-39)
        seed_type: Type of seed
        
    Returns:
        True if valid for storage
    """
    if seed_type not in ["BIP-39", "SLIP-39", "Simple"]:
        return False
    
    # Handle SLIP-39 shares (list of strings)
    if seed_type == "SLIP-39":
        if not isinstance(seed_phrase, list):
            return False
        if len(seed_phrase) < 2:  # Need at least 2 shares
            return False
        for share in seed_phrase:
            if not share or not share.strip():
                return False
            if len(share) > 500:  # Reasonable limit per share
                return False
        return True
    
    # Handle BIP-39 and Simple (strings)
    if not isinstance(seed_phrase, str):
        return False
    if not seed_phrase or not seed_phrase.strip():
        return False
    
    # Check reasonable length limits
    if len(seed_phrase) > 1000:  # Reasonable upper limit
        return False
    
    # Additional BIP-39 validation
    if seed_type == "BIP-39":
        words = seed_phrase.strip().split()
        if len(words) not in [12, 15, 18, 21, 24]:  # Valid BIP-39 lengths
            return False
    
    return True


# Async context manager for convenient usage
class OnePasswordSession:
    """Async context manager for 1Password operations."""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.manager = OnePasswordManager()
    
    async def __aenter__(self):
        await self.manager.authenticate(self.token)
        return self.manager
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        # SDK handles cleanup automatically
        pass


# Example usage and testing
async def demo_1password_integration():
    """Demonstrate 1Password SDK integration."""
    print("1Password SDK Integration Demo")
    print("=" * 35)
    
    try:
        async with OnePasswordSession() as op_manager:
            print("✓ Authenticated with 1Password SDK")
            
            # List vaults
            vaults = await op_manager.list_vaults()
            print(f"Available vaults: {len(vaults)}")
            for vault in vaults[:3]:  # Show first 3
                print(f"  - {vault['name']} ({vault['id']})")
            
            if vaults:
                # Search for existing seed items in first vault
                vault_id = vaults[0]["id"]
                items = await op_manager.search_seed_items(vault_id)
                print(f"Found {len(items)} seed card items in {vaults[0]['name']}")
                
                for item in items[:3]:  # Show first 3
                    print(f"  - {item.title} (Created: {item.created_at})")
            
    except OnePasswordError as e:
        print(f"1Password error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    asyncio.run(demo_1password_integration())
