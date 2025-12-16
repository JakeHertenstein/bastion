"""Entropy generation and management for cryptographic operations.

This module provides high-quality entropy collection from multiple sources:
- YubiKey HMAC-SHA1 challenge-response (hardware RNG)
- Physical casino dice rolls (base-6 collection)
- Combined sources using SHA3-512 hashing

Entropy pools are stored in 1Password with full metadata and audit trails.
Statistical analysis via ENT tool validates entropy quality.
"""

import base64
import hashlib
import json
import re
import subprocess
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional
from pathlib import Path


class QualityThreshold(Enum):
    """Quality thresholds for entropy pools.
    
    Used for filtering in batch collection and validation.
    Values are ordered from highest to lowest quality.
    """
    EXCELLENT = "EXCELLENT"
    GOOD = "GOOD"
    FAIR = "FAIR"
    POOR = "POOR"
    
    @classmethod
    def meets_threshold(cls, rating: str, minimum: "QualityThreshold") -> bool:
        """Check if a rating meets the minimum threshold.
        
        Args:
            rating: Quality rating string (e.g., "GOOD")
            minimum: Minimum acceptable threshold
            
        Returns:
            True if rating meets or exceeds minimum threshold
        """
        order = [cls.EXCELLENT, cls.GOOD, cls.FAIR, cls.POOR]
        try:
            rating_level = cls(rating.upper())
            return order.index(rating_level) <= order.index(minimum)
        except ValueError:
            return False


class EntropyAnalysis:
    """Results from ENT statistical analysis."""
    
    def __init__(
        self,
        entropy_bits_per_byte: float,
        chi_square: float,
        chi_square_pvalue: float,
        arithmetic_mean: float,
        monte_carlo_pi: float,
        monte_carlo_error: float,
        serial_correlation: float,
    ):
        """Initialize analysis results.
        
        Args:
            entropy_bits_per_byte: Entropy in bits per byte (ideal: 8.0)
            chi_square: Chi-square value
            chi_square_pvalue: Chi-square p-value (ideal: 0.5, acceptable: 0.01-0.99)
            arithmetic_mean: Mean byte value (ideal: 127.5)
            monte_carlo_pi: Monte Carlo approximation of π
            monte_carlo_error: Error percentage for π approximation
            serial_correlation: Serial correlation coefficient (ideal: 0.0)
        """
        self.entropy_bits_per_byte = entropy_bits_per_byte
        self.chi_square = chi_square
        self.chi_square_pvalue = chi_square_pvalue
        self.arithmetic_mean = arithmetic_mean
        self.monte_carlo_pi = monte_carlo_pi
        self.monte_carlo_error = monte_carlo_error
        self.serial_correlation = serial_correlation
    
    def is_acceptable(self) -> bool:
        """Check if entropy meets minimum quality standards.
        
        Returns:
            True if entropy is acceptable for cryptographic use
        """
        return (
            self.entropy_bits_per_byte >= 7.5  # Near-ideal entropy
            and 0.01 <= self.chi_square_pvalue <= 0.99  # Not suspiciously uniform or non-uniform
            and abs(self.serial_correlation) < 0.1  # Low correlation between bytes
        )
    
    def quality_rating(self) -> str:
        """Get human-readable quality rating.
        
        Returns:
            Rating string: EXCELLENT, GOOD, FAIR, or POOR
        
        Thresholds calibrated for Infinite Noise TRNG which produces
        ~7.988 bits/byte entropy at 16KB+ sample sizes. Chi-square p-value
        has high natural variance (3%-98% observed), so we use wider windows.
        """
        if self.entropy_bits_per_byte >= 7.985 and 0.05 <= self.chi_square_pvalue <= 0.95:
            return "EXCELLENT"
        elif self.entropy_bits_per_byte >= 7.9 and 0.01 <= self.chi_square_pvalue <= 0.99:
            return "GOOD"
        elif self.entropy_bits_per_byte >= 7.5 and 0.001 <= self.chi_square_pvalue <= 0.999:
            return "FAIR"
        else:
            return "POOR"
    
    def to_dict(self) -> dict[str, float]:
        """Convert to dictionary for storage.
        
        Returns:
            Dictionary of analysis metrics
        """
        return {
            "entropy_bits_per_byte": self.entropy_bits_per_byte,
            "chi_square": self.chi_square,
            "chi_square_pvalue": self.chi_square_pvalue,
            "arithmetic_mean": self.arithmetic_mean,
            "monte_carlo_pi": self.monte_carlo_pi,
            "monte_carlo_error": self.monte_carlo_error,
            "serial_correlation": self.serial_correlation,
        }
    
    @staticmethod
    def from_dict(data: dict[str, float]) -> "EntropyAnalysis":
        """Create from dictionary.
        
        Args:
            data: Dictionary from to_dict()
            
        Returns:
            EntropyAnalysis instance
        """
        return EntropyAnalysis(
            entropy_bits_per_byte=data["entropy_bits_per_byte"],
            chi_square=data["chi_square"],
            chi_square_pvalue=data["chi_square_pvalue"],
            arithmetic_mean=data["arithmetic_mean"],
            monte_carlo_pi=data["monte_carlo_pi"],
            monte_carlo_error=data["monte_carlo_error"],
            serial_correlation=data["serial_correlation"],
        )


class EntropyPool:
    """Entropy pool with metadata and 1Password integration."""
    
    SOURCE_ITEM_PREFIX = "Bastion Entropy Source"
    DERIVED_ITEM_PREFIX = "Bastion Entropy Derived"
    POOL_TAG = "Bastion/ENTROPY"
    
    def __init__(self):
        """Initialize entropy pool manager."""
        self._cached_pools: dict[str, tuple[bytes, dict]] = {}  # uuid -> (entropy_bytes, metadata)
        self._cached_max_serial: int | None = None  # Session-level serial cache for batch ops
    
    def find_highest_serial_number(self, version: str = "v1", use_cache: bool = False) -> int:
        """Find the highest serial number for entropy pools.
        
        Args:
            version: Version string (e.g., "v1")
            use_cache: If True, return cached value if available (for batch ops)
            
        Returns:
            Highest serial number found, or 0 if none exist
        """
        # Return cached value if available and requested
        if use_cache and self._cached_max_serial is not None:
            return self._cached_max_serial
        
        try:
            result = subprocess.run(
                ["op", "item", "list", "--tags", self.POOL_TAG, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=120,  # Longer timeout for large pool counts (200+)
            )
            
            items = json.loads(result.stdout)
            
            # Parse serial numbers from titles (match both Source and Derived prefixes)
            # Title format: "Bastion Entropy Source #N" or "Bastion Entropy Derived #N"
            patterns = [
                re.compile(rf'{re.escape(self.SOURCE_ITEM_PREFIX)} #(\d+)'),
                re.compile(rf'{re.escape(self.DERIVED_ITEM_PREFIX)} #(\d+)'),
            ]
            max_serial = 0
            
            for item in items:
                title = item.get("title", "")
                for pattern in patterns:
                    match = pattern.search(title)
                    if match:
                        serial = int(match.group(1))
                        max_serial = max(max_serial, serial)
                        break
            
            # Cache the result for subsequent calls
            self._cached_max_serial = max_serial
            return max_serial
            
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError, ValueError):
            return 0
    
    def set_cached_serial(self, serial: int) -> None:
        """Set the cached max serial number.
        
        Used by batch operations that already know the max serial from
        a previous list operation, avoiding redundant 1Password calls.
        
        Args:
            serial: The highest serial number to cache
        """
        self._cached_max_serial = serial
    
    def invalidate_serial_cache(self) -> None:
        """Invalidate the cached max serial number.
        
        Call this if external changes may have modified pool serials.
        """
        self._cached_max_serial = None
    
    def create_pool(
        self,
        entropy_bytes: bytes,
        source: str,
        analysis: Optional[EntropyAnalysis] = None,
        vault: str = "Private",
        version: str = "v1",
        expiry_days: int = 90,
        pool_type: str = "source",
        source_type: Optional[str] = None,
        source_uuids: Optional[list[str]] = None,
        derivation_method: Optional[str] = None,
        device_metadata: Optional[dict] = None,
        batch_id: Optional[int] = None,
    ) -> tuple[str, int]:
        """Create entropy pool in 1Password.
        
        Args:
            entropy_bytes: Raw entropy data
            source: Source description (e.g., "yubikey", "dice", "yubikey+dice")
            analysis: Optional ENT analysis results
            vault: Vault name (default: "Private")
            version: Version string (default: "v1")
            expiry_days: Days until pool expires (default: 90)
            pool_type: "source" for raw entropy, "derived" for combined pools
            source_type: Specific source type (e.g., "yubikey_openpgp", "system_urandom")
            source_uuids: List of source pool UUIDs (for derived pools)
            derivation_method: Method used to derive (e.g., "sha3_512")
            device_metadata: Additional metadata dict (serial numbers, OS info, etc.)
            batch_id: Optional batch collection ID (sequential integer for batch runs)
            device_metadata: Additional metadata dict (serial numbers, OS info, etc.)
            
        Returns:
            Tuple of (pool_uuid, serial_number)
            
        Raises:
            RuntimeError: If creation fails
        """
        # Find next serial number using cache if available (batch ops)
        highest_serial = self.find_highest_serial_number(version, use_cache=True)
        next_serial = highest_serial + 1
        
        # Build title based on pool type (version in metadata, not title)
        if pool_type == "source":
            title = f"{self.SOURCE_ITEM_PREFIX} #{next_serial}"
        else:
            title = f"{self.DERIVED_ITEM_PREFIX} #{next_serial}"
        
        # Encode entropy as base64
        entropy_b64 = base64.b64encode(entropy_bytes).decode('utf-8')
        byte_count = len(entropy_bytes)
        bit_count = byte_count * 8
        
        # Calculate Unix timestamps for date fields
        created_timestamp = int(datetime.now().timestamp())
        expires_timestamp = int((datetime.now() + timedelta(days=expiry_days)).timestamp())
        
        # Build field list using native 1Password sections
        # Section format: "Section Name.Field Name[type]=value"
        # Field names use Title Case for 1Password canonical form
        # Use SECURE_NOTE category for better organization
        fields = [
            "--category", "secure note",
            "--title", title,
            "--vault", vault,
            "--tags", self.POOL_TAG,
            # Size section (first for visibility)
            f"Size.Bytes[text]={byte_count}",
            f"Size.Bits[text]={bit_count}",
            # Pool Info section
            f"Pool Info.Version[text]={version}",
            f"Pool Info.Serial Number[text]={next_serial}",
            f"Pool Info.Pool Type[text]={pool_type}",
            f"Pool Info.Source[text]={source}",
        ]
        
        # Store entropy in a concealed field within Pool Info section
        fields.append(f"Pool Info.Entropy[concealed]={entropy_b64}")
        
        if source_type:
            fields.append(f"Pool Info.Source Type[text]={source_type}")
        
        # Batch ID (for batch collection runs)
        if batch_id is not None:
            fields.append(f"Pool Info.Batch ID[text]={batch_id}")
        
        # Combine method (for combined/derived pools)
        if derivation_method:
            # Store human-readable combine method name
            combine_method_display = {
                "xor_shake256": "XOR+SHAKE256",
                "sha3_512": "SHA3-512",
            }.get(derivation_method, derivation_method.upper())
            fields.append(f"Pool Info.Combine Method[text]={combine_method_display}")
        
        # Entropy Sources section (for derived pools - individual UUID fields)
        if pool_type == "derived" and source_uuids:
            for i, uuid in enumerate(source_uuids, 1):
                fields.append(f"Entropy Sources.Source {i}[text]={uuid}")
        
        # Device Metadata section
        if device_metadata:
            for key, value in device_metadata.items():
                fields.append(f"Device Metadata.{key}[text]={value}")
        
        # Lifecycle section
        fields.extend([
            f"Lifecycle.Created At[date]={created_timestamp}",
            f"Lifecycle.Expires At[date]={expires_timestamp}",
            "Lifecycle.Consumed[text]=False",
        ])
        
        # Statistical Analysis section (only for samples >= 1KB)
        if analysis and byte_count >= 1024:
            fields.extend([
                f"Statistical Analysis.Entropy Per Byte[text]={analysis.entropy_bits_per_byte:.6f}",
                f"Statistical Analysis.Chi Square[text]={analysis.chi_square:.2f}",
                f"Statistical Analysis.Chi Square P-Value[text]={analysis.chi_square_pvalue:.6f}",
                f"Statistical Analysis.Arithmetic Mean[text]={analysis.arithmetic_mean:.4f}",
                f"Statistical Analysis.Monte Carlo Pi[text]={analysis.monte_carlo_pi:.6f}",
                f"Statistical Analysis.Monte Carlo Error Pct[text]={analysis.monte_carlo_error:.2f}",
                f"Statistical Analysis.Serial Correlation[text]={analysis.serial_correlation:.6f}",
                f"Statistical Analysis.Quality Rating[text]={analysis.quality_rating()}", 
            ])
        
        fields.append("--format")
        fields.append("json")
        
        try:
            # Create password item with all fields in sections
            result = subprocess.run(
                ["op", "item", "create"] + fields,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            item_data = json.loads(result.stdout)
            pool_uuid = item_data.get("id", "")
            
            # Cache the pool
            metadata = {
                "serial": next_serial,
                "source": source,
                "byte_count": byte_count,
                "created_at": created_timestamp,
                "expires_at": expires_timestamp,
                "consumed": False,
                "analysis": analysis.to_dict() if analysis else None,
            }
            self._cached_pools[pool_uuid] = (entropy_bytes, metadata)
            
            # Update serial cache for next create_pool call
            self._cached_max_serial = next_serial
            
            return (pool_uuid, next_serial)
            
        except subprocess.CalledProcessError as e:
            # Import here to avoid circular import
            from bastion.op_client import OPAuthError, is_auth_error
            
            # Check if this is an auth error (1Password locked)
            if is_auth_error(e.stderr or ""):
                # Raise auth error WITHOUT exposing entropy
                raise OPAuthError(
                    "1Password authentication required. Please unlock 1Password."
                ) from None  # Use 'from None' to suppress chained exception
            
            # For non-auth errors, still don't expose the command (contains entropy)
            raise RuntimeError(
                f"Failed to create entropy pool: {e.stderr or 'Unknown error'}"
            ) from None
    
    def get_pool(self, pool_uuid: str) -> Optional[tuple[bytes, dict]]:
        """Retrieve entropy pool from 1Password.
        
        Args:
            pool_uuid: Pool UUID
            
        Returns:
            Tuple of (entropy_bytes, metadata) or None if not found
        """
        if pool_uuid in self._cached_pools:
            return self._cached_pools[pool_uuid]
        
        try:
            result = subprocess.run(
                ["op", "item", "get", pool_uuid, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            item_data = json.loads(result.stdout)
            
            # Extract entropy field (base64 entropy) - check both new "Entropy" field and legacy "password" field
            entropy_b64 = None
            for field in item_data.get("fields", []):
                label = field.get("label", "")
                field_id = field.get("id", "")
                if (label == "Entropy" or field_id == "password") and field.get("value"):
                    entropy_b64 = field["value"]
                    break
            
            if not entropy_b64:
                return None
            
            # Decode entropy
            entropy_bytes = base64.b64decode(entropy_b64)
            
            # Extract metadata from custom fields
            metadata: dict = {}
            for field in item_data.get("fields", []):
                label = field.get("label", "")
                value = field.get("value")
                
                if label == "serial_number":
                    metadata["serial"] = int(value) if value else 0
                elif label == "source":
                    metadata["source"] = value
                elif label == "byte_count":
                    metadata["byte_count"] = int(value) if value else len(entropy_bytes)
                elif label == "created_at":
                    metadata["created_at"] = value
                elif label == "expires_at":
                    metadata["expires_at"] = value
                elif label == "consumed":
                    metadata["consumed"] = value.lower() == "true"
                elif label == "entropy_bits_per_byte":
                    if "analysis" not in metadata:
                        metadata["analysis"] = {}
                    metadata["analysis"]["entropy_bits_per_byte"] = float(value) if value else 0.0
                elif label == "chi_square_pvalue":
                    if "analysis" not in metadata:
                        metadata["analysis"] = {}
                    metadata["analysis"]["chi_square_pvalue"] = float(value) if value else 0.0
                elif label == "quality_rating":
                    if "analysis" not in metadata:
                        metadata["analysis"] = {}
                    metadata["analysis"]["quality_rating"] = value
            
            # Cache the pool
            self._cached_pools[pool_uuid] = (entropy_bytes, metadata)
            
            return (entropy_bytes, metadata)
            
        except (subprocess.CalledProcessError, json.JSONDecodeError, ValueError):
            return None
    
    def mark_consumed(self, pool_uuid: str) -> None:
        """Mark entropy pool as consumed.
        
        Args:
            pool_uuid: Pool UUID to mark
            
        Raises:
            RuntimeError: If update fails
        """
        try:
            subprocess.run(
                [
                    "op", "item", "edit", pool_uuid,
                    "Lifecycle.Consumed[text]=True",
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            # Update cache
            if pool_uuid in self._cached_pools:
                entropy_bytes, metadata = self._cached_pools[pool_uuid]
                metadata["consumed"] = True
                self._cached_pools[pool_uuid] = (entropy_bytes, metadata)
                
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to mark pool as consumed: {e.stderr}") from e
    
    def list_pools(self, include_consumed: bool = False) -> list[dict]:
        """List all entropy pools.
        
        Args:
            include_consumed: Whether to include consumed pools
            
        Returns:
            List of pool metadata dictionaries
        """
        try:
            result = subprocess.run(
                ["op", "item", "list", "--tags", self.POOL_TAG, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            items = json.loads(result.stdout)
            pools = []
            
            for item in items:
                pool_uuid = item.get("id", "")
                title = item.get("title", "")
                
                # Get full details
                detail_result = subprocess.run(
                    ["op", "item", "get", pool_uuid, "--format", "json"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                
                detail_data = json.loads(detail_result.stdout)
                
                # Extract metadata
                pool_info = {
                    "uuid": pool_uuid,
                    "title": title,
                }
                
                for field in detail_data.get("fields", []):
                    label = field.get("label", "")
                    value = field.get("value")
                    
                    # Support both Title Case (new) and snake_case (legacy) field names
                    if label in ("Serial Number", "serial_number"):
                        pool_info["serial"] = value
                    elif label in ("Source", "source"):
                        pool_info["source"] = value
                    elif label in ("Byte Count", "byte_count"):
                        pool_info["byte_count"] = int(value) if value else 0
                    elif label in ("Bit Count", "bit_count"):
                        pool_info["bit_count"] = int(value) if value else 0
                    elif label in ("Created At", "created_at"):
                        pool_info["created_at"] = value
                    elif label in ("Expires At", "expires_at"):
                        pool_info["expires_at"] = value
                    elif label in ("Consumed", "consumed"):
                        pool_info["consumed"] = str(value).lower() == "true"
                    elif label in ("Quality Rating", "quality_rating"):
                        pool_info["quality_rating"] = value
                    elif label in ("Bytes", "byte_count"):
                        pool_info["byte_count"] = int(value) if value else 0
                    elif label in ("Bits", "bit_count"):
                        pool_info["bit_count"] = int(value) if value else 0
                
                # Filter consumed if requested
                if not include_consumed and pool_info.get("consumed", False):
                    continue
                
                pools.append(pool_info)
            
            return pools
            
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return []
    
    def list_pools_by_source(
        self,
        source: str,
        min_bits: int = 0,
        include_consumed: bool = False,
    ) -> list[dict]:
        """List entropy pools filtered by source type.
        
        Args:
            source: Source type to filter (e.g., 'infnoise', 'yubikey', 'system')
            min_bits: Minimum bit count required (default 0 = no minimum)
            include_consumed: Whether to include consumed pools (default False)
            
        Returns:
            List of pool metadata dictionaries matching criteria, sorted by serial number
        """
        all_pools = self.list_pools(include_consumed=include_consumed)
        
        filtered = []
        for pool in all_pools:
            pool_source = pool.get("source", "").lower()
            pool_bits = pool.get("bit_count", 0)
            
            # Match source (partial match to handle 'yubikey' matching 'yubikey_openpgp', etc.)
            if source.lower() not in pool_source:
                continue
            
            # Check minimum bits
            if min_bits > 0 and pool_bits < min_bits:
                continue
            
            filtered.append(pool)
        
        # Sort by serial number (oldest first)
        filtered.sort(key=lambda p: int(p.get("serial", 0)))
        
        return filtered
    
    def get_first_available_pool(
        self,
        source: str,
        min_bits: int = 0,
    ) -> Optional[dict]:
        """Get the first unconsumed pool matching source and bit requirements.
        
        Args:
            source: Source type to filter
            min_bits: Minimum bit count required
            
        Returns:
            Pool metadata dict or None if no matching pool found
        """
        pools = self.list_pools_by_source(
            source=source,
            min_bits=min_bits,
            include_consumed=False,
        )
        return pools[0] if pools else None


def combine_entropy_sources(*sources: bytes) -> bytes:
    """Combine multiple entropy sources using XOR with SHAKE256 extension.
    
    Preserves maximum entropy by:
    1. Finding largest source size
    2. Extending smaller sources using SHAKE256 (XOF)
    3. XORing all extended sources together
    
    The XOR operation ensures that if ANY source has good entropy,
    the output will have good entropy. SHAKE256 extension is
    cryptographically secure deterministic expansion.
    
    Args:
        *sources: Variable number of entropy byte strings
        
    Returns:
        Combined entropy with size = max(len(source)) bytes
        
    Raises:
        ValueError: If no sources provided
    """
    if not sources:
        raise ValueError("At least one entropy source required")
    
    if len(sources) == 1:
        return sources[0]  # Nothing to combine
    
    max_len = max(len(s) for s in sources)
    
    # Extend each source to max_len using SHAKE256
    extended = []
    for source in sources:
        if len(source) >= max_len:
            extended.append(source[:max_len])
        else:
            # Extend using SHAKE256 with source as seed
            # Include original length to differentiate same-content different-length inputs
            shake = hashlib.shake_256(len(source).to_bytes(8, 'big') + source)
            extended.append(shake.digest(max_len))
    
    # XOR all extended sources together
    result = bytearray(max_len)
    for ext in extended:
        for i in range(max_len):
            result[i] ^= ext[i]
    
    return bytes(result)


def store_and_combine_entropy_sources(
    source_entropies: list[tuple[str, str, bytes, dict]],
    vault: str = "Private",
    store_sources: bool = True,
) -> tuple[str, list[str]]:
    """Store each entropy source separately, then create derived pool.
    
    This function implements the multi-source entropy workflow:
    1. Store each source entropy separately in 1Password (if store_sources=True)
    2. Combine all sources using XOR+SHAKE256 (preserves max entropy size)
    3. Create a derived pool that references all source UUIDs
    4. Return derived pool UUID and list of source UUIDs
    
    Args:
        source_entropies: List of (source_name, source_type, entropy_bytes, device_metadata)
            Example: [
                ("yubikey", "yubikey_openpgp", b"...", {"serial": "12345678"}),
                ("dice", "dice", b"...", {"rolls": 198}),
                ("system", "system_urandom", b"...", {"os": "Darwin"}),
            ]
        vault: 1Password vault name (default: "Private")
        store_sources: If True, store individual sources before combining
        
    Returns:
        Tuple of (derived_pool_uuid, list_of_source_pool_uuids)
        If store_sources=False, source list will be empty
        
    Raises:
        RuntimeError: If creation fails
        ValueError: If no sources provided
    """
    if not source_entropies:
        raise ValueError("At least one entropy source required")
    
    pool = EntropyPool()
    source_uuids = []
    all_entropy_bytes = []
    
    # Step 1: Store each source separately (if requested)
    if store_sources:
        for source_name, source_type, entropy_bytes, device_metadata in source_entropies:
            # Analyze each source
            analysis = analyze_entropy_with_ent(entropy_bytes)
            
            # Store source pool
            source_uuid, _ = pool.create_pool(
                entropy_bytes=entropy_bytes,
                source=source_name,
                analysis=analysis,
                vault=vault,
                pool_type="source",
                source_type=source_type,
                device_metadata=device_metadata,
            )
            source_uuids.append(source_uuid)
            all_entropy_bytes.append(entropy_bytes)
    else:
        # Just extract entropy bytes without storing
        all_entropy_bytes = [entropy for _, _, entropy, _ in source_entropies]
    
    # Step 2: Combine sources using XOR+SHAKE256
    combined_bytes = combine_entropy_sources(*all_entropy_bytes)
    derivation_method = "xor_shake256"
    
    # Step 3: Analyze combined entropy
    combined_analysis = analyze_entropy_with_ent(combined_bytes)
    
    # Step 4: Build source label for derived pool
    source_names = [name for name, _, _, _ in source_entropies]
    derived_source_label = "+".join(source_names)
    
    # Step 5: Store derived pool with references
    derived_uuid, _ = pool.create_pool(
        entropy_bytes=combined_bytes,
        source=derived_source_label,
        analysis=combined_analysis,
        vault=vault,
        pool_type="derived",
        source_uuids=source_uuids if store_sources else None,
        derivation_method=derivation_method,
    )
    
    return (derived_uuid, source_uuids)


def derive_salt_from_entropy_pool(
    entropy_pool_uuid: str,
    info: Optional[str] = None,
    output_length: int = 64,
    ident: str = "username-generator",
) -> tuple[bytes, str, str]:
    """Derive deterministic salt from entropy pool using HKDF-SHA512.
    
    Uses HKDF (HMAC-based Key Derivation Function) with SHA-512 to derive
    a deterministic salt from an entropy pool. The same entropy pool with
    the same info string will always produce the same output.
    
    This function marks the entropy pool as consumed after derivation.
    
    The `info` parameter uses Bastion Label format for domain separation:
        Bastion/SALT/HKDF/SHA2/512:{ident}:{date}#VERSION=1
    
    Args:
        entropy_pool_uuid: UUID of source entropy pool in 1Password
        info: Context string for domain separation. If None, generates a
              Bastion Label using the ident parameter and current date.
        output_length: Bytes of output (default: 64 = 512 bits)
        ident: Identifier for the salt purpose (default: "username-generator")
               Used to generate info label if info is None.
        
    Returns:
        Tuple of (derived_salt_bytes, entropy_pool_uuid, derivation_label)
        
    Raises:
        RuntimeError: If entropy pool not found, too small, or derivation fails
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError:
        raise RuntimeError(
            "cryptography library required for HKDF. Install with: pip install cryptography"
        ) from None
    
    pool = EntropyPool()
    result = pool.get_pool(entropy_pool_uuid)
    
    if not result:
        raise RuntimeError(f"Entropy pool {entropy_pool_uuid} not found")
    
    entropy_bytes, metadata = result
    
    # Check minimum pool size (512 bits = 64 bytes)
    if len(entropy_bytes) < 64:
        raise RuntimeError(
            f"Entropy pool {entropy_pool_uuid} is too small ({len(entropy_bytes)} bytes). "
            f"Minimum 64 bytes (512 bits) required for salt derivation."
        )
    
    # Check if pool is already consumed
    if metadata.get("consumed", False):
        raise RuntimeError(
            f"Entropy pool {entropy_pool_uuid} has already been consumed. "
            "Create a new entropy pool for additional derivations."
        )
    
    # Generate Bastion Label for info if not provided
    if info is None:
        from datetime import datetime
        date_str = datetime.now().strftime("%Y-%m-%d")
        info = f"Bastion/SALT/HKDF/SHA2/512:{ident}:{date_str}#VERSION=1"
    
    # HKDF-SHA512 derivation
    # Note: cryptography library doesn't support SHA3 in HKDF yet (as of 2025)
    # Using SHA-512 which is still quantum-resistant and widely supported
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=output_length,
        salt=None,  # Entropy pool is already high-quality, no additional salt needed
        info=info.encode('utf-8'),
    )
    
    derived_salt = hkdf.derive(entropy_bytes)
    
    # Mark pool as consumed
    pool.mark_consumed(entropy_pool_uuid)
    
    return (derived_salt, entropy_pool_uuid, info)


def analyze_entropy_with_ent(entropy_bytes: bytes) -> Optional[EntropyAnalysis]:
    """Analyze entropy using ENT tool.
    
    Args:
        entropy_bytes: Entropy data to analyze
        
    Returns:
        EntropyAnalysis instance or None if ENT not available
        
    Raises:
        RuntimeError: If ENT is installed but fails to run
    """
    try:
        # Write entropy to temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            temp_path = Path(f.name)
            f.write(entropy_bytes)
        
        try:
            # Run ENT
            result = subprocess.run(
                ["ent", str(temp_path)],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            # Parse ENT output
            output = result.stdout
            
            # Extract values using regex
            entropy_match = re.search(r'Entropy = ([\d.]+) bits per byte', output)
            chi_square_match = re.search(r'Chi square distribution for \d+ samples is ([\d.]+)', output)
            pvalue_match = re.search(r'would exceed this value ([\d.]+) percent', output)
            mean_match = re.search(r'Arithmetic mean value of data bytes is ([\d.]+)', output)
            pi_match = re.search(r'Monte Carlo value for Pi is ([\d.]+)', output)
            pi_error_match = re.search(r'error ([\d.]+) percent', output)
            correlation_match = re.search(r'Serial correlation coefficient is ([-\d.]+)', output)
            
            if not all([entropy_match, chi_square_match, pvalue_match, mean_match, 
                       pi_match, pi_error_match, correlation_match]):
                raise RuntimeError("Failed to parse ENT output")
            
            return EntropyAnalysis(
                entropy_bits_per_byte=float(entropy_match.group(1)),
                chi_square=float(chi_square_match.group(1)),
                chi_square_pvalue=float(pvalue_match.group(1)) / 100.0,  # Convert percentage to decimal
                arithmetic_mean=float(mean_match.group(1)),
                monte_carlo_pi=float(pi_match.group(1)),
                monte_carlo_error=float(pi_error_match.group(1)),
                serial_correlation=float(correlation_match.group(1)),
            )
            
        finally:
            # Clean up temp file
            temp_path.unlink(missing_ok=True)
            
    except FileNotFoundError:
        # ENT not installed
        return None
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"ENT analysis failed: {e.stderr}") from e


def attach_visualization_to_pool(
    pool_uuid: str,
    histogram_pdf: bytes,
    chi_square_pdf: bytes,
) -> bool:
    """Attach visualization PDF files to an entropy pool item in 1Password.
    
    Creates a "Visualization" section with two file attachments:
    - Histogram: Byte frequency distribution and bit pattern grid
    - Chi-Square: Chi-square distribution analysis
    
    Args:
        pool_uuid: UUID of the entropy pool item
        histogram_pdf: PDF bytes for histogram visualization
        chi_square_pdf: PDF bytes for chi-square visualization
        
    Returns:
        True if attachments were successful, False otherwise
        
    Raises:
        RuntimeError: If 1Password CLI fails
    """
    import tempfile
    
    # Write PDF bytes to temporary files
    with tempfile.TemporaryDirectory() as tmpdir:
        histogram_path = Path(tmpdir) / "histogram.pdf"
        chi_square_path = Path(tmpdir) / "chi-square.pdf"
        
        histogram_path.write_bytes(histogram_pdf)
        chi_square_path.write_bytes(chi_square_pdf)
        
        try:
            # Attach histogram visualization
            # Field name includes escaped .pdf extension for 1Password preview support
            # Backslash escapes the dot so it's not treated as section separator
            subprocess.run(
                ["op", "item", "edit", pool_uuid, f"Visualization.histogram\\.pdf[file]={histogram_path}"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            # Attach chi-square visualization
            subprocess.run(
                ["op", "item", "edit", pool_uuid, f"Visualization.chi-square\\.pdf[file]={chi_square_path}"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            return True
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to attach visualization: {e.stderr}") from e


def pool_has_visualization(pool_uuid: str) -> bool:
    """Check if an entropy pool already has visualization attachments.
    
    Args:
        pool_uuid: UUID of the entropy pool item
        
    Returns:
        True if pool has Visualization section with files, False otherwise
    """
    try:
        result = subprocess.run(
            ["op", "item", "get", pool_uuid, "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        
        item_data = json.loads(result.stdout)
        
        # Check for files in Visualization section
        files = item_data.get("files", [])
        for f in files:
            section = f.get("section", {})
            if section.get("label") == "Visualization":
                return True
        
        # Also check fields for Visualization section
        for field in item_data.get("fields", []):
            section = field.get("section", {})
            if section.get("label") == "Visualization":
                return True
        
        return False
        
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return False
