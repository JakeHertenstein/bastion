"""OpenTimestamps calendar client.

This module handles communication with OTS calendar servers for:
- Submitting merkle roots for timestamping
- Retrieving pending proofs
- Upgrading proofs once Bitcoin confirmation is available
"""

from __future__ import annotations

import base64
import hashlib
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class CalendarServer(str, Enum):
    """Known OpenTimestamps calendar servers."""
    
    ALICE = "https://alice.btc.calendar.opentimestamps.org"
    BOB = "https://bob.btc.calendar.opentimestamps.org"
    FINNEY = "https://finney.calendar.forever.covfefe.org"


# Default calendars to use
DEFAULT_CALENDARS = [
    CalendarServer.ALICE,
    CalendarServer.BOB,
    CalendarServer.FINNEY,
]


class OTSProof(BaseModel):
    """An OpenTimestamps proof file.
    
    This represents the .ots file that contains the timestamp proof.
    """
    
    digest: str = Field(description="Hex-encoded SHA256 of timestamped data")
    proof_data: str = Field(description="Base64-encoded .ots file contents")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Attestation status
    is_pending: bool = Field(default=True)
    bitcoin_attested: bool = Field(default=False)
    
    # Bitcoin attestation details (populated after upgrade)
    block_height: int | None = Field(default=None)
    block_hash: str | None = Field(default=None)
    block_time: datetime | None = Field(default=None)
    
    model_config = {"frozen": False}
    
    def save(self, path: Path) -> None:
        """Save the .ots proof to a file.
        
        Args:
            path: Path to save the proof (should end in .ots)
        """
        proof_bytes = base64.b64decode(self.proof_data)
        path.write_bytes(proof_bytes)
    
    @classmethod
    def load(cls, path: Path, digest: str) -> "OTSProof":
        """Load a .ots proof from a file.
        
        Args:
            path: Path to the .ots file
            digest: Hex-encoded digest this proof is for
            
        Returns:
            OTSProof instance
        """
        proof_bytes = path.read_bytes()
        return cls(
            digest=digest,
            proof_data=base64.b64encode(proof_bytes).decode(),
            is_pending=True,  # Will be updated after verify
        )


@dataclass
class CalendarResponse:
    """Response from a calendar server."""
    
    server: CalendarServer
    success: bool
    timestamp: datetime
    response_data: bytes | None = None
    error: str | None = None


class OTSCalendar:
    """Client for OpenTimestamps calendar servers.
    
    This class uses the `ots` CLI tool for actual operations,
    providing a Python interface for sigchain integration.
    
    The ots CLI handles:
    - Stamp: Submit data to calendars
    - Upgrade: Check for Bitcoin attestations
    - Verify: Verify timestamp proofs
    - Info: Display proof information
    
    Example:
        >>> client = OTSCalendar()
        >>> proof = client.stamp(merkle_root_bytes)
        >>> # Later, upgrade the proof
        >>> upgraded = client.upgrade(proof)
    """
    
    def __init__(
        self,
        calendars: list[CalendarServer] | None = None,
        ots_path: str = "ots",
    ):
        """Initialize the calendar client.
        
        Args:
            calendars: List of calendar servers to use
            ots_path: Path to ots CLI binary
        """
        self.calendars = calendars or DEFAULT_CALENDARS
        self.ots_path = ots_path
    
    def _run_ots(
        self,
        args: list[str],
        input_data: bytes | None = None,
    ) -> tuple[bool, str, str]:
        """Run an ots CLI command.
        
        Args:
            args: Command arguments
            input_data: Optional stdin data
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            result = subprocess.run(
                [self.ots_path] + args,
                input=input_data,
                capture_output=True,
                timeout=60,
            )
            return (
                result.returncode == 0,
                result.stdout.decode(errors="replace"),
                result.stderr.decode(errors="replace"),
            )
        except FileNotFoundError:
            return False, "", f"ots CLI not found at {self.ots_path}"
        except subprocess.TimeoutExpired:
            return False, "", "ots command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def is_available(self) -> bool:
        """Check if ots CLI is available.
        
        Returns:
            True if ots CLI is installed and accessible
        """
        success, _, _ = self._run_ots(["--version"])
        return success
    
    def stamp(self, data: bytes, output_path: Path | None = None) -> OTSProof | None:
        """Create a timestamp for data.
        
        Submits the SHA256 hash of the data to calendar servers.
        
        Args:
            data: Data to timestamp (typically merkle root)
            output_path: Optional path to save .ots file
            
        Returns:
            OTSProof if successful, None otherwise
        """
        digest = hashlib.sha256(data).hexdigest()
        
        # Create temp file for stamping
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(data)
            input_path = Path(f.name)
        
        try:
            # Build calendar args
            calendar_args = []
            for cal in self.calendars:
                calendar_args.extend(["--calendar", cal.value])
            
            # Run stamp command
            success, stdout, stderr = self._run_ots(
                ["stamp"] + calendar_args + [str(input_path)]
            )
            
            if not success:
                return None
            
            # Read the generated .ots file
            ots_path = input_path.with_suffix(".txt.ots")
            if not ots_path.exists():
                return None
            
            proof_data = base64.b64encode(ots_path.read_bytes()).decode()
            
            proof = OTSProof(
                digest=digest,
                proof_data=proof_data,
                is_pending=True,
            )
            
            # Save to output path if specified
            if output_path:
                proof.save(output_path)
            
            return proof
            
        finally:
            # Cleanup temp files
            input_path.unlink(missing_ok=True)
            input_path.with_suffix(".txt.ots").unlink(missing_ok=True)
    
    def stamp_hash(
        self,
        hash_hex: str,
        output_path: Path | None = None
    ) -> OTSProof | None:
        """Create a timestamp for a hash directly.
        
        Use this when you already have a hash (like a merkle root).
        
        Args:
            hash_hex: Hex-encoded SHA256 hash to timestamp
            output_path: Optional path to save .ots file
            
        Returns:
            OTSProof if successful, None otherwise
        """
        # Create a file with just the hash for stamping
        import tempfile
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".txt", mode="w"
        ) as f:
            f.write(hash_hex)
            input_path = Path(f.name)
        
        try:
            # Build calendar args
            calendar_args = []
            for cal in self.calendars:
                calendar_args.extend(["--calendar", cal.value])
            
            # Use --hash flag to stamp hash directly
            success, stdout, stderr = self._run_ots(
                ["stamp", "--hash", hash_hex] + calendar_args
            )
            
            # The ots CLI creates <hash>.ots in current directory
            ots_path = Path(f"{hash_hex}.ots")
            
            if not ots_path.exists():
                # Try without --hash flag, stamping the file
                success, stdout, stderr = self._run_ots(
                    ["stamp"] + calendar_args + [str(input_path)]
                )
                ots_path = input_path.with_suffix(".txt.ots")
            
            if not ots_path.exists():
                return None
            
            proof_data = base64.b64encode(ots_path.read_bytes()).decode()
            
            proof = OTSProof(
                digest=hash_hex,
                proof_data=proof_data,
                is_pending=True,
            )
            
            if output_path:
                proof.save(output_path)
            
            # Cleanup generated ots file
            ots_path.unlink(missing_ok=True)
            
            return proof
            
        finally:
            input_path.unlink(missing_ok=True)
            input_path.with_suffix(".txt.ots").unlink(missing_ok=True)
    
    def upgrade(self, proof: OTSProof) -> OTSProof:
        """Attempt to upgrade a pending proof.
        
        Checks if Bitcoin attestation is available and upgrades
        the proof if so.
        
        Args:
            proof: The proof to upgrade
            
        Returns:
            Updated proof (may still be pending if not yet attested)
        """
        import tempfile
        
        # Write proof to temp file
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".ots"
        ) as f:
            f.write(base64.b64decode(proof.proof_data))
            ots_path = Path(f.name)
        
        try:
            # Run upgrade command
            success, stdout, stderr = self._run_ots(
                ["upgrade", str(ots_path)]
            )
            
            if success and "Success!" in stdout:
                # Read upgraded proof
                upgraded_data = base64.b64encode(ots_path.read_bytes()).decode()
                proof.proof_data = upgraded_data
                proof.is_pending = False
                proof.bitcoin_attested = True
                
                # Parse block info from output
                self._parse_attestation_info(proof, stdout)
            
            return proof
            
        finally:
            ots_path.unlink(missing_ok=True)
    
    def verify(self, proof: OTSProof, data: bytes | None = None) -> bool:
        """Verify a timestamp proof.
        
        Args:
            proof: The proof to verify
            data: Optional original data to verify against
            
        Returns:
            True if proof is valid
        """
        import tempfile
        
        # Write proof to temp file
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".ots"
        ) as f:
            f.write(base64.b64decode(proof.proof_data))
            ots_path = Path(f.name)
        
        # If data provided, write it too
        data_path = None
        if data:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".txt"
            ) as f:
                f.write(data)
                data_path = Path(f.name)
        
        try:
            if data_path:
                success, stdout, stderr = self._run_ots(
                    ["verify", str(ots_path), str(data_path)]
                )
            else:
                success, stdout, stderr = self._run_ots(
                    ["verify", str(ots_path)]
                )
            
            return success and "Success!" in stdout
            
        finally:
            ots_path.unlink(missing_ok=True)
            if data_path:
                data_path.unlink(missing_ok=True)
    
    def info(self, proof: OTSProof) -> dict[str, Any]:
        """Get information about a proof.
        
        Args:
            proof: The proof to inspect
            
        Returns:
            Dict with proof information
        """
        import tempfile
        
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".ots"
        ) as f:
            f.write(base64.b64decode(proof.proof_data))
            ots_path = Path(f.name)
        
        try:
            success, stdout, stderr = self._run_ots(
                ["info", str(ots_path)]
            )
            
            return {
                "success": success,
                "output": stdout,
                "error": stderr if not success else None,
            }
            
        finally:
            ots_path.unlink(missing_ok=True)
    
    def _parse_attestation_info(self, proof: OTSProof, output: str) -> None:
        """Parse Bitcoin attestation info from ots output.
        
        Args:
            proof: Proof to update
            output: ots command output
        """
        # Look for patterns like:
        # "Bitcoin block 123456 attests..."
        # "block hash abc123..."
        import re
        
        block_match = re.search(r"block\s+(\d+)", output, re.IGNORECASE)
        if block_match:
            proof.block_height = int(block_match.group(1))
        
        hash_match = re.search(r"hash\s+([a-f0-9]{64})", output, re.IGNORECASE)
        if hash_match:
            proof.block_hash = hash_match.group(1)


def check_ots_available() -> tuple[bool, str]:
    """Check if OpenTimestamps CLI is available.
    
    Returns:
        Tuple of (available, message)
    """
    client = OTSCalendar()
    if client.is_available():
        return True, "OpenTimestamps CLI is available"
    else:
        return False, (
            "OpenTimestamps CLI not found. Install with:\n"
            "  pip install opentimestamps-client\n"
            "Or: brew install opentimestamps-client"
        )


# =============================================================================
# HTTP-based Calendar Client (no CLI dependency)
# =============================================================================

class OTSHttpClient:
    """HTTP-based OpenTimestamps calendar client.
    
    This client communicates directly with calendar servers via HTTP,
    without requiring the ots CLI tool. Useful for:
    - Environments where CLI installation is difficult
    - Programmatic access without subprocess overhead
    - Custom calendar server configurations
    
    Note: This provides basic submission functionality. For full
    proof verification, the ots CLI or opentimestamps library is
    recommended.
    
    Example:
        >>> client = OTSHttpClient()
        >>> response = await client.submit_digest(merkle_root_bytes)
        >>> if response.success:
        ...     print(f"Submitted to {response.server}")
    """
    
    # Calendar server endpoints
    DIGEST_ENDPOINT = "/digest"
    
    def __init__(
        self,
        calendars: list[CalendarServer] | None = None,
        timeout: float = 30.0,
    ):
        """Initialize HTTP client.
        
        Args:
            calendars: List of calendar servers to use
            timeout: Request timeout in seconds
        """
        self.calendars = calendars or DEFAULT_CALENDARS
        self.timeout = timeout
    
    async def submit_digest_async(
        self,
        digest: bytes,
        calendar: CalendarServer | None = None,
    ) -> CalendarResponse:
        """Submit a digest to a calendar server asynchronously.
        
        Args:
            digest: 32-byte SHA256 digest to timestamp
            calendar: Specific calendar (None = first available)
            
        Returns:
            CalendarResponse with submission result
        """
        try:
            import httpx
        except ImportError:
            return CalendarResponse(
                server=calendar or self.calendars[0],
                success=False,
                timestamp=datetime.now(timezone.utc),
                error="httpx not installed. Run: pip install httpx",
            )
        
        target_calendar = calendar or self.calendars[0]
        url = f"{target_calendar.value}{self.DIGEST_ENDPOINT}"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    url,
                    content=digest,
                    headers={
                        "Content-Type": "application/x-opentimestamps-digest",
                        "Accept": "application/vnd.opentimestamps.v1",
                    },
                )
                
                return CalendarResponse(
                    server=target_calendar,
                    success=response.status_code == 200,
                    timestamp=datetime.now(timezone.utc),
                    response_data=response.content if response.status_code == 200 else None,
                    error=f"HTTP {response.status_code}" if response.status_code != 200 else None,
                )
        except httpx.TimeoutException:
            return CalendarResponse(
                server=target_calendar,
                success=False,
                timestamp=datetime.now(timezone.utc),
                error="Request timed out",
            )
        except httpx.RequestError as e:
            return CalendarResponse(
                server=target_calendar,
                success=False,
                timestamp=datetime.now(timezone.utc),
                error=str(e),
            )
    
    def submit_digest(
        self,
        digest: bytes,
        calendar: CalendarServer | None = None,
    ) -> CalendarResponse:
        """Submit a digest to a calendar server synchronously.
        
        Args:
            digest: 32-byte SHA256 digest to timestamp
            calendar: Specific calendar (None = first available)
            
        Returns:
            CalendarResponse with submission result
        """
        try:
            import httpx
        except ImportError:
            return CalendarResponse(
                server=calendar or self.calendars[0],
                success=False,
                timestamp=datetime.now(timezone.utc),
                error="httpx not installed. Run: pip install httpx",
            )
        
        target_calendar = calendar or self.calendars[0]
        url = f"{target_calendar.value}{self.DIGEST_ENDPOINT}"
        
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    url,
                    content=digest,
                    headers={
                        "Content-Type": "application/x-opentimestamps-digest",
                        "Accept": "application/vnd.opentimestamps.v1",
                    },
                )
                
                return CalendarResponse(
                    server=target_calendar,
                    success=response.status_code == 200,
                    timestamp=datetime.now(timezone.utc),
                    response_data=response.content if response.status_code == 200 else None,
                    error=f"HTTP {response.status_code}" if response.status_code != 200 else None,
                )
        except httpx.TimeoutException:
            return CalendarResponse(
                server=target_calendar,
                success=False,
                timestamp=datetime.now(timezone.utc),
                error="Request timed out",
            )
        except httpx.RequestError as e:
            return CalendarResponse(
                server=target_calendar,
                success=False,
                timestamp=datetime.now(timezone.utc),
                error=str(e),
            )
    
    async def submit_to_all_async(
        self,
        digest: bytes,
    ) -> list[CalendarResponse]:
        """Submit digest to all configured calendars asynchronously.
        
        Args:
            digest: 32-byte SHA256 digest to timestamp
            
        Returns:
            List of CalendarResponse from each server
        """
        try:
            import asyncio
        except ImportError:
            return [
                CalendarResponse(
                    server=cal,
                    success=False,
                    timestamp=datetime.now(timezone.utc),
                    error="asyncio not available",
                )
                for cal in self.calendars
            ]
        
        tasks = [
            self.submit_digest_async(digest, calendar)
            for calendar in self.calendars
        ]
        
        return await asyncio.gather(*tasks)
    
    def submit_to_all(
        self,
        digest: bytes,
    ) -> list[CalendarResponse]:
        """Submit digest to all configured calendars synchronously.
        
        Args:
            digest: 32-byte SHA256 digest to timestamp
            
        Returns:
            List of CalendarResponse from each server
        """
        responses = []
        for calendar in self.calendars:
            response = self.submit_digest(digest, calendar)
            responses.append(response)
        return responses
    
    def submit_merkle_root(
        self,
        merkle_root_hex: str,
    ) -> list[CalendarResponse]:
        """Submit a merkle root hash to all calendars.
        
        Convenience method for sigchain anchoring.
        
        Args:
            merkle_root_hex: Hex-encoded merkle root
            
        Returns:
            List of CalendarResponse from each server
        """
        digest = bytes.fromhex(merkle_root_hex)
        return self.submit_to_all(digest)
    
    def check_calendars_available(self) -> dict[CalendarServer, bool]:
        """Check which calendar servers are reachable.
        
        Returns:
            Dict mapping calendar to availability status
        """
        try:
            import httpx
        except ImportError:
            return {cal: False for cal in self.calendars}
        
        results = {}
        for calendar in self.calendars:
            try:
                with httpx.Client(timeout=5.0) as client:
                    response = client.get(calendar.value)
                    results[calendar] = response.status_code < 500
            except Exception:
                results[calendar] = False
        
        return results
