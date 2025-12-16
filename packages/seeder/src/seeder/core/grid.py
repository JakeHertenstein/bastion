#!/usr/bin/env python3
"""
Grid generation and coordinate management for token layout.
Extracted from monolithic seed.py for better modularity.
"""

import csv
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .config import BASE_CONFIGS, CHARS_PER_TOKEN, DEFAULT_BASE, TOKENS_TALL, TOKENS_WIDE
from .crypto import SeedCardCrypto
from .exceptions import CoordinateError, GridGenerationError

# Remove logging for now to fix imports


class SeederGrid:
    """Manages the 10x10 token grid layout and operations."""
    
    def __init__(self, seed_bytes: bytes, card_id: Optional[str] = None, base: str = DEFAULT_BASE, card_index: str = "A0"):
        """
        Initialize grid with seed material.
        
        Args:
            seed_bytes: 64-byte seed for token generation
            card_id: Optional card ID to incorporate into token generation
            base: Base system to use (base10, base62, base90) - defaults to base90
            card_index: Card index for batch generation (A0-J9), default "A0"
            
        Raises:
            GridGenerationError: If grid generation fails or base is invalid
        """
        if base not in BASE_CONFIGS:
            raise GridGenerationError(f"Invalid base '{base}'. Must be one of {list(BASE_CONFIGS.keys())}")
        
        self.seed_bytes = seed_bytes
        self.card_id = card_id
        self.base = base
        self.card_index = card_index
        self.alphabet = BASE_CONFIGS[base]["alphabet"]
        self.crypto = SeedCardCrypto()
        self._tokens: Optional[List[List[str]]] = None
        self._coordinate_map: Optional[Dict[str, str]] = None
    
    @property
    def tokens(self) -> List[List[str]]:
        """Get the 10x10 token grid (lazy generation)."""
        if self._tokens is None:
            self._generate_grid()
        return self._tokens
    
    @property
    def coordinate_map(self) -> Dict[str, str]:
        """Get coordinate-to-token mapping (lazy generation)."""
        if self._coordinate_map is None:
            self._generate_coordinate_map()
        return self._coordinate_map
    
    def _generate_grid(self) -> None:
        """Generate the complete 10x10 token grid using per-token HMAC labels."""
        try:
            # Generate token stream using crypto module with per-token HMAC labels
            token_stream = self.crypto.generate_token_stream(
                self.seed_bytes, 
                TOKENS_WIDE * TOKENS_TALL,
                self.card_id,
                self.alphabet,
                self.card_index
            )
            
            # Organize into 10x10 grid
            self._tokens = []
            for row in range(TOKENS_TALL):
                token_row = []
                for col in range(TOKENS_WIDE):
                    index = row * TOKENS_WIDE + col
                    token_row.append(token_stream[index])
                self._tokens.append(token_row)
            
            # logger.log_grid_generation(TOKENS_WIDE * TOKENS_TALL, success=True)
            
        except Exception as e:
            # logger.log_grid_generation(0, success=False, error=str(e))
            raise GridGenerationError(f"Grid generation failed: {e}") from e
    
    def _generate_coordinate_map(self) -> None:
        """Generate coordinate-to-token mapping.
        
        Spreadsheet convention: letter=column (A-J), number=row (0-9)
        A0=top-left, J0=top-right, A9=bottom-left, J9=bottom-right
        """
        if self._tokens is None:
            self._generate_grid()
        
        self._coordinate_map = {}
        for row in range(TOKENS_TALL):
            for col in range(TOKENS_WIDE):
                # Spreadsheet convention: column letter + row number
                coord = f"{chr(ord('A') + col)}{row}"
                self._coordinate_map[coord] = self._tokens[row][col]
    
    def get_token(self, coordinate: str) -> str:
        """
        Get token at specific coordinate.
        
        Args:
            coordinate: Grid coordinate (e.g., "A0", "J9")
            
        Returns:
            Token string at coordinate
            
        Raises:
            CoordinateError: If coordinate is invalid
        """
        try:
            coord = coordinate.upper().strip()
            
            if len(coord) != 2:
                raise CoordinateError(f"Invalid coordinate format: {coordinate}")
            
            col_char, row_char = coord[0], coord[1]
            
            if not ('A' <= col_char <= 'J'):
                raise CoordinateError(f"Invalid column: {col_char} (must be A-J)")
            
            if not ('0' <= row_char <= '9'):
                raise CoordinateError(f"Invalid row: {row_char} (must be 0-9)")
            
            col = ord(col_char) - ord('A')
            row = int(row_char)
            
            return self.tokens[row][col]
            
        except (IndexError, ValueError) as e:
            raise CoordinateError(f"Coordinate access failed: {e}") from e
    
    def get_tokens_by_pattern(self, coordinates: List[str]) -> List[str]:
        """
        Get tokens for a list of coordinates.
        
        Args:
            coordinates: List of coordinate strings
            
        Returns:
            List of tokens corresponding to coordinates
        """
        return [self.get_token(coord) for coord in coordinates]
    
    def find_token_coordinates(self, target_token: str) -> List[str]:
        """
        Find all coordinates containing a specific token.
        
        Args:
            target_token: Token to search for
            
        Returns:
            List of coordinates where token appears
        """
        coordinates = []
        for row in range(TOKENS_TALL):
            for col in range(TOKENS_WIDE):
                if self.tokens[row][col] == target_token:
                    coord = f"{chr(ord('A') + col)}{row}"
                    coordinates.append(coord)
        return coordinates
    
    def verify_tokens_at_coordinates(self, coordinate_token_pairs: List[Tuple[str, str]]) -> bool:
        """
        Verify that expected tokens appear at specified coordinates.
        
        Args:
            coordinate_token_pairs: List of (coordinate, expected_token) tuples
            
        Returns:
            True if all tokens match, False otherwise
        """
        for coord, expected_token in coordinate_token_pairs:
            try:
                actual_token = self.get_token(coord)
                if actual_token != expected_token:
                    return False
            except CoordinateError:
                return False
        return True
    
    def get_grid_as_string(self, separator: str = " ") -> str:
        """
        Get grid as formatted string.
        
        Args:
            separator: Token separator (default: space)
            
        Returns:
            Grid formatted as string
        """
        lines = []
        for row in self.tokens:
            lines.append(separator.join(row))
        return "\n".join(lines)
    
    def get_grid_statistics(self) -> Dict[str, any]:
        """
        Get statistics about the generated grid.
        
        Returns:
            Dictionary with grid statistics
        """
        all_tokens = [token for row in self.tokens for token in row]
        unique_tokens = set(all_tokens)
        
        return {
            "total_tokens": len(all_tokens),
            "unique_tokens": len(unique_tokens),
            "collision_rate": 1.0 - (len(unique_tokens) / len(all_tokens)),
            "grid_dimensions": f"{TOKENS_WIDE}x{TOKENS_TALL}",
            "token_length": CHARS_PER_TOKEN
        }


class CSVExporter:
    """Handle CSV export of grid data for card generation."""
    
    @staticmethod
    def export_to_csv(
        grid: SeederGrid,
        card_id: str,
        filename: str = "Seeds.csv"
    ) -> None:
        """
        Export grid data to CSV format compatible with card template.
        
        Args:
            grid: SeederGrid instance containing the token matrix
            card_id: Unique identifier for this card/matrix
            filename: Output CSV filename
            
        Raises:
            GridGenerationError: If export fails
        """
        try:
            # Generate SHA-512 hash for integrity
            import hashlib
            seed_hash = hashlib.sha512(grid.seed_bytes).hexdigest()
            short_hash = seed_hash[:6].upper()  # First 6 chars in uppercase for Code39 barcode
            
            # Format tokens for CSV (newline-separated rows)
            tokens_str = grid.get_grid_as_string()
            
            # Prepare CSV row
            csv_row = {
                "ID": card_id,
                "Date": datetime.now().strftime("%Y-%m-%d"),
                "SHORT_HASH": short_hash,
                "SHA512": seed_hash,
                "Tokens": tokens_str
            }
            
            # Write to CSV (append mode)
            file_exists = False
            try:
                with open(filename, 'r'):
                    file_exists = True
            except FileNotFoundError:
                pass
            
            with open(filename, 'a', newline='', encoding='utf-8') as csvfile:
                fieldnames = ["ID", "Date", "SHORT_HASH", "SHA512", "Tokens"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                if not file_exists:
                    writer.writeheader()
                
                writer.writerow(csv_row)
            
            # logger.log_csv_export(filename, card_id, success=True)
            
        except Exception as e:
            # logger.log_csv_export(filename, card_id, success=False, error=str(e))
            raise GridGenerationError(f"CSV export failed: {e}") from e


class CoordinateUtils:
    """Utility functions for coordinate manipulation.
    
    Spreadsheet convention: letter=column (A-J), number=row (0-9)
    A0=top-left, J0=top-right, A9=bottom-left, J9=bottom-right
    """
    
    @staticmethod
    def validate_coordinate(coordinate: str) -> bool:
        """
        Validate coordinate format.
        
        Spreadsheet convention: letter=column (A-J), number=row (0-9)
        
        Args:
            coordinate: Coordinate string to validate (e.g., "A0", "J9")
            
        Returns:
            True if valid, False otherwise
        """
        if not isinstance(coordinate, str) or len(coordinate) != 2:
            return False
        
        col_char, row_char = coordinate.upper()  # Letter=column, Number=row
        return ('A' <= col_char <= 'J') and ('0' <= row_char <= '9')
    
    @staticmethod
    def coordinate_to_indices(coordinate: str) -> Tuple[int, int]:
        """
        Convert coordinate to row/column indices.
        
        Spreadsheet convention: letter=column (A-J), number=row (0-9)
        
        Args:
            coordinate: Grid coordinate (e.g., "A0" = col 0, row 0)
            
        Returns:
            Tuple of (row, column) indices for matrix[row][col] access
            
        Raises:
            CoordinateError: If coordinate is invalid
        """
        if not CoordinateUtils.validate_coordinate(coordinate):
            raise CoordinateError(f"Invalid coordinate: {coordinate}")
        
        coord = coordinate.upper()
        col = ord(coord[0]) - ord('A')
        row = int(coord[1])
        
        return (row, col)
    
    @staticmethod
    def indices_to_coordinate(row: int, col: int) -> str:
        """
        Convert row/column indices to coordinate.
        
        Spreadsheet convention: letter=column (A-J), number=row (0-9)
        
        Args:
            row: Row index (0-9) - becomes the number in coordinate
            col: Column index (0-9) - becomes the letter in coordinate
            
        Returns:
            Coordinate string (e.g., row=0, col=0 -> "A0")
            
        Raises:
            CoordinateError: If indices are out of range
        """
        if not (0 <= row <= 9) or not (0 <= col <= 9):
            raise CoordinateError(f"Indices out of range: row={row}, col={col}")
        
        col_char = chr(ord('A') + col)
        return f"{col_char}{row}"
    
    @staticmethod
    def get_adjacent_coordinates(coordinate: str) -> List[str]:
        """
        Get coordinates adjacent to given coordinate.
        
        Args:
            coordinate: Center coordinate
            
        Returns:
            List of valid adjacent coordinates
        """
        row, col = CoordinateUtils.coordinate_to_indices(coordinate)
        adjacent = []
        
        for dr in [-1, 0, 1]:
            for dc in [-1, 0, 1]:
                if dr == 0 and dc == 0:
                    continue  # Skip center
                
                new_row, new_col = row + dr, col + dc
                if 0 <= new_row <= 9 and 0 <= new_col <= 9:
                    adjacent.append(CoordinateUtils.indices_to_coordinate(new_row, new_col))
        
        return adjacent


# Example usage and testing
if __name__ == "__main__":
    print("CR80 Grid Demo")
    print("=" * 20)
    
    # Create test grid
    test_seed = b'x' * 64  # Test seed
    grid = SeederGrid(test_seed)
    
    # Test basic operations
    print(f"Token at A0: {grid.get_token('A0')}")
    print(f"Token at J9: {grid.get_token('J9')}")
    
    # Test pattern retrieval
    diagonal = ["A0", "B1", "C2", "D3"]
    tokens = grid.get_tokens_by_pattern(diagonal)
    print(f"Diagonal tokens: {' '.join(tokens)}")
    
    # Test statistics
    stats = grid.get_grid_statistics()
    print(f"Grid stats: {stats}")
    
    # Test coordinate validation
    print(f"A0 valid: {CoordinateUtils.validate_coordinate('A0')}")
    print(f"Z9 valid: {CoordinateUtils.validate_coordinate('Z9')}")
