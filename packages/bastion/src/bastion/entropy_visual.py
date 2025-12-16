"""Entropy visualization using matplotlib.

This module creates visual representations of entropy data
to help assess randomness quality through visual inspection.
"""

import io
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from typing import Optional


def visualize_entropy(
    entropy_bytes: bytes,
    output_path: Optional[Path] = None,
    title: str = "Entropy Visualization",
    return_bytes: bool = False,
) -> Path | bytes:
    """Create visual representation of entropy data.
    
    Generates two visualizations:
    1. Byte frequency histogram (should be roughly uniform for good entropy)
    2. Bit pattern grid (visual inspection for patterns)
    
    Args:
        entropy_bytes: Entropy data to visualize
        output_path: Optional output file path (default: entropy_visual.png)
        title: Title for the visualization
        return_bytes: If True, return PNG bytes instead of saving to file
        
    Returns:
        Path to saved PNG file, or PNG bytes if return_bytes=True
    """
    # Convert bytes to numpy array
    byte_array = np.frombuffer(entropy_bytes, dtype=np.uint8)
    
    # Create figure with two subplots
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
    fig.suptitle(title, fontsize=16, fontweight='bold')
    
    # Subplot 1: Byte frequency histogram
    ax1.hist(byte_array, bins=256, range=(0, 256), color='steelblue', alpha=0.7, edgecolor='black')
    ax1.axhline(y=len(byte_array)/256, color='red', linestyle='--', linewidth=1, 
                label=f'Expected frequency ({len(byte_array)/256:.1f})')
    ax1.set_xlabel('Byte Value (0-255)', fontsize=12)
    ax1.set_ylabel('Frequency', fontsize=12)
    ax1.set_title('Byte Frequency Distribution (should be roughly uniform)', fontsize=14)
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Add statistics text
    mean_val = np.mean(byte_array)
    std_val = np.std(byte_array)
    ax1.text(0.02, 0.98, f'Mean: {mean_val:.2f} (ideal: 127.5)\nStd Dev: {std_val:.2f} (ideal: ~74)',
             transform=ax1.transAxes, fontsize=10, verticalalignment='top',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    # Subplot 2: Bit pattern grid
    # Convert bytes to bits for visualization
    bit_count = len(entropy_bytes) * 8
    bits = np.unpackbits(byte_array)
    
    # Determine grid size (try to make it roughly square)
    grid_width = min(128, bit_count)  # Max width 128 bits
    grid_height = (bit_count + grid_width - 1) // grid_width
    
    # Pad bits to fill grid
    total_cells = grid_width * grid_height
    if len(bits) < total_cells:
        bits = np.pad(bits, (0, total_cells - len(bits)), constant_values=0)
    else:
        bits = bits[:total_cells]
    
    # Reshape to grid
    bit_grid = bits.reshape(grid_height, grid_width)
    
    # Display as image (0=black, 1=white)
    ax2.imshow(bit_grid, cmap='binary', interpolation='nearest', aspect='auto')
    ax2.set_xlabel(f'Bit Position (width: {grid_width} bits)', fontsize=12)
    ax2.set_ylabel('Bit Rows', fontsize=12)
    ax2.set_title('Bit Pattern Grid (no visible patterns = good randomness)', fontsize=14)
    
    # Add bit count info
    ones_count = np.sum(bits)
    zeros_count = len(bits) - ones_count
    ones_pct = (ones_count / len(bits)) * 100
    ax2.text(0.02, 0.98, f'1-bits: {ones_count} ({ones_pct:.1f}%)\n0-bits: {zeros_count} ({100-ones_pct:.1f}%)\nIdeal: 50% each',
             transform=ax2.transAxes, fontsize=10, verticalalignment='top',
             bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.5))
    
    # Adjust layout and save/return
    plt.tight_layout()
    
    if return_bytes:
        buf = io.BytesIO()
        plt.savefig(buf, format='pdf', bbox_inches='tight')
        plt.close()
        buf.seek(0)
        return buf.getvalue()
    
    if output_path is None:
        output_path = Path("entropy_visual.pdf")
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    return output_path


def visualize_chi_square(
    entropy_bytes: bytes,
    output_path: Optional[Path] = None,
    title: str = "Chi-Square Distribution Analysis",
    return_bytes: bool = False,
) -> Path | bytes:
    """Create chi-square distribution visualization.
    
    Compares observed byte frequencies against expected uniform distribution.
    
    Args:
        entropy_bytes: Entropy data to analyze
        output_path: Optional output file path (default: entropy_chisquare.png)
        title: Title for the visualization
        return_bytes: If True, return PNG bytes instead of saving to file
        
    Returns:
        Path to saved PNG file, or PNG bytes if return_bytes=True
    """
    # Convert bytes to numpy array
    byte_array = np.frombuffer(entropy_bytes, dtype=np.uint8)
    
    # Calculate observed frequencies for each byte value (0-255)
    observed_freq = np.bincount(byte_array, minlength=256)
    
    # Expected frequency (uniform distribution)
    expected_freq = len(byte_array) / 256.0
    
    # Calculate chi-square contributions for each byte value
    chi_square_contrib = ((observed_freq - expected_freq) ** 2) / expected_freq
    
    # Create figure
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
    fig.suptitle(title, fontsize=16, fontweight='bold')
    
    # Subplot 1: Chi-square contributions by byte value
    ax1.bar(range(256), chi_square_contrib, color='steelblue', alpha=0.7, edgecolor='black')
    ax1.set_xlabel('Byte Value (0-255)', fontsize=12)
    ax1.set_ylabel('Chi-Square Contribution', fontsize=12)
    ax1.set_title('Chi-Square Contribution per Byte Value (lower = more uniform)', fontsize=14)
    ax1.grid(True, alpha=0.3, axis='y')
    
    # Calculate total chi-square
    total_chi_square = np.sum(chi_square_contrib)
    degrees_of_freedom = 255  # 256 categories - 1
    
    # Add statistics
    ax1.text(0.02, 0.98, 
             f'Total χ²: {total_chi_square:.2f}\nDegrees of freedom: {degrees_of_freedom}\n'
             f'Expected χ²: {degrees_of_freedom:.0f}\n'
             f'Sample size: {len(byte_array)} bytes',
             transform=ax1.transAxes, fontsize=10, verticalalignment='top',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    # Subplot 2: Deviation from expected frequency
    deviation = observed_freq - expected_freq
    ax2.bar(range(256), deviation, color='coral', alpha=0.7, edgecolor='black')
    ax2.axhline(y=0, color='black', linestyle='-', linewidth=0.5)
    ax2.set_xlabel('Byte Value (0-255)', fontsize=12)
    ax2.set_ylabel('Deviation from Expected', fontsize=12)
    ax2.set_title('Frequency Deviation (should hover near zero)', fontsize=14)
    ax2.grid(True, alpha=0.3, axis='y')
    
    # Add deviation statistics
    max_dev = np.max(np.abs(deviation))
    mean_abs_dev = np.mean(np.abs(deviation))
    ax2.text(0.02, 0.98,
             f'Max deviation: {max_dev:.2f}\nMean |deviation|: {mean_abs_dev:.2f}',
             transform=ax2.transAxes, fontsize=10, verticalalignment='top',
             bbox=dict(boxstyle='round', facecolor='lightgreen', alpha=0.5))
    
    # Adjust layout and save/return
    plt.tight_layout()
    
    if return_bytes:
        buf = io.BytesIO()
        plt.savefig(buf, format='pdf', bbox_inches='tight')
        plt.close()
        buf.seek(0)
        return buf.getvalue()
    
    if output_path is None:
        output_path = Path("entropy_chisquare.pdf")
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    return output_path
