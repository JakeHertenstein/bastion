#!/usr/bin/env python3
"""Generate PWA icons for Seed Card web app."""

import os

from PIL import Image, ImageDraw, ImageFont

icons_dir = 'docs/web/public/icons'

for size in [192, 512]:
    img = Image.new('RGB', (size, size), '#1a1a2e')
    draw = ImageDraw.Draw(img)
    
    # Try to use a system font, fallback to default
    font_size = int(size * 0.7)
    font = None
    
    # Try various system fonts
    font_paths = [
        '/System/Library/Fonts/SFNS.ttf',
        '/System/Library/Fonts/SFNSDisplay.ttf', 
        '/System/Library/Fonts/Helvetica.ttc',
        '/Library/Fonts/Arial.ttf',
    ]
    
    for font_path in font_paths:
        try:
            font = ImageFont.truetype(font_path, font_size)
            break
        except:
            continue
    
    if font is None:
        font = ImageFont.load_default()
    
    # Draw 'S' centered
    text = 'S'
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    x = (size - text_width) // 2
    y = (size - text_height) // 2 - bbox[1]
    draw.text((x, y), text, fill='#e0e0e0', font=font)
    
    output_path = f'{icons_dir}/icon-{size}.png'
    img.save(output_path)
    print(f'Created {output_path}')

print('Done!')
print('Done!')
