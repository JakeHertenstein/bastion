#!/usr/bin/env bash
set -euo pipefail

# Generates raster brand assets from the Bastion SVG logo and a social preview composite.
# Outputs are written to docs/assets/logos/

repo_root="$(cd "$(dirname "$0")"/.. && pwd)"
logo_svg_default="$repo_root/docs/assets/logos/bastion-logo.svg"
out_dir="$repo_root/docs/assets/logos"

logo_svg="$logo_svg_default"
bg_spec="gradient:#dbeafe-#93c5fd"  # default: light blue gradient
title_text="Bastion Security Suite"
text_color="#000000"  # black text for contrast on light background
canvas_size="1280x640"
logo_size="448x448"   # slightly smaller to reduce overlap with text
undercolor="none"      # no banner by default; set to rgba(...) to enable
stroke_color=""
stroke_width="0"
font="Helvetica-Bold"  # bold for readability
gravity="south"        # text position
annotate_y=20          # vertical offset for annotation

# Parse flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    --svg)
      logo_svg="$2"; shift 2;;
    --bg)
      bg_spec="$2"; shift 2;;
    --title)
      title_text="$2"; shift 2;;
    --text-color)
      text_color="$2"; shift 2;;
    --size)
      canvas_size="$2"; shift 2;;
    --logo-size)
      logo_size="$2"; shift 2;;
    --undercolor)
      undercolor="$2"; shift 2;;
    --stroke-color)
      stroke_color="$2"; shift 2;;
    --stroke-width)
      stroke_width="$2"; shift 2;;
    --font)
      font="$2"; shift 2;;
    --gravity)
      gravity="$2"; shift 2;;
    --annotate-y)
      annotate_y="$2"; shift 2;;
    *)
      echo "Unknown option: $1" >&2; exit 1;;
  esac
done

mkdir -p "$out_dir"

have() { command -v "$1" >/dev/null 2>&1; }

render_svg() {
  local svg="$1"; shift
  local w="$1"; shift
  local h="$1"; shift
  local out="$1"; shift
  if have rsvg-convert; then
    rsvg-convert -w "$w" -h "$h" "$svg" -o "$out"
  elif have inkscape; then
    inkscape "$svg" --export-type=png --export-filename="$out" --export-width="$w" --export-height="$h"
  else
    echo "ERROR: Need rsvg-convert (librsvg) or inkscape to rasterize SVG." >&2
    exit 1
  fi
}

make_bg() {
  local size="$1"; shift
  local spec="$1"; shift
  local out="$1"; shift
  local w="${size%x*}"; local h="${size#*x}"
  local type="${spec%%:*}"; local value="${spec#*:}"
  if have magick; then
    case "$type" in
      gradient)
        magick -size "$size" gradient:"$value" "$out" 2>/dev/null || magick -size "$size" xc:"#ffffff" "$out";;
      solid)
        magick -size "$size" xc:"$value" "$out";;
      *)
        magick -size "$size" xc:"#ffffff" "$out";;
    esac
  elif have convert; then
    case "$type" in
      gradient)
        convert -size "$size" gradient:"$value" "$out" 2>/dev/null || convert -size "$size" xc:"#ffffff" "$out";;
      solid)
        convert -size "$size" xc:"$value" "$out";;
      *)
        convert -size "$size" xc:"#ffffff" "$out";;
    esac
  else
    echo "ERROR: Need ImageMagick (magick or convert) to build composite." >&2
    exit 1
  fi
}

compose_social_preview() {
  local bg="$1"; shift
  local logo_png="$1"; shift
  local out="$1"; shift
  local title="$title_text"
  local logo_w="${logo_size%x*}"; local logo_h="${logo_size#*x}"
  if have magick; then
    if [[ "$stroke_width" != "0" && -n "$stroke_color" ]]; then
      if [[ "$undercolor" != "none" ]]; then
        magick "$bg" \( "$logo_png" -resize ${logo_w}x${logo_h} \) -gravity center -composite \
          -font "$font" -pointsize 72 -fill "$text_color" -undercolor "$undercolor" -stroke "$stroke_color" -strokewidth "$stroke_width" \
          -gravity "$gravity" -annotate +0+${annotate_y} "$title" \
          "$out"
      else
        magick "$bg" \( "$logo_png" -resize ${logo_w}x${logo_h} \) -gravity center -composite \
          -font "$font" -pointsize 72 -fill "$text_color" -stroke "$stroke_color" -strokewidth "$stroke_width" \
          -gravity "$gravity" -annotate +0+${annotate_y} "$title" \
          "$out"
      fi
    else
      if [[ "$undercolor" != "none" ]]; then
        magick "$bg" \( "$logo_png" -resize ${logo_w}x${logo_h} \) -gravity center -composite \
          -font "$font" -pointsize 72 -fill "$text_color" -undercolor "$undercolor" \
          -gravity "$gravity" -annotate +0+${annotate_y} "$title" \
          "$out"
      else
        magick "$bg" \( "$logo_png" -resize ${logo_w}x${logo_h} \) -gravity center -composite \
          -font "$font" -pointsize 72 -fill "$text_color" \
          -gravity "$gravity" -annotate +0+${annotate_y} "$title" \
          "$out"
      fi
    fi
  elif have convert; then
    if [[ "$stroke_width" != "0" && -n "$stroke_color" ]]; then
      if [[ "$undercolor" != "none" ]]; then
        convert "$bg" \( "$logo_png" -resize ${logo_w}x${logo_h} \) -gravity center -composite \
          -font "$font" -pointsize 72 -fill "$text_color" -undercolor "$undercolor" -stroke "$stroke_color" -strokewidth "$stroke_width" \
          -gravity "$gravity" -annotate +0+${annotate_y} "$title" \
          "$out"
      else
        convert "$bg" \( "$logo_png" -resize ${logo_w}x${logo_h} \) -gravity center -composite \
          -font "$font" -pointsize 72 -fill "$text_color" -stroke "$stroke_color" -strokewidth "$stroke_width" \
          -gravity "$gravity" -annotate +0+${annotate_y} "$title" \
          "$out"
      fi
    else
      if [[ "$undercolor" != "none" ]]; then
        convert "$bg" \( "$logo_png" -resize ${logo_w}x${logo_h} \) -gravity center -composite \
          -font "$font" -pointsize 72 -fill "$text_color" -undercolor "$undercolor" \
          -gravity "$gravity" -annotate +0+${annotate_y} "$title" \
          "$out"
      else
        convert "$bg" \( "$logo_png" -resize ${logo_w}x${logo_h} \) -gravity center -composite \
          -font "$font" -pointsize 72 -fill "$text_color" \
          -gravity "$gravity" -annotate +0+${annotate_y} "$title" \
          "$out"
      fi
    fi
  else
    echo "ERROR: Need ImageMagick (magick or convert)." >&2
    exit 1
  fi
}

echo "Generating brand assets from: $logo_svg"

# Favicons and icons
render_svg "$logo_svg" 512 512 "$out_dir/icon-512.png"
render_svg "$logo_svg" 180 180 "$out_dir/apple-touch-icon.png"
render_svg "$logo_svg" 32 32 "$out_dir/favicon-32.png"
render_svg "$logo_svg" 16 16 "$out_dir/favicon-16.png"

# Social preview composite
tmp_bg="$out_dir/.social-bg.png"
tmp_logo="$out_dir/.logo-512.png"
render_svg "$logo_svg" ${logo_size%x*} ${logo_size#*x} "$tmp_logo"
make_bg "$canvas_size" "$bg_spec" "$tmp_bg"
compose_social_preview "$tmp_bg" "$tmp_logo" "$out_dir/social-preview.png"
rm -f "$tmp_bg" "$tmp_logo"

echo "Done. Outputs:"
ls -1 "$out_dir" | sed 's/^/  /'
