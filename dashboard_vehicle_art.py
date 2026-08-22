"""High-quality code-rendered vehicle hero art for the production dashboard.

The asset is generated locally with Pillow from deterministic vector-like primitives.
No network request, model-generated image, or runtime telemetry fabrication is used.
"""

from __future__ import annotations

import math
from typing import Tuple


def _rgb(hex_color: str) -> Tuple[int, int, int]:
    value = hex_color.lstrip("#")
    return tuple(int(value[i : i + 2], 16) for i in (0, 2, 4))


def _lerp(a: Tuple[int, int, int], b: Tuple[int, int, int], t: float) -> Tuple[int, int, int]:
    return tuple(int(a[i] * (1.0 - t) + b[i] * t) for i in range(3))


def _vertical_gradient(image, top: str, bottom: str) -> None:
    """Paint a full-width gradient using one Pillow line per row, not per-pixel Python loops."""
    from PIL import ImageDraw

    draw = ImageDraw.Draw(image)
    c0, c1 = _rgb(top), _rgb(bottom)
    h = image.height
    for y in range(h):
        t = y / max(h - 1, 1)
        draw.line((0, y, image.width, y), fill=(*_lerp(c0, c1, t), 255))


def render_vehicle_hero(width: int, height: int):
    """Return a cached-friendly anti-aliased RGBA hero image for the vehicle overview."""
    from PIL import Image, ImageDraw, ImageFilter

    width = max(420, int(width))
    height = max(250, int(height))
    scale = 3
    w, h = width * scale, height * scale

    bg = Image.new("RGBA", (w, h), (3, 9, 20, 255))
    _vertical_gradient(bg, "#081a34", "#030814")
    cx, cy = w // 2, int(h * 0.67)

    glow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse((cx - int(w * 0.35), cy - int(h * 0.18), cx + int(w * 0.35), cy + int(h * 0.18)), fill=(0, 104, 255, 78))
    bg = Image.alpha_composite(bg, glow.filter(ImageFilter.GaussianBlur(30 * scale)))

    shield = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shield)
    sy = int(h * 0.105)
    shield_pts = [
        (cx, sy),
        (cx + int(w * 0.105), sy + int(h * 0.068)),
        (cx + int(w * 0.084), sy + int(h * 0.240)),
        (cx, sy + int(h * 0.340)),
        (cx - int(w * 0.084), sy + int(h * 0.240)),
        (cx - int(w * 0.105), sy + int(h * 0.068)),
    ]
    sd.line(shield_pts + [shield_pts[0]], fill=(40, 132, 242, 125), width=2 * scale, joint="curve")
    inner = [(int(cx + (x - cx) * 0.77), int(sy + (y - sy) * 0.77 + 8 * scale)) for x, y in shield_pts]
    sd.line(inner + [inner[0]], fill=(20, 79, 155, 105), width=scale, joint="curve")
    bg = Image.alpha_composite(bg, shield)

    platform = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    pd = ImageDraw.Draw(platform)
    platform_y = int(h * 0.825)
    for i, alpha in enumerate((175, 105, 60)):
        rx = int(w * (0.295 + i * 0.037))
        ry = int(h * (0.048 + i * 0.014))
        pd.ellipse((cx - rx, platform_y - ry, cx + rx, platform_y + ry), outline=(22, 144, 255, alpha), width=max(scale, 1))
    pd.ellipse((cx - int(w * 0.235), platform_y - int(h * 0.025), cx + int(w * 0.235), platform_y + int(h * 0.025)), fill=(0, 120, 255, 30))
    bg = Image.alpha_composite(bg, platform.filter(ImageFilter.GaussianBlur(6 * scale)))
    bg = Image.alpha_composite(bg, platform)

    car_y = int(h * 0.61)
    shadow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).ellipse((cx - int(w * 0.25), car_y + int(h * 0.11), cx + int(w * 0.27), car_y + int(h * 0.235)), fill=(0, 0, 0, 205))
    bg = Image.alpha_composite(bg, shadow.filter(ImageFilter.GaussianBlur(13 * scale)))

    car = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    body_pts = [
        (cx - int(w * 0.292), car_y + int(h * 0.060)),
        (cx - int(w * 0.273), car_y + int(h * 0.012)),
        (cx - int(w * 0.226), car_y - int(h * 0.030)),
        (cx - int(w * 0.148), car_y - int(h * 0.061)),
        (cx - int(w * 0.067), car_y - int(h * 0.078)),
        (cx + int(w * 0.046), car_y - int(h * 0.079)),
        (cx + int(w * 0.130), car_y - int(h * 0.057)),
        (cx + int(w * 0.210), car_y - int(h * 0.024)),
        (cx + int(w * 0.276), car_y + int(h * 0.023)),
        (cx + int(w * 0.298), car_y + int(h * 0.066)),
        (cx + int(w * 0.269), car_y + int(h * 0.102)),
        (cx + int(w * 0.206), car_y + int(h * 0.115)),
        (cx - int(w * 0.238), car_y + int(h * 0.115)),
        (cx - int(w * 0.294), car_y + int(h * 0.091)),
    ]
    body_mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(body_mask).polygon(body_pts, fill=255)
    metallic = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    md = ImageDraw.Draw(metallic)
    c1, c2, c3 = _rgb("#1b96ff"), _rgb("#0756c5"), _rgb("#052b6a")
    y0 = max(0, car_y - int(h * 0.095))
    y1 = min(h - 1, car_y + int(h * 0.120))
    for y in range(y0, y1 + 1):
        t = (y - y0) / max(y1 - y0, 1)
        rgb = _lerp(c1, c2, t / 0.44) if t < 0.44 else _lerp(c2, c3, (t - 0.44) / 0.56)
        md.line((0, y, w, y), fill=(*rgb, 255))
    car = Image.alpha_composite(car, Image.composite(metallic, Image.new("RGBA", (w, h), (0, 0, 0, 0)), body_mask))
    cd = ImageDraw.Draw(car)
    cd.line(body_pts + [body_pts[0]], fill=(77, 207, 255, 255), width=2 * scale, joint="curve")

    cabin_pts = [
        (cx - int(w * 0.122), car_y - int(h * 0.061)),
        (cx - int(w * 0.075), car_y - int(h * 0.148)),
        (cx + int(w * 0.036), car_y - int(h * 0.160)),
        (cx + int(w * 0.114), car_y - int(h * 0.067)),
    ]
    cd.polygon(cabin_pts, fill=(5, 25, 52, 255), outline=(71, 204, 255, 255))
    cd.polygon([cabin_pts[0], (cx - int(w * 0.065), car_y - int(h * 0.135)), (cx - int(w * 0.012), car_y - int(h * 0.140)), (cx - int(w * 0.022), car_y - int(h * 0.066))], fill=(8, 37, 72, 255), outline=(31, 105, 170, 255))
    cd.polygon([(cx - int(w * 0.005), car_y - int(h * 0.141)), (cx + int(w * 0.031), car_y - int(h * 0.147)), (cx + int(w * 0.096), car_y - int(h * 0.069)), (cx - int(w * 0.014), car_y - int(h * 0.067))], fill=(4, 24, 49, 255), outline=(29, 92, 148, 255))

    cd.line((cx - int(w * 0.268), car_y + int(h * 0.034), cx - int(w * 0.112), car_y - int(h * 0.028), cx + int(w * 0.063), car_y - int(h * 0.031)), fill=(150, 239, 255, 240), width=2 * scale)
    cd.line((cx + int(w * 0.073), car_y - int(h * 0.030), cx + int(w * 0.220), car_y + int(h * 0.012)), fill=(39, 165, 250, 235), width=2 * scale)
    cd.line((cx - int(w * 0.235), car_y + int(h * 0.074), cx + int(w * 0.232), car_y + int(h * 0.076)), fill=(11, 66, 136, 255), width=2 * scale)
    cd.polygon([(cx + int(w * 0.060), car_y + int(h * 0.010)), (cx + int(w * 0.135), car_y + int(h * 0.019)), (cx + int(w * 0.111), car_y + int(h * 0.080)), (cx + int(w * 0.050), car_y + int(h * 0.069))], fill=(3, 19, 43, 230), outline=(24, 119, 199, 255))

    cd.polygon([(cx - int(w * 0.278), car_y + int(h * 0.022)), (cx - int(w * 0.207), car_y + int(h * 0.003)), (cx - int(w * 0.221), car_y + int(h * 0.031)), (cx - int(w * 0.281), car_y + int(h * 0.048))], fill=(207, 250, 255, 250))
    cd.polygon([(cx + int(w * 0.220), car_y - int(h * 0.002)), (cx + int(w * 0.267), car_y + int(h * 0.021)), (cx + int(w * 0.230), car_y + int(h * 0.028))], fill=(104, 221, 255, 225))

    wheel_y = car_y + int(h * 0.092)
    wheel_r = int(h * 0.071)
    for wheel_x in (cx - int(w * 0.187), cx + int(w * 0.193)):
        cd.ellipse((wheel_x - wheel_r - 3 * scale, wheel_y - wheel_r - 3 * scale, wheel_x + wheel_r + 3 * scale, wheel_y + wheel_r + 3 * scale), fill=(2, 6, 13, 255), outline=(20, 74, 122, 255), width=2 * scale)
        cd.ellipse((wheel_x - int(wheel_r * 0.73), wheel_y - int(wheel_r * 0.73), wheel_x + int(wheel_r * 0.73), wheel_y + int(wheel_r * 0.73)), fill=(12, 20, 31, 255), outline=(116, 137, 157, 255), width=2 * scale)
        cd.ellipse((wheel_x - int(wheel_r * 0.27), wheel_y - int(wheel_r * 0.27), wheel_x + int(wheel_r * 0.27), wheel_y + int(wheel_r * 0.27)), fill=(164, 37, 59, 255), outline=(255, 87, 111, 255), width=scale)
        spoke_r = int(wheel_r * 0.62)
        for angle in range(0, 360, 45):
            a = math.radians(angle)
            cd.line((wheel_x, wheel_y, wheel_x + int(math.cos(a) * spoke_r), wheel_y + int(math.sin(a) * spoke_r)), fill=(151, 164, 178, 255), width=scale)
        cd.ellipse((wheel_x - 4 * scale, wheel_y - 4 * scale, wheel_x + 4 * scale, wheel_y + 4 * scale), fill=(211, 223, 233, 255))

    cd.ellipse((cx + int(w * 0.106), car_y - int(h * 0.066), cx + int(w * 0.140), car_y - int(h * 0.046)), fill=(7, 72, 158, 255), outline=(64, 202, 255, 255), width=scale)
    cd.line((cx - int(w * 0.172), car_y + int(h * 0.108), cx + int(w * 0.210), car_y + int(h * 0.108)), fill=(15, 137, 235, 255), width=2 * scale)

    highlights = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    hd = ImageDraw.Draw(highlights)
    hd.line((cx - int(w * 0.208), car_y - int(h * 0.016), cx - int(w * 0.041), car_y - int(h * 0.060), cx + int(w * 0.077), car_y - int(h * 0.051)), fill=(133, 237, 255, 115), width=3 * scale)
    hd.line((cx - int(w * 0.122), car_y + int(h * 0.014), cx + int(w * 0.160), car_y + int(h * 0.020)), fill=(44, 185, 255, 90), width=2 * scale)
    car = Image.alpha_composite(car, highlights.filter(ImageFilter.GaussianBlur(scale)))

    bg = Image.alpha_composite(bg, car)
    return bg.resize((width, height), Image.Resampling.LANCZOS)
