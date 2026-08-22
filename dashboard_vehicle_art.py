"""High-quality code-rendered vehicle hero art for the production dashboard.

The asset is generated locally with Pillow from deterministic vector-like primitives.
No network request, model-generated image, or runtime telemetry fabrication is used.
"""

from __future__ import annotations

from typing import Tuple


def _rgb(hex_color: str) -> Tuple[int, int, int]:
    value = hex_color.lstrip("#")
    return tuple(int(value[i : i + 2], 16) for i in (0, 2, 4))


def render_vehicle_hero(width: int, height: int):
    """Return an anti-aliased RGBA Pillow image sized for the vehicle overview."""
    from PIL import Image, ImageDraw, ImageFilter

    width = max(420, int(width))
    height = max(250, int(height))
    scale = 3
    w, h = width * scale, height * scale

    bg = Image.new("RGBA", (w, h), (4, 13, 28, 255))
    px = bg.load()
    top = _rgb("#07162d")
    bottom = _rgb("#030915")
    for y in range(h):
        t = y / max(h - 1, 1)
        r = int(top[0] * (1 - t) + bottom[0] * t)
        g = int(top[1] * (1 - t) + bottom[1] * t)
        b = int(top[2] * (1 - t) + bottom[2] * t)
        for x in range(w):
            px[x, y] = (r, g, b, 255)

    # Soft ambient blue glow.
    glow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    cx, cy = w // 2, int(h * 0.67)
    gd.ellipse((cx - int(w * 0.34), cy - int(h * 0.17), cx + int(w * 0.34), cy + int(h * 0.17)), fill=(0, 94, 255, 72))
    glow = glow.filter(ImageFilter.GaussianBlur(int(32 * scale)))
    bg = Image.alpha_composite(bg, glow)

    # Security shield behind the car.
    shield = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shield)
    scx, sy = cx, int(h * 0.12)
    shield_pts = [
        (scx, sy),
        (scx + int(w * 0.105), sy + int(h * 0.07)),
        (scx + int(w * 0.085), sy + int(h * 0.24)),
        (scx, sy + int(h * 0.34)),
        (scx - int(w * 0.085), sy + int(h * 0.24)),
        (scx - int(w * 0.105), sy + int(h * 0.07)),
    ]
    sd.line(shield_pts + [shield_pts[0]], fill=(34, 119, 225, 120), width=2 * scale, joint="curve")
    inner = [(int(scx + (x - scx) * 0.78), int(sy + (y - sy) * 0.78 + 8 * scale)) for x, y in shield_pts]
    sd.line(inner + [inner[0]], fill=(20, 74, 145, 105), width=1 * scale, joint="curve")
    bg = Image.alpha_composite(bg, shield)

    # Holographic platform with bloom.
    platform = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    pd = ImageDraw.Draw(platform)
    platform_y = int(h * 0.81)
    for i, alpha in enumerate((150, 95, 55)):
        rx = int(w * (0.30 + i * 0.035))
        ry = int(h * (0.055 + i * 0.014))
        pd.ellipse((cx - rx, platform_y - ry, cx + rx, platform_y + ry), outline=(15, 132, 255, alpha), width=max(scale, 1))
    pd.ellipse((cx - int(w * 0.23), platform_y - int(h * 0.025), cx + int(w * 0.23), platform_y + int(h * 0.025)), fill=(0, 116, 255, 28))
    bloom = platform.filter(ImageFilter.GaussianBlur(7 * scale))
    bg = Image.alpha_composite(bg, bloom)
    bg = Image.alpha_composite(bg, platform)

    # Vehicle shadow.
    shadow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    shd = ImageDraw.Draw(shadow)
    car_y = int(h * 0.61)
    shd.ellipse((cx - int(w * 0.245), car_y + int(h * 0.12), cx + int(w * 0.265), car_y + int(h * 0.24)), fill=(0, 0, 0, 190))
    shadow = shadow.filter(ImageFilter.GaussianBlur(14 * scale))
    bg = Image.alpha_composite(bg, shadow)

    car = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    cd = ImageDraw.Draw(car)

    # Main body mask and metallic vertical gradient.
    body_pts = [
        (cx - int(w * 0.285), car_y + int(h * 0.055)),
        (cx - int(w * 0.267), car_y + int(h * 0.010)),
        (cx - int(w * 0.225), car_y - int(h * 0.027)),
        (cx - int(w * 0.145), car_y - int(h * 0.060)),
        (cx - int(w * 0.065), car_y - int(h * 0.076)),
        (cx + int(w * 0.045), car_y - int(h * 0.077)),
        (cx + int(w * 0.125), car_y - int(h * 0.057)),
        (cx + int(w * 0.205), car_y - int(h * 0.025)),
        (cx + int(w * 0.270), car_y + int(h * 0.022)),
        (cx + int(w * 0.292), car_y + int(h * 0.065)),
        (cx + int(w * 0.265), car_y + int(h * 0.098)),
        (cx + int(w * 0.205), car_y + int(h * 0.112)),
        (cx - int(w * 0.235), car_y + int(h * 0.112)),
        (cx - int(w * 0.288), car_y + int(h * 0.088)),
    ]
    body_mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(body_mask).polygon(body_pts, fill=255)
    metallic = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    mp = metallic.load()
    c1, c2, c3 = _rgb("#168cff"), _rgb("#0751b9"), _rgb("#062c72")
    y0 = car_y - int(h * 0.09)
    y1 = car_y + int(h * 0.12)
    for y in range(max(0, y0), min(h, y1 + 1)):
        t = (y - y0) / max(y1 - y0, 1)
        if t < 0.45:
            q = t / 0.45
            rgb = tuple(int(c1[i] * (1 - q) + c2[i] * q) for i in range(3))
        else:
            q = (t - 0.45) / 0.55
            rgb = tuple(int(c2[i] * (1 - q) + c3[i] * q) for i in range(3))
        for x in range(w):
            mp[x, y] = (*rgb, 255)
    car.alpha_composite(Image.composite(metallic, Image.new("RGBA", (w, h)), body_mask))
    cd = ImageDraw.Draw(car)
    cd.line(body_pts + [body_pts[0]], fill=(68, 199, 255, 255), width=2 * scale, joint="curve")

    # Cabin and glass.
    cabin_pts = [
        (cx - int(w * 0.120), car_y - int(h * 0.061)),
        (cx - int(w * 0.075), car_y - int(h * 0.145)),
        (cx + int(w * 0.035), car_y - int(h * 0.158)),
        (cx + int(w * 0.112), car_y - int(h * 0.067)),
    ]
    cd.polygon(cabin_pts, fill=(6, 26, 53, 255), outline=(61, 187, 255, 255))
    cd.polygon([
        cabin_pts[0],
        (cx - int(w * 0.065), car_y - int(h * 0.133)),
        (cx - int(w * 0.012), car_y - int(h * 0.138)),
        (cx - int(w * 0.022), car_y - int(h * 0.066)),
    ], fill=(9, 34, 66, 255), outline=(32, 100, 160, 255))
    cd.polygon([
        (cx - int(w * 0.005), car_y - int(h * 0.139)),
        (cx + int(w * 0.030), car_y - int(h * 0.145)),
        (cx + int(w * 0.094), car_y - int(h * 0.069)),
        (cx - int(w * 0.014), car_y - int(h * 0.067)),
    ], fill=(5, 24, 49, 255), outline=(30, 90, 145, 255))

    # Sculpting, lights, intakes, side skirt.
    cd.line((cx - int(w * 0.265), car_y + int(h * 0.035), cx - int(w * 0.110), car_y - int(h * 0.027), cx + int(w * 0.060), car_y - int(h * 0.030)), fill=(127, 231, 255, 235), width=2 * scale)
    cd.line((cx + int(w * 0.072), car_y - int(h * 0.030), cx + int(w * 0.215), car_y + int(h * 0.010)), fill=(32, 150, 245, 235), width=2 * scale)
    cd.line((cx - int(w * 0.232), car_y + int(h * 0.073), cx + int(w * 0.226), car_y + int(h * 0.075)), fill=(11, 61, 126, 255), width=2 * scale)
    cd.polygon([
        (cx + int(w * 0.060), car_y + int(h * 0.010)),
        (cx + int(w * 0.130), car_y + int(h * 0.018)),
        (cx + int(w * 0.108), car_y + int(h * 0.077)),
        (cx + int(w * 0.050), car_y + int(h * 0.067)),
    ], fill=(3, 20, 44, 225), outline=(21, 107, 183, 255))
    cd.polygon([
        (cx - int(w * 0.273), car_y + int(h * 0.024)),
        (cx - int(w * 0.205), car_y + int(h * 0.005)),
        (cx - int(w * 0.220), car_y + int(h * 0.031)),
        (cx - int(w * 0.275), car_y + int(h * 0.046)),
    ], fill=(191, 247, 255, 245))
    cd.polygon([
        (cx + int(w * 0.218), car_y - int(h * 0.002)),
        (cx + int(w * 0.260), car_y + int(h * 0.020)),
        (cx + int(w * 0.225), car_y + int(h * 0.026)),
    ], fill=(101, 218, 255, 220))

    # Wheels with layered rims and red brake calipers.
    wheel_y = car_y + int(h * 0.090)
    wheel_r = int(h * 0.070)
    for wheel_x in (cx - int(w * 0.185), cx + int(w * 0.190)):
        cd.ellipse((wheel_x - wheel_r - 3 * scale, wheel_y - wheel_r - 3 * scale, wheel_x + wheel_r + 3 * scale, wheel_y + wheel_r + 3 * scale), fill=(2, 6, 13, 255), outline=(21, 73, 120, 255), width=2 * scale)
        cd.ellipse((wheel_x - int(wheel_r * 0.72), wheel_y - int(wheel_r * 0.72), wheel_x + int(wheel_r * 0.72), wheel_y + int(wheel_r * 0.72)), fill=(12, 20, 31, 255), outline=(110, 132, 153, 255), width=2 * scale)
        cd.ellipse((wheel_x - int(wheel_r * 0.27), wheel_y - int(wheel_r * 0.27), wheel_x + int(wheel_r * 0.27), wheel_y + int(wheel_r * 0.27)), fill=(161, 37, 59, 255), outline=(255, 84, 107, 255), width=scale)
        for angle in range(0, 360, 45):
            import math
            r = int(wheel_r * 0.62)
            a = math.radians(angle)
            cd.line((wheel_x, wheel_y, wheel_x + int(math.cos(a) * r), wheel_y + int(math.sin(a) * r)), fill=(145, 158, 172, 255), width=scale)
        cd.ellipse((wheel_x - 4 * scale, wheel_y - 4 * scale, wheel_x + 4 * scale, wheel_y + 4 * scale), fill=(203, 217, 229, 255))

    # Mirror and aerodynamic accents.
    cd.ellipse((cx + int(w * 0.105), car_y - int(h * 0.065), cx + int(w * 0.138), car_y - int(h * 0.046)), fill=(7, 69, 151, 255), outline=(57, 189, 255, 255), width=scale)
    cd.line((cx - int(w * 0.170), car_y + int(h * 0.105), cx + int(w * 0.205), car_y + int(h * 0.105)), fill=(13, 126, 224, 255), width=2 * scale)

    # Gloss highlights and subtle bloom on the body.
    highlights = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    hd = ImageDraw.Draw(highlights)
    hd.line((cx - int(w * 0.205), car_y - int(h * 0.016), cx - int(w * 0.040), car_y - int(h * 0.058), cx + int(w * 0.075), car_y - int(h * 0.050)), fill=(117, 231, 255, 110), width=3 * scale)
    hd.line((cx - int(w * 0.120), car_y + int(h * 0.015), cx + int(w * 0.155), car_y + int(h * 0.020)), fill=(36, 175, 255, 85), width=2 * scale)
    highlights = highlights.filter(ImageFilter.GaussianBlur(scale))
    car = Image.alpha_composite(car, highlights)

    bg = Image.alpha_composite(bg, car)
    return bg.resize((width, height), Image.Resampling.LANCZOS)
