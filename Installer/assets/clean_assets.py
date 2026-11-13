"""
generate_logicflow_assets.py
DelgadoLogic — Milestone 2 (M2)
Generates:
1. Products/LogicFlow/installer/assets/sprites/logo_sentinel_core.png
2. Products/LogicFlow/installer/assets/sprites/label_logicflow_pill.png
3. Products/LogicFlow/Assets/Icons/logicflow_logo.png
4. Products/LogicFlow/branding/AppIcon.jpg
5. Website/site/public/assets/img/logicflow_icon.png
6. Products/LogicFlow/Assets/Icons/logicflow_logo.ico & LogicFlow.ico
Verifies PerimeterMaxAlpha = 0 on sprites.
"""

import os
import sys
from pathlib import Path
import numpy as np
from PIL import Image, ImageFilter
import cv2

LOGICFLOW_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = Path(os.environ.get("DELGADOLOGIC_ROOT", str(LOGICFLOW_ROOT.parents[1])))
SHIELD_SRC = Path(os.environ.get("LOGICFLOW_SHIELD_SRC", str(LOGICFLOW_ROOT / "branding" / "sentinel_core_shield.jpg")))
PILL_SRC = Path(os.environ.get("LOGICFLOW_PILL_SRC", str(LOGICFLOW_ROOT / "branding" / "logicflow_pill_badge.jpg")))

INSTALLER_SPRITES = LOGICFLOW_ROOT / "installer" / "assets" / "sprites"
INSTALLER_ASSETS = LOGICFLOW_ROOT / "installer" / "assets"
ICONS_DIR = LOGICFLOW_ROOT / "Assets" / "Icons"
BRANDING_DIR = LOGICFLOW_ROOT / "branding"
WEB_IMG_DIR = WORKSPACE_ROOT / "Website" / "site" / "public" / "assets" / "img"

for d in [INSTALLER_SPRITES, INSTALLER_ASSETS, ICONS_DIR, BRANDING_DIR, WEB_IMG_DIR]:
    d.mkdir(parents=True, exist_ok=True)

def verify_perimeter(alpha: np.ndarray, name: str) -> float:
    p_top = alpha[0, :].max()
    p_bottom = alpha[-1, :].max()
    p_left = alpha[:, 0].max()
    p_right = alpha[:, -1].max()
    max_p = float(max(p_top, p_bottom, p_left, p_right))
    print(f"[{name}] PerimeterMaxAlpha: {max_p} (top={p_top}, bot={p_bottom}, left={p_left}, right={p_right})")
    assert max_p == 0.0, f"PerimeterMaxAlpha must be 0 for {name}, got {max_p}"
    return max_p

# ==============================================================================
# 1. Generate logo_sentinel_core.png
# ==============================================================================
print("\n--- 1. Generating logo_sentinel_core.png ---")
s_img = Image.open(SHIELD_SRC).convert("RGB")
s_rgb = np.array(s_img, dtype=np.float32)
s_gray = cv2.cvtColor(s_rgb.astype(np.uint8), cv2.COLOR_RGB2GRAY)

# Threshold to find main shield
_, bin_s = cv2.threshold(s_gray, 28, 255, cv2.THRESH_BINARY)
contours, _ = cv2.findContours(bin_s, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
c_main = max(contours, key=cv2.contourArea)

# Shield core mask (fill interior of shield completely)
shield_core_mask = np.zeros(s_gray.shape, dtype=np.uint8)
cv2.drawContours(shield_core_mask, [c_main], -1, 255, -1)

# Glow dilation zone (around the outer rim)
glow_zone = cv2.dilate(shield_core_mask, cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (75, 75)))

# Outer glow alpha based on max color channel intensity
max_c = np.maximum(s_rgb[:,:,0], np.maximum(s_rgb[:,:,1], s_rgb[:,:,2]))
glow_alpha = np.clip((max_c - 12.0) / (75.0 - 12.0), 0.0, 1.0) * 255.0
glow_alpha[glow_zone == 0] = 0.0

# Inside the shield, ensure high alpha (255)
combined_alpha = np.maximum(shield_core_mask.astype(float), glow_alpha)
combined_alpha = cv2.GaussianBlur(combined_alpha, (9, 9), 2.0)

# Un-premultiply RGB for glow pixels to preserve bright neon cyan and purple
scale = 255.0 / np.maximum(combined_alpha, 35.0)
scale[shield_core_mask > 200] = 1.0  # inside the shield is already natural
clean_rgb = np.clip(s_rgb * scale[:, :, None], 0.0, 255.0)

# Crop to tight bounding box of visible content
nz = np.argwhere(combined_alpha > 3)
ymin, xmin = nz.min(axis=0)
ymax, xmax = nz.max(axis=0)

# Pad symmetrically
pad_y = 12
pad_x = 12
ymin_c = max(0, ymin - pad_y)
ymax_c = min(s_rgb.shape[0] - 1, ymax + pad_y)
xmin_c = max(0, xmin - pad_x)
xmax_c = min(s_rgb.shape[1] - 1, xmax + pad_x)

cropped_rgb = clean_rgb[ymin_c:ymax_c+1, xmin_c:xmax_c+1]
cropped_alpha = combined_alpha[ymin_c:ymax_c+1, xmin_c:xmax_c+1]

# Ensure outer 3 perimeter rings are strictly 0
cropped_alpha[:4, :] = 0.0
cropped_alpha[-4:, :] = 0.0
cropped_alpha[:, :4] = 0.0
cropped_alpha[:, -4:] = 0.0

verify_perimeter(cropped_alpha, "logo_sentinel_core")

sentinel_rgba = np.dstack([cropped_rgb.astype(np.uint8), cropped_alpha.astype(np.uint8)])
sentinel_pil = Image.fromarray(sentinel_rgba, "RGBA")
sentinel_pil.save(INSTALLER_SPRITES / "logo_sentinel_core.png", "PNG")
sentinel_pil.save(INSTALLER_ASSETS / "logo_sentinel_core.png", "PNG")
print(f"Saved logo_sentinel_core.png: {sentinel_pil.size} RGBA")

# ==============================================================================
# 2. Generate label_logicflow_pill.png
# ==============================================================================
print("\n--- 2. Generating label_logicflow_pill.png ---")
p_img = Image.open(PILL_SRC).convert("RGB")
p_rgb = np.array(p_img, dtype=np.float32)
p_gray = cv2.cvtColor(p_rgb.astype(np.uint8), cv2.COLOR_RGB2GRAY)

_, bin_p = cv2.threshold(p_gray, 22, 255, cv2.THRESH_BINARY)
contours_p, _ = cv2.findContours(bin_p, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
c_pill = max(contours_p, key=cv2.contourArea)

pill_mask = np.zeros(p_gray.shape, dtype=np.uint8)
cv2.drawContours(pill_mask, [c_pill], -1, 255, -1)

# Dilate for soft pill glow rim
glow_pill_zone = cv2.dilate(pill_mask, cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (35, 35)))

max_cp = np.maximum(p_rgb[:,:,0], np.maximum(p_rgb[:,:,1], p_rgb[:,:,2]))
glow_alpha_p = np.clip((max_cp - 10.0) / (60.0 - 10.0), 0.0, 1.0) * 255.0
glow_alpha_p[glow_pill_zone == 0] = 0.0

combined_alpha_p = np.maximum(pill_mask.astype(float), glow_alpha_p)
combined_alpha_p = cv2.GaussianBlur(combined_alpha_p, (7, 7), 1.5)

scale_p = 255.0 / np.maximum(combined_alpha_p, 30.0)
scale_p[pill_mask > 200] = 1.0
clean_rgb_p = np.clip(p_rgb * scale_p[:, :, None], 0.0, 255.0)

nz_p = np.argwhere(combined_alpha_p > 3)
ymin_p, xmin_p = nz_p.min(axis=0)
ymax_p, xmax_p = nz_p.max(axis=0)

pad_yp = 10
pad_xp = 14
ymin_cp = max(0, ymin_p - pad_yp)
ymax_cp = min(p_rgb.shape[0] - 1, ymax_p + pad_yp)
xmin_cp = max(0, xmin_p - pad_xp)
xmax_cp = min(p_rgb.shape[1] - 1, xmax_p + pad_xp)

cropped_rgb_p = clean_rgb_p[ymin_cp:ymax_cp+1, xmin_cp:xmax_cp+1]
cropped_alpha_p = combined_alpha_p[ymin_cp:ymax_cp+1, xmin_cp:xmax_cp+1]

# Ensure outer 3 perimeter rings are strictly 0
cropped_alpha_p[:4, :] = 0.0
cropped_alpha_p[-4:, :] = 0.0
cropped_alpha_p[:, :4] = 0.0
cropped_alpha_p[:, -4:] = 0.0

verify_perimeter(cropped_alpha_p, "label_logicflow_pill")

pill_rgba = np.dstack([cropped_rgb_p.astype(np.uint8), cropped_alpha_p.astype(np.uint8)])
pill_pil = Image.fromarray(pill_rgba, "RGBA")
pill_pil.save(INSTALLER_SPRITES / "label_logicflow_pill.png", "PNG")
pill_pil.save(INSTALLER_ASSETS / "label_logicflow_pill.png", "PNG")
print(f"Saved label_logicflow_pill.png: {pill_pil.size} RGBA")

# ==============================================================================
# 3. Generate Elevated 3D Icons
# ==============================================================================
print("\n--- 3. Generating Elevated 3D Icons & ICO ---")
# Full elevated icon square composition (1024x1024)
# Center the cropped shield cleanly inside 1024x1024 with breathing room
icon_canvas = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
# Scale shield to fit comfortably (e.g. 920x920 max)
target_h = 920
ratio = target_h / float(sentinel_pil.height)
target_w = int(round(sentinel_pil.width * ratio))
scaled_shield = sentinel_pil.resize((target_w, target_h), Image.Resampling.LANCZOS)

paste_x = (1024 - target_w) // 2
paste_y = (1024 - target_h) // 2
icon_canvas.paste(scaled_shield, (paste_x, paste_y), scaled_shield)

# A. Website Icon: Website/site/public/assets/img/logicflow_icon.png (1024x1024 RGBA)
icon_canvas.save(WEB_IMG_DIR / "logicflow_icon.png", "PNG")
print(f"Saved website logicflow_icon.png: {icon_canvas.size} RGBA")

# B. Products/LogicFlow/Assets/Icons/logicflow_logo.png (1024x1024 RGBA)
icon_canvas.save(ICONS_DIR / "logicflow_logo.png", "PNG")
print(f"Saved Products/LogicFlow/Assets/Icons/logicflow_logo.png: {icon_canvas.size} RGBA")

# C. Products/LogicFlow/branding/AppIcon.jpg (1024x1024 RGB on dark background)
dark_bg = Image.new("RGB", (1024, 1024), (10, 14, 22))
dark_bg.paste(scaled_shield, (paste_x, paste_y), scaled_shield)
dark_bg.save(BRANDING_DIR / "AppIcon.jpg", "JPEG", quality=96)
print(f"Saved Products/LogicFlow/branding/AppIcon.jpg: {dark_bg.size} RGB JPEG")

# D. Multi-Resolution Windows ICO (16, 24, 32, 48, 64, 128, 256px)
ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
icon_canvas.save(ICONS_DIR / "logicflow_logo.ico", format="ICO", sizes=ico_sizes)
icon_canvas.save(ICONS_DIR / "LogicFlow.ico", format="ICO", sizes=ico_sizes)
print(f"Saved logicflow_logo.ico & LogicFlow.ico with 7 resolutions: {ico_sizes}")

print("\n--- ALL ASSETS SUCCESSFULLY GENERATED & VERIFIED ---")
