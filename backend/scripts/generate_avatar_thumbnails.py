#!/usr/bin/env python3
"""
================================================================================
    Script: Generate Avatar Thumbnails
================================================================================

AI_MODULE: generate_avatar_thumbnails
AI_DESCRIPTION: Genera thumbnails PNG 256x256 dai modelli GLB avatar
AI_BUSINESS: Fornisce preview visive per galleria avatar nel frontend

USAGE:
    cd backend
    python scripts/generate_avatar_thumbnails.py
    python scripts/generate_avatar_thumbnails.py --size 512
    python scripts/generate_avatar_thumbnails.py --force

REQUIREMENTS:
    pip install trimesh pillow pyglet pyrender numpy

OUTPUT:
    - storage/avatars/thumbnails/*.png (256x256 default)
    - Database updated con thumbnail_url

================================================================================
"""

import sys
import os
import argparse
from pathlib import Path
from datetime import datetime

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# ============================================================================
# Configuration
# ============================================================================

STORAGE_PATH = Path(__file__).parent.parent / "storage" / "avatars"
MODELS_PATH = STORAGE_PATH / "models"
THUMBNAILS_PATH = STORAGE_PATH / "thumbnails"

DEFAULT_SIZE = 256
DEFAULT_BACKGROUND = (240, 240, 245, 255)  # Light gray


# ============================================================================
# Thumbnail Generation
# ============================================================================

def generate_thumbnail_trimesh(glb_path: Path, output_path: Path, size: int = 256) -> bool:
    """
    Generate thumbnail using trimesh + pyrender.

    Args:
        glb_path: Path to GLB file
        output_path: Path to save PNG thumbnail
        size: Image size (width = height)

    Returns:
        True if successful, False otherwise
    """
    try:
        import trimesh
        import numpy as np
        from PIL import Image

        # Load the GLB file
        scene = trimesh.load(str(glb_path))

        # Handle different return types
        if isinstance(scene, trimesh.Scene):
            # Get all meshes from scene
            geometries = list(scene.geometry.values())
            if not geometries:
                print(f"  Warning: No geometries in scene")
                return generate_placeholder_thumbnail(output_path, size)

            # Combine all meshes
            combined = trimesh.util.concatenate(geometries)
        elif isinstance(scene, trimesh.Trimesh):
            combined = scene
        else:
            print(f"  Warning: Unexpected mesh type: {type(scene)}")
            return generate_placeholder_thumbnail(output_path, size)

        # Try pyrender for better quality
        try:
            import pyrender

            # Create pyrender scene
            pr_scene = pyrender.Scene(bg_color=np.array(DEFAULT_BACKGROUND) / 255.0)

            # Create mesh
            mesh = pyrender.Mesh.from_trimesh(combined)
            pr_scene.add(mesh)

            # Set up camera
            camera = pyrender.PerspectiveCamera(yfov=np.pi / 3.0)

            # Calculate camera position based on mesh bounds
            bounds = combined.bounds
            center = combined.centroid
            extent = np.max(bounds[1] - bounds[0])
            camera_distance = extent * 2.0

            # Position camera
            camera_pose = np.eye(4)
            camera_pose[:3, 3] = center + np.array([0, extent * 0.3, camera_distance])
            pr_scene.add(camera, pose=camera_pose)

            # Add light
            light = pyrender.DirectionalLight(color=np.ones(3), intensity=3.0)
            light_pose = np.eye(4)
            light_pose[:3, 3] = center + np.array([extent, extent, extent])
            pr_scene.add(light, pose=light_pose)

            # Render
            renderer = pyrender.OffscreenRenderer(size, size)
            color, _ = renderer.render(pr_scene)
            renderer.delete()

            # Save image
            image = Image.fromarray(color)
            image.save(str(output_path), 'PNG')
            return True

        except ImportError:
            print("  pyrender not available, using basic render")
            pass
        except Exception as e:
            print(f"  pyrender failed: {e}, using basic render")
            pass

        # Fallback: basic trimesh rendering
        try:
            # Get scene bounds for camera positioning
            bounds = combined.bounds
            center = combined.centroid
            extent = np.max(bounds[1] - bounds[0])

            # Create a scene for rendering
            render_scene = trimesh.Scene(combined)

            # Try to render with trimesh's built-in renderer
            png_data = render_scene.save_image(resolution=[size, size])

            if png_data:
                # Save the rendered image
                with open(output_path, 'wb') as f:
                    f.write(png_data)
                return True

        except Exception as e:
            print(f"  trimesh render failed: {e}")

        # Final fallback: placeholder
        return generate_placeholder_thumbnail(output_path, size)

    except ImportError as e:
        print(f"  Missing dependency: {e}")
        return generate_placeholder_thumbnail(output_path, size)
    except Exception as e:
        print(f"  Error generating thumbnail: {e}")
        return generate_placeholder_thumbnail(output_path, size)


def generate_placeholder_thumbnail(output_path: Path, size: int = 256) -> bool:
    """
    Generate a placeholder thumbnail with avatar icon.

    Args:
        output_path: Path to save PNG
        size: Image size

    Returns:
        True if successful
    """
    try:
        from PIL import Image, ImageDraw, ImageFont

        # Create image with background
        img = Image.new('RGBA', (size, size), DEFAULT_BACKGROUND)
        draw = ImageDraw.Draw(img)

        # Draw a simple avatar silhouette
        center_x = size // 2
        center_y = size // 2

        # Head (circle)
        head_radius = size // 6
        draw.ellipse([
            center_x - head_radius,
            center_y - head_radius * 2,
            center_x + head_radius,
            center_y
        ], fill=(200, 200, 210, 255))

        # Body (rounded rectangle approximation)
        body_width = size // 3
        body_height = size // 3
        draw.ellipse([
            center_x - body_width // 2,
            center_y,
            center_x + body_width // 2,
            center_y + body_height
        ], fill=(200, 200, 210, 255))

        # Add "3D" text
        try:
            font = ImageFont.truetype("arial.ttf", size // 8)
        except:
            font = ImageFont.load_default()

        text = "3D"
        text_bbox = draw.textbbox((0, 0), text, font=font)
        text_width = text_bbox[2] - text_bbox[0]
        text_height = text_bbox[3] - text_bbox[1]

        draw.text(
            (center_x - text_width // 2, size - text_height - size // 10),
            text,
            fill=(100, 100, 120, 255),
            font=font
        )

        # Save
        img.save(str(output_path), 'PNG')
        return True

    except Exception as e:
        print(f"  Error generating placeholder: {e}")
        return False


# ============================================================================
# Database Update
# ============================================================================

def update_database_thumbnails():
    """
    Update avatar records in database with thumbnail URLs.
    """
    try:
        from core.database import SessionLocal
        from models.avatar import Avatar

        db = SessionLocal()
        updated = 0

        # Get all avatars
        avatars = db.query(Avatar).filter(Avatar.is_active == True).all()

        for avatar in avatars:
            # Check if thumbnail exists
            thumbnail_path = THUMBNAILS_PATH / f"{avatar.id}.png"

            if thumbnail_path.exists():
                thumbnail_url = f"/api/v1/avatars/{avatar.id}/thumbnail"

                if avatar.thumbnail_url != thumbnail_url:
                    avatar.thumbnail_url = thumbnail_url
                    updated += 1
                    print(f"  Updated: {avatar.name} -> {thumbnail_url}")

        db.commit()
        db.close()

        return updated

    except Exception as e:
        print(f"  Database update failed: {e}")
        return 0


def get_avatar_model_mapping():
    """
    Get mapping of avatar IDs to their model files.

    Returns dict: {avatar_id: model_filename}
    """
    try:
        from core.database import SessionLocal
        from models.avatar import Avatar

        db = SessionLocal()
        mapping = {}

        avatars = db.query(Avatar).filter(Avatar.is_active == True).all()

        for avatar in avatars:
            # Extract filename from model_url or use known pattern
            avatar_id = str(avatar.id)

            # Check if file exists with avatar ID pattern
            for ext in ['.glb', '.gltf']:
                model_path = MODELS_PATH / f"{avatar_id}{ext}"
                if model_path.exists():
                    mapping[avatar_id] = model_path
                    break

            # Also check for named files (from seed)
            if avatar_id not in mapping:
                # Search by name pattern
                name_slug = avatar.name.lower().replace(' ', '_')
                for model_file in MODELS_PATH.glob(f"*{name_slug}*"):
                    mapping[avatar_id] = model_file
                    break

        # Also add any orphan GLB files
        for glb_file in MODELS_PATH.glob("*.glb"):
            file_id = glb_file.stem
            if file_id not in mapping:
                mapping[file_id] = glb_file

        db.close()
        return mapping

    except Exception as e:
        print(f"  Error getting avatar mapping: {e}")

        # Fallback: just list all GLB files
        mapping = {}
        if MODELS_PATH.exists():
            for glb_file in MODELS_PATH.glob("*.glb"):
                mapping[glb_file.stem] = glb_file
        return mapping


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate avatar thumbnails from GLB models",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_avatar_thumbnails.py                 # Generate all thumbnails
  python generate_avatar_thumbnails.py --size 512     # Use 512x512 size
  python generate_avatar_thumbnails.py --force        # Regenerate existing
  python generate_avatar_thumbnails.py --no-db        # Skip database update
        """
    )

    parser.add_argument(
        '--size',
        type=int,
        default=DEFAULT_SIZE,
        help=f'Thumbnail size in pixels (default: {DEFAULT_SIZE})'
    )

    parser.add_argument(
        '--force',
        action='store_true',
        help='Regenerate existing thumbnails'
    )

    parser.add_argument(
        '--no-db',
        action='store_true',
        help='Skip database update'
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Avatar Thumbnail Generator")
    print("=" * 60)
    print(f"Models path: {MODELS_PATH}")
    print(f"Thumbnails path: {THUMBNAILS_PATH}")
    print(f"Size: {args.size}x{args.size}")
    print()

    # Create thumbnails directory
    THUMBNAILS_PATH.mkdir(parents=True, exist_ok=True)

    # Get avatar model mapping
    print("1. Loading avatar models...")
    mapping = get_avatar_model_mapping()
    print(f"   Found {len(mapping)} models")

    # Generate thumbnails
    print("\n2. Generating thumbnails...")
    generated = 0
    skipped = 0
    failed = 0

    for avatar_id, model_path in mapping.items():
        output_path = THUMBNAILS_PATH / f"{avatar_id}.png"

        # Skip if exists and not forcing
        if output_path.exists() and not args.force:
            print(f"   [SKIP] {avatar_id} (exists)")
            skipped += 1
            continue

        print(f"   Generating: {avatar_id} from {model_path.name}...")

        if generate_thumbnail_trimesh(model_path, output_path, args.size):
            print(f"   [OK] {output_path.name}")
            generated += 1
        else:
            print(f"   [FAIL] {avatar_id}")
            failed += 1

    # Update database
    db_updated = 0
    if not args.no_db:
        print("\n3. Updating database...")
        db_updated = update_database_thumbnails()

    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  Generated: {generated}")
    print(f"  Skipped: {skipped}")
    print(f"  Failed: {failed}")
    print(f"  DB updated: {db_updated}")

    # List generated files
    if THUMBNAILS_PATH.exists():
        thumbnails = list(THUMBNAILS_PATH.glob("*.png"))
        print(f"\n  Total thumbnails: {len(thumbnails)}")
        for thumb in thumbnails[:5]:
            size = thumb.stat().st_size
            print(f"    - {thumb.name} ({size} bytes)")
        if len(thumbnails) > 5:
            print(f"    ... and {len(thumbnails) - 5} more")

    print("\nDone!")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
