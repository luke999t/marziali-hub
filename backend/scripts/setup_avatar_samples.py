#!/usr/bin/env python3
"""
================================================================================
    Setup Script: Avatar Sample Files
================================================================================

AI_MODULE: setup_avatar_samples
AI_DESCRIPTION: Genera file GLB di esempio per test avatar API
AI_BUSINESS: Setup ambiente test con modelli 3D validi
AI_USAGE: python scripts/setup_avatar_samples.py

FUNZIONALITA:
  1. Crea directory storage/avatars/models/ se non esiste
  2. Genera 3+ file GLB validi minimali per test
  3. Opzionalmente scarica modelli da repository pubblici

OUTPUT:
  - storage/avatars/models/sample_realistic.glb
  - storage/avatars/models/sample_cartoon.glb
  - storage/avatars/models/sample_anime.glb
  - storage/avatars/models/test_avatar.glb

================================================================================
"""

import os
import sys
import json
import struct
import argparse
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.error


# ============================================================================
# Configuration
# ============================================================================

STORAGE_DIR = Path(__file__).parent.parent / "storage" / "avatars" / "models"

# Public GLB files from GitHub (glTF sample models)
PUBLIC_GLB_URLS = {
    "duck": "https://raw.githubusercontent.com/KhronosGroup/glTF-Sample-Models/master/2.0/Duck/glTF-Binary/Duck.glb",
    "box": "https://raw.githubusercontent.com/KhronosGroup/glTF-Sample-Models/master/2.0/Box/glTF-Binary/Box.glb",
    "avocado": "https://raw.githubusercontent.com/KhronosGroup/glTF-Sample-Models/master/2.0/Avocado/glTF-Binary/Avocado.glb",
}

# Avatar styles to generate
AVATAR_STYLES = ["realistic", "cartoon", "anime", "stylized"]


# ============================================================================
# GLB Generation
# ============================================================================

def create_minimal_glb(output_path: Path, name: str = "Root") -> bool:
    """
    Create a minimal valid GLB file.

    GLB Format:
    - 12-byte header: magic (4) + version (4) + length (4)
    - JSON chunk: length (4) + type (4) + data (padded to 4 bytes)

    Args:
        output_path: Path where to save the GLB file
        name: Name for the root node

    Returns:
        True if successful, False otherwise
    """
    try:
        # Create minimal valid glTF JSON
        gltf_json = json.dumps({
            "asset": {
                "version": "2.0",
                "generator": "MediaCenter Avatar Setup Script"
            },
            "scene": 0,
            "scenes": [
                {
                    "name": f"Scene_{name}",
                    "nodes": [0]
                }
            ],
            "nodes": [
                {
                    "name": name,
                    "translation": [0, 0, 0],
                    "rotation": [0, 0, 0, 1],
                    "scale": [1, 1, 1]
                }
            ]
        }, separators=(',', ':')).encode('utf-8')

        # Pad JSON to 4-byte boundary (GLB requirement)
        json_padding = (4 - len(gltf_json) % 4) % 4
        gltf_json_padded = gltf_json + b' ' * json_padding

        # Calculate lengths
        json_chunk_length = len(gltf_json_padded)
        total_length = 12 + 8 + json_chunk_length  # header + chunk header + json

        # Write GLB file
        with open(output_path, 'wb') as f:
            # GLB Header
            f.write(struct.pack('<I', 0x46546C67))  # magic: "glTF" in little-endian
            f.write(struct.pack('<I', 2))            # version: 2
            f.write(struct.pack('<I', total_length)) # total file length

            # JSON Chunk Header
            f.write(struct.pack('<I', json_chunk_length))  # chunk data length
            f.write(struct.pack('<I', 0x4E4F534A))         # chunk type: "JSON" in little-endian

            # JSON Chunk Data
            f.write(gltf_json_padded)

        return True

    except Exception as e:
        print(f"Error creating GLB file {output_path}: {e}")
        return False


def create_avatar_glb(output_path: Path, style: str, gender: str = "neutral") -> bool:
    """
    Create a GLB file representing an avatar with specific style.

    This creates a slightly more complex model with a basic humanoid structure.

    Args:
        output_path: Path where to save the GLB file
        style: Avatar style (realistic, cartoon, anime, stylized)
        gender: Avatar gender (male, female, neutral)

    Returns:
        True if successful, False otherwise
    """
    try:
        # Create a more complex glTF with multiple nodes (basic skeleton)
        gltf_data = {
            "asset": {
                "version": "2.0",
                "generator": "MediaCenter Avatar Setup Script",
                "copyright": "Test Avatar for Integration Testing"
            },
            "scene": 0,
            "scenes": [
                {
                    "name": f"Avatar_{style}_{gender}",
                    "nodes": [0]
                }
            ],
            "nodes": [
                # Root node
                {
                    "name": "Armature",
                    "children": [1],
                    "translation": [0, 0, 0]
                },
                # Hips (root bone)
                {
                    "name": "Hips",
                    "children": [2, 3, 4],
                    "translation": [0, 1.0, 0]
                },
                # Spine
                {
                    "name": "Spine",
                    "children": [5],
                    "translation": [0, 0.2, 0]
                },
                # Left Upper Leg
                {
                    "name": "LeftUpperLeg",
                    "children": [6],
                    "translation": [-0.1, -0.1, 0]
                },
                # Right Upper Leg
                {
                    "name": "RightUpperLeg",
                    "children": [7],
                    "translation": [0.1, -0.1, 0]
                },
                # Chest
                {
                    "name": "Chest",
                    "children": [8, 9, 10],
                    "translation": [0, 0.3, 0]
                },
                # Left Lower Leg
                {
                    "name": "LeftLowerLeg",
                    "children": [11],
                    "translation": [0, -0.4, 0]
                },
                # Right Lower Leg
                {
                    "name": "RightLowerLeg",
                    "children": [12],
                    "translation": [0, -0.4, 0]
                },
                # Neck
                {
                    "name": "Neck",
                    "children": [13],
                    "translation": [0, 0.2, 0]
                },
                # Left Upper Arm
                {
                    "name": "LeftUpperArm",
                    "children": [14],
                    "translation": [-0.2, 0, 0]
                },
                # Right Upper Arm
                {
                    "name": "RightUpperArm",
                    "children": [15],
                    "translation": [0.2, 0, 0]
                },
                # Left Foot
                {
                    "name": "LeftFoot",
                    "translation": [0, -0.4, 0.1]
                },
                # Right Foot
                {
                    "name": "RightFoot",
                    "translation": [0, -0.4, 0.1]
                },
                # Head
                {
                    "name": "Head",
                    "translation": [0, 0.15, 0]
                },
                # Left Lower Arm
                {
                    "name": "LeftLowerArm",
                    "children": [16],
                    "translation": [-0.25, 0, 0]
                },
                # Right Lower Arm
                {
                    "name": "RightLowerArm",
                    "children": [17],
                    "translation": [0.25, 0, 0]
                },
                # Left Hand
                {
                    "name": "LeftHand",
                    "translation": [-0.2, 0, 0]
                },
                # Right Hand
                {
                    "name": "RightHand",
                    "translation": [0.2, 0, 0]
                }
            ],
            "extensionsUsed": [],
            "extras": {
                "avatar_style": style,
                "avatar_gender": gender,
                "created_for": "integration_testing"
            }
        }

        gltf_json = json.dumps(gltf_data, separators=(',', ':')).encode('utf-8')

        # Pad to 4-byte boundary
        json_padding = (4 - len(gltf_json) % 4) % 4
        gltf_json_padded = gltf_json + b' ' * json_padding

        # Calculate lengths
        json_chunk_length = len(gltf_json_padded)
        total_length = 12 + 8 + json_chunk_length

        # Write GLB
        with open(output_path, 'wb') as f:
            f.write(struct.pack('<I', 0x46546C67))  # magic
            f.write(struct.pack('<I', 2))            # version
            f.write(struct.pack('<I', total_length)) # length
            f.write(struct.pack('<I', json_chunk_length))
            f.write(struct.pack('<I', 0x4E4F534A))   # JSON
            f.write(gltf_json_padded)

        return True

    except Exception as e:
        print(f"Error creating avatar GLB {output_path}: {e}")
        return False


# ============================================================================
# Download Functions
# ============================================================================

def download_glb(url: str, output_path: Path, timeout: int = 30) -> bool:
    """
    Download a GLB file from URL.

    Args:
        url: URL to download from
        output_path: Path to save the file
        timeout: Request timeout in seconds

    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"  Downloading from {url}...")
        request = urllib.request.Request(
            url,
            headers={'User-Agent': 'MediaCenter-Avatar-Setup/1.0'}
        )

        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read()

            # Verify it's a valid GLB (check magic number)
            if len(data) >= 4 and struct.unpack('<I', data[:4])[0] == 0x46546C67:
                with open(output_path, 'wb') as f:
                    f.write(data)
                return True
            else:
                print(f"  Downloaded file is not a valid GLB")
                return False

    except urllib.error.URLError as e:
        print(f"  Download failed: {e}")
        return False
    except Exception as e:
        print(f"  Error downloading: {e}")
        return False


# ============================================================================
# Main Setup Functions
# ============================================================================

def setup_directory() -> bool:
    """Create the storage directory if it doesn't exist."""
    try:
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        print(f"Storage directory: {STORAGE_DIR}")
        return True
    except Exception as e:
        print(f"Error creating directory: {e}")
        return False


def generate_sample_avatars() -> int:
    """
    Generate sample avatar GLB files for all styles.

    Returns:
        Number of files successfully created
    """
    created = 0

    for style in AVATAR_STYLES:
        output_path = STORAGE_DIR / f"sample_{style}.glb"

        if output_path.exists():
            print(f"  {output_path.name} already exists, skipping")
            created += 1
            continue

        print(f"  Creating {output_path.name}...")
        if create_avatar_glb(output_path, style):
            print(f"  Created {output_path.name}")
            created += 1
        else:
            print(f"  Failed to create {output_path.name}")

    return created


def generate_test_avatar() -> bool:
    """Generate a basic test avatar for unit tests."""
    output_path = STORAGE_DIR / "test_avatar.glb"

    if output_path.exists():
        print(f"  {output_path.name} already exists")
        return True

    print(f"  Creating {output_path.name}...")
    if create_minimal_glb(output_path, "TestAvatar"):
        print(f"  Created {output_path.name}")
        return True
    else:
        print(f"  Failed to create {output_path.name}")
        return False


def download_sample_models(models: list[str] = None) -> int:
    """
    Download sample models from public repositories.

    Args:
        models: List of model names to download, or None for all

    Returns:
        Number of files successfully downloaded
    """
    if models is None:
        models = list(PUBLIC_GLB_URLS.keys())

    downloaded = 0

    for model_name in models:
        if model_name not in PUBLIC_GLB_URLS:
            print(f"  Unknown model: {model_name}")
            continue

        url = PUBLIC_GLB_URLS[model_name]
        output_path = STORAGE_DIR / f"{model_name}.glb"

        if output_path.exists():
            print(f"  {output_path.name} already exists, skipping")
            downloaded += 1
            continue

        if download_glb(url, output_path):
            print(f"  Downloaded {output_path.name}")
            downloaded += 1
        else:
            print(f"  Failed to download {model_name}")

    return downloaded


def verify_files() -> dict:
    """
    Verify all GLB files in the storage directory.

    Returns:
        Dictionary with verification results
    """
    results = {
        "valid": [],
        "invalid": [],
        "total_size": 0
    }

    if not STORAGE_DIR.exists():
        return results

    for glb_file in STORAGE_DIR.glob("*.glb"):
        try:
            with open(glb_file, 'rb') as f:
                header = f.read(12)

                if len(header) >= 12:
                    magic, version, length = struct.unpack('<III', header)

                    if magic == 0x46546C67 and version == 2:
                        file_size = glb_file.stat().st_size
                        results["valid"].append({
                            "name": glb_file.name,
                            "size": file_size,
                            "version": version
                        })
                        results["total_size"] += file_size
                    else:
                        results["invalid"].append(glb_file.name)
                else:
                    results["invalid"].append(glb_file.name)

        except Exception as e:
            results["invalid"].append(f"{glb_file.name} (error: {e})")

    return results


# ============================================================================
# CLI
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Setup avatar sample files for testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup_avatar_samples.py                    # Generate all sample avatars
  python setup_avatar_samples.py --download         # Also download public models
  python setup_avatar_samples.py --verify           # Only verify existing files
  python setup_avatar_samples.py --clean            # Remove all generated files
        """
    )

    parser.add_argument(
        '--download',
        action='store_true',
        help='Download sample models from public repositories'
    )

    parser.add_argument(
        '--verify',
        action='store_true',
        help='Only verify existing files without generating'
    )

    parser.add_argument(
        '--clean',
        action='store_true',
        help='Remove all generated files'
    )

    parser.add_argument(
        '--models',
        nargs='+',
        choices=list(PUBLIC_GLB_URLS.keys()),
        help='Specific models to download'
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Avatar Sample Files Setup")
    print("=" * 60)

    # Clean mode
    if args.clean:
        print("\nCleaning generated files...")
        if STORAGE_DIR.exists():
            for glb_file in STORAGE_DIR.glob("*.glb"):
                print(f"  Removing {glb_file.name}")
                glb_file.unlink()
            print("Done!")
        else:
            print("  No files to clean")
        return 0

    # Verify mode
    if args.verify:
        print("\nVerifying existing files...")
        results = verify_files()

        print(f"\nValid GLB files: {len(results['valid'])}")
        for f in results['valid']:
            print(f"  - {f['name']} ({f['size']} bytes)")

        if results['invalid']:
            print(f"\nInvalid files: {len(results['invalid'])}")
            for f in results['invalid']:
                print(f"  - {f}")

        print(f"\nTotal size: {results['total_size']:,} bytes")
        return 0 if not results['invalid'] else 1

    # Setup mode
    print("\n1. Setting up directory...")
    if not setup_directory():
        return 1

    print("\n2. Generating sample avatars...")
    generated = generate_sample_avatars()

    print("\n3. Generating test avatar...")
    test_ok = generate_test_avatar()

    downloaded = 0
    if args.download:
        print("\n4. Downloading public models...")
        downloaded = download_sample_models(args.models)

    print("\n5. Verifying files...")
    results = verify_files()

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  Generated avatars: {generated}/{len(AVATAR_STYLES)}")
    print(f"  Test avatar: {'OK' if test_ok else 'FAILED'}")
    if args.download:
        print(f"  Downloaded models: {downloaded}")
    print(f"  Total valid files: {len(results['valid'])}")
    print(f"  Total size: {results['total_size']:,} bytes")

    if results['invalid']:
        print(f"\n  WARNING: {len(results['invalid'])} invalid files found")
        return 1

    print("\nSetup complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
