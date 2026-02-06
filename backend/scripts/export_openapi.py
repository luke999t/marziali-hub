#!/usr/bin/env python3
"""
Export OpenAPI specification from FastAPI application.

Usage:
    python scripts/export_openapi.py

This script exports the OpenAPI spec to:
    - docs/openapi/openapi.json
    - docs/openapi/openapi.yaml

Requires the backend dependencies to be installed.
"""

import json
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def export_openapi():
    """Export OpenAPI specification to JSON and YAML files."""
    try:
        # Import FastAPI app
        from main import app
    except ImportError as e:
        print(f"Error importing main app: {e}")
        print("Make sure you're running from the backend directory")
        sys.exit(1)

    # Get OpenAPI schema
    openapi_schema = app.openapi()

    # Ensure output directory exists
    output_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'docs', 'openapi'
    )
    os.makedirs(output_dir, exist_ok=True)

    # Export JSON
    json_path = os.path.join(output_dir, 'openapi.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(openapi_schema, f, indent=2, ensure_ascii=False)
    print(f"[OK] Exported OpenAPI JSON to: {json_path}")

    # Export YAML (if pyyaml is available)
    try:
        import yaml
        yaml_path = os.path.join(output_dir, 'openapi.yaml')
        with open(yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump(openapi_schema, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"[OK] Exported OpenAPI YAML to: {yaml_path}")
    except ImportError:
        print("[WARN] PyYAML not installed, skipping YAML export")
        print("       Install with: pip install pyyaml")

    # Print statistics
    paths = openapi_schema.get('paths', {})
    endpoint_count = sum(
        1 for path_methods in paths.values()
        for method in path_methods.keys()
        if method in ['get', 'post', 'put', 'delete', 'patch']
    )

    print(f"\n[INFO] OpenAPI Statistics:")
    print(f"       - API Title: {openapi_schema.get('info', {}).get('title')}")
    print(f"       - API Version: {openapi_schema.get('info', {}).get('version')}")
    print(f"       - OpenAPI Version: {openapi_schema.get('openapi')}")
    print(f"       - Total Endpoints: {endpoint_count}")
    print(f"       - Total Paths: {len(paths)}")


if __name__ == '__main__':
    export_openapi()
