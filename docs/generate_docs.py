#!/usr/bin/env python3
"""
API Documentation Generator
Generates Markdown documentation from OpenAPI spec
"""

import json
import os
from collections import defaultdict
from typing import Any, Dict, List

DOCS_DIR = os.path.dirname(os.path.abspath(__file__))
OPENAPI_PATH = os.path.join(DOCS_DIR, 'openapi', 'openapi.json')
API_DIR = os.path.join(DOCS_DIR, 'api')


def load_openapi_spec() -> Dict[str, Any]:
    """Load OpenAPI spec from JSON file."""
    with open(OPENAPI_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_schema_example(schema: Dict[str, Any], components: Dict[str, Any], depth: int = 0) -> Any:
    """Generate example value from schema."""
    if depth > 5:
        return "..."

    if '$ref' in schema:
        ref_path = schema['$ref'].split('/')[-1]
        if ref_path in components.get('schemas', {}):
            return get_schema_example(components['schemas'][ref_path], components, depth + 1)
        return {}

    if 'example' in schema:
        return schema['example']

    if 'default' in schema:
        return schema['default']

    schema_type = schema.get('type', 'object')

    if schema_type == 'string':
        if schema.get('format') == 'date-time':
            return "2024-01-15T10:30:00Z"
        if schema.get('format') == 'date':
            return "2024-01-15"
        if schema.get('format') == 'email':
            return "user@example.com"
        if schema.get('format') == 'uuid':
            return "550e8400-e29b-41d4-a716-446655440000"
        if schema.get('format') == 'uri':
            return "https://example.com"
        if 'enum' in schema:
            return schema['enum'][0]
        return "string"
    elif schema_type == 'integer':
        return 1
    elif schema_type == 'number':
        return 1.0
    elif schema_type == 'boolean':
        return True
    elif schema_type == 'array':
        items = schema.get('items', {})
        return [get_schema_example(items, components, depth + 1)]
    elif schema_type == 'object':
        props = schema.get('properties', {})
        result = {}
        for prop_name, prop_schema in list(props.items())[:10]:  # Limit properties
            result[prop_name] = get_schema_example(prop_schema, components, depth + 1)
        return result

    return None


def schema_to_table(schema: Dict[str, Any], components: Dict[str, Any], required: List[str] = None) -> str:
    """Convert schema properties to markdown table."""
    if '$ref' in schema:
        ref_path = schema['$ref'].split('/')[-1]
        if ref_path in components.get('schemas', {}):
            schema = components['schemas'][ref_path]
        else:
            return f"*Reference: {ref_path}*\n"

    props = schema.get('properties', {})
    if not props:
        return "*No parameters*\n"

    required = required or schema.get('required', [])

    lines = ["| Field | Type | Required | Description |", "|-------|------|----------|-------------|"]

    for prop_name, prop_schema in props.items():
        prop_type = prop_schema.get('type', 'any')
        if '$ref' in prop_schema:
            prop_type = prop_schema['$ref'].split('/')[-1]
        if prop_type == 'array':
            items_type = prop_schema.get('items', {}).get('type', 'any')
            if '$ref' in prop_schema.get('items', {}):
                items_type = prop_schema['items']['$ref'].split('/')[-1]
            prop_type = f"array[{items_type}]"

        is_required = "Yes" if prop_name in required else "No"
        description = prop_schema.get('description', '-').replace('\n', ' ')[:100]

        lines.append(f"| {prop_name} | {prop_type} | {is_required} | {description} |")

    return '\n'.join(lines) + '\n'


def get_auth_requirement(security: List[Dict]) -> str:
    """Get authentication requirement string."""
    if not security:
        return "None"

    auth_types = []
    for sec in security:
        auth_types.extend(sec.keys())

    if 'OAuth2PasswordBearer' in auth_types or 'bearerAuth' in auth_types:
        return "Bearer Token (JWT)"
    if 'APIKeyHeader' in auth_types:
        return "API Key"

    return "Required"


def generate_endpoint_doc(path: str, method: str, details: Dict[str, Any], components: Dict[str, Any]) -> str:
    """Generate documentation for a single endpoint."""
    method_upper = method.upper()
    summary = details.get('summary', 'No summary')
    description = details.get('description', summary)

    # Authentication
    security = details.get('security', [])
    auth = get_auth_requirement(security)

    doc = f"## {method_upper} {path}\n\n"
    doc += f"**Description**: {description}\n\n"
    doc += f"**Authentication**: {auth}\n\n"

    # Path parameters
    path_params = [p for p in details.get('parameters', []) if p.get('in') == 'path']
    if path_params:
        doc += "**Path Parameters**:\n"
        doc += "| Parameter | Type | Required | Description |\n"
        doc += "|-----------|------|----------|-------------|\n"
        for param in path_params:
            p_type = param.get('schema', {}).get('type', 'string')
            p_desc = param.get('description', '-')
            doc += f"| {param['name']} | {p_type} | Yes | {p_desc} |\n"
        doc += "\n"

    # Query parameters
    query_params = [p for p in details.get('parameters', []) if p.get('in') == 'query']
    if query_params:
        doc += "**Query Parameters**:\n"
        doc += "| Parameter | Type | Required | Description |\n"
        doc += "|-----------|------|----------|-------------|\n"
        for param in query_params:
            p_type = param.get('schema', {}).get('type', 'string')
            p_required = "Yes" if param.get('required', False) else "No"
            p_desc = param.get('description', '-')
            p_default = param.get('schema', {}).get('default')
            if p_default is not None:
                p_desc += f" (default: {p_default})"
            doc += f"| {param['name']} | {p_type} | {p_required} | {p_desc} |\n"
        doc += "\n"

    # Request body
    request_body = details.get('requestBody', {})
    if request_body:
        doc += "**Request Body**:\n"
        content = request_body.get('content', {})
        for content_type, content_schema in content.items():
            schema = content_schema.get('schema', {})
            doc += schema_to_table(schema, components)
            doc += "\n"

            # Example
            example = get_schema_example(schema, components)
            if example:
                doc += "**Request Example**:\n```json\n"
                doc += json.dumps(example, indent=2)
                doc += "\n```\n\n"
            break  # Only show first content type

    # Responses
    responses = details.get('responses', {})
    for status_code, response in responses.items():
        if status_code.startswith('2'):
            doc += f"**Response {status_code}**:\n"
            resp_desc = response.get('description', '')
            if resp_desc:
                doc += f"{resp_desc}\n\n"

            content = response.get('content', {})
            for content_type, content_schema in content.items():
                schema = content_schema.get('schema', {})
                example = get_schema_example(schema, components)
                if example:
                    doc += "```json\n"
                    doc += json.dumps(example, indent=2)
                    doc += "\n```\n\n"
                break
            break

    # Error codes
    error_codes = []
    for status_code, response in responses.items():
        if not status_code.startswith('2'):
            error_codes.append(f"- **{status_code}**: {response.get('description', 'Error')}")

    if error_codes:
        doc += "**Error Codes**:\n"
        doc += '\n'.join(error_codes)
        doc += "\n\n"

    doc += "---\n\n"
    return doc


def generate_tag_doc(tag: str, endpoints: List[Dict], components: Dict[str, Any]) -> str:
    """Generate documentation for a tag/router."""
    tag_title = tag.replace('-', ' ').title()

    doc = f"# {tag_title} API\n\n"
    doc += f"API endpoints for {tag_title.lower()} functionality.\n\n"
    doc += "## Table of Contents\n\n"

    # TOC
    for endpoint in endpoints:
        method = endpoint['method'].upper()
        path = endpoint['path']
        anchor = f"{method.lower()}-{path.replace('/', '-').replace('{', '').replace('}', '')}"
        summary = endpoint['details'].get('summary', path)
        doc += f"- [{method} {path}](#{anchor}) - {summary}\n"

    doc += "\n---\n\n"

    # Endpoints
    for endpoint in endpoints:
        doc += generate_endpoint_doc(
            endpoint['path'],
            endpoint['method'],
            endpoint['details'],
            components
        )

    return doc


def main():
    """Main function to generate all documentation."""
    print("Loading OpenAPI spec...")
    spec = load_openapi_spec()

    components = spec.get('components', {})
    paths = spec.get('paths', {})

    # Group endpoints by tag
    endpoints_by_tag = defaultdict(list)

    for path, methods in paths.items():
        for method, details in methods.items():
            if method not in ['get', 'post', 'put', 'delete', 'patch']:
                continue

            tags = details.get('tags', ['untagged'])
            for tag in tags:
                endpoints_by_tag[tag].append({
                    'path': path,
                    'method': method,
                    'details': details
                })

    # Create API docs directory
    os.makedirs(API_DIR, exist_ok=True)

    # Generate per-tag documentation
    print(f"Generating documentation for {len(endpoints_by_tag)} tags...")
    tag_files = []

    for tag, endpoints in sorted(endpoints_by_tag.items()):
        tag_file = f"{tag.lower().replace(' ', '_').replace('-', '_')}.md"
        tag_path = os.path.join(API_DIR, tag_file)

        doc = generate_tag_doc(tag, endpoints, components)

        with open(tag_path, 'w', encoding='utf-8') as f:
            f.write(doc)

        tag_files.append((tag, tag_file, len(endpoints)))
        print(f"  - {tag}: {len(endpoints)} endpoints -> {tag_file}")

    # Generate main API reference
    print("Generating API_REFERENCE.md...")

    main_doc = """# Media Center Arti Marziali - API Reference

Complete API documentation for the Media Center Arti Marziali platform.

## Overview

- **Base URL**: `http://localhost:8000` (development) / `https://api.example.com` (production)
- **API Version**: v1
- **OpenAPI Version**: 3.1.0
- **Total Endpoints**: {total_endpoints}

## Authentication

Most endpoints require authentication via JWT Bearer token.

### Getting a Token

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{{"email": "user@example.com", "password": "password"}}'
```

### Using the Token

```bash
curl http://localhost:8000/api/v1/users/me \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## API Sections

| Section | Endpoints | Description |
|---------|-----------|-------------|
"""

    total_endpoints = sum(len(endpoints) for endpoints in endpoints_by_tag.values())
    main_doc = main_doc.format(total_endpoints=total_endpoints)

    for tag, tag_file, count in sorted(tag_files, key=lambda x: x[0]):
        tag_title = tag.replace('-', ' ').title()
        main_doc += f"| [{tag_title}](api/{tag_file}) | {count} | {tag_title} API |\n"

    main_doc += """
## Quick Links

- [Authentication](api/auth.md) - Login, register, token refresh
- [Users](api/users.md) - User management
- [Videos](api/videos.md) - Video content management
- [Live](api/live.md) - Live streaming
- [Payments](api/payments.md) - Payment processing
- [Admin](api/admin.md) - Administration

## Error Handling

All API errors follow a consistent format:

```json
{
  "detail": "Error message description",
  "status_code": 400
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Missing or invalid token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - Resource already exists |
| 422 | Validation Error - Invalid data format |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error |

## Rate Limiting

API requests are rate limited:
- Anonymous: 100 requests/minute
- Authenticated: 1000 requests/minute
- Admin: 5000 requests/minute

## Pagination

List endpoints support pagination:

```
GET /api/v1/videos?skip=0&limit=20
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| skip | integer | 0 | Number of items to skip |
| limit | integer | 20 | Maximum items to return |

## OpenAPI Spec

The complete OpenAPI specification is available at:
- JSON: `/openapi.json`
- Swagger UI: `/docs`
- ReDoc: `/redoc`

---

*Generated automatically from OpenAPI specification*
"""

    with open(os.path.join(DOCS_DIR, 'API_REFERENCE.md'), 'w', encoding='utf-8') as f:
        f.write(main_doc)

    print(f"\nDone! Generated:")
    print(f"  - API_REFERENCE.md")
    print(f"  - {len(tag_files)} tag documentation files in api/")
    print(f"  - Total endpoints documented: {total_endpoints}")


if __name__ == '__main__':
    main()
