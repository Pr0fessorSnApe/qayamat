"""QAYAMAT — GraphQL Analyzer
Performs introspection, deep query generation, and attack surface analysis on GraphQL endpoints.
"""

import requests
from typing import Dict, Any, List, Optional, Set


INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""


class GraphQLAnalyzer:
    def __init__(self, endpoint: str, headers: Optional[Dict[str, str]] = None, timeout: int = 15):
        self.endpoint = endpoint
        self.headers = headers or {}
        self.timeout = timeout
        self.schema: Optional[Dict] = None

    def fetch_schema(self) -> Optional[Dict]:
        """Run GraphQL introspection and store the schema."""
        try:
            resp = requests.post(
                self.endpoint,
                json={"query": INTROSPECTION_QUERY},
                headers=self.headers,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                self.schema = data.get("data", {}).get("__schema")
        except Exception:
            self.schema = None
        return self.schema

    def _resolve_type_name(self, type_obj: dict) -> Optional[str]:
        """Unwrap NON_NULL / LIST wrappers to get the base type name."""
        if not type_obj:
            return None
        if type_obj.get("name"):
            return type_obj["name"]
        return self._resolve_type_name(type_obj.get("ofType"))

    def _get_fields_for_type(self, type_name: str, depth: int, max_depth: int, visited: Set[str]) -> List[str]:
        if depth >= max_depth or type_name in visited or not self.schema:
            return []

        visited = visited | {type_name}   # immutable copy — avoid shared state across branches

        for t in self.schema.get("types", []):
            if t.get("name") != type_name or t.get("kind") != "OBJECT":
                continue
            fields = t.get("fields") or []
            result = []
            for f in fields:
                field_type_name = self._resolve_type_name(f.get("type", {}))
                base_kind = f.get("type", {}).get("kind") or (
                    f.get("type", {}).get("ofType") or {}
                ).get("kind", "")
                if field_type_name and base_kind in ("OBJECT", "INTERFACE") and depth + 1 < max_depth:
                    nested = self._get_fields_for_type(field_type_name, depth + 1, max_depth, visited)
                    if nested:
                        result.append(f"{f['name']} {{ {' '.join(nested)} }}")
                        continue
                result.append(f["name"])
            return result

        return []

    def generate_deep_nested_query(self, root_field: Optional[str] = None, max_depth: int = 3) -> str:
        """Generate an example query that follows relationships up to max_depth levels."""
        if not self.schema:
            return ""

        query_type_name = (self.schema.get("queryType") or {}).get("name", "Query")

        if not root_field:
            for t in self.schema.get("types", []):
                if t.get("name") == query_type_name and t.get("fields"):
                    root_field = t["fields"][0]["name"]
                    break

        if not root_field:
            return ""

        fields = self._get_fields_for_type(query_type_name, 0, max_depth, set())
        if fields:
            return f"{{ {root_field} {{ {' '.join(fields)} }} }}"
        return f"{{ {root_field} }}"

    def detect_issues(self) -> List[Dict[str, str]]:
        """Return a list of potential security issues discovered via introspection."""
        issues = []

        if self.schema is None:
            issues.append({
                "type": "introspection_disabled",
                "severity": "Info",
                "message": "GraphQL introspection is disabled or endpoint unreachable.",
            })
            return issues

        # Introspection is enabled — that itself may be an issue in production
        issues.append({
            "type": "introspection_enabled",
            "severity": "Low",
            "message": "GraphQL introspection is enabled. Disable in production.",
        })

        sensitive_names = {"user", "account", "admin", "password", "secret", "token", "key"}
        for t in self.schema.get("types", []):
            if t.get("kind") == "OBJECT" and t.get("name", "").lower() in sensitive_names:
                issues.append({
                    "type": "sensitive_type_exposed",
                    "severity": "Medium",
                    "message": f"Sensitive object type '{t['name']}' exposed in schema.",
                })

        return issues

    def check_depth_limit(self, depth: int = 10) -> Optional[Dict]:
        """Test whether the endpoint enforces query depth limits."""
        # Build a deeply nested query
        nested = "id"
        for _ in range(depth):
            nested = f"friends {{ {nested} }}"
        query = f"{{ user {{ {nested} }} }}"
        try:
            resp = requests.post(
                self.endpoint,
                json={"query": query},
                headers=self.headers,
                timeout=self.timeout,
            )
            data = resp.json()
            if "errors" not in data:
                return {
                    "type": "no_depth_limit",
                    "severity": "Medium",
                    "message": f"No query depth limit detected (tested depth {depth}).",
                }
        except Exception:
            pass
        return None
