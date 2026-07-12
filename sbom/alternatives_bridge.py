"""Suggested remediations for libraries commonly flagged with restrictive/incompatible
licenses. Where the real upstream project ships permissively, that is noted — a copyleft
flag usually means a fork/vendored copy, so "revert to upstream" is the fix.
"""
LIBRARY_ALTERNATIVES = {
    "kafka-clients": "Use the upstream Apache Kafka client (Apache-2.0), or aiokafka (Apache-2.0).",
    "jackson-core": "Gson (Apache-2.0) or org.json (public domain) cover the same JSON parsing needs.",
    "netty-all": "Upstream Netty ships Apache-2.0 — if this is a fork, revert to the official package.",
    "requests": "httpx (BSD-3-Clause) or urllib3 (MIT) are drop-in permissive alternatives.",
    "psycopg2": "psycopg3 (LGPL, linking-safe) or pg8000 (BSD-3-Clause).",
    "cryptography": "Upstream pyca/cryptography ships Apache-2.0/BSD — verify this isn't a modified fork.",
    "safety": "pip-audit (Apache-2.0) covers the same dependency-vulnerability scanning use case.",
    "twisted": "Upstream Twisted ships MIT — if this is a fork, revert; otherwise consider aiohttp (Apache-2.0).",
    "sequelize": "Prisma (Apache-2.0) or TypeORM (MIT) cover the same ORM use case.",
    "knex": "Drizzle ORM (Apache-2.0) is a permissively licensed query-builder alternative.",
    "aws-sdk-go": "Upstream aws-sdk-go ships Apache-2.0 — verify this isn't a modified fork.",
    "json-iterator": "Go's standard library encoding/json avoids the third-party dependency entirely.",
    "numpy": "Upstream NumPy ships BSD-3-Clause — verify this isn't a modified fork.",
    "guava": "Upstream Guava ships Apache-2.0 — verify this isn't a modified fork.",
    "lodash": "Upstream Lodash ships MIT — verify this isn't a modified fork, or use native ES2015+ methods.",
    "moment": "day.js (MIT) or date-fns (MIT) — moment.js is also in maintenance mode, migrate regardless.",
    "nats": "Upstream nats.go ships Apache-2.0 — verify this isn't a modified fork.",
    "logrus": "zap (MIT) or zerolog (MIT) are actively maintained permissive alternatives.",
}
DEFAULT_SUGGESTION = ("Search for a permissively-licensed (MIT/Apache-2.0/BSD) alternative, "
                      "or request a commercial license from the vendor.")


def suggest_alternative(library: str) -> str:
    return LIBRARY_ALTERNATIVES.get(library, DEFAULT_SUGGESTION)
