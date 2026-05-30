"""Print a fresh JWT for Jane (analyst at Acme Corp)."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import jwt

from app.core.config import get_settings


def main() -> None:
    settings = get_settings()
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "00000000-0000-0000-0000-00000000a001",
            "email": "jane.morrison@acme.example",
            "aud": "authenticated",
            "role": "authenticated",
            "exp": now + 3600,
            "iat": now,
        },
        settings.SUPABASE_JWT_SECRET,
        algorithm="HS256",
    )
    print(token)


if __name__ == "__main__":
    main()