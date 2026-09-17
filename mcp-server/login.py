#!/usr/bin/env python3
"""Sign in to the product service from the terminal.

Runs the same browser flow the MCP server uses, so you can authorize once up
front instead of waiting on a tool call to open the browser mid conversation.

    python login.py            # sign in
    python login.py --status   # show the cached login
    python login.py --logout   # forget the cached tokens
"""

from __future__ import annotations

import sys

import auth


def main(argv: list[str]) -> int:
    if "--logout" in argv:
        print("Signed out." if auth.clear_tokens() else "No cached token to remove.")
        return 0

    if "--status" in argv:
        state = auth.status()
        if not state["logged_in"]:
            print(state["detail"])
            return 1
        print(f"Signed in as {state['user']}")
        print(f"  scopes:     {' '.join(state['scopes']) or '(none)'}")
        print(f"  expires in: {state['access_token_expires_in_seconds']}s")
        print(f"  token file: {state['token_file']}")
        return 0

    print(f"Opening your browser to sign in at {auth.BASE_URL} ...")
    try:
        state = auth.login()
    except auth.AuthError as exc:
        print(f"Login failed: {exc}", file=sys.stderr)
        return 1

    print(f"Signed in as {state['user']}; granted: {' '.join(state['scopes']) or '(none)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
