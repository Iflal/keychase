# This file is intentionally clean — no secrets here.
# Used to verify that the scanner does NOT produce false positives.

import os
import sys


def hello():
    """Just a normal function."""
    name = os.environ.get("USER", "world")
    print(f"Hello, {name}!")
    return name


class Config:
    """A normal config class with no secrets."""
    DEBUG = True
    PORT = 8080
    HOST = "0.0.0.0"
    DATABASE_NAME = "my_app_db"
    LOG_LEVEL = "INFO"
    # Note: passwords should be loaded from env vars, not hardcoded
    # password = os.environ.get("DB_PASSWORD")


if __name__ == "__main__":
    hello()
