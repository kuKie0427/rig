#!/usr/bin/env python3
"""Thin shim — functionality has moved to rig.eval.trends."""

from rig.eval.trends import *  # noqa: F403
from rig.eval.trends import main

if __name__ == "__main__":
    main()
