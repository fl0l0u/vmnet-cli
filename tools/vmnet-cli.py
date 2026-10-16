#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vmnet-cli launcher — keeps the single-file entry point working after the
refactor into the vmnet_cli package. Deployed as C:\\ludus\\vmnet-cli.py."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmnet_cli.cli import main

sys.exit(main())
