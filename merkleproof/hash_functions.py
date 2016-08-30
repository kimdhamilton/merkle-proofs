#!/usr/bin/env python
"""
Hash functions that can be used in building the Merkle Tree. While other functions can be used by chainpoint, these
are the only ones that have been tested by this library.
"""
import hashlib


def sha256(content):
    """Finds the sha256 hash of the content."""
    if isinstance(content, str):
        content = content.encode('utf-8')
    return hashlib.sha256(content).hexdigest()

def md5(content):
    """Finds the md5 hash of the content."""
    return hashlib.md5(content).hexdigest()

def sha512(content):
    """Finds the sha512 hash of the content."""
    return hashlib.sha512(content).hexdigest()

def sha224(content):
    """Finds the sha224 hash of the content."""
    return hashlib.sha224(content).hexdigest()

def sha384(content):
    """Finds the sha384 hash of the content."""
    return hashlib.sha384(content).hexdigest()
