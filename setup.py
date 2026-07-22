#!/usr/bin/env python3
from setuptools import setup

setup(
    name="recon-tool",
    version="6.0.0",
    description="Multi-source OSINT recon tool — emails, subdomains, IPs, URLs, takeovers",
    author="PORT 777",
    author_email="",
    url="https://github.com/PORT-777/recon-tool",
    py_modules=["recon"],
    entry_points={
        "console_scripts": [
            "recon=recon:main",
        ],
    },
    install_requires=[
        "httpx",
        "beautifulsoup4",
        "lxml",
        "colorama",
    ],
    python_requires=">=3.9",
)
