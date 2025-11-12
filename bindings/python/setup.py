#!/usr/bin/env python3
"""
Setup script for SecureAPIs Python bindings
"""

import os
import sys
import subprocess
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py


class BuildRustLibrary(build_py):
    """Custom build_py command that builds the Rust library first"""

    def run(self):
        # Build the Rust library
        rust_dir = os.path.join(os.path.dirname(__file__), '..', '..')
        try:
            subprocess.check_call(['cargo', 'build', '--release'], cwd=rust_dir)
        except subprocess.CalledProcessError as e:
            print(f"Failed to build Rust library: {e}")
            sys.exit(1)

        # Copy the built library to the package directory
        self.copy_rust_library()

        # Run the normal build_py
        super().run()

    def copy_rust_library(self):
        """Copy the built Rust library to the package directory"""
        rust_dir = os.path.join(os.path.dirname(__file__), '..', '..')
        target_dir = os.path.join(rust_dir, 'target', 'release')

        # Determine library name based on platform
        if sys.platform.startswith('win'):
            lib_name = 'secureapis.dll'
        elif sys.platform.startswith('darwin'):
            lib_name = 'libsecureapis.dylib'
        else:
            lib_name = 'libsecureapis.so'

        src_path = os.path.join(target_dir, lib_name)
        dst_path = os.path.join(os.path.dirname(__file__), 'secureapis', lib_name)

        if os.path.exists(src_path):
            import shutil
            shutil.copy2(src_path, dst_path)
            print(f"Copied {lib_name} to package directory")
        else:
            print(f"Warning: {lib_name} not found at {src_path}")


setup(
    name="secureapis",
    version="1.0.0",
    description="High-performance security middleware for Python applications",
    long_description=open(os.path.join(os.path.dirname(__file__), 'README.md')).read(),
    long_description_content_type="text/markdown",
    author="SecureAPIs Contributors",
    author_email="",
    url="https://github.com/secureapis/secureapis",
    packages=find_packages(),
    package_data={
        'secureapis': ['*.dll', '*.so', '*.dylib', '*.config.json'],
    },
    include_package_data=True,
    cmdclass={
        'build_py': BuildRustLibrary,
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
    ],
    python_requires=">=3.8",
    keywords="security api middleware rate-limiting authentication input-validation",
    project_urls={
        "Bug Reports": "https://github.com/secureapis/secureapis/issues",
        "Source": "https://github.com/secureapis/secureapis",
    },
)