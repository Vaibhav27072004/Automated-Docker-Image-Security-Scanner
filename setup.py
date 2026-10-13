"""
Docker Security Scanner — Python Package Setup
===============================================

Tool configuration (black, isort, mypy, pytest, coverage) lives in
pyproject.toml; flake8 reads .flake8.
"""

from pathlib import Path

from setuptools import find_packages, setup

HERE = Path(__file__).parent

long_description = (HERE / "README.md").read_text(encoding="utf-8")


def read_requirements(filename: str, required: bool = True) -> list[str]:
    """Return the pip requirements listed in ``filename``.

    Only runtime requirements belong in ``install_requires``. Development and
    test tooling is intentionally excluded — it lives in requirements-dev.txt.

    Args:
        filename: Requirements file relative to this setup.py.
        required: When False, a missing file yields an empty list instead of
            raising. The scanner image copies only the runtime requirements, so
            the optional dev extra must not break that build.

    Returns:
        List of requirement specifiers, with comments, blanks and ``-r``
        includes stripped out.
    """
    path = HERE / filename
    if not path.is_file():
        if required:
            raise FileNotFoundError(f"Missing requirements file: {path}")
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    requirements = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        requirements.append(line)
    return requirements


setup(
    name="docker-security-scanner",
    version="1.0.0",
    author="Vaibhav Kumar Sahu",
    author_email="vaibhavkumarsahu25@gmail.com",
    description=(
        "Automated Docker Image Security Scanner — "
        "CVE detection, secret scanning, Dockerfile linting, and SBOM generation"
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Vaibhav27072004/docker-security-scanner",
    project_urls={
        "Source": "https://github.com/Vaibhav27072004/docker-security-scanner",
        "Bug Tracker": "https://github.com/Vaibhav27072004/docker-security-scanner/issues",
        "Documentation": (
            "https://github.com/Vaibhav27072004/docker-security-scanner/tree/main/docs"
        ),
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Software Development :: Build Tools",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    # src-layout: the importable package is docker_security_scanner, not a
    # generic top-level "src" that would collide with every other project.
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    # The HTML report template ships inside the package.
    package_data={"docker_security_scanner": ["templates/*.j2"]},
    python_requires=">=3.10",
    install_requires=read_requirements("requirements.txt"),
    extras_require={"dev": read_requirements("requirements-dev.txt", required=False)},
    entry_points={
        "console_scripts": [
            "docker-scan=docker_security_scanner.scanner:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
