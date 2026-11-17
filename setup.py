import pathlib
from setuptools import find_packages, setup

here = pathlib.Path(__file__).parent.resolve()
long_description = (here / "README.md").read_text(encoding="utf-8")

with open(here / "requirements.txt", encoding="utf-8") as fh:
    install_requires = [
        line.strip() for line in fh if line.strip() and not line.startswith("#")
    ]

setup(
    name="rulepulse",
    version="1.0.0",
    description="Autonomous, read-only Detection Quality & SIEM Drift Assurance Agent using Median/MAD baselines, static DaC auditing, and bounded LLM escalation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lawaleladipo/rulepulse",
    author="Olawale Oladipo",
    author_email="lawaleladipo@gmail.com",
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.10",
    install_requires=install_requires,
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "flake8>=7.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "rulepulse=rulepulse.cli:cli",
        ]
    },
)
