from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="sentinel-eye",
    version="0.1.0",
    description="Security Information and Event Management / Host-based Intrusion Detection System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="SentinelEye",
    author_email="dev@sentinel-eye.io",
    url="https://github.com/sentinel-eye/sentinel-eye",
    packages=find_packages(include=["src", "src.*"]),
    package_dir={"": "."},
    include_package_data=True,
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "sentinel-eye=src.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
)
