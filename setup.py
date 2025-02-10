from setuptools import setup, find_packages

setup(
    name="k8s-security-checker",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "kubernetes>=29.0.0",
        "rich>=13.7.0",
        "requests>=2.31.0",
        "PyYAML>=6.0.1",
        "docker>=7.0.0",
    ],
    entry_points={
        "console_scripts": [
            "k8s-security-check=k8s_security_checker.main:main",
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="A comprehensive security checker for Kubernetes clusters",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/k8s-security-checker",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
) 