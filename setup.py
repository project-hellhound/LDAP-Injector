from setuptools import setup, find_packages

setup(
    name="dnwatch",
    version="1.0",
    description="DNwatch: Advanced LDAP Injection Security Toolkit [HELLHOUND-class]",
    author="Hellhound Security",
    packages=find_packages(),
    py_modules=["dnwatch"],
    entry_points={
        "console_scripts": [
            "dnwatch=dnwatch:main",
        ],
    },
    install_requires=[
        "requests",
        "beautifulsoup4",
        "rich",
    ],
    python_requires=">=3.7",
)
