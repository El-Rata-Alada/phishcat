#hi. thanks for being here.
#will add details hortly.
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "phishcat"
version = "0.1.0"
description = "Rule-based email phishing analysis tool (.eml)"
readme = "README.md"
requires-python = ">=3.9"
authors = [
  { name = "PhishCat" }
]

dependencies = [
  "beautifulsoup4",
  "lxml",
  "python-magic; platform_system != 'Windows'",
  "python-magic-bin; platform_system == 'Windows'"
]

[project.scripts]
phishcat = "phishcat.cli:main"

[tool.setuptools]
packages = ["phishcat", "phishcat.modules"]
