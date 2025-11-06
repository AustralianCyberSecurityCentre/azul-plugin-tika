# Azul Plugin Tika

Azul plugin for extracting metadata and text using Apache Tika.

Uses https://tika.apache.org/ to extract metadata and text across a variety
of file types. It relies on interfacing to an external tika server, most
commonly deployed as a separate container, running with the plugin's container
in a shared pod.

## Development Installation

To install azul-plugin-tika for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage: azul-tika

Usage on local files:

```bash
azul-plugin-tika --config tika_server http://localhost:9998 example.doc
```

Example Output:

```bash
----- Tika results -----
OK

Output features:
  file_metadata: Page-Count - 1
                 meta:page-count - 1
                 xmpTPg:NPages - 1
                 Revision-Number - 2
                 cp:revision - 2
                 Creation-Date - 2015-07-16T12:19:00Z
                 Last-Modified - 2015-07-16T12:19:00Z
                 Last-Save-Date - 2015-07-16T12:19:00Z
                 date - 2015-07-16T12:19:00Z
                 dcterms:created - 2015-07-16T12:19:00Z
                 dcterms:modified - 2015-07-16T12:19:00Z
                 meta:creation-date - 2015-07-16T12:19:00Z
                 meta:save-date - 2015-07-16T12:19:00Z
                 modified - 2015-07-16T12:19:00Z
                 Character Count - 2311
                 meta:character-count - 2311
                 Word-Count - 405
                 meta:word-count - 405
                 Application-Name - Microsoft Office Word
                 extended-properties:Application - Microsoft Office Word
                 Template - Normal.dotm
                 extended-properties:Template - Normal.dotm
                 Author - Vb1
                 Last-Author - Vb1
                 creator - Vb1
                 dc:creator - Vb1
                 meta:author - Vb1
                 meta:last-author - Vb1
       mimetype: application/msword

Generated child entities (3):
  {'action': 'extracted'} <binary: ebdd2e7d62df7dc836c1b36ae7fc670a8b10fd4e7b38d5c5c718fd7673f0a3c1>
    content: 7110 bytes
  {'action': 'extracted'} <binary: c318703e53a157f59b453b9e84ed99f5ea48c1d6bc55aa691e923ad6844a1a1c>
    content: 13282 bytes
  {'action': 'extracted'} <binary: d371c5a6d5cc6efdfd9e4a6a44316db4f31de75ccf0e20e3bd2e1d64d9f6b443>
    content: 678668 bytes

Feature key:
  file_metadata:  Metadata field extracted by tika, label is the field name
  mimetype:  Magic mime type

```

Automated usage in system:

```bash
azul-tika --config tika_server http://tikaserver:9998 --server http://azul-dispatcher.localnet/
```

## Integration tests

Integration tests are included in this repo and to run them you need to start the apache tika docker image found in the
root directory of this project.

It's recommended to run integration tests when you do version upgrades of Tika.

The provided `docker-compose.yaml` will run the last compatible-tested tika.
Start this with `docker compose up` and then execute `pytest tests` in another session.

Otherwise, to set the tika-server URL for integration tests set the environment variable "TIKA_SERVER_URI"
e.g TIKA_SERVER_URI='http://tikaserver:9998'

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
