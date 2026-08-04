"""Offline tests for the reference archive tool.

Standard library `unittest` only, so running the tests pulls in no dependency.
No test touches the network and no test writes outside a temporary directory.

Run from the repository root:

    python -m unittest discover -s tools/references/tests -t tools/references
"""
