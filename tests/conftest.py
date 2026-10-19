"""Keep the developer's own credentials out of every test: xrdsec's own test plugin.

:mod:`xrdsec.testing.fixtures` is the hermetic environment, the ``pki`` and
the ``grid_env`` every client's suite loads too; xrdsec's suite has nothing
of its own to add to it. ``pytester`` runs small suites of their own under
the plugin, which is how ``tests/test_testing_fixtures.py`` tests it.
"""

pytest_plugins = ["xrdsec.testing.fixtures", "pytester"]
