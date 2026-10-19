"""Private implementation of :mod:`xrdsec.voms`, one concern per module.

Import from :mod:`xrdsec.voms`; it is the public facade and
re-exports every name these modules define. The pieces, from the bottom of the
import graph up:

- :mod:`.model` - OIDs, the ``Certificate`` protocol, ``VOMSStatus`` and the
  entry/result/diagnostic types.
- :mod:`.diagnostics` - the user-facing wording of trust and I/O failures.
- :mod:`.ac` - strict DER decoding of attribute certificates; no trust.
- :mod:`.trust` - CA-directory anchors and ``vomsdir`` LSC/legacy matching.
- :mod:`.policy` - the per-AC validation pipeline, ending in :mod:`.trust`.
- :mod:`.vomses` - syntax checks for ``vomses`` endpoint configuration.

The facade itself keeps the public entry points (``inspect_voms``,
``validate_voms``, ``check_vomses`` and the default paths), so it reads as the
module's table of contents.
"""
