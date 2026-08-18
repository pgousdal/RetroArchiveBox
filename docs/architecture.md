# Architecture and preservation boundary

RAB separates the preservation plane from the convenience and analysis plane.

```text
source occurrence -> verified staging copy -> immutable SHA-256 object
                                             | manifest + occurrences + events
                                             +-> read-only analysis/export input
                                                   -> disposable copy/overlay
                                                   -> derivative (when retained)
```

The SQLite catalogue is disposable indexing infrastructure. Critical identity,
fixity, provenance, rights, relationship, and event data are stored in the
content-addressed object tree. One payload is stored for byte-identical content;
every acquisition remains an independent occurrence.

Payload permissions are a guard, not the entire immutability design. Production
deployment should place the object tree on snapshot-capable storage, expose it
read-only to Web/API/emulator services, and grant write access only to a narrow
ingest service account. Append-only/offline replication remains necessary.

## Policy invariants

- Detection creates an event and never deletes, cleans, or repairs a master.
- Export verifies the input and the emitted bytes.
- Existing export paths are never silently overwritten.
- Changed content becomes another object. A retained transformation must carry
  an explicit `derived_from` relationship.
- Emulator inputs are read-only and sessions use disposable overlays.
- Source accessibility is not acquisition permission or redistribution rights.

