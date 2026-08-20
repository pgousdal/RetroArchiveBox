# Physical Preservation Workflow

M6.12 provides one safe operator sequence while retaining the lower-level
expert commands. Normal mode is:

    rab preserve doctor
    rab preserve intake begin --provenance original_physical_owned --platform amiga
    rab preserve devices
    rab preserve plan --candidate optical:DEVICE --title "Descriptive title"
    rab preserve next --candidate optical:DEVICE --title "Descriptive title"
    rab preserve report rab-preserve-ID

`preserve next` discovers, inspects, registers/selects the physical medium,
plans, requests confirmation, captures read-only, verifies and ingests into CAS,
then analyzes only the immutable master. It submits eligible immutable objects
to the configured AVBox provider, records returned malware coverage, rebuilds
identity, produces scoped metadata products, writes a final report, and reports
whether operator removal is appropriate. `preserve eject` intentionally returns
`OPERATOR_EJECT_REQUIRED`; M6.12 never unmounts unrelated filesystems or
controls hardware implicitly.

Use `rab preserve resume RUN` after interruption. A completed capture or CAS
ingest is reused; resume does not reread physical media merely because analysis
failed. Use `rab preserve review` for repeated-read disagreement, ambiguous
devices, unsupported layouts, partial reads, missing preservation-critical
tools, or limits requiring judgment. Cancellation retains completed masters.

## Profiles and completion

- `quick`: one capture, metadata-only analysis, minimal products.
- `standard`: one verified capture, bounded contained-byte preservation,
  a `current-standard` AVBox request, and normal reports.
- `conservative`: two captures, required equality, deeper bounded analysis.

`COMPLETE` means the requested profile completed. `COMPLETE_WITH_WARNINGS`
means preservation succeeded but optional downstream coverage was incomplete.
`PARTIAL` retains useful incomplete evidence. `FAILED` means no acceptable
requested representation resulted. `NEEDS_OPERATOR` means automation cannot
make a preservation-safe decision. Malware detection never deletes or repairs
content. Ownership and provenance never grant redistribution.

If AVBox is disabled or unreachable, requests remain `PENDING_PROVIDER` and the
workflow becomes `COMPLETE_WITH_WARNINGS`; preserved media need not be
reinserted. Later run `rab malware pending` and `rab malware submit-pending`.
Provider detection still leaves the preservation workflow successful.

## First real ingest checklist

1. Run `rab preserve doctor` for the intended media class.
2. Verify preservation and staging free space.
3. Start an intake session with explicit provenance and rights defaults.
4. Insert one known, non-critical operator-supplied test medium.
5. Inspect the generated plan and its limitations.
6. Run the standard workflow.
7. Inspect the final report and review queue.
8. Verify physical-medium-to-capture linkage and master fixity.
9. Inspect contained-object analysis and source relationships.
10. Inspect malware coverage; missing optional scanners are warnings.
11. Inspect derived products and identity entries.
12. Begin batch ingest only after the complete workflow is satisfactory.

This checklist is preparation only. Automated tests use generated synthetic
fixtures and never enumerate or access developer host devices. Real-hardware
and real-collection qualification have not been performed.
