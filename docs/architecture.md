# Architecture

## Current safe-demo architecture

```text
Simulated exports
  |-- Entra identity evidence (JSON)
  |-- Azure/Sentinel audit evidence (JSON)
          |
          v
Python normalization + control checks
          |
          v
Control mapping (CMMC / NIST 800-171 Rev. 2)
          |
          v
Machine-readable findings (JSON + CSV)
          |
          v
Human-readable compliance report (Markdown)
          |
          v
Risk owner / remediation / evidence follow-up
```

The repository deliberately avoids live credentials. The purpose is to demonstrate the GRC engineering pattern clearly and safely.

## Production-style extension

A real implementation could replace the sample JSON with read-only collectors using Microsoft Graph, Azure Resource Graph, Azure Policy, Defender for Cloud, and Log Analytics. Those collectors should use least-privileged service identities, secrets management, logging, failure handling, and documented evidence provenance.
