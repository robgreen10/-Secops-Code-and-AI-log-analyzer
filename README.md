# Hybrid SecOps Ingestion & AI Remediator

This project is a high-performance, cost-optimized threat analysis model designed to triage, sanitize, and remediate system authentication logs. 
By balancing deterministic local code execution with asynchronous cloud intelligence, the pipeline achieves real-time threat containment while keeping 
API overhead exceptionally low.

```
[Raw Logs] ──> [Local Python Engine] ──(If Severity >= High)──> [Token-Optimized LLM] ──> [Strategic Advice]
                     │
                     └──> Immediate Local Playbook Actions

```

Core Architecture & Operational Impact

The local execution layer utilizes native Python and regex to ingest raw log streams from a file on your local host, classify by event severity, and redacts sensitive telemetry like internal IP addresses on the host machine. 
If a critical or high threat signature is matched, this layer executes immediate, zero-latency containment playbooks such as locking privilege tokens or isolating 
affected subnets—without waiting for a network response.

The LLM acts as a senior security analyst, initiating a lean API call to an LLM when critical or high threat thresholds are breached. 
Instead of wasting budget on routine log noise, the AI reviews a highly compressed, token-optimized payload to provide long-term architectural fixes and compliance-driven remediation strategies.

By separating immediate tactical actions from deep semantic reasoning, this hybrid framework dramatically reduces MTTD (Mean Time to Detect) and MTTR (Mean Time to Respond) metrics. Filtering data locally before transmission ensures strict data privacy sovereignty and slashes cloud infrastructure consumption costs.
