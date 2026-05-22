# Hybrid SecOps Ingestion & AI Remediator

This project is a hybrid AI-powered threat analysis pipeline designed to triage, sanitize, and remediate authentication logs in real time while minimizing cloud API costs.

```
[Raw Logs] ──> [Local Python Engine] ──(If Severity >= High)──> [Token-Optimized LLM] ──> [Strategic Advice]
                     │
                     └──> Immediate Local Playbook Actions

```


The system combines deterministic local Python execution with targeted LLM-based analysis to separate immediate threat containment from deeper semantic investigation. A local Python engine ingests raw authentication logs, classifies event severity using regex and rule-based detection logic, and redacts sensitive telemetry such as internal IP addresses before any external processing occurs.

For critical or high-severity detections, the pipeline triggers immediate local response actions such as privilege restriction and network isolation without waiting for cloud inference. Only high-risk events are forwarded to the LLM through a compressed, token-efficient payload, where the model generates contextual remediation guidance, investigation summaries, and long-term security recommendations.

This architecture reduces unnecessary API usage, lowers response latency, and improves operational efficiency by combining fast local execution with AI-assisted analysis. By filtering and sanitizing telemetry before transmission, the framework also supports stronger privacy controls and reduced cloud processing overhead.

Technologies Used:
Python • Regex • Azure OpenAI/OpenAI API • Security Automation • Log Analysis • Threat Detection • AI-Assisted Incident Response

