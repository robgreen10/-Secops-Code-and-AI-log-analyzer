import os
import sys
import re
from dotenv import load_dotenv
from openai import OpenAI

# Force load local .env variables for local MacBook testing
load_dotenv()

# Initialize secure cloud-ready API configuration
api_key = os.environ.get("OPENAI_API_KEY")


class SentinelPipe:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        # Regex setup to capture all IPv4 address configurations
        self.ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    def scan_for_logs(self):
        """Verifies directory existence and reads available log files."""
        if not os.path.exists(self.target_dir):
            print(
                f"[CRITICAL ERROR] Target log directory '{self.target_dir}' missing.")
            sys.exit(1)
        found_files = os.listdir(self.target_dir)
        print(f"[SUCCESS] Ingestion system online. Found files: {found_files}")
        return found_files

    def sanitize_log_data(self, raw_log_text):
        """Finds sensitive network data patterns and masks them to protect privacy."""
        sanitized_text = self.ip_regex.sub(
            "[REDACTED_INTERNAL_IP]", raw_log_text)
        return sanitized_text

    def escalate_to_llm(self, report_context):
        """
        Queries OpenAI API using gpt-4o-mini to get an intelligent,
        context-aware engineering recommendation based on the extracted metrics.
        """
        if not api_key:
            return " -> API CONFIGURATION ERROR: OPENAI_API_KEY environment variable is missing. Unable to fetch AI remediation."

        try:
            client = OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a Senior cybersecurity analyst. You will be given a parsed security metric report. Provide one concise, high-impact sentence containing an accureate security remediation step to mitigate the detected threat vectors."
                    },
                    {"role": "user", "content": f"Review this incident triage summary and provide a next-step remediation action:\n\n{report_context}"}
                ]
            )
            return f" -> AI COMPLIANCE ENGINE RECOMMENDATION: {response.choices[0].message.content.strip()}"
        except Exception as e:
            return f" -> AI ESCALATION FAILURE: Unable to query external intelligence provider: {str(e)}"

    def ai_semantic_analysis(self, sanitized_log_text):
        """
        Advanced Forensic Layer: Maps users to their attempt counts, specific
        threat severities, tracks Source/Destination IP metrics, and selectively
        escalates to an LLM provider for contextual architectural recommendations.
        """
        print("\n[AI ENGINE] Performing deep packet/semantic extraction...")

        log_lines = sanitized_log_text.strip().split("\n")

        highest_severity = "LOW"
        targeted_assets = set()
        incident_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        # List to capture ONLY the specific log lines that warrant AI analysis
        escalation_payload_lines = []

        # Master dictionary to map User -> Counts, Severities, Src IPs, and Dest IPs
        user_forensics = {}

        for line in log_lines:
            if not line.strip():
                continue
            line_lower = line.lower()

            # --- Dynamic Username Extraction Engine ---
            user_match = re.search(r'user\s+(\w+)', line_lower)
            if user_match:
                current_user = user_match.group(1)
            elif "admin" in line_lower:
                current_user = "admin"
            else:
                current_user = "Unknown / System"

            # Dynamically extract all IP tokens present in the current row
            ip_matches = re.findall(r'\[REDACTED_INTERNAL_IP\]', line)

            # Map IPs to Source vs Destination metrics based on count layout
            src_ip = "[REDACTED_SRC_IP]" if len(
                ip_matches) > 0 else "Unknown / Local Event"
            dest_ip = "[REDACTED_DEST_IP]" if len(
                ip_matches) > 1 else "Internal Gateway / Core"

            # --- Severity Classification ---
            if "malicious" in line_lower or "blocked" in line_lower:
                line_severity = "CRITICAL"
                incident_breakdown["CRITICAL"] += 1
                highest_severity = "CRITICAL"
                targeted_assets.add("External Malicious Database Connection")
                escalation_payload_lines.append(
                    f"[USER ID: {current_user}] {line}")

            elif "admin" in line_lower:
                line_severity = "HIGH"
                incident_breakdown["HIGH"] += 1
                if highest_severity != "CRITICAL":
                    highest_severity = "HIGH"
                escalation_payload_lines.append(
                    f"[USER ID: {current_user}] {line}")

            elif "switch" in line_lower or "hardware" in line_lower:
                line_severity = "MEDIUM"
                incident_breakdown["MEDIUM"] += 1
                if highest_severity not in ["CRITICAL", "HIGH"]:
                    highest_severity = "MEDIUM"
                targeted_assets.add("core-switch-01")
            else:
                line_severity = "LOW"
                incident_breakdown["LOW"] += 1

            # --- Update User Forensic Dictionary ---
            if current_user not in user_forensics:
                user_forensics[current_user] = {
                    "attempts": 1,
                    "severities": {line_severity},
                    "src_ips": {src_ip},
                    "dest_ips": {dest_ip}
                }
            else:
                user_forensics[current_user]["attempts"] += 1
                user_forensics[current_user]["severities"].add(line_severity)
                user_forensics[current_user]["src_ips"].add(src_ip)
                user_forensics[current_user]["dest_ips"].add(dest_ip)

        # 3. Format the complete forensics ledger into a clean text report
        user_report_string = ""
        for user, data in user_forensics.items():
            severities_list = ", ".join(data["severities"])
            src_list = ", ".join(data["src_ips"])
            dest_list = ", ".join(data["dest_ips"])

            user_report_string += (
                f"\n   - [USER]: '{user}'\n"
                f"     [ATTEMPTS]: {data['attempts']} | [SEVERITY]: {severities_list}\n"
                f"     [SRC METRIC]: {src_list} -> [DEST METRIC]: {dest_list}\n"
                f"     -----------------------------------------------------"
            )

        if not user_report_string:
            user_report_string = "\n   - None Detected"

        # 4. Compile the final security report
        report = f"""
================ SECURE AI THREAT REPORT ================
GLOBAL INCIDENT THREAT LEVEL : {highest_severity} PRIORITY

[METRIC TRIAGE SUMMARY]
   - Critical Threats Detected: {incident_breakdown['CRITICAL']}
   - High Risk Anomaly Items  : {incident_breakdown['HIGH']}
   - Infrastructure Warnings   : {incident_breakdown['MEDIUM']}
   - Routine Low-Risk Events   : {incident_breakdown['LOW']}

[CONTEXT DETAILS EXTRACTED]{user_report_string}
   - Vulnerable/Impacted Assets: {list(targeted_assets) if targeted_assets else 'None Detected'}

[IMMEDIATE ACTIONABLE REMEDIATIONS]"""

        # Inline Identity Routing
        has_remediations = False
        for user, data in user_forensics.items():
            if "CRITICAL" in data["severities"]:
                report += f"\n   [!] ACCOUNT: '{user}' -> IMMEDIATE ACTION REQUIRED: Isolating affected subnets. Reviewing Firewall rules."
                has_remediations = True
            elif "HIGH" in data["severities"]:
                report += f"\n   [!] ACCOUNT: '{user}' -> ACTION REQUIRED: Temporarily locking privilege tokens. Enforce MFA check."
                has_remediations = True

        if not has_remediations:
            report += "\n   [+] NO IMMEDIATE ACCOUNT LEVEL REMEDIATIONS REQUIRED: Low risk signatures documented to standard logs."

        report += "\n\n[AI Compliance Layer]"

        # --- The Dynamic Per-User Ai Gatekeeper Block ---
        if highest_severity in ["CRITICAL", "HIGH"]:
            print(
                f"[ALERT MATCHED] Threat level is {highest_severity}. Escalating flagged accounts to AI Analyst...")

            # Group the escalation lines by user so we can send clean packages to the API
            user_payloads = {}
            for payload_line in escalation_payload_lines:
                # Extract the username back out of our formatted payload string
                match = re.match(r'\[USER ID:\s*(.*?)\]', payload_line)
                if match:
                    user_tag = match.group(1)
                    if user_tag not in user_payloads:
                        user_payloads[user_tag] = []
                    user_payloads[user_tag].append(payload_line)

            # Query OpenAI separately for each specific account that has issues
            for user_tag, lines in user_payloads.items():
                clean_ai_payload = "\n".join(lines)
                remediation_advice = self.escalate_to_llm(clean_ai_payload)

                # Format the output so it's explicitly tied to that specific account name
                report += f"\n -> TARGETED [{user_tag}] AI RECOMMENDATION: {remediation_advice.replace(' -> AI COMPLIANCE ENGINE RECOMMENDATION: ', '')}"
        else:
            print(
                f"\n[INFO] Threat level is {highest_severity}. Skipping AI escalation to optimize token usage.")
            report += "\n -> NO GLOBAL ACTION: Logs logged to database for standard review retention."

        return report


# ==========================================
#         EXECUTION ENGINE (DRIVER)
# ==========================================
if __name__ == "__main__":
    TARGET_DIRECTORY = "network_logs"

    pipeline = SentinelPipe(TARGET_DIRECTORY)
    log_files = pipeline.scan_for_logs()

    if "auth_log.txt" in log_files:
        file_path = os.path.join(TARGET_DIRECTORY, "auth_log.txt")

        with open(file_path, "r") as file:
            raw_data = file.read()

        print("\n[INBOUND DATA]:")
        print(raw_data)

        sanitized_data = pipeline.sanitize_log_data(raw_data)
        print("\n[SECURE PIPELINE LAYER OUTPUT]:")
        print(sanitized_data)

        final_report = pipeline.ai_semantic_analysis(sanitized_data)
        print(final_report)
    else:
        print(
            f"\n[ERROR] 'auth_log.txt' was not found inside the '{TARGET_DIRECTORY}' folder.")
