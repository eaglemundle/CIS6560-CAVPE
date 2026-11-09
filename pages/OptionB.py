import os
import csv
import json
import re
import pandas as pd
import numpy as np

# --- 1. Dynamic File Path Definitions ---
CONFIG_WEIGHTS_PATH = "weight_config.json"
CONFIG_OPTION_B_PATH = "engines/taxonomy_option_b.json"

CISA_KEV_CSV = "reference_data/known_exploited_vulnerabilities.csv"
INPUT_EXCEL = "reference_data/vulnerability_contextualization_scanner_sample_updated.xlsx"
COORDINATED_LEDGER = "reference_data/vulnerability_coordinated_ledger.xlsx"


class RiskLedgerOrchestrator:
    def __init__(self, kev_path, weights_json_path, option_b_json_path):
        self.kev_path = kev_path
        self.kev_cves = set()
        
        # Hydrate configuration taxonomies directly from externalized JSON files
        self.weights = self._load_json_config(weights_json_path)["weights"]
        self.exposure_mapping = self._load_json_config(option_b_json_path)["exposure_classification_mapping"]
        
        # Prime the localized CISA KEV lookup database
        self._load_cisa_kev_cache()

    def _load_json_config(self, file_path):
        """Safely loads external taxonomy files and schema parameters."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"[!] Critical Error: Required configuration file missing at: '{file_path}'")
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _load_cisa_kev_cache(self):
        """Loads CISA KEV database to check wild exploitation status."""
        if not os.path.exists(self.kev_path):
            print(f"[!] Warning: CISA KEV reference file missing at '{self.kev_path}'.")
            return
        with open(self.kev_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id = row.get('cveID')
                if cve_id:
                    self.kev_cves.add(cve_id.strip().upper())
        print(f"[*] CISA KEV Threat Database cached: {len(self.kev_cves)} active CVEs loaded.")

    def parse_remediation_range_split(self, effort_val):
        """
        Parses duration ranges like '1-2 days', '1-4 hours' into business hours tuple (min, max).
        Safely extracts numeric elements to avoid sequence replication type errors.
        """
        if pd.isna(effort_val):
            return 8.0, 24.0  # Default: Min 1 day (8h), Max 3 days (24h)
        
        effort_str = str(effort_val).strip().lower()
        numbers = [float(x) for x in re.findall(r"\d+\.?\d*", effort_str)]
        
        if not numbers:
            return 8.0, 24.0
            
        if len(numbers) == 1:
            min_raw = numbers[0]
            max_raw = numbers[0]
        else:
            min_raw = numbers[0]
            max_raw = numbers[-1]
            
        multiplier = 1.0
        if "week" in effort_str:
            multiplier = 40.0
        elif "day" in effort_str:
            multiplier = 8.0
        elif "hour" in effort_str:
            multiplier = 1.0
            
        return float(min_raw * multiplier), float(max_raw * multiplier)

    def calculate_contextual_risk(self, row):
        """
        Recalculates Contextual Risk Score and P-Tiers using ONLY the 6 specified metrics.
        CVSS severity data is explicitly excluded from calculation.
        """
        cve_id = str(row.get('CVE ID', '')).strip().upper()
        
       # --- [Metric 1] asset_value: Comprehensive asset tier weighting calculation ---
        # Extracts raw infrastructure counts from standard scanner input matrix
        total_assets = max(float(row.get('Total affected assets', 1.0)), 1.0)
        
        crit_count = float(row.get('Critical assets', 0.0))
        high_count = float(row.get('High-criticality assets', 0.0))
        med_count = float(row.get('Medium-criticality assets', 0.0))
        low_count = float(row.get('Low-criticality assets', 0.0))
        
        # Apply standard operational weights relative to asset importance tiers
        weighted_asset_sum = (
            (crit_count * 10.0) + 
            (high_count * 7.5) + 
            (med_count * 4.0) + 
            (low_count * 1.0)
        )
        
        # Derive proportional score and clamp securely between 0.0 and 10.0 bounds
        asset_value = min(weighted_asset_sum / total_assets, 10.0)
        
        # [Metric 2] exploit_evidence: Threat intelligence mapping with proactive CISA KEV lookup integration
        if cve_id in self.kev_cves:
            exploit_evidence = 10.0
        else:
            exploit_ctx = str(row.get('Exploitation context', 'none')).strip().lower()
            exploit_evidence = 10.0 if 'exploit' in exploit_ctx else (5.0 if 'poc' in exploit_ctx else 0.0)

        # [Metric 3] exposure: Isolation structure calculation bound securely to taxonomy configurations
        exposure_raw = str(row.get('Exposure classification', 'internal')).strip().lower()
        exposure_tier = self.exposure_mapping.get(exposure_raw, 2)
        exposure = (exposure_tier / 4.0) * 10.0

        # [Metric 4] compensating_controls: Mitigating factor analysis scaling down to risk base bounds
        comp_val = row.get('Compensating controls')
        if pd.isna(comp_val) or str(comp_val).strip().lower() in ['none', '']:
            compensating_controls = 10.0 
        else:
            compensating_controls = 3.0

        # [Metric 5] business_impact: Infrastructure coverage perimeter calculations for blast-radius analysis
        total_assets = max(float(row.get('Total affected assets', 1.0)), 1.0)
        crit_assets = float(row.get('Critical assets', 0.0)) + float(row.get('High-criticality assets', 0.0))
        business_impact = min((crit_assets / total_assets) * 10.0, 10.0)

        # [Metric 6] patch_feasibility: Friction matrix combining layout bounds with maximum duration metrics
        min_hours, max_hours = self.parse_remediation_range_split(row.get('Estimated remediation effort'))
        if max_hours <= 4.0:
            effort_vector = 1.0
        elif max_hours >= 40.0:
            effort_vector = 10.0
        else:
            effort_vector = 1.0 + (9.0 * ((max_hours - 4.0) / 36.0))
            
        complexity = str(row.get('Patch complexity', 'low')).strip().lower()
        complexity_vector = 10.0 if 'high' in complexity else (5.0 if 'medium' in complexity else 2.0)
        patch_feasibility = (complexity_vector * 0.5) + (effort_vector * 0.5)

        # --- Pure Taxonomical Formula Weighting Engine ---
        # Synthesizes only the 6 core asset metrics validated by weight_config.json
        final_contextual_score = (
            (asset_value * self.weights['asset_value']) +
            (exploit_evidence * self.weights['exploit_evidence']) +
            (exposure * self.weights['exposure']) +
            (compensating_controls * self.weights['compensating_controls']) +
            (business_impact * self.weights['business_impact']) +
            (patch_feasibility * self.weights['patch_feasibility'])
        )
        final_contextual_score = min(max(final_contextual_score, 0.0), 10.0)

        # --- Refined Governance Priority Tier Assignment ---
        # Maps dynamic risk score metrics cleanly into standard corporate P-Tier targets
        if final_contextual_score >= 8.5:
            priority_tier = "P1 - Urgent"
        elif final_contextual_score >= 7.0:
            priority_tier = "P2 - High"
        elif final_contextual_score >= 4.0:
            priority_tier = "P3 - Medium"
        else:
            priority_tier = "P4 - Planned"

        # Captures native baseline priority string for illustrative trace comparison mapping
        illustrative_priority = str(row.get('Contextual priority', 'N/A')).strip()

        return pd.Series([
            round(final_contextual_score, 2), 
            priority_tier, 
            min_hours, 
            max_hours,
            illustrative_priority
        ])

    def generate_coordinated_ledger(self, input_excel_path, output_ledger_path):
        """Processes raw scanner telemetry and populates the master coordination asset matrix."""
        if not os.path.exists(input_excel_path):
            print(f"[!] Critical Error: Input staging file missing at '{input_excel_path}'")
            return
            
        print(f"[*] Extracting risk factors from: {input_excel_path}")
        df = pd.read_excel(input_excel_path)
        
        print("[*] Re-calculating master matrices and mapping coordinates...")
        # Safely assign multi-column structural arrays inline matching requirements
        df[['Contextual risk score', 'Contextual priority', 'Min remediation effort (hours)', 'Max remediation effort (hours)', 'Illustartive contextual priority']] = df.apply(
            self.calculate_contextual_risk, axis=1
        )
        
        # Re-arrange columns to ensure core risk indicators reside at the very beginning
        front_columns = [
            'CVE ID', 'Contextual risk score', 'Contextual priority', 'Illustartive contextual priority',
            'Min remediation effort (hours)', 'Max remediation effort (hours)', 'Exposure classification'
        ]
        remaining_columns = [col for col in df.columns if col not in front_columns]
        final_ledger_df = df[front_columns + remaining_columns]
        
        # Persist ledger down into binary storage paths safely
        os.makedirs(os.path.dirname(output_ledger_path), exist_ok=True)
        final_ledger_df.to_excel(output_ledger_path, index=False, engine='openpyxl')
        print(f"[+] Coordinated Master Ledger successfully compiled: '{output_ledger_path}'")


if __name__ == "__main__":
    orchestrator = RiskLedgerOrchestrator(
        kev_path=CISA_KEV_CSV,
        weights_json_path=CONFIG_WEIGHTS_PATH,
        option_b_json_path=CONFIG_OPTION_B_PATH
    )
    orchestrator.generate_coordinated_ledger(INPUT_EXCEL, COORDINATED_LEDGER)
