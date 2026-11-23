import pandas as pd

pd.read_excel("reference_data/vulnerability_contextualization_scanner_sample_updated.xlsx").to_json("reference_data/vulnerability_contextualization_scanner_sample_updated.json", orient="records", indent=2)
pd.read_excel("reference_data/vulnerability_coordinated_ledger.xlsx").to_json("reference_data/vulnerability_coordinated_ledger.json", orient="records", indent=2)
