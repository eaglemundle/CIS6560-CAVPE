import numpy as np
import pandas as pd

from engines.scoring import calculate_risk_score, calculate_risk_scores


WEIGHTS = {
    "severity": 0.3,
    "exploited_in_the_wild": 0.15,
    "poc_exploit_availability": 0.15,
    "patch_difficulty": 0.1,
    "compensating_controls": 0.15,
    "asset_criticality": 0.1,
    "risk_transfer": 0.05,
}
SCORING_CONFIG = {
    "risk_transfer_mode": "reducer",
    "risk_transfer_min_score": 0.0,
}


def test_vectorized_scores_match_row_wrapper_within_tolerance():
    data = pd.DataFrame(
        [
            {
                "CVSS base score": 9.8,
                "Exploited_score": 2,
                "Asset_Crit_A": 4,
                "PoC_norm": 1.0,
                "Patch_norm": 0.75,
                "Controls_norm": 0.2,
                "Transfer_norm": 0.5,
            },
            {
                "CVSS base score": 4.2,
                "Exploited_score": 0,
                "Asset_Crit_A": 2,
                "PoC_norm": 0.5,
                "Patch_norm": 0.25,
                "Controls_norm": 1.0,
                "Transfer_norm": 0.0,
            },
        ]
    )

    vectorized = calculate_risk_scores(
        data, "Asset_Crit_A", WEIGHTS, SCORING_CONFIG
    )
    row_scores = [
        calculate_risk_score(row, "Asset_Crit_A", WEIGHTS, SCORING_CONFIG)
        for _, row in data.iterrows()
    ]

    np.testing.assert_allclose(vectorized.to_numpy(), row_scores, atol=1e-9)
