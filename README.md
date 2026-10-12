

\## Authentication Threat Detection: Rules vs. Machine Learning



SecureOps combines deterministic authentication threat detection with an experimental machine-learning anomaly detector.



\### Detection capabilities



The rule-based engine detects:



\- Brute-force authentication attempts

\- Low-and-slow brute-force attempts

\- Password spraying

\- Low-and-slow password spraying

\- Distributed password spraying (review-only)



The experimental ML pipeline uses Isolation Forest and authentication traffic features, including request volume, authentication failure rates, distinct accounts, source IPs, and failure concentrations.



\### Evaluation methodology



The benchmark uses reproducible synthetic authentication traffic with separate training, validation, and final-test periods.



\- Time-window candidates: 60, 300, and 900 seconds

\- Selected ML window: 300 seconds

\- Anomaly threshold: 0.03363737880038309

\- Validation-based model selection

\- Final evaluation: 14 days of synthetic traffic

\- Attack scenarios: brute force, password spray, distributed spray, and slow brute force



\### Final benchmark results



| Metric | Rule-based detector | ML detector |

|---|---|---|

| Attack scenarios detected | 4/4 | 4/4 |

| Alerts / flagged windows | 5 alerts | 110 windows |

| Benign-only alerts / false-positive windows | 0 alerts | 102 windows |

| Attack-window recall | Not measured | 80% |

| Precision | Not directly comparable | 7.27% |

| False-positive rate | Not directly comparable | 3.62% |



The ML detector correctly flagged 8 of 10 attack-containing windows, including 5 of 7 windows associated with slow brute-force activity.



The rule-based detector produced five attack-related alerts, with no benign-only alerts in this benchmark. One password-spray scenario triggered two different rules.



Rule-generated alerts and ML window classifications are different evaluation units, so their false-positive counts should not be interpreted as directly comparable.



\### Engineering conclusions



The rule-based engine remains the primary authentication detection mechanism. The ML detector is maintained as an experimental component for studying behavioral anomaly detection, false-positive trade-offs, and detection coverage.



The benchmark does not establish production performance. It uses synthetic traffic, a limited attack set, and related generators across datasets. No automatic ML-based blocking is performed.



\### Reproducing the evaluation



```powershell

python -m pytest -q

python -m ml.window\_selection

python -m ml.final\_evaluate

python -m ml.final\_compare

```



The complete test suite currently contains 185 passing tests.
