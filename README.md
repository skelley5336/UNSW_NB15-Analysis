[README.md](https://github.com/user-attachments/files/33639594/README.md)
# Which Network Services Should a Security Team Defend First?

**Using the UNSW-NB15 intrusion dataset to rank network services by attack risk**

Security teams never have enough time or budget to harden everything at once. This project analyzes 257,673 labeled network flows to answer a practical question: **if you can only prioritize a few services for patching, monitoring and hardening, which ones should come first?**

Write-up on Medium: *Where Should Network Security Teams Focus First During an Attack?* ([medium.com/@skelley5](https://medium.com/@skelley5))

---

## Question and stakeholder

| | |
|---|---|
| **Question** | Which network services are attacked most often, and by which kinds of attacks? |
| **Stakeholder** | A network security engineer or SOC lead at a mid-size organization |
| **Decision** | Where to spend limited defensive resources first: patching, WAF rules, MFA, vulnerability scanning, or decommissioning legacy services |

## Data

- **Source:** [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) (UNSW Canberra Cyber Range Lab). The official training and testing sets are combined here.
- **Size:** 257,673 network flows, 164,673 of them labeled as attacks.
- **Fields used:** `service` (dns, http, smtp, …), `label` (normal or attack) and `attack_cat` (nine attack categories: Exploits, Fuzzers, DoS, Generic, Reconnaissance, Analysis, Backdoor, Shellcode, Worms).
- Flows with no identified service (`-`) are grouped as **unspecified**.

## Method

1. **Combine and clean:** Merge the training and testing sets and normalize service names.
2. **Measure exposure per service:** Count total flows, attack flows and attack rate (attacks ÷ total flows).
3. **Profile the attacks:** Build a service × attack-category matrix showing which attacks hit which services.
4. **Score and rank:** Each service gets a risk score that balances how *often* it is attacked against how *concentrated* attacks are on it:

   ```
   risk_score = 0.6 × (attack flows ÷ max attack flows) + 0.4 × (attack rate ÷ max attack rate)
   ```

   Volume carries more weight, so a service with tens of thousands of attacks ranks above one with a 100% attack rate on a few dozen flows.

## Results

| Rank | Service | Attack flows | Attack rate | Risk score | Top attack types |
|---:|---|---:|---:|---:|---|
| 1 | unspecified | 77,434 | 54.8% | 0.82 | Exploits, Fuzzers, DoS |
| 2 | dns | 58,100 | 84.6% | 0.79 | Generic |
| 3 | pop3 | 1,524 | 99.7% | 0.41 | Exploits, DoS |
| 4 | dhcp | 120 | 100% | 0.40 | Exploits, DoS, Generic |
| 5 | ssl | 86 | 100% | 0.40 | Exploits, Generic, DoS |
| 6 | irc | 30 | 100% | 0.40 | Exploits, Backdoor, DoS |
| 7 | http | 17,650 | 65.3% | 0.40 | Exploits, Reconnaissance, DoS |
| 8 | snmp | 108 | 99.1% | 0.40 | Reconnaissance, DoS |
| 9 | radius | 17 | 81.0% | 0.32 | Exploits, Generic |
| 10 | smtp | 4,695 | 68.0% | 0.31 | Exploits, DoS |
| 11 | ftp | 3,004 | 60.3% | 0.26 | Exploits, Fuzzers |
| 12 | ftp-data | 1,890 | 35.1% | 0.15 | Exploits |
| 13 | ssh | 15 | 1.0% | 0.00 | Exploits |

### Key findings

- **DNS is the clearest named-service priority.** 84.6% of DNS flows are attacks, and almost all of them (57,278) are *Generic* attacks. That points to DNS monitoring and rate limiting as high-value controls.
- **HTTP faces the widest range of attacks.** It sees the most Exploits of any named service (11,481) plus heavy Reconnaissance, so web application firewalls and patching web-facing systems pay off here.
- **Legacy and rarely used services are almost entirely malicious.** POP3, DHCP, SSL, IRC and SNMP traffic is 99–100% attack traffic. If an organization doesn't need these services, turning them off removes risk at almost no cost.
- **SSH is the exception.** Only 1% of SSH flows are attacks, so it is a lower priority in this dataset.
- **Unspecified traffic is the biggest single bucket.** It holds the most attacks and the widest mix of attack types, which makes the case for better service identification and network visibility.

## Limitations

- UNSW-NB15 is generated in a lab, and attacks make up about 64% of its flows. Attack *rates* here are far higher than on a real network, so use the **relative ranking** rather than the absolute percentages.
- Services with very few flows (IRC, RADIUS, SSL) can reach a 100% attack rate on small samples. The volume-weighted score limits how much that affects the ranking.
- The 60/40 weighting is a judgment call. Another organization might weight attack severity or asset value instead.

## Repository contents

| File | Description |
|---|---|
| `build_security_prioritization_datasets.py` | Builds all output datasets from the raw UNSW-NB15 CSVs |
| `service_prioritization.csv` | Final ranked list of services with risk scores and top attack types |
| `service_risk_summary.csv` | Total, attack and normal flows and attack rate per service |
| `service_attack_matrix.csv` | Attack counts for each service × attack category |

## How to run

1. Download `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` from the [UNSW-NB15 dataset page](https://research.unsw.edu.au/projects/unsw-nb15-dataset) and place them in this folder.
2. Run the script. It uses only the Python standard library, so nothing needs to be installed:

   ```bash
   python build_security_prioritization_datasets.py
   ```

The script writes the three summary CSVs above, plus `combined_traffic.csv` (about 52 MB), which is not tracked in the repo.

## Tools

Python (standard library: `csv`, `collections`) · UNSW-NB15

---

**Author:** Shea Kelley, Information Science, University of Maryland · [GitHub](https://github.com/skelley5336) · [Medium](https://medium.com/@skelley5)
