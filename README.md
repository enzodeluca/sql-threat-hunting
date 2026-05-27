# Enterprise Threat Hunting with SQL

## Project Overview
This project demonstrates how advanced data analytics and database querying are leveraged for proactive threat hunting and incident response. Using a mock enterprise authentication dataset, I engineered relational queries to isolate malicious patterns, detect automated brute-force attacks, and flag critical identity compromises across geographic boundaries.

## MITRE ATT&CK Mapping
- **Tactic:** Defense Evasion / Initial Access (TA0005 / TA0001)
- **Technique:** Use of Valid Accounts (T1078)
- **Detection Strategy:** Behavioral Anomaly Correlation via Relational Self-Joins

## Simulated Scenarios & Detection Logic

### 1. Automated Brute-Force & Credential Stuffing Detection
- **Objective:** Separate routine user authentication errors from high-frequency, automated password-guessing campaigns.
- **Data Logic:** Utilizes aggregate functions (`COUNT`) paired with condition filters (`HAVING`) to isolate accounts experiencing more than 5 explicit failures within a logged cycle.

### 2. "Impossible Travel" Identity Anomaly
- **Objective:** Identify session hijacking or compromised corporate credentials by identifying geographically impossible authentications.
- **Data Logic:** Executes an optimized database self-join on transactional user records, correlating concurrent successful logins across mismatched geolocations within a strict 60-minute window.

## Technical Proficiencies Demonstrated
- **Advanced SQL:** Relational self-joins, conditional aggregations, database indexing strategy, datetime manipulation.
- **Defensive Engineering:** Indicator of Compromise (IoC) isolation, pattern matching, behavioral analysis.