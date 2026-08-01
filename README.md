# WebInject2026

A contemporary corpus for web application injection attack detection.

## Contents
- 52,696 labelled HTTP requests
- 39,648 benign / 13,048 attack
- Three applications: DVWA, OWASP Juice Shop, bWAPP
- Three attack families: SQL injection, XSS, OS command injection

## Validation
- Attack ratio: 0.248
- Duplicate payloads: 0
- Benign/attack median length gap: 0.000
- F1 achievable from payload length alone: 24.18% (i.e. length is not a shortcut)

## Generation
Traffic captured against live containerised instances of each application.
Attack payloads sourced from PayloadsAllTheThings, embedded into genuine
request contexts rather than scored as bare strings.

Full generation code in `notebooks/`.
