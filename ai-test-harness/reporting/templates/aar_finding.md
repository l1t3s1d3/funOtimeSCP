# Finding: {{ finding_id }}

**Severity:** {{ severity }}
**Category:** {{ category }}
**NIST Control(s):** {{ controls }}
**Date Identified:** {{ date }}

---

## Description

{{ description }}

## Attack Chain Position

{{ attack_chain_step }}

## Evidence

| Type | Path | SHA-256 |
|------|------|---------|
{% for artifact in artifacts %}
| {{ artifact.type }} | {{ artifact.path }} | {{ artifact.sha256 }} |
{% endfor %}

## Steps to Reproduce

{{ reproduction_steps }}

## Impact Assessment

{{ impact }}

## Recommended Remediation

{{ remediation }}

## Detection Analysis

**Was this detected?** {{ detected }}
**Detection mechanism:** {{ detection_mechanism }}
**Time to detect:** {{ time_to_detect }}
**Detection gap analysis:** {{ detection_gap }}
