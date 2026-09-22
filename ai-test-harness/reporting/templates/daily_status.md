# Daily Status Report

**Engagement:** {{ engagement_id }}
**Date:** {{ date }}
**Day:** {{ day_number }} of {{ total_days }}
**Operator:** {{ operator }}

---

## Summary

{{ summary }}

## Activities Completed

| Time (UTC) | Category | Action | Finding |
|------------|----------|--------|---------|
{% for entry in activities %}
| {{ entry.timestamp }} | {{ entry.category }} | {{ entry.action }} | {{ entry.finding }} |
{% endfor %}

## Findings

| # | Severity | Category | Description | Control Tested |
|---|----------|----------|-------------|----------------|
{% for finding in findings %}
| {{ loop.index }} | {{ finding.severity }} | {{ finding.category }} | {{ finding.description }} | {{ finding.control }} |
{% endfor %}

## Blockers / Issues

{{ blockers }}

## Plan for Next Day

{{ next_day_plan }}

---

**Evidence artifacts generated today:** {{ artifact_count }}
**Timeline entries logged:** {{ timeline_count }}
