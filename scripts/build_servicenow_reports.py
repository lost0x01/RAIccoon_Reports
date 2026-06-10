from __future__ import annotations

import csv
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import yaml

ROOT = Path('/home/lost0x01/github/RAIccoon_Reports')
LOGO = Path('/home/lost0x01/Downloads/lost-boys-cyber-branding/lost-boys-cyber-logo-titlepage.svg')
DATE_PUBLISHED = '2026-06-10'
TITLE = 'ServiceNow Hosted Instance API Security Incident'
SLUG = 'servicenow-api-security-incident'
TR_ID = 'LBC-TR-2026-001'
ES_ID = 'LBC-ES-2026-001'
CLASSIFICATION = 'TLP:CLEAR'
AUTHOR = 'Lost Boys Cyber'
THREAT_REPORT_DIR = ROOT / 'Threat Reports' / f'{TR_ID}_{SLUG}'
EXEC_SUMMARY_DIR = ROOT / 'Executive Summaries' / f'{ES_ID}_{SLUG}'

AI_DISCLAIMER = (
    'AI Generation: This report was generated with AI assistance and is provided for informational '
    'purposes only. All findings, IOCs, detection rules, hunting queries, attribution assessments, '
    'and recommendations must be independently reviewed and validated by a qualified security '
    'professional before operational use.'
)

BLUF = (
    'Between 2-3 June 2026, attackers exploited a ServiceNow-hosted API access control failure '
    'to query data from a subset of customer instances before the vendor pushed a hosted fix on '
    '5 June. Public reporting and multiple secondary sources consistently indicate the exposure '
    'was tied to an endpoint associated with /api/now/related_list_edit/create and a configuration '
    'state that allowed unauthenticated access. The most material enterprise risk is not only the '
    'direct exposure of tickets, employee records, workflow data, and security cases, but the '
    'secondary exposure of credentials, API tokens, integration secrets, and internal process '
    'knowledge commonly stored in ServiceNow records.'
)

EXPECTED_IMPACT = (
    'Expected impact is HIGH for directly affected tenants and MODERATE for the broader '
    'ServiceNow customer base. For affected organisations, likely consequences include regulatory '
    'notification pressure, third-party risk escalation, targeted follow-on intrusion using '
    'harvested secrets, and trust degradation around SaaS control boundaries. For customers not '
    'individually notified by ServiceNow, immediate platform compromise risk appears reduced after '
    'the 5 June hosted remediation, but log review, secret rotation for sensitive records, and '
    'validation of legacy/custom API exposure remain warranted.'
)

SOURCES = [
    {
        'id': 'SRC-001',
        'title': 'ServiceNow support bulletin KB3067321 (quoted by secondary reporting)',
        'type': 'Vendor advisory (indirectly accessible)',
        'confidence': 'High for quoted vendor statements; lower for absent technical specifics',
        'notes': 'Multiple independent outlets quote the same vendor language: hosted fix on 5 June 2026; unauthenticated user could gain greater access than intended; subset of customers observed with successful table queries; affected customers notified by case; CVE still under evaluation.'
    },
    {
        'id': 'SRC-002',
        'title': 'BleepingComputer reporting mirrored at note.f5.pm',
        'type': 'News / secondary reporting',
        'confidence': 'High',
        'notes': 'Provides the clearest accessible summary of the vendor bulletin, affected scope, probable endpoint, and customer notification approach.'
    },
    {
        'id': 'SRC-003',
        'title': 'The CyberSec Guru analysis',
        'type': 'Technical community reporting',
        'confidence': 'Medium',
        'notes': 'Contains the strongest single-source technical narrative around the probable REST resource, requires_authentication flag, suspected IPs, and the 7 April internal problem-record claim. Useful but not fully vendor-confirmed.'
    },
    {
        'id': 'SRC-004',
        'title': 'Triskele Labs advisory',
        'type': 'Defender-oriented synthesis',
        'confidence': 'High',
        'notes': 'Adds pragmatic detection, scoping, and response guidance while clearly marking what is vendor-confirmed versus community-reported.'
    },
    {
        'id': 'SRC-005',
        'title': 'Anavem and other tertiary summaries',
        'type': 'Supplementary reporting',
        'confidence': 'Medium',
        'notes': 'Useful to corroborate business-impact framing but not relied upon for unique technical claims.'
    },
]

IOCS = [
    {
        'ioc_type': 'Source IP',
        'value': '51.159.98.241',
        'confidence': 'Medium',
        'source': 'SRC-002 / SRC-003 / SRC-004',
        'notes': 'Most consistently cited suspicious IP tied to requests against the exposed endpoint.'
    },
    {
        'ioc_type': 'Source IP',
        'value': '86.245.155.105',
        'confidence': 'Low',
        'source': 'SRC-003',
        'notes': 'Additional possible source IP mentioned in single-source technical reporting; treat as hunt lead rather than confirmed IOC.'
    },
    {
        'ioc_type': 'URI Path',
        'value': '/api/now/related_list_edit/create',
        'confidence': 'Medium',
        'source': 'SRC-002 / SRC-003 / SRC-004',
        'notes': 'Community-reported vulnerable endpoint; vendor has not publicly confirmed the exact path.'
    },
    {
        'ioc_type': 'User Context',
        'value': 'Guest',
        'confidence': 'Medium',
        'source': 'SRC-003 / SRC-004',
        'notes': 'Unauthenticated requests may appear in transaction logs as Guest due to missing user context.'
    },
    {
        'ioc_type': 'Time Window',
        'value': '2026-06-02 through 2026-06-03 UTC',
        'confidence': 'High',
        'source': 'SRC-001 / SRC-004',
        'notes': 'Observed anomalous activity window repeatedly cited across reporting.'
    },
    {
        'ioc_type': 'Affected Scope',
        'value': 'Australia release and some pre-Australia instances with specific configuration changes',
        'confidence': 'High',
        'source': 'SRC-001 / SRC-002 / SRC-004',
        'notes': 'Vendor-quoted scope language.'
    },
]

ATTACK_MAPPING = [
    {
        'tactic': 'Reconnaissance',
        'technique': 'T1595 - Active Scanning',
        'confidence': 'Medium',
        'assessment': 'Attackers likely enumerated exposed ServiceNow tenants and tested the target API path across instances.'
    },
    {
        'tactic': 'Initial Access',
        'technique': 'T1190 - Exploit Public-Facing Application',
        'confidence': 'High',
        'assessment': 'The exposed REST endpoint functioned as an internet-reachable application surface that could be queried without valid authentication.'
    },
    {
        'tactic': 'Collection',
        'technique': 'T1213 - Data from Information Repositories',
        'confidence': 'High',
        'assessment': 'Vendor-confirmed successful table queries indicate collection from business-data repositories hosted inside customer instances.'
    },
    {
        'tactic': 'Credential Access',
        'technique': 'T1552 - Unsecured Credentials',
        'confidence': 'Medium',
        'assessment': 'If tickets or attachments contained passwords, API keys, or troubleshooting secrets, exposed records could directly yield usable credentials.'
    },
    {
        'tactic': 'Exfiltration',
        'technique': 'T1041 - Exfiltration Over C2 Channel',
        'confidence': 'Low',
        'assessment': 'Successful data querying is vendor-confirmed, but publicly available evidence does not yet prove broad downstream exfiltration volume or destination.'
    },
]

KQL_QUERY = textwrap.dedent('''
let suspiciousIPs = dynamic(["51.159.98.241", "86.245.155.105"]);
let suspiciousPath = "/api/now/related_list_edit/create";
ServiceNowLogs
| where TimeGenerated between (datetime(2026-06-02) .. datetime(2026-06-06))
| where Url has suspiciousPath or RequestUri has suspiciousPath or RawData has suspiciousPath
| extend SourceIP = coalesce(ClientIP, SrcIpAddr, SourceIp, RemoteIP)
| extend UserContext = coalesce(User, UserName, Account, tostring(parse_json(AdditionalFields).user))
| summarize Requests=count(), DistinctIPs=dcount(SourceIP), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Tenant=coalesce(Instance, TenantId, Hostname), SourceIP, UserContext, tostring(HttpMethod), tostring(HttpStatus)
| order by Requests desc
''').strip()

SPL_QUERY = textwrap.dedent('''
index=servicenow (uri_path="/api/now/related_list_edit/create" OR request_uri="/api/now/related_list_edit/create" OR _raw="/api/now/related_list_edit/create")
| eval source_ip=coalesce(src_ip, client_ip, remote_addr, ip)
| eval user_context=coalesce(user, user_name, account, principal, "unknown")
| search earliest="06/02/2026:00:00:00" latest="06/06/2026:23:59:59"
| stats count as requests min(_time) as first_seen max(_time) as last_seen values(method) as methods values(status) as statuses by host source_ip user_context
| convert ctime(first_seen) ctime(last_seen)
| sort - requests
''').strip()

SIGMA_RULE = textwrap.dedent('''
title: ServiceNow Related List Edit Endpoint Queried from Untrusted Source
id: 9a4694de-3e5f-42d4-a75a-182552620001
status: experimental
description: Detects requests to the community-reported ServiceNow endpoint associated with the June 2026 hosted-instance security incident.
author: Lost Boys Cyber
logsource:
  category: webserver
  product: servicenow

detection:
  selection_path:
    cs-uri-stem|contains: '/api/now/related_list_edit/create'
  selection_ip:
    c-ip:
      - '51.159.98.241'
      - '86.245.155.105'
  condition: selection_path or (selection_path and selection_ip)
fields:
  - c-ip
  - cs-uri-stem
  - cs-method
  - sc-status
  - cs-username
falsepositives:
  - Legitimate internal testing of the same endpoint
level: high
''').strip() + '\n'

EXEC_MD = f'''# {TITLE} — Threat Intelligence Executive Summary

Classification: {CLASSIFICATION}
Published: {DATE_PUBLISHED}
Version: 1.0
Author: {AUTHOR}
Report Type: Threat Intelligence Executive Summary
Severity: High

## 1. BLUF
{BLUF}

## 2. Expected Impact Statement
{EXPECTED_IMPACT}

## 3. What Happened
- ServiceNow applied a hosted security update on 5 June 2026 after identifying a security issue that could allow an unauthenticated user, in certain circumstances, to gain greater access to customer instances than intended.
- ServiceNow stated that, for a subset of customers, it observed evidence of successful queries of instance tables and opened direct support cases with affected customers.
- Public reporting consistently states the issue primarily affected customers on the Australia platform release or customers on pre-Australia releases who had made certain configuration changes.
- Community and third-party reporting strongly suggest the exposed path was `/api/now/related_list_edit/create`, likely associated with a Scripted REST Resource configured in a way that did not require authentication.

## 4. Why It Matters
- ServiceNow instances often hold highly operational data rather than just generic support metadata: incident tickets, change records, employee information, asset inventories, security cases, workflow logic, and attachments.
- Tickets and support cases routinely contain sensitive implementation detail, including credentials, API tokens, architecture notes, and troubleshooting artefacts that can enable follow-on intrusion even when the original exposure appears "read only."
- This incident raises vendor-risk and compliance questions because public reporting indicates the underlying issue may have been known internally before the hosted remediation window, although that timing claim is not yet vendor-confirmed in a public source.

## 5. Confidence and Caveats
- High confidence: hosted remediation date (5 June 2026), successful table queries against a subset of customers, customer notification-by-case model, affected-scope language, and no public CVE assignment as of publication.
- Medium confidence: the exact endpoint path, the `requires_authentication=false` root-cause explanation, the use of the `Guest` context in logs, and the IP `51.159.98.241` as a primary hunt lead.
- Low-to-medium confidence: the additional IP `86.245.155.105` and claims that ServiceNow internally documented the issue on 7 April 2026.

## 6. Immediate Actions for Defenders
1. Confirm whether your organisation received a ServiceNow support case related to this incident.
2. Review ServiceNow transaction and node logs for 2-3 June 2026, focused on `/api/now/related_list_edit/create`, `Guest` context events, and suspicious external IPs.
3. Review tickets, attachments, knowledge items, and workflow records that may have contained plaintext credentials, tokens, VPN configs, or sensitive architecture details.
4. Rotate any secrets that may have been exposed through records accessible from the affected instance.
5. Audit all custom and legacy Scripted REST Resources for authentication and ACL enforcement, even if ServiceNow stated no further customer action was required for hosted remediation.

## 7. Bottom-Line Assessment
This was not merely a routine SaaS bug fix. It was a confirmed security incident involving successful unauthorised queries against customer data inside a widely trusted enterprise workflow platform. Even where the directly exposed data volume is still unknown, the likely secondary risk from secrets embedded in operational records makes this incident materially more serious than a narrow metadata leak.
'''

THREAT_MD = f'''# {TITLE} — Threat Intelligence Report

Classification: {CLASSIFICATION}
Published: {DATE_PUBLISHED}
Version: 1.0
Author: {AUTHOR}
Report Type: Threat Intelligence Report
Severity: High

## 1. Executive Summary
{BLUF}

{EXPECTED_IMPACT}

## 2. Intelligence Requirement and Scope
This report assesses the June 2026 ServiceNow hosted-instance security incident, with emphasis on what is vendor-confirmed, what is community-reported, the likely data at risk, the detection implications for enterprise defenders, and the expected downstream business impact for affected organisations.

This report does not assume compromise of the ServiceNow corporate environment itself. The available evidence points to unauthorised access against customer instances via a public-facing API control failure.

## 3. Source Review and Confidence
| Source ID | Source | Assessment |
| --- | --- | --- |
| SRC-001 | ServiceNow support bulletin KB3067321, quoted by multiple outlets | Highest-confidence source for remediation date, affected scope, customer notification model, and vendor wording. |
| SRC-002 | BleepingComputer reporting mirrored at note.f5.pm | Strong secondary source summarising the hidden vendor bulletin and operational implications. |
| SRC-003 | The CyberSec Guru technical write-up | Useful for probable root cause and hunt indicators; several claims remain single-sourced. |
| SRC-004 | Triskele Labs advisory | Strong defender-focused synthesis that clearly distinguishes confirmed from unconfirmed details. |
| SRC-005 | Anavem and other tertiary summaries | Supportive corroboration for business-impact framing only. |

Overall confidence is HIGH for incident existence, patch timing, and confirmed successful queries against a subset of customers; MEDIUM for exact technical root cause; and LOW-TO-MEDIUM for some reported infrastructure indicators and pre-disclosure timeline details.

## 4. Incident Overview
On 5 June 2026, ServiceNow applied a hosted security update to customer instances after identifying a security issue that could allow an unauthenticated user, in certain circumstances, to gain greater access to ServiceNow instances than intended. According to the quoted vendor bulletin, ServiceNow also detected anomalous activity related to the issue and observed evidence of successful queries of instance tables for a subset of customers.

The public reporting available at the time of writing consistently describes this as a hosted-platform incident rather than a self-managed patching exercise. ServiceNow reportedly notified affected customers directly via support cases and stated that customers not contacted were not believed to be affected.

## 5. Timeline
| Date | Event | Confidence |
| --- | --- | --- |
| 2026-04-07 | Single-source claim that ServiceNow had internally documented the issue in a problem record. | Low-Medium |
| 2026-06-02 to 2026-06-03 | Observed anomalous activity and probable exploitation window across affected tenants. | High |
| 2026-06-05 | ServiceNow applies a hosted security update restricting the affected endpoint to authenticated users. | High |
| 2026-06-09 | Customers receive support-case notifications; broader public reporting begins to surface. | High |
| 2026-06-10 | Third-party analyses expand hunting guidance, suspected endpoint details, and business-impact framing. | High |

## 6. Technical Analysis
### 6.1 Assessed Root Cause
Public reporting strongly suggests the incident involved a Scripted REST Resource associated with `/api/now/related_list_edit/create`. Multiple sources state the endpoint was configured such that authentication was not required, and that the 5 June update changed the endpoint configuration to restrict access to authenticated users only.

Important caveat: ServiceNow has not publicly confirmed the exact endpoint path or publicly released a detailed root-cause advisory at the time of this report. Accordingly, the specific implementation detail should be treated as a high-value working hypothesis rather than a public vendor-confirmed fact.

### 6.2 Affected Scope
The quoted vendor language indicates the incident primarily affected:
- Customers on the Australia platform release.
- Customers on releases prior to Australia that made certain configuration changes.

This scope limitation matters because it reduces the likelihood of indiscriminate exposure across all tenants, but it does not materially reduce the seriousness for impacted organisations. A smaller affected population can still produce severe downstream compromise where ServiceNow is used as a store of privileged operational information.

### 6.3 Access Pattern and Logging Implications
Community and third-party reporting indicates:
- Requests may have targeted the endpoint roughly five times per tenant in several affected environments.
- Unauthenticated activity may appear in logs under the `Guest` context because no valid session or user principal existed.
- Many customers may lack full request/response visibility because REST message logging was not enabled before the incident.

This creates a common SaaS-forensics problem: defenders may be able to prove that suspicious requests hit the endpoint, while remaining unable to reconstruct exactly which records or fields were returned.

### 6.4 Likely Data at Risk
Depending on instance usage, the following categories should be treated as plausibly exposed:
- ITSM records: incidents, problems, change tickets, CMDB records, and service requests.
- Security operations data: detections, investigations, vulnerability workflows, and response notes.
- Human resources or employee-service data where the platform is used outside pure ITSM.
- Internal documentation, workflow notes, architectural references, and attachments.
- Embedded secrets: API keys, temporary credentials, admin screenshots, troubleshooting artefacts, MFA recovery material, VPN details, or cloud integration strings.

### 6.5 What is Confirmed vs. Assessed
Confirmed at high confidence:
- Hosted security update applied on 5 June 2026.
- Vendor observed anomalous activity.
- Successful queries of instance tables for a subset of customers.
- Affected customers were notified directly.
- CVE publication remained under evaluation as of reporting.

Assessed but not fully vendor-confirmed in public:
- Endpoint path `/api/now/related_list_edit/create`.
- `requires_authentication=false` as the precise root cause.
- `Guest` user attribution pattern in logs.
- Suspicious source IPs 51.159.98.241 and 86.245.155.105.
- Internal ServiceNow awareness date of 7 April 2026.

## 7. Threat Activity Assessment
No public attribution exists tying the exploitation to a named threat actor. At present, the activity is best understood as opportunistic exploitation of a high-value SaaS misconfiguration or access-control failure.

However, the target profile materially elevates the threat. ServiceNow instances often function as an enterprise operational memory store. An actor who can enumerate and query those records may gain:
- Knowledge of internal architecture and change windows.
- Credentials and tokens left in tickets or attachments.
- Help-desk process insight useful for social engineering.
- Security-operations artefacts that reveal monitoring gaps or active investigations.

That means even limited data access can materially increase the success probability of later phishing, identity abuse, cloud exploitation, or vendor impersonation operations.

## 8. Infrastructure and Indicators
| Type | Value | Confidence | Notes |
| --- | --- | --- | --- |
| Source IP | 51.159.98.241 | Medium | Most consistently cited suspicious IP in community and third-party reporting. |
| Source IP | 86.245.155.105 | Low | Single-source possible secondary IP; retain as hunt lead only. |
| URI Path | /api/now/related_list_edit/create | Medium | Community-reported vulnerable endpoint. |
| User Context | Guest | Medium | Reported logging artefact for unauthenticated requests. |
| Time Window | 2026-06-02 through 2026-06-03 UTC | High | Likely primary exploitation window before hosted fix. |

## 9. Victimology and Targeting
Potentially exposed organisations include enterprises that use ServiceNow to centralise ITSM, SecOps, HR, asset management, and workflow automation. Particularly sensitive verticals include:
- Healthcare, where tickets may include protected health information and privileged workflows.
- Financial services, where operational records may expose change management and privileged integration detail.
- Government and defence, where case records can reveal mission support data, asset inventories, and security workflows.
- Managed service providers and SaaS operators, where ServiceNow records may contain downstream customer details and administrative procedures.

## 10. Detection Engineering
### 10.1 Detection Priorities
| Priority | Signal | Why it matters |
| --- | --- | --- |
| 1 | Requests to `/api/now/related_list_edit/create` during 2-3 June 2026 | Highest-confidence hunt lead tied to public reporting. |
| 2 | Requests from 51.159.98.241 or 86.245.155.105 | Useful infrastructure pivot, though not definitive alone. |
| 3 | `Guest`-context access to related-list edit operations | May identify unauthenticated activity hidden as non-user actions. |
| 4 | Abrupt spikes in table-query volume or unusual row-access patterns | Can reveal broader enumeration outside the primary IOC set. |
| 5 | Post-incident use of secrets stored in tickets or attachments | Detects likely follow-on exploitation rather than the initial exposure alone. |

### 10.2 Example Microsoft Sentinel / KQL Hunt
```kusto
{KQL_QUERY}
```

### 10.3 Example Splunk Hunt
```spl
{SPL_QUERY}
```

### 10.4 Example Sigma Analytic Logic
```yaml
{SIGMA_RULE.strip()}
```

## 11. Threat Hunting Guidance
1. Pull all transaction, node, API gateway, and reverse-proxy logs covering 1-6 June 2026.
2. Hunt for the endpoint path and suspicious IPs across ServiceNow-native logs and any external WAF/CDN logs.
3. Review all records accessed in the relevant window for embedded secrets, architecture notes, screenshots, attachments, and privileged change tickets.
4. Cross-check subsequent authentication events in identity providers, PAM tools, VPN concentrators, cloud consoles, and developer platforms for accounts or secrets that appeared in those records.
5. Review outbound communications or phishing attempts themed around help-desk, incident-response, or change-management topics in the days following the incident.

## 12. Risk Assessment
| Dimension | Assessment |
| --- | --- |
| Confidentiality | High for affected tenants because records may contain sensitive business data and credentials. |
| Integrity | Medium because the clearest public evidence points to successful query activity, but some reporting suggests write attempts may also have occurred. |
| Availability | Low direct impact from the incident itself; main risk is downstream disruption if exposed secrets are abused. |
| Regulatory / Compliance | High for affected organisations in regulated sectors due to possible exposure of personal, security, or support-case data. |
| Third-Party / Vendor Risk | High because the incident occurred inside a trusted SaaS workflow platform and may trigger review of shared-responsibility assumptions. |

## 13. Recommended Actions
### 13.1 Immediate (0-24 hours)
- Confirm whether your organisation received a ServiceNow support case tied to this incident.
- Preserve all relevant ServiceNow logs, WAF logs, and SIEM evidence from 1-6 June 2026.
- Identify records likely to contain secrets and begin risk-ranked secret rotation.
- Notify legal/privacy/vendor-risk teams if suspicious access is confirmed.

### 13.2 Near-Term (1-7 days)
- Audit all Scripted REST Resources, especially legacy or rarely reviewed endpoints, for both authentication and ACL enforcement.
- Review attachments, tickets, and knowledge entries for plaintext credentials or sensitive troubleshooting artefacts.
- Validate whether compensating controls such as IP restrictions, WAF rules, API monitoring, and anomaly alerting are in place.
- Reassess vendor-assurance questions around notification timeliness, logging sufficiency, and change-control visibility.

### 13.3 Strategic (7-30 days)
- Reduce secret sprawl in ticketing and workflow systems by enforcing secure secret-sharing alternatives.
- Establish a SaaS incident response playbook for third-party platforms that hold privileged operational data.
- Build detections around abnormal ServiceNow data access volume, unauthenticated endpoint exposure, and post-ticket credential abuse.
- Treat enterprise workflow platforms as high-value information repositories in threat models, not merely as administrative tooling.

## 14. Bottom-Line Assessment
The ServiceNow incident should be assessed as a confirmed third-party SaaS security event with potentially outsized downstream consequences. The strongest current evidence supports successful unauthorised data queries against a limited subset of customer instances rather than a universal platform-wide catastrophe. Even so, because ServiceNow often stores the exact operational detail attackers need for privilege escalation and social engineering, affected organisations should treat any confirmed access as a possible precursor to broader compromise.

## 15. References
1. ServiceNow KB3067321, vendor support bulletin quoted in secondary reporting; customer portal access required.
2. BleepingComputer reporting mirrored at https://note.f5.pm/go-422046.html
3. The CyberSec Guru, “ServiceNow API Breach: What Customers Need to Know Now”
4. Triskele Labs, “ServiceNow Security Incident: Unauthenticated API Access Exposing Customer Instance Data”
5. Anavem, “ServiceNow API Flaw Exposes Customer Data in Security Breach”
'''


def ensure_dirs(base: Path) -> None:
    for rel in ['final', 'detections', 'evidence/extracted-text', 'notes']:
        (base / rel).mkdir(parents=True, exist_ok=True)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + '\n', encoding='utf-8')


def write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding='utf-8')


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def html_escape(text: str) -> str:
    return (
        text.replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
    )


def p(text: str) -> str:
    return f'<p>{html_escape(text)}</p>'


def bullet(items: list[str]) -> str:
    body = ''.join(f'<li>{html_escape(item)}</li>' for item in items)
    return f'<ul>{body}</ul>'


def code_block(language: str, code: str) -> str:
    return f'<div class="code-title">{html_escape(language)}</div><pre class="code">{html_escape(code)}</pre>'


def table(headers: list[str], rows: list[list[str]]) -> str:
    thead = ''.join(f'<th>{html_escape(h)}</th>' for h in headers)
    body_rows = []
    for row in rows:
        body_rows.append('<tr>' + ''.join(f'<td>{cell}</td>' for cell in row) + '</tr>')
    return '<table><thead><tr>' + thead + '</tr></thead><tbody>' + ''.join(body_rows) + '</tbody></table>'


def render_html(base: Path, metadata: dict, cover_title: str, subtitle: str, sections: list[tuple[str, str]]) -> Path:
    short_title = cover_title.replace('Threat Intelligence Executive Summary', 'Executive Summary').replace('Threat Intelligence Report', 'Threat Intelligence Report')
    toc_items = ''.join(
        f'<li><a href="#sec-{i}">{html_escape(title)}</a></li>' for i, (title, _) in enumerate(sections, start=1)
    )
    section_html = []
    for i, (title, body) in enumerate(sections, start=1):
        section_html.append(f'<div class="page-break"></div><h1 id="sec-{i}">{html_escape(title)}</h1>{body}')
    logo_html = ''
    if LOGO.exists():
        logo_html = f'<div class="logo-wrap"><img class="logo" src="file://{LOGO}" alt="Lost Boys Cyber logo"></div>'
    html = f'''<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{html_escape(cover_title)}</title>
  <style>
    @page {{ size: Letter; margin: 0.72in; }}
    body {{ font-family: "Liberation Serif", serif; color: #111; font-size: 10.5pt; line-height: 1.35; }}
    h1, h2, h3 {{ color: #123d63; }}
    h1 {{ font-size: 15pt; margin-top: 0; border-bottom: 1px solid #75a9cf; padding-bottom: 5px; }}
    h2 {{ font-size: 12pt; margin-top: 16px; }}
    h3 {{ font-size: 11pt; margin-top: 12px; }}
    p {{ margin: 8px 0; }}
    ul, ol {{ margin-top: 6px; margin-bottom: 8px; }}
    li {{ margin-bottom: 4px; }}
    .cover {{ min-height: 9.5in; position: relative; }}
    .logo-wrap {{ text-align: center; margin-top: 12px; margin-bottom: 24px; }}
    .logo {{ max-width: 320px; max-height: 90px; }}
    .title {{ color: #123d63; font-size: 18pt; font-weight: 700; margin-top: 46px; }}
    .subtitle {{ font-size: 11pt; margin-top: 6px; }}
    .meta {{ width: 100%; border-collapse: collapse; margin-top: 18px; }}
    .meta td {{ border: 1px solid #75a9cf; padding: 6px 8px; }}
    .meta td:first-child {{ width: 28%; font-weight: 700; background: #f3f6f8; }}
    .identity {{ margin-top: 14px; color: #123d63; font-weight: 700; }}
    .identity-sub {{ margin-top: 4px; font-size: 9.5pt; }}
    .callout {{ margin-top: 18px; border: 1px solid #75a9cf; background: #eaf4fb; padding: 10px 12px; font-size: 9.5pt; }}
    .toc h1 {{ border-bottom: none; }}
    .toc ol {{ margin-left: 18px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 10px 0 14px 0; font-size: 9.7pt; }}
    th, td {{ border: 1px solid #75a9cf; padding: 6px 7px; vertical-align: top; }}
    thead th {{ background: #123d63; color: white; text-align: left; }}
    tbody tr:nth-child(even) td {{ background: #f3f6f8; }}
    .page-break {{ page-break-before: always; }}
    .code-title {{ color: #123d63; font-weight: bold; margin-top: 8px; font-size: 9.5pt; }}
    pre.code {{ white-space: pre-wrap; word-wrap: break-word; font-family: "Liberation Mono", monospace; font-size: 8.3pt; border: 1px solid #75a9cf; background: #f8fbfd; padding: 8px; }}
    .small {{ font-size: 9pt; }}
  </style>
</head>
<body>
  <div class="cover">
    {logo_html}
    <div class="title">{html_escape(cover_title)}</div>
    <div class="subtitle">{html_escape(subtitle)}</div>
    <table class="meta">
      <tr><td>Classification</td><td>{html_escape(metadata['classification'])}</td></tr>
      <tr><td>Published</td><td>{html_escape(metadata['published'])}</td></tr>
      <tr><td>Version</td><td>{html_escape(metadata['version'])}</td></tr>
      <tr><td>Author</td><td>{html_escape(metadata['author'])}</td></tr>
      <tr><td>Report Type</td><td>{html_escape(metadata['report_type'])}</td></tr>
      <tr><td>Severity</td><td>{html_escape(metadata['severity'])}</td></tr>
    </table>
    <div class="identity">{html_escape(metadata['classification'])} | Lost Boys Cyber | {html_escape(short_title)}</div>
    <div class="identity-sub">Published: {html_escape(metadata['published'])} | {html_escape(metadata['classification'])} | Version: {html_escape(metadata['version'])} | Author: {html_escape(metadata['author'])}</div>
    <div class="callout">{html_escape(AI_DISCLAIMER)}</div>
  </div>
  <div class="page-break toc">
    <h1>Table of Contents</h1>
    <ul>{toc_items}</ul>
  </div>
  {''.join(section_html)}
</body>
</html>
'''
    out_path = base / 'final' / (base.name + '.html')
    write_text(out_path, html)
    return out_path


def convert_pdf(html_path: Path) -> Path:
    outdir = html_path.parent
    subprocess.run([
        'libreoffice', '--headless', '--convert-to', 'pdf', '--outdir', str(outdir), str(html_path)
    ], check=True, cwd=str(html_path.parent))
    return outdir / (html_path.stem + '.pdf')


def extract_pdf_text(pdf_path: Path, destination: Path) -> None:
    subprocess.run(['pdftotext', str(pdf_path), str(destination)], check=True)


def build_exec_summary() -> None:
    ensure_dirs(EXEC_SUMMARY_DIR)
    metadata = {
        'report_id': ES_ID,
        'title': TITLE,
        'classification': CLASSIFICATION,
        'published': DATE_PUBLISHED,
        'version': '1.0',
        'author': AUTHOR,
        'report_type': 'Threat Intelligence Executive Summary',
        'severity': 'High',
    }
    write_yaml(EXEC_SUMMARY_DIR / 'metadata.yaml', metadata)
    write_text(EXEC_SUMMARY_DIR / 'report.md', EXEC_MD)
    write_text(EXEC_SUMMARY_DIR / 'sources.md', '\n'.join(f"- {s['id']}: {s['title']} ({s['type']}) — {s['notes']}" for s in SOURCES))
    write_text(EXEC_SUMMARY_DIR / 'references.md', '\n'.join([
        '1. ServiceNow support bulletin KB3067321 (quoted in secondary reporting; customer portal access required).',
        '2. BleepingComputer mirror: https://note.f5.pm/go-422046.html',
        '3. The CyberSec Guru: https://thecybersecguru.com/news/servicenow-api-vulnerability-breach/',
        '4. Triskele Labs: https://www.triskelelabs.com/resources/servicenow-security-incident-unauthenticated-api-access-exposing-customer-data',
        '5. Anavem: https://www.anavem.com/en/news/cybersecurity/servicenow-api-flaw-exposes-customer-data-in-security-breach',
    ]))
    write_csv(EXEC_SUMMARY_DIR / 'iocs.csv', IOCS)

    sections = [
        ('1. BLUF', p(BLUF)),
        ('2. Expected Impact Statement', p(EXPECTED_IMPACT)),
        ('3. What Happened', bullet([
            'ServiceNow applied a hosted security update on 5 June 2026 after identifying a security issue that could let an unauthenticated user gain greater access to instances than intended.',
            'The vendor stated that, for a subset of customers, it observed successful queries of instance tables and notified those customers directly by support case.',
            'Public reporting indicates the issue primarily impacted Australia-release tenants and some earlier-release instances with specific configuration changes.',
            'Community and third-party reporting strongly suggest the issue involved /api/now/related_list_edit/create and missing authentication on a Scripted REST resource.',
        ])),
        ('4. Why It Matters', bullet([
            'ServiceNow often stores highly sensitive operational data rather than just ticket metadata.',
            'Support cases and attachments can contain credentials, API tokens, architecture notes, and troubleshooting artefacts that enable follow-on intrusion.',
            'Even a limited read-only exposure can materially increase phishing, identity-abuse, and vendor-impersonation risk.',
            'Notification timing and hidden-advisory handling create third-party risk and compliance questions for affected organisations.',
        ])),
        ('5. Confidence and Caveats', table(
            ['Category', 'Assessment'],
            [
                ['High confidence', html_escape('Hosted remediation date, successful table queries for a subset of customers, vendor notification-by-case model, affected-scope language, and no public CVE assignment as of publication.')],
                ['Medium confidence', html_escape('Exact endpoint path, requires_authentication=false root-cause theory, Guest log context, and IP 51.159.98.241 as a primary hunt lead.')],
                ['Low-to-medium confidence', html_escape('Additional IP 86.245.155.105 and the claim that the issue was internally documented on 7 April 2026.')],
            ]
        )),
        ('6. Immediate Actions for Defenders', bullet([
            'Confirm whether your organisation received a ServiceNow support case tied to the incident.',
            'Review ServiceNow transaction and node logs for 2-3 June 2026, with focus on /api/now/related_list_edit/create and Guest-context activity.',
            'Review tickets, attachments, and knowledge records that may have contained plaintext credentials or sensitive implementation detail.',
            'Rotate any exposed secrets and monitor for follow-on use across identity, VPN, cloud, and developer platforms.',
            'Audit custom and legacy Scripted REST Resources for both authentication and ACL enforcement.',
        ])),
        ('7. Bottom-Line Assessment', p('This incident should be treated as a confirmed third-party SaaS security event with likely downstream exploitation value. Even if the exposed dataset proves limited, ServiceNow commonly holds the exact operational detail adversaries need to pivot into broader enterprise compromise.')),
    ]
    html_path = render_html(EXEC_SUMMARY_DIR, metadata, f'{TITLE} — Threat Intelligence Executive Summary', 'Executive Summary', sections)
    pdf_path = convert_pdf(html_path)
    extract_pdf_text(pdf_path, EXEC_SUMMARY_DIR / 'evidence' / 'extracted-text' / (pdf_path.stem + '.txt'))


def build_threat_report() -> None:
    ensure_dirs(THREAT_REPORT_DIR)
    metadata = {
        'report_id': TR_ID,
        'title': TITLE,
        'classification': CLASSIFICATION,
        'published': DATE_PUBLISHED,
        'version': '1.0',
        'author': AUTHOR,
        'report_type': 'Threat Intelligence Report',
        'severity': 'High',
    }
    write_yaml(THREAT_REPORT_DIR / 'metadata.yaml', metadata)
    write_text(THREAT_REPORT_DIR / 'report.md', THREAT_MD)
    write_text(THREAT_REPORT_DIR / 'sources.md', '\n'.join(f"- {s['id']}: {s['title']} ({s['confidence']}) — {s['notes']}" for s in SOURCES))
    write_text(THREAT_REPORT_DIR / 'references.md', '\n'.join([
        '1. ServiceNow support bulletin KB3067321 (quoted in secondary reporting; customer portal access required).',
        '2. BleepingComputer mirror: https://note.f5.pm/go-422046.html',
        '3. The CyberSec Guru: https://thecybersecguru.com/news/servicenow-api-vulnerability-breach/',
        '4. Triskele Labs: https://www.triskelelabs.com/resources/servicenow-security-incident-unauthenticated-api-access-exposing-customer-data',
        '5. Anavem: https://www.anavem.com/en/news/cybersecurity/servicenow-api-flaw-exposes-customer-data-in-security-breach',
    ]))
    write_csv(THREAT_REPORT_DIR / 'iocs.csv', IOCS)
    write_yaml(THREAT_REPORT_DIR / 'mitre_attack.yaml', {'attack_mapping': ATTACK_MAPPING})
    write_text(THREAT_REPORT_DIR / 'detections' / 'servicenow_hunt.kql', KQL_QUERY)
    write_text(THREAT_REPORT_DIR / 'detections' / 'servicenow_hunt.spl', SPL_QUERY)
    write_text(THREAT_REPORT_DIR / 'detections' / 'servicenow_related_list_edit.yml', SIGMA_RULE)

    sections = [
        ('1. Executive Summary', p(BLUF) + p(EXPECTED_IMPACT)),
        ('2. Intelligence Requirement and Scope', p('This report assesses the June 2026 ServiceNow hosted-instance security incident, with emphasis on confirmed facts, assessed technical root cause, likely data at risk, detection implications, and expected business impact.') + p('Available evidence points to unauthorised access against customer instances via a public-facing API control failure, not a broadly evidenced compromise of the ServiceNow corporate environment itself.')),
        ('3. Source Review and Confidence', table(
            ['Source ID', 'Source', 'Assessment'],
            [[s['id'], html_escape(s['title']), html_escape(s['confidence'] + ' — ' + s['notes'])] for s in SOURCES]
        )),
        ('4. Incident Overview', p('On 5 June 2026, ServiceNow applied a hosted security update to customer instances after identifying a security issue that could allow an unauthenticated user, in certain circumstances, to gain greater access to ServiceNow instances than intended.') + p('According to the quoted vendor bulletin, ServiceNow detected anomalous activity and observed evidence of successful queries of instance tables for a subset of customers, then notified affected customers directly through support cases.')),
        ('5. Timeline', table(
            ['Date', 'Event', 'Confidence'],
            [
                ['2026-04-07', html_escape('Single-source claim that ServiceNow had internally documented the issue in a problem record.'), 'Low-Medium'],
                ['2026-06-02 to 2026-06-03', html_escape('Observed anomalous activity and likely exploitation window across affected tenants.'), 'High'],
                ['2026-06-05', html_escape('ServiceNow applies hosted fix restricting the affected endpoint to authenticated users.'), 'High'],
                ['2026-06-09', html_escape('Customer notifications by support case and public reporting begin to surface.'), 'High'],
                ['2026-06-10', html_escape('Defender-focused third-party analyses expand detection and response guidance.'), 'High'],
            ]
        )),
        ('6. Technical Analysis',
            '<h2>6.1 Assessed Root Cause</h2>' + p('Public reporting strongly suggests the incident involved a Scripted REST Resource associated with /api/now/related_list_edit/create. Multiple sources state the endpoint did not require authentication and that the 5 June update changed the configuration to authenticated-only access.') +
            p('ServiceNow has not publicly confirmed the exact path or issued a public deep-dive advisory, so the endpoint-level explanation should be treated as a high-value working hypothesis rather than a fully public vendor-confirmed fact.') +
            '<h2>6.2 Affected Scope</h2>' + bullet([
                'Customers on the Australia platform release.',
                'Customers on releases prior to Australia who made certain configuration changes.',
            ]) +
            '<h2>6.3 Access Pattern and Logging Implications</h2>' + bullet([
                'Several affected tenants reportedly observed a small cluster of hits against the probable endpoint.',
                'Unauthenticated activity may appear in transaction logs as Guest because no authenticated principal existed.',
                'Many customers may not be able to reconstruct full data access because REST message logging was not enabled beforehand.',
            ]) +
            '<h2>6.4 Likely Data at Risk</h2>' + bullet([
                'ITSM records including incidents, problems, change records, CMDB entries, and service requests.',
                'Security operations workflows, incident-response notes, vulnerability data, and case attachments.',
                'Employee-service data, internal documentation, workflow notes, and administrative attachments.',
                'Credentials, API tokens, screenshots, troubleshooting notes, and integration strings stored in records.',
            ])
        ),
        ('7. Threat Activity Assessment', p('No public evidence currently attributes the exploitation to a named actor. The activity is best understood as opportunistic exploitation of a high-value SaaS access-control failure.') + bullet([
            'Operational architecture knowledge useful for later intrusion or social engineering.',
            'Embedded credentials or tokens stored in tickets and attachments.',
            'Security-process insight that can reveal monitoring blind spots.',
            'Help-desk and change-management detail that can be weaponised for trust-based attacks.',
        ])),
        ('8. Infrastructure and Indicators', table(
            ['Type', 'Value', 'Confidence', 'Notes'],
            [[ioc['ioc_type'], html_escape(ioc['value']), ioc['confidence'], html_escape(ioc['notes'])] for ioc in IOCS]
        )),
        ('9. Victimology and Targeting', bullet([
            'Enterprises using ServiceNow as an operational system of record for ITSM, SecOps, HR, CMDB, and workflow automation.',
            'Healthcare, financial services, government, and MSP environments where ticket content may expose regulated or privileged information.',
            'Organisations with mature integrations that store secrets, connection strings, or troubleshooting artefacts inside records and attachments.',
        ])),
        ('10. Detection Engineering',
            table(
                ['Priority', 'Signal', 'Why it matters'],
                [
                    ['1', html_escape('Requests to /api/now/related_list_edit/create during 2-3 June 2026'), html_escape('Highest-confidence hunt lead tied to public reporting.')],
                    ['2', html_escape('Requests from 51.159.98.241 or 86.245.155.105'), html_escape('Useful infrastructure pivot, though not definitive alone.')],
                    ['3', html_escape('Guest-context access to related-list edit operations'), html_escape('May identify unauthenticated activity hidden as non-user actions.')],
                    ['4', html_escape('Spikes in table-query volume or unusual row-access patterns'), html_escape('Can reveal broader enumeration outside the IOC set.')],
                    ['5', html_escape('Post-incident use of secrets stored in tickets or attachments'), html_escape('Detects follow-on exploitation rather than the initial access alone.')],
                ]
            ) +
            '<h2>10.2 Example Microsoft Sentinel / KQL Hunt</h2>' + code_block('kusto', KQL_QUERY) +
            '<h2>10.3 Example Splunk Hunt</h2>' + code_block('spl', SPL_QUERY) +
            '<h2>10.4 Example Sigma Analytic Logic</h2>' + code_block('yaml', SIGMA_RULE)
        ),
        ('11. Threat Hunting Guidance', bullet([
            'Pull all ServiceNow transaction, node, API gateway, reverse-proxy, and WAF logs for 1-6 June 2026.',
            'Hunt for the probable endpoint path, suspicious source IPs, and Guest-context related-list operations.',
            'Review records accessed in the relevant time window for secrets, attachments, screenshots, and architecture detail.',
            'Cross-check downstream authentication events in IdP, VPN, PAM, cloud, and developer platforms for exposed accounts or secrets.',
            'Monitor for phishing or impersonation activity themed around help-desk, incident response, or change-management processes.',
        ])),
        ('12. Risk Assessment', table(
            ['Dimension', 'Assessment'],
            [
                ['Confidentiality', html_escape('High for affected tenants because records may contain sensitive business data and credentials.')],
                ['Integrity', html_escape('Medium because public reporting most strongly supports successful query activity, but some community reporting suggests write attempts may also have occurred.')],
                ['Availability', html_escape('Low direct impact from the incident itself; main concern is downstream disruption if exposed secrets are abused.')],
                ['Regulatory / Compliance', html_escape('High for regulated organisations if personal, security, or support-case data was exposed.')],
                ['Third-Party / Vendor Risk', html_escape('High because the incident occurred inside a trusted SaaS workflow platform and challenges shared-responsibility assumptions.')],
            ]
        )),
        ('13. Recommended Actions',
            '<h2>13.1 Immediate (0-24 hours)</h2>' + bullet([
                'Confirm whether your organisation received a ServiceNow support case tied to this incident.',
                'Preserve all relevant ServiceNow and perimeter logs from 1-6 June 2026.',
                'Identify records likely to contain secrets and begin risk-ranked secret rotation.',
                'Notify legal, privacy, and vendor-risk teams if suspicious access is confirmed.',
            ]) +
            '<h2>13.2 Near-Term (1-7 days)</h2>' + bullet([
                'Audit all Scripted REST Resources for authentication and ACL enforcement.',
                'Review attachments, tickets, and knowledge entries for plaintext credentials or sensitive troubleshooting artefacts.',
                'Validate WAF, IP restriction, and API-monitoring coverage around internet-reachable endpoints.',
                'Reassess vendor-assurance questions around notification timeliness and logging sufficiency.',
            ]) +
            '<h2>13.3 Strategic (7-30 days)</h2>' + bullet([
                'Reduce secret sprawl in ticketing and workflow systems.',
                'Create SaaS-focused incident-response playbooks for platforms that hold privileged operational data.',
                'Build detections for abnormal ServiceNow data access and post-ticket credential abuse.',
                'Threat-model workflow platforms as high-value information repositories, not just administrative tooling.',
            ])
        ),
        ('14. ATT&CK Mapping', table(
            ['Tactic', 'Technique', 'Confidence', 'Assessment'],
            [[row['tactic'], html_escape(row['technique']), row['confidence'], html_escape(row['assessment'])] for row in ATTACK_MAPPING]
        )),
        ('15. Bottom-Line Assessment', p('The strongest current evidence supports successful unauthorised data queries against a limited subset of customer instances rather than a universal platform-wide catastrophe. Even so, because ServiceNow often stores the exact operational detail attackers need for privilege escalation, social engineering, and secret abuse, any confirmed affected tenant should treat this incident as a possible precursor to broader compromise.')),
        ('16. References', '<ol>' + ''.join([
            '<li>ServiceNow KB3067321, vendor support bulletin quoted in secondary reporting; customer portal access required.</li>',
            '<li>BleepingComputer mirror: https://note.f5.pm/go-422046.html</li>',
            '<li>The CyberSec Guru: https://thecybersecguru.com/news/servicenow-api-vulnerability-breach/</li>',
            '<li>Triskele Labs: https://www.triskelelabs.com/resources/servicenow-security-incident-unauthenticated-api-access-exposing-customer-data</li>',
            '<li>Anavem: https://www.anavem.com/en/news/cybersecurity/servicenow-api-flaw-exposes-customer-data-in-security-breach</li>',
        ]) + '</ol>'),
    ]
    html_path = render_html(THREAT_REPORT_DIR, metadata, f'{TITLE} — Threat Intelligence Report', 'Full Threat Intelligence Report', sections)
    pdf_path = convert_pdf(html_path)
    extract_pdf_text(pdf_path, THREAT_REPORT_DIR / 'evidence' / 'extracted-text' / (pdf_path.stem + '.txt'))


if __name__ == '__main__':
    if shutil.which('libreoffice') is None:
        raise SystemExit('libreoffice is required but not installed')
    build_exec_summary()
    build_threat_report()
    print('Built ServiceNow executive summary and threat report.')
