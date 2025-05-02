# OWASP Top 10 Web Application Security Risks (2021)

The OWASP Top 10 is a standard awareness document representing a broad consensus about the most critical security risks to web applications.

## Table of Contents
1. [A01:2021 - Broken Access Control](#a01-broken-access-control)
2. [A02:2021 - Cryptographic Failures](#a02-cryptographic-failures)
3. [A03:2021 - Injection](#a03-injection)
4. [A04:2021 - Insecure Design](#a04-insecure-design)
5. [A05:2021 - Security Misconfiguration](#a05-security-misconfiguration)
6. [A06:2021 - Vulnerable and Outdated Components](#a06-vulnerable-and-outdated-components)
7. [A07:2021 - Identification and Authentication Failures](#a07-identification-and-authentication-failures)
8. [A08:2021 - Software and Data Integrity Failures](#a08-software-and-data-integrity-failures)
9. [A09:2021 - Security Logging and Monitoring Failures](#a09-security-logging-and-monitoring-failures)
10. [A10:2021 - Server-Side Request Forgery](#a10-server-side-request-forgery)

## <a name="a01-broken-access-control"></a>A01:2021 - Broken Access Control

**Moved up from #5 in 2017**

* On average, 3.81% of applications tested had one or more Common Weakness Enumerations (CWEs) in this category
* Over 318k occurrences of CWEs in this risk category
* The 34 CWEs mapped to Broken Access Control had more occurrences in applications than any other category

## <a name="a02-cryptographic-failures"></a>A02:2021 - Cryptographic Failures

**Shifted up from #3 in 2017 (previously known as "Sensitive Data Exposure")**

* The renamed category focuses on failures related to cryptography
* This category often leads to:
  * Sensitive data exposure
  * System compromise

## <a name="a03-injection"></a>A03:2021 - Injection

**Moved down from #1 in 2017**

* 94% of applications were tested for some form of injection
* Maximum incidence rate of 19%
* Average incidence rate of 3.37%
* 33 CWEs mapped into this category have the second most occurrences (274k)
* Cross-site Scripting is now part of this category

## <a name="a04-insecure-design"></a>A04:2021 - Insecure Design

**New category for 2021**

* Focuses on risks related to design flaws
* Highlights the need for:
  * More threat modeling
  * Secure design patterns and principles
  * Reference architectures
* An insecure design cannot be fixed by perfect implementation as needed security controls were never created to defend against specific attacks

## <a name="a05-security-misconfiguration"></a>A05:2021 - Security Misconfiguration

**Moved up from #6 in 2017**

* 90% of applications were tested for some form of misconfiguration
* Average incidence rate of 4.5%
* Over 208k occurrences of CWEs mapped to this risk category
* The former category for A4:2017-XML External Entities (XXE) is now part of this risk category

## <a name="a06-vulnerable-and-outdated-components"></a>A06:2021 - Vulnerable and Outdated Components

**Moved up from #9 in 2017 (previously titled "Using Components with Known Vulnerabilities")**

* Ranked #2 in the Top 10 community survey
* This category is a known issue that we struggle to test and assess risk
* The only category without any Common Vulnerability and Exposures (CVEs) mapped to the included CWEs
* Default exploit and impact weights of 5.0 are factored into scores

## <a name="a07-identification-and-authentication-failures"></a>A07:2021 - Identification and Authentication Failures

**Moved down from #2 in 2017 (previously "Broken Authentication")**

* Now includes CWEs more related to identification failures
* Still an integral part of the Top 10
* The increased availability of standardized frameworks seems to be helping reduce this risk

## <a name="a08-software-and-data-integrity-failures"></a>A08:2021 - Software and Data Integrity Failures

**New category for 2021**

* Focuses on making assumptions related to:
  * Software updates
  * Critical data
  * CI/CD pipelines without verifying integrity
* One of the highest weighted impacts from CVE/CVSS data mapped to the 10 CWEs in this category
* A8:2017-Insecure Deserialization is now part of this larger category

## <a name="a09-security-logging-and-monitoring-failures"></a>A09:2021 - Security Logging and Monitoring Failures

**Moved up from #10 in 2017 (previously "Insufficient Logging & Monitoring")**

* Added from the Top 10 community survey (#3)
* This category is expanded to include more types of failures
* Challenging to test for and not well represented in the CVE/CVSS data
* Failures in this category can directly impact:
  * Visibility
  * Incident alerting
  * Forensics

## <a name="a10-server-side-request-forgery"></a>A10:2021 - Server-Side Request Forgery

**New addition from the Top 10 community survey (#1)**

* The data shows a relatively low incidence rate with above-average testing coverage
* Above-average ratings for Exploit and Impact potential
* Represents an area the security community identifies as important, even though it's not fully illustrated in the data
