# [PhishNet] - HackTheBox Writeup

![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green)
![OS](https://img.shields.io/badge/OS-Linux-blue)
![Type](https://img.shields.io/badge/Type-Blue%20Team-blueviolet)

## Summary

**Platform:** HackTheBox  
**Challenge Type:** Sherlock 
**Difficulty:** Very Easy  
**Date Completed:** 16-11-2025  
**Time Taken:** 1 hours  

**Quick Overview:**  
This Sherlock challenges you to investigate a phishing incident by analyzing phishing mail.

---

## Scenario

An accounting team receives an urgent payment request from a known vendor. The email appears legitimate but contains a suspicious link and a .zip attachment hiding malware. Your task is to analyze the email headers, and uncover the attacker's scheme.

---

## Analysis & Methodology

### Step 1: Initial Triage

**What I did:**
- Extract the zip file in a safe VM.
- Checked file hashes
- Identified file types

**Code/Commands:**
```bash
ls -lah
file *
md5sum PhishNet.zip
```

**Findings:**
- Found 1 eml file (email.eml)

**Screenshot:**
[Evidence triage screenshot]

---

## Questions & Answers

**Q1: What is the originating IP address of the sender?**  
**A:** 
    Firstly when we start to investigate the email.eml file we see a sended phishing email log we 
    

**Q2: What malware family was used?**  
**A:** Meterpreter (based on C2 port 4444 and reverse shell characteristics)

**Q3: What was the attacker's goal?**  
**A:** Establish persistence and perform lateral movement (attempted Pass-the-Hash at 04:12)

---

## Lessons Learned & Recommendations

**Detection Gaps Identified:**
1. No alerting on off-hours RDP logons
2. PowerShell script block logging not monitored in real-time
3. No egress filtering for known malicious IPs

**Recommendations:**
1. **Implement SIEM alerting** for:
   - Off-hours administrative logons
   - PowerShell execution with base64 encoding
   - Connections to non-standard ports (4444, 8443, etc.)

2. **Harden RDP:**
   - Implement MFA for all RDP sessions
   - Restrict RDP to jump servers only
   - Use network-level authentication (NLA)

3. **Improve logging:**
   - Enable PowerShell Module Logging
   - Increase Sysmon verbosity
   - Centralize logs to SIEM

4. **Network controls:**
   - Block outbound traffic to known C2 infrastructure
   - Implement application whitelisting

---

## Tools & Resources
- [CyberChef](https://gchq.github.io/CyberChef/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## Conclusion

This investigation demonstrated a classic post-exploitation scenario where an attacker gained initial access via RDP, deployed a PowerShell payload, and established C2 communication. The attack could have been prevented with proper monitoring and hardening.

**Personal Reflection:**  
This challenge reinforced the importance of baseline knowledge - knowing what "normal" looks like makes detecting anomalies much easier. The correlation between event logs and network traffic was key to building a complete picture.

---

## Metadata

**Tags:** #BlueTeam #Forensics #WindowsEventLogs #PowerShell #IncidentResponse  
**HTB Profile:** [YourUsername](https://app.hackthebox.com/users/xxxxx)  
**Date:** 2025-XX-XX
