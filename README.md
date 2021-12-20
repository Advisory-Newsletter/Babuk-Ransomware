# Babuk-Ransomware
**RELATED IOCs, MITIGATION STEPS AND REFERENCE LINKS**

**Common Vulnerabilities and Exposures (CVE)** 
CVE-2021-34473, CVE-2021-34523 and CVE-2021-31207

**IOCs(Indicators of compromise)**

PAYLOAD:- bd26b65807026a70909d38c48f2a9e0f8730b1126e80ef078e29e10379722b49 

**RELATED SAMPLES:**

b3b66f7e70f1e1b1494677d0ed79fcc7d4901ffae53d89fd023c8b789bb0fe62 - reverse shell to 185[.]219[.]52[.]229:6666 

949c262359f87c8a0e8747f28a89cf3d519b35fbc5a8be81b2cd9e6adc830370 - PowerCat netcat clone 

4fa565cc2ebfe97b996786facdb454e4328a28792e27e80e8b46fe24b44781af - leaked Babuk builder 

**MITIGATION**
—	Ensure to have all July security patches associated with Microsoft Exchange is added.
https://techcommunity.microsoft.com/t5/exchange-team-blog/released-july-2021-exchange-server-security-updates/ba-p/2523421

—	Have rules created to identify webshells and malicious binaries in EDR and SIEM. Sample rules are in below link.

	https://github.com/Neo23x0/signature-base/blob/master/yara/expl_proxyshell.yar
	https://github.com/Neo23x0/signature-base/blob/master/yara/generic_anomalies.yar#L410

—	Monitor activities of w3wp.exe 
—	Ensure AV and EDR is deployed on all servers across the environment especially on those where we have not patched.

 **Reference link:**
 
1	https://gbhackers.com/babuk-locker-emerges-as-new-enterprise-ransomware-of-2021/ 

2	https://www.securityweek.com/babuk-ransomware-seen-exploiting-proxyshell-vulnerabilities 

3	https://threatpost.com/babuk-ransomware-builder-virustotal/167481/

4	https://threatpost.com/ransomware-babuk-locker-large-corporations/162836/ 

5	https://blogs.quickheal.com/anydesk-software-exploited-to-spread-babuk-ransomware/ 
