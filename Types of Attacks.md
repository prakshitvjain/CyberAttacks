In the world of Cyber-Security, malicious attackers uses various kinds of techniques or methods to attack organizations or Individuals for personal gain. In this article, we'll be discussing various attack vectors that hackers use to attack systems and their preventive measures.

## Social Engineering Attacks
The Social Engineering attacks are one of the most common attacks in cyber security. They involve targeting particular humans or employees of an organization or a group of people rather than devices.

Social Engineering Attacks include
#### Phishing
Phishing involves sending mass emails randomly with malicious links or files which when clicked, download malicious software or redirect to a fraudulent site that steals the victim's credentials.
#### Spear Phishing
Spear Phishing is similar to phishing but it is targeted at a specific individual or an organisation.
#### Vishing 
Voice Phishing refers to Phishing attacks over the phone calls to extract sensitive information.
#### Smishing
Smishing refers to SMS Phishing where fraudulent text messages are sent to deceive people into revealing personal information.
#### Pretexting
Pretexting refers to creating a fabricated story to convince victims to release confidential information.
#### Baiting
Baiting involves luring victims to reveal information by offering exciting discounts or prizes that they can't refuse.
#### Quizzes/Surveys
Manipulating victims into filling personal information via forms guaranteeing them rewards.
### Precautions
1. Never click on unknown links or open files from a unauthorized source.
2. Never reveal any information to anyone about the company or a user of the company via calls, emails, messages without verifying the client.
3. There is a thin line between a responsible employee and a kind person, a kind person is vulnerable and is a threat to the security of the organization.
4. Never believe lottery wins, offers, discounts or any other kinds of rewards from unauthorized sources or if you are unaware of the sources.
5. If an email contains a link, hover over the link to identify where will it redirect you to.

## Malware Attacks
Malware Attacks involve malicious software or code that can steal sensitive data or damage computer, network or servers without the victim even noticing. There are various types of malware attacks such as
#### Viruses
A malicious software that is attached to a file and spreads when the files are shared by the victims. It is popularly known by the people but yet very effective if implemented accordingly.
#### Worms
Worms are self-replicating malware that spread across networks. They do not require any human intervention and spread quickly and cause widespread damage and data loss. They also install backdoors through which attackers can enter the system.
#### Trojans
Trojans refers to malicious software that are posed as legitimate applications, that are installed by the victim itself. Trojans are common in websites that offer pirated content for free.
#### Ransomware
In Ransomware, the attackers encrypt the files of the victim, and demands payment (ransom) for decryption. There are numerous case studies on ransomware.
#### Spyware
Spyware is another type of malware that monitors the victim's activity and steals information. The attacker can know when you use the applications, what applications you use, what you type in the system (including passwords) and a lot of other information. The key stroke monitoring malware are called key-loggers.
#### Adware
This malicious software forcefully displays or downloads unwanted ads on the victim's system. 
#### Rootkits
These are designed to help attackers gain access to victim's system without being detected for a long time. Such attacks are difficult to detect. They also hide the activity of attacker to help him remain hidden.
### Precautions
1. Do not install software or application from unknown sources.
2. Always have trusted anti-virus software installed in the system.
3. Conduct regular scans for malware using reputed anti-malware software.
4. Use robust firewalls in the operating system.
5. Regularly back-up important data in case of failures or attacks.
## Network Attacks
These are unauthorized attacks on a network's digital assets, targeting the network's perimeter to gain access to internal systems. These are generally targeted on networks of organisations.

Network Attacks include
#### DoS
In Denial of Service attack, the attacker floods the server or network with large number of HTTP requests resulting in the server or network becoming unavailable or unresponsive to legitimate users.
#### DDoS
The Distributed Denial of Service attack involves attackers to use multiple compromised systems to flood the server or network with enormous amount of requests, resulting in the server becoming unresponsive.
#### MITM
The Man In The Middle attack involves a scenario where the attacker is positioned in between two communicating parties. The attacker can eavesdrop, manipulate, impersonate one of the parties and steal data.
#### DNS Spoofing
DNS Spoofing refers to redirecting traffic by corrupting the DNS cache, leading users to malicious sites.
#### Sniffing
Sniffing refer to process of intercepting any analyzing traffic to steal sensitive information such as passwords, credit card numbers etc.
#### Spoofing
Spoofing refers to impersonating a trusted entity to gain access to systems or services and stealing data or misusing the access in any way.
### Precautions
As an Organisation, the following steps are to be implemented
1. Next-generation Firewalls to scan the incoming requests and allow only legitimate requests.
2. Strong Encryption algorithms are to be used in case of data leakage or unauthorized access to data.
3. Appropriate access control is to be implemented using the PoLP (Principle of Least Privilege).
4. Intrusion Detection Systems to monitor the incoming traffic and unauthorized intrusions.

## Application and Web based Attacks
The Application and Web based Attacks are attacks carried on the Web Application of an organisation. Such attacks are very common and pose critical security threats that are irreversible in some cases.
#### SQL Injection
SQL Injection involves injecting malicious SQL queries into input fields to bypass authentication or steal data. In some cases, the entire Database can be deleted. Posing existential threats to the organisation.
#### Cross Site Scripting (XSS)
Cross Site Scripting refers to attackers injecting malicious scripts into the input field to steal cookies and sessions data, change web page content and redirect the browser to another site.
#### Cross Site Request Forgery (CSRF)
This attack involves forcing victims to execute malicious actions on a web application in which they're already logged in. The web application executes the request as it seemed to come from a legitimate source.
#### Command Injection
Attackers can inject malicious operating system commands into a system's input fields to execute unauthorized operations.
#### Remote Code Execution (RCE)
Remote Code Execution is a severe attack where attacker uploads a malicious files. This file when executed, can allow the attacker to have full control on the web server. The attacker can run OS commands that can leak confidential information.
#### Broken Authentication
Attackers can gain unauthorized access to user accounts by exploiting weak authentication mechanisms that have poorly implemented session management.
#### Insecure Direct Object References (IDOR)
This involves attacker to exploit flaws that allows attacker to access information that they shouldn't have access to. This happens when the application uses user supplied input to access the objects directly.
### Precautions
1. During the development of the application, parameterized queries or prepared statements are to be used to prevent SQL Injection.
2. Every User Input should be validated and special symbols should be escaped safely.
3. Secure Software Development Life Cycle (SSDLC) is to be followed.

## Credential-based Attacks
These attacks revolve around credentials such as usernames and passwords.
#### Brute Force
The popular technique involving the attacker to repeatedly try all possible combinations of passwords until the correct one is found. Brute Force is ineffective considering modern security practices.
#### Dictionary Attack
The attacker tries a pre defined list of possible passwords until the correct one is found. The list usually consists of common passwords. This method is similar to brute force except that in Dictionary Attack, common phrases are tried instead of all possible combinations.
#### Credential Stuffing
The Attacker uses stolen credentials from one breach to gain access elsewhere.
#### Password Cracking
The Attacker breaks encrypted passwords by exploiting weak encryption algorithms.
### Precautions
1. Always use complex (a mix of lowercase, uppercase, symbols and numbers) and long (16 characters is recommended) passwords.
2. Always use different passwords for different accounts. Do NOT repeat your passwords.
3. As an organisation, always use robust encryption algorithms like AES 256.

## Insider Threats
Insider Threats are threats that originate from within the Organisation.
#### Malicious Insiders
Employees or trusted individuals who intentionally misuse their access to cause harm the organization or steal data for personal gain.
#### Negligent Insiders
Employees who mistakenly reveal sensitive information of the organisation due to their carelessness or lack of knowledge.
### Precautions
As an Organisation,
1. Employees are to be trained and educated on what is safe and unsafe.
2. Continuously monitor the activities of employees to look for unusual activities.

## Zero-Day Attack
The Zero-Day Attack is itself an attack involves attacker exploiting software, hardware or firmware weaknesses that are unknown to the vendor and has not been patched.
### Precautions
1. Implement Web Application Firewalls
2. Always keep your systems and software updated.
3. Perform rigorous patch management

## Physical Security Attacks
#### USB Dropping
The Attackers drop malicious USB drives in public spaces in hopes that random people might plug them into their systems. If such USB drives are plugged into systems, the attacker can gain control over the systems.
#### Hardware Key-Loggers
The attacker installs hardware devices on computers or ATM machines to record keystrokes to capture passwords and PINs.
#### Physical Theft
The Attacker can steal the devices such as laptops, smartphones, hard drives that contain sensitive data.
### Precautions
1. Never plug unknown devices into any systems. Hold your excitement. It is extremely dangerous.
2. As far as possible, never enter your credentials on other devices and protect you device from unauthorized access.
3. Always keep your devices in safe cabinets and not in easily accessible places.


