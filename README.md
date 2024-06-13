# Active Directory Lab

## Objective

The Active Directory Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to set up an Active Directory environment with sysmon to log endpoints events and configure them to forward events to Splunk. The secondary focus was to utilize a Kali Linux virtual machine to simulate a brute force attack and install Atomic Red Team to test which attacks would be caught by Splunk. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

### Skills Learned

- **Active Directory Installation and Configuration**: Setting up a Windows Server machine as a domain controller involves installing and configuring Active Directory Domain Services (AD DS), which includes tasks such as domain creation, DNS configuration, and user/group management.
- **Group Policy Management**: Configuring Group Policy Objects (GPOs) to enforce security policies, manage user and computer configurations, and deploy software across the domain.
- **User and Group Management**: Creating and managing user accounts, groups, and organizational units (OUs) within Active Directory, and understanding the principles of least privilege and role-based access control (RBAC).
- **Security Hardening**: Implementing security best practices for securing Active Directory, such as configuring password policies, enabling multi-factor authentication, and setting up administrative roles and delegation.
- **Endpoint Security Configuration**: Configuring security settings on Windows 10 target machines to protect against common attack vectors, such as enabling Windows Defender antivirus, configuring firewall rules, and implementing security updates.
- **Logging and Monitoring**: Setting up centralized logging using Splunk to collect and analyze security event logs from Windows machines, including authentication events, privilege escalation attempts, and suspicious activities.
- **Attack and Penetration Testing**: Using Kali Linux to simulate various attack scenarios against the Windows 10 target machine, such as phishing attacks, privilege escalation exploits, and lateral movement techniques.
- **Security Incident Response**: Developing incident response procedures and protocols for detecting, analyzing, and responding to security incidents within the Active Directory environment, including steps for containment, eradication, and recovery.
- **Documentation and Reportin**g: Documenting the configuration settings, security policies, and procedures implemented within the Active Directory environment, and preparing reports on security posture, vulnerabilities, and remediation actions.

### Tools Used

- **Active Directory Domain Services (AD DS)**: Built-in Windows Server role for managing domain controllers, users, groups, and computers within a Windows domain.
- **Windows Server 2022**: Used as the operating system for the domain controller to host Active Directory services.
- **Windows 10**: Used as the operating system for the target machine representing a user endpoint within the domain.
- **Kali Linux**: A Linux distribution designed for penetration testing and ethical hacking, used as the attacker machine to simulate various attack scenarios.
- **Splunk**: A platform for collecting, indexing, and analyzing machine-generated data, used as the centralized logging and monitoring solution for collecting security event logs from Windows machines.
- **Sysmon**: A Windows system service that logs detailed system activity to the Windows event log, aiding in threat detection and incident response. It enhances visibility into potential security threats by monitoring process creation, network connections, file modifications, and more.
- **Atomic Red Team**: Atomic Red Team provides a library of test cases based on the MITRE ATT&CK framework, allowing organizations to validate their security controls and detection capabilities against known adversary tactics, techniques, and procedures (TTPs).

## Steps

### 1: Topology Design

Designing the topology for a project like this is a necessary first step to ensure the efficient allocation of resources, proper communication between systems, and the establishment of a secure network architecture tailored to the project's objectives.

![Active Directory drawio](https://github.com/LukaB0/CTF-Challenges/assets/169913850/1789521f-9478-42e7-9813-c56d9f6497c0)
*Ref 1: Active Directory Project Topology*

### 2: Installing Virtual Machines

The following step was installing and setting up all 4 virtual machines via Virtual Box. The machines used were as follows:

- **Ubuntu Server** : For the Splunk Server
- **Windows Server 2022** : For Active Directory
- **Windows 10** : For sysmon and splunk forwarder service
- **Kali Linux** : For attack simulation

### 3: Configure Splunk & Target Machine

This step entailed configuring the splunk server and target machine with the correct static ip addresses and dns servers as planned by the topology in _Ref 1_. Then, a custom inputs.conf file was created to forward certain WinEventLogs to Splunk.

![Network conf for Target Machine](https://github.com/LukaB0/CTF-Challenges/assets/169913850/dc217d2b-82dd-4d63-bd55-355fd34c5c44)
*Ref 2: Static IP Address and DNS Configuration for the Target Machine*

![inputs config for splunkforwarder](https://github.com/LukaB0/CTF-Challenges/assets/169913850/9d2f117b-8d0b-4fa1-93cb-332ee7b1dc9a)
*Ref 3: WinEventLogs will be sent to the Splunk "endpoint" index*

Afterwards it was time to login to the Splunk interface and configure the index and receiving port.

![Splunk endpoint conf](https://github.com/LukaB0/CTF-Challenges/assets/169913850/69b27635-e0ab-47c7-b4c2-ad9d206ac300)
*Ref 4: New index created named endpoint. This is where all sysmon logs will be sent to.*

![Splunk receiving confg](https://github.com/LukaB0/CTF-Challenges/assets/169913850/084e55af-08b3-4000-a8ec-ec8d2d54621e)
*Ref 5: Receiving port configured to the default 9997*

### 4: Install Active Directory & Sysmon on Windows Server 2022 

After installing ADDS and configuring the Windows Server with the network settings it was time to set up a new forest with users.

![Server AD Domain and Users](https://github.com/LukaB0/CTF-Challenges/assets/169913850/adc0215e-ec78-4289-8386-6fdb2ecfc775)
*Ref 6: New forest with the name luka.lab created along with 2 departments: IT & HR*

![bdylan IT](https://github.com/LukaB0/CTF-Challenges/assets/169913850/4b9fcdca-81f0-4461-a3bf-c298bf45c0bc)
*Ref 7: New user named Bob Dylan is created in the IT Department.*

![swosniak HR](https://github.com/LukaB0/CTF-Challenges/assets/169913850/91954c73-85ea-46ca-80d2-605a9d3e49c0)
*Ref 8: New user named Steve Wosniak is created in the HR Department.*

### 5: Simulate Attack on Target Machine

Before attacking the machine it was necessary to enable remote desktop for the user whose machine would be attacked.

![RDP Config](https://github.com/LukaB0/CTF-Challenges/assets/169913850/8812b76f-99cd-473d-a14f-b6253deadb39)
*Ref 9: RDP enabled for Users*

Now it was time to attack the Windows 10 machine with a brute force attack. A password list was created with 20 options from the rockyou password list along with a specific entry custom to this attack.

![Kali bruteforce command](https://github.com/LukaB0/CTF-Challenges/assets/169913850/dc736909-f1fb-4a43-bf38-ac8ffc6dd4d1)
*Ref 10: Crowbar tool is used to bruteforce the login.*

The attack is caught in Splunk.

![splunk kali bruteforce notif](https://github.com/LukaB0/CTF-Challenges/assets/169913850/3671390c-09b5-4843-8c10-fa838eb40f98)
*Ref 11: The bruteforce attack in the Splunk database.*

After it was time to install Atomic Red Team on the target machine to run tests and see what Splunk would pick up on.

![Atomic Red Team Folder](https://github.com/LukaB0/CTF-Challenges/assets/169913850/b27f4585-365d-48e0-b18f-efe172f0bac6)
*Ref 12: List of MITRE ATT&CKs availble for use in ART*

I first used T1136.01 which would create a local account on the machine.

![Atomic Red Test T1136 01](https://github.com/LukaB0/CTF-Challenges/assets/169913850/46a27ccb-7d43-4ffc-a966-73fafc18f51d)
*Ref 13: T1136.01 attack to maintain access to the target*

Here it is being picked up by Splunk. The name of the user NEWLOCALUSER can be seen within the report.

![splunk T1136 01 notif NewLocalUser](https://github.com/LukaB0/CTF-Challenges/assets/169913850/2ee017b3-4246-47f7-b355-013985d01909)
*Ref 14: Splunk sees the attack from WinEventLog with the event ID of 4720 which is the ID for a new user account being created.*

I wanted to try another attack so I used T1059.01 which is an attack that abuses Powershell's commands and scripts.

![Atomic Red Test T1059 01](https://github.com/LukaB0/CTF-Challenges/assets/169913850/399ed2fd-449a-48a0-ab42-26b8ec0ffa52)
*Ref 15: T1059.01 being run*

Interestingly Windows Defender picked up and notified the user of this attack directly on the machine. But failed to do so with the T1136 attack.

![Windows Defender Notification](https://github.com/LukaB0/CTF-Challenges/assets/169913850/4ef180e1-a381-4bfd-99bd-190633a3b4cd)
*Ref 16: Windows Defender Notification*

After searching for the keyword "Powershell" in the endpoint index, splunk returned these technique IDs from the attack ran with Atomic Red Team.

![MITRE ATTACK Technique IDs in Splunk](https://github.com/LukaB0/CTF-Challenges/assets/169913850/1daa659e-fe53-4215-8597-cf0285e2f4b4)
*Ref 17: Technique IDs in Splunk*

## Conclusion & Future Thoughts

Overall this was a fun project. I enjoyed going through the steps of setting up the various servers and Active Directory elements. It felt like I gained some valuable skills in how a company adds departments and users to their domain. My favorite part of the project was attacking the machine and seeing what attacks would get picked up by Windows Defender. Thankfully, whatever security exploits that Windows Defender missed Splunk was able to catch and highlight them.

I thoroughly enjoyed doing this project. In the future I will attempt other attack types, perhaps some privilege escalation and credential access attacks with the goal of remaining undetected. 

