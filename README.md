# Cloud SOC Detection & Adversary Emulation Lab

An enterprise-grade Security Operations Center (SOC) lab deployed in Microsoft Azure. This project demonstrates end-to-end telemetry engineering, log forwarding, adversary simulation mapped to the MITRE ATT&CK framework, and detection engineering using Splunk Enterprise and Microsoft Sysmon.

---

## Architecture Overview

```text
                      +-------------------------------------------------+
                      |              Microsoft Azure Cloud              |
                      |                 Region: East Asia               |
                      +-------------------------------------------------+
                                       |
        +------------------------------+------------------------------+
        |                                                             |
        ▼                                                             ▼
+------------------------------------+              +------------------------------------+
|        Target Windows Node         |              |          Splunk SIEM Node          |
|  VM: vm-windows-target (Win 2022)  |              |   VM: vm-splunk-server (Ubuntu)    |
|                                    |              |                                    |
| - Microsoft Sysmon (v4.91)         |              | - Splunk Enterprise 9.3.0          |
|   (SwiftOnSecurity Config)         |              | - Index: "endpoint"                |
| - Windows Security Auditing (4688) |              | - TCP Port 9997 (Receiver)         |
| - Invoke-AtomicRedTeam             |              | - TCP Port 8000 (Splunk Web UI)    |
| - Splunk Universal Forwarder       |              |                                    |
+------------------------------------+              +------------------------------------+
        |                                                             ▲
        |                                                             |
        +----------------- Encrypted TCP Port 9997 -------------------+
                          (Sysmon, Security, System Logs)

Technical Highlights & Key CompetenciesCloud Infrastructure & Network Hardening: Provisioned and managed Linux and Windows virtual machines in Microsoft Azure, configuring Network Security Group (NSG) firewall rules to restrict administrative exposure.Telemetry Pipeline Engineering: Configured the Splunk Universal Forwarder on Windows Server 2022 to collect, parse, and ship high-fidelity telemetry from Windows Event Logs (Security, System) and Microsoft-Windows-Sysmon/Operational into a dedicated index.Systems Administration & Privilege Troubleshooting: Diagnosed and resolved Windows virtual account permission restrictions (NT SERVICE\SplunkForwarder) preventing Sysmon log ingestion by reconfiguring the service security context to LocalSystem.Adversary Emulation (MITRE ATT&CK): Leveraged the Red Canary Invoke-AtomicRedTeam framework to execute real-world adversary techniques across execution and persistence tactics.Detection Engineering (SPL): Developed, tested, and validated Search Processing Language (SPL) detection queries with spath XML extraction to surface unauthorized process executions and registry persistence.Operational Monitoring: Designed a multi-panel visual SOC dashboard and alert rules for automated threat notification.Environment SpecificationsComponentOperating SystemRoleKey ToolingSIEM ServerUbuntu Server 22.04 LTS (x64)Log Collection, Indexing, AnalyticsSplunk Enterprise 9.3.0Target EndpointWindows Server 2022 Datacenter (x64)Telemetry Source & Simulation TargetSysmon 64-bit, Splunk Universal ForwarderEmulation EngineWindows PowerShell 5.1Adversary Testing FrameworkInvoke-AtomicRedTeamPhase 1: SIEM Server Deployment (Splunk Enterprise)1.1 Ingestion ConfigurationSplunk Enterprise was installed on Ubuntu Linux 22.04 LTS and configured to listen for forwarder traffic on TCP port 9997:

# Enable automatic startup on boot
sudo /opt/splunk/bin/splunk enable boot-start

# Enable ingestion listener on TCP port 9997
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:<password>

1.2 Dedicated Index Creation
To prevent data contamination with internal Splunk logs (_internal), a dedicated index named endpoint was provisioned via Splunk Web (Settings > Indexes > New Index).

Phase 2: Endpoint Telemetry & Forwarder Hardening
2.1 Sysmon Deployment
Sysmon was deployed alongside the community-standard SwiftOnSecurity configuration file to capture process creations, network connections, file modifications, and registry changes:

New-Item -ItemType Directory -Path "C:\Tools" -Force
Set-Location "C:\Tools"

# Download Sysmon & SwiftOnSecurity Config
Invoke-WebRequest -Uri "[https://download.sysinternals.com/files/Sysmon.zip](https://download.sysinternals.com/files/Sysmon.zip)" -OutFile "Sysmon.zip"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force
Invoke-WebRequest -Uri "[https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml](https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml)" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"

# Install Sysmon Service
& "C:\Tools\Sysmon\Sysmon64.exe" -accepteula -i "C:\Tools\Sysmon\sysmonconfig.xml"

2.2 Inputs Configuration (inputs.conf)The Universal Forwarder was configured via C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf:Ini, TOML[WinEventLog://Security]
disabled = 0
index = endpoint
renderXml = true

[WinEventLog://System]
disabled = 0
index = endpoint
renderXml = true

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = endpoint
renderXml = true
current_only = 0
checkpointInterval = 5
2.3 Engineering Challenge: Service Account Permission ResolutionIssue: Following forwarder deployment, Windows Security (Event ID 4688) and System logs were successfully indexed, but Microsoft-Windows-Sysmon/Operational yielded zero events.Root Cause: In Windows Server, Splunk Universal Forwarder runs as virtual service account NT SERVICE\SplunkForwarder. This identity possesses rights for core OS logs but lacks Discretionary Access Control List (DACL) read permissions on custom modern channels like Sysmon.Resolution: Reconfigured the service principal to LocalSystem and granted explicit membership in the local Event Log Readers security group:PowerShellsc.exe config SplunkForwarder obj= LocalSystem
Add-LocalGroupMember -Group "Event Log Readers" -Member "NT SERVICE\SplunkForwarder" -ErrorAction SilentlyContinue
Restart-Service SplunkForwarder
Result: Immediately ingested over 1,200 backlogged Sysmon events across 10 distinct event categories.Phase 3: Adversary Emulation (MITRE ATT&CK)Testing was conducted using Red Canary's Invoke-AtomicRedTeam.Emulation MatrixMITRE IDTechnique NameTacticDescriptionArtifacts GeneratedT1059.001Command and Scripting Interpreter: PowerShellExecutionExecution of unquoted / encoded PowerShell commands and download cradlesSysmon Event ID 1, Windows Event ID 4688T1547.001Boot or Logon Autostart: Registry Run KeysPersistenceAdversary persistence established by adding an execution binary to HKCU\...\CurrentVersion\RunSysmon Event ID 12/13, Windows Event ID 4657/4688Execution CommandsPowerShell# Install Execution Framework
Set-ExecutionPolicy Bypass -Scope Process -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (New-Object Net.WebClient).DownloadString('[https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1](https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1)')
Install-AtomicRedTeam -getAtomics -Force

# Execute Persistence Emulation (T1547.001)
Invoke-AtomicTest T1547.001 -TestNumbers 1

# Execute Cleanup
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
Phase 4: Detection Engineering & Validated SPL Queries1. Ingestion Health & Sysmon Event BreakdownSplunk SPLindex="endpoint" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| spath
| stats count by "Event.System.EventID"
| rename "Event.System.EventID" as EventID, count as TotalEvents
| sort - TotalEvents
Validated Telemetry Breakdown:Event ID 1: Process Creation (636 events)Event ID 11: File Creation (417 events)Event ID 13: Registry Value Modification (175 events)Event ID 2 & 3: Time Manipulation & Network Connections (40 events)Event ID 12: Registry Object Added/Deleted (4 events)Event ID 8: CreateRemoteThread Process Injection (3 events)2. Detection Rule: Registry Run Key Persistence (T1547.001)Splunk SPLindex="endpoint" (sourcetype="*Sysmon*" OR sourcetype="*Security*") ("CurrentVersion\Run" OR "CurrentVersion\RunOnce")
| spath
| eval EventCode=coalesce('Event.System.EventID', EventCode)
| eval TargetObject=coalesce('Event.EventData.TargetObject', 'Event.EventData.Data')
| table _time, host, EventCode, TargetObject
3. Detection Rule: Suspicious PowerShell Process SpawnSplunk SPLindex="endpoint" sourcetype="*Sysmon*"
| spath
| search "Event.System.EventID"=1
| search "Event.EventData.Data"="*powershell.exe*" ("Event.EventData.Data"="*-enc*" OR "Event.EventData.Data"="*-ExecutionPolicy Bypass*" OR "Event.EventData.Data"="*IEX*")
| table _time, host, "Event.EventData.Data"
Phase 5: Visual Splunk Dashboard (Dashboard XML)To visualize incoming endpoint telemetry, create a dashboard in Splunk Web (Dashboards > Create New Dashboard > Source XML):XML<dashboard version="1.1" theme="dark">
  <label>Endpoint Telemetry &amp; Adversary Detection</label>
  <row>
    <panel>
      <single>
        <title>Total Security &amp; Sysmon Events</title>
        <search>
          <query>index="endpoint" | stats count</query>
          <earliest>0</earliest>
          <latest></latest>
        </search>
        <option name="colorMode">block</option>
        <option name="rangeColors">["0x53a051","0x006d9c"]</option>
      </single>
    </panel>
    <panel>
      <chart>
        <title>Ingestion Volume by Sourcetype</title>
        <search>
          <query>index="endpoint" | stats count by sourcetype</query>
          <earliest>0</earliest>
          <latest></latest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Sysmon Event ID Breakdown</title>
        <search>
          <query>index="endpoint" sourcetype="*Sysmon*" | spath | stats count by "Event.System.EventID"</query>
          <earliest>0</earliest>
          <latest></latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.axisTitleX.text">Count</option>
        <option name="charting.axisTitleY.text">Event ID</option>
      </chart>
    </panel>
    <panel>
      <table>
        <title>Adversary Persistence Detections (T1547.001)</title>
        <search>
          <query>index="endpoint" "CurrentVersion\Run" | spath | table _time, host, "Event.System.EventID", "Event.EventData.Data"</query>
          <earliest>0</earliest>
          <latest></latest>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
Phase 6: Automated Incident AlertingSplunk automated alerting triggers immediately when high-fidelity adversary indicators are detected:In Splunk Search, enter the detection query:Splunk SPLindex="endpoint" ("CurrentVersion\Run" OR "T1547") ("Event.System.EventID"=12 OR "Event.System.EventID"=13 OR EventID=4688)
Click Save As > Alert.Settings:Title: ALERT - MITRE T1547.001 Registry Persistence DetectedAlert Type: Real-time (or Scheduled checking every 5 minutes).Trigger condition: Number of Results > 0.Trigger Actions:Webhook: Post alert payload directly to a Slack / Microsoft Teams / Discord incident response channel.Email: Dispatch formatted email to the SOC queue containing timestamp, affected host, and command details.Lessons Learned & Production ConsiderationsTelemetry Cost vs. Fidelity: Ingesting every Sysmon event in production can overwhelm license volume. Using tuning configurations like SwiftOnSecurity or Floris Munnik’s schema balances noise reduction with adversarial visibility.Service Account Hardening: Running forwarders under LocalSystem grants full access, but in regulated enterprise environments, custom Group Managed Service Accounts (gMSA) with targeted SDDL log permissions represent least-privilege best practice.Continuous Validation: Static detection rules degrade as adversaries modify tradecraft. Continuous execution of unit-level atomic tests validates detection rule health over time.
