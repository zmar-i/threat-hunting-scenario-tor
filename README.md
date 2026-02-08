<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/zmar-i/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "zuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-02-05T18:52:52.2382007Z`. These events began at `2026-02-05T18:26:42.5944586Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "zz-threat-hunt-"
| where InitiatingProcessAccountName == "zuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-02-05T18:26:42.5944586Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1142" height="558" alt="image" src="https://github.com/user-attachments/assets/77cda164-d599-414b-9341-dca2cdfd00d9" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.5.exe". Based on the logs returned, at `2026-02-05T18:28:28.1110325Z`, an employee("zuser") on the "zz-threat-hunt-" device ran the file `tor-browser-windows-x86_64-portable-15.0.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "zz-threat-hunt-"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1156" height="159" alt="image" src="https://github.com/user-attachments/assets/61b1aeb6-a2f1-48d5-85ad-d8af5ea9a47e" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "zuser" actually opened the TOR browser. There was evidence that they did open it at `2026-02-05T18:29:08.9038998Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "zz-threat-hunt-"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```
<img width="1134" height="455" alt="image" src="https://github.com/user-attachments/assets/d815c88e-d0bb-4ebd-a5ed-f7ce4fd98a18" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-02-05T18:30:10.3271224Z`, an employee on the "zz-threat-hunt-" device successfully established a connection to the remote IP address `170.133.2.81` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\zuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "zz-threat-hunt-"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, RemoteUrl, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1154" height="360" alt="image" src="https://github.com/user-attachments/assets/798af157-88df-4251-b618-ffdaca39cbc5" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-02-05T18:26:42.5944586Z`
- **Event:** The user "zuser" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\zuser\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-02-05T18:28:28.1110325Z`
- **Event:** The user "zuser" executed the file `tor-browser-windows-x86_64-portable-15.0.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.5.exe /S`
- **File Path:** `C:\Users\zuser\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-02-05T18:29:08.9038998Z`
- **Event:** User "zuser" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\zuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-02-05T18:30:10.3271224Z`
- **Event:** A network connection to IP `170.133.2.81` on port `9001` by user "zuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\zuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-02-05T18:30:39.4091305Z` - Connected to `80.108.222.2` on port `9001`.
  - `2026-02-05T18:30:12.793682Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "zuser" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-02-05T18:52:52.2382007Z`
- **Event:** The user "zuser" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\zuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user "zuser" on the "zz-threat-hunt-" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `zz-threat-hunt-` by the user `zuser`. The device was isolated, and the user's direct manager was notified.

---
