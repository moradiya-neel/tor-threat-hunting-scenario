# Threat Hunting Scenario-based Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/moradiya-neel/tor-threat-hunting-scenario/blob/main/docs/threat-hunting-scenario-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machine (Microsoft Azure)
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

Searched the `DeviceFileEvents` table for any file containing the string "tor" and discovered that the user `nmr` downloaded a Tor installer. This was followed by multiple Tor-related files being copied to the desktop, likely as part of the installation process. Additionally, a file named `tor-shopping-list.txt` was created on the desktop at `2026-01-03T14:44:19.4373787Z` and modified a few minutes later. These events began at `2026-01-03T14:26:52.2624898Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "vm-windows"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "nmr"
| where Timestamp >= datetime(2026-01-03T14:26:52.2624898Z)
| project Timestamp, Account = InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp
```
<img width="1200" alt="Screenshot 2026-01-03 at 12 46 20 PM" src="https://github.com/user-attachments/assets/b8cf4bf5-ea63-4353-9d8d-fac2333b84ae" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the `DeviceProcessEvents` table for any `ProcessCommandLine` containing the executable filename `tor-browser-windows-x86_64-portable-15.0.3.exe` from the above results. Based on the logs, on January 3, 2026 at 9:29 AM, the user account `nmr` executed the Tor Browser installer (`tor-browser-windows-x86_64-portable-15.0.3.exe`) from the Downloads folder. The `/S` flag indicates a silent installation, meaning the software was installed without displaying any user prompts or windows.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "vm-windows"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.3.exe"
| project Timestamp, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1200" alt="Screenshot 2026-01-03 at 1 00 39 PM" src="https://github.com/user-attachments/assets/1b9a9bae-3e71-4b72-9d7e-2daad21beeee" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table for any indication that the user `nmr` opened the Tor Browser. Evidence confirms the browser was launched at `2026-01-03T14:29:43.7227096Z`. Several subsequent instances of `firefox.exe` (Tor Browser) and `tor.exe` were spawned afterwards, indicating active usage.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "vm-windows"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1200" alt="Screenshot 2026-01-03 at 1 10 22 PM" src="https://github.com/user-attachments/assets/a7635a4d-40fd-41f9-ba75-a97c2ed4ed0d" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the `DeviceNetworkEvents` table for any indication that the Tor Browser established connections using known Tor ports. On January 3, 2026 at 9:30 AM, approximately one minute after installation, `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`, successfully established a connection to an external IP address (185.231.102.74) on port 9001 — a known Tor network relay port. The connection was initiated from the user's workstation, confirming that Tor Browser was not only installed but actively used to route traffic through the Tor anonymization network. Additional connections were observed to other external IPs over port 443. This activity indicates the user may have been attempting to bypass network security controls, hide browsing activity, or access restricted content.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "vm-windows"
| order by Timestamp desc
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9150", "9040", "9051", "9050", "443", "80")
| where InitiatingProcessFileName in ("firefox.exe", "tor.exe")
| project Timestamp, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1200" alt="Screenshot 2026-01-03 at 1 16 27 PM" src="https://github.com/user-attachments/assets/eabbb4ab-f7dc-4852-b652-17e7701ce90c" />

---

## Chronological Event Timeline 

### 1. File Download - Tor Installer
- **Timestamp:** `2026-01-03T14:26:52.2624898Z`
- **Event:** The user `nmr` downloaded a file named `tor-browser-windows-x86_64-portable-15.0.3.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\nmr\Downloads\tor-browser-windows-x86_64-portable-15.0.3.exe`

### 2. Process Execution - Tor Browser Installation
- **Timestamp:** `2026-01-03T14:29:06Z`
- **Event:** The user `nmr` executed the file `tor-browser-windows-x86_64-portable-15.0.3.exe` in silent mode, initiating a background installation of the Tor Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.3.exe /S`
- **File Path:** `C:\Users\nmr\Downloads\tor-browser-windows-x86_64-portable-15.0.3.exe`

### 3. Process Execution - Tor Browser Launch
- **Timestamp:** `2026-01-03T14:29:43.7227096Z`
- **Event:** The user `nmr` opened the Tor Browser. Subsequent processes associated with Tor Browser, such as `firefox.exe` and `tor.exe`, were spawned, indicating the browser launched successfully.
- **Action:** Process creation of Tor Browser-related executables detected.
- **File Path:** `C:\Users\nmr\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - Tor Network
- **Timestamp:** `2026-01-03T14:30:19Z`
- **Event:** A network connection to IP `185.231.102.74` on port `9001` was established by `tor.exe` under the user `nmr`, confirming Tor network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\nmr\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - Tor Browser Activity
- **Timestamps:**
  - `2026-01-03T14:30:15Z` — Connected to `31.133.0.210` on port `443`
  - `2026-01-03T14:30:18Z` — Connected to `147.135.65.26` on port `443`
  - `2026-01-03T14:30:30Z` — Local connection to `127.0.0.1` on port `9150`
- **Event:** Additional Tor network connections were established, indicating ongoing activity by user `nmr` through the Tor Browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - Tor Shopping List
- **Timestamp:** `2026-01-03T14:44:19.4373787Z`
- **Event:** The user `nmr` created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their Tor Browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\nmr\Desktop\tor-shopping-list.txt`
- **Modified:** `2026-01-03T14:51:19Z`

---

## Summary

On January 3, 2026, the user `nmr` on device `vm-windows` downloaded and silently installed Tor Browser using the `/S` flag to avoid detection. Within minutes, `tor.exe` connected to multiple Tor relay nodes on ports 443 and 9001, establishing an anonymous browsing session. Approximately 14 minutes later, the user created a file named `tor-shopping-list.txt` on the desktop, which was modified shortly after - suggesting potential intent to purchase items through dark web marketplaces.

This activity represents a policy violation and potential insider threat. The silent installation, use of anonymization tools, and creation of a "shopping list" file indicate deliberate attempts to bypass network security controls and potentially engage in illicit activity.

---

## Response Taken

Tor Browser usage was confirmed on endpoint `vm-windows` by the user `nmr`. The device was immediately isolated and the user's direct manager was notified for further action.

---

