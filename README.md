# Forensic Analysis of WannaCry Ransomware Attack  
![GitHub](https://img.shields.io/badge/Language-LaTeX-blue) ![GitHub](https://img.shields.io/badge/Tools-Autopsy%2C%20Volatility%2C%20FTK%20Imager-orange)  

## 📝 Project Overview  
This project conducts a **forensic analysis** of the WannaCry ransomware attack, focusing on disk and memory forensics to identify Indicators of Compromise (IoCs) and malware behavior. The analysis was performed in an isolated VMware environment using tools like Autopsy and Volatility.  

## 🔍 Key Features  
- **Isolated Environment**: Configured VMware networks (`vmnet0`, `vmnet1`, `vmnet8`) for secure testing.  
- **Disk Forensics**: Identified `WannaDecryptor.exe` and encrypted files using Autopsy.  
- **Memory Analysis**: Tracked malicious processes (e.g., `or4qtckT.exe`) with Volatility.  
- **VirusTotal Integration**: Validated findings against 72 security vendors.  

## 🛠️ Tools Used  
- **VMware Workstation**: Host-only and NAT network setup.  
- **FTK Imager**: Disk and memory image acquisition.  
- **Autopsy**: File system analysis.  
- **Volatility**: Memory forensics.  
- **VirusTotal/pestudio**: Malware detection and scoring.  

## 📋 Key Findings  
- **Malware Traces**: Detected `WannaDecryptor.exe` in disk images.  
- **Suspicious Processes**: Identified self-modifying sections and Trojan signatures.  
- **Vendor Flags**: 24/72 vendors flagged the sample as malicious (e.g., `Trojan.GenericKD.76211654`).  

## 👥 Contributors  
This project was developed by:  

- **[Shameer Awais](https://github.com/ShameerAwais)**  
- **[Rooshan Riaz](https://github.com/rooshanriaz)**  
- **[Yasir Khan](https://github.com/Yasirkhan26)**  
- **[Naqi Raza](https://github.com/naqirraza99)**  
