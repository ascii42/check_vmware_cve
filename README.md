# check_vmware_cve

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-bash-green.svg)](https://www.gnu.org/software/bash/)
[![Monitoring](https://img.shields.io/badge/Monitoring-Icinga%2FNagios-blue.svg)](https://icinga.com/)
[![Version](https://img.shields.io/badge/version-0.0.3-orange.svg)](CHANGELOG.md)

**Enhanced VMware CVE Monitoring Plugin for Icinga/Nagios**

A comprehensive monitoring plugin that automatically tracks VMware vulnerabilities with real-time CVE data fetching, build number verification, and multi-source intelligence.

## 🚀 Features

### **Core Functionality**
- **Auto-detecting VMware Products**: ESXi, vCenter, NSX (not tested yet), vCloud Director (not tested yet), vRealize/Aria (not tested yet)
- **Real-time CVE Database**: Auto-fetches from multiple authoritative sources
- **Precise Build Matching**: Compares actual build numbers with vulnerability data
- **Enterprise Proxy Support**: Full HTTP/HTTPS proxy integration with authentication
- **Multi-source Intelligence**: Broadcom Security, NIST NVD, BSI CERT, Manual entries

### **Advanced Features**
- **SOAP-based Detection**: Accurate product and version identification
- **Enhanced Vulnerability Logic**: Supports complex build range patterns (`< 24785000`, ranges, exact matches)
- **Age-based Severity**: Optional CVE age consideration in risk assessment  
- **Manual CVE Support**: Custom vulnerability tracking for internal issues
- **Comprehensive Logging**: Detailed debug output and operation tracking
- **Performance Data**: Nagios/Icinga compatible metrics output

## 📋 Prerequisites

- `bash` (version 4.0+)
- `curl` (with proxy support)
- `jq` (for JSON processing)
- `bc` (for floating point calculations)
- `timeout` (command timeout utility)
- Network access to VMware hosts and CVE sources
- Valid VMware credentials (root/administrator)

## 🛠 Installation

```bash
# Download the plugin
wget https://raw.githubusercontent.com/yourusername/check_vmware_cve/main/check_vmware_cve.sh

# Make executable
chmod +x check_vmware_cve.sh

# Copy to plugin directory
cp check_vmware_cve.sh /usr/lib/nagios/plugins/

# Initialize CVE database
/usr/lib/nagios/plugins/check_vmware_cve.sh --fetch-only --force-update
```

## 🔧 Configuration

### **Basic Usage**
```bash
# Check ESXi host
./check_vmware_cve.sh -H esxi-host.local -u root -p password

# Check vCenter with product specification
./check_vmware_cve.sh -H vcenter.local -u administrator@vsphere.local -p password -P vcenter

# Verbose debugging
./check_vmware_cve.sh -H esxi-host.local -u root -p password --verbose
```

### **Enterprise Proxy Configuration**
```bash
# Individual proxy settings
./check_vmware_cve.sh -H host -u user -p pass --proxy-host proxy.company.com --proxy-port 8080

# Full proxy URL with authentication
./check_vmware_cve.sh -H host -u user -p pass --proxy-url http://user:pass@proxy.company.com:8080

# System proxy (default behavior)
export HTTP_PROXY=http://proxy.company.com:3128
./check_vmware_cve.sh -H host -u user -p pass
```

### **CVE Source Management**
```bash
# Use only Broadcom sources (recommended for VMware-specific CVEs)
./check_vmware_cve.sh -H host -u user -p pass --only-broadcom

# Disable specific sources
./check_vmware_cve.sh -H host -u user -p pass --disable-nvd --disable-bsi

# Force fresh CVE data fetch
./check_vmware_cve.sh -H host -u user -p pass --force-update
```

## ⚙️ Advanced Options

### **Command Line Parameters**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-H, --hostname` | VMware hostname or IP | Required |
| `-u, --username` | VMware username | Required |
| `-p, --password` | VMware password | Required |
| `-P, --product` | Force product type (esxi\|vcenter\|nsx\|vcloud\|aria) | Auto-detect |
| `-w, --warning` | Warning CVSS threshold | 7.0 |
| `-c, --critical` | Critical CVSS threshold | 9.0 |
| `-d, --use-days` | Include CVE age in severity | false |
| `-W, --warn-days` | Warning age threshold (days) | 90 |
| `-C, --crit-days` | Critical age threshold (days) | 30 |
| `-t, --timeout` | Connection timeout (seconds) | 30 |
| `-v, --verbose` | Enable debug output | false |
| `-f, --force-update` | Force CVE database refresh | false |

### **CVE Database Management**
```bash
# Update only CVE cache (no host checking)
./check_vmware_cve.sh --fetch-only --force-update

# Update build mappings from VMware release notes
./check_vmware_cve.sh --fetch-only --update-build-mappings --force-update

# Use existing cache only (no network fetching)
./check_vmware_cve.sh -H host -u user -p pass --disable-fetching
```

## 🕐 Automated Updates (Cron Setup)

### **Recommended Cron Configuration**
```bash
# Edit crontab
crontab -e

# Add CVE database update (runs every 6 hours)
0 */6 * * * /usr/lib/nagios/plugins/check_vmware_cve.sh --fetch-only --update-build-mappings --force-update >/dev/null 2>&1

# Or daily at 2 AM
0 2 * * * /usr/lib/nagios/plugins/check_vmware_cve.sh --fetch-only --update-build-mappings --force-update
```

### **Systemd Timer (Alternative)**
```bash
# Create timer unit
cat > /etc/systemd/system/vmware-cve-update.service << 'EOF'
[Unit]
Description=VMware CVE Database Update
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/lib/nagios/plugins/check_vmware_cve.sh --fetch-only --update-build-mappings --force-update
User=nagios
Group=nagios
EOF

cat > /etc/systemd/system/vmware-cve-update.timer << 'EOF'
[Unit]
Description=Update VMware CVE Database every 6 hours
Requires=vmware-cve-update.service

[Timer]
OnCalendar=*-*-* 00/6:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start
systemctl enable vmware-cve-update.timer
systemctl start vmware-cve-update.timer
```

## 📊 Output Examples

### **Clean System**
```
[OK] - VMware ESXi 8.0.3 (build-24859861) on esxi-host.local has no known active CVEs |critical_cves=0;0;1;0 warning_cves=0;0;1;0 total_cves=0;;;0
```

### **Vulnerable System**
```
[CRITICAL] - VMware ESXi 8.0.3 (build-22348816) on esxi-host.local has 2 critical CVE(s) (CVSS≥9.0): CVE-2025-22224 (CVSS: 9.3, EXPLOITED IN WILD) [VMSA-2025-0004] [Fixed in: ESXi 8.0 U3d]; CVE-2025-41236 (CVSS: 9.3, EXPLOITED IN WILD) [VMSA-2025-0013] [Fixed in: ESXi 8.0 U3f] |critical_cves=2;0;1;0 warning_cves=0;0;1;0 total_cves=2;;;0
```

### **With Age Consideration**
```bash
# Enable age-based severity
./check_vmware_cve.sh -H host -u user -p pass -d -W 60 -C 30

[WARNING] - VMware vCenter Server 8.0.3 (build-24322831) on vcenter.local has 1 warning CVE(s) (CVSS≥7.0 or ≥60d old): CVE-2024-38812 (CVSS: 9.8, 128d old) [VMSA-2024-0019] [Fixed in: vCenter 8.0 U3b] |critical_cves=0;0;1;0 warning_cves=1;0;1;0 total_cves=1;;;0
```

## 🗂 File Structure

The plugin creates and maintains several database files:

```
/tmp/vmware_cve_cache/
├── combined_cve_cache.json          # Main cache file
└── cve_sources/
    ├── broadcom_cve_cache.json      # Broadcom Security Advisories
    ├── nvd_cve_cache.json           # NIST NVD data
    ├── bsi_cve_cache.json           # BSI CERT data  
    ├── manual_cves.json             # Custom CVE entries
    ├── build_mappings.json          # VMware build number database
    ├── real_cve_database.json       # Core vulnerability data
    └── fetch.log                    # Operation log
```

## 🛠 Custom CVE Management

### **Adding Manual CVEs**
```bash
# Edit manual CVE file
nano /tmp/vmware_cve_cache/cve_sources/manual_cves.json
```

### **Example Manual CVE Entry**
```json
{
  "source": "Manual Entries",
  "last_updated": "2025-08-24T10:00:00Z",
  "cves": [
    {
      "cve_id": "CVE-INTERNAL-2025",
      "affected_products": ["esxi"],
      "cvss_score": 8.5,
      "severity": "High",
      "published_date": "2025-08-01",
      "description": "Internal security vulnerability",
      "workaround": "Apply internal security controls",
      "patch_available": true,
      "source": "Internal Security Team",
      "affected_versions": [
        {
          "version": "8.0",
          "vulnerable_builds": ["< 24900000"],
          "fixed_builds": ["24900000"],
          "fixed_in_release": "ESXi 8.0 U3h"
        }
      ],
      "auto_fetched": false,
      "exploited_in_wild": false
    }
  ]
}
```

## 🔍 Troubleshooting

### **Common Issues**

1. **Connection Timeouts**
   ```bash
   # Increase timeout
   ./check_vmware_cve.sh -H host -u user -p pass -t 60
   ```

2. **Proxy Issues**
   ```bash
   # Test proxy connectivity
   curl --proxy http://proxy.company.com:8080 https://www.google.com
   
   # Debug proxy settings
   ./check_vmware_cve.sh --fetch-only --verbose
   ```

3. **Permission Issues**
   ```bash
   # Check cache directory permissions
   ls -la /tmp/vmware_cve_cache/
   
   # Fix permissions
   chmod 755 /tmp/vmware_cve_cache/
   chmod 644 /tmp/vmware_cve_cache/cve_sources/*
   ```

4. **CVE Database Issues**
   ```bash
   # Force complete refresh
   rm -rf /tmp/vmware_cve_cache/
   ./check_vmware_cve.sh --fetch-only --force-update
   ```

### **Debug Mode**
```bash
# Full debug output
./check_vmware_cve.sh -H host -u user -p pass --verbose

# Check CVE database status
./check_vmware_cve.sh --fetch-only --verbose
```

## 🔐 Security Considerations

- **Credential Management**: Use secure credential storage (encrypted files, vault systems)
- **Network Security**: Ensure proxy settings align with security policies  
- **File Permissions**: Restrict access to cache files containing vulnerability data
- **Regular Updates**: Maintain current CVE databases for accurate threat assessment

## 📈 Integration Examples

### **Icinga2 Configuration**
```
object CheckCommand "vmware_cve" {
  command = [ PluginDir + "/check_vmware_cve.sh" ]
  arguments = {
    "-H" = "$vmware_hostname$"
    "-u" = "$vmware_username$"
    "-p" = "$vmware_password$"
    "-P" = "$vmware_product$"
    "-w" = "$cve_warning_cvss$"
    "-c" = "$cve_critical_cvss$"
    "-t" = "$vmware_timeout$"
  }
}

object Service "vmware-cve" {
  host_name = "esxi-host"
  check_command = "vmware_cve"
  vars.vmware_hostname = "esxi-host.local"
  vars.vmware_username = "root"
  vars.vmware_password = "password"
  vars.vmware_product = "esxi"
  vars.cve_warning_cvss = 7.0
  vars.cve_critical_cvss = 9.0
  vars.vmware_timeout = 30
  check_interval = 6h
}
```

### **Nagios Configuration**
```
define command{
    command_name    check_vmware_cve
    command_line    $USER1$/check_vmware_cve.sh -H $HOSTADDRESS$ -u $ARG1$ -p $ARG2$ -P $ARG3$ -w $ARG4$ -c $ARG5$
}

define service{
    service_description     VMware CVE Check
    host_name              esxi-host
    check_command          check_vmware_cve!root!password!esxi!7.0!9.0
    check_interval         360
}
```

## 📋 Real CVE Database

The plugin includes current VMware vulnerabilities:

| CVE ID | Product | CVSS | Status | Description |
|--------|---------|------|--------|-------------|
| CVE-2025-22224 | ESXi | 9.3 | **Exploited** | TOCTOU privilege escalation |
| CVE-2025-41236 | ESXi | 9.3 | **Exploited** | VMXNET3 integer overflow |
| CVE-2025-41237 | ESXi | 9.3 | **Exploited** | VMCI integer underflow |
| CVE-2024-38812 | vCenter | 9.8 | Critical | DCERPC heap overflow |
| CVE-2025-41225 | vCenter | 8.8 | High | Authenticated command execution |
| CVE-2025-41239 | ESXi | 7.1 | High | Information disclosure |

## 📝 Changelog

### Version 0.0.3 (Latest)
- ✅ Enhanced proxy support with authentication
- ✅ Real-time CVE data fetching from multiple sources
- ✅ Precise build number vulnerability matching
- ✅ Auto-detection of VMware products via SOAP
- ✅ Comprehensive logging and debug capabilities
- ✅ Manual CVE management system
- ✅ Age-based severity assessment
- ✅ Performance data output for monitoring integration

### Version 0.0.2
- ➕ Added basic proxy support
- 🔧 Improved error handling

### Version 0.0.1
- 🎯 Initial alpha release
- ✅ Basic CVE checking functionality

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💬 Support

For support, please:
1. Check the troubleshooting section above
2. Review existing GitHub issues
3. Create a new issue with:
   - Your environment details
   - Command used and full output
   - Debug output (`--verbose` flag)
   - VMware product versions

## 👨‍💻 Author

**Felix Longardt**
- Email: monitoring@longardt.com
- GitHub: [@ascii42](https://github.com/ascii42)

## 🙏 Acknowledgments

- Broadcom/VMware for security advisory transparency
- NIST NVD for comprehensive vulnerability database
- BSI CERT for German cybersecurity intelligence
- The monitoring community for feedback and suggestions
- Contributors who have helped improve this plugin

## ⚠️ Disclaimer

This plugin is not officially supported by VMware/Broadcom. Use in production environments should be thoroughly tested. The accuracy of vulnerability assessment depends on the availability and correctness of public CVE databases.
