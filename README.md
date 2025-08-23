# check_vmware_cve
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-bash-green.svg)](https://www.gnu.org/software/bash/)
[![Monitoring](https://img.shields.io/badge/Monitoring-Icinga%2FNagios-blue.svg)](https://icinga.com/)
[![Version](https://img.shields.io/badge/version-0.0.1-orange.svg)](CHANGELOG.md)

check_vmware_cve is an icinga plugin to gather CVEs and compare it with the used products

**! ! ! BEWARE - THIS IS AN ALPHA ! ! !**

##  Features

- Fetches installed VMware products, versions, and components.
- Queries a CVE database (local or online) for matching vulnerabilities.
- Reports status: OK, WARNING or CRITICAL, depending on severity and matches.
- Optional JSON or performance data output for integration or automation.

##  Prerequisites

- `bash` (version 4.0+)
- `curl`
- `jq` (for JSON handling)
- Access to a CVE database or endpoint
- VMware environment accessible for inventory querying

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please:
1. Check the troubleshooting section above
2. Review existing GitHub issues
3. Create a new issue with detailed information about your environment and the problem

## 👨‍💻 Author

**Felix Longardt**
- Email: monitoring@longardt.com
- GitHub: [@ascii42](https://github.com/ascii42)

## Acknowledgments

- VMware for the Horizon API documentation
- The monitoring community for feedback and suggestions
- Contributors who have helped improve this plugin

---

**Note**: This plugin is not officially supported by VMware.
