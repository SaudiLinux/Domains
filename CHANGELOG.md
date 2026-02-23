# Changelog

## [2.0.0] - Enhanced Edition - 2026-02-23

### Added
- ✨ **POC (Proof of Concept) Generation**: Every vulnerability now includes ready-to-run Python code
- ✨ **Direct Vulnerability URLs**: Display the exact vulnerable URL for each finding
- ✨ **12 Vulnerability Types**: Comprehensive scanning for major security issues
- ✨ **Enhanced HTML Reports**: Beautiful, color-coded reports with full POC code
- ✨ **Remediation Steps**: Detailed fix recommendations for each vulnerability
- ✨ **Real-time Detection**: Instant display when vulnerabilities are found
- ✨ **Multiple Report Formats**: HTML, Markdown, and Text reports

### Improved
- 🔧 **Vulnerability Scanner Module**: Complete rewrite with POC support
- 🔧 **Report Generator**: Enhanced with color-coded severity levels
- 🔧 **Performance**: Optimized scanning threads and timeout handling
- 🔧 **User Experience**: Better progress indicators and colored output

### Security Scans Added
1. SQL Injection with error-based detection
2. XSS (Reflected & Stored) with payload reflection testing
3. LFI/RFI with file content verification
4. Open Redirect with redirect chain analysis
5. SSRF with internal network detection
6. XXE with entity expansion testing
7. CSRF with token absence detection
8. Security Headers analysis (5+ critical headers)
9. Information Disclosure (sensitive files)
10. Backup Files exposure detection
11. CORS Misconfiguration with credential testing
12. Clickjacking with X-Frame-Options check

### Documentation
- 📚 Comprehensive README with examples
- 📚 Vulnerabilities Guide with POC samples
- 📚 Installation instructions
- 📚 Usage examples in Arabic

## [1.0.0] - Initial Release

### Features
- Basic domain information gathering
- Subdomain enumeration
- URL discovery
- Admin panel finder
- Attack surface mapping
- Basic vulnerability scanning
- Simple text reports
