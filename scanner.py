import rich
import packaging
import jinja2
import json
import requests
import nvdlib
# import osv #getting errors
import re
import pip_audit

# def parse_requirements(filename="requirements.txt"):
#     deps = []
#     with open(filename, "r") as file:
#         for line in file:
#             line = line.strip()
#             if not line or line.startswith("#"):
#                 continue
#             match = re.match(r"([a-zA-Z0-9_\-]+)==([^\s]+)", line)
#             if match:
#                 pkg, ver = match.groups()
#                 deps.append((pkg, ver))
#     return deps

file_path = "requirements.txt"
def parse_requirements(file_path):
    requirements = {}
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith("#"):  # Ignore comments and empty lines
                match = re.match(r'([^=<>]+)([=<>]=)?(.+)?', line)
                if match:
                    package = match.group(1).strip()
                    version = match.group(3).strip() if match.group(3) else "Latest"
                    requirements[package] = version
    return requirements

# spoondla6
def query_nvd(package_name, version):
    """Query the NVD database using nvdlib."""
    try:
        # Search CVEs by package/version (keyword search)
        # cves = nvdlib.searchCVE(keyword=f"{package_name} {version}", limit=8) #Not working
        # cves = nvdlib.searchCVE(keyword=f"{package_name}", limit=8) #Not working
        cves = nvdlib.searchCVE(keywordSearch=f"{package_name}", limit=8)
        results = []
        for cve in cves:
            severity = "UNKNOWN"
            if hasattr(cve, "v31score") and cve.v31score:
                severity = cve.v31score
            elif hasattr(cve, "v2score") and cve.v2score:
                severity = cve.v2score
            results.append({
                "cve_id": cve.id,
                "severity": severity,
                "source": "NVD"
            })
        return results
    except Exception as e:
        print(f"NVD query failed for {package_name}=={version}: {e}")
        return []

def query_osv(package_name, version):
    """Search OSV for vulnerabilities related to a package."""
    # spoondla6 Working
    # Output: osv query example
    # Result[0]: {'id': 'GHSA-fpfv-jqm9-f5jm', 'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'}], 'details': 'Incomplete string comparison in the numpy.core component in NumPy1.9.x, which allows attackers to fail the APIs via constructing specific string objects.'}
    
    url = f"https://api.osv.dev/v1/query"
    payload = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
    try:
        response = requests.post(url, json=payload)
        data = response.json()
        results = []
        if "vulns" in data:
            for vuln in data["vulns"]:
                severity = vuln.get("severity", "UNKNOWN")
                results.append({
                    "id": vuln["id"],
                    "severity": severity,
                    "details": vuln.get("details", "No details available")
                })
            
            for i in range(len(results)):
                print(f"Result[{i}]: {results[i]}")
        return results
    except Exception as e:
        print(f"Error querying OSV: {e}")
        return []


def pip_audit_queries():
    # Audit dependencies from a requirements file
    results = pip_audit.audit(requirement="requirements.txt")
    for result in results:
        print(f"Package: {result.dep.name}, Version: {result.dep.version}, Vulnerabilities: {result.vulns}")

def main():
    print("Hello World")
    parsed_requirements = parse_requirements(file_path)
    vulnerabilities = []
    
    print("osv query example")
    # Example
    query_osv("numpy", "1.21.0")

    
    print("parsed the requirements.txt")
    print(parsed_requirements)
    print("AAAA2")
    for package, version in parsed_requirements.items():
        print(f"{package}: {version}")
        print("Querying the nvd database")
        nvd_vulnerabilities = query_nvd(package, version)
        
        for vuln in nvd_vulnerabilities:
            vulnerabilities.append({
                "package": package,
                "version": version,
                "cve_id": vuln["cve_id"],
                "severity": vuln["severity"],
                "source": vuln["source"]
            })
    
    print("Parsed all requirements, printing the vulnearbilities")
    for vuln in vulnerabilities:
        print(vuln)
    # {'package': 'requests', 'version': '2.19.1', 'cve_id': 'CVE-1999-0168', 'severity': 7.5, 'source': 'NVD'}
    # {'package': 'requests', 'version': '2.19.1', 'cve_id': 'CVE-1999-0107', 'severity': 5.0, 'source': 'NVD'}
    # {'package': 'requests', 'version': '2.19.1', 'cve_id': 'CVE-1999-0551', 'severity': 4.6, 'source': 'NVD'}
    # {'package': 'requests', 'version': '2.19.1', 'cve_id': 'CVE-1999-0797', 'severity': 2.6, 'source': 'NVD'}
    # {'package': 'requests', 'version': '2.19.1', 'cve_id': 'CVE-1999-1412', 'severity': 5.0, 'source': 'NVD'}
    # {'package': 'requests', 'version': '2.19.1', 'cve_id': 'CVE-1999-0929', 'severity': 5.0, 'source': 'NVD'}
    # {'package': 'requests', 'version': '2.19.1', 'cve_id': 'CVE-1999-1537', 'severity': 5.0, 'source': 'NVD'}
    # {'package': 'requests', 'version': '2.19.1', 'cve_id': 'CVE-1999-0867', 'severity': 5.0, 'source': 'NVD'}
    # {'package': 'flask', 'version': '0.12.2', 'cve_id': 'CVE-2008-3687', 'severity': 6.8, 'source': 'NVD'}
    # {'package': 'flask', 'version': '0.12.2', 'cve_id': 'CVE-2014-1891', 'severity': 5.2, 'source': 'NVD'}
    # {'package': 'flask', 'version': '0.12.2', 'cve_id': 'CVE-2014-1893', 'severity': 5.2, 'source': 'NVD'}

    
        

if __name__ == "__main__":
    main()
