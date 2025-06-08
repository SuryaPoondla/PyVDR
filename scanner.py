import rich
import packaging
import jinja2
import json
import requests
import nvdlib
# import osv #getting errors, using requests as workaround to query osv
import re
import pip_audit
import safety #To rank the vulnerabilities
import bandit #To rank the vulnerabilities
import subprocess


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
    # print("AAAAEntered query_nvd")
    try:
        # Search CVEs by package/version (keyword search)
        # cves = nvdlib.searchCVE(keyword=f"{package_name} {version}", limit=8) #Fix the format/syntax
        cves = nvdlib.searchCVE(keywordSearch=f"{package_name}", limit=8) #Working
        results = []
        for cve in cves:
            # print(cve)
            severity = "UNKNOWN"
            if hasattr(cve, "v31score") and cve.v31score:
                severity = cve.v31score
            elif hasattr(cve, "v2score") and cve.v2score:
                severity = cve.v2score
            # check if version is mentioned in description
            version_mentioned = version in cve.descriptions[0].value if cve.descriptions else False
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
    """Search OSV for vulnerabilities related to a package and refine missing details."""
    
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}

    try:
        response = requests.post(url, json=payload)
        data = response.json()
        results = []
        
        if "vulns" in data:
            for vuln in data["vulns"]:
                severity = "UNKNOWN"
                
                # Extract severity from CVSS vector if available
                if "severity" in vuln and vuln["severity"]:
                    severity_info = vuln["severity"]
                    if isinstance(severity_info, list):
                        severity = next((s["score"] for s in severity_info if "score" in s), "UNKNOWN")
                
                # Ensure affected package name is correct
                affected_package = vuln.get("package_name", package_name)
                
                # Normalize affected versions
                affected_versions = vuln.get("affected_versions", [version])
                
                results.append({
                    "id": vuln["id"],
                    "severity": severity,
                    "affected_package": affected_package,
                    "affected_versions": affected_versions,
                    "references": vuln.get("references", []),
                    "description": vuln.get("details", "OSV description unavailable")
                })
            
        return results
    except Exception as e:
        print(f"Error querying OSV for {package_name}=={version}: {e}")
        return []

def query_osv_v3(package_name, version):
    """
    Query OSV for vulnerabilities for a given PyPI package and version.
    Returns a list of vulnerability dictionaries.
    """
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": version
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        results = []

        if "vulns" in data:
            for vuln in data["vulns"]:
                # Parse severity
                severity = "UNKNOWN"
                if "severity" in vuln:
                    for s in vuln["severity"]:
                        if s.get("type") == "CVSS_V3" and "score" in s:
                            severity = s["score"]
                            break

                # Parse affected versions
                affected_versions = []
                for affected in vuln.get("affected", []):
                    ranges = affected.get("ranges", [])
                    for r in ranges:
                        if r.get("type") == "ECOSYSTEM":
                            for event in r.get("events", []):
                                if "introduced" in event or "fixed" in event:
                                    affected_versions.append(event)

                results.append({
                    "id": vuln.get("id", "N/A"),
                    "severity": severity,
                    "affected_package": package_name,
                    "affected_versions": affected_versions,
                    "references": vuln.get("references", []),
                    "description": vuln.get("details", "OSV description unavailable")
                })

        return results

    except requests.RequestException as e:
        print(f"[OSV] Network error for {package_name}=={version}: {e}")
        return []
    except ValueError as e:
        print(f"[OSV] JSON decode error for {package_name}=={version}: {e}")
        return []
    except Exception as e:
        print(f"[OSV] Unexpected error for {package_name}=={version}: {e}")
        return []


def query_osv_original(package_name, version):    
    # print("BBBEntered query_osv")
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
            
            # for i in range(len(results)):
            #     print(f"OSV Result[{i}]: {results[i]}")
        return results
    except Exception as e:
        print(f"Error querying OSV: {e}")
        return []


def pip_audit_queries():
    # Audit dependencies from a requirements file
    results = pip_audit.audit(requirement="requirements.txt")
    for result in results:
        print(f"Package: {result.dep.name}, Version: {result.dep.version}, Vulnerabilities: {result.vulns}")

def safety_query():
    with open("requirements.txt") as req_file:
        requirements = req_file.read().splitlines()
    output = subprocess.run(["safety", "check", "-r", "requirements.txt"], capture_output=True, text=True)
    print(output.stdout)

# Some error in unifying, spoondla6 to do
def unify_vulnerability_data(nvd_data, osv_data):
    unified_vulnerabilities = []

    for vuln in nvd_data:
        unified_vulnerabilities.append({
            "id": vuln["cve_id"],
            "severity": vuln["severity"],
            # "cvss_vector": vuln.get("cvss_vector", "N/A"),
            "affected_package": vuln["package"],
            "affected_versions": vuln["version"],
            "references": vuln.get("references", []),
            "description": vuln.get("description", "NVD description unavailable")
        })

    for vuln in osv_data:
        unified_vulnerabilities.append({
            "id": vuln["id"],
            "severity": vuln["severity"],
            # "cvss_vector": vuln.get("severity", {}).get("score", "N/A"),
            "affected_package": vuln.get("package_name", "Unknown"),
            "affected_versions": vuln.get("affected_versions", []),
            "references": vuln.get("references", []),
            "description": vuln.get("details", "OSV description unavailable")
        })

    return unified_vulnerabilities

def main():
    print("Hello World")
    parsed_requirements = parse_requirements(file_path)
    nvd_vulnerabilities = []
    osv_vulnerabilities = []
    
    # print("osv query example")
    # Example
    # query_osv("numpy", "1.21.0")
    
    print("parsed the requirements.txt")
    print(parsed_requirements)
    print("AAAA2")
    for package, version in parsed_requirements.items():
        print(f"{package}: {version}")
        print("Querying the nvd database")
        nvd_vulnerabilities_raw = query_nvd(package, version)
        
        for vuln in nvd_vulnerabilities_raw:
            nvd_vulnerabilities.append({
                "package": package,
                "version": version,
                "cve_id": vuln["cve_id"],
                "severity": vuln["severity"],
                "source": vuln["source"]
            })
            
        # osv_vulnerabilities_raw = query_osv(package, version) #Working, fix syntax
        osv_vulnerabilities_raw = query_osv_v3(package, version)
        for vuln in osv_vulnerabilities_raw:
            osv_vulnerabilities.append(vuln);
    
    print(f"printing the len of NVD, {len(nvd_vulnerabilities)}, len of OSV, {len(osv_vulnerabilities)}")
    
    '''
    print(f"Parsed all requirements, printing the vulnerabilities that are present in NVD, {len(nvd_vulnerabilities)}")
    for vuln in nvd_vulnerabilities:
        print(vuln)
    '''
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

    '''
    print(f"Parsed all requirements, printing the vulnerabilities that are present in OSV, {len(osv_vulnerabilities)}")
    for vuln in osv_vulnerabilities:
        print(vuln)
    '''
    # OSV Result[0]: {'id': 'GHSA-fpfv-jqm9-f5jm', 'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'}], 'details': 'Incomplete string comparison in the numpy.core component in NumPy1.9.x, which allows attackers to fail the APIs via constructing specific string objects.'}
        
    
    print(f"Printing the nvd_vulnerabilities, its len is {len(nvd_vulnerabilities)}")
    for vuln in nvd_vulnerabilities:
        print(vuln)
    
    print(f"Printing the osv_vulnerabilities, its len is {len(osv_vulnerabilities)}")
    for vuln in osv_vulnerabilities:
        print(vuln)
        
    unified_vulnerabilities = unify_vulnerability_data(nvd_vulnerabilities, osv_vulnerabilities)
    print(f"Printing the unified_vulnerabilities, its len is {len(unified_vulnerabilities)}")
    # for vuln in unified_vulnerabilities:
    #     print(vuln)
    
    # Query the pip_audit, this will be used to evaluate the ranking system
    # pip_audit_queries() #To fix the format
    
    # Query safety, this will be used to evaluate the ranking system
    # safety_query() #Works

if __name__ == "__main__":
    main()
