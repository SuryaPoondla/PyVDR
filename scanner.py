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


def query_osv_backup_v2(package_name, version):
    """Search OSV for vulnerabilities related to a package and summarize essential details."""
    
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}

    try:
        response = requests.post(url, json=payload)
        data = response.json()
        
        vuln_ids = []
        severities = []
        max_severity = "UNKNOWN"
        exploitability_scores = []

        if "vulns" in data:
            for vuln in data["vulns"]:
                vuln_ids.append(vuln["id"])
                
                severity = "UNKNOWN"
                exploitability = None
                
                
                if "severity" in vuln and vuln["severity"]:
                    severity_info = vuln["severity"]
                    if isinstance(severity_info, list):
                        severity_scores = [s["score"] for s in severity_info if "score" in s]
                        max_severity = max(severity_scores, default="UNKNOWN")  # Get highest score
                        severities = severity_scores
                
                # Extract exploitability score if available
                if "cvss" in vuln and vuln["cvss"]:
                    cvss_info = vuln["cvss"]
                    if isinstance(cvss_info, list):
                        exploitability = next((cvss.get("exploitabilityScore") for cvss in cvss_info if "exploitabilityScore" in cvss), None)
                        if exploitability:
                            exploitability_scores.append(exploitability)
                
                if severity != "UNKNOWN" and (max_severity == "UNKNOWN" or severity > max_severity):
                    max_severity = severity
                
            
        return {
            "vuln_ids": vuln_ids,
            "max_severity": max_severity,
            "severities": severities, #Aux info
            "exploitability_scores": exploitability_scores
        }
    except Exception as e:
        print(f"Error querying OSV for {package_name}=={version}: {e}")
        return {}

def get_package_download_count(package_name):
    url = f"https://pypistats.org/api/packages/{package_name}/recent"
    try:
        response = requests.get(url)
        data = response.json()
        return data["data"]["last_month"]
    except Exception as e:
        return f"Download lookup failed: {e}"

def query_osv(package_name, version):
    """Search OSV for vulnerabilities related to a package and summarize essential details."""
    
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}

    try:
        response = requests.post(url, json=payload)
        data = response.json()
        
        vuln_ids = []
        cve_ids = []
        severities = []
        max_severity = "UNKNOWN"
        package_download_count = 0
        exploitability_scores = []

        if "vulns" in data:
            for vuln in data["vulns"]:
                vuln_ids.append(vuln.get("id", "UNKNOWN"))

                # Extract CVEs from aliases
                aliases = vuln.get("aliases", [])
                cve_list = [a for a in aliases if a.startswith("CVE-")]
                cve_ids.extend(cve_list)

                # Extract severity scores
                severity_info = vuln.get("severity", [])
                severity_scores = [s["score"] for s in severity_info if "score" in s]
                if severity_scores:
                    severities.extend(severity_scores)
                    max_severity = max(severities, default=max_severity)

                # Extract exploitability scores (if any)
                for cvss in vuln.get("cvss", []):
                    if "exploitabilityScore" in cvss:
                        exploitability_scores.append(cvss["exploitabilityScore"])
        
        package_download_count = get_package_download_count(package_name)
        
        return {
            "vuln_ids": vuln_ids,
            "cve_ids": cve_ids,
            "max_severity": max_severity,
            "severities": severities,
            "package_download_count": package_download_count,
            "exploitability_scores": exploitability_scores
        }

    except Exception as e:
        print(f"Error querying OSV for {package_name}=={version}: {e}")
        return {}


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
    osv_vulnerabilities = {}
    
    print("parsed the requirements.txt")
    print(parsed_requirements)
    print("AAAA2")
    for package, version in parsed_requirements.items():
        print(f"{package}: {version}")
        print("Querying the nvd database")
        # spoondla6 temporary comment
        # nvd_vulnerabilities_raw = query_nvd(package, version)
        
        # for vuln in nvd_vulnerabilities_raw:
        #     nvd_vulnerabilities.append({
        #         "package": package,
        #         "version": version,
        #         "cve_id": vuln["cve_id"],
        #         "severity": vuln["severity"],
        #         "source": vuln["source"]
        #     })
            
        osv_vulnerabilities[f"{package}=={version}"] = query_osv(package, version)
        
    
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
    
    print(f"Printing the keys and contents of osv_vulnerabilities, its len is {len(osv_vulnerabilities)}")
    for package_version, vuln_data in osv_vulnerabilities.items():
        print(f"{package_version}: {vuln_data}")  # Prints each package version along with its details
        print("\n")
        
    # unified_vulnerabilities = unify_vulnerability_data(nvd_vulnerabilities, osv_vulnerabilities) #Fix synatx issues
    # print(f"Printing the unified_vulnerabilities, its len is {len(unified_vulnerabilities)}")
    # for vuln in unified_vulnerabilities:
    #     print(vuln)
    
    # Query the pip_audit, this will be used to evaluate the ranking system
    # pip_audit_queries() #To fix the format
    
    # Query safety, this will be used to evaluate the ranking system
    # safety_query() #Works

if __name__ == "__main__":
    main()
