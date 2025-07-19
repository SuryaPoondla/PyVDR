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
from cvss import CVSS2, CVSS3, CVSS4
import yaml

file_path = "requirements.txt"
def parse_requirements(file_path):
    requirements = {}
    if file_path.endswith(('.yml', '.yaml')):
        with open(file_path, 'r') as file:
            data = yaml.safe_load(file)
            # Expecting YAML structure like: dependencies: [package1==version, package2]
            for dep in data.get('dependencies', []):
                match = re.match(r'([^=<>]+)([=<>]=)?(.+)?', dep)
                if match:
                    package = match.group(1).strip()
                    version = match.group(3).strip() if match.group(3) else "Latest"
                    requirements[package] = version
    
    elif file_path.endswith('.txt'):                
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


def query_nvd_v1(package_name, version):
    """Query the NVD database using nvdlib."""
    
    try:
        # Search CVEs by package/version (keyword search)
        cves = nvdlib.searchCVE(keywordSearch=f"{package_name}", limit=8)
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
        #     return {
        #     "vuln_ids": vuln_ids,
        #     "cve_ids": cve_ids,
        #     "max_severity": max_severity,
        #     "severities": severities,
        #     "package_download_count": package_download_count,
        #     "exploitability_scores": exploitability_scores
        # }
        return results
    except Exception as e:
        print(f"NVD query failed for {package_name}=={version}: {e}")
        return []


def query_nvd(package_name, version):
    """Query the NVD database using nvdlib and extract structured vulnerability data."""
    try:
        cves = nvdlib.searchCVE(keywordSearch=package_name, limit=8)
        
        vuln_ids = "UNKNOWN" #This is used to see the the correct version of the corresponding package
        cve_ids = []
        severities = []
        exploitability_scores = []
        max_severity = "UNKNOWN"
        package_download_count = "UNKNOWN"

        for cve in cves:
            # print(cve)
            
            # Check severity
            severity = "UNKNOWN"
            if hasattr(cve, "v31score") and cve.v31score:
                severity = cve.v31score
            elif hasattr(cve, "v2score") and cve.v2score:
                severity = cve.v2score

            severities.append(severity)

            # Attempt to get CVE ID and exploitability score
            cve_ids.append(cve.id)
            if hasattr(cve, "exploitabilityScore"):
                exploitability_scores.append(cve.exploitabilityScore)
            else:
                exploitability_scores.append("UNKNOWN")

            # Check if version is mentioned in the CVE description
            version_mentioned = (
                version in cve.descriptions[0].value if cve.descriptions and cve.descriptions[0].value and False else False
            )

            # print(f"version_mentioned: {version_mentioned}")

            if version_mentioned and severity != "UNKNOWN":
                if max_severity == "UNKNOWN" or severity > max_severity:
                    max_severity = severity

        return {
            "vuln_ids": vuln_ids,
            "cve_ids": cve_ids,
            "max_severity": max_severity,
            "severities": severities,
            "package_download_count": package_download_count,
            "exploitability_scores": exploitability_scores,
            "is_curr_version": version_mentioned
        }

    except Exception as e:
        print(f"NVD query failed for {package_name}=={version}: {e}")
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


def clean_raw_data_and_default_rank(packages):
    # Data may contain duplicate data, clear it.
    # Note: In some cases, distinct vuln_ids can point to the same cve_ids, this is also cleaned here (like the duplicate cve_id will be removed).
    for pkg_data in packages.values():
        pkg_data['cve_ids'] = sorted(set(pkg_data['cve_ids']))
        pkg_data['vuln_ids'] = sorted(set(pkg_data['vuln_ids']))
    sorted_pkgs = dict(sorted(packages.items(), key=lambda item: len(set(item[1]['cve_ids'])), reverse=True))
    return sorted_pkgs


def parse_cvss_score(vector):
    try:
        if vector.startswith("CVSS:4.0"):
            return CVSS4(vector).base_score
        elif vector.startswith("CVSS:3"):
            return CVSS3(vector).scores()[0]
        else:
            return CVSS2(vector).scores()[0]
    except:
        return 0

def compute_exploitability(cvss_vector):
    try:
        vector = cvss_vector.upper()
        if vector.startswith("CVSS:4.0"):
            # From CVSS v4.0 specification (approximate based on spec)
            metrics = {k: v for k, v in [item.split(':') for item in vector.split('/')[1:]]}
            AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}.get(metrics.get('AV'), 0)
            AC = {'L': 0.77, 'H': 0.44}.get(metrics.get('AC'), 0)
            AT = {'N': 1.0, 'P': 0.62}.get(metrics.get('AT'), 1.0)
            PR = {'N': 0.85, 'L': 0.62, 'H': 0.27}.get(metrics.get('PR'), 0)
            UI = {'N': 0.85, 'P': 0.62}.get(metrics.get('UI'), 0)
            exploitability = 8.22 * AV * AC * AT * PR * UI
            return round(exploitability, 2)

        elif vector.startswith("CVSS:3"):
            metrics = {k: v for k, v in [item.split(':') for item in vector.split('/')[1:]]}
            S = metrics.get('S', 'U')
            AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}.get(metrics.get('AV'), 0)
            AC = {'L': 0.77, 'H': 0.44}.get(metrics.get('AC'), 0)
            UI = {'N': 0.85, 'R': 0.62}.get(metrics.get('UI'), 0)
            PR_raw = metrics.get('PR', 'N')
            if PR_raw == 'N':
                PR = 0.85
            elif PR_raw == 'L':
                PR = 0.62 if S == 'U' else 0.68
            elif PR_raw == 'H':
                PR = 0.27 if S == 'U' else 0.5
            else:
                PR = 0
            exploitability = 8.22 * AV * AC * PR * UI
            return round(exploitability, 2)

        else:  # CVSS2 v2.0
            # approx for v2 exploitability metrics
            metrics = {k: v for k, v in [item.split(':') for item in vector.split('/')[1:]]}
            AV = {'N': 1.0, 'A': 0.646, 'L': 0.395}.get(metrics.get('AV'), 0)
            AC = {'L': 0.71, 'M': 0.61, 'H': 0.35}.get(metrics.get('AC'), 0)
            AU = {'N': 0.704, 'S': 0.56, 'M': 0.45}.get(metrics.get('AU'), 0)
            exploitability = 20 * AV * AC * AU
            return round(exploitability, 2)

    except Exception as e:
        print(f"Error in exploitability calc: {e}")
        return 0


def rank_by_cvss_severities(packages):
    rankings = []
    for name, data in packages.items():
        cve_ids = set(data.get('cve_ids', []))
        severities = data.get('severities', [])

        scores = [parse_cvss_score(v) for v in severities]
        max_score = max(scores) if scores else 0
        avg_score = sum(scores) / len(scores) if scores else 0

        # Weighted ranking formula (adjust weights as needed)
        risk_score = (avg_score * 0.2) + (max_score * 0.7) + (len(cve_ids) * 0.1)

        rankings.append((name, round(risk_score, 2), len(cve_ids), round(avg_score, 2), round(max_score, 2)))

    return sorted(rankings, key=lambda x: x[1], reverse=True)


def rank_by_cvss_severity_and_download_count(packages):
    rankings = []
    for name, data in packages.items():
        cve_ids = set(data.get('cve_ids', []))
        severities = data.get('severities', [])

        scores = [parse_cvss_score(v) for v in severities]
        max_score = max(scores) if scores else 0
        avg_score = sum(scores) / len(scores) if scores else 0
        # downloads = data.get('package_download_count', 0) / 1_000_000  # Normalize to millions
        downloads = data.get('package_download_count', 0) / 1_000_000  # Normalize to millions
        exploit_scores = [compute_exploitability(v) for v in data.get('severities', [])]
        avg_exploit = sum(exploit_scores) / len(exploit_scores) if exploit_scores else 0
        max_exploit = max(exploit_scores) if exploit_scores else 0
        # print(f"downloads={downloads}, avg_exploit={avg_exploit}, max_exploit={max_exploit}")

        # Assigning more weight for real-world scenarios
        risk_score = (
            avg_score * 0.2 +
            max_score * 0.5 +
            len(cve_ids) * 0.1 +
            downloads * 0.2
        )

        rankings.append((name, round(risk_score, 2), len(cve_ids), round(avg_score, 2), round(max_score, 2), round(downloads, 1), round(avg_exploit, 2), round(max_exploit, 2)))

    return sorted(rankings, key=lambda x: x[1], reverse=True)

def label_cvss_score(score):
    if score == 0:
        return "None"
    elif score < 4.0:
        return "Low"
    elif score < 7.0:
        return "Medium"
    elif score < 9.0:
        return "High"
    else:
        return "Critical"


def unify_vulnerability_data(nvd_vulnerabilities, osv_vulnerabilities):
    """
    Combines vulnerabilities from OSV and NVD sources.
    Note: osv api also gets the data from nvd, so in some cases the data might contain some duplicates and this will be cleaned in clean_raw_data_and_default_rank()
    """
    unified = {}

    for key, osv_data in osv_vulnerabilities.items():
        nvd_data = nvd_vulnerabilities.get(key)
        
        if nvd_data and nvd_data.get("is_curr_version", False):
            pass
          
        unified[key] = osv_data

    return unified


def print_cur_dict(curDict):
    for package_version, vuln_data in curDict.items():
        print(f"{package_version}: {vuln_data}")  # Prints each package version along with its details
        print("\n")

# print ranking engine 1
def print_ranking_engine_cvss(results):
    print(f"{'Package':<20} {'Risk Score':<12} {'Number of CVEs':<16} {'Avg CVSS score':<16} {'Max CVSS score':<16} {'Severity label':<15}")
    print('-' * 100)
    
    for pkg, risk, num_cves, avg_cvss_score, max_cvss_score in results:
        # severity = label_cvss_score(avg_cvss_score)
        severity = label_cvss_score(max_cvss_score)
        print(f"{pkg:<20} {risk:<12.2f} {num_cves:<16} {avg_cvss_score:<16.2f} {max_cvss_score:<16.2f} {severity:<15}")

def print_ranking_engine_csvv_downloads(results):
    print(f"{'Package':<20} {'Risk Score':<12} {'num of CVEs':<16} {'Avg CVSS':<12} {'Max CVSS':<12} {'Downloads (M)':<16} {'Avg Exploit':<14} {'Max Exploit':<14}")
    print('-' * 110)

    for pkg, risk, cves, avg_cvss, max_cvss, downloads, avg_expl, max_expl in results:
        print(f"{pkg:<20} {risk:<12.2f} {cves:<16} {avg_cvss:<12.2f} {max_cvss:<12.2f} {downloads:<16.1f} {avg_expl:<14.2f} {max_expl:<14.2f}")

def process_and_save_ranking_engine1(ranking_engine1):
    ranking_engine_1_dicts = [
    {
        "package": pkg,
        "risk_score": score,
        "cvss_count": cve_count,
        "avg_cvss": avg_cvss,
        "max_cvss": max_cvss
    }
    for pkg, score, cve_count, avg_cvss, max_cvss in ranking_engine1
    ]
    
    with open("ranking_engine_1.json", "w") as f1:
        json.dump(ranking_engine_1_dicts, f1, indent=4)


def process_and_save_ranking_engine2(ranking_engine2):
    
    ranking_engine_2_dicts = [
    {
        "package": pkg,
        "risk_score": score,
        "cvss_count": cve_count,
        "avg_cvss": avg_cvss,
        "max_cvss": max_cvss,
        "downloads": downloads,
        "avg_exploit": avg_exploit,
        "max_exploit": max_exploit
    }
    for pkg, score, cve_count, avg_cvss, max_cvss, downloads, avg_exploit, max_exploit in ranking_engine2
    ]
    
    with open("ranking_engine_2.json", "w") as f2:
        json.dump(ranking_engine_2_dicts, f2, indent=4)

def main():
    parsed_requirements = parse_requirements(file_path)
    nvd_vulnerabilities = {}
    osv_vulnerabilities = {}
    unified_vulnerabilities = {}
    
    print("parsed the requirements.txt")
    print(parsed_requirements)
    print("\n")
    
    for package, version in parsed_requirements.items():
        print(f"{package}: {version}")
        print("Querying the nvd, osv databases")
        nvd_vulnerabilities[f"{package}=={version}"] = query_nvd(package, version)
        osv_vulnerabilities[f"{package}=={version}"] = query_osv(package, version)
        
    
    # print(f"printing the len of NVD, {len(nvd_vulnerabilities)}, len of OSV, {len(osv_vulnerabilities)}")
    
    
    unified_vulnerabilities = unify_vulnerability_data(nvd_vulnerabilities, osv_vulnerabilities)
    # Let's merge all the vulnerabilities into osv_vulnerabilities
    osv_vulnerabilities = unified_vulnerabilities
    # sample output:
    # requests==2.19.1: {'vuln_ids': ['GHSA-9hjg-9r4m-mvj7', 'GHSA-9wx4-h78v-vm56', 'GHSA-j8r2-6x86-q33q', 'GHSA-x84v-xcm2-53pg', 'PYSEC-2018-28', 'PYSEC-2023-74'], 'cve_ids': ['CVE-2024-47081', 'CVE-2024-35195', 'CVE-2023-32681', 'CVE-2018-18074', 'CVE-2018-18074', 'CVE-2023-32681'], 'max_severity': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 'severities': ['CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N', 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'], 'package_download_count': 735854162, 'exploitability_scores': []}
    print("\n")
    
    # This is staging data, the data in osv_vulnerabilities inside the CVE_ids contains duplicates
    print(f"Printing the contents of the detection engine")
    print_cur_dict(osv_vulnerabilities)
    
    
    # Clean the data from staging state
    osv_vulnerabilities = clean_raw_data_and_default_rank(osv_vulnerabilities)
    # print_cur_dict(osv_vulnerabilities)
    
    
    print(f"Printing the keys and contents of ranking engine 1")
    ranking_engine1 = rank_by_cvss_severities(osv_vulnerabilities)
    print_ranking_engine_cvss(ranking_engine1)
    
    print("\n")
    print(f"Printing the keys and contents of ranking engine 2")
    ranking_engine2 = rank_by_cvss_severity_and_download_count(osv_vulnerabilities)
    # print(ranking_engine2)
    print_ranking_engine_csvv_downloads(ranking_engine2)
    
    print("\nCreating the json formats for ranking engine 1 and ranking engine 2, this will be used in the UI")
    process_and_save_ranking_engine1(ranking_engine1)
    process_and_save_ranking_engine2(ranking_engine2)
    
    
    
    # Both the below will be done outside
    # Query the pip_audit, this will be used to evaluate the detection engine
    # pip_audit_queries()
    
    # Query safety, this will be used to evaluate the ranking system either by below command
    # safety_query()
    # Or by running the safety website (https://platform.safetycli.com/codebases/pyvdr/findings)

if __name__ == "__main__":
    main()
