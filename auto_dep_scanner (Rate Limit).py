# === auto_dep_scanner.py ===
# Real-time unified vulnerability scanner for Maven, Gradle, and Python projects

import os
import re
import time
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict
from dataclasses import dataclass
from abc import ABC, abstractmethod
import requests
from collections import Counter

@dataclass
class Dependency:
    group_id: str
    artifact_id: str
    version: str
    scope_or_config: str = "compile"
    build_system: str = "maven"

@dataclass
class Vulnerability:
    cve_id: str
    description: str
    severity: str
    score: float
    published_date: str
    source: str

class IVulnerabilitySource(ABC):
    @abstractmethod
    def search(self, dependency: Dependency) -> List[Vulnerability]:
        pass
class NVDScanner(IVulnerabilitySource):
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
        self.headers = {"apiKey": api_key} if api_key else {}
        self.rate_limit_delay = 0.6 if not api_key else 1.2

    def search(self, dependency: Dependency) -> List[Vulnerability]:
        results = []
        terms = [f"{dependency.group_id} {dependency.artifact_id}", dependency.artifact_id] if dependency.build_system != "python" else [dependency.artifact_id]
        seen = set()
        for term in terms:
            time.sleep(self.rate_limit_delay)
            try:
                res = requests.get(self.base_url, params={"keywordSearch": term, "resultsPerPage": 20}, headers=self.headers)
                res.raise_for_status()
                data = res.json()
                for vuln_data in data.get("vulnerabilities", []):
                    cve = vuln_data["cve"]
                    cve_id = cve.get("id", "unknown")
                    desc = cve.get("descriptions", [{}])[0].get("value", "")
                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
                    severity = metrics[0]["cvssData"].get("baseSeverity", "Unknown") if metrics else "Unknown"
                    score = metrics[0]["cvssData"].get("baseScore", 0.0) if metrics else 0.0
                    published = cve.get("published", "unknown")
                    if cve_id not in seen:
                        seen.add(cve_id)
                        results.append(Vulnerability(cve_id, desc, severity, score, published, "NVD"))
            except:
                continue
        return results[:5]

class OSSIndexScanner(IVulnerabilitySource):
    def __init__(self, username: Optional[str] = None, token: Optional[str] = None):
        self.api_url = "https://ossindex.sonatype.org/api/v3/component-report"
        self.auth = (username, token) if username and token else None

    def to_purl(self, dep: Dependency) -> Optional[str]:
        if dep.build_system == "python":
            return f"pkg:pypi/{dep.artifact_id}@{dep.version}"
        elif dep.build_system == "maven":
            return f"pkg:maven/{dep.group_id}/{dep.artifact_id}@{dep.version}"
        elif dep.build_system == "gradle":
            return f"pkg:gradle/{dep.group_id}/{dep.artifact_id}@{dep.version}"
        return None

    def search(self, dependency: Dependency) -> List[Vulnerability]:
        purl = self.to_purl(dependency)
        if not purl:
            return []
        try:
            headers = {"Content-Type": "application/vnd.ossindex.component-report-request.v1+json"}
            auth = requests.auth.HTTPBasicAuth(*self.auth) if self.auth else None
            res = requests.post(self.api_url, json={"coordinates": [purl]}, headers=headers, auth=auth)
            res.raise_for_status()
            data = res.json()
            results = []
            for item in data:
                for vuln in item.get("vulnerabilities", []):
                    results.append(Vulnerability(
                        cve_id=vuln.get("id", "unknown"),
                        description=vuln.get("title", "No description"),
                        severity=vuln.get("cvssScore", 0.0),
                        score=vuln.get("cvssScore", 0.0),
                        published_date=vuln.get("published", "unknown"),
                        source="OSS Index"
                    ))
            return results
        except:
            return []

class GitHubAdvisoryScanner(IVulnerabilitySource):
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.api_url = "https://api.github.com/graphql"

    def search(self, dependency: Dependency) -> List[Vulnerability]:
        if not self.token:
            return []

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        query = """
        query($package: String!) {
          securityVulnerabilities(package: $package, first: 10) {
            nodes {
              severity
              advisory {
                identifiers {
                  type
                  value
                }
                summary
                publishedAt
              }
            }
          }
        }
        """

        variables = {"package": dependency.artifact_id}

        try:
            res = requests.post(self.api_url, headers=headers, json={"query": query, "variables": variables})
            res.raise_for_status()
            data = res.json()

            results = []
            nodes = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
            for node in nodes:
                advisory = node.get("advisory", {})
                identifiers = advisory.get("identifiers", [])
                cve = next((i['value'] for i in identifiers if i['type'] == 'CVE'), 'unknown')
                summary = advisory.get("summary", "No description")
                published = advisory.get("publishedAt", "unknown")
                severity = node.get("severity", "Unknown")
                results.append(Vulnerability(cve, summary, severity, 0.0, published, "GitHub"))
            return results
        except:
            return []

class SnykScanner(IVulnerabilitySource):
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.base_url = "https://api.snyk.io/v1/test"

    def search(self, dependency: Dependency) -> List[Vulnerability]:
        if not self.token:
            return []

        eco_map = {"python": "pip", "maven": "maven", "gradle": "gradle"}
        eco = eco_map.get(dependency.build_system)
        if not eco:
            return []

        package = f"{dependency.group_id}/{dependency.artifact_id}" if dependency.build_system in ["maven", "gradle"] else dependency.artifact_id
        url = f"{self.base_url}/{eco}/{package}/{dependency.version}?version=1.0.0"

        headers = {
            "Authorization": f"token {self.token}",
            "Content-Type": "application/json",
        }

        try:
            res = requests.get(url, headers=headers)
            if res.status_code != 200:
                return []
            data = res.json()

            vulns = []
            for issue in data.get("vulnerabilities", []):
                vulns.append(Vulnerability(
                    cve_id=issue.get("identifiers", {}).get("CVE", ["unknown"])[0],
                    description=issue.get("title", "No description"),
                    severity=issue.get("severity", "Unknown"),
                    score=issue.get("cvssScore", 0.0),
                    published_date=issue.get("publicationTime", "unknown"),
                    source="Snyk"
                ))
            return vulns
        except:
            return []

class UnifiedMultiSourceScanner:
    def __init__(self, sources: List[IVulnerabilitySource], global_delay: float = 0.5):
        self.sources = sources
        self.global_delay = global_delay  # seconds between source requests

    def scan_dependency(self, dep: Dependency) -> List[Vulnerability]:
        all_vulns = []
        for src in self.sources:
            time.sleep(self.global_delay)
            all_vulns.extend(src.search(dep))
        return all_vulns

def discover_dependencies(project_dir: str) -> List[Dependency]:
    dependencies = []
    pom = os.path.join(project_dir, "pom.xml")
    if os.path.exists(pom):
        try:
            tree = ET.parse(pom)
            root = tree.getroot()
            ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
            for dep in root.findall(".//m:dependency", ns):
                group_id_el = dep.find("m:groupId", ns)
                artifact_id_el = dep.find("m:artifactId", ns)
                version_el = dep.find("m:version", ns)

                group_id = group_id_el.text if group_id_el is not None else ""
                artifact_id = artifact_id_el.text if artifact_id_el is not None else ""
                version = version_el.text if version_el is not None else "latest"

                dependencies.append(Dependency(group_id, artifact_id, version, build_system="maven"))
        except Exception as e:
            print(f"[!] Failed to parse pom.xml: {e}")

    gradle = os.path.join(project_dir, "build.gradle")
    if os.path.exists(gradle):
        try:
            with open(gradle) as f:
                for line in f:
                    match = re.search(r"['\"]([\w\.-]+):([\w\.-]+):([\d\.\-]+)['\"]", line)
                    if match:
                        group, artifact, version = match.groups()
                        dependencies.append(Dependency(group, artifact, version, build_system="gradle"))
        except Exception as e:
            print(f"[!] Failed to parse build.gradle: {e}")

    requirements = os.path.join(project_dir, "requirements.txt")
    if os.path.exists(requirements):
        try:
            with open(requirements) as f:
                for line in f:
                    if "==" in line:
                        pkg, ver = line.strip().split("==")
                        dependencies.append(Dependency("", pkg.strip(), ver.strip(), build_system="python"))
        except Exception as e:
            print(f"[!] Failed to parse requirements.txt: {e}")

    return dependencies

def summarize_results(dependencies: List[Dependency], all_vulnerabilities: Dict[str, List[Vulnerability]]):
    print("\n📊 DEPENDENCY SUMMARY:")
    by_type = Counter([d.build_system for d in dependencies])
    print(f"📄 Maven: {by_type.get('maven', 0)}")
    print(f"🔧 Gradle: {by_type.get('gradle', 0)}")
    print(f"🐍 Python: {by_type.get('python', 0)}")
    print(f"📦 Total: {len(dependencies)}")

    all_vulns = [v for vulns in all_vulnerabilities.values() for v in vulns]
    severity_counter = Counter([str(v.severity).lower() for v in all_vulns])
    print("\n🚨 VULNERABILITY SUMMARY:")
    print(f"🔴 Critical: {severity_counter.get('critical', 0)}")
    print(f"🟠 High: {severity_counter.get('high', 0)}")
    print(f"🟡 Medium: {severity_counter.get('medium', 0)}")
    print(f"🟢 Low: {severity_counter.get('low', 0)}")
    print(f"⚪ Unknown: {severity_counter.get('unknown', 0)}")
    print(f"\n📋 Total Vulnerabilities: {len(all_vulns)}")

    print("\n🔍 DETAILED VULNERABILITIES:")
    for dep_key, vulns in all_vulnerabilities.items():
        if vulns:
            print(f"\n📦 {dep_key}:")
            for v in vulns:
                print(f"  - [{v.source}] {v.cve_id} | {v.severity} ({v.score}) - {v.description[:80]}")

if __name__ == "__main__":
    path = input("Enter path to project directory: ").strip()
    if not os.path.isdir(path):
        print("[!] Invalid path.")
        exit(1)

    github_token = None  # Optional GitHub token
    snyk_token = None    # Optional Snyk token

    scanners = [
        NVDScanner(),
        OSSIndexScanner(),
        GitHubAdvisoryScanner(token=github_token),
        SnykScanner(token=snyk_token)
    ]

    scanner = UnifiedMultiSourceScanner(scanners, global_delay=1.0)
    discovered = discover_dependencies(path)
    if not discovered:
        print("[!] No dependencies found.")
        exit(0)

    all_vulns: Dict[str, List[Vulnerability]] = {}
    for dep in discovered:
        key = f"{dep.build_system}:{dep.artifact_id}:{dep.version}"
        print(f"\n🔍 Scanning {key}...")
        vulns = scanner.scan_dependency(dep)
        all_vulns[key] = vulns

    summarize_results(discovered, all_vulns)
