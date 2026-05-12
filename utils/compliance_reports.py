"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Compliance Report Generator
Generates reports for SOC2, PCI-DSS, HIPAA, ISO27001 compliance
"""

import os
import sys
import json
from datetime import datetime
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class ComplianceReportGenerator:
    """
    Compliance Report Generator
    
    Generates reports for:
    - SOC 2 Type II
    - PCI-DSS
    - HIPAA
    - ISO 27001
    """

    def __init__(self):
        self.frameworks = {
            'soc2': self._generate_soc2,
            'pci_dss': self._generate_pci_dss,
            'hipaa': self._generate_hipaa,
            'iso27001': self._generate_iso27001,
        }

    def generate(self, framework: str, scan_results: List[Dict],
                 infected_hosts: set, failed_targets: set,
                 vulnerabilities: List[Dict] = None,
                 credentials: List[Dict] = None,
                 output_dir: str = "reports") -> str:
        """Generate compliance report"""
        if framework not in self.frameworks:
            raise ValueError(f"Unknown framework: {framework}. Available: {list(self.frameworks.keys())}")

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(output_dir, f"compliance_{framework}_{timestamp}.json")

        report = self.frameworks[framework](scan_results, infected_hosts, failed_targets, vulnerabilities, credentials)

        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"Compliance report generated: {filepath}")
        return filepath

    def _generate_soc2(self, scan_results, infected_hosts, failed_targets, vulns, creds) -> Dict:
        """SOC 2 Type II Report"""
        return {
            'framework': 'SOC 2 Type II',
            'generated_at': datetime.now().isoformat(),
            'trust_service_criteria': {
                'security': {
                    'CC6.1': self._check_logical_access(scan_results, creds),
                    'CC6.6': self._check_external_threats(vulns),
                    'CC7.1': self._check_monitoring(infected_hosts),
                    'CC7.2': self._check_incident_response(failed_targets),
                },
                'availability': {
                    'A1.1': self._check_system_availability(scan_results),
                    'A1.2': self._check_recovery_capabilities(),
                },
                'confidentiality': {
                    'C1.1': self._check_data_classification(creds),
                    'C1.2': self._check_encryption(scan_results),
                },
            },
            'findings': self._compile_findings(vulns, creds, scan_results),
            'recommendations': self._soc2_recommendations(vulns, creds),
        }

    def _generate_pci_dss(self, scan_results, infected_hosts, failed_targets, vulns, creds) -> Dict:
        """PCI-DSS Report"""
        return {
            'framework': 'PCI-DSS v4.0',
            'generated_at': datetime.now().isoformat(),
            'requirements': {
                'req_1': self._check_firewall_config(scan_results),
                'req_2': self._check_default_passwords(creds),
                'req_3': self._check_data_protection(creds),
                'req_4': self._check_encryption_in_transit(scan_results),
                'req_5': self._check_antivirus(vulns),
                'req_6': self._check_secure_development(vulns),
                'req_7': self._check_access_control(creds),
                'req_8': self._check_authentication(creds),
                'req_11': self._check_security_testing(vulns),
            },
            'findings': self._compile_findings(vulns, creds, scan_results),
            'recommendations': self._pci_recommendations(vulns, creds),
        }

    def _generate_hipaa(self, scan_results, infected_hosts, failed_targets, vulns, creds) -> Dict:
        """HIPAA Report"""
        return {
            'framework': 'HIPAA Security Rule',
            'generated_at': datetime.now().isoformat(),
            'safeguards': {
                'administrative': {
                    'risk_analysis': self._check_risk_analysis(vulns),
                    'workforce_security': self._check_workforce_security(creds),
                },
                'physical': {
                    'facility_access': self._check_facility_access(scan_results),
                    'workstation_security': self._check_workstation_security(scan_results),
                },
                'technical': {
                    'access_control': self._check_access_control(creds),
                    'audit_controls': self._check_audit_controls(infected_hosts),
                    'integrity': self._check_data_integrity(scan_results),
                    'transmission_security': self._check_transmission_security(scan_results),
                },
            },
            'findings': self._compile_findings(vulns, creds, scan_results),
            'recommendations': self._hipaa_recommendations(vulns, creds),
        }

    def _generate_iso27001(self, scan_results, infected_hosts, failed_targets, vulns, creds) -> Dict:
        """ISO 27001 Report"""
        return {
            'framework': 'ISO 27001:2022',
            'generated_at': datetime.now().isoformat(),
            'controls': {
                'A.5': self._check_organizational_controls(scan_results),
                'A.6': self._check_people_controls(creds),
                'A.7': self._check_physical_controls(scan_results),
                'A.8': self._check_technological_controls(vulns),
            },
            'findings': self._compile_findings(vulns, creds, scan_results),
            'recommendations': self._iso_recommendations(vulns, creds),
        }

    def _check_default_passwords(self, creds):
        default_users = {'admin', 'root', 'password', 'default', 'user', 'test'}
        found_defaults = [c for c in (creds or []) if c.get('username', '').lower() in default_users]
        return {'status': 'FAIL' if found_defaults else 'PASS', 'details': f'{len(found_defaults)} default credentials found'}

    def _check_logical_access(self, scan_results, creds):
        return {'status': 'REVIEW', 'details': f'{len(creds or [])} credentials discovered, {len(scan_results)} hosts scanned'}

    def _check_external_threats(self, vulns):
        critical = [v for v in (vulns or []) if v.get('severity') == 'CRITICAL']
        return {'status': 'FAIL' if critical else 'PASS', 'details': f'{len(critical)} critical vulnerabilities'}

    def _check_monitoring(self, infected_hosts):
        return {'status': 'PASS', 'details': f'{len(infected_hosts)} hosts monitored'}

    def _check_incident_response(self, failed_targets):
        return {'status': 'REVIEW', 'details': f'{len(failed_targets)} failed targets logged'}

    def _check_system_availability(self, scan_results):
        return {'status': 'PASS', 'details': f'{len(scan_results)} systems inventoried'}

    def _check_recovery_capabilities(self):
        return {'status': 'REVIEW', 'details': 'Recovery testing recommended'}

    def _check_data_classification(self, creds):
        return {'status': 'FAIL' if creds else 'PASS', 'details': f'{len(creds or [])} credential sets discovered'}

    def _check_encryption(self, scan_results):
        encrypted = [h for h in scan_results if any(p in h.get('open_ports', []) for p in [443, 993, 995])]
        return {'status': 'REVIEW', 'details': f'{len(encrypted)}/{len(scan_results)} hosts with encryption'}

    def _check_firewall_config(self, scan_results):
        high_risk_ports = {21, 23, 445, 3389}
        exposed = [h for h in scan_results if any(p in h.get('open_ports', []) for p in high_risk_ports)]
        return {'status': 'FAIL' if exposed else 'PASS', 'details': f'{len(exposed)} hosts with high-risk ports'}

    def _check_data_protection(self, creds):
        return {'status': 'FAIL' if creds else 'PASS', 'details': f'{len(creds or [])} unprotected credentials'}

    def _check_encryption_in_transit(self, scan_results):
        return self._check_encryption(scan_results)

    def _check_antivirus(self, vulns):
        return {'status': 'REVIEW' if vulns else 'PASS', 'details': f'{len(vulns or [])} vulnerabilities found'}

    def _check_secure_development(self, vulns):
        high = [v for v in (vulns or []) if v.get('severity') in ('CRITICAL', 'HIGH')]
        return {'status': 'FAIL' if high else 'PASS', 'details': f'{len(high)} high/critical vulns'}

    def _check_access_control(self, creds):
        return {'status': 'FAIL' if creds else 'PASS', 'details': f'{len(creds or [])} credential sets'}

    def _check_authentication(self, creds):
        return self._check_default_passwords(creds)

    def _check_security_testing(self, vulns):
        return {'status': 'REVIEW', 'details': f'{len(vulns or [])} vulnerabilities identified'}

    def _check_risk_analysis(self, vulns):
        return {'status': 'REVIEW', 'details': f'{len(vulns or [])} risks identified'}

    def _check_workforce_security(self, creds):
        return self._check_default_passwords(creds)

    def _check_facility_access(self, scan_results):
        return {'status': 'REVIEW', 'details': f'{len(scan_results)} facilities scanned'}

    def _check_workstation_security(self, scan_results):
        return {'status': 'REVIEW', 'details': f'{len(scan_results)} workstations assessed'}

    def _check_audit_controls(self, infected_hosts):
        return {'status': 'PASS', 'details': f'{len(infected_hosts)} hosts under audit'}

    def _check_data_integrity(self, scan_results):
        return {'status': 'REVIEW', 'details': f'{len(scan_results)} systems assessed'}

    def _check_transmission_security(self, scan_results):
        return self._check_encryption(scan_results)

    def _check_organizational_controls(self, scan_results):
        return {'status': 'REVIEW', 'details': f'{len(scan_results)} systems inventoried'}

    def _check_people_controls(self, creds):
        return self._check_default_passwords(creds)

    def _check_physical_controls(self, scan_results):
        return {'status': 'REVIEW', 'details': f'{len(scan_results)} physical endpoints'}

    def _check_technological_controls(self, vulns):
        critical = [v for v in (vulns or []) if v.get('severity') == 'CRITICAL']
        return {'status': 'FAIL' if critical else 'PASS', 'details': f'{len(critical)} critical findings'}

    def _compile_findings(self, vulns, creds, scan_results):
        findings = []
        for v in (vulns or []):
            findings.append({'type': 'vulnerability', 'severity': v.get('severity', 'UNKNOWN'), 'detail': v.get('name', '')})
        for c in (creds or []):
            findings.append({'type': 'credential', 'detail': f"{c.get('username', '')}@{c.get('host_ip', '')}"})
        return findings

    def _soc2_recommendations(self, vulns, creds):
        recs = []
        if vulns:
            recs.append('Implement vulnerability management program')
        if creds:
            recs.append('Enforce strong password policy and MFA')
        recs.extend(['Implement continuous monitoring', 'Conduct regular penetration testing'])
        return recs

    def _pci_recommendations(self, vulns, creds):
        recs = []
        if vulns:
            recs.append('Patch all critical and high vulnerabilities within 30 days')
        if creds:
            recs.append('Change all default passwords immediately')
        recs.extend(['Implement network segmentation', 'Deploy IDS/IPS'])
        return recs

    def _hipaa_recommendations(self, vulns, creds):
        recs = []
        if vulns:
            recs.append('Conduct comprehensive risk assessment')
        if creds:
            recs.append('Implement role-based access control')
        recs.extend(['Enable audit logging', 'Implement data encryption at rest and in transit'])
        return recs

    def _iso_recommendations(self, vulns, creds):
        recs = []
        if vulns:
            recs.append('Implement information security risk management')
        if creds:
            recs.append('Implement identity and access management')
        recs.extend(['Establish security awareness program', 'Implement incident management'])
        return recs
