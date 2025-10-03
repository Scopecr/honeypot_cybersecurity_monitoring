#!/usr/bin/env python3
"""
Comprehensive Honeypot Analysis Script for Weeks 2, 3 & 4
Analyzes Cowrie honeypot logs and generates structured reports with clear week indicators
"""

import json
import re
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import ipaddress
from pathlib import Path
import argparse
import geoip2.database
import geoip2.errors

class HoneypotAnalyzer:
    def __init__(self, log_file, output_dir="demo"):
        self.log_file = log_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Data structures for analysis
        self.connections = []
        self.commands = []
        self.credentials = []
        self.downloads = []
        self.sessions = defaultdict(dict)

        # Week classification
        self.week_boundaries = {
            2: "Basic data collection and initial attacker behavior capture",
            3: "Pattern analysis, attack fingerprinting, and geographic mapping",
            4: "Advanced threat analysis and network hardening recommendations"
        }

    def load_cowrie_logs(self):
        """Load and parse Cowrie JSON logs"""
        print("[WEEK 2] Loading and parsing honeypot logs...")

        try:
            with open(self.log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        if line.strip():
                            log_entry = json.loads(line.strip())
                            self._categorize_log_entry(log_entry)
                    except json.JSONDecodeError as e:
                        print(f"Warning: Invalid JSON at line {line_num}: {e}")
                        continue

            print(f"Loaded {len(self.connections)} connections, {len(self.commands)} commands")

        except FileNotFoundError:
            print(f"Error: Log file {self.log_file} not found")
            sys.exit(1)

    def _categorize_log_entry(self, entry):
        """Categorize log entries by event type"""
        event_id = entry.get('eventid', '')

        if event_id == 'cowrie.session.connect':
            self.connections.append(entry)
            session_id = entry.get('session')
            self.sessions[session_id].update({
                'src_ip': entry.get('src_ip'),
                'timestamp': entry.get('timestamp'),
                'start_time': entry.get('timestamp')
            })

        elif event_id == 'cowrie.command.input':
            self.commands.append(entry)

        elif event_id == 'cowrie.login.success' or event_id == 'cowrie.login.failed':
            self.credentials.append(entry)

        elif event_id == 'cowrie.session.file_download':
            self.downloads.append(entry)

    def week2_basic_analysis(self):
        """WEEK 2: Basic data collection and attacker behavior capture"""
        print("\n" + "="*60)
        print("WEEK 2 ANALYSIS: Basic Data Collection & Attacker Behavior")
        print("="*60)

        report = {
            'week': 2,
            'description': self.week_boundaries[2],
            'analysis': {}
        }

        # Basic statistics
        unique_ips = set(conn.get('src_ip') for conn in self.connections)
        total_commands = len(self.commands)

        report['analysis']['basic_stats'] = {
            'total_connections': len(self.connections),
            'unique_attackers': len(unique_ips),
            'total_commands': total_commands,
            'analysis_period': self._get_time_range()
        }

        # Most common commands (basic attacker behavior)
        command_counter = Counter()
        for cmd in self.commands:
            input_cmd = cmd.get('input', '').strip()
            if input_cmd:
                command_counter[input_cmd] += 1

        report['analysis']['top_commands'] = dict(command_counter.most_common(20))

        # Basic credential analysis
        credential_stats = self._analyze_credentials()
        report['analysis']['credential_attacks'] = credential_stats

        # Top attacking IPs
        ip_counter = Counter(conn.get('src_ip') for conn in self.connections)
        report['analysis']['top_attackers'] = dict(ip_counter.most_common(10))

        # Save Week 2 report
        self._save_report(report, 'week2_basic_analysis.json')
        self._generate_week2_summary(report)

        return report

    def week3_pattern_analysis(self):
        """WEEK 3: Pattern analysis, attack fingerprinting, and geographic mapping"""
        print("\n" + "="*60)
        print("WEEK 3 ANALYSIS: Pattern Analysis & Attack Fingerprinting")
        print("="*60)

        report = {
            'week': 3,
            'description': self.week_boundaries[3],
            'analysis': {}
        }

        # Attack pattern classification
        attack_patterns = self._classify_attack_patterns()
        report['analysis']['attack_patterns'] = attack_patterns

        # Geographic analysis
        geographic_data = self._analyze_geography()
        report['analysis']['geographic_distribution'] = geographic_data

        # Temporal patterns
        temporal_patterns = self._analyze_temporal_patterns()
        report['analysis']['temporal_patterns'] = temporal_patterns

        # Attack tool fingerprinting
        tool_signatures = self._fingerprint_tools()
        report['analysis']['tool_signatures'] = tool_signatures

        # Command sequence analysis
        sequences = self._analyze_command_sequences()
        report['analysis']['command_sequences'] = sequences

        # Save Week 3 report
        self._save_report(report, 'week3_pattern_analysis.json')
        self._generate_week3_summary(report)

        return report

    def week4_threat_analysis(self):
        """WEEK 4: Advanced threat analysis and network hardening recommendations"""
        print("\n" + "="*60)
        print("WEEK 4 ANALYSIS: Threat Analysis & Hardening Recommendations")
        print("="*60)

        report = {
            'week': 4,
            'description': self.week_boundaries[4],
            'analysis': {}
        }

        # Threat actor clustering
        threat_clusters = self._cluster_threat_actors()
        report['analysis']['threat_actor_clusters'] = threat_clusters

        # Malware analysis
        malware_analysis = self._analyze_malware()
        report['analysis']['malware_analysis'] = malware_analysis

        # Network hardening recommendations
        hardening_recommendations = self._generate_hardening_recommendations()
        report['analysis']['hardening_recommendations'] = hardening_recommendations

        # Risk assessment
        risk_assessment = self._assess_risks()
        report['analysis']['risk_assessment'] = risk_assessment

        # IOCs (Indicators of Compromise)
        iocs = self._extract_iocs()
        report['analysis']['indicators_of_compromise'] = iocs

        # Save Week 4 report
        self._save_report(report, 'week4_threat_analysis.json')
        self._generate_week4_summary(report)

        return report

    def _classify_attack_patterns(self):
        """Classify attacks by pattern and technique"""
        patterns = {
            'reconnaissance': [],
            'malware_deployment': [],
            'persistence_attempts': [],
            'privilege_escalation': [],
            'lateral_movement': []
        }

        recon_keywords = ['uname', 'whoami', 'id', 'hostname', 'cat /proc', 'ls', 'pwd', 'which']
        malware_keywords = ['wget', 'curl', 'nohup', 'chmod +x', '/tmp/', 'base64']
        persistence_keywords = ['authorized_keys', 'crontab', 'chattr', 'systemctl', '.bashrc']
        privesc_keywords = ['sudo', 'su', 'passwd', '/etc/passwd', '/etc/shadow']

        for cmd in self.commands:
            input_cmd = cmd.get('input', '').lower()
            src_ip = cmd.get('src_ip', '')

            if any(keyword in input_cmd for keyword in recon_keywords):
                patterns['reconnaissance'].append({
                    'command': cmd.get('input'),
                    'src_ip': src_ip,
                    'timestamp': cmd.get('timestamp')
                })
            elif any(keyword in input_cmd for keyword in malware_keywords):
                patterns['malware_deployment'].append({
                    'command': cmd.get('input'),
                    'src_ip': src_ip,
                    'timestamp': cmd.get('timestamp')
                })
            elif any(keyword in input_cmd for keyword in persistence_keywords):
                patterns['persistence_attempts'].append({
                    'command': cmd.get('input'),
                    'src_ip': src_ip,
                    'timestamp': cmd.get('timestamp')
                })
            elif any(keyword in input_cmd for keyword in privesc_keywords):
                patterns['privilege_escalation'].append({
                    'command': cmd.get('input'),
                    'src_ip': src_ip,
                    'timestamp': cmd.get('timestamp')
                })

        return {k: len(v) for k, v in patterns.items()}

    def _analyze_geography(self):
        """Analyze geographic distribution of attacks"""
        # This is a simplified version - in production you'd use GeoIP database
        country_counter = Counter()

        # Basic IP-to-region mapping (simplified)
        ip_regions = {
            '196.251': 'South Africa',
            '134.209': 'United States',
            '139.59': 'Singapore',
            '165.227': 'United States',
            '178.128': 'Singapore',
            '188.166': 'Germany',
            '213.209': 'Germany',
            '27.201': 'China',
            '51.79': 'Canada',
            '8.140': 'China',
            '47.76': 'Singapore',
            '47.243': 'Singapore'
        }

        for conn in self.connections:
            src_ip = conn.get('src_ip', '')
            for prefix, region in ip_regions.items():
                if src_ip.startswith(prefix):
                    country_counter[region] += 1
                    break
            else:
                country_counter['Unknown'] += 1

        return dict(country_counter.most_common())

    def _analyze_temporal_patterns(self):
        """Analyze attack timing patterns"""
        hourly_dist = Counter()
        daily_dist = Counter()

        for conn in self.connections:
            timestamp = conn.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    hourly_dist[dt.hour] += 1
                    daily_dist[dt.date().isoformat()] += 1
                except ValueError:
                    continue

        return {
            'hourly_distribution': dict(hourly_dist),
            'daily_distribution': dict(daily_dist),
            'peak_hours': [k for k, v in hourly_dist.most_common(3)]
        }

    def _fingerprint_tools(self):
        """Identify potential tools based on command patterns"""
        tool_signatures = {}

        # Look for specific tool patterns
        for cmd in self.commands:
            input_cmd = cmd.get('input', '')

            # Nmap-style reconnaissance
            if re.search(r'uname -[a-z]+', input_cmd, re.IGNORECASE):
                tool_signatures.setdefault('nmap_scripts', 0)
                tool_signatures['nmap_scripts'] += 1

            # Automated scanners
            if 'uname=$(uname' in input_cmd and len(input_cmd) > 200:
                tool_signatures.setdefault('automated_scanner', 0)
                tool_signatures['automated_scanner'] += 1

            # Wget/curl download patterns
            if re.search(r'(wget|curl).*http://.*:\d+', input_cmd):
                tool_signatures.setdefault('malware_downloader', 0)
                tool_signatures['malware_downloader'] += 1

        return tool_signatures

    def _analyze_command_sequences(self):
        """Analyze common command sequences"""
        sequences = defaultdict(int)

        # Group commands by session
        session_commands = defaultdict(list)
        for cmd in self.commands:
            session = cmd.get('session', '')
            if session:
                session_commands[session].append(cmd.get('input', ''))

        # Find common 2-command sequences
        for session, commands in session_commands.items():
            for i in range(len(commands) - 1):
                seq = f"{commands[i]} -> {commands[i+1]}"
                sequences[seq] += 1

        return dict(Counter(sequences).most_common(10))

    def _cluster_threat_actors(self):
        """Cluster threat actors by behavior"""
        clusters = {
            'reconnaissance_focused': [],
            'malware_deployers': [],
            'credential_bruteforcers': [],
            'persistent_attackers': []
        }

        # Group activity by IP
        ip_activity = defaultdict(lambda: {'commands': [], 'logins': [], 'downloads': []})

        for cmd in self.commands:
            ip = cmd.get('src_ip', '')
            ip_activity[ip]['commands'].append(cmd.get('input', ''))

        for cred in self.credentials:
            ip = cred.get('src_ip', '')
            ip_activity[ip]['logins'].append(cred)

        # Classify IPs based on behavior
        for ip, activity in ip_activity.items():
            recon_commands = sum(1 for cmd in activity['commands']
                               if any(kw in cmd.lower() for kw in ['uname', 'whoami', 'hostname']))
            malware_commands = sum(1 for cmd in activity['commands']
                                 if any(kw in cmd.lower() for kw in ['wget', 'curl', 'nohup']))

            if recon_commands > 10:
                clusters['reconnaissance_focused'].append(ip)
            if malware_commands > 0:
                clusters['malware_deployers'].append(ip)
            if len(activity['logins']) > 5:
                clusters['credential_bruteforcers'].append(ip)

        return {k: len(v) for k, v in clusters.items()}

    def _analyze_malware(self):
        """Analyze malware samples and C&C infrastructure"""
        malware_analysis = {
            'download_attempts': len(self.downloads),
            'c2_servers': set(),
            'malware_families': [],
            'payload_analysis': []
        }

        # Extract C&C servers from commands
        for cmd in self.commands:
            input_cmd = cmd.get('input', '')
            # Look for HTTP downloads
            http_matches = re.findall(r'https?://([^/\s]+)', input_cmd)
            for match in http_matches:
                malware_analysis['c2_servers'].add(match)

        malware_analysis['c2_servers'] = list(malware_analysis['c2_servers'])

        # Analyze payload patterns
        for cmd in self.commands:
            input_cmd = cmd.get('input', '')
            if 'base64' in input_cmd.lower() or len(input_cmd) > 500:
                malware_analysis['payload_analysis'].append({
                    'command_length': len(input_cmd),
                    'contains_base64': 'base64' in input_cmd.lower(),
                    'src_ip': cmd.get('src_ip'),
                    'timestamp': cmd.get('timestamp')
                })

        return malware_analysis

    def _generate_hardening_recommendations(self):
        """Generate network hardening recommendations"""
        recommendations = {
            'immediate_actions': [],
            'monitoring_improvements': [],
            'policy_changes': [],
            'technical_controls': []
        }

        # Analyze attack data to generate recommendations
        unique_ips = set(conn.get('src_ip') for conn in self.connections)

        recommendations['immediate_actions'] = [
            f"Block {len(unique_ips)} malicious IP addresses identified in analysis",
            "Implement rate limiting for SSH connections (max 3 attempts per IP per minute)",
            "Deploy fail2ban with custom rules for detected attack patterns"
        ]

        recommendations['monitoring_improvements'] = [
            "Monitor for complex uname command patterns indicating automated scanning",
            "Alert on wget/curl commands downloading from suspicious domains",
            "Track SSH key injection attempts in authorized_keys files"
        ]

        recommendations['policy_changes'] = [
            "Disable password authentication, use key-based auth only",
            "Implement network segmentation for critical systems",
            "Regular security awareness training on social engineering"
        ]

        recommendations['technical_controls'] = [
            "Deploy SIEM with custom rules for honeypot attack patterns",
            "Implement geofencing to block connections from high-risk countries",
            "Use intrusion prevention system (IPS) with behavioral analysis"
        ]

        return recommendations

    def _assess_risks(self):
        """Assess security risks based on observed attacks"""
        total_attacks = len(self.commands)
        unique_attackers = len(set(conn.get('src_ip') for conn in self.connections))

        risk_level = "HIGH" if total_attacks > 1000 else "MEDIUM" if total_attacks > 100 else "LOW"

        return {
            'overall_risk_level': risk_level,
            'attack_volume': total_attacks,
            'attacker_diversity': unique_attackers,
            'key_risks': [
                'Automated scanning and reconnaissance',
                'Malware deployment attempts',
                'Credential brute force attacks',
                'Persistence mechanism deployment'
            ]
        }

    def _extract_iocs(self):
        """Extract Indicators of Compromise"""
        iocs = {
            'malicious_ips': [],
            'malicious_domains': [],
            'malicious_urls': [],
            'attack_signatures': []
        }

        # Get top attacking IPs
        ip_counter = Counter(conn.get('src_ip') for conn in self.connections)
        iocs['malicious_ips'] = [ip for ip, count in ip_counter.most_common(20)]

        # Extract domains and URLs from commands
        for cmd in self.commands:
            input_cmd = cmd.get('input', '')
            domains = re.findall(r'https?://([^/\s:]+)', input_cmd)
            urls = re.findall(r'https?://[^\s]+', input_cmd)

            iocs['malicious_domains'].extend(domains)
            iocs['malicious_urls'].extend(urls)

        # Remove duplicates
        iocs['malicious_domains'] = list(set(iocs['malicious_domains']))
        iocs['malicious_urls'] = list(set(iocs['malicious_urls']))

        # Attack signatures
        iocs['attack_signatures'] = [
            'uname=$(uname -s -v -n -m 2>/dev/null)',
            'nohup $SHELL -c "curl http://',
            'chmod +x /tmp/',
            'echo "ssh-rsa AAAAB3NzaC1yc2E'
        ]

        return iocs

    def _analyze_credentials(self):
        """Analyze credential attack patterns"""
        success_count = sum(1 for cred in self.credentials if cred.get('eventid') == 'cowrie.login.success')
        failed_count = sum(1 for cred in self.credentials if cred.get('eventid') == 'cowrie.login.failed')

        usernames = Counter()
        passwords = Counter()

        for cred in self.credentials:
            username = cred.get('username', '')
            password = cred.get('password', '')
            if username:
                usernames[username] += 1
            if password:
                passwords[password] += 1

        return {
            'total_attempts': len(self.credentials),
            'successful_logins': success_count,
            'failed_logins': failed_count,
            'top_usernames': dict(usernames.most_common(10)),
            'top_passwords': dict(passwords.most_common(10))
        }

    def _get_time_range(self):
        """Get the time range of the analysis"""
        if not self.connections:
            return "No data available"

        timestamps = [conn.get('timestamp') for conn in self.connections if conn.get('timestamp')]
        if not timestamps:
            return "No timestamps available"

        start_time = min(timestamps)
        end_time = max(timestamps)
        return f"{start_time} to {end_time}"

    def _save_report(self, report, filename):
        """Save report to JSON file"""
        output_path = self.output_dir / filename
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"Report saved: {output_path}")

    def _generate_week2_summary(self, report):
        """Generate Week 2 text summary"""
        summary_path = self.output_dir / "week2_summary.txt"

        with open(summary_path, 'w') as f:
            f.write("="*60 + "\n")
            f.write("WEEK 2: BASIC DATA COLLECTION & ATTACKER BEHAVIOR\n")
            f.write("="*60 + "\n\n")

            stats = report['analysis']['basic_stats']
            f.write(f"Analysis Period: {stats['analysis_period']}\n")
            f.write(f"Total Connections: {stats['total_connections']}\n")
            f.write(f"Unique Attackers: {stats['unique_attackers']}\n")
            f.write(f"Total Commands: {stats['total_commands']}\n\n")

            f.write("TOP 10 ATTACKING IPS:\n")
            f.write("-" * 30 + "\n")
            for ip, count in list(report['analysis']['top_attackers'].items())[:10]:
                f.write(f"{ip:15} {count:>5} attacks\n")

            f.write("\nTOP 10 COMMANDS:\n")
            f.write("-" * 30 + "\n")
            for cmd, count in list(report['analysis']['top_commands'].items())[:10]:
                f.write(f"{count:>3} {cmd[:50]}...\n")

        print(f"Week 2 summary saved: {summary_path}")

    def _generate_week3_summary(self, report):
        """Generate Week 3 text summary"""
        summary_path = self.output_dir / "week3_summary.txt"

        with open(summary_path, 'w') as f:
            f.write("="*60 + "\n")
            f.write("WEEK 3: PATTERN ANALYSIS & ATTACK FINGERPRINTING\n")
            f.write("="*60 + "\n\n")

            patterns = report['analysis']['attack_patterns']
            f.write("ATTACK PATTERN CLASSIFICATION:\n")
            f.write("-" * 30 + "\n")
            for pattern, count in patterns.items():
                f.write(f"{pattern.replace('_', ' ').title():25} {count:>5}\n")

            f.write("\nGEOGRAPHIC DISTRIBUTION:\n")
            f.write("-" * 30 + "\n")
            for country, count in report['analysis']['geographic_distribution'].items():
                f.write(f"{country:20} {count:>5}\n")

            f.write("\nTOOL SIGNATURES DETECTED:\n")
            f.write("-" * 30 + "\n")
            for tool, count in report['analysis']['tool_signatures'].items():
                f.write(f"{tool.replace('_', ' ').title():20} {count:>5}\n")

        print(f"Week 3 summary saved: {summary_path}")

    def _generate_week4_summary(self, report):
        """Generate Week 4 text summary"""
        summary_path = self.output_dir / "week4_summary.txt"

        with open(summary_path, 'w') as f:
            f.write("="*60 + "\n")
            f.write("WEEK 4: THREAT ANALYSIS & HARDENING RECOMMENDATIONS\n")
            f.write("="*60 + "\n\n")

            risk = report['analysis']['risk_assessment']
            f.write(f"OVERALL RISK LEVEL: {risk['overall_risk_level']}\n")
            f.write(f"Attack Volume: {risk['attack_volume']}\n")
            f.write(f"Attacker Diversity: {risk['attacker_diversity']}\n\n")

            f.write("THREAT ACTOR CLUSTERS:\n")
            f.write("-" * 30 + "\n")
            clusters = report['analysis']['threat_actor_clusters']
            for cluster, count in clusters.items():
                f.write(f"{cluster.replace('_', ' ').title():25} {count:>5}\n")

            f.write("\nIMMEDIATE ACTIONS REQUIRED:\n")
            f.write("-" * 30 + "\n")
            for i, action in enumerate(report['analysis']['hardening_recommendations']['immediate_actions'], 1):
                f.write(f"{i}. {action}\n")

            f.write("\nMALWARE ANALYSIS:\n")
            f.write("-" * 30 + "\n")
            malware = report['analysis']['malware_analysis']
            f.write(f"Download Attempts: {malware['download_attempts']}\n")
            f.write(f"C&C Servers: {len(malware['c2_servers'])}\n")
            for server in malware['c2_servers'][:5]:  # Top 5
                f.write(f"  - {server}\n")

        print(f"Week 4 summary saved: {summary_path}")

    def generate_demo_overview(self):
        """Generate overview document for demo"""
        overview_path = self.output_dir / "DEMO_OVERVIEW.md"

        with open(overview_path, 'w') as f:
            f.write(f"""# Honeypot Analysis Demo
## Comprehensive 4-Week Project Analysis

This demo contains analysis results from a 4-week honeypot deployment project using Cowrie SSH honeypot.


### Key Findings:
- **{len(self.connections)}** total connections from **{len(set(conn.get('src_ip') for conn in self.connections))}** unique IPs
- **{len(self.commands)}** commands executed by attackers
- Multiple attack patterns identified: reconnaissance, malware deployment, persistence
- Geographic distribution across multiple countries
- Specific tool signatures and attack sequences documented


Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
""")
        print(f"Demo overview saved: {overview_path}")

def main():
    parser = argparse.ArgumentParser(description='Comprehensive Honeypot Analysis for Weeks 2-4')
    parser.add_argument('log_file', help='Path to Cowrie JSON log file')
    parser.add_argument('--output-dir', default='demo', help='Output directory (default: demo)')

    args = parser.parse_args()

    # Initialize analyzer
    analyzer = HoneypotAnalyzer(args.log_file, args.output_dir)

    # Load logs
    analyzer.load_cowrie_logs()

    if not analyzer.connections:
        print("No connection data found in logs. Please check the log file format.")
        return

    # Run all week analyses
    print("\nRunning comprehensive analysis for Weeks 2, 3, and 4...")

    week2_report = analyzer.week2_basic_analysis()
    week3_report = analyzer.week3_pattern_analysis()
    week4_report = analyzer.week4_threat_analysis()

    # Generate demo overview
    analyzer.generate_demo_overview()

    print(f"\n{'='*60}")
    print("DEMO ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"All reports saved to: {analyzer.output_dir}")
    print("\nFiles generated:")
    for file in sorted(analyzer.output_dir.glob("*")):
        print(f"  - {file.name}")

    print(f"\nStart your demo with: cat {analyzer.output_dir}/DEMO_OVERVIEW.md")

if __name__ == "__main__":
    main()
