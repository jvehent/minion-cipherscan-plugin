# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
from minion.plugins.base import ExternalProcessPlugin

class CipherScanPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "CipherScan"
    PLUGIN_VERSION = "0.1"

    CIPHERSCAN_NAME = "cipherscan"

	def do_configure(self):
		""" Find the path to cipherscan """
        logging.debug("CipherScanPlugin.do_configure")
		curr = os.path.dirname(os.path.abspath(__file))
		cipherscan_path = curr + '/cipherscan/' + CIPHERSCAN_NAME
		if not os.path.exists(cipherscan_path):
			raise Exception("Cannot find %s" % cipherscan_path)
		self.cipherscan_path = cipherscan_path

    def do_start(self):
        logging.debug("CipherScanPlugin.do_start")
        self.cipherscan_stdout = ""
        self.cipherscan_stderr = ""
        u = urlparse.urlparse(self.configuration['target'])
		if u.scheme != "https":
			raise Exception("Target scheme isn't HTTPS")
		t = u.hostname + ":443"
		cmd = [t, "-json"]
        self.spawn(cipherscan_path, cmd)

    def do_process_stdout(self, data):
        self.cipherscan_stdout += data

    def do_process_stderr(self, data):
        self.cipherscan_stderr += data

    def do_process_ended(self, status):
		with open("cipherscan.stdout.txt", "w") as f:
			f.write(self.cipherscan_stdout)
		with open("cipherscan.stderr.txt", "w") as f:
			f.write(self.cipherscan_stderr)
		self.report_artifacts("cipherscan Output", ["cipherscan.stdout.txt", "cipherscan.stderr.txt"])
		scan_output = json.loads(self.cipherscan_stdout)
		issues = scan_to_issues(scan_output)
		self.report_issues(issues)
		self.report_finish()

NOTABLE_ISSUES = [
    {
        "_ports": [22],
        "Severity": "Low",
        "Summary": "Public SSH service found"
    },
    {
        "_ports": [53],
        "Severity": "Low",
        "Summary": "Public DNS service found"
    },
    {
        "_ports": [80,443],
        "Severity": "Informational",
        "Summary": "Standard HTTP services were found"
    },
    {
        "_ports": [3306],
        "Ports": [],
        "Severity": "High",
        "Summary": "Public MySQL database found",
        "Description": "A publicly accessible instance of the MySQL database was found on port 3306.",
        "Solution": "Configure MySQL to listen only on localhost. If other servers need to access to this database then use firewall rules to only allow those servers to connect."
    },
    {
        "_ports": [5432],
        "Severity": "High",
        "Summary": "Public PostgreSQL database found",
        "Description": "A publicly accessible instance of the PostgreSQL database was found on port 5432.",
        "Solution": "Configure PostgreSQL to listen only on localhost. If other servers need to access this database then use firewall rules to only allow those servers to connect."
    },
    {
        "_ports": [25,113,143,465,587,993,995],
        "Severity": "Medium",
        "Summary": "Email service(s) found",
        "Solution": "It is not recomended to run email services on the same server on which a web site is hosted. It is generally a good idea to separate services to different servers to minimize the attack surface."
    }
]

def find_notable_issue(port):
    for issue in NOTABLE_ISSUES:
        if port in issue['_ports']:
            return issue

def find_port_in_issues(port, issues):
    for issue in issues:
        if port in issue['Ports']:
            return True

def find_earlier_found_issue(port, issues):
    for issue in issues:
        if port in issue['_ports']:
            return issue

def services_to_issues(services):

    unique_ports = set()
    for service in services:
        unique_ports.add(service['port'])

    high_risk_ports = set()

    issues = []

    for port in unique_ports:
        # If we have not seen this port before
        if port not in high_risk_ports and not find_port_in_issues(port, issues):
            issue = find_earlier_found_issue(port, issues)
            if issue:
                issue.setdefault("Ports", []).append(port)
            else:
                issue = find_notable_issue(port)
                if issue:
                    # If we have a detailed issue then we use that
                    issues.append(issue)
                    issue.setdefault("Ports", []).append(port)
                else:
                    # Otherwise all unknown services go to high risk.
                    high_risk_ports.add(port)

    if len(high_risk_ports) > 0:
        issues.append({"Ports": list(high_risk_ports), "Severity": "High",
                       "Summary": "Unknown public services found."})

    for issue in issues:
        if '_ports' in issue:
            del issue['_ports']

    return issues


