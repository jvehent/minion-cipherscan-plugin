# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import logging
import os
import re
import urlparse
from minion.plugins.base import ExternalProcessPlugin

class CipherScanPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "CipherScan"
    PLUGIN_VERSION = "0.1"
    CIPHERSCAN_NAME = "cipherscan"
    REFERENCE_CIPHERSUITE = (
        'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:'
        'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:'
        'ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:'
        'ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:'
        'DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:'
        'DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:'
        'ECDHE-RSA-RC4-SHA:ECDH-RSA-AES128-GCM-SHA256:'
        'ECDH-RSA-AES128-SHA256:ECDH-RSA-AES128-SHA:AES128-SHA256:'
        'AES128-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:'
        'ECDH-RSA-AES256-SHA:AES256-SHA256:AES256-SHA:RC4-SHA:'
        'DHE-RSA-CAMELLIA256-SHA:CAMELLIA256-SHA:DHE-RSA-CAMELLIA128-SHA:'
        'DHE-DSS-CAMELLIA128-SHA:CAMELLIA128-SHA'
    )
    SOLUTION = ( "Use recommended configuration from "
                 "https://wiki.mozilla.org/Security/Server_Side_TLS" )

    def do_configure(self):
        """ Find the path to cps """
        logging.debug("CipherScanPlugin.do_configure")
        curr = os.path.dirname(os.path.abspath(__file__))
        cps_path = curr + '/' + self.CIPHERSCAN_NAME
        if not os.path.exists(cps_path):
            raise Exception("Cannot find %s" % cps_path)
        self.cps_path = cps_path

    def do_start(self):
        logging.debug("CipherScanPlugin.do_start")
        self.cps_stdout = ""
        self.cps_stderr = ""
        u = urlparse.urlparse(self.configuration['target'])
        if u.scheme != "https":
            raise Exception("Target scheme isn't HTTPS")
        t = u.hostname + ":443"
        cmd = [t, "-json"]
        self.spawn(self.cps_path, cmd)

    def do_process_stdout(self, data):
        self.cps_stdout += data

    def do_process_stderr(self, data):
        self.cps_stderr += data

    def do_process_ended(self, status):
        logging.debug("CipherScanPlugin.do_ended")
        with open("cps.stdout.txt", "w") as f:
            f.write(self.cps_stdout)
        with open("cps.stderr.txt", "w") as f:
            f.write(self.cps_stderr)
        self.report_artifacts("cps Output",
            ["cps.stdout.txt", "cps.stderr.txt"])
        self.scan_output = json.loads(self.cps_stdout)
        issues = []
        if self.scan_output["ciphersuite"]:
            issues = scan_to_issues(self)
        self.report_issues(issues)
        self.report_finish()

def scan_to_issues(self):
    """ Find issues in scan output """
    issues = []
    issue = check_distance(self)
    if issue:
        issues.append(issue)
    issue = check_pfs_pref(self)
    if issue:
        issues.append(issue)
    issue = check_pfs_keysize_dhe(self)
    if issue:
        issues.append(issue)
    issue = check_pfs_keysize_ecdhe(self)
    if issue:
        issues.append(issue)
    issue = check_tls_protocols(self)
    if issue:
        issues.append(issue)
    issue = check_rc4_notfirst(self)
    if issue:
        issues.append(issue)
    issue = check_rc4_or_3des(self)
    if issue:
        issues.append(issue)
    return issues

def check_distance(self):
    """ check distance from ref ciphersuite """
    desc = ("This test measure the distance from the retrieved ciphersuite "
            "to the standard ciphersuite recommended by Mozilla.")
    sev = "OK"
    summary = "Retrieved ciphersuite is close to Mozilla's standard"
    issue = []
    csuite = retrieve_csuite(self.scan_output["ciphersuite"])
    logging.debug("CipherScanPlugin ciphersuite: %s" % csuite)
    dld = damerau_levenshtein_distance(csuite, self.REFERENCE_CIPHERSUITE)
    logging.debug("CipherScanPlugin Damerau-Levenshtein distance %s" % dld)
    if dld > 500:
        sev = "Medium"
        summary = "Ciphersuite is far from Mozilla's standard"
    elif dld > 250:
        sev = "Low"
        summary = "Ciphersuite is different from Mozilla's standard"
    issue = ({"Distance": dld, "Severity": sev, "Summary": summary,
              "Solution": self.SOLUTION, "Description": desc})
    return issue

def retrieve_csuite(clist):
    """
    retrieve the ciphers from the scan result
    and concat them into a string
    """
    ciphersuite = ""
    for entry in clist:
        if ciphersuite != "":
            ciphersuite += ":"
        ciphersuite += entry["cipher"]
    return ciphersuite

def damerau_levenshtein_distance(s1, s2):
    """
    Compute the Damerau-Levenshtein distance
    between two given string
    http://www.guyrutenberg.com/2008/12/15/damerau-levenshtein-distance-in-python/
    """
    d = {}
    lenstr1 = len(s1)
    lenstr2 = len(s2)
    for i in xrange(-1,lenstr1+1):
        d[(i,-1)] = i+1
    for j in xrange(-1,lenstr2+1):
        d[(-1,j)] = j+1
    for i in xrange(lenstr1):
        for j in xrange(lenstr2):
            if s1[i] == s2[j]:
                cost = 0
            else:
                cost = 1
            d[(i,j)] = min(
                           d[(i-1,j)] + 1, # deletion
                           d[(i,j-1)] + 1, # insertion
                           d[(i-1,j-1)] + cost, # substitution
                          )
            if i and j and s1[i]==s2[j-1] and s1[i-1] == s2[j]:
                d[(i,j)] = min (d[(i,j)], d[i-2,j-2] + cost) # transposition
    return d[lenstr1-1,lenstr2-1]

def check_pfs_pref(self):
    """ Check PFS preference in ciphersuite """
    desc = ("PFS ciphers start with DHE or ECDHE. They prevent "
            "an attacker from being able to decrypt traffic by obtaining "
            "the private key alone.")
    summary = "PFS ciphers are preferred"
    sev = "OK"
    issue = []
    pos = 1
    has_pfs = False
    for entry in self.scan_output["ciphersuite"]:
        if re.search('^(ECDHE|DHE)-', entry["cipher"]):
            has_pfs = True
            break
        pos += 1
    if has_pfs and pos > 1:
        sev = "Low"
        summary = "PFS cipher is not first. Found in position %s" % pos
    elif not has_pfs:
        sev = "Medium"
        summary = "PFS ciphers not found in the ciphersuite"
    issue = ({"Severity": sev, "Summary": summary,
              "Solution": self.SOLUTION, "Description": desc})
    return issue

def check_pfs_keysize_dhe(self):
    """ Check PFS keysize > 1024 bits for DHE """
    desc = ("PFS key size for Diffie-Hellman key exchange should be "
            "equal to the RSA key size. In most cases, this should be "
            "2048 bits.")
    sev = "OK"
    summary = "DHE keysize is up to standard"
    keysize = 0
    issue = []
    for entry in self.scan_output["ciphersuite"]:
        if re.search('^DHE-', entry["cipher"]):
            a, b, keysize = entry["pfs"].partition(",")
            keysize, a, b = keysize.partition("bit")
            keysize = int(keysize)
            if keysize <= 512:
                sev = "High"
                summary = "DHE keysize is dangerously small"
            elif keysize <= 1024:
                sev = "Medium"
                summary = "DHE keysize is smaller than Mozilla's standard"
            elif keysize < 2048:
                sev = "Low"
                summary = "DHE keysize is smaller than Mozilla's standard"
            break
    if keysize > 0:
        issue = ({"Keysize": keysize, "Severity": sev, "Summary": summary,
                  "Solution": self.SOLUTION, "Description": desc})
    return issue

def check_pfs_keysize_ecdhe(self):
    """ Check PFS keysize > 256 bits for ECDHE """
    desc = ("PFS key size for Elliptic Curves key exchange should be "
            "proportional to the RSA key size. In most cases, this should be "
            "256 bits.")
    sev = "OK"
    summary = "ECDHE keysize is up to standard"
    keysize = 0
    issue = []
    for entry in self.scan_output["ciphersuite"]:
        if re.search('^ECDHE-', entry["cipher"]):
            a, b, keysize = entry["pfs"].partition(",")
            a, b, keysize = keysize.partition(",")
            keysize, a, b = keysize.partition("bit")
            keysize = int(keysize)
            if keysize <= 64:
                sev = "High"
                summary = "ECDHE keysize is dangerously small"
            elif keysize <= 128:
                sev = "Medium"
                summary = "ECDHE keysize is smaller than Mozilla's standard"
            elif keysize < 256:
                sev = "Low"
                summary = "ECDHE keysize is smaller than Mozilla's standard"
            break
    if keysize > 0:
        issue = ({"Keysize": keysize, "Severity": sev, "Summary": summary,
                  "Solution": self.SOLUTION, "Description": desc})
    return issue

def check_tls_protocols(self):
    """ Check TLS protocol support """
    desc = "All versions of TLS should be supported."
    sev = "OK"
    summary = "All versions of TLS are supported"
    TLS1 = False
    TLS11 = False
    TLS12 = False
    issue = []
    for entry in self.scan_output["ciphersuite"]:
        if "TLSv1" in entry["protocols"]:
            TLS1 = True
        if "TLSv1.1" in entry["protocols"]:
            TLS11 = True
        if "TLSv1.2" in entry["protocols"]:
            TLS12 = True
    if not TLS1 or not TLS11 or not TLS12:
        summary = "Support for TLS versions is missing:"
        if not TLS12:
            sev = "Low"
            summary += " TLS1.2"
        if not TLS11:
            sev = "Medium"
            summary += " TLS1.1"
        if not TLS1:
            sev = "High"
            summary += " TLS1"
    issue = ({"Severity": sev, "Summary": summary,
              "Solution": self.SOLUTION, "Description": desc})
    return issue

def check_rc4_notfirst(self):
    """ Check that RC4 isn't first """
    desc = ("RC4 is a deprecated cipher that should not be preferred. "
            "It can be used for backward compatibility with old clients, "
            "but should be listed at the bottom of the ciphersuite.")
    summary = "RC4 cipher not found"
    sev = "OK"
    issue = []
    pos = 1
    clist_len = len(self.scan_output["ciphersuite"])
    for entry in self.scan_output["ciphersuite"]:
        if "RC4" in entry["cipher"]:
            if pos == 1:
                sev = "Medium"
                summary = "RC4 is the preferred cipher"
                break
            elif pos < clist_len:
                sev = "Low"
                summary = "RC4 is present before the bottom of the ciphersuite"
                break
            else:
                summary = "RC4 is present but listed last"
                break
        pos += 1
    issue = ({"Severity": sev, "Summary": summary,
              "Solution": self.SOLUTION, "Description": desc})
    return issue

def check_rc4_or_3des(self):
    """ Check that either RC4 or 3DES are enabled """
    desc = ("Either RC4 or 3DES are required for backward compatility with "
            "old clients. If neither ciphers are enabled, clients using IE "
            "6/7/8 on Windows XP, that doesn't support AES, will fail to connect.")
    summary = "Neither RC4 or 3DES are supported"
    sev = "Low"
    issue = []
    RC4 = False
    DES = False
    clist_len = len(self.scan_output["ciphersuite"])
    for entry in self.scan_output["ciphersuite"]:
        if "RC4" in entry["cipher"]:
            RC4 = True
        if "DES-CBC3" in entry["cipher"]:
            DES = True
    if RC4 or DES:
        sev = "OK"
        summary = "Legacy ciphers are supported: "
        if RC4:
            summary += "RC4"
        if DES:
            summary += "3DES"
    issue = ({"Severity": sev, "Summary": summary,
              "Solution": self.SOLUTION, "Description": desc})
    return issue

