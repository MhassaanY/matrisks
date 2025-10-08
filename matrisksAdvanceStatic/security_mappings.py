"""
Security Classification Mappings
CWE and OWASP Mobile Top 10 mappings for vulnerabilities
"""

# CWE (Common Weakness Enumeration) Mappings
CWE_MAPPINGS = {
    'ALLOW_BACKUP': 'CWE-200',  # Exposure of Sensitive Information
    'DEBUGGABLE': 'CWE-489',  # Active Debug Code
    'HACKER_DEBUGGABLE_CERT': 'CWE-798',  # Use of Hard-coded Credentials
    'EXPORTED_ACTIVITIES_NO_PERMISSION': 'CWE-927',  # Use of Implicit Intent for Sensitive Communication
    'EXPORTED_SERVICES_NO_PERMISSION': 'CWE-927',
    'EXPORTED_RECEIVERS_NO_PERMISSION': 'CWE-927',
    'EXPORTED_PROVIDERS_NO_PERMISSION': 'CWE-927',
    'EXTERNAL_STORAGE_USAGE': 'CWE-312',  # Cleartext Storage of Sensitive Information
    'INSECURE_STORAGE': 'CWE-312',
    'SHARED_PREFS_WORLD_READABLE': 'CWE-732',  # Incorrect Permission Assignment
    'SQL_INJECTION': 'CWE-89',  # SQL Injection
    'WEBVIEW_FILE_ACCESS': 'CWE-749',  # Exposed Dangerous Method or Function
    'WEBVIEW_JAVASCRIPT': 'CWE-749',
    'WEBVIEW_ALLOW_FILE_ACCESS_FROM_FILE_URLS': 'CWE-346',  # Origin Validation Error
    'SSL_NO_HOSTNAME_VERIFIER': 'CWE-297',  # Improper Validation of Certificate
    'SSL_CUSTOM_TRUSTMANAGER': 'CWE-295',  # Improper Certificate Validation
    'SSL_CUSTOM_HOSTNAMESERVER': 'CWE-297',
    'WEAK_CRYPTO_ALGORITHM': 'CWE-327',  # Use of Broken or Risky Cryptographic Algorithm
    'WEAK_HASH_ALGORITHM': 'CWE-328',  # Reversible One-Way Hash
    'HARDCODED_SECRETS': 'CWE-798',  # Use of Hard-coded Credentials
    'HARDCODED_KEY': 'CWE-321',  # Use of Hard-coded Cryptographic Key
    'ROOT_DETECTION': 'CWE-919',  # Weaknesses in Mobile Applications
    'RUNTIME_EXEC': 'CWE-78',  # OS Command Injection
    'DYNAMIC_CODE_LOADING': 'CWE-494',  # Download of Code Without Integrity Check
    'FRAGMENT_INJECTION': 'CWE-470',  # Use of Externally-Controlled Input
    'WEBVIEW_RCE': 'CWE-94',  # Improper Control of Generation of Code
    'PATH_TRAVERSAL': 'CWE-22',  # Path Traversal
    'INTENT_SCHEME_URL': 'CWE-939',  # Improper Authorization in Handler for Custom URL Scheme
    'TAPJACKING': 'CWE-1021',  # Improper Restriction of Rendered UI Layers
    'STRANDHOGG': 'CWE-284',  # Improper Access Control
    'IMPLICIT_INTENT': 'CWE-927',  # Use of Implicit Intent for Sensitive Communication
    'BROADCAST_THEFT': 'CWE-285',  # Improper Authorization
    'PERMISSION_DANGEROUS': 'CWE-250',  # Execution with Unnecessary Privileges
    'NATIVE_CODE': 'CWE-676',  # Use of Potentially Dangerous Function
    'OBFUSCATION': 'CWE-656',  # Reliance on Security Through Obscurity
}

# OWASP Mobile Top 10 2024 Mappings
OWASP_MOBILE_MAPPINGS = {
    'ALLOW_BACKUP': 'M2',  # Inadequate Supply Chain Security / M2: Insecure Data Storage
    'DEBUGGABLE': 'M7',  # Insufficient Binary Protections
    'HACKER_DEBUGGABLE_CERT': 'M7',
    'EXPORTED_ACTIVITIES_NO_PERMISSION': 'M1',  # Improper Platform Usage
    'EXPORTED_SERVICES_NO_PERMISSION': 'M1',
    'EXPORTED_RECEIVERS_NO_PERMISSION': 'M1',
    'EXPORTED_PROVIDERS_NO_PERMISSION': 'M1',
    'EXTERNAL_STORAGE_USAGE': 'M2',  # Insecure Data Storage
    'INSECURE_STORAGE': 'M2',
    'SHARED_PREFS_WORLD_READABLE': 'M2',
    'SQL_INJECTION': 'M7',  # Client Code Quality / Code Injection
    'WEBVIEW_FILE_ACCESS': 'M1',  # Improper Platform Usage
    'WEBVIEW_JAVASCRIPT': 'M1',
    'WEBVIEW_ALLOW_FILE_ACCESS_FROM_FILE_URLS': 'M1',
    'SSL_NO_HOSTNAME_VERIFIER': 'M3',  # Insecure Communication
    'SSL_CUSTOM_TRUSTMANAGER': 'M3',
    'SSL_CUSTOM_HOSTNAMESERVER': 'M3',
    'WEAK_CRYPTO_ALGORITHM': 'M5',  # Insecure Cryptography
    'WEAK_HASH_ALGORITHM': 'M5',
    'HARDCODED_SECRETS': 'M5',
    'HARDCODED_KEY': 'M5',
    'ROOT_DETECTION': 'M8',  # Security Misconfiguration
    'RUNTIME_EXEC': 'M7',  # Client Code Quality
    'DYNAMIC_CODE_LOADING': 'M7',
    'FRAGMENT_INJECTION': 'M1',
    'WEBVIEW_RCE': 'M7',
    'PATH_TRAVERSAL': 'M2',
    'INTENT_SCHEME_URL': 'M1',
    'TAPJACKING': 'M1',
    'STRANDHOGG': 'M1',
    'IMPLICIT_INTENT': 'M1',
    'BROADCAST_THEFT': 'M1',
    'PERMISSION_DANGEROUS': 'M1',
    'NATIVE_CODE': 'M7',
    'OBFUSCATION': 'M7',
}

# OWASP Mobile Top 10 2024 Descriptions
OWASP_MOBILE_DESCRIPTIONS = {
    'M1': 'Improper Platform Usage',
    'M2': 'Insecure Data Storage',
    'M3': 'Insecure Communication',
    'M4': 'Insecure Authentication',
    'M5': 'Insufficient Cryptography',
    'M6': 'Insecure Authorization',
    'M7': 'Client Code Quality',
    'M8': 'Code Tampering',
    'M9': 'Reverse Engineering',
    'M10': 'Extraneous Functionality'
}

# CWE Descriptions (partial list for most common)
CWE_DESCRIPTIONS = {
    'CWE-22': 'Path Traversal',
    'CWE-78': 'OS Command Injection',
    'CWE-89': 'SQL Injection',
    'CWE-94': 'Improper Control of Generation of Code',
    'CWE-200': 'Exposure of Sensitive Information',
    'CWE-250': 'Execution with Unnecessary Privileges',
    'CWE-284': 'Improper Access Control',
    'CWE-285': 'Improper Authorization',
    'CWE-295': 'Improper Certificate Validation',
    'CWE-297': 'Improper Validation of Certificate with Host Mismatch',
    'CWE-312': 'Cleartext Storage of Sensitive Information',
    'CWE-321': 'Use of Hard-coded Cryptographic Key',
    'CWE-327': 'Use of Broken or Risky Cryptographic Algorithm',
    'CWE-328': 'Reversible One-Way Hash',
    'CWE-346': 'Origin Validation Error',
    'CWE-470': 'Use of Externally-Controlled Input',
    'CWE-489': 'Active Debug Code',
    'CWE-494': 'Download of Code Without Integrity Check',
    'CWE-656': 'Reliance on Security Through Obscurity',
    'CWE-676': 'Use of Potentially Dangerous Function',
    'CWE-732': 'Incorrect Permission Assignment',
    'CWE-749': 'Exposed Dangerous Method or Function',
    'CWE-798': 'Use of Hard-coded Credentials',
    'CWE-919': 'Weaknesses in Mobile Applications',
    'CWE-927': 'Use of Implicit Intent for Sensitive Communication',
    'CWE-939': 'Improper Authorization in Handler for Custom URL Scheme',
    'CWE-1021': 'Improper Restriction of Rendered UI Layers'
}


def get_cwe_for_finding(finding_id):
    """Get CWE classification for a finding"""
    # Check direct mapping first
    if finding_id in CWE_MAPPINGS:
        cwe = CWE_MAPPINGS[finding_id]
        description = CWE_DESCRIPTIONS.get(cwe, '')
        return f"{cwe}: {description}" if description else cwe
    
    # Check partial matches
    for key, cwe in CWE_MAPPINGS.items():
        if key in finding_id or finding_id in key:
            description = CWE_DESCRIPTIONS.get(cwe, '')
            return f"{cwe}: {description}" if description else cwe
    
    return 'N/A'


def get_owasp_for_finding(finding_id):
    """Get OWASP Mobile classification for a finding"""
    # Check direct mapping first
    if finding_id in OWASP_MOBILE_MAPPINGS:
        owasp = OWASP_MOBILE_MAPPINGS[finding_id]
        description = OWASP_MOBILE_DESCRIPTIONS.get(owasp, '')
        return f"{owasp}: {description}" if description else owasp
    
    # Check partial matches
    for key, owasp in OWASP_MOBILE_MAPPINGS.items():
        if key in finding_id or finding_id in key:
            description = OWASP_MOBILE_DESCRIPTIONS.get(owasp, '')
            return f"{owasp}: {description}" if description else owasp
    
    return 'N/A'


def enrich_finding_with_classifications(finding_id, finding_data):
    """
    Enrich a finding with CWE and OWASP Mobile classifications
    
    Args:
        finding_id: The finding identifier
        finding_data: The finding data dictionary
    
    Returns:
        Enhanced finding data with CWE and OWASP classifications
    """
    enhanced = finding_data.copy()
    
    # Add CWE if not present, is None, or is N/A
    if 'cwe' not in enhanced or enhanced.get('cwe') in (None, 'N/A', ''):
        enhanced['cwe'] = get_cwe_for_finding(finding_id)
    
    # Add OWASP Mobile if not present, is None, or is N/A
    if 'owasp_mobile' not in enhanced or enhanced.get('owasp_mobile') in (None, 'N/A', ''):
        enhanced['owasp_mobile'] = get_owasp_for_finding(finding_id)
    
    return enhanced
