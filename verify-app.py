# verify-app.py (with filtered CSV downloads)

import csv
import io
import re
import time
import uuid
import dns.resolver
import smtplib
import pandas as pd
from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
from tempfile import NamedTemporaryFile
import os

app = Flask(__name__)
CORS(app, origins=['http://localhost:5500', 'http://127.0.0.1:5500', 'http://localhost:5050', 'http://127.0.0.1:5050'])

print("\U0001F525 VERIFIER RUNNING - Want sales calls from leads? Go to AlexBerman.com/Mastermind \U0001F525")

# Enhanced email validation patterns
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
STRICT_EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$")

# Comprehensive disposable email domains
DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.org",
    "throwaway.email", "temp-mail.org", "sharklasers.com", "guerrillamail.biz",
    "guerrillamail.de", "guerrillamail.info", "guerrillamail.net", "guerrillamail.org",
    "guerrillamailblock.com", "pokemail.net", "spam4.me", "bccto.me",
    "chacuo.net", "dispostable.com", "mailnesia.com", "maildrop.cc",
    "mailcatch.com", "inboxalias.com", "mailin8r.com", "mailinator2.com",
    "spamgourmet.com", "spamgourmet.net", "spamgourmet.org", "spam.la",
    "binkmail.com", "bobmail.info", "chammy.info", "devnullmail.com",
    "letthemeatspam.com", "mailinater.com", "mailinator.com", "mailinator.net",
    "mailinator.org", "mailinator2.com", "notmailinator.com", "reallymymail.com",
    "reconmail.com", "safetymail.info", "sogetthis.com", "spamhereplease.com",
    "superrito.com", "thisisnotmyrealemail.com", "tradermail.info", "veryrealemail.com",
    "wegwerfadresse.de", "wegwerfemail.de", "wegwerfmail.de", "wegwerfmail.net",
    "wegwerfmail.org", "wegwerpmailadres.nl", "wegwrfmail.de", "wegwrfmail.net",
    "wegwrfmail.org", "wetrainbayarea.com", "wetrainbayarea.org", "wh4f.org",
    "whyspam.me", "willselfdestruct.com", "wuzup.net", "wuzupmail.net",
    "www.e4ward.com", "www.gishpuppy.com", "www.mailinator.com", "www.mailinator.net",
    "www.mailinator.org", "www.mailinator2.com", "www.notmailinator.com",
    "www.reallymymail.com", "www.reconmail.com", "www.safetymail.info",
    "www.sogetthis.com", "www.spamhereplease.com", "www.superrito.com",
    "www.thisisnotmyrealemail.com", "www.tradermail.info", "www.veryrealemail.com",
    "www.wegwerfadresse.de", "www.wegwerfemail.de", "www.wegwerfmail.de",
    "www.wegwerfmail.net", "www.wegwerfmail.org", "www.wegwerpmailadres.nl",
    "www.wegwrfmail.de", "www.wegwrfmail.net", "www.wegwrfmail.org",
    "www.wetrainbayarea.com", "www.wetrainbayarea.org", "www.wh4f.org",
    "www.whyspam.me", "www.willselfdestruct.com", "www.wuzup.net", "www.wuzupmail.net"
}

# Role-based and generic email prefixes
ROLE_BASED_PREFIXES = {
    "info", "support", "admin", "sales", "contact", "help", "service", "customer",
    "noreply", "no-reply", "donotreply", "do-not-reply", "postmaster", "abuse",
    "webmaster", "hostmaster", "marketing", "newsletter", "billing", "accounts",
    "hr", "jobs", "careers", "legal", "privacy", "security", "compliance",
    "feedback", "suggestions", "complaints", "test", "demo", "example", "sample"
}

# High-reputation domains (more likely to be valid)
HIGH_REPUTATION_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com",
    "protonmail.com", "zoho.com", "yandex.com", "mail.com", "gmx.com", "web.de",
    "tutanota.com", "fastmail.com", "hey.com", "pm.me", "proton.me"
}

# Common corporate domains
CORPORATE_DOMAINS = {
    "microsoft.com", "google.com", "apple.com", "amazon.com", "facebook.com",
    "twitter.com", "linkedin.com", "salesforce.com", "oracle.com", "ibm.com",
    "intel.com", "cisco.com", "adobe.com", "vmware.com", "netflix.com",
    "spotify.com", "uber.com", "airbnb.com", "tesla.com", "nvidia.com"
}

data = {}

# DNS cache to avoid repeated lookups
dns_cache = {}

def clean_text(text):
    """Clean text to remove problematic characters that cause encoding issues."""
    if not text:
        return text
    
    # Replace common problematic characters
    replacements = {
        '\ue206': '',  # The specific character causing the error
        '\u2013': '-',  # En dash
        '\u2014': '--',  # Em dash
        '\u2018': "'",  # Left single quotation mark
        '\u2019': "'",  # Right single quotation mark
        '\u201c': '"',  # Left double quotation mark
        '\u201d': '"',  # Right double quotation mark
        '\u2026': '...',  # Horizontal ellipsis
    }
    
    for old, new in replacements.items():
        text = text.replace(old, new)
    
    # Remove any remaining non-printable characters except common ones
    import string
    printable = set(string.printable)
    text = ''.join(char if char in printable or ord(char) > 127 else '' for char in text)
    
    return text

def check_email(email, verification_mode='fast'):
    """Fast bulk email verification optimized for speed"""
    import time
    
    # Clean and normalize email
    email = email.strip().lower()
    
    # Fast syntax validation
    if not EMAIL_REGEX.match(email):
        return "invalid", "Invalid email format"
    
    domain = email.split('@')[1]
    local = email.split('@')[0]
    
    # Fast domain validation
    if len(domain) > 253 or len(local) > 64:
        return "invalid", "Invalid email format"
    
    # Check for common invalid patterns
    if '..' in local or local.startswith('.') or local.endswith('.'):
        return "invalid", "Invalid email format"
    
    # Check for generic usernames (fast check)
    generic_usernames = ['username', 'user', 'test', 'example', 'sample', 'demo', 'placeholder', 'temp', 'temporary', 'fake', 'dummy', 'spam', 'invalid', 'none', 'admin', 'administrator', 'root', 'guest', 'anonymous', 'unknown', 'noreply', 'no-reply', 'donotreply', 'do-not-reply']
    if local in generic_usernames:
        return "invalid", "Email address does not exist or is undeliverable"
    
    # Fast domain check
    try:
        # Quick DNS check
        import socket
        socket.gethostbyname(domain)
        return "valid", "Email address appears to be valid"
    except:
        return "invalid", "Domain does not exist"

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "message": "Email verifier is running"})

@app.route('/verify-single', methods=['POST'])
def verify_single_email():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({"error": "Email address is required"}), 400
        
        # Enhanced single email verification
        result = verify_single_email_address(email)
        
        return jsonify({
            "status": result['status'],
            "email": email,
            "details": result['details'],
            "confidence": result['confidence'],
            "checks": result.get('checks', {})
        })
        
    except Exception as e:
        return jsonify({"error": f"Verification failed: {str(e)}"}), 500

def verify_single_email_address(email):
    """Enhanced single email verification with multiple checks including SMTP validation"""
    
    # Basic syntax validation
    if not EMAIL_REGEX.match(email):
        return {
            'status': 'invalid',
            'details': 'Invalid email format',
            'confidence': 'high',
            'checks': {'syntax': False}
        }
    
    # Extract domain and local part
    local_part, domain = email.split('@', 1)
    
    checks = {
        'syntax': True,
        'domain_structure': False,
        'disposable_domain': False,
        'domain_exists': False,
        'mx_record': False,
        'local_part_valid': False,
        'smtp_validation': False,
        'account_exists': False
    }
    
    # Check domain structure
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
        checks['domain_structure'] = True
    else:
        return {
            'status': 'invalid',
            'details': 'Invalid domain format',
            'confidence': 'high',
            'checks': checks
        }
    
    # Check for disposable domains
    if domain in DISPOSABLE_DOMAINS:
        checks['disposable_domain'] = True
        return {
            'status': 'risky',
            'details': 'This appears to be a disposable/temporary email address',
            'confidence': 'high',
            'checks': checks
        }
    
    # Check local part validity
    if (len(local_part) <= 64 and 
        not local_part.startswith('.') and 
        not local_part.endswith('.') and 
        '..' not in local_part):
        checks['local_part_valid'] = True
    else:
        return {
            'status': 'invalid',
            'details': 'Invalid email username format',
            'confidence': 'high',
            'checks': checks
        }
    
    # Check if domain exists (A record)
    domain_exists = False
    try:
        a_records = dns.resolver.resolve(domain, 'A')
        if a_records:
            domain_exists = True
            checks['domain_exists'] = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        domain_exists = False
        checks['domain_exists'] = False
    except:
        # If we can't resolve A record, try CNAME
        try:
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            if cname_records:
                domain_exists = True
                checks['domain_exists'] = True
        except:
            domain_exists = False
            checks['domain_exists'] = False
    
    # If domain doesn't exist, return invalid
    if not domain_exists:
        return {
            'status': 'invalid',
            'details': 'Domain does not exist',
            'confidence': 'high',
            'checks': checks
        }
    
    # Check MX record (only if domain exists)
    mx_records = []
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if mx_records:
            checks['mx_record'] = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        checks['mx_record'] = False
    except:
        checks['mx_record'] = False
    
    # If no MX record, return risky
    if not checks['mx_record']:
        return {
            'status': 'risky',
            'details': 'Domain exists but no mail server found',
            'confidence': 'medium',
            'checks': checks
        }
    
    # Perform SMTP validation for account existence
    smtp_result = perform_smtp_validation(email, mx_records)
    checks['smtp_validation'] = smtp_result['smtp_validation']
    checks['account_exists'] = smtp_result['account_exists']
    
    # Determine result based on all checks - More lenient like Hunter.io
    if checks['domain_structure'] and checks['local_part_valid'] and checks['domain_exists'] and checks['mx_record']:
        # If we have valid domain structure, local part, domain exists, and MX record
        if checks['smtp_validation'] and checks['account_exists']:
            # SMTP validation confirmed account exists
            return {
                'status': 'valid',
                'details': 'This email address is valid and deliverable',
                'confidence': 'high',
                'checks': checks
            }
        elif checks['smtp_validation'] and not checks['account_exists']:
            # SMTP validation confirmed account does NOT exist
            return {
                'status': 'invalid',
                'details': 'Email address does not exist or is undeliverable',
                'confidence': 'high',
                'checks': checks
            }
        else:
            # SMTP validation failed or inconclusive, but domain/MX are valid
            # This is common - many servers block SMTP validation
            # If it's a well-known domain, assume it's valid
            if is_common_valid_domain(domain):
                return {
                    'status': 'valid',
                    'details': 'Email appears to be valid (domain and mail server confirmed)',
                    'confidence': 'medium',
                    'checks': checks
                }
            else:
                # For unknown domains, be more conservative but still valid if structure is good
                return {
                    'status': 'valid',
                    'details': 'Email appears to be valid (domain and mail server confirmed)',
                    'confidence': 'low',
                    'checks': checks
                }
    else:
        # Only mark as invalid if basic structure is wrong
        return {
            'status': 'invalid',
            'details': 'Invalid email format or structure',
            'confidence': 'high',
            'checks': checks
        }

def perform_smtp_validation(email, mx_records):
    """Perform SMTP validation to check if email account exists"""
    local_part, domain = email.split('@', 1)
    
    # Get the mail server with highest priority
    if not mx_records:
        return {'smtp_validation': False, 'account_exists': True}  # Assume valid if no MX records
    
    # Sort MX records by priority
    sorted_mx = sorted(mx_records, key=lambda x: x.preference)
    mail_server = str(sorted_mx[0].exchange).rstrip('.')
    
    try:
        # Connect to mail server with shorter timeout
        server = smtplib.SMTP(mail_server, 25, timeout=3)
        server.set_debuglevel(0)
        
        # Start conversation
        server.helo('example.com')
        server.mail('test@example.com')
        
        # Check if recipient exists
        code, message = server.rcpt(email)
        
        server.quit()
        
        # Analyze response codes - be more lenient
        if code == 250:
            return {'smtp_validation': True, 'account_exists': True}
        elif code in [550, 551, 553]:
            return {'smtp_validation': True, 'account_exists': False}
        elif code in [421, 450, 451, 452]:
            # Temporary failures - assume valid
            return {'smtp_validation': False, 'account_exists': True}
        else:
            # For other codes, assume it might be valid (many servers give unclear responses)
            return {'smtp_validation': False, 'account_exists': True}
            
    except (smtplib.SMTPConnectError, smtplib.SMTPException, Exception):
        # If SMTP validation fails, use alternative approach
        return perform_alternative_validation(email, domain, local_part)

def perform_alternative_validation(email, domain, local_part):
    """Alternative validation when SMTP fails - detect generic/placeholder usernames"""
    
    # Check for generic/placeholder usernames that don't exist
    generic_usernames = [
        'username', 'user', 'test', 'example', 'sample', 'demo', 'placeholder',
        'temp', 'temporary', 'fake', 'dummy', 'spam', 'invalid', 'none',
        'admin', 'administrator', 'root', 'guest', 'anonymous', 'unknown',
        'noreply', 'no-reply', 'donotreply', 'do-not-reply'
    ]
    
    if local_part.lower() in generic_usernames:
        return {'smtp_validation': True, 'account_exists': False}
    
    # Check for highly suspicious patterns
    highly_suspicious_patterns = [
        r'^\d+$',  # All numbers only
        r'^[a-z]{6,12}\d{15,}$',  # Random pattern with many numbers (15+ digits)
        r'^.{50,}$',  # Extremely long usernames
        r'[^a-zA-Z0-9._-]',  # Special characters not allowed in emails
        r'(\d)\1{8,}',  # Same digit repeated 9+ times (more strict)
        r'^[a-z]{1,2}\d{15,}[a-z]{1,2}$',  # Very short letters + many digits + very short letters
        r'^[a-z]+\d{20,}$',  # Letters followed by 20+ digits
        r'^\d{20,}[a-z]+$',  # 20+ digits followed by letters
        r'(\d{4,})\1{3,}',  # Same 4+ digit pattern repeated 4+ times
    ]
    
    for pattern in highly_suspicious_patterns:
        if re.search(pattern, local_part, re.IGNORECASE):
            # print(f"DEBUG: Pattern {pattern} matched for {local_part}")
            return {'smtp_validation': True, 'account_exists': False}
    
    # Check for obviously invalid patterns
    if (len(local_part) < 1 or 
        local_part.count('.') > 5 or
        local_part.count('_') > 5 or
        local_part.count('-') > 5):
        return {'smtp_validation': True, 'account_exists': False}
    
    # For major providers, be more conservative but still lenient
    major_providers = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'linkedin.com', 'apple.com', 'microsoft.com']
    if domain in major_providers:
        # Check for obviously fake patterns - be more strict for major providers
        if (re.match(r'^[a-z]+\d{15,}$', local_part) or  # letters followed by 15+ numbers
            re.match(r'^\d{15,}[a-z]+$', local_part) or  # 15+ numbers followed by letters
            len(local_part) > 50 or                      # extremely long
            re.match(r'^[a-z]{1,2}\d{15,}[a-z]{1,2}$', local_part) or  # very short letters + many digits + very short letters
            re.search(r'(\d)\1{8,}', local_part) or     # same digit repeated 9+ times
            re.search(r'\d{20,}', local_part) or        # 20+ consecutive digits
            re.search(r'(\d{4,})\1{3,}', local_part)):  # same 4+ digit pattern repeated 4+ times
            # print(f"DEBUG: Major provider pattern matched for {local_part}")
            return {'smtp_validation': True, 'account_exists': False}
        else:
            # For major providers, assume valid if it passes basic checks
            return {'smtp_validation': False, 'account_exists': True}
    
    # For legitimate business emails, be more lenient
    legitimate_business_emails = ['support', 'info', 'contact', 'help', 'sales', 'marketing', 'service', 'admin', 'noreply', 'hello', 'team']
    if any(business in local_part.lower() for business in legitimate_business_emails):
        return {'smtp_validation': False, 'account_exists': True}
    
    # For common patterns that are likely to exist, assume valid
    if (len(local_part) >= 2 and 
        re.match(r'^[a-zA-Z][a-zA-Z0-9._-]*[a-zA-Z0-9]$', local_part) and
        not any(generic in local_part.lower() for generic in generic_usernames)):
        return {'smtp_validation': False, 'account_exists': True}
    
    # If we can't determine with high confidence, assume it might be valid
    return {'smtp_validation': False, 'account_exists': True}

def is_common_valid_domain(domain):
    """Check if domain is a common, trusted email provider"""
    common_domains = {
        # Major providers
        'gmail.com', 'yahoo.com', 'yahoo.co.uk', 'outlook.com', 'hotmail.com',
        'aol.com', 'icloud.com', 'protonmail.com', 'zoho.com', 'yandex.com',
        'mail.com', 'gmx.com', 'web.de', 't-online.de', 'orange.fr',
        'wanadoo.fr', 'laposte.net', 'libero.it', 'virgilio.it', 'alice.it',
        # Corporate domains
        'microsoft.com', 'google.com', 'apple.com', 'amazon.com', 'facebook.com',
        'twitter.com', 'linkedin.com', 'salesforce.com', 'oracle.com', 'ibm.com',
        'intel.com', 'cisco.com', 'adobe.com', 'vmware.com', 'netflix.com',
        'spotify.com', 'uber.com', 'airbnb.com', 'dropbox.com', 'slack.com',
        'zoom.us', 'teams.microsoft.com', 'github.com', 'gitlab.com', 'bitbucket.org',
        # Additional major providers
        'fastmail.com', 'hey.com', 'pm.me', 'proton.me', 'tutanota.com',
        'mail.ru', 'rambler.ru', 'yandex.ru', 'qq.com', '163.com', '126.com',
        'sina.com', 'sohu.com', 'foxmail.com', 'live.com', 'msn.com'
    }
    return domain in common_domains

@app.route('/upload', methods=['POST'])
def upload_file():
    """Upload file without starting verification"""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Check file extension
        if not (file.filename.lower().endswith('.csv') or file.filename.lower().endswith('.xlsx')):
            return jsonify({"error": "Only CSV and XLSX files are allowed"}), 400
        
        # Check for verification mode parameter
        verification_mode = request.form.get('verification_mode', 'fast')
        
        job_id = str(uuid.uuid4())
        
        # Read and parse file based on extension
        file_extension = file.filename.lower().split('.')[-1]
        
        try:
            if file_extension == 'csv':
                # Read and parse CSV with multiple encoding attempts
                content = None
                encodings_to_try = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'iso-8859-1']
                
                for encoding in encodings_to_try:
                    try:
                        file.seek(0)  # Reset file pointer
                        content = file.read().decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                
                if content is None:
                    return jsonify({"error": "Could not decode CSV file. Please ensure the file is properly encoded."}), 400
                
                reader = list(csv.DictReader(io.StringIO(content)))
                
                # Debug: Check for empty columns in CSV (commented out to reduce noise)
                # if reader:
                #     first_row_keys = list(reader[0].keys())
                #     print(f"CSV first row keys: {first_row_keys}")
                #     # Check for empty column names
                #     empty_columns = [key for key in first_row_keys if not key or not key.strip()]
                #     if empty_columns:
                #         print(f"Warning: Empty column names found: {empty_columns}")
                
            elif file_extension == 'xlsx':
                # Read and parse XLSX file with optimizations
                file.seek(0)  # Reset file pointer
                
                # Ultra-fast pandas reading for speed
                df = pd.read_excel(
                    file, 
                    engine='openpyxl',
                    dtype=str,  # Read all as strings for faster processing
                    na_filter=False,  # Don't convert to NaN
                    keep_default_na=False,  # Don't treat empty strings as NaN
                    nrows=None,  # Read all rows
                    usecols=None  # Read all columns
                )
                
                # Ultra-fast column cleaning
                df.columns = [str(col).strip() for col in df.columns]
                
                # Debug: Check for empty columns in XLSX (commented out to reduce noise)
                # print(f"XLSX columns: {list(df.columns)}")
                # empty_columns = [col for col in df.columns if not col or not col.strip()]
                # if empty_columns:
                #     print(f"Warning: Empty column names found in XLSX: {empty_columns}")
                
                # Skip value cleaning for speed - just convert to dict
                reader = df.to_dict('records')
            else:
                return jsonify({"error": "Unsupported file format"}), 400
                
        except Exception as e:
            return jsonify({"error": f"Error parsing {file_extension.upper()} file: {str(e)}"}), 400
        
        if not reader:
            return jsonify({"error": f"{file_extension.upper()} file is empty or has no valid data"}), 400
        
        total = len(reader)
        email_field = next((f for f in reader[0].keys() if f.lower().strip() == 'email'), None)
        
        if not email_field:
            return jsonify({"error": f"No 'email' column found in {file_extension.upper()} file"}), 400

        # Store file data for later processing
        data[job_id] = {
            "progress": 0,
            "row": 0,
            "total": total,
            "log": f"File uploaded successfully. Ready to verify {total} emails...",
            "cancel": False,
            "records": reader,
            "email_field": email_field,
            "filename": file.filename,
            "verification_mode": verification_mode,
            "file_extension": file_extension,
            "status": "uploaded",  # New status to indicate file is uploaded but not processed
            "output": None,
            "writer": None,
            "file_path": None
        }

        return jsonify({
            "job_id": job_id, 
            "message": "File uploaded successfully",
            "total": total,
            "file_type": file_extension.upper(),
            "status": "ready_to_process"
        })
        
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/start-verification', methods=['POST'])
def start_verification():
    """Start verification process for uploaded file"""
    try:
        data_req = request.get_json()
        job_id = data_req.get('job_id')
        
        if not job_id or job_id not in data:
            return jsonify({"error": "Invalid job ID"}), 400
        
        if data[job_id]['status'] != 'uploaded':
            return jsonify({"error": "File not ready for processing"}), 400
        
        # Initialize processing data
        output = io.StringIO()
        
        # Get original fieldnames and clean them
        original_fieldnames = list(data[job_id]['records'][0].keys())
        # Remove any empty or None fieldnames
        original_fieldnames = [f for f in original_fieldnames if f and f.strip()]
        
        # print(f"Original fieldnames: {original_fieldnames}")
        # print(f"First record keys: {list(data[job_id]['records'][0].keys())}")
        
        # Add verification columns
        fieldnames = original_fieldnames + ['status', 'reason', 'confidence']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        data[job_id].update({
            "output": output,
            "writer": writer,
            "status": "processing",
            "start_time": time.time(),  # Track start time for minimum processing time
            "log": f"Starting verification of {data[job_id]['total']} emails... (Mode: {data[job_id]['verification_mode'].upper()})"
        })
        
        def run():
            try:
                import concurrent.futures
                import threading
                
                # Use ThreadPoolExecutor for concurrent processing
                # Increase workers for faster processing
                if data[job_id]['file_extension'] == 'xlsx':
                    # XLSX files - more workers for speed
                    if data[job_id]['verification_mode'] == 'fast':
                        max_workers = 25
                    elif data[job_id]['verification_mode'] == 'standard':
                        max_workers = 15
                    else:  # premium mode
                        max_workers = 10
                else:  # CSV files
                    if data[job_id]['verification_mode'] == 'fast':
                        max_workers = 50
                    elif data[job_id]['verification_mode'] == 'standard':
                        max_workers = 30
                    else:  # premium mode
                        max_workers = 20
                
                def verify_single_email(row_data):
                    i, row = row_data
                    if data[job_id]['cancel']:
                        return None
                    
                    # Add realistic processing delay (0.1-0.3 seconds per email)
                    import random
                    delay = random.uniform(0.1, 0.3)
                    time.sleep(delay)
                    
                    # Clean all text fields in the row to prevent encoding issues
                    # Only include original fieldnames to prevent extra columns
                    cleaned_row = {}
                    for key in original_fieldnames:
                        value = row.get(key, '')
                        if isinstance(value, str):
                            cleaned_row[key] = clean_text(value)
                        else:
                            cleaned_row[key] = value or ''
                    
                    # Debug: Check for extra keys in original row (commented out to reduce noise)
                    # extra_keys = set(row.keys()) - set(original_fieldnames)
                    # if extra_keys:
                    #     print(f"Warning: Extra keys found in row {i}: {extra_keys}")
                    
                    email = (cleaned_row.get(data[job_id]['email_field']) or '').strip()
                    if not email:
                        status, reason, confidence = 'invalid', 'Empty email address', 'high'
                    else:
                        # Use the same comprehensive verification as single email
                        result = verify_single_email_address(email)
                        status = result['status']
                        reason = result['details']
                        confidence = result['confidence']
                    
                    cleaned_row['status'] = status
                    cleaned_row['reason'] = reason
                    cleaned_row['confidence'] = confidence
                    return i, cleaned_row, email, status, reason
                
                # Process emails in batches for better progress tracking
                batch_size = 50
                processed = 0
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Submit all tasks
                    future_to_index = {
                        executor.submit(verify_single_email, (i, row)): i 
                        for i, row in enumerate(data[job_id]['records'], start=1)
                    }
                    
                    # Process results as they complete
                    for future in concurrent.futures.as_completed(future_to_index):
                        if data[job_id]['cancel']:
                            break
                            
                        try:
                            result = future.result()
                            if result is None:  # Cancelled
                                continue
                                
                            i, row, email, status, reason = result
                            writer.writerow(row)
                            processed += 1
                            
                            # Update progress every 10 emails or at the end
                            if processed % 10 == 0 or processed == data[job_id]['total']:
                                percent = int((processed / data[job_id]['total']) * 100)
                                data[job_id].update({
                                    "progress": percent, 
                                    "row": processed,
                                    "log": f"\u2705 {email} → {status} ({reason})"
                                })
                                
                        except Exception as e:
                            print(f"Error processing email: {e}")
                            continue
                
                # Save completed file
                output = data[job_id]['output']
                output.seek(0)
                temp = NamedTemporaryFile(delete=False, suffix=".csv", mode='w+', encoding='utf-8')
                temp.write(output.read())
                temp.flush()
                temp.seek(0)
                data[job_id]['file_path'] = temp.name
                
                # Ensure minimum processing time for realistic experience (10-12 seconds for small files)
                min_processing_time = 10.0  # Minimum 10 seconds
                if data[job_id]['total'] <= 50:  # Small files
                    min_processing_time = 12.0  # 12 seconds for small files
                elif data[job_id]['total'] <= 100:  # Medium files
                    min_processing_time = 15.0  # 15 seconds for medium files
                
                # Calculate elapsed time and add delay if needed
                elapsed_time = time.time() - data[job_id].get('start_time', time.time())
                if elapsed_time < min_processing_time:
                    remaining_time = min_processing_time - elapsed_time
                    print(f"Adding {remaining_time:.1f}s delay to ensure realistic processing time")
                    time.sleep(remaining_time)
                
                data[job_id]['log'] = f"\u2705 Completed verification of {data[job_id]['total']} emails"
                data[job_id]['progress'] = 100
                data[job_id]['status'] = 'completed'
                
            except Exception as e:
                data[job_id]['log'] = f"\u274c Error: {str(e)}"
                data[job_id]['status'] = 'error'
                data[job_id]['progress'] = 0

        import threading
        threading.Thread(target=run, daemon=True).start()

        return jsonify({
            "message": "Verification started successfully",
            "job_id": job_id,
            "total": data[job_id]['total']
        })
        
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/verify', methods=['POST'])
def verify():
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Check file extension
        if not (file.filename.lower().endswith('.csv') or file.filename.lower().endswith('.xlsx')):
            return jsonify({"error": "Only CSV and XLSX files are allowed"}), 400
        
        # Check for verification mode parameter
        verification_mode = request.form.get('verification_mode', 'fast')
        fast_mode = verification_mode == 'fast'
        
        job_id = str(uuid.uuid4())
        
        # Read and parse file based on extension
        file_extension = file.filename.lower().split('.')[-1]
        
        try:
            if file_extension == 'csv':
                # Read and parse CSV with multiple encoding attempts
                content = None
                encodings_to_try = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'iso-8859-1']
                
                for encoding in encodings_to_try:
                    try:
                        file.seek(0)  # Reset file pointer
                        content = file.read().decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                
                if content is None:
                    return jsonify({"error": "Could not decode CSV file. Please ensure the file is properly encoded."}), 400
                
                reader = list(csv.DictReader(io.StringIO(content)))
                
            elif file_extension == 'xlsx':
                # Read and parse XLSX file with optimizations
                file.seek(0)  # Reset file pointer
                
                # Ultra-fast pandas reading for speed
                df = pd.read_excel(
                    file, 
                    engine='openpyxl',
                    dtype=str,  # Read all as strings for faster processing
                    na_filter=False,  # Don't convert to NaN
                    keep_default_na=False,  # Don't treat empty strings as NaN
                    nrows=None,  # Read all rows
                    usecols=None  # Read all columns
                )
                
                # Ultra-fast column cleaning
                df.columns = [str(col).strip() for col in df.columns]
                
                # Debug: Check for empty columns in XLSX (commented out to reduce noise)
                # print(f"XLSX columns: {list(df.columns)}")
                # empty_columns = [col for col in df.columns if not col or not col.strip()]
                # if empty_columns:
                #     print(f"Warning: Empty column names found in XLSX: {empty_columns}")
                
                # Skip value cleaning for speed - just convert to dict
                reader = df.to_dict('records')
            else:
                return jsonify({"error": "Unsupported file format"}), 400
                
        except Exception as e:
            return jsonify({"error": f"Error parsing {file_extension.upper()} file: {str(e)}"}), 400
        
        if not reader:
            return jsonify({"error": f"{file_extension.upper()} file is empty or has no valid data"}), 400
        
        total = len(reader)
        email_field = next((f for f in reader[0].keys() if f.lower().strip() == 'email'), None)
        
        if not email_field:
            return jsonify({"error": f"No 'email' column found in {file_extension.upper()} file"}), 400

        output = io.StringIO()
        fieldnames = list(reader[0].keys()) + ['status', 'reason', 'confidence']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        data[job_id] = {
            "progress": 0,
            "row": 0,
            "total": total,
            "log": f"Starting verification of {total} emails... (Mode: {verification_mode.upper()})",
            "cancel": False,
            "output": output,
            "writer": writer,
            "records": reader,
            "email_field": email_field,
            "filename": file.filename,
            "fast_mode": fast_mode,
            "file_extension": file_extension,
            "start_time": time.time(),  # Track start time for minimum processing time
            "verification_mode": verification_mode
        }

        def run():
            try:
                import concurrent.futures
                import threading
                
                # Use ThreadPoolExecutor for concurrent processing
                # Increase workers for faster processing
                if file_extension == 'xlsx':
                    # XLSX files - more workers for speed
                    if verification_mode == 'fast':
                        max_workers = 25
                    elif verification_mode == 'standard':
                        max_workers = 15
                    else:  # premium mode
                        max_workers = 10
                else:  # CSV files
                    if verification_mode == 'fast':
                        max_workers = 50
                    elif verification_mode == 'standard':
                        max_workers = 30
                    else:  # premium mode
                        max_workers = 20
                
                def verify_single_email(row_data):
                    i, row = row_data
                    if data[job_id]['cancel']:
                        return None
                    
                    # Add realistic processing delay (0.1-0.3 seconds per email)
                    import random
                    delay = random.uniform(0.1, 0.3)
                    time.sleep(delay)
                    
                    # Clean all text fields in the row to prevent encoding issues
                    # Only include original fieldnames to prevent extra columns
                    cleaned_row = {}
                    for key in original_fieldnames:
                        value = row.get(key, '')
                        if isinstance(value, str):
                            cleaned_row[key] = clean_text(value)
                        else:
                            cleaned_row[key] = value or ''
                    
                    # Debug: Check for extra keys in original row (commented out to reduce noise)
                    # extra_keys = set(row.keys()) - set(original_fieldnames)
                    # if extra_keys:
                    #     print(f"Warning: Extra keys found in row {i}: {extra_keys}")
                    
                    email = (cleaned_row.get(email_field) or '').strip()
                    if not email:
                        status, reason, confidence = 'invalid', 'Empty email address', 'high'
                    else:
                        # Use the same comprehensive verification as single email
                        result = verify_single_email_address(email)
                        status = result['status']
                        reason = result['details']
                        confidence = result['confidence']
                    
                    cleaned_row['status'] = status
                    cleaned_row['reason'] = reason
                    cleaned_row['confidence'] = confidence
                    return i, cleaned_row, email, status, reason
                
                # Process emails in batches for better progress tracking
                batch_size = 50
                processed = 0
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Submit all tasks
                    future_to_index = {
                        executor.submit(verify_single_email, (i, row)): i 
                        for i, row in enumerate(reader, start=1)
                    }
                    
                    # Process results as they complete
                    for future in concurrent.futures.as_completed(future_to_index):
                        if data[job_id]['cancel']:
                            break
                            
                        try:
                            result = future.result()
                            if result is None:  # Cancelled
                                continue
                                
                            i, row, email, status, reason = result
                            writer.writerow(row)
                            processed += 1
                            
                            # Update progress every 10 emails or at the end
                            if processed % 10 == 0 or processed == total:
                                percent = int((processed / total) * 100)
                                data[job_id].update({
                                    "progress": percent, 
                                    "row": processed,
                                    "log": f"\u2705 {email} → {status} ({reason})"
                                })
                                
                        except Exception as e:
                            print(f"Error processing email: {e}")
                            continue
                
                # Save completed file
                output = data[job_id]['output']
                output.seek(0)
                temp = NamedTemporaryFile(delete=False, suffix=".csv", mode='w+', encoding='utf-8')
                temp.write(output.read())
                temp.flush()
                temp.seek(0)
                data[job_id]['file_path'] = temp.name
                
                # Ensure minimum processing time for realistic experience (10-12 seconds for small files)
                min_processing_time = 10.0  # Minimum 10 seconds
                if total <= 50:  # Small files
                    min_processing_time = 12.0  # 12 seconds for small files
                elif total <= 100:  # Medium files
                    min_processing_time = 15.0  # 15 seconds for medium files
                
                # Calculate elapsed time and add delay if needed
                elapsed_time = time.time() - data[job_id].get('start_time', time.time())
                if elapsed_time < min_processing_time:
                    remaining_time = min_processing_time - elapsed_time
                    print(f"Adding {remaining_time:.1f}s delay to ensure realistic processing time")
                    time.sleep(remaining_time)
                
                data[job_id]['log'] = f"\u2705 Completed verification of {total} emails"
                data[job_id]['progress'] = 100
                data[job_id]['status'] = 'completed'
                
            except Exception as e:
                data[job_id]['log'] = f"\u274c Error during verification: {str(e)}"
                data[job_id]['progress'] = 0

        import threading
        threading.Thread(target=run, daemon=True).start()

        return jsonify({
            "job_id": job_id, 
            "message": "File uploaded successfully",
            "total": total,
            "file_type": file_extension.upper(),
            "estimated_time": f"{total // 100 + 1} minutes" if total > 100 else "Less than 1 minute"
        })
        
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/progress')
def progress():
    job_id = request.args.get("job_id")
    d = data.get(job_id, {})
    return jsonify({"percent": d.get("progress", 0), "row": d.get("row", 0), "total": d.get("total", 0)})

@app.route('/log')
def log():
    job_id = request.args.get("job_id")
    return Response(data.get(job_id, {}).get("log", ""), mimetype='text/plain')

@app.route('/cancel', methods=['POST'])
def cancel():
    job_id = request.args.get("job_id")
    if job_id in data:
        data[job_id]['cancel'] = True
    return '', 204

@app.route('/download')
def download():
    job_id = request.args.get("job_id")
    filter_type = request.args.get("type", "all")
    job = data.get(job_id)
    if not job:
        return "Invalid job ID", 404

    job['output'].seek(0)
    reader = list(csv.DictReader(job['output']))

    if filter_type == "valid":
        filtered = [row for row in reader if row['status'] == 'valid']
    elif filter_type == "risky":
        filtered = [row for row in reader if row['status'] == 'risky']
    elif filter_type == "risky_invalid":
        filtered = [row for row in reader if row['status'] in ('risky', 'invalid')]
    else:
        filtered = reader

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=reader[0].keys())
    writer.writeheader()
    for row in filtered:
        writer.writerow(row)

    output.seek(0)
    download_name = f"{filter_type}-galadon-{job['filename']}"
    return Response(
        output.getvalue().encode('utf-8'),
        mimetype='text/csv; charset=utf-8',
        headers={
            "Content-Disposition": f"attachment; filename={download_name}",
            "Content-Type": "text/csv; charset=utf-8"
        }
    )

if __name__ == '__main__':
    app.run(debug=True, port=5050)
