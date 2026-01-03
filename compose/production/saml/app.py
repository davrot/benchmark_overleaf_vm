from flask import Flask, request, redirect, render_template_string, session, make_response
import secrets
import time
from datetime import datetime, timedelta
from lxml import etree
import base64
import zlib
from urllib.parse import urlencode, parse_qs, urlparse, unquote
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import uuid

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
IDP_ENTITY_ID = "https://overleaf.local/saml/idp"
SP_ENTITY_ID = "MyOverleaf"
SP_ACS_URL = "https://overleaf.local/saml/login/callback"
SP_SLS_URL = "https://overleaf.local/saml/logout/callback"

# Generate RSA key pair for signing
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Generate self-signed certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Test"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Test"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SAML Test IdP"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"overleaf.local"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    public_key
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.utcnow()
).not_valid_after(
    datetime.utcnow() + timedelta(days=3650)
).sign(private_key, hashes.SHA256())

# In-memory storage
auth_requests = {}
users = {
    "test@example.com": {
        "email": "test@example.com",
        "givenName": "Test",
        "sn": "User",
        "mail": "test@example.com",
        "password": "password"
    },
    "admin@example.com": {
        "email": "admin@example.com",
        "givenName": "Admin",
        "sn": "User",
        "mail": "admin@example.com",
        "is_admin": "true",
        "password": "admin",
    },
    "overleaf.admin@example.com": {
        "email": "overleaf.admin@example.com",
        "givenName": "Super",
        "sn": "Admin",
        "mail": "overleaf.admin@example.com",
        "is_admin": "true",
        "password": "admin",
    }
}

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>SAML IdP Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }
        .login-box {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        h2 {
            margin-top: 0;
            color: #333;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #666;
        }
        input {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 0.75rem;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1rem;
        }
        button:hover {
            background: #0056b3;
        }
        .error {
            color: #dc3545;
            margin-bottom: 1rem;
            padding: 0.75rem;
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
        }
        .hint {
            margin-top: 1rem;
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 4px;
            font-size: 0.875rem;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>SAML IdP Login</h2>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <input type="hidden" name="SAMLRequest" value="{{ saml_request }}">
            <input type="hidden" name="RelayState" value="{{ relay_state }}">
            <button type="submit">Login</button>
        </form>
        <div class="hint">
            <strong>Test Accounts:</strong><br>
            • test@example.com / password<br>
            • admin@example.com / admin<br>
            • overleaf.admin@example.com / admin (super admin)
        </div>
    </div>
</body>
</html>
"""

def decode_saml_request(saml_request):
    """Decode and inflate SAML request"""
    decoded = base64.b64decode(saml_request)
    inflated = zlib.decompress(decoded, -15)
    return etree.fromstring(inflated)

def create_saml_response(user, request_id, acs_url, session_index):
    """Create SAML Response XML"""
    now = datetime.utcnow()
    issue_instant = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    not_before = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    not_on_or_after = (now + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    assertion_id = f"__{uuid.uuid4().hex}"
    response_id = f"__{uuid.uuid4().hex}"
    
    # Create attribute statements
    attributes = []
    for key, value in user.items():
        if key != 'password':
            attributes.append(f'''
                <saml:Attribute Name="{key}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
                                         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                                         xsi:type="xs:string">{value}</saml:AttributeValue>
                </saml:Attribute>''')
    
    attributes_xml = '\n'.join(attributes)
    
    saml_response = f'''<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{response_id}"
                Version="2.0"
                IssueInstant="{issue_instant}"
                Destination="{acs_url}"
                InResponseTo="{request_id}">
    <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{assertion_id}"
                    Version="2.0"
                    IssueInstant="{issue_instant}">
        <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user['email']}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}"
                                              Recipient="{acs_url}"
                                              InResponseTo="{request_id}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
            <saml:AudienceRestriction>
                <saml:Audience>{SP_ENTITY_ID}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="{session_index}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            {attributes_xml}
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>'''
    
    return saml_response

@app.route("/")
@app.route("/health")
def health():
    """Health check endpoint"""
    return {"status": "ok", "service": "saml-emulator"}

@app.route("/saml/idp/metadata")
def metadata():
    """IdP Metadata endpoint"""
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    cert_data = cert_pem.replace('-----BEGIN CERTIFICATE-----\n', '').replace('-----END CERTIFICATE-----\n', '').replace('\n', '')
    
    sso_url = "https://overleaf.local/saml/idp/SSOService"
    slo_url = "https://overleaf.local/saml/idp/SingleLogoutService"
    
    metadata_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="{IDP_ENTITY_ID}">
    <IDPSSODescriptor WantAuthnRequestsSigned="false"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{cert_data}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </KeyDescriptor>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                           Location="{slo_url}"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                           Location="{slo_url}"/>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="{sso_url}"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="{sso_url}"/>
    </IDPSSODescriptor>
</EntityDescriptor>'''
    
    response = make_response(metadata_xml)
    response.headers['Content-Type'] = 'application/xml'
    return response

@app.route("/saml/idp/SSOService", methods=['GET', 'POST'])
def sso_service():
    """Single Sign-On Service - receives AuthnRequest"""
    if request.method == 'GET':
        saml_request = request.args.get('SAMLRequest')
        relay_state = request.args.get('RelayState', '')
    else:
        saml_request = request.form.get('SAMLRequest')
        relay_state = request.form.get('RelayState', '')
    
    if not saml_request:
        return "Missing SAMLRequest parameter", 400
    
    try:
        # Decode and parse SAML request
        authn_request = decode_saml_request(saml_request)
        request_id = authn_request.get('ID')
        acs_url = authn_request.get('AssertionConsumerServiceURL', SP_ACS_URL)
        
        # Store request info
        auth_requests[request_id] = {
            'acs_url': acs_url,
            'relay_state': relay_state,
            'timestamp': time.time()
        }
        
        return render_template_string(
            LOGIN_PAGE,
            error=None,
            saml_request=saml_request,
            relay_state=relay_state
        )
    except Exception as e:
        print(f"Error processing SAML request: {e}")
        return f"Error processing SAML request: {e}", 400

@app.route("/saml/idp/SSOService", methods=['POST'])
def sso_service_post():
    """Handle login form submission"""
    email = request.form.get('email')
    password = request.form.get('password')
    
    # Check if this is a login form submission or SAML request redirect
    if email and password:
        # This is a login form POST
        saml_request_b64 = request.form.get('SAMLRequest')
        relay_state = request.form.get('RelayState', '')
        
        # Validate credentials
        user = users.get(email)
        if not user or user['password'] != password:
            return render_template_string(
                LOGIN_PAGE,
                error="Invalid credentials",
                saml_request=saml_request_b64,
                relay_state=relay_state
            )
        
        try:
            # Decode SAML request to get request ID and ACS URL
            authn_request = decode_saml_request(saml_request_b64)
            request_id = authn_request.get('ID')
            acs_url = authn_request.get('AssertionConsumerServiceURL', SP_ACS_URL)
            
            # Store session info
            session_index = f"__{uuid.uuid4().hex}"
            
            # Create SAML response
            saml_response_xml = create_saml_response(user, request_id, acs_url, session_index)
            
            # Base64 encode the response
            saml_response_b64 = base64.b64encode(saml_response_xml.encode('utf-8')).decode('utf-8')
            
            print(f"DEBUG - Created SAML response for {email}, sessionIndex: {session_index}")
            
            # Create auto-submit form
            form_html = f'''
<!DOCTYPE html>
<html>
<head>
    <title>SAML Response</title>
</head>
<body onload="document.forms[0].submit()">
    <form method="POST" action="{acs_url}">
        <input type="hidden" name="SAMLResponse" value="{saml_response_b64}"/>
        <input type="hidden" name="RelayState" value="{relay_state}"/>
        <noscript>
            <button type="submit">Continue</button>
        </noscript>
    </form>
</body>
</html>'''
            
            return form_html
            
        except Exception as e:
            print(f"Error creating SAML response: {e}")
            import traceback
            traceback.print_exc()
            return f"Error creating SAML response: {e}", 500
    else:
        # This is a SAML POST binding request (not implemented in this simple emulator)
        return "HTTP-POST binding not supported, use HTTP-Redirect", 400

@app.route("/saml/idp/SingleLogoutService", methods=['GET', 'POST'])
def single_logout_service():
    """Single Logout Service"""
    session.clear()
    
    if request.method == 'GET':
        relay_state = request.args.get('RelayState', '')
    else:
        relay_state = request.form.get('RelayState', '')
    
    # For simplicity, just redirect back to SP
    if relay_state:
        return redirect(relay_state)
    
    return "Logged out successfully", 200

@app.route("/saml/idp/certs/idp_cert.pem")
def get_certificate():
    """Download IdP certificate"""
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    response = make_response(cert_pem)
    response.headers['Content-Type'] = 'application/x-pem-file'
    response.headers['Content-Disposition'] = 'attachment; filename=idp_cert.pem'
    return response

if __name__ == "__main__":
    # Print certificate for configuration
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    print("=" * 80)
    print("SAML IdP Certificate (save as idp_cert.pem):")
    print("=" * 80)
    print(cert_pem)
    print("=" * 80)
    
    app.run(host="0.0.0.0", port=8081, debug=True)