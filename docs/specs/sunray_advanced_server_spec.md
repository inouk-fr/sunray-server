# Sunray Advanced Server Specification

## 🎯 Overview

This document specifies the advanced features available in the Sunray Advanced edition Admin Server (Odoo addon). These features extend the core functionality described in [sunray_admin_server_spec_v3.md](./sunray_admin_server_spec_v3.md).

## 📦 Module Structure

The advanced features are implemented in the `sunray_advanced` addon that depends on `sunray_core`:

```python
# sunray_advanced/__manifest__.py
{
    'name': 'Sunray Advanced',
    'version': '1.0.0',
    'category': 'Security',
    'depends': ['sunray_core'],
    'license': 'OPL-1',  # Odoo Proprietary License
    'price': 108.00,
    'currency': 'EUR',
    'data': [
        'security/advanced_security.xml',
        'security/ir.model.access.csv',
        'views/advanced_menu.xml',
        'views/totp_views.xml',
        'views/advanced_dashboard.xml',
        'views/compliance_views.xml',
        'data/advanced_cron.xml',
        'wizards/bulk_operations_wizard.xml',
    ],
    'assets': {
        'web.assets_backend': [
            'sunray_advanced/static/src/js/dashboard_advanced.js',
            'sunray_advanced/static/src/css/advanced.css',
        ],
    },
}
```

## 🗄️ Advanced Data Models

### sunray.user (Extended)

```python
class SunrayUser(models.Model):
    _inherit = 'sunray.user'
    
    # TOTP fields
    totp_secret = fields.Char(string='TOTP Secret', readonly=True, groups='sunray_advanced.group_admin')
    totp_enabled = fields.Boolean(string='TOTP Enabled', default=False)
    totp_verified_at = fields.Datetime(string='Last TOTP Verification')
    totp_backup_codes = fields.Text(string='Backup Codes (Encrypted)')
    
    # Risk assessment
    risk_score = fields.Float(string='Risk Score', compute='_compute_risk_score', store=True)
    trust_level = fields.Selection([
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('trusted', 'Trusted')
    ], default='medium', string='Trust Level')
    
    # Advanced session management
    session_ip_binding = fields.Selection([
        ('none', 'No Binding'),
        ('soft', 'Soft Binding (Warning)'),
        ('strict', 'Strict Binding (Block)')
    ], default='soft', string='IP Binding Policy')
    
    allowed_countries = fields.Text(string='Allowed Countries (JSON)', default='[]',
                                   help='ISO country codes, empty = all allowed')
    access_schedule = fields.Text(string='Access Schedule (JSON)',
                                 help='Time-based access rules')
    
    # Compliance fields
    last_security_review = fields.Datetime(string='Last Security Review')
    compliance_notes = fields.Text(string='Compliance Notes')
    data_classification = fields.Selection([
        ('public', 'Public'),
        ('internal', 'Internal'),
        ('confidential', 'Confidential'),
        ('restricted', 'Restricted')
    ], default='internal')
    
    @api.model
    def generate_totp_secret(self):
        """Generate and return TOTP provisioning URI"""
        import pyotp
        import qrcode
        from io import BytesIO
        import base64
        
        # Generate secret
        secret = pyotp.random_base32()
        self.totp_secret = secret
        
        # Create provisioning URI
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=self.email,
            issuer_name='Sunray'
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_image = base64.b64encode(buffer.getvalue()).decode()
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        self.totp_backup_codes = self._encrypt_backup_codes(backup_codes)
        
        return {
            'secret': secret,
            'uri': provisioning_uri,
            'qr_image': f'data:image/png;base64,{qr_image}',
            'backup_codes': backup_codes
        }
    
    def verify_totp(self, code):
        """Verify TOTP code"""
        if not self.totp_enabled or not self.totp_secret:
            return False
        
        import pyotp
        totp = pyotp.TOTP(self.totp_secret)
        
        # Check regular code
        if totp.verify(code, valid_window=1):
            self.totp_verified_at = fields.Datetime.now()
            return True
        
        # Check backup codes
        backup_codes = self._decrypt_backup_codes()
        if code in backup_codes:
            backup_codes.remove(code)
            self.totp_backup_codes = self._encrypt_backup_codes(backup_codes)
            self.totp_verified_at = fields.Datetime.now()
            return True
        
        return False
    
    @api.depends('passkey_ids', 'last_login', 'audit_log_ids')
    def _compute_risk_score(self):
        """Calculate user risk score based on behavior"""
        for user in self:
            score = 0.0
            
            # No passkeys = higher risk
            if not user.passkey_ids:
                score += 0.3
            
            # Inactive for long time
            if user.last_login:
                days_inactive = (fields.Datetime.now() - user.last_login).days
                if days_inactive > 90:
                    score += 0.2
                elif days_inactive > 30:
                    score += 0.1
            
            # Recent failed attempts
            recent_failures = self.env['sunray.audit.log'].search_count([
                ('user_id', '=', user.id),
                ('event_type', '=', 'auth.failure'),
                ('timestamp', '>', fields.Datetime.now() - timedelta(days=7))
            ])
            if recent_failures > 10:
                score += 0.3
            elif recent_failures > 5:
                score += 0.2
            
            user.risk_score = min(score, 1.0)
```

### sunray.host (Extended)

```python
class SunrayHost(models.Model):
    _inherit = 'sunray.host'
    
    # TOTP enforcement
    require_totp = fields.Boolean(string='Require TOTP', default=False,
                                 help='Require TOTP in addition to passkey')
    totp_enforcement_mode = fields.Selection([
        ('all', 'All Users'),
        ('high_risk', 'High Risk Only (score > 0.7)'),
        ('specific', 'Specific Users/Groups')
    ], default='all', string='TOTP Enforcement')
    totp_grace_period_s = fields.Integer(string='TOTP Grace Period (seconds)',
                                        default=3600,
                                        help='How long TOTP verification remains valid')
    totp_required_users = fields.Many2many('sunray.user', 
                                          'sunray_host_totp_users_rel',
                                          string='TOTP Required Users')
    
    # Advanced access control
    min_trust_level = fields.Selection([
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('trusted', 'Trusted Only')
    ], default='low', string='Minimum Trust Level')
    
    blocked_countries = fields.Text(string='Blocked Countries (JSON)', default='[]',
                                   help='ISO country codes to block')
    
    # Rate limiting
    rate_limit_enabled = fields.Boolean(string='Enable Rate Limiting', default=True)
    rate_limit_window_s = fields.Integer(string='Rate Limit Window (seconds)', default=60)
    rate_limit_max_requests = fields.Integer(string='Max Requests per Window', default=100)
    
    # Compliance
    compliance_mode = fields.Selection([
        ('none', 'None'),
        ('gdpr', 'GDPR'),
        ('hipaa', 'HIPAA'),
        ('pci', 'PCI-DSS'),
        ('sox', 'SOX')
    ], string='Compliance Mode')
    
    audit_retention_days = fields.Integer(string='Audit Log Retention (days)', 
                                         default=90,
                                         help='0 = unlimited')
```

### sunray.security.alert

```python
class SunraySecurityAlert(models.Model):
    _name = 'sunray.security.alert'
    _description = 'Security Alert'
    _order = 'timestamp desc'
    
    timestamp = fields.Datetime(default=fields.Datetime.now, required=True)
    severity = fields.Selection([
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ], required=True)
    
    alert_type = fields.Selection([
        ('impossible_travel', 'Impossible Travel'),
        ('brute_force', 'Brute Force Attempt'),
        ('suspicious_ip', 'Suspicious IP'),
        ('automated_access', 'Automated Access'),
        ('data_exfiltration', 'Potential Data Exfiltration'),
        ('privilege_escalation', 'Privilege Escalation Attempt'),
        ('emergency_access', 'Emergency Access Used')
    ], required=True)
    
    user_id = fields.Many2one('sunray.user')
    host_id = fields.Many2one('sunray.host')
    ip_address = fields.Char(string='IP Address')
    
    details = fields.Text(string='Alert Details (JSON)')
    resolved = fields.Boolean(string='Resolved', default=False)
    resolved_by = fields.Many2one('res.users')
    resolved_at = fields.Datetime()
    resolution_notes = fields.Text()
    
    # Automated response
    auto_response_taken = fields.Boolean(default=False)
    auto_response_action = fields.Text(string='Automated Action Taken')
    
    def take_automated_action(self):
        """Execute automated response based on alert type and severity"""
        if self.severity == 'critical':
            if self.alert_type == 'brute_force':
                # Block IP
                self._block_ip_address()
            elif self.alert_type == 'impossible_travel':
                # Suspend user
                self._suspend_user()
            elif self.alert_type == 'data_exfiltration':
                # Revoke all sessions
                self._revoke_all_sessions()
        
        self.auto_response_taken = True
        self.auto_response_action = f'Automated response at {fields.Datetime.now()}'
```

### sunray.compliance.report

```python
class SunrayComplianceReport(models.Model):
    _name = 'sunray.compliance.report'
    _description = 'Compliance Report'
    
    name = fields.Char(string='Report Name', required=True)
    report_type = fields.Selection([
        ('gdpr_access', 'GDPR Access Report'),
        ('gdpr_deletion', 'GDPR Deletion Report'),
        ('audit_trail', 'Audit Trail Report'),
        ('access_review', 'Access Review Report'),
        ('security_posture', 'Security Posture Report')
    ], required=True)
    
    generated_date = fields.Datetime(default=fields.Datetime.now)
    generated_by = fields.Many2one('res.users', default=lambda self: self.env.user)
    
    start_date = fields.Datetime(string='Period Start')
    end_date = fields.Datetime(string='Period End')
    
    # Report data
    report_data = fields.Text(string='Report Data (JSON)')
    report_file = fields.Binary(string='Report File')
    report_filename = fields.Char(string='Filename')
    
    # Compliance scores
    compliance_score = fields.Float(string='Compliance Score (%)')
    findings_count = fields.Integer(string='Findings')
    critical_findings = fields.Integer(string='Critical Findings')
    
    @api.model
    def generate_gdpr_report(self, user_id):
        """Generate GDPR data access report for a user"""
        user_obj = self.env['sunray.user'].browse(user_id)
        
        report_data = {
            'user': {
                'username': user_obj.username,
                'email': user_obj.email,
                'created': user_obj.create_date.isoformat(),
                'last_login': user_obj.last_login.isoformat() if user_obj.last_login else None
            },
            'passkeys': [],
            'sessions': [],
            'audit_logs': []
        }
        
        # Collect passkey data
        for passkey in user_obj.passkey_ids:
            report_data['passkeys'].append({
                'name': passkey.name,
                'created': passkey.create_date.isoformat(),
                'last_used': passkey.last_used.isoformat() if passkey.last_used else None
            })
        
        # Collect audit logs
        logs = self.env['sunray.audit.log'].search([
            ('user_id', '=', user_id),
            ('timestamp', '>', fields.Datetime.now() - timedelta(days=90))
        ])
        
        for log in logs:
            report_data['audit_logs'].append({
                'timestamp': log.timestamp.isoformat(),
                'event': log.event_type,
                'ip': log.ip_address
            })
        
        # Create report
        report = self.create({
            'name': f'GDPR Report - {user_obj.username}',
            'report_type': 'gdpr_access',
            'report_data': json.dumps(report_data, indent=2)
        })
        
        return report
```

## 🔌 Advanced API Endpoints

### TOTP Management

```python
@http.route('/sunray-srvr/v1/advanced/verify-totp', type='json', auth='none', methods=['POST'])
def verify_totp(self, session_id, totp_code, **kwargs):
    """Verify TOTP code for a session"""
    if not self._authenticate_api(request):
        return {'error': 'Unauthorized'}, 401
    
    # Get session data from Worker
    session_obj = self.env['sunray.session'].sudo().search([
        ('session_id', '=', session_id),
        ('is_active', '=', True)
    ])
    
    if not session_obj:
        return {'error': 'Invalid session'}, 404
    
    # Verify TOTP
    if session_obj.user_id.verify_totp(totp_code):
        session_obj.totp_verified = True
        session_obj.totp_verified_at = fields.Datetime.now()
        
        # Log successful verification
        self.env['sunray.audit.log'].sudo().create({
            'event_type': 'totp.success',
            'user_id': session_obj.user_id.id,
            'username': session_obj.user_id.username,
            'details': json.dumps({'session_id': session_id})
        })
        
        return {'success': True}
    
    # Log failure
    self.env['sunray.audit.log'].sudo().create({
        'event_type': 'totp.failure',
        'user_id': session_obj.user_id.id,
        'username': session_obj.user_id.username,
        'details': json.dumps({'session_id': session_id})
    })
    
    return {'error': 'Invalid TOTP code'}, 401
```

### Security Monitoring

```python
@http.route('/sunray-srvr/v1/advanced/security-alerts', type='json', auth='none', methods=['POST'])
def report_security_alert(self, anomalies, session_id=None, username=None, **kwargs):
    """Receive security alerts from Worker"""
    if not self._authenticate_api(request):
        return {'error': 'Unauthorized'}, 401
    
    for anomaly in anomalies:
        # Create alert
        alert_obj = request.env['sunray.security.alert'].sudo().create({
            'timestamp': fields.Datetime.now(),
            'severity': anomaly.get('severity', 'medium'),
            'alert_type': anomaly.get('type', 'unknown').lower(),
            'details': json.dumps(anomaly.get('details', {})),
            'ip_address': kwargs.get('ip_address'),
            'user_id': self._get_user_by_username(username).id if username else False
        })
        
        # Take automated action if configured
        if alert_obj.severity in ['high', 'critical']:
            alert_obj.take_automated_action()
        
        # Send notifications
        if alert_obj.severity == 'critical':
            self._send_critical_alert_notification(alert_obj)
    
    return {'success': True, 'alerts_created': len(anomalies)}
```

### Emergency Access

```python
@http.route('/sunray-srvr/v1/advanced/emergency-access', type='json', auth='none', methods=['POST'])
def request_emergency_access(self, username, justification, duration_minutes=60, **kwargs):
    """Handle emergency access requests"""
    if not self._authenticate_api(request):
        return {'error': 'Unauthorized'}, 401
    
    user_obj = self.env['sunray.user'].sudo().search([
        ('username', '=', username),
        ('is_active', '=', True)
    ])
    
    if not user_obj:
        return {'error': 'User not found'}, 404
    
    # Create emergency token
    emergency_token = secrets.token_urlsafe(32)
    expires_at = fields.Datetime.now() + timedelta(minutes=duration_minutes)
    
    # Create emergency access record
    access_obj = self.env['sunray.emergency.access'].sudo().create({
        'user_id': user_obj.id,
        'token': emergency_token,
        'justification': justification,
        'expires_at': expires_at,
        'request_ip': kwargs.get('request_ip'),
        'approved_by': self.env.user.id  # Auto-approve for now
    })
    
    # Create security alert
    self.env['sunray.security.alert'].sudo().create({
        'timestamp': fields.Datetime.now(),
        'severity': 'high',
        'alert_type': 'emergency_access',
        'user_id': user_obj.id,
        'details': json.dumps({
            'justification': justification,
            'duration_minutes': duration_minutes,
            'expires_at': expires_at.isoformat()
        })
    })
    
    # Send notifications
    self._notify_security_team({
        'type': 'EMERGENCY_ACCESS_GRANTED',
        'user': username,
        'justification': justification,
        'expires_at': expires_at
    })
    
    return {
        'token': emergency_token,
        'expires_at': expires_at.isoformat()
    }
```

## 🖥️ Advanced Admin Interface

### Advanced Dashboard

```xml
<record id="view_sunray_advanced_dashboard" model="ir.ui.view">
    <field name="name">sunray.advanced.dashboard</field>
    <field name="model">sunray.dashboard</field>
    <field name="arch" type="xml">
        <dashboard>
            <view type="graph" ref="view_security_alerts_graph"/>
            <group>
                <aggregate name="total_alerts" string="Security Alerts (7d)" 
                          field="alert_count" group_operator="sum"/>
                <aggregate name="critical_alerts" string="Critical Alerts" 
                          field="critical_count" group_operator="sum"/>
                <aggregate name="risk_score_avg" string="Avg Risk Score" 
                          field="risk_score" group_operator="avg"/>
            </group>
            
            <view type="pie" ref="view_compliance_scores_pie"/>
            <view type="line" ref="view_totp_adoption_line"/>
            
            <group string="Real-time Monitoring">
                <widget name="web_map" attrs="{'lat_field': 'latitude', 'lng_field': 'longitude'}"/>
                <widget name="activity_stream" model="sunray.audit.log"/>
            </group>
        </dashboard>
    </field>
</record>
```

### TOTP Setup Wizard

```python
class TOTPSetupWizard(models.TransientModel):
    _name = 'sunray.totp.setup.wizard'
    _description = 'TOTP Setup Wizard'
    
    user_id = fields.Many2one('sunray.user', required=True)
    qr_image = fields.Binary(string='QR Code', readonly=True)
    secret = fields.Char(string='Secret Key', readonly=True)
    backup_codes = fields.Text(string='Backup Codes', readonly=True)
    verification_code = fields.Char(string='Verification Code', 
                                  help='Enter code from your authenticator app')
    
    @api.model
    def default_get(self, fields):
        res = super().default_get(fields)
        
        user_id = self.env.context.get('active_id')
        if user_id:
            user_obj = self.env['sunray.user'].browse(user_id)
            totp_data = user_obj.generate_totp_secret()
            
            res.update({
                'user_id': user_id,
                'qr_image': totp_data['qr_image'].split(',')[1],  # Remove data:image prefix
                'secret': totp_data['secret'],
                'backup_codes': '\n'.join(totp_data['backup_codes'])
            })
        
        return res
    
    def confirm_setup(self):
        """Verify code and enable TOTP"""
        if self.user_id.verify_totp(self.verification_code):
            self.user_id.totp_enabled = True
            
            # Log activation
            self.env['sunray.audit.log'].create({
                'event_type': 'totp.enabled',
                'user_id': self.user_id.id,
                'username': self.user_id.username,
                'details': json.dumps({'setup_by': self.env.user.name})
            })
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'type': 'success',
                    'title': 'TOTP Enabled',
                    'message': 'Two-factor authentication has been successfully enabled.',
                    'sticky': False,
                }
            }
        else:
            raise UserError('Invalid verification code. Please try again.')
```

## 🔄 Advanced Scheduled Actions

```xml
<!-- Advanced security monitoring -->
<record id="ir_cron_security_monitoring" model="ir.cron">
    <field name="name">Sunray Advanced: Security Monitoring</field>
    <field name="model_id" ref="model_sunray_security_monitor"/>
    <field name="state">code</field>
    <field name="code">model.run_security_checks()</field>
    <field name="interval_number">5</field>
    <field name="interval_type">minutes</field>
    <field name="numbercall">-1</field>
    <field name="active">True</field>
</record>

<!-- Compliance reporting -->
<record id="ir_cron_compliance_report" model="ir.cron">
    <field name="name">Sunray Advanced: Weekly Compliance Report</field>
    <field name="model_id" ref="model_sunray_compliance_report"/>
    <field name="state">code</field>
    <field name="code">model.generate_weekly_report()</field>
    <field name="interval_number">1</field>
    <field name="interval_type">weeks</field>
    <field name="numbercall">-1</field>
    <field name="active">True</field>
</record>

<!-- License validation -->
<record id="ir_cron_license_check" model="ir.cron">
    <field name="name">Sunray Advanced: License Validation</field>
    <field name="model_id" ref="model_sunray_license"/>
    <field name="state">code</field>
    <field name="code">model.validate_license()</field>
    <field name="interval_number">1</field>
    <field name="interval_type">days</field>
    <field name="numbercall">-1</field>
    <field name="active">True</field>
</record>
```

## 📊 Advanced Reporting

### Security Posture Report

```python
@api.model
def generate_security_posture_report(self):
    """Generate comprehensive security posture report"""
    report_data = {
        'generated_at': fields.Datetime.now().isoformat(),
        'metrics': {},
        'findings': [],
        'recommendations': []
    }
    
    # Calculate metrics
    total_users = self.env['sunray.user'].search_count([('is_active', '=', True)])
    totp_enabled = self.env['sunray.user'].search_count([
        ('is_active', '=', True),
        ('totp_enabled', '=', True)
    ])
    
    report_data['metrics'] = {
        'total_users': total_users,
        'totp_adoption_rate': (totp_enabled / total_users * 100) if total_users else 0,
        'avg_risk_score': self.env['sunray.user'].search([
            ('is_active', '=', True)
        ]).mapped('risk_score'),
        'unresolved_alerts': self.env['sunray.security.alert'].search_count([
            ('resolved', '=', False)
        ]),
        'critical_alerts_7d': self.env['sunray.security.alert'].search_count([
            ('severity', '=', 'critical'),
            ('timestamp', '>', fields.Datetime.now() - timedelta(days=7))
        ])
    }
    
    # Identify findings
    # Users without passkeys
    no_passkey_users = self.env['sunray.user'].search([
        ('is_active', '=', True),
        ('passkey_ids', '=', False)
    ])
    if no_passkey_users:
        report_data['findings'].append({
            'severity': 'high',
            'title': 'Users without passkeys',
            'count': len(no_passkey_users),
            'users': no_passkey_users.mapped('username')
        })
    
    # High-risk users without TOTP
    high_risk_no_totp = self.env['sunray.user'].search([
        ('is_active', '=', True),
        ('risk_score', '>', 0.7),
        ('totp_enabled', '=', False)
    ])
    if high_risk_no_totp:
        report_data['findings'].append({
            'severity': 'critical',
            'title': 'High-risk users without TOTP',
            'count': len(high_risk_no_totp),
            'users': high_risk_no_totp.mapped('username')
        })
    
    # Generate recommendations
    if report_data['metrics']['totp_adoption_rate'] < 50:
        report_data['recommendations'].append({
            'priority': 'high',
            'action': 'Increase TOTP adoption',
            'description': 'Less than 50% of users have TOTP enabled'
        })
    
    # Create report record
    report = self.env['sunray.compliance.report'].create({
        'name': f'Security Posture Report - {fields.Date.today()}',
        'report_type': 'security_posture',
        'report_data': json.dumps(report_data, indent=2),
        'compliance_score': self._calculate_compliance_score(report_data),
        'findings_count': len(report_data['findings']),
        'critical_findings': len([f for f in report_data['findings'] if f['severity'] == 'critical'])
    })
    
    # Send to stakeholders
    self._send_report_email(report)
    
    return report
```

## 🔐 License Management

```python
class SunrayLicense(models.Model):
    _name = 'sunray.license'
    _description = 'Advanced License'
    _rec_name = 'license_key'
    
    license_key = fields.Char(string='License Key', required=True)
    customer_name = fields.Char(string='Customer')
    max_users = fields.Integer(string='Maximum Users')
    max_hosts = fields.Integer(string='Maximum Hosts')
    valid_from = fields.Date(string='Valid From')
    valid_until = fields.Date(string='Valid Until')
    
    features = fields.Text(string='Enabled Features (JSON)')
    is_valid = fields.Boolean(string='Valid', compute='_compute_validity')
    
    @api.depends('valid_until', 'max_users', 'max_hosts')
    def _compute_validity(self):
        for license in self:
            # Check expiration
            if license.valid_until and license.valid_until < fields.Date.today():
                license.is_valid = False
                continue
            
            # Check limits
            active_users = self.env['sunray.user'].search_count([('is_active', '=', True)])
            active_hosts = self.env['sunray.host'].search_count([('is_active', '=', True)])
            
            if license.max_users and active_users > license.max_users:
                license.is_valid = False
            elif license.max_hosts and active_hosts > license.max_hosts:
                license.is_valid = False
            else:
                license.is_valid = True
    
    @api.model
    def validate_license(self):
        """Called by cron and API to validate license"""
        license = self.search([('is_valid', '=', True)], limit=1)
        
        if not license:
            # Revert to free edition
            self._disable_advanced_features()
            return False
        
        # Update feature flags
        self._update_feature_flags(json.loads(license.features or '{}'))
        return True
```