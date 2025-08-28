# -*- coding: utf-8 -*-
from odoo import models, fields, api
from odoo.exceptions import UserError
from datetime import datetime, timedelta
import hashlib
import logging
import cbor2
import base64

try:
    from pycose.keys import CoseKey
    from pycose.exceptions import CoseException
    COSE_AVAILABLE = True
except ImportError:
    COSE_AVAILABLE = False

_logger = logging.getLogger(__name__)


class SunrayPasskey(models.Model):
    _name = 'sunray.passkey'
    _description = 'Sunray Passkey'
    _rec_name = 'name'
    _order = 'create_date desc'
    
    user_id = fields.Many2one(
        'sunray.user', 
        required=True, 
        ondelete='cascade',
        string='User'
    )
    credential_id = fields.Char(
        string='Credential ID', 
        required=True, 
        index=True,
        help='WebAuthn credential identifier'
    )
    public_key = fields.Text(
        string='Public Key', 
        required=True,
        help='WebAuthn public key in CBOR/COSE format (base64-encoded). Must be a valid COSE_Key structure per WebAuthn specification.'
    )
    name = fields.Char(
        string='Device Name', 
        required=True,
        help='User-friendly name for this passkey'
    )
    last_used = fields.Datetime(
        string='Last Used',
        help='Last authentication timestamp'
    )
    counter = fields.Integer(
        string='Authentication Counter',
        default=0,
        help='WebAuthn authentication counter for replay attack prevention. Must increment on each successful authentication.'
    )
    
    # WebAuthn rpId binding - CRITICAL for security
    host_domain = fields.Char(
        string='Registered Host Domain',
        required=False,  # Allow blank for existing records to force re-registration
        index=True,
        help='The host domain (rpId) this passkey is bound to per WebAuthn spec. Empty value means passkey needs re-registration to comply with WebAuthn security requirements.'
    )
    
    # Audit fields
    created_ip = fields.Char(
        string='Registration IP',
        help='IP address used during passkey registration'
    )
    created_user_agent = fields.Text(
        string='Registration User Agent',
        help='Browser user agent during registration'
    )
    
    # NEW FIELD: Link to setup token
    setup_token_id = fields.Many2one(
        'sunray.setup.token',
        string='Setup Token',
        help='The setup token used to register this passkey',
        ondelete='set null',
        index=True  # Index for audit queries
    )
    
    _sql_constraints = [
        ('credential_unique', 'UNIQUE(credential_id)', 'Credential ID must be unique!'),
        ('unique_credential_user', 'UNIQUE(credential_id, user_id)', 'Credential ID must be unique per user')
    ]
    
    def _validate_cbor_public_key(self, public_key_b64):
        """
        Validate that the public key is proper CBOR/COSE format.
        
        Args:
            public_key_b64 (str): Base64-encoded public key
            
        Returns:
            tuple: (is_valid, result) where result is CoseKey on success or error message on failure
        """
        try:
            # Decode base64
            try:
                cbor_data = base64.b64decode(public_key_b64)
            except Exception as e:
                return False, f"Invalid base64 encoding: {str(e)}"
            
            # Validate CBOR structure
            try:
                cbor_obj = cbor2.loads(cbor_data)
            except Exception as e:
                return False, f"Invalid CBOR format: {str(e)}"
            
            # Validate COSE key format if library is available
            if COSE_AVAILABLE:
                try:
                    cose_key = CoseKey.from_dict(cbor_obj)
                    return True, cose_key
                except Exception as e:
                    return False, f"Invalid COSE key structure: {str(e)}"
            else:
                # Basic CBOR validation without COSE
                if not isinstance(cbor_obj, dict):
                    return False, "CBOR data must be a dictionary"
                
                # Check for required COSE key fields
                if 1 not in cbor_obj:  # kty (key type)
                    return False, "Missing required COSE key type field (1)"
                
                return True, cbor_obj
                
        except Exception as e:
            return False, f"Unexpected validation error: {str(e)}"
    
    def _normalize_public_key_to_cbor(self, public_key_data):
        """
        Convert any public key format to canonical CBOR.
        Currently assumes input is already in CBOR format.
        
        Args:
            public_key_data (str): Public key data (base64 encoded)
            
        Returns:
            str: Canonical CBOR-encoded public key (base64)
        """
        # For now, we assume the key is already in proper CBOR format
        # Future enhancement could add format detection and conversion
        is_valid, result = self._validate_cbor_public_key(public_key_data)
        if is_valid:
            return public_key_data.strip()
        else:
            raise UserError(f"Cannot normalize public key: {result}")
    
    # CBOR-related error messages
    CBOR_ERROR_MESSAGES = {
        'invalid_base64': 'Public key must be valid base64-encoded data',
        'invalid_cbor': 'Public key must be valid CBOR-encoded data', 
        'invalid_cose': 'Public key must be valid COSE key format',
        'unsupported_algorithm': 'Public key algorithm not supported',
        'missing_required_fields': 'COSE key missing required fields'
    }
    
    def update_authentication_counter(self, new_counter):
        """
        Update the authentication counter and last_used timestamp for successful authentication.
        
        This method implements WebAuthn counter validation to prevent replay attacks.
        The counter must always increase with each authentication.
        
        Args:
            new_counter (int): The new counter value from WebAuthn authentication
            
        Returns:
            dict: Success result with updated values
            
        Raises:
            UserError: If counter validation fails (potential replay attack)
        """
        self.ensure_one()
        
        # Validate counter increment (WebAuthn spec requirement)
        if new_counter <= self.counter:
            # CRITICAL: Potential replay attack or counter rollback
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.counter_violation',
                details={
                    'username': self.user_id.username,
                    'credential_id': self.credential_id,
                    'passkey_id': self.id,
                    'current_counter': self.counter,
                    'attempted_counter': new_counter,
                    'passkey_name': self.name,
                    'host_domain': self.host_domain,
                    'violation_type': 'counter_not_increased',
                    'security_risk': 'replay_attack_or_cloned_credential'
                },
                severity='critical',
                sunray_user_id=self.user_id.id,
                username=self.user_id.username
            )
            raise UserError(f'403|Authentication counter violation: counter must increase (current: {self.counter}, attempted: {new_counter})')
        
        # Update counter and last_used atomically
        now = fields.Datetime.now()
        self.write({
            'counter': new_counter,
            'last_used': now
        })
        
        # Log successful authentication
        self.env['sunray.audit.log'].sudo().create_audit_event(
            event_type='passkey.authenticated',
            details={
                'username': self.user_id.username,
                'credential_id': self.credential_id,
                'passkey_id': self.id,
                'passkey_name': self.name,
                'host_domain': self.host_domain,
                'previous_counter': self.counter,  # Store current counter before update
                'new_counter': new_counter,
                'counter_increment': new_counter - self.counter,
                'authentication_time': now.isoformat()
            },
            severity='info',
            sunray_user_id=self.user_id.id,
            username=self.user_id.username
        )
        
        return {
            'success': True,
            'counter': self.counter,
            'last_used': self.last_used,
            'message': 'Authentication counter updated successfully'
        }
    
    def revoke(self):
        """Revoke this passkey"""
        self.ensure_one()
        
        # Log the revocation
        self.env['sunray.audit.log'].create_user_event(
            event_type='passkey.revoked',
            details={
                'passkey_name': self.name,
                'credential_id': self.credential_id
            },
            sunray_user_id=self.user_id.id,
            username=self.user_id.username  # Keep for compatibility
        )
        
        # Delete the passkey
        self.unlink()
        
        return True
    
    @api.model
    def register_with_setup_token(self, username, setup_token_hash, credential_id, public_key, host_domain, 
                                  device_name='Passkey', client_ip=None, user_agent=None, worker_id=None):
        """
        Register a new passkey with comprehensive security validation.
        
        This method encapsulates all the business logic for passkey registration,
        making it testable without HTTP context.
        
        Returns:
            dict: {'success': True, 'passkey_id': id} or raises UserError/ValidationError
        """
        _logger.info(f"Starting passkey registration for username: {username}")
        now = fields.Datetime.now()
        
        # Validate required parameters (check for None, not empty strings)
        missing_fields = []
        if username is None:
            missing_fields.append('username')
        if setup_token_hash is None:
            missing_fields.append('setup_token_hash')
        if credential_id is None:
            missing_fields.append('credential_id')
        if host_domain is None:
            missing_fields.append('host_domain')
        
        if missing_fields:
            # AUDIT: Log missing required fields
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.missing_fields',
                details={
                    'username': username,
                    'missing_fields': missing_fields,
                    'provided_fields': [f for f in ['username', 'setup_token_hash', 'credential_id', 'public_key', 'host_domain'] if f not in missing_fields],
                    'host_domain': host_domain or 'not_provided',
                    'worker_id': worker_id
                },
                severity='warning',
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError(f'400|Missing required fields: {", ".join(missing_fields)}')
        
        # Special validation for public_key (handle missing, empty, whitespace-only)
        if public_key is None or not str(public_key).strip():
            # AUDIT: Log missing public key
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.missing_public_key',
                details={
                    'username': username,
                    'credential_id': credential_id,
                    'public_key_provided': public_key is not None,
                    'public_key_empty': public_key == '' if public_key is not None else None,
                    'host_domain': host_domain,
                    'worker_id': worker_id,
                    'error': 'WebAuthn public key is required for passkey registration'
                },
                severity='critical',
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError('400|Public key is required for passkey registration')
        
        # Phase 1: User Validation
        _logger.debug("Validating user existence and status")
        user_obj = self.env['sunray.user'].sudo().search([('username', '=', username)], limit=1)
        if not user_obj:
            _logger.warning(f"User not found: {username}")
            # AUDIT: Log user not found
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.user_not_found',
                details={
                    'username': username,
                    'worker_id': worker_id
                },
                severity='warning',
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError('404|User not found')
        
        if not user_obj.is_active:
            _logger.warning(f"Inactive user attempted registration: {username}")
            # AUDIT: Log inactive user attempt
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.user_inactive',
                details={
                    'username': username,
                    'user_id': user_obj.id,
                    'worker_id': worker_id
                },
                severity='warning',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError('404|User is inactive')
        
        # Setup Token Hash Validation
        _logger.debug(f"Validating setup token hash for user {username}")
        
        token_obj = self.env['sunray.setup.token'].sudo().search([
            ('token_hash', '=', setup_token_hash),
            ('user_id', '=', user_obj.id)
        ], limit=1)
        
        if not token_obj:
            _logger.warning(f"Invalid setup token hash for user {username}")
            # AUDIT: Log invalid token hash
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.setup_token_not_found',
                details={
                    'username': username,
                    'user_id': user_obj.id,
                    'worker_id': worker_id
                },
                severity='critical',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError('401|Invalid setup token hash')
        
        # Check token expiry
        if token_obj.expires_at < now:
            hours_ago = (now - token_obj.expires_at).total_seconds() / 3600
            _logger.warning(f"Expired token used for {username}, expired {hours_ago:.1f} hours ago")
            # AUDIT: Log expired token
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.token_expired',
                details={
                    'username': username,
                    'token_id': token_obj.id,
                    'expired_hours_ago': round(hours_ago, 1),
                    'expired_at': token_obj.expires_at.isoformat(),
                    'worker_id': worker_id
                },
                severity='warning',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError('401|Setup token expired')
        
        # Check if token is already consumed
        if token_obj.consumed:
            _logger.warning(f"Consumed token reuse attempted for {username}")
            # AUDIT: Log consumed token reuse
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.token_already_consumed',
                details={
                    'username': username,
                    'token_id': token_obj.id,
                    'consumed_date': token_obj.consumed_date.isoformat() if token_obj.consumed_date else None,
                    'current_uses': token_obj.current_uses,
                    'max_uses': token_obj.max_uses,
                    'worker_id': worker_id
                },
                severity='critical',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError('403|Token already consumed')
        
        # Check token usage limit
        if token_obj.current_uses >= token_obj.max_uses:
            _logger.warning(f"Token usage limit exceeded for {username}: {token_obj.current_uses}/{token_obj.max_uses}")
            # AUDIT: Log token usage limit exceeded
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.token_usage_exceeded',
                details={
                    'username': username,
                    'token_id': token_obj.id,
                    'current_uses': token_obj.current_uses,
                    'max_uses': token_obj.max_uses,
                    'worker_id': worker_id
                },
                severity='critical',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError('403|Token usage limit exceeded')
        
        # Phase 3: Host Domain Validation
        _logger.debug(f"Validating host domain: {host_domain}")
        host_obj = self.env['sunray.host'].sudo().search([('domain', '=', host_domain)], limit=1)
        
        if not host_obj:
            _logger.warning(f"Unknown host domain: {host_domain}")
            # AUDIT: Log unknown host
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.unknown_host',
                details={
                    'username': username,
                    'requested_host': host_domain,
                    'token_id': token_obj.id,
                    'worker_id': worker_id
                },
                severity='warning',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError('400|Unknown host domain')
        
        if not host_obj.is_active:
            _logger.warning(f"Inactive host domain: {host_domain}")
            # AUDIT: Log inactive host
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.host_inactive',
                details={
                    'username': username,
                    'requested_host': host_domain,
                    'host_id': host_obj.id,
                    'token_id': token_obj.id,
                    'worker_id': worker_id
                },
                severity='warning',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError('400|Host is inactive')
        
        # Validate token is for the correct host
        if token_obj.host_id and token_obj.host_id.id != host_obj.id:
            _logger.warning(f"Token host mismatch: token for {token_obj.host_id.domain}, requested {host_domain}")
            # AUDIT: Log host mismatch
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.token_wrong_host',
                details={
                    'username': username,
                    'token_host': token_obj.host_id.domain,
                    'requested_host': host_domain,
                    'token_id': token_obj.id,
                    'worker_id': worker_id
                },
                severity='critical',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError('403|Token not valid for this host')
        
        # User Authorization Check
        if user_obj not in host_obj.user_ids:
            _logger.warning(f"User {username} not authorized for host {host_domain}")
            # AUDIT: Log unauthorized user for host
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.user_not_authorized',
                details={
                    'username': username,
                    'host_domain': host_domain,
                    'host_user_count': len(host_obj.user_ids),
                    'token_id': token_obj.id,
                    'worker_id': worker_id
                },
                severity='critical',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError(f'403|User not authorized for host: {host_domain}')
        
        # Phase 4: IP CIDR Restriction Check
        if token_obj.allowed_cidrs and client_ip:
            _logger.debug(f"Checking IP {client_ip} against CIDR restrictions")
            from odoo.addons.sunray_core.utils.cidr import check_cidr_match
            allowed_cidrs = token_obj.get_allowed_cidrs()
            
            ip_allowed = False
            for cidr in allowed_cidrs:
                if check_cidr_match(client_ip, cidr):
                    ip_allowed = True
                    break
            
            if not ip_allowed:
                # AUDIT: Log IP restriction violation
                self.env['sunray.audit.log'].sudo().create_audit_event(
                    event_type='security.passkey.ip_not_allowed',
                    details={
                        'username': username,
                        'host_domain': host_domain,
                        'client_ip': client_ip,
                        'allowed_cidrs': allowed_cidrs,
                        'token_id': token_obj.id,
                        'worker_id': worker_id
                    },
                    severity='critical',
                    sunray_user_id=user_obj.id,
                    sunray_worker=worker_id,
                    ip_address=client_ip,
                    username=username
                )
                raise UserError('403|IP not allowed')
        
        # Phase 5: Credential Validation - CRITICAL for WebAuthn security
        _logger.debug(f"Validating credential for user {username}")
        
        # Validate public_key is provided and not empty
        if not public_key or not public_key.strip():
            # AUDIT: Log missing public key
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.missing_public_key',
                details={
                    'username': username,
                    'host_domain': host_domain,
                    'credential_id': credential_id,
                    'token_id': token_obj.id,
                    'worker_id': worker_id,
                    'error': 'Public key is required for WebAuthn passkey registration'
                },
                severity='critical',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError('400|Public key is required for passkey registration')
        
        # Phase 5.5: CBOR Format Validation - NEW
        _logger.debug(f"Validating CBOR/COSE format for public key")
        is_valid_cbor, validation_result = self._validate_cbor_public_key(public_key.strip())
        
        if not is_valid_cbor:
            # AUDIT: Log CBOR validation failure
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.invalid_cbor_format',
                details={
                    'username': username,
                    'credential_id': credential_id,
                    'host_domain': host_domain,
                    'validation_error': validation_result,
                    'public_key_length': len(public_key),
                    'token_id': token_obj.id,
                    'worker_id': worker_id,
                    'cose_available': COSE_AVAILABLE
                },
                severity='critical',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError(f'400|Invalid WebAuthn public key format: {validation_result}')
        
        # Log successful CBOR validation
        _logger.info(f"CBOR validation successful for user {username}")
        self.env['sunray.audit.log'].sudo().create_audit_event(
            event_type='passkey.cbor_validation_success',
            details={
                'username': username,
                'credential_id': credential_id,
                'host_domain': host_domain,
                'validation_result': 'Valid CBOR/COSE format',
                'cose_available': COSE_AVAILABLE,
                'token_id': token_obj.id,
                'worker_id': worker_id
            },
            severity='info',
            sunray_user_id=user_obj.id,
            sunray_worker=worker_id,
            ip_address=client_ip,
            username=username
        )
        
        # Phase 6: Duplicate Check
        _logger.debug(f"Checking for duplicate credential: {credential_id}")
        existing_passkey = self.sudo().search([
            ('credential_id', '=', credential_id),
            ('user_id', '=', user_obj.id)
        ])
        
        if existing_passkey:
            _logger.warning(f"Duplicate credential found: {existing_passkey.id}")
            # AUDIT: Log duplicate passkey attempt
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.duplicate_credential',
                details={
                    'username': username,
                    'host_domain': host_domain,
                    'credential_id': credential_id,
                    'existing_passkey_id': existing_passkey.id,
                    'existing_passkey_name': existing_passkey.name,
                    'existing_created_date': existing_passkey.create_date.isoformat(),
                    'token_id': token_obj.id,
                    'worker_id': worker_id
                },
                severity='warning',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise UserError('409|Credential already registered')
        
        # Phase 7: Passkey Creation
        _logger.info(f"Creating passkey for user {username} on host {host_domain}")
        try:
            passkey_obj = self.sudo().create({
                'user_id': user_obj.id,
                'credential_id': credential_id,
                'public_key': public_key.strip(),
                'name': device_name,
                'host_domain': host_domain,
                'created_ip': client_ip,
                'created_user_agent': user_agent,
                'setup_token_id': token_obj.id
            })
            _logger.info(f"Passkey created successfully with ID: {passkey_obj.id}")
            
            # Consume the token using the dedicated method
            token_result = token_obj.consume()
            
            # Phase 8: Success Audit
            _logger.info("Recording success audit event")
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='passkey.registered',
                details={
                    'passkey_id': passkey_obj.id,
                    'token_id': token_obj.id,
                    'host_domain': host_domain,
                    'device_name': device_name,
                    'credential_id': credential_id,
                    'token_uses': f"{token_result['current_uses']}/{token_result['max_uses']}",
                    'token_consumed': token_result['consumed'],
                    'worker_id': worker_id
                },
                severity='info',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                user_agent=user_agent,
                username=username
            )
            
            return {
                'success': True,
                'passkey_id': passkey_obj.id,
                'message': 'Passkey registered successfully'
            }
            
        except Exception as e:
            _logger.error(f"Failed to create passkey: {str(e)}")
            # AUDIT: Log creation failure
            self.env['sunray.audit.log'].sudo().create_audit_event(
                event_type='security.passkey.creation_failed',
                details={
                    'username': username,
                    'error': str(e),
                    'token_id': token_obj.id,
                    'worker_id': worker_id
                },
                severity='error',
                sunray_user_id=user_obj.id,
                sunray_worker=worker_id,
                ip_address=client_ip,
                username=username
            )
            raise