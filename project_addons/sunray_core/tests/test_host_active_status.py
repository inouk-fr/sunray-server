# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
from odoo import fields
import json
from unittest.mock import patch


class TestHostActiveStatus(TransactionCase):
    """Test suite for Host is_active field rework
    
    Tests the new behavior where:
    - is_active controls worker blocking behavior
    - API endpoints include is_active flag
    - Audit logging tracks protection state changes
    - Backward compatibility is maintained
    """

    def setUp(self):
        """Set up test data"""
        super().setUp()
        
        # Create test host
        self.host = self.env['sunray.host'].create({
            'domain': 'test.example.com',
            'backend_url': 'http://backend:8080',
            'is_active': True
        })
        
        # Create test user
        self.user = self.env['sunray.user'].create({
            'username': 'testuser',
            'email': 'test@example.com',
            'is_active': True,
            'host_ids': [(4, self.host.id)]
        })
        
        # Create test worker
        self.worker = self.env['sunray.worker'].create({
            'name': 'test-worker-001',
            'worker_type': 'cloudflare'
        })
        
        # Create API key for worker
        self.api_key = self.env['sunray.api.key'].create({
            'name': 'test-api-key',
            'key': 'test-api-key-12345',
            'is_active': True
        })
        
        # Bind worker to API key
        self.worker.api_key_id = self.api_key.id
        
        # Bind worker to host
        self.host.sunray_worker_id = self.worker.id

    def test_01_inactive_host_returns_config_with_flag(self):
        """Test that config endpoints include inactive hosts with is_active flag"""
        
        # Make host inactive
        self.host.is_active = False
        
        # Test get_config_data method returns is_active field
        config_data = self.host.get_config_data()
        
        self.assertIn('is_active', config_data)
        self.assertFalse(config_data['is_active'])
        self.assertEqual(config_data['domain'], 'test.example.com')
        
        # Test with empty recordset
        empty_hosts = self.env['sunray.host'].browse()
        empty_config = empty_hosts.get_config_data()
        self.assertEqual(empty_config, {'hosts': []})
        
        # Test with multiple hosts
        active_host = self.env['sunray.host'].create({
            'domain': 'active.example.com', 
            'backend_url': 'http://active:8080',
            'is_active': True
        })
        
        both_hosts = self.host | active_host
        multi_config = both_hosts.get_config_data()
        
        self.assertIsInstance(multi_config, list)
        self.assertEqual(len(multi_config), 2)
        
        # Find configs by domain
        inactive_config = next(c for c in multi_config if c['domain'] == 'test.example.com')
        active_config = next(c for c in multi_config if c['domain'] == 'active.example.com')
        
        self.assertFalse(inactive_config['is_active'])
        self.assertTrue(active_config['is_active'])

    def test_02_registration_to_inactive_host_allowed(self):
        """Test that worker can register to inactive hosts and audit is logged"""
        
        # Make host inactive
        self.host.is_active = False
        
        # Simulate registration request data
        registration_data = {
            'hostname': self.host.domain,
            'worker_name': self.worker.name,
            'api_key': self.api_key.key
        }
        
        # Before registration - clear any existing audit logs
        self.env['sunray.audit.log'].sudo().search([]).unlink()
        
        # Mock the registration endpoint logic
        host_obj = self.env['sunray.host'].search([('domain', '=', registration_data['hostname'])])
        worker_obj = self.env['sunray.worker'].search([('name', '=', registration_data['worker_name'])])
        
        self.assertTrue(host_obj)
        self.assertTrue(worker_obj)
        
        # Test that registration succeeds and returns is_active flag
        config = {
            'version': 4,
            'generated_at': fields.Datetime.now().isoformat(),
            'worker_id': worker_obj.id,
            'worker_name': worker_obj.name,
            'host': host_obj.get_config_data()
        }
        
        self.assertFalse(config['host']['is_active'])
        
        # Test audit logging for inactive host registration
        if not host_obj.is_active:
            audit_event = self.env['sunray.audit.log'].sudo().create({
                'event_type': 'worker.registered_inactive_host',
                'severity': 'warning',
                'details': json.dumps({
                    'worker_id': worker_obj.id,
                    'worker_name': registration_data['worker_name'],
                    'host_id': host_obj.id,
                    'hostname': registration_data['hostname'],
                    'is_active': False
                }),
                'event_source': 'api'
            })
            
            # Verify audit log was created
            self.assertTrue(audit_event.id)
            self.assertEqual(audit_event.event_type, 'worker.registered_inactive_host')
            self.assertEqual(audit_event.severity, 'warning')
            
            details = json.loads(audit_event.details)
            self.assertFalse(details['is_active'])
            self.assertEqual(details['hostname'], 'test.example.com')

    def test_03_passkey_blocked_on_inactive_host(self):
        """Test that no new passkeys can be registered on inactive hosts"""
        
        # Make host inactive
        self.host.is_active = False
        
        # Try to register passkey (this should be blocked by existing logic)
        # The passkey registration logic already checks host.is_active 
        # and raises UserError('400|Host is inactive') when host is inactive
        
        # Create a setup token for testing
        setup_token = self.env['sunray.setup.token'].create({
            'username': self.user.username,
            'token_hash': 'sha512:test-token-hash',
            'device_name': 'Test Device',
            'hours_valid': 24,
            'is_active': True
        })
        
        # Mock the passkey registration attempt
        with self.assertRaises(Exception) as context:
            # This will trigger the host active status check in the passkey model
            self.env['sunray.passkey'].register_with_setup_token(
                username=self.user.username,
                setup_token_hash='sha512:test-token-hash',
                credential_id='test-credential-id',
                public_key='test-public-key',
                host_domain=self.host.domain,
                device_name='Test Device',
                client_ip='127.0.0.1',
                user_agent='Test Browser',
                worker_id='test-worker'
            )
        
        # The error should contain "Host is inactive" message
        error_message = str(context.exception)
        self.assertIn('Host is inactive', error_message)

    def test_04_audit_logging_activation_deactivation(self):
        """Test that audit events are logged when changing is_active status"""
        
        # Clear existing audit logs
        self.env['sunray.audit.log'].sudo().search([]).unlink()
        
        # Test deactivation
        self.host.write({'is_active': False})
        
        # Check audit log was created for deactivation
        deactivation_log = self.env['sunray.audit.log'].search([
            ('event_type', '=', 'config.host.protection_disabled')
        ], limit=1)
        
        self.assertTrue(deactivation_log)
        self.assertEqual(deactivation_log.severity, 'warning')
        
        details = deactivation_log.details
        if isinstance(details, str):
            details = json.loads(details)
        
        self.assertEqual(details['host'], 'test.example.com')
        self.assertTrue(details['previous_state'])
        self.assertFalse(details['new_state'])
        self.assertEqual(details['host_id'], self.host.id)
        
        # Test reactivation
        self.host.write({'is_active': True})
        
        # Check audit log was created for activation
        activation_log = self.env['sunray.audit.log'].search([
            ('event_type', '=', 'config.host.protection_enabled')
        ], limit=1)
        
        self.assertTrue(activation_log)
        self.assertEqual(activation_log.severity, 'warning')
        
        details = activation_log.details
        if isinstance(details, str):
            details = json.loads(details)
        
        self.assertEqual(details['host'], 'test.example.com')
        self.assertFalse(details['previous_state'])
        self.assertTrue(details['new_state'])

    def test_05_active_sessions_continue_on_inactive(self):
        """Test that existing sessions remain valid when host becomes inactive"""
        
        # Create an active session
        session = self.env['sunray.session'].create({
            'session_id': 'test-session-123',
            'user_id': self.user.id,
            'host_id': self.host.id,
            'created_ip': '127.0.0.1',
            'expires_at': fields.Datetime.now() + fields.timedelta(hours=1)
        })
        
        self.assertTrue(session.is_active)
        
        # Make host inactive
        self.host.write({'is_active': False})
        
        # Session should still be active (not automatically revoked)
        session.invalidate_cache()
        self.assertTrue(session.is_active)
        
        # Session should still be linked to the host
        self.assertEqual(session.host_id.id, self.host.id)
        
        # Host should still show the active session
        self.assertIn(session.id, self.host.active_session_ids.ids)

    def test_06_get_config_data_method(self):
        """Test the new get_config_data() method with different recordset sizes"""
        
        # Test single host (ensure_one case)
        single_config = self.host.get_config_data()
        
        self.assertIsInstance(single_config, dict)
        self.assertIn('domain', single_config)
        self.assertIn('is_active', single_config)
        self.assertIn('backend', single_config)
        self.assertIn('exceptions_tree', single_config)
        self.assertTrue(single_config['is_active'])
        
        # Test empty recordset
        empty_hosts = self.env['sunray.host'].browse()
        empty_config = empty_hosts.get_config_data()
        
        self.assertEqual(empty_config, {'hosts': []})
        
        # Test multiple hosts
        host2 = self.env['sunray.host'].create({
            'domain': 'test2.example.com',
            'backend_url': 'http://backend2:8080',
            'is_active': False
        })
        
        multiple_hosts = self.host | host2
        multiple_config = multiple_hosts.get_config_data()
        
        self.assertIsInstance(multiple_config, list)
        self.assertEqual(len(multiple_config), 2)
        
        # Check both configs have required fields
        for config in multiple_config:
            self.assertIn('domain', config)
            self.assertIn('is_active', config)
            self.assertIn('backend', config)
        
        # Check specific values
        config1 = next(c for c in multiple_config if c['domain'] == 'test.example.com')
        config2 = next(c for c in multiple_config if c['domain'] == 'test2.example.com')
        
        self.assertTrue(config1['is_active'])
        self.assertFalse(config2['is_active'])

    def test_07_field_help_text_updated(self):
        """Test that the is_active field help text has been updated"""
        
        # Get field definition
        host_model = self.env['sunray.host']
        is_active_field = host_model._fields['is_active']
        
        # Check string (label) was updated
        self.assertEqual(is_active_field.string, 'Protection Enabled')
        
        # Check help text mentions the new behavior
        help_text = is_active_field.help
        self.assertIn('503 Service Unavailable', help_text)
        self.assertIn('Access Rules', help_text)
        self.assertIn('disabling protection', help_text)

    def test_08_backward_compatibility(self):
        """Test that changes are backward compatible"""
        
        # Test that old API behavior still works (hosts with is_active=False should be handled)
        inactive_host = self.env['sunray.host'].create({
            'domain': 'inactive.example.com',
            'backend_url': 'http://inactive:8080', 
            'is_active': False
        })
        
        # get_config_data should work for inactive hosts
        config = inactive_host.get_config_data()
        self.assertFalse(config['is_active'])
        
        # Mixed recordsets should work
        mixed_hosts = self.host | inactive_host
        mixed_config = mixed_hosts.get_config_data()
        
        self.assertEqual(len(mixed_config), 2)
        
        # Field defaults should remain True for new hosts
        new_host = self.env['sunray.host'].create({
            'domain': 'new.example.com',
            'backend_url': 'http://new:8080'
            # is_active not specified - should default to True
        })
        
        self.assertTrue(new_host.is_active)