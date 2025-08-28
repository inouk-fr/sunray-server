# -*- coding: utf-8 -*-
from odoo.tests.common import TransactionCase
from odoo.exceptions import UserError
from datetime import datetime, timedelta
import json


class TestPasskeyCounter(TransactionCase):
    """Test WebAuthn passkey counter functionality and security"""
    
    def setUp(self):
        super().setUp()
        
        # Create test user
        self.user_obj = self.env['sunray.user'].create({
            'username': 'counter_test_user',
            'email': 'counter@test.com',
            'is_active': True
        })
        
        # Create test host
        self.host_obj = self.env['sunray.host'].create({
            'name': 'Counter Test Host',
            'domain': 'counter.test.com',
            'is_active': True,
            'session_duration_s': 3600
        })
        
        # Link user to host
        self.host_obj.user_ids = [(4, self.user_obj.id)]
        
        # Create test passkey
        self.passkey_obj = self.env['sunray.passkey'].create({
            'user_id': self.user_obj.id,
            'credential_id': 'test_counter_cred_123',
            'public_key': 'test_public_key_counter',
            'name': 'Counter Test Device',
            'host_domain': 'counter.test.com',
            'counter': 10  # Starting counter value
        })
        
        # Create API key for session creation tests
        self.api_key_obj = self.env['sunray.api.key'].create({
            'name': 'Counter Test API Key',
            'scopes': 'config:read,session:write',
            'is_active': True
        })
    
    def test_01_counter_increment_success(self):
        """Test successful counter increment updates both counter and last_used"""
        original_counter = self.passkey_obj.counter
        original_last_used = self.passkey_obj.last_used
        
        # Update counter with valid increment
        result = self.passkey_obj.update_authentication_counter(original_counter + 5)
        
        # Verify success response
        self.assertTrue(result['success'])
        self.assertEqual(result['counter'], original_counter + 5)
        self.assertIsNotNone(result['last_used'])
        
        # Verify database updates
        self.passkey_obj.invalidate_recordset()  # Ensure fresh read
        self.assertEqual(self.passkey_obj.counter, original_counter + 5)
        self.assertNotEqual(self.passkey_obj.last_used, original_last_used)
        self.assertIsNotNone(self.passkey_obj.last_used)
        
        # Verify audit log entry
        audit_logs = self.env['sunray.audit.log'].search([
            ('event_type', '=', 'passkey.authenticated'),
            ('sunray_user_id', '=', self.user_obj.id)
        ])
        self.assertTrue(audit_logs)
        self.assertEqual(audit_logs[-1].severity, 'info')
        
        # Verify audit details
        details = json.loads(audit_logs[-1].details)
        self.assertEqual(details['passkey_id'], self.passkey_obj.id)
        self.assertEqual(details['new_counter'], original_counter + 5)
        self.assertEqual(details['counter_increment'], 5)
    
    def test_02_counter_same_value_rejection(self):
        """Test rejection when counter doesn't increase (same value)"""
        current_counter = self.passkey_obj.counter
        
        # Attempt to use same counter value
        with self.assertRaises(UserError) as context:
            self.passkey_obj.update_authentication_counter(current_counter)
        
        # Verify error message format
        error_msg = str(context.exception)
        self.assertIn('403|Authentication counter violation', error_msg)
        self.assertIn(f'current: {current_counter}', error_msg)
        self.assertIn(f'attempted: {current_counter}', error_msg)
        
        # Verify counter wasn't updated
        self.passkey_obj.invalidate_recordset()
        self.assertEqual(self.passkey_obj.counter, current_counter)
        
        # Verify critical security audit log
        security_logs = self.env['sunray.audit.log'].search([
            ('event_type', '=', 'security.passkey.counter_violation'),
            ('sunray_user_id', '=', self.user_obj.id)
        ])
        self.assertTrue(security_logs)
        self.assertEqual(security_logs[-1].severity, 'critical')
        
        # Verify security log details
        details = json.loads(security_logs[-1].details)
        self.assertEqual(details['current_counter'], current_counter)
        self.assertEqual(details['attempted_counter'], current_counter)
        self.assertEqual(details['violation_type'], 'counter_not_increased')
    
    def test_03_counter_backward_rejection(self):
        """Test rejection when counter goes backward (potential replay attack)"""
        current_counter = self.passkey_obj.counter
        attempted_counter = current_counter - 1
        
        # Attempt to use smaller counter value
        with self.assertRaises(UserError) as context:
            self.passkey_obj.update_authentication_counter(attempted_counter)
        
        # Verify error message
        error_msg = str(context.exception)
        self.assertIn('403|Authentication counter violation', error_msg)
        self.assertIn(f'current: {current_counter}', error_msg)
        self.assertIn(f'attempted: {attempted_counter}', error_msg)
        
        # Verify counter wasn't updated
        self.passkey_obj.invalidate_recordset()
        self.assertEqual(self.passkey_obj.counter, current_counter)
        
        # Verify critical security audit log
        security_logs = self.env['sunray.audit.log'].search([
            ('event_type', '=', 'security.passkey.counter_violation'),
            ('sunray_user_id', '=', self.user_obj.id)
        ])
        self.assertTrue(security_logs)
        self.assertEqual(security_logs[-1].severity, 'critical')
        
        # Verify detailed security logging
        details = json.loads(security_logs[-1].details)
        self.assertEqual(details['current_counter'], current_counter)
        self.assertEqual(details['attempted_counter'], attempted_counter)
        self.assertEqual(details['security_risk'], 'replay_attack_or_cloned_credential')
    
    def test_04_session_creation_with_counter_success(self):
        """Test successful session creation with counter update"""
        original_counter = self.passkey_obj.counter
        new_counter = original_counter + 3
        
        # Create session with counter update
        session_data = {
            'session_id': 'test_session_counter_success',
            'username': self.user_obj.username,
            'host_domain': self.host_obj.domain,
            'credential_id': self.passkey_obj.credential_id,
            'counter': new_counter,
            'created_ip': '192.168.1.100',
            'user_agent': 'Test Browser Counter',
            'csrf_token': 'test_csrf_counter'
        }
        
        # Simulate API request
        from odoo.http import request
        from unittest.mock import Mock
        
        mock_request = Mock()
        mock_request.httprequest.data = json.dumps(session_data).encode()
        mock_request.env = self.env
        
        # Create controller instance and call method
        controller = self.env['sunray.rest.api']
        
        # Mock authentication 
        original_auth = controller._authenticate_api
        controller._authenticate_api = lambda r: self.api_key_obj
        
        # Mock request context setup
        controller._setup_request_context = lambda r: {'worker_id': 'test_worker'}
        
        try:
            # Call session creation
            with self.env.registry.cursor() as cr:
                env = self.env(cr=cr)
                controller_env = env['sunray.rest.api']
                controller_env._authenticate_api = lambda r: self.api_key_obj
                controller_env._setup_request_context = lambda r: {'worker_id': 'test_worker'}
                
                response = controller_env.with_context(request=mock_request).create_session()
                
                # Verify response structure
                if hasattr(response, 'data'):
                    response_data = json.loads(response.data.decode())
                    self.assertTrue(response_data['success'])
                    self.assertEqual(response_data['session_id'], session_data['session_id'])
                
                # Verify passkey counter was updated
                self.passkey_obj.invalidate_recordset()
                self.assertEqual(self.passkey_obj.counter, new_counter)
                
                # Verify session was created with passkey link
                session_obj = env['sunray.session'].search([
                    ('session_id', '=', session_data['session_id'])
                ])
                self.assertTrue(session_obj)
                self.assertEqual(session_obj.passkey_id.id, self.passkey_obj.id)
                self.assertEqual(session_obj.credential_id, self.passkey_obj.credential_id)
                
        finally:
            # Restore original authentication method
            controller._authenticate_api = original_auth
    
    def test_05_session_creation_counter_violation(self):
        """Test session creation rejection due to counter violation"""
        current_counter = self.passkey_obj.counter
        invalid_counter = current_counter - 1  # Backward counter
        
        # Attempt session creation with invalid counter
        session_data = {
            'session_id': 'test_session_counter_violation',
            'username': self.user_obj.username,
            'host_domain': self.host_obj.domain,
            'credential_id': self.passkey_obj.credential_id,
            'counter': invalid_counter,
            'created_ip': '192.168.1.101',
            'user_agent': 'Test Browser Violation'
        }
        
        from odoo.http import request
        from unittest.mock import Mock
        
        mock_request = Mock()
        mock_request.httprequest.data = json.dumps(session_data).encode()
        mock_request.env = self.env
        
        controller = self.env['sunray.rest.api']
        controller._authenticate_api = lambda r: self.api_key_obj
        controller._setup_request_context = lambda r: {'worker_id': 'test_worker'}
        
        # Call session creation - should fail
        response = controller.with_context(request=mock_request).create_session()
        
        # Verify error response (method should return error, not raise exception)
        if hasattr(response, 'status_code'):
            self.assertEqual(response.status_code, 403)
        
        # Verify session was NOT created
        session_obj = self.env['sunray.session'].search([
            ('session_id', '=', session_data['session_id'])
        ])
        self.assertFalse(session_obj)
        
        # Verify counter was NOT updated
        self.passkey_obj.invalidate_recordset()
        self.assertEqual(self.passkey_obj.counter, current_counter)
        
        # Verify security audit log
        security_logs = self.env['sunray.audit.log'].search([
            ('event_type', '=', 'security.passkey.counter_violation'),
            ('sunray_user_id', '=', self.user_obj.id)
        ])
        self.assertTrue(security_logs)
        self.assertEqual(security_logs[-1].severity, 'critical')
    
    def test_06_session_creation_without_counter(self):
        """Test session creation without counter (should succeed without counter update)"""
        original_counter = self.passkey_obj.counter
        
        # Create session without counter field
        session_data = {
            'session_id': 'test_session_no_counter',
            'username': self.user_obj.username,
            'host_domain': self.host_obj.domain,
            'credential_id': self.passkey_obj.credential_id,
            'created_ip': '192.168.1.102',
            'user_agent': 'Test Browser No Counter'
        }
        
        from odoo.http import request
        from unittest.mock import Mock
        
        mock_request = Mock()
        mock_request.httprequest.data = json.dumps(session_data).encode()
        mock_request.env = self.env
        
        controller = self.env['sunray.rest.api']
        controller._authenticate_api = lambda r: self.api_key_obj
        controller._setup_request_context = lambda r: {'worker_id': 'test_worker'}
        
        # Call session creation
        response = controller.with_context(request=mock_request).create_session()
        
        # Should succeed
        if hasattr(response, 'data'):
            response_data = json.loads(response.data.decode())
            self.assertTrue(response_data['success'])
        
        # Verify counter was NOT updated (no counter provided)
        self.passkey_obj.invalidate_recordset()
        self.assertEqual(self.passkey_obj.counter, original_counter)
        
        # Verify session was created but without counter update
        session_obj = self.env['sunray.session'].search([
            ('session_id', '=', session_data['session_id'])
        ])
        self.assertTrue(session_obj)
        self.assertEqual(session_obj.credential_id, self.passkey_obj.credential_id)
    
    def test_07_session_creation_no_credential_id(self):
        """Test session creation without credential_id (should succeed, no counter validation)"""
        original_counter = self.passkey_obj.counter
        
        # Create session without credential_id
        session_data = {
            'session_id': 'test_session_no_credential',
            'username': self.user_obj.username,
            'host_domain': self.host_obj.domain,
            'counter': 999,  # Counter provided but no credential_id
            'created_ip': '192.168.1.103'
        }
        
        from odoo.http import request
        from unittest.mock import Mock
        
        mock_request = Mock()
        mock_request.httprequest.data = json.dumps(session_data).encode()
        mock_request.env = self.env
        
        controller = self.env['sunray.rest.api']
        controller._authenticate_api = lambda r: self.api_key_obj
        controller._setup_request_context = lambda r: {'worker_id': 'test_worker'}
        
        # Call session creation
        response = controller.with_context(request=mock_request).create_session()
        
        # Should succeed (counter ignored without credential_id)
        if hasattr(response, 'data'):
            response_data = json.loads(response.data.decode())
            self.assertTrue(response_data['success'])
        
        # Verify counter was NOT updated (no credential_id)
        self.passkey_obj.invalidate_recordset()
        self.assertEqual(self.passkey_obj.counter, original_counter)
    
    def test_08_multiple_counter_increments(self):
        """Test multiple sequential counter increments"""
        base_counter = self.passkey_obj.counter
        
        # Perform multiple counter updates
        for i in range(1, 6):
            expected_counter = base_counter + i
            result = self.passkey_obj.update_authentication_counter(expected_counter)
            
            self.assertTrue(result['success'])
            self.assertEqual(result['counter'], expected_counter)
            
            # Verify database update
            self.passkey_obj.invalidate_recordset()
            self.assertEqual(self.passkey_obj.counter, expected_counter)
        
        # Verify final counter value
        self.assertEqual(self.passkey_obj.counter, base_counter + 5)
        
        # Verify we have multiple authentication audit logs
        auth_logs = self.env['sunray.audit.log'].search([
            ('event_type', '=', 'passkey.authenticated'),
            ('sunray_user_id', '=', self.user_obj.id)
        ])
        self.assertEqual(len(auth_logs), 5)  # Should have 5 authentication events
    
    def test_09_concurrent_counter_updates_simulation(self):
        """Test atomic counter updates to prevent race conditions"""
        original_counter = self.passkey_obj.counter
        new_counter = original_counter + 1
        
        # Simulate concurrent update attempt
        # First update succeeds
        result1 = self.passkey_obj.update_authentication_counter(new_counter)
        self.assertTrue(result1['success'])
        
        # Second update with same counter should fail
        with self.assertRaises(UserError):
            self.passkey_obj.update_authentication_counter(new_counter)
        
        # Third update with higher counter should succeed
        result3 = self.passkey_obj.update_authentication_counter(new_counter + 1)
        self.assertTrue(result3['success'])
        self.assertEqual(result3['counter'], new_counter + 1)
    
    def test_10_audit_log_details_validation(self):
        """Test that all required audit log details are properly recorded"""
        original_counter = self.passkey_obj.counter
        new_counter = original_counter + 7
        
        # Perform authentication
        self.passkey_obj.update_authentication_counter(new_counter)
        
        # Get the audit log
        audit_log = self.env['sunray.audit.log'].search([
            ('event_type', '=', 'passkey.authenticated'),
            ('sunray_user_id', '=', self.user_obj.id)
        ], order='create_date desc', limit=1)
        
        self.assertTrue(audit_log)
        
        # Verify audit log fields
        self.assertEqual(audit_log.event_type, 'passkey.authenticated')
        self.assertEqual(audit_log.severity, 'info')
        self.assertEqual(audit_log.sunray_user_id.id, self.user_obj.id)
        self.assertEqual(audit_log.username, self.user_obj.username)
        
        # Verify audit details
        details = json.loads(audit_log.details)
        required_fields = [
            'username', 'credential_id', 'passkey_id', 'passkey_name',
            'host_domain', 'previous_counter', 'new_counter', 'counter_increment',
            'authentication_time'
        ]
        
        for field in required_fields:
            self.assertIn(field, details, f'Missing audit detail field: {field}')
        
        self.assertEqual(details['passkey_id'], self.passkey_obj.id)
        self.assertEqual(details['new_counter'], new_counter)
        self.assertEqual(details['counter_increment'], 7)
        self.assertEqual(details['credential_id'], self.passkey_obj.credential_id)