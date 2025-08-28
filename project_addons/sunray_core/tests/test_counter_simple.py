# -*- coding: utf-8 -*-
from odoo.tests.common import TransactionCase
from odoo.exceptions import UserError


class TestCounterSimple(TransactionCase):
    """Simple test for passkey counter functionality"""
    
    def setUp(self):
        super().setUp()
        
        # Create test user
        self.user_obj = self.env['sunray.user'].create({
            'username': 'test_counter_user',
            'email': 'test@counter.com',
            'is_active': True
        })
        
        # Create test passkey
        self.passkey_obj = self.env['sunray.passkey'].create({
            'user_id': self.user_obj.id,
            'credential_id': 'test_cred_counter',
            'public_key': 'test_public_key',
            'name': 'Test Device',
            'host_domain': 'test.com',
            'counter': 5  # Starting counter value
        })
    
    def test_counter_increment(self):
        """Test successful counter increment"""
        original_counter = self.passkey_obj.counter
        new_counter = original_counter + 3
        
        # Update counter
        result = self.passkey_obj.update_authentication_counter(new_counter)
        
        # Verify success
        self.assertTrue(result['success'])
        self.assertEqual(result['counter'], new_counter)
        
        # Verify database update
        self.passkey_obj.invalidate_recordset()
        self.assertEqual(self.passkey_obj.counter, new_counter)
    
    def test_counter_violation(self):
        """Test counter violation rejection"""
        current_counter = self.passkey_obj.counter
        
        # Attempt to use same counter value - should fail
        with self.assertRaises(UserError) as context:
            self.passkey_obj.update_authentication_counter(current_counter)
        
        # Verify error message
        error_msg = str(context.exception)
        self.assertIn('403|Authentication counter violation', error_msg)