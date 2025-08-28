# -*- coding: utf-8 -*-
from odoo.tests.common import TransactionCase
from odoo.exceptions import UserError
from datetime import datetime, timedelta
from odoo import fields
import hashlib


class TestSetupToken(TransactionCase):
    """Test suite for sunray.setup.token model"""

    def setUp(self):
        super().setUp()
        # Create test host
        self.host_obj = self.env['sunray.host'].create({
            'name': 'test.example.com',
            'domain': 'test.example.com'
        })
        
        # Create test user
        self.user_obj = self.env['sunray.user'].create({
            'username': 'testuser',
            'email': 'test@example.com',
            'is_active': True
        })
    
    def test_01_token_creation_and_hashing(self):
        """Test token creation with proper hashing"""
        token_obj, plain_token = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='Test Device',
            validity_hours=24,
            max_uses=1
        )
        
        # Verify token object was created
        self.assertTrue(token_obj)
        self.assertEqual(token_obj.user_id.id, self.user_obj.id)
        self.assertEqual(token_obj.host_id.id, self.host_obj.id)
        self.assertEqual(token_obj.device_name, 'Test Device')
        self.assertEqual(token_obj.max_uses, 1)
        self.assertEqual(token_obj.current_uses, 0)
        self.assertFalse(token_obj.consumed)
        
        # Verify token hash matches plain token
        expected_hash = f"sha512:{hashlib.sha512(plain_token.encode()).hexdigest()}"
        self.assertEqual(token_obj.token_hash, expected_hash)
        
        # Verify expiration is set correctly
        expected_expiry = fields.Datetime.now() + timedelta(hours=24)
        time_diff = abs((token_obj.expires_at - expected_expiry).total_seconds())
        self.assertLess(time_diff, 60)  # Within 1 minute tolerance
    
    def test_02_consume_single_use_token(self):
        """Test consuming a single-use token marks it as consumed"""
        token_obj, _ = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='Single Use Device',
            max_uses=1
        )
        
        # Initial state
        self.assertEqual(token_obj.current_uses, 0)
        self.assertFalse(token_obj.consumed)
        self.assertFalse(token_obj.consumed_date)
        
        # Consume token
        result = token_obj.consume()
        
        # Verify consumption result
        self.assertTrue(result['consumed'])
        self.assertEqual(result['current_uses'], 1)
        self.assertEqual(result['max_uses'], 1)
        
        # Verify token state updated
        self.assertEqual(token_obj.current_uses, 1)
        self.assertTrue(token_obj.consumed)
        self.assertTrue(token_obj.consumed_date)
    
    def test_03_consume_multi_use_token(self):
        """Test consuming a multi-use token increments properly"""
        token_obj, _ = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='Multi Use Device',
            max_uses=3
        )
        
        # First consumption
        result1 = token_obj.consume()
        self.assertFalse(result1['consumed'])
        self.assertEqual(result1['current_uses'], 1)
        self.assertEqual(token_obj.current_uses, 1)
        self.assertFalse(token_obj.consumed)
        
        # Second consumption
        result2 = token_obj.consume()
        self.assertFalse(result2['consumed'])
        self.assertEqual(result2['current_uses'], 2)
        self.assertEqual(token_obj.current_uses, 2)
        self.assertFalse(token_obj.consumed)
        
        # Third consumption (should mark as consumed)
        result3 = token_obj.consume()
        self.assertTrue(result3['consumed'])
        self.assertEqual(result3['current_uses'], 3)
        self.assertEqual(token_obj.current_uses, 3)
        self.assertTrue(token_obj.consumed)
        self.assertTrue(token_obj.consumed_date)
    
    def test_04_allowed_cidrs_parsing(self):
        """Test CIDR parsing with comments and inline comments"""
        token_obj, _ = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='CIDR Test Device',
            allowed_cidrs="""192.168.1.0/24    # Home network
10.0.0.0/8        # Corporate network
# This is a comment line
172.16.0.0/12     # VPN network
127.0.0.1         # Localhost
"""
        )
        
        expected_cidrs = [
            '192.168.1.0/24',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '127.0.0.1'
        ]
        
        parsed_cidrs = token_obj.get_allowed_cidrs()
        self.assertEqual(parsed_cidrs, expected_cidrs)
    
    def test_05_empty_allowed_cidrs(self):
        """Test that empty CIDR field returns empty list"""
        token_obj, _ = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='No CIDR Device',
            allowed_cidrs=''
        )
        
        parsed_cidrs = token_obj.get_allowed_cidrs()
        self.assertEqual(parsed_cidrs, [])
    
    def test_06_cidrs_only_comments(self):
        """Test CIDR field with only comments returns empty list"""
        token_obj, _ = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='Comments Only Device',
            allowed_cidrs="""# This is just a comment
# Another comment
# Third comment
"""
        )
        
        parsed_cidrs = token_obj.get_allowed_cidrs()
        self.assertEqual(parsed_cidrs, [])
    
    def test_07_user_auto_authorization(self):
        """Test that token creation auto-authorizes user for host"""
        # Verify user not initially authorized
        self.assertNotIn(self.user_obj, self.host_obj.user_ids)
        
        # Create token
        token_obj, _ = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='Auto Auth Test'
        )
        
        # Verify user is now authorized
        self.assertIn(self.user_obj, self.host_obj.user_ids)
    
    def test_08_cleanup_expired_tokens(self):
        """Test cleanup of expired tokens"""
        # Create expired token
        expired_token, _ = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='Expired Device'
        )
        # Force expiry
        expired_token.expires_at = fields.Datetime.now() - timedelta(hours=1)
        
        # Create valid token
        valid_token, _ = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='Valid Device'
        )
        
        # Create consumed but expired token (should not be cleaned)
        consumed_token, _ = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='Consumed Device'
        )
        consumed_token.expires_at = fields.Datetime.now() - timedelta(hours=1)
        consumed_token.consumed = True
        
        initial_count = self.env['sunray.setup.token'].search_count([])
        
        # Run cleanup
        self.env['sunray.setup.token'].cleanup_expired()
        
        final_count = self.env['sunray.setup.token'].search_count([])
        
        # Should remove only the expired unconsumed token
        self.assertEqual(final_count, initial_count - 1)
        
        # Verify specific tokens
        self.assertFalse(expired_token.exists())
        self.assertTrue(valid_token.exists())
        self.assertTrue(consumed_token.exists())
    
    def test_09_concurrent_consumption(self):
        """Test that multiple consume() calls work correctly"""
        token_obj, _ = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='Concurrent Test',
            max_uses=2
        )
        
        # Simulate concurrent consumption
        result1 = token_obj.consume()
        result2 = token_obj.consume()
        
        # Verify final state
        self.assertEqual(token_obj.current_uses, 2)
        self.assertTrue(token_obj.consumed)
        self.assertTrue(result2['consumed'])
        self.assertEqual(result2['current_uses'], 2)
    
    def test_10_consume_ensures_one(self):
        """Test that consume() method works on single record"""
        token_obj1, _ = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='Device 1'
        )
        
        token_obj2, _ = self.env['sunray.setup.token'].create_setup_token(
            user_id=self.user_obj.id,
            host_id=self.host_obj.id,
            device_name='Device 2'
        )
        
        # Single record should work
        result = token_obj1.consume()
        self.assertTrue(result)
        
        # Multiple records should fail
        with self.assertRaises(ValueError):
            (token_obj1 | token_obj2).consume()