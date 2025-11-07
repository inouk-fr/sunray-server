# -*- coding: utf-8 -*-
from odoo import models, fields, api


class SunrayProtectedHostUserListReport(models.Model):
    """Report model for displaying user statistics per protected host

    This model provides a computed view of users with host-specific statistics.
    Records are computed on-the-fly based on the host's authorized users.

    Table name: protected_host_user_list_report
    """
    _name = 'sunray.protected_host_user_list_report'
    _description = 'Protected Host User List Report - Sunray'
    _rec_name = 'user_id'
    _order = 'username'

    # Relations
    host_id = fields.Many2one(
        'sunray.host',
        string='Host',
        required=True,
        ondelete='cascade'
    )
    user_id = fields.Many2one(
        'sunray.user',
        string='User',
        required=True,
        ondelete='cascade'
    )

    # Related fields from user for display
    username = fields.Char(
        related='user_id.username',
        string='Username',
        readonly=True,
        store=True
    )
    email = fields.Char(
        related='user_id.email',
        string='Email',
        readonly=True,
        store=True
    )
    is_active = fields.Boolean(
        related='user_id.is_active',
        string='Active',
        readonly=True,
        store=True
    )

    # Host-specific computed statistics
    passkey_count = fields.Integer(
        compute='_compute_stats',
        string='Passkeys',
        store=True,
        help='Number of passkeys for this user on this specific host'
    )
    setup_token_count = fields.Integer(
        compute='_compute_stats',
        string='Setup Tokens',
        store=True,
        help='Number of setup tokens for this user on this specific host'
    )
    active_session_count = fields.Integer(
        related='user_id.active_session_count',
        string='Active Sessions',
        readonly=True
    )
    last_login = fields.Datetime(
        related='user_id.last_login',
        string='Last Login',
        readonly=True
    )

    @api.depends('user_id.passkey_ids', 'user_id.setup_token_ids', 'host_id.domain')
    def _compute_stats(self):
        """Compute host-specific statistics for each user"""
        for stat_obj in self:
            if not stat_obj.user_id or not stat_obj.host_id:
                stat_obj.passkey_count = 0
                stat_obj.setup_token_count = 0
                continue

            # Count passkeys for this host
            stat_obj.passkey_count = len(stat_obj.user_id.passkey_ids.filtered(
                lambda p: p.host_domain == stat_obj.host_id.domain
            ))

            # Count setup tokens for this host
            stat_obj.setup_token_count = len(stat_obj.user_id.setup_token_ids.filtered(
                lambda t: t.host_id.id == stat_obj.host_id.id
            ))

    def btn_remove_user(self):
        """Remove user from host and delete all host-specific credentials

        This action will:
        - Remove user from host's authorized users
        - Delete all passkeys for this user on this host
        - Delete all setup tokens for this user on this host
        - Revoke all active sessions for this user on this host
        """
        self.ensure_one()

        user = self.user_id
        host = self.host_id

        # Delete passkeys for this host
        passkeys_to_delete = user.passkey_ids.filtered(
            lambda p: p.host_domain == host.domain
        )
        if passkeys_to_delete:
            passkeys_to_delete.unlink()

        # Delete setup tokens for this host
        tokens_to_delete = user.setup_token_ids.filtered(
            lambda t: t.host_id.id == host.id
        )
        if tokens_to_delete:
            tokens_to_delete.unlink()

        # Revoke active sessions for this user on this host
        sessions_to_revoke = self.env['sunray.session'].search([
            ('user_id', '=', user.id),
            ('host_id', '=', host.id),
            ('is_active', '=', True)
        ])
        if sessions_to_revoke:
            for session in sessions_to_revoke:
                session.revoke(f'User removed from host {host.domain}')

        # Remove user from host
        host.write({
            'user_ids': [(3, user.id)]  # Unlink user from host
        })

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'User Removed',
                'message': f'User {user.username} removed from {host.domain}. '
                          f'Deleted {len(passkeys_to_delete)} passkey(s), '
                          f'{len(tokens_to_delete)} setup token(s), '
                          f'and revoked {len(sessions_to_revoke)} session(s).',
                'type': 'success',
            }
        }
