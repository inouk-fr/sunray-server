# -*- coding: utf-8 -*-
from odoo import models, fields


class SunrayAuditLogEnterprise(models.Model):
    _inherit = 'sunray.audit.log'

    event_type = fields.Selection(
        selection_add=[
            # Token Email Events
            ('token.email.sent', 'Token Email Sent'),
            ('token.email.no_template', 'Token Email No Template'),
            ('token.email.no_recipient', 'Token Email No Recipient'),
            ('token.email.error', 'Token Email Error'),
        ],
        ondelete={
            'token.email.sent': 'cascade',
            'token.email.no_template': 'cascade',
            'token.email.no_recipient': 'cascade',
            'token.email.error': 'cascade',
        }
    )
