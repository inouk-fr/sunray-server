# -*- coding: utf-8 -*-
from odoo import models, fields, api


class SetupTokenWizardEnterprise(models.TransientModel):
    _inherit = 'sunray.setup.token.wizard'

    # Email fields
    send_email = fields.Boolean(
        string='Email Setup Token',
        default=False,
        help='Send the setup token to the user by email'
    )
    email_sent = fields.Boolean(
        string='Email Sent',
        readonly=True,
        default=False
    )
    email_error = fields.Text(
        string='Email Error',
        readonly=True
    )

    def _get_mail_template(self):
        """Get the mail template from system settings"""
        template_xmlid = self.env['ir.config_parameter'].sudo().get_param(
            'sunray.setup_token_mail_template',
            'sunray_enterprise.mail_template_setup_token_v2'
        )
        try:
            return self.env.ref(template_xmlid)
        except ValueError:
            # Fallback to default template if configured one doesn't exist
            return self.env.ref('sunray_enterprise.mail_template_setup_token_v2', raise_if_not_found=False)

    def generate_token(self):
        """Override to add email sending"""
        # Call parent to generate token
        result = super(SetupTokenWizardEnterprise, self).generate_token()

        # Send email if requested
        if self.send_email and self.generated_token:
            # Get the token object
            token_obj = self.env['sunray.setup.token'].search([
                ('user_id', '=', self.user_id.id),
                ('device_name', '=', self.device_name)
            ], limit=1, order='create_date DESC')

            if token_obj:
                self._send_token_email(token_obj, self.generated_token)

        return result

    def _send_token_email(self, token_obj, token_value):
        """Send setup token email to user

        Args:
            token_obj: The sunray.setup.token record
            token_value: The plain text token value to include in email
        """
        self.ensure_one()

        try:
            template = self._get_mail_template()

            if not template:
                error_msg = "No email template configured. Please configure a default template in Settings."
                self.email_error = error_msg
                self.email_sent = False

                # Log error
                self.env['sunray.audit.log'].create_audit_event(
                    event_type='token.email.no_template',
                    details={
                        'username': self.user_id.username,
                        'host': self.host_id.domain,
                        'device_name': self.device_name,
                        'error': error_msg
                    },
                    severity='error',
                    sunray_user_id=self.user_id.id,
                    username=self.user_id.username
                )
                return

            # Verify user has email
            if not self.user_id.email:
                error_msg = f"User {self.user_id.username} has no email address configured."
                self.email_error = error_msg
                self.email_sent = False

                # Log error
                self.env['sunray.audit.log'].create_audit_event(
                    event_type='token.email.no_recipient',
                    details={
                        'username': self.user_id.username,
                        'host': self.host_id.domain,
                        'device_name': self.device_name,
                        'error': error_msg
                    },
                    severity='warning',
                    sunray_user_id=self.user_id.id,
                    username=self.user_id.username
                )
                return

            # Send email with token_value in context
            template.with_context(token_value=token_value).send_mail(
                token_obj.id,
                force_send=True,
                raise_exception=True
            )

            self.email_sent = True
            self.email_error = False

            self.env['sunray.audit.log'].create_audit_event(
                event_type='token.email.sent',
                details={
                    'username': self.user_id.username,
                    'email': self.user_id.email,
                    'host': self.host_id.domain,
                    'device_name': self.device_name,
                    'template': template.name
                },
                severity='info',
                sunray_user_id=self.user_id.id,
                username=self.user_id.username
            )

        except Exception as e:
            error_msg = f"Failed to send email: {str(e)}"
            self.email_error = error_msg
            self.email_sent = False

            self.env['sunray.audit.log'].create_audit_event(
                event_type='token.email.error',
                details={
                    'username': self.user_id.username,
                    'email': self.user_id.email,
                    'host': self.host_id.domain,
                    'device_name': self.device_name,
                    'error': str(e)
                },
                severity='error',
                sunray_user_id=self.user_id.id,
                username=self.user_id.username
            )
