# -*- coding: utf-8 -*-
{
    'name': 'Sunray Enterprise',
    'version': '1.0',
    'category': 'Security',
    'summary': 'Advanced features for Sunray Zero Trust Access',
    'description': """
Sunray Enterprise Edition
==========================

Advanced features for Sunray Zero Trust Access solution:
* Email notifications for setup tokens
* Advanced analytics and reporting
* Enhanced audit logging
* Custom branding options
* Priority support
    """,
    'author': 'Inouk',
    'website': 'https://sunray-zero-trust.com',
    'depends': ['sunray_core', 'mail'],
    'data': [
        'security/ir.model.access.csv',
        'data/ir_config_parameter.xml',
        'data/mail_templates.xml',
        'views/res_config_settings_views.xml',
        'wizards/setup_token_wizard_views.xml',
        'views/sunray_menu.xml',
    ],
    'installable': True,
    'application': False,
    'auto_install': False,
    'license': 'LGPL-3',
}
