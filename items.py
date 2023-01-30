# noinspection PyTypedDict
from os.path import join
from bundlewrap.utils import get_file_contents

global node, repo


def sort_by_prio(x):
    return "{p:50d}_{n}".format(p=int(x[1].get('prio', 10)), n=str(x[0]))


pkg_apt = {
    'spf-tools-perl': {
        'installed': True,
    },
}
pkg_pip = {}
files = {}
directories = {}
git_deploy = {}

actions = {
    'exim_update_config': {
        'command': '/usr/sbin/update-exim4.conf',
        'triggered': True,
        'needed_by': [
            'svc_systemd:exim4:restart',
        ],
    },
}

svc_systemd = {
    "exim4": {
        'needs': []
    },
}

exim_config = node.metadata.get('exim', {})

aliases_content = [
    '# /etc/aliases',
    'mailer-daemon: postmaster',
    'postmaster: root',
    'nobody: root',
    'hostmaster: root',
    'usenet: root',
    'news: root',
    '# webmaster: root',
    'www: root',
    'ftp: root',
    'abuse: root',
    'noc: root',
    'security: root',
]

aliases_content += ["{}: {}".format(x, y) for x, y in exim_config.get('additional_aliases', {}).items()]

needs_exim = []
if exim_config.get('type', 'light') == 'heavy':
    pkg_apt['exim4-daemon-heavy'] = {
        "installed": True,
        'needed_by': ['svc_systemd:exim4'],
        "when_creating": {
            "start_service": False,
        },
    }
    needs_exim += ['pkg_apt:exim4-daemon-heavy']
else:
    pkg_apt['exim4-daemon-light'] = {
        "installed": True,
        'needed_by': ['svc_systemd:exim4'],
        "when_creating": {
            "start_service": False,
        },
    }
    needs_exim += ['pkg_apt:exim4-daemon-light']

if exim_config.get('srs', {}).get('enabled', False):
    svc_systemd['srsd'] = {
        'needs': [
            'file:/etc/systemd/system/srsd.service',
            'file:/etc/srsd.secret',
        ]
    }
    pkg_apt['srs'] = {
        "installed": True,
        'needed_by': [
            'svc_systemd:srsd',
            'svc_systemd:exim4'
        ],
    }
    files['/etc/systemd/system/srsd.service'] = {
        'content_type': 'text',
        'owner': "root",
        'group': "root",
        'mode': "0444",
    }
    files['/etc/srsd.secret'] = {
        'content': repo.vault.password_for('exim_srs_secret_node_{}'.format(node.name), length=16).value + '\n',
        'content_type': 'text',
        'owner': "Debian-exim",
        'group': "root",
        'mode': "0600",
        'needs': needs_exim,
    }

if exim_config.get('malware', {}).get('enabled', False) and \
        exim_config.get('malware', {}).get('service', 'clamav') == 'clamav':
    pkg_apt['clamav-daemon'] = {
        "installed": True,
        'needed_by': [
            'svc_systemd:exim4'
        ],
        'needs': needs_exim,
    }

    if exim_config.get('srs', {}).get('enabled', False):
        pkg_apt['clamav-daemon']['needed_by'] += ['svc_systemd:srsd', ]

    aliases_content += ['clamav: root', ]


if exim_config.get('spamassassin', {}).get('enabled', False):
    svc_systemd['spamassassin'] = {
        'needed_by': [
            'svc_systemd:exim4'
        ],
    }
    pkg_apt['spamassassin'] = {
        "installed": True,
        'needed_by': [
            'svc_systemd:spamassassin',
        ],
        'needs': needs_exim,
    }
    pkg_apt['pyzor'] = {
        "installed": True,
        'needed_by': [
            'svc_systemd:spamassassin',
        ],
        'needs': needs_exim,
    }
    pkg_apt['razor'] = {
        "installed": True,
        'needed_by': [
            'svc_systemd:spamassassin',
        ],
        'needs': needs_exim,
    }
    pkg_apt['libgeo-ip-perl'] = {
        "installed": True,
        'needed_by': [
            'svc_systemd:spamassassin',
        ],
        'needs': needs_exim,
    }

    files['/etc/default/spamassassin'] = {
        'content_type': 'text',
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'needed_by': [
            'svc_systemd:spamassassin',
        ],
    }
    files['/etc/spamassassin/init.pre'] = {
        'content_type': 'text',
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'needed_by': [
            'svc_systemd:spamassassin',
        ],
    }

    # TODO: add context so we can add trusted networks
    files['/etc/spamassassin/local.cf'] = {
        'content_type': 'text',
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'needed_by': [
            'svc_systemd:spamassassin',
        ],
    }

    # TODO: add spamfilter

if exim_config.get('greylist', {}).get('enabled', False):
    greylist_config = exim_config['greylist']

    svc_systemd['greylistd'] = {}
    pkg_apt['greylistd'] = {
        "installed": True,
        'needed_by': [
            'svc_systemd:greylistd',
            'svc_systemd:exim4'
        ],
        'needs': needs_exim,
    }

    pkg_pip['py3dns'] = {"installed": True, }
    pkg_pip['pyspf'] = {"installed": True, }

    files['/etc/greylistd/config'] = {
        'source': 'greylist.config',
        'content_type': 'jinja2',
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'triggers': [
            'svc_systemd:greylistd:restart',
            'svc_systemd:exim4:restart',
        ],
        'context': {
            'single_update': greylist_config.get('single_update', False),
            'single_check': greylist_config.get('single_check', False),
            'save_triplets': greylist_config.get('save_triplets', True),
            'update_time': greylist_config.get('update_time', 600),
            'expire': greylist_config.get('expire', 5184000),
            'retry_max': greylist_config.get('retry_max', 28800),
            'retry_min': greylist_config.get('retry_min', 600),
        },
        'needs': ['pkg_apt:greylistd'],
    }

    directories['/opt/exim-tools'] = {
        'mode': '755',
        'owner': 'root',
        'group': 'root',
    }

    git_deploy['/opt/exim-tools'] = {
        'repo': 'ssh://github.com/shorst/tools.git',
        'rev': 'master',
    }

    actions['greylist_regenerate_whitelist'] = {
        'command': '/opt/exim-tools/generateWhitelist.py '
                   '/etc/greylistd/whitelist-domains.template '
                   '/etc/greylistd/whitelist-ips.template '
                   '/etc/greylistd/whitelist-hosts',
        'triggered': True,
        'needs': [
            'git_deploy:/opt/exim-tools',
        ],
        'needed_by': [
            'svc_systemd:greylistd',
            'svc_systemd:exim4',
        ]
    }

    files['/etc/greylistd/whitelist-domains.template'] = {
        'content': "\n".join(greylist_config.get('whitelist', {}).get('domains', [])) + '\n',
        'content_type': 'text',
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'triggers': [
            'action:greylist_regenerate_whitelist',
            'svc_systemd:greylistd:restart',
            'svc_systemd:exim4:restart',
        ],
        'needs': ['pkg_apt:greylistd'],
    }
    files['/etc/greylistd/whitelist-ips.template'] = {
        'content': "\n".join(greylist_config.get('whitelist', {}).get('ips', [])) + '\n',
        'content_type': 'text',
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'triggers': [
            'action:greylist_regenerate_whitelist',
            'svc_systemd:greylistd:restart',
            'svc_systemd:exim4:restart',
        ],
        'needs': ['pkg_apt:greylistd'],
    }


local_interfaces_ips = ['127.0.0.1', '::1']

for add_interfaces in [node.metadata.get('main_interface', 'eth0')] + exim_config.get('additional_interfaces', []):
    local_interfaces_ips += node.metadata.get('interfaces', {}).get(add_interfaces, {}).get('ip_addresses', [])
    local_interfaces_ips += node.metadata.get('interfaces', {}).get(add_interfaces, {}).get('ipv6_addresses', [])

files['/etc/exim4/update-exim4.conf.conf'] = {
    'content_type': 'jinja2',
    'owner': 'root',
    'group': 'root',
    'mode': '0644',
    'triggers': [
        'action:exim_update_config',
        'svc_systemd:exim4:restart',
    ],
    'context': {
        'dc_eximconfig_configtype': exim_config.get('configtype', 'local'),
        'dc_other_hostnames': exim_config.get('hostnames', []),
        'dc_local_interfaces': local_interfaces_ips,
        'dc_readhost': exim_config.get('dc_readhost', [node.hostname, ]),
        'dc_relay_domains': sorted(list(set(exim_config.get('relay_domains', [])))),
        'dc_minimaldns': str(exim_config.get('minimaldns', False)).lower(),
        'dc_relay_nets': exim_config.get('relay_nets', []),
        'dc_smarthost': exim_config.get('smarthost', ''),
        'CFILEMODE': exim_config.get('CFILEMODE', '644'),
        'dc_hide_mailname': str(exim_config.get('hide_mailname', False)).lower(),
        'dc_mailname_in_oh': str(exim_config.get('mailname_in_oh', True)).lower(),
        'dc_localdelivery': exim_config.get('localdelivery', 'mail_spool'),
    },
    'needs': needs_exim,
}

files['/etc/mailname'] = {
    'content': exim_config.get('mailname', node.hostname) + "\n",
    'owner': 'root',
    'group': 'root',
    'mode': '0644',
    'needs': needs_exim,
}

if exim_config.get('hubbed_hosts', {}):
    files['/etc/exim4/hubbed_hosts'] = {
        'content': '\n'.join([f'{h}: ' + ':'.join(i) for h, i in exim_config.get('hubbed_hosts', {}).items()]) + '\n',
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'triggers': [
            'svc_systemd:exim4:restart',
        ],
        'needs': needs_exim,
    }
else:
    files['/etc/exim4/hubbed_hosts'] = {
        'delete': True,
        'triggers': [
            'svc_systemd:exim4:restart',
        ],
        'needs': needs_exim,
    }

files['/etc/aliases'] = {
    'content': "\n".join(aliases_content) + "\n",
    'owner': 'root',
    'group': 'root',
    'mode': '0644',
    'triggers': [
        'svc_systemd:exim4:restart',
    ],
    'needs': needs_exim,
}

generated_config = []

acl_overwrites_high_prio = {}
acl_overwrites_low_prio = {
    '  .ifdef LOCAL_DENY_EXCEPTIONS_LOCAL_ACL_FILE': [],  # readd comment, which will get deleted later
}
for acl_name, acl_adds in exim_config.get('acl_add', {}).items():
    content_hp = []
    content_lp = []
    for acl_sub_name, acl_add_content in sorted(acl_adds.items(), key=sort_by_prio):
        if acl_name not in ('acl_smtp_rcpt', 'acl_smtp_data') or acl_add_content.get('prio', 0) < 100:
            content_hp += acl_add_content.get('add_content', [])
        else:
            content_lp += acl_add_content.get('add_content', [])
    acl_overwrites_high_prio[exim_config.get('acl_config', {}).get(acl_name, acl_name) + ':'] = content_hp

    if acl_name == 'acl_smtp_rcpt':
        acl_overwrites_low_prio['  .ifdef CHECK_RCPT_LOCAL_ACL_FILE'] = content_lp
    elif acl_name == 'acl_smtp_data':
        acl_overwrites_low_prio['  .ifdef CHECK_DATA_LOCAL_ACL_FILE'] = content_lp

remove_lines = [
    '  # This hook allows you to hook in your own ACLs without having to',
    '  # modify this file. If you do it like we suggest, you\'ll end up with',
    '  # a small performance penalty since there is an additional file being',
    '  # accessed. This doesn\'t happen if you leave the macro unset.',
]

# load in correct order
for config_group in ['main', 'acl', 'router', 'transport', 'retry', 'rewrite', 'auth']:
    # order by prio
    for config_name, config in sorted(exim_config.get(config_group, {}).items(), key=sort_by_prio):
        if config.get('disabled', False):
            continue
        generated_config += [
            '#####################################################',
            '### {group}/{prio:02d}_{name}'.format(
                group=config_group,
                prio=config.get('prio', 10),
                name=config_name
            ),
            '#####################################################'
        ]

        if config_group == 'main':
            for line in config.get('content', []):
                if line == 'UPEX4CmacrosUPEX4C = 1':
                    # add macros right after debian macros
                    generated_config += [line, '', ]
                    generated_config += exim_config.get('after_UPEX4CmacrosUPEX4C', [])
                else:
                    generated_config.append(line)

            generated_config += config.get('additional_content', [])
        elif config_group == 'acl':
            for line in config.get('content', []):
                if line in acl_overwrites_high_prio.keys():
                    generated_config += [line, ]
                    generated_config += acl_overwrites_high_prio[line]
                elif line in acl_overwrites_low_prio.keys():
                    # add before the ifdef line
                    generated_config += acl_overwrites_low_prio[line]
                    generated_config += [
                        '  # This hook allows you to hook in your own ACLs without having to',
                        '  # modify this file. If you do it like we suggest, you\'ll end up with',
                        '  # a small performance penalty since there is an additional file being',
                        '  # accessed. This doesn\'t happen if you leave the macro unset.',
                        line,
                    ]
                elif line in remove_lines:
                    pass
                else:
                    generated_config.append(line)

            generated_config += config.get('additional_content', [])
        else:
            generated_config += config.get('content', [])
            generated_config += config.get('additional_content', [])

        generated_config += [
            '#####################################################',
            '### end {group}/{prio:02d}_{name}'.format(
                group=config_group,
                prio=config.get('prio', 10),
                name=config_name
            ),
            '#####################################################'
        ]

files['/etc/exim4/exim4.conf.template'] = {
    'content': "\n".join(generated_config) + "\n",
    'owner': 'root',
    'group': 'root',
    'mode': '0644',
    'triggers': [
        'action:exim_update_config',
        'svc_systemd:exim4:restart',
    ],
    'needs': needs_exim,
    # 'verify_with': "/usr/sbin/update-exim4.conf --check",
}
files['/etc/default/exim4'] = {
    'owner': 'root',
    'group': 'root',
    'mode': '0644',
    'triggers': [
        'svc_systemd:exim4:restart',
    ],
    'needs': needs_exim,
}

# TODO: seperate generation / checking
if exim_config.get('dkim', {}).get('enabled', False):
    directories['/etc/exim4/dkim'] = {
        'mode': '755',
        'owner': 'root',
        'group': 'Debian-exim',
        'needs': needs_exim,
    }
    for domain, config in exim_config['dkim'].get('domains', {}).items():
        selector = config.get('selector', exim_config['dkim'].get('defaults', {}).get('selector', '20161012'))
        files[f'/etc/exim4/dkim/{selector}.{domain}.crt'] = {
            'content': get_file_contents(
                join(repo.path, "data", "dkim_keys", config.get('crt', f'{selector}.{domain}.crt'))
            ),
            'content_type': 'text',
            'owner': "Debian-exim",
            'group': "Debian-exim",
            'mode': "0400",
            'needs': needs_exim,
        }

        files[f'/etc/exim4/dkim/{selector}.{domain}.key'] = {
            'content': repo.vault.decrypt_file(
                join("dkim_keys", config.get('key', f'{selector}.{domain}.key'))
            ),
            'content_type': 'text',
            'owner': "Debian-exim",
            'group': "Debian-exim",
            'mode': "0400",
            'needs': needs_exim,
        }
