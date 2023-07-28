from os.path import join
from bundlewrap.utils import get_file_contents
from bundlewrap.metadata import atomic

global repo, node, DoNotRunAgain, metadata_reactor

defaults = {}

# load default_configs, which is located next to us, but we have to do this limbo to import it
input_variables = {}
exec(get_file_contents(join(repo.path, 'bundles', 'exim', 'default_configs.py')), input_variables)
default_configs = input_variables.get('default_configs', {})

# load default_config into exim_config
defaults['exim'] = default_configs

# allow for additional ACL config via hook
defaults['exim']['acl_config'] = {
    'acl_smtp_mail': 'acl_check_mail',
    'acl_smtp_rcpt': 'acl_check_rcpt',
    'acl_smtp_data': 'acl_check_data',
    'acl_smtp_dkim': 'acl_check_dkim',
}

defaults['exim']['acl_add'] = {
    'acl_smtp_mail': {},
    'acl_smtp_rcpt': {},
    'acl_smtp_data': {},
    'acl_smtp_dkim': {},
}

defaults['exim']['dkim'] = {
    'defaults': {
        'canon': 'relaxed',
        'selector': '20161012',
    },
}


def sort_by_order(x):
    if isinstance(x, str):
        return '0010_{}'.format(x)

    if isinstance(x[1], dict):
        prio = x[1].get('order', 100)
    else:
        prio = 10

    return '{}_{}'.format(str(prio).zfill(3), x[0])


@metadata_reactor
def add_iptables_rules(metadata):
    if not node.has_bundle("iptables"):
        raise DoNotRunAgain

    # only open, if we are configured for internet or smarthost use
    if metadata.get('exim/configtype', '') in ('internet', 'smarthost'):
        ports = [25, 587, 465]

        interfaces = ['main_interface']
        interfaces += metadata.get('exim/additional_interfaces', [])

        iptables_rules = {}
        for interface in interfaces:
            for port in ports:
                iptables_rules += repo.libs.iptables.accept(). \
                    input(interface). \
                    state_new(). \
                    tcp(). \
                    dest_port(port)

        return iptables_rules

    return {}


@metadata_reactor
def add_restic_rules(metadata):
    if not node.has_bundle('restic'):
        raise DoNotRunAgain

    if metadata.get('exim/configtype', '') in ('internet', 'smarthost') and metadata.get('exim/vexim/enabled', False):
        # TODO: add spool and other directoryies
        # TODO: configure correct folder here
        return {
            'restic': {
                'backup_folders': {
                    '/var/opt/vmail',
                }
            }

        }

    return {}


@metadata_reactor
def add_dehydrated_hook(metadata):
    if not node.has_bundle('dehydrated'):
        raise DoNotRunAgain

    # is enabled by default
    if metadata.get('exim/tls/enabled', True):
        mail_hostnames = metadata.get('exim/hostnames', [node.hostname, ])

        return {
            'dehydrated': {
                'domains': {' '.join(mail_hostnames), },
                'hooks': {
                    'deploy_cert': {
                        'exim': [
                            f'if [ "$DOMAIN" = "{mail_hostnames[0]}" ]; then',
                            '  cp "$FULLCHAINFILE" /etc/exim4/exim.crt',
                            '  cp "$KEYFILE" /etc/exim4/exim.key',
                            '',
                            '  chown Debian-exim /etc/exim4/exim.crt',
                            '  chown Debian-exim /etc/exim4/exim.key',
                            '',
                            '  service exim4 restart',
                            'fi',
                        ]
                    }
                }
            }
        }
    else:
        return {}


@metadata_reactor
def add_acl_config(metadata):
    possible_acl = [
        'acl_not_smtp',
        'acl_not_smtp_mime',
        'acl_not_smtp_start',
        'acl_smtp_auth',
        'acl_smtp_connect',
        'acl_smtp_data',  # special
        'acl_smtp_data_prdr',
        'acl_smtp_dkim',  # special
        'acl_smtp_etrn',
        'acl_smtp_expn',
        'acl_smtp_helo',
        'acl_smtp_mail',  # special
        'acl_smtp_mailauth',
        'acl_smtp_mime',
        'acl_smtp_notquit',
        'acl_smtp_predata',
        'acl_smtp_quit',
        'acl_smtp_rcpt',  # special
        'acl_smtp_starttls',
        'acl_smtp_vrfy',
    ]

    special_variable_acl = {
        'acl_smtp_data': 'MAIN_ACL_CHECK_DATA',
        'acl_smtp_mail': 'MAIN_ACL_CHECK_MAIL',
        'acl_smtp_rcpt': 'MAIN_ACL_CHECK_RCPT',
        'acl_smtp_dkim': 'MAIN_ACL_CHECK_DKIM',
    }

    default_acl = {
        'acl_smtp_data': 'acl_check_data',
        'acl_smtp_mail': 'acl_check_mail',
        'acl_smtp_rcpt': 'acl_check_rcpt',
        'acl_smtp_dkim': 'acl_check_dkim',
    }

    config = {
        'exim': {
            'main': {
                'acl': {
                    'prio': 0,
                    'content': [],
                }
            }
        }
    }
    for acl in possible_acl:
        if metadata.get(f'exim/acl_config/{acl}', None) is not default_acl.get(acl, None):
            config['exim']['main']['acl']['content'] += [
                special_variable_acl.get(acl, acl) + ' = ' + metadata.get(f'exim/acl_config/{acl}'),
                ]

    if not config['exim']['main']['acl']['content']:
        return {}

    return config


@metadata_reactor
def convert_relay_domains(metadata):
    return {
        'exim': {
            'relay_domains': [x for x in metadata.get('exim/hubbed_hosts', {}).keys() if x not in
                              metadata.get('exim/blacklist_relay_domains', [])]
        }
    }


@metadata_reactor
def add_dkim_config(metadata):
    # TODO: seperate generation / checking
    if metadata.get('exim/dkim/enabled', False):
        default_config = metadata.get('exim/dkim/defaults', {})

        canon = ''
        canon_close = ''
        selector = ''
        selector_close = ''
        domain = ''
        domain_close = ''
        for dkim_domain, dkim_config in sorted(metadata.get('exim/dkim/domains', {}).items(), key=sort_by_order):
            canon += '${if eq {${lc:${domain:$h_from:}}}{'+dkim_domain+'} {' + \
                     dkim_config.get('canon', default_config.get('canon', 'relaxed')) + '}{'
            canon_close += '}}'
            selector += '${if eq {${lc:${domain:$h_from:}}}{' + dkim_domain + '} {' + \
                        dkim_config.get('selector', default_config.get('selector', '')) + '}{'
            selector_close += '}}'
            domain += '${if eq {${lc:${domain:$h_from:}}}{' + dkim_domain + '} {' + dkim_domain + '}{'
            domain_close += '}}'

        return {
            'exim': {
                'main': {
                    'dkim_macros': {
                        'prio': 0,
                        'content': [
                            f'DKIM_CANON = {canon}relaxed{canon_close}',
                            f'DKIM_SELECTOR = {selector}{selector_close}',
                            '',
                            '# Get the domain from the outgoing mail.',
                            f'DKIM_DOMAIN = {domain}{domain_close}',
                            '',
                            '# The file is based on the outgoing domain-name in the from-header.',
                            'DKIM_FILE = /etc/exim4/dkim/${dkim_selector}.${dkim_domain}.key',
                            '',
                            '# If key exists then use it, if not don\'t.',
                            'DKIM_PRIVATE_KEY = ${if exists{DKIM_FILE}{DKIM_FILE}{0}}',
                        ],
                    },
                    'enable_dkim': {
                        'prio': 5,
                        'content': [
                            '# Defines the access control list that is run when an',
                            '# SMTP DKIM command is received.',
                            '#',
                            '.ifndef MAIN_ACL_CHECK_DKIM',
                            'MAIN_ACL_CHECK_DKIM = acl_check_dkim',
                            '.endif',
                            'acl_smtp_dkim = MAIN_ACL_CHECK_DKIM',
                        ],
                    },
                },
                'acl': {
                    'local_dkim_check': {
                        'prio': 10,
                        'content': [
                            'acl_check_dkim:',
                            '      # Deny failures',
                            # '      deny',  # only warn
                            '      warn',
                            '           dkim_status = fail',
                            '           logwrite = DKIM test failed: $dkim_verify_reason',
                            '           add_header = X-DKIM: DKIM test failed: '
                            '(address=$sender_address domain=$dkim_cur_signer), signature is bad.',
                            '',
                            '',
                            '      # Deny invalid signatures',
                            # '      deny',  # only warn
                            '      warn',
                            '           dkim_status = invalid',
                            '           add_header = X-DKIM: $dkim_cur_signer '
                            '($dkim_verify_status); $dkim_verify_reason',
                            '           logwrite = DKIM test passed (address=$sender_address domain=$dkim_cur_signer), '
                            'but signature is invalid.',
                            '',
                            '      # Accept valid/passed sigs',
                            '      accept',
                            '           dkim_status = pass',
                            '           logwrite = DKIM test passed',
                            '           add_header = X-DKIM: DKIM passed:'
                            ' (address=$sender_address domain=$dkim_cur_signer), signature is good.',
                            '',
                            '',
                            '      # And anything else.',
                            '      accept',
                        ],
                    }
                }
            },
        }

    return {}


@metadata_reactor
def add_srs_config(metadata):
    if metadata.get('exim/srs/enabled', False):
        return {
            'exim': {
                'router': {
                    'srs': {
                        'prio': 175,
                        'content': [
                            'srs_bounce:',
                            '  debug_print = "R: srs_bounce for $local_part@$domain"',
                            '  driver = redirect',
                            '  allow_fail',
                            '  allow_defer',
                            '  domains = $primary_hostname',
                            '  local_part_prefix = srs0+ : srs0- : srs0= : srs1+ : srs1- : srs1=',
                            '  caseful_local_part',
                            '  address_data = ${readsocket{/tmp/srsd}{REVERSE $local_part_prefix$local_part@$domain}{5s}{\\n}{:defer: SRS daemon failure}}',
                            '  data = ${if match{$address_data}{^ERROR}{:fail: Invalid SRS address}{$address_data}}',
                            '',
                            'srs_forward:',
                            '  debug_print = "R: srs_forward for $local_part@$domain"',
                            '  no_verify',
                            '  senders = ! : ! *@+local_domains',
                            '  address_data = ${readsocket{/tmp/srsd}\\',
                            '                {FORWARD $sender_address_local_part@$sender_address_domain $primary_hostname\\n}\\',
                            '                                        {5s}{\\n}{:defer: SRS daemon failure}}',
                            '  errors_to = ${quote_local_part:${local_part:$address_data}}@${domain:$address_data}',
                            '  headers_add = "X-SRS: Sender address rewritten from <$sender_address> to <${quote_local_part:${local_part:$address_data}}@${domain:$address_data}> by $primary_hostname."',
                            '  driver = redirect',
                            '  repeat_use = false',
                            '  allow_defer',
                            '  data = ${quote_local_part:$local_part}@$domain',
                        ]
                    }
                }
            }
        }

    return {}


@metadata_reactor
def add_spamassassin_config(metadata):
    if metadata.get('exim/spamassassin/enabled', False):
        spamd_address = metadata.get('exim/spamassassin/address', '127.0.0.1')
        spamd_user = metadata.get('exim/spamassassin/user', 'debian-spamd')
        spamd_port = metadata.get('exim/spamassassin/port', 783)
        return {
            'exim': {
                'main': {
                    'spamassassin': {
                        'prio': 4,
                        'content': [
                            f'spamd_address = {spamd_address} {spamd_port}'
                        ],
                    }
                },
                'acl_add': {
                    'acl_smtp_data': {
                        'spamassassin': {
                            'prio': 100,
                            'add_content': [
                                '  # Reject messages with an "X-Spam-Flag: YES" header.',
                                '  deny    message   = Sender openly considers message as spam \\',
                                '                      (X-Spam-Flag header with a positive value was found).',
                                '          !hosts    = : +relay_from_hosts',
                                '          condition = ${if bool{$header_x-spam-flag:}{true}{false}}',
                                '',
                                '  # Remove internal headers',
                                '  warn',
                                '    remove_header = X-Spam_score: X-Spam_score_int : X-Spam_bar : \\',
                                '                    X-Spam_report',
                                '',
                                '  warn',
                                '    condition = ${if <{$message_size}{300k}{1}{0}}',
                                '    # ":true" to add headers/acl variables even if not spam',
                                f'   spam        = {spamd_user}:true',
                                '    add_header  = X-Spam_score: $spam_score',
                                '    add_header  = X-Spam_bar: $spam_bar',
                                '    # Do not enable this unless you have shorted SpamAssassin\'s report',
                                '    #add_header = X-Spam_report: $spam_report',
                                '',
                                # '  # Reject spam messages (score >15.0).',
                                # '  # This breaks mailing list and forward messages.',
                                # '  deny',
                                # '    condition = ${if <{$message_size}{300k}{1}{0}}',
                                # '    condition = ${if >{$spam_score_int}{150}{true}{false}}',
                                # '    message = Classified as spam (score $spam_score)',
                                '',

                            ],
                        },
                    },
                },
            },
        }

    return {}


@metadata_reactor
def add_greylistd_config(metadata):
    if metadata.get('exim/greylist/enabled', False):
        return {
            'exim': {
                'acl_add': {
                    'acl_smtp_rcpt': {
                        'greylist': {
                            'prio': 0,
                            'add_content': [
                                '  # greylistd(8) configuration follows.',
                                '  # This statement has been added by "greylistd-setup-exim4",',
                                '  # and can be removed by running "greylistd-setup-exim4 remove".',
                                '  # Any changes you make here will then be lost.',
                                '  #',
                                '  # Perform greylisting on incoming messages from remote hosts.',
                                '  # We do NOT greylist messages with no envelope sender, because that',
                                '  # would conflict with remote hosts doing callback verifications, and we',
                                '  # might not be able to send mail to such hosts for a while (until the',
                                '  # callback attempt is no longer greylisted, and then some).',
                                '  #',
                                '  # We also check the local whitelist to avoid greylisting mail from',
                                '  # hosts that are expected to forward mail here (such as backup MX hosts,',
                                '  # list servers, etc).',
                                '  #',
                                '  # Because the recipient address has not yet been verified, we do so',
                                '  # now and skip this statement for non-existing recipients.  This is',
                                '  # in order to allow for a 550 (reject) response below.  If the delivery',
                                '  # happens over a remote transport (such as "smtp"), recipient callout',
                                '  # verification is performed, with the original sender intact.',
                                '  #',
                                '  defer',
                                '    message        = $sender_host_address is not yet authorized to deliver \\',
                                '                     mail from <$sender_address> to <$local_part@$domain>. \\',
                                '                     Please try later.',
                                '    log_message    = greylisted.',
                                '    !senders       = :',
                                '    !hosts         = : +relay_from_hosts : \\',
                                '                     ${if exists {/etc/greylistd/whitelist-hosts}\\',
                                '                                 {/etc/greylistd/whitelist-hosts}{}} : \\',
                                '                     ${if exists {/var/lib/greylistd/whitelist-hosts}\\',
                                '                                 {/var/lib/greylistd/whitelist-hosts}{}}',
                                '    !authenticated = *',
                                '    !acl           = acl_local_deny_exceptions',
                                '    !dnslists      = ${if exists {/etc/greylistd/dnswl-known-good-sender}\\',
                                '                                 {${readfile{/etc/greylistd/dnswl-known-good-sender}}}{}}',
                                '    domains        = +local_domains : +relay_to_domains',
                                '    local_parts    = ${if exists {/etc/greylistd/whitelist-local-$domain}\\',
                                '                                 {!/etc/greylistd/whitelist-local-$domain_data}{*}}',
                                '    verify         = recipient',
                                '    condition      = ${readsocket{/var/run/greylistd/socket}\\',
                                '                                 {--grey \\',
                                '                                  $sender_host_address \\',
                                '                                  $sender_address \\',
                                '                                  $local_part@$domain}\\',
                                '                                 {5s}{}{false}}',
                                '',
                                '  # Deny if blacklisted by greylist',
                                '  deny',
                                '    message = $sender_host_address is blacklisted from delivering \\',
                                '                      mail from <$sender_address> to <$local_part@$domain>.',
                                '    log_message = blacklisted.',
                                '    !senders        = :',
                                '    !authenticated = *',
                                '    domains        = +local_domains : +relay_to_domains',
                                '    verify         = recipient',
                                '    condition      = ${readsocket{/var/run/greylistd/socket}\\',
                                '                                  {--black \\',
                                '                                   $sender_host_address \\',
                                '                                   $sender_address \\',
                                '                                   $local_part@$domain}\\',
                                '                                  {5s}{}{false}}',
                                '',
                                '',
                                '',
                            ],
                        },
                    },
                    'acl_smtp_data': {
                        'greylist': {
                            'prio': 0,
                            'add_content': [
                                '  # greylistd(8) configuration follows.',
                                '  # This statement has been added by "greylistd-setup-exim4",',
                                '  # and can be removed by running "greylistd-setup-exim4 remove".',
                                '  # Any changes you make here will then be lost.',
                                '  #',
                                '  # Perform greylisting on incoming messages with no envelope sender here.',
                                '  # We did not subject these to greylisting after RCPT TO:, because that',
                                '  # would interfere with remote hosts doing sender callout verifications.',
                                '  #',
                                '  # Because there is no sender address, we supply only two data items:',
                                '  #  - The remote host address',
                                '  #  - The recipient address (normally, bounces have only one recipient)',
                                '  #',
                                '  # We also check the local whitelist to avoid greylisting mail from',
                                '  # hosts that are expected to forward mail here (such as backup MX hosts,',
                                '  # list servers, etc).',
                                '  #',
                                '  defer',
                                '    message        = $sender_host_address is not yet authorized to deliver \\',
                                '                     mail from <$sender_address> to <$recipients>. \\',
                                '                     Please try later.',
                                '    log_message    = greylisted.',
                                '    senders        = :',
                                '    !hosts         = : +relay_from_hosts : \\',
                                '                     ${if exists {/etc/greylistd/whitelist-hosts}\\',
                                '                                 {/etc/greylistd/whitelist-hosts}{}} : \\',
                                '                     ${if exists {/var/lib/greylistd/whitelist-hosts}\\',
                                '                                 {/var/lib/greylistd/whitelist-hosts}{}}',
                                '    !authenticated = *',
                                '    !acl           = acl_local_deny_exceptions',
                                '    condition      = ${readsocket{/var/run/greylistd/socket}\\',
                                '                                 {--grey \\',
                                '                                  $sender_host_address \\',
                                '                                  $recipients}\\',
                                '                                 {5s}{}{false}}',
                                '',
                                '  # Deny if blacklisted by greylist',
                                '  deny',
                                '    message = $sender_host_address is blacklisted from delivering \\',
                                '                      mail from <$sender_address> to <$recipients>.',
                                '    log_message = blacklisted.',
                                '    !senders        = :',
                                '    !authenticated = *',
                                '    condition      = ${readsocket{/var/run/greylistd/socket}\\',
                                '                                  {--black \\',
                                '                                   $sender_host_address \\',
                                '                                   $recipients}\\',
                                '                                  {5s}{}{false}}',
                                '',
                                '',
                            ],
                        },
                    },
                },
            }
        }

    return {}


@metadata_reactor
def add_malware_config(metadata):
    if metadata.get('exim/malware/enabled', False):
        return {
            'exim': {
                'main': {
                    'malware': {
                        'prio': 4,
                        'content': [
                            'av_scanner = clamd:/run/clamav/clamd.ctl',  # TODO: make configurable
                        ],
                    }
                },
                'acl_add': {
                    'acl_smtp_data': {
                        'malware': {
                            'prio': 10,
                            'add_content': [
                                '  # Reject virus infested messages.',
                                '  #',
                                '  warn    message     = This message contains malware ($malware_name)',
                                '    malware     = *',
                                '    log_message = This message contains malware ($malware_name)',
                            ],
                        },
                    },
                },
            }
        }

    return {}
