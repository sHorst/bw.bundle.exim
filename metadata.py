from os.path import join
from bundlewrap.utils import get_file_contents
from bundlewrap.metadata import atomic

defaults = {}

# load default_configs, which is located next to us, but we have to do this limbo to import it
input_variables = {}
exec(get_file_contents(join(repo.path, 'bundles', 'exim', 'default_configs.py')), input_variables)
default_configs = input_variables.get('default_configs', {})

# load default_config into exim_config
defaults['exim'] = default_configs


@metadata_reactor
def add_iptables_rules(metadata):
    if not node.has_bundle("iptables"):
        raise DoNotRunAgain

    # only open, if we are configured for internet use
    if metadata.get('exim/configtype', '') == 'internet':
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

    if metadata.get('exim/configtype', '') == 'internet':
        # TODO: add spool and other directoryies
        # TODO: configure correct folder here
        return {
            'restic': {
                'backup_folders': ['/var/opt/vmail', ]
            }

        }

    return {}


@metadata_reactor
def add_dkim_config(metadata):
    if metadata.get('exim/dkim/enabled', False):
        return {
            'exim': {
                'main': {
                    'dkim_macros': {
                        'prio': 0,
                        'content': [
                            # TODO: make configurable by domain
                            'DKIM_CANON = relaxed',
                            # TODO: make configurable by domain
                            'DKIM_SELECTOR = 20161012',
                            '',
                            '# Get the domain from the outgoing mail.',
                            'DKIM_DOMAIN = ${sg{${lc:${domain:$h_from:}}}{^www\.}{}}',
                            '',
                            '# The file is based on the outgoing domain-name in the from-header.',
                            'DKIM_FILE = /etc/exim4/dkim/DKIM_DOMAIN.key',
                            '',
                            '# If key exists then use it, if not don\'t.',
                            'DKIM_PRIVATE_KEY = ${if exists{DKIM_FILE}{DKIM_FILE}{0}}',
                        ],
                    },
                    'enable_dkim': {
                        'prio': 5,
                        'content': [
                            'acl_smtp_dkim = acl_check_dkim',
                        ],
                    },
                },
                'acl': {
                    'local_dkim_check': {
                        'prio': 10,
                        'content': [
                            'acl_check_dkim:',
                            '      accept', # TODO: remove this
                            '',
                            '      # Deny failures',
                            '      deny',
                            '           dkim_status = fail',
                            '           logwrite = DKIM test failed: $dkim_verify_reason',
                            '           add_header = X-DKIM: DKIM test failed: '
                            '(address=$sender_address domain=$dkim_cur_signer), signature is bad.',
                            '',
                            '',
                            '      # Deny invalid signatures',
                            '      deny',
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
def add_greylistd_config(metadata):
    if metadata.get('exim/greylist/enabled', False):
        if 'exim4-config_check_rcpt' not in metadata.get('exim/acl', {}) \
                or 'exim4-config_check_data' not in metadata.get('exim/acl', {}):
            return {}

        # patch greylist into config
        check_rcpt = []
        check_data = []

        for line in metadata.get('exim/acl/exim4-config_check_rcpt/content'):
            if line == 'acl_check_rcpt:':
                check_rcpt += [
                    'acl_check_rcpt:',
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
                ]
            else:
                check_rcpt.append(line)

        for line in metadata.get('exim/acl/exim4-config_check_data/content'):
            if line == 'acl_check_data:':
                check_data += [
                    'acl_check_data:',
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
                ]
            else:
                check_data.append(line)

        return {
            'exim': {
                'acl': {
                    'exim4-config_check_rcpt': {
                        'content': atomic(check_rcpt),
                    },
                    'exim4-config_check_data': {
                        'content': atomic(check_data),
                    }

                },
            }
        }

    return {}
