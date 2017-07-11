Role Name
=========

Install and configures iptables for IPv4 and IPv6

Requirements
------------

This role requires Ansible 1.9 or higher.

Role Variables
--------------

Default values:

```yaml
#### IPv4 ####
iptables_enabled: yes                   # The role is enabled
iptables_logging: yes                   # Log dropped packets

iptables_deny_all : yes                 # Deny all except allowed


## Filter Table ##
iptables_allowed_sources: []            # List of allowed source

iptables_allowed_tcp_ports: [22]        # List of allowed tcp ports

iptables_allowed_udp_ports: []          # List of allowed udp ports

iptables_filter_rules: []               # List of custom filter table rules
                                        # Ex. iptables_filter_rules:
                                        #     - -A INPUT -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT
                                        #     - -A INPUT -i eth0 -p tcp -m tcp --dport 80 -j ACCEPT

## Nat Table ##
iptables_forwarded_tcp_ports: []        # Forward tcp ports
                                        # Ex. iptables_forwarded_tcp_ports:
                                        #       - { from: 22, to: 2222 }

iptables_forwarded_udp_ports: []        # Ex. iptables_forwarded_udp_ports:
                                        #       - { from: 22, to: 2222 }

iptables_dnat_tcp: []                   # DNAT tcp rules
                                        # Ex. iptables_dnat_tcp:
                                        #       - { in_interface: eth0, from: 2222, to: '192.168.0.100:22' }

iptables_dnat_udp: []                   # DNAT udp rules
                                        # Ex. iptables_dnat_udp:
                                        #       - { in_interface: eth0, from: 2222, to: '192.168.0.100:22' }

iptables_snat: []                       # SNAT rules
                                        # Ex. iptables_snat:
                                        #       - { out_interface: eth0, from: '10.0.0.0/24', to: 192.168.0.1 }

iptables_masquerade: []                 # MASQUERADE rules
                                        # Ex. iptables_masquerade:
                                        #       - { out_interface: eth0, from: 10.0.0.0/24 }

iptables_nat_rules: []                  # List of custom nat table rules
                                        # Ex. iptables_nat_rules:
                                        #     - -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j SNAT --to-source 192.168.0.1

## Mangle Table ##
iptables_mangle_rules: []               # List of custom mangle table rules
                                        # Ex. iptables_nat_rules:
                                        #     - -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

## Raw Table ##
iptables_raw_table_enabled: no
iptables_raw_rules: []                  # List of custom raw table rules

#### IPv6 ####
ip6tables_enabled: yes                  # The role is enabled
ip6tables_logging: yes                  # Log dropped packets

## Filter Table ##
ip6tables_allowed_sources: []           # List of allowed source

ip6tables_allowed_tcp_ports: [22]       # List of allowed tcp ports

ip6tables_allowed_udp_ports: []         # List of allowed udp ports

ip6tables_filter_rules: []              # List of custom filter table rules
                                        # Ex. iptables_filter_rules:
                                        #     - -A INPUT -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT
                                        #     - -A INPUT -i eth0 -p tcp -m tcp --dport 80 -j ACCEPT

## Nat Table ##
ip6tables_forwarded_tcp_ports: []       # Forward tcp ports
                                        # Ex. iptables_forwarded_tcp_ports:
                                        #       - { from: 22, to: 2222 }

ip6tables_forwarded_udp_ports: []       # Ex. iptables_forwarded_udp_ports:
                                        #       - { from: 22, to: 2222 }

ip6tables_dnat_tcp: []                  # DNAT tcp rules
                                        # Ex. iptables_dnat_tcp:
                                        #       - { in_interface: eth0, from: 2222, to: '[2001:555:111:01::1]:22' }

ip6tables_dnat_udp: []                  # DNAT udp rules
                                        # Ex. iptables_dnat_udp:
                                        #       - { in_interface: eth0, from: 2222, to: '[2001:555:111:01::1]:22' }

ip6tables_snat: []                      # SNAT rules
                                        # Ex. iptables_snat:
                                        #       - { out_interface: eth0, from: '2001:555:111:02::1/64', to: '2001:555:111:01::1' }

ip6tables_masquerade: []                # MASQUERADE rules
                                        # Ex. iptables_masquerade:
                                        #       - { out_interface: eth0, from: '2001:555:111:02::1/64' }

ip6tables_nat_rules: []                 # List of custom nat table rules
                                        # Ex. iptables_nat_rules:
                                        #     - -A POSTROUTING -s '2001:555:111:02::1/64' -o eth0 -j SNAT --to-source '2001:555:111:01::1'

## Mangle Table ##
ip6tables_mangle_rules: []              # List of custom mangle table rules
```

Debian/Ubuntu values:
```yaml
iptables_confdir: /etc/iptables

iptables_rules_path: "{{ iptables_confdir }}/rules.v4"  # Path iptables to rule file

ip6tables_rules_path: "{{ iptables_confdir }}/rules.v6" # Path ip6tables to rule file
```

RedHat/CentOS values:
```yaml
iptables_confdir: /etc/sysconfig

iptables_rules_path: "{{ iptables_confdir }}/iptables"  # Path to rule file

ip6tables_rules_path: "{{ iptables_confdir }}/ip6tables"  # Path to rule file
```

Dependencies
------------

None

Example Playbook
----------------

```yaml
  - hosts: all
    roles:
      - ansible-iptables
    vars:
      iptables_allowed_sources:
        - 192.168.0.0/24
      iptables_allowed_tcp_ports:
        - 22
        - 80
        - 443
      iptables_filter_rules:
        - -A INPUT -p icmp -j ACCEPT
        - -A OUTPUT -p udp --dport 123 -j ACCEPT
        - -A INPUT -p udp --sport 123 -j ACCEPT
      ip6tables_allowed_sources:
        - '2001:222:4562::/48'
      ip6tables_allowed_tcp_ports:
        - 22
        - 80
        - 443
      ip6tables_filter_rules:
        - -A INPUT -p icmpv6 -j ACCEPT
        - -A OUTPUT -p udp --dport 123 -j ACCEPT
        - -A INPUT -p udp --sport 123 -j ACCEPT
```

License
-------

Licensed under the GPLv3 License. See the LICENSE file for details.

Author Information
------------------

Hispanico
