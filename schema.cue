package fastnetmon

import (
	"net"
)

config: [string]: main: #FastNetMon_Main
config: [string]: hostgroups: [...#FastNetMon_Hostgroup_Default]
config: [string]: bgpSessions: [...#FastNetMon_BGP]
config: [string]: trafficRules: [...#FastNetMon_TrafficRule]

#FastNetMon_Main: {
	// af_packet
	mirror_afpacket:                             bool | *false     // Enable capture from mirror port using AF_PACKET capture engine
	interfaces:                                  [...string] | *[] // Interfaces list for traffic capture
	af_packet_extract_tunnel_traffic:            bool | *false     // Enables for af_packet code which strips external level for GRE tunnels
	mirror_af_packet_sampling:                   bool | *true      // Enables sampling for mirror mode offloaded on kernel / driver level
	mirror_af_external_packet_sampling:          bool | *false     // Enables external sampling for mirror mode when router or switch does sampling
	mirror_af_packet_socket_stats:               bool | *true      // Enables capture socket performance statistics
	mirror_af_packet_disable_multithreading:     bool | *true      // Disables multi thread processing and handles all traffic using single thread
	mirror_af_packet_fanout_mode:                string | *"cpu"   // Fanout mode. Algorithm to spread load over threads
	af_packet_use_new_generation_parser:         bool | *false     // Enable new improved packet parser (experimental)
	mirror_af_packet_sampling_rate:              >=0 | *100        // Sampling rate for AF_PACKET
	mirror_external_af_packet_sampling_rate:     >=0 | *100        // External sampling rate for AF_PACKET
	mirror_af_packet_workers_number_override:    bool | *false     // Enables logic to explicitly override number of worker processes
	mirror_af_packet_workers_number:             >=0 | *1          // Specifies how many worker processes we need for each interface
	afpacket_strict_cpu_affinity:                bool | *false     // Enables strict CPU affinity and binds traffic capture threads to fixed logical CPUs
	af_packet_read_packet_length_from_ip_header: bool | *false     // By default, FastNetMon reads packet length from the wire. But it can use information from IP header when you enable this option

	// api
	enable_api: bool | *true          // Enable internal FastNetMon API. It’s mandatory for fcli and public web API
	api_host:   net.IP | *"127.0.0.1" // Internal API host for listening
	api_port:   >0 & <=65535 | *50052 // Internal API port for listening

	// ban_management
	enable_ban:                               bool | *false // Completely enable or disable all ban actions
	enable_ban_hostgroup:                     bool | *false // Completely enable or disable all ban for total traffic per hostgroup
	enable_ban_remote_outgoing:               bool | *false // Enable blocking for remote hosts in outgoing direction
	enable_ban_remote_incoming:               bool | *false // Enable blocking for remote hosts in incoming direction
	do_not_ban_incoming:                      bool | *false // Completely disables ban for incoming traffic
	do_not_ban_outgoing:                      bool | *false // Completely disables ban for outgoing traffic
	per_direction_hostgroup_thresholds:       bool | *true  // Changes hostgroup thresholds to be per direction. Default becomes incoming
	flexible_thresholds:                      bool | *false // Enables flexible thresholds logic
	flexible_thresholds_disable_multi_alerts: bool | *false // Enables compatibility mode for flexible threshold which triggers attack only using single threshold and only in single direction
	keep_flow_spec_announces_during_restart:  bool | *false // Saves list of flow spec announces on shutdown and restores it on startup
	keep_blocked_hosts_during_restart:        bool | *false // Saves list of blocked hosts on shutdown and restores it on startup
	enable_ban_ipv6:                          bool | *false // Completely enable or disable all ban actions for IPv6 traffic
	unban_enabled:                            bool | *true  // We will try to unban blocked IPs after this time expires
	ban_status_updates:                       bool | *false // FastNetMon will report active attacks every X seconds
	ban_status_delay:                         >=0 | *20     // How often FastNetMon will update external systems about active attacks
	ban_time:                                 >=0 | *1900   // How long we should keep an IP in blocked state. Zero value is prohibited here.
	unban_only_if_attack_finished:            bool | *true  // Check if the attack is still active, before triggering an unblock callback with this option. If the attack is still active, check each run of the unblock watchdog
	gobgp_flow_spec_announces:                bool | *false // Announce flow spec rules to block only malicious traffic. Use only if you have BGP Flowspec capable routers
	gobgp_flow_spec_v6_announces:             bool | *false // Announce flow spec IPv6 rules to block only malicious traffic. Use only if you have BGP Flowspec capable routers
	flow_spec_unban_enabled:                  bool | *true  // We will try to withdraw flow spec rule when blocking time expires
	flow_spec_ban_time:                       >=0 | *1900   // How long we should flow spec keep rule in announces. Zero value is prohibited here.
	collect_attack_pcap_dumps:                bool | *false // This option enables pcap collection for attack’s traffic dump. Works only for mirror and sFlow modes
	collect_simple_attack_dumps:              bool | *true  // Collect simple attack dumps which include information from attack’s sample. Works for all capture engines
	ban_details_records_count:                >=0 | *25     // How many packets will be collected from attack’s traffic. Please decrease this value if you are using sampled capture protocols
	threshold_specific_ban_details:           bool | *false // In this mode FastNetMon will collect only traffic relevant to direction and type of threshold. It works only with traffic_buffer
	do_not_cap_ban_details_records_count:     bool | *false // Disables logic which automatically reduces ban_details_records_count when it exceeds 100 for sFlow and Netflow
	unban_total_hostgroup_enabled:            bool | *true  // We will try to unban blocked hostgroup after specified amount of time
	ban_time_total_hostgroup:                 >=0 | *1900   // How long we should keep hostgroup in blocked state. Zero value is prohibited here.

	// bgp
	gobgp:                                                       bool | *false         // Enable BGP daemon integration
	gobgp_api_host:                                              string | *"localhost" // IP address or host to connect to GoBGP
	gobgp_api_port:                                              >0 & <=65535 | *50051 // Port to connect to GoBGP
	gobgp_bgp_listen_port:                                       >0 & <=65535 | *179   // BGP listen port
	gobgp_router_id:                                             string | *""          // Router ID to override default configuration
	gobgp_next_hop:                                              net.IP | *"0.0.0.0"   // Next hop value for BGP unicast IPv4 announces
	gobgp_next_hop_remote_host:                                  net.IP | *"0.0.0.0"   // Next hop value for BGP unicast remote host IPv4 announces
	gobgp_do_not_manage_daemon:                                  bool | *false         // Disables automatic start / restart operations for BGP daemon
	gobgp_announce_host:                                         bool | *true          // Announce /32 host itself with BGP
	gobgp_announce_whole_subnet:                                 bool | *false         // Announce origin subnet of IP address
	gobgp_announce_whole_subnet_force_custom_prefix_length:      bool | *false         // Enables override for subnet announce
	gobgp_announce_whole_subnet_custom_prefix_length:            >=0 | *24             // Prefix length to override default one
	gobgp_announce_whole_subnet_force_custom_ipv6_prefix_length: bool | *false         // Enables override for IPv6 subnet announce
	gobgp_announce_whole_subnet_custom_ipv6_prefix_length:       >=0 | *24             // IPv6 prefix length to override default one
	gobgp_announce_remote_host:                                  bool | *false         // Announce remote /32 host itself with BGP
	gobgp_community_host:                                        string | *"65001:668" // BGP community for outgoing host announces. Here you can add community string for the host announce. Usage ASN:Community. ASN and community should be from 1 to 65535).
	gobgp_communities_host_ipv4:                                 [...string] | *[]     // BGP communities for outgoing host announces. Here you can add communities strings for the host announces. Usage ASN:Community. ASN and community should be from 1 to 65535).
	gobgp_community_subnet:                                      string | *"65001:667" // BGP community for outgoing subnet announces. Here you can add community string for the prefix subnet announce. Usage ASN:Community. ASN and community should be from 1 to 65535).
	gobgp_communities_subnet_ipv4:                               [...string] | *[]     // BGP communities for outgoing subnet announces. Here you can add communities strings for the prefix subnet announce. Usage ASN:Community. ASN and community should be from 1 to 65535).
	gobgp_community_remote_host:                                 string | *"65001:669" // BGP community for outgoing remote host announces. Here you can add community string for the host announce. Usage ASN:Community. ASN and community should be from 1 to 65535).
	gobgp_ipv6:                                                  bool | *false         // Enable BGP actions for IPv6 traffic
	gobgp_next_hop_ipv6:                                         string | *"100::1"    // Next hop value for BGP unicast IPv6 announces
	gobgp_announce_host_ipv6:                                    bool | *true          // Announce /128 host itself with BGP
	gobgp_announce_whole_subnet_ipv6:                            bool | *false         // IPv6 prefix subnet, that will be announced
	gobgp_community_host_ipv6:                                   string | *"65001:668" // BGP community for outgoing host announces for IPv6 protocol. Here you can add community string for the host announce. Usage ASN:Community. ASN and community should be from 1 to 65535).
	gobgp_community_subnet_ipv6:                                 string | *"65001:667" // BGP community for outgoing subnet announces for IPv6 protocol. Here you can add community string for the prefix subnet announce. Usage ASN:Community. ASN and community should be from 1 to 65535).
	gobgp_flow_spec_default_action:                              string | *"discard"   // Default action for flow spec rules. You could specify discard or rate-limit here
	gobgp_flow_spec_next_hop_ipv4:                               [...string] | *[]     // List of IPv4 next hops
	gobgp_flow_spec_next_hop_ipv6:                               [...string] | *[]     // List of IPv6 next hops
	gobgp_flow_spec_v6_default_action:                           string | *"discard"   // Default action for flow spec rules. You could specify discard or rate-limit here
	gobgp_flow_spec_v6_rate_limit_value:                         >=0 | *1024           // For rate-limit action you could specify rate
	gobgp_flow_spec_rate_limit_value:                            >=0 | *1024           // For rate-limit action you could specify rate
	flow_spec_detection_prefer_simple_packets:                   bool | *false         // Enables logic which prefers simple packets over raw packets in bucket for Flow Spec analyzer
	flow_spec_tcp_options_use_match_bit:                         bool | *false         // Enables force match bit in outgoing BGP Flow Spec announces about TCP flags
	flow_spec_fragmentation_options_use_match_bit:               bool | *false         // Enables force match bit in outgoing BGP Flow Spec announces about fragmentation
	flow_spec_do_not_process_length_field:                       bool | *false         // Disables processing for length field completely. Use it if your device produces incorrect information about packet’s length
	flow_spec_do_not_process_tcp_flags_field:                    bool | *false         // Disables processing for TCP flags field completely. You may need it if your router does not support all TCP flags in flow spec rules
	flow_spec_do_not_process_ip_fragmentation_flags_field:       bool | *false         // Disables processing for IP fragmentation field completely. You may need it if your router does not support all IP fragmentations flags in flow spec rules
	flow_spec_ignore_do_not_fragment_flag:                       bool | *false         // Disables processing for do not fragment field completely. It’s useful on Arista and Extreme
	flow_spec_do_not_process_source_address_field:               bool | *false         // Disables processing for source address field completely. Use it if you experience attacks from big number of IP addresses
	flow_spec_execute_validation:                                bool | *true          // With this option we check that source and destination addresses in flow spec rule specified from fcli or web API belongs to our ranges
	do_not_withdraw_unicast_announces_on_restart:                bool | *false         // Disables automatic withdrawal of BGP Unicast announces
	do_not_withdraw_flow_spec_announces_on_restart:              bool | *false         // Disables automatic withdrawal of BGP Flow Spec announces
	gobgp_announce_hostgroup_networks:                           bool | *false         // Enable BGP announces for any network from specific hostgroup when per hostgroup aka total thresholds in use
	gobgp_announce_hostgroup_networks_ipv4:                      bool | *false         // Enable BGP announces for all IPv4 networks from specific hostgroup when per hostgroup aka total thresholds in use
	gobgp_announce_hostgroup_networks_ipv6:                      bool | *false         // Enable BGP announces for all IPv6 networks from specific hostgroup when per hostgroup aka total thresholds in use
	gobgp_next_hop_hostgroup_networks_ipv4:                      string | *"0.0.0.0"   // Next hop for IPv4 per hostgroup network announces
	gobgp_next_hop_hostgroup_networks_ipv6:                      string | *"100::1"    // Next hop for IPv6 per hostgroup network announces
	gobgp_communities_hostgroup_networks_ipv4:                   [...string] | *[]     // BGP communities for IPv4 hostgroup network announces. Here you can add communities strings for the host announces. Usage ASN:Community. ASN and community should be from 1 to 65535).
	gobgp_communities_hostgroup_networks_ipv6:                   [...string] | *[]     // BGP communities for IPv6 hostgroup network announces. Here you can add communities strings for the host announces. Usage ASN:Community. ASN and community should be from 1 to 65535).

	// clickhouse_metrics
	clickhouse_metrics:                       bool | *false          // Export traffic speed metrics to ClickHouse
	clickhouse_metrics_database:              string | *"fastnetmon" // Database for ClickHouse traffic metrics
	clickhouse_metrics_username:              string | *"default"    // Username for ClickHouse metrics
	clickhouse_metrics_password:              string | *""           // Password for ClickHouse metrics
	clickhouse_metrics_host:                  net.IP | *"127.0.0.1"  // Server address for ClickHouse metric
	clickhouse_metrics_port:                  >0 & <=65535 | *9000   // ClickHouse server port
	clickhouse_metrics_push_period:           >=0 | *1               // Delay for run ClickHouse push thread
	clickhouse_metrics_per_protocol_counters: bool | *true           // Enables export for per protocol counters to Clickhouse

	// email_notification
	email_notifications_enabled:                    bool | *false                                                      // Enable email notifications
	email_notifications_disable_certificate_checks: bool | *false                                                      // Disables TLS certificate validation completely
	email_notifications_host:                       string | *"mail.example.com"                                       // Hostname of SMTP server
	email_notifications_port:                       >0 & <=65535 | *587                                                // Port of SMTP server used for email notifications
	email_notifications_tls:                        bool | *true                                                       // Enable TLS for your SMTP server
	email_notifications_auth:                       bool | *true                                                       // Enable auth for your SMTP server
	email_notifications_auth_method:                string | *""                                                       // Auth method for SMTP authorization. Used only when auth enabled
	email_notifications_username:                   string | *"fastnetmon@yourdomain.com"                              // Username for SMTP authorization
	email_notifications_password:                   string | *"super-secret-password"                                  // Password for SMTP authorization
	email_notifications_from:                       string | *"fastnetmon@yourdomain.com"                              // Email address for FROM field
	email_notifications_recipients:                 [...string] | *[]                                                  // Email notification recipients
	email_notifications_hide_flow_spec_rules:       bool | *false                                                      // Hide flow spec rules from email
	email_notifications_add_simple_packet_dump:     bool | *true                                                       // Add simple packet dump to email
	email_subject_blackhole_block:                  string | *"FastNetMon blocked host {{ ip }}"                       // Subject template for email notification about blocked host
	email_subject_blackhole_unblock:                string | *"FastNetMon unblocked host {{ ip }}"                     // Subject template for email notification about unblocked host
	email_subject_partial_block:                    string | *"FastNetMon partially blocked traffic for host {{ ip }}" // Subject template for email notification about partially blocked host

	// graphite
	graphite:             bool | *false          // Enabled metrics export to Graphite
	graphite_host:        net.IP | *"127.0.0.1"  // Graphite server address
	graphite_port:        >0 & <=65535 | *2003   // Graphite server port
	graphite_prefix:      string | *"fastnetmon" // Default prefix for Graphite metrics
	graphite_push_period: >=0 | *1               // Delay for run Graphite push thread

	// influxdb
	influxdb_kafka:                            bool | *false          // Enables traffic metrics export to Influxdb over Kafka
	influxdb_kafka_brokers:                    [...string] | *[]      // Kafka brokers for InfluxDB export
	influxdb_kafka_topic:                      string | *"fastnetmon" // Topic name for Kafka InfluxDB instance
	influxdb_kafka_partitioner:                string | *"consistent" // Partitioner between available partitions
	influxdb:                                  bool | *false          // Enabled traffic metrics export to Influxdb
	influxdb_database:                         string | *"fastnetmon" // Database for InfluxDB data
	influxdb_host:                             string | *"127.0.0.1"  // InfluxDB server address (IP or domain name)
	influxdb_port:                             >0 & <=65535 | *8086   // InfluxDB server port
	influxdb_custom_tags:                      bool | *false          // Adds custom tag to InfluxDB export data
	influxdb_tag_name:                         string | *"node"       // Custom tag name
	influxdb_tag_value:                        string | *"master"     // Custom tag value
	influxdb_tags_table:                       [string] | *[]         //  Custom tags in key=value format
	influxdb_skip_host_counters:               bool | *false          // Skip export for host counters to reduce load on InfluxDB server
	influxdb_push_host_ipv6_counters:          bool | *true           // Enable pushing per host IPv6 counters to InfluxDB
	influxdb_push_host_ipv4_flexible_counters: bool | *true           // Enables export of flexible per host IPv4 counters to InfluxDB
	influxdb_push_host_ipv6_flexible_counters: bool | *true           // Enables export of flexible per host IPv6 counters to InfluxDB
	influxdb_user:                             string | *"fastnetmon" // Username for InfluxDB
	influxdb_password:                         string | *"fastnetmon" // Password for InfluxDB
	influxdb_auth:                             bool | *false          // Enable authorization for InfluxDB
	influxdb_per_protocol_counters:            bool | *true           // Enables export for per protocol counters to InfluxDB
	influxdb_attack_notification:              bool | *false          // Enables attack notifications in Grafana
	influxdb_push_period:                      >=0 | *1               // Delay for run InfluxDB push thread

	// logging
	logging_level:                 string | *"info"        // Configures logging level
	logging_local_syslog_logging:  bool | *false           // Enable this option if you want to send logs to local syslog facility
	logging_remote_syslog_logging: bool | *false           // Enable this option if you want to send logs to a remote syslog server using UDP protocol
	logging_remote_syslog_server:  net.IP | *"10.10.10.10" // This is the IPv4 address of your syslog server. You can specify the address you need
	logging_remote_syslog_port:    >0 & <=65535 | *514     // Remote syslog server port

	// mongo
	mongo_store_attack_information: bool | *false // Enables attacks export to MongoDB

	// netflow
	netflow:                                  bool | *false           // Enable Netflow capture. We support Netflow v5, v9 and IPFIX (10)
	netflow_count_packets_per_device:         bool | *false           // Enable logic to count number of packets from each router
	netflow_multi_thread_processing:          bool | *false           // Enables multi thread processing for each Netflow port
	netflow_threads_per_port:                 >=0 | *1                // Number of threads per Netflow port
	netflow_ports:                            [...>0 & <=65535] | *[] // Netflow collector port. It’s possible to specify multiple ports here
	netflow_host:                             string | *"0.0.0.0"     // Netflow collector host. To bind to all interfaces for all protocols: not possible yet. To bind to all interfaces for a specific protocol: :: or 0.0.0.0. To bind to localhost for a specific protocol: ::1 or 127.0.0.1.
	netflow_socket_read_mode:                 string | *"recvfrom"    // Switches logic used to read data from socket: recvfrom or recvmsg
	netflow_rx_queue_overflow_monitoring:     bool | *false           // Switches on logic to monitor drops on socket
	netflow_custom_sampling_ratio_enable:     bool | *false           // Netflow v9 and IPFIX agents use different and very complex approaches for notifying about sample ratio. Here you could specify a sampling ratio for all this agents. For Netflow v5 we extract sampling ratio from packets directly and this option not used.
	netflow_ignore_sampling_rate_from_device: bool | *false           // Ignores sampling rate announces from device. For Netflow v9 and IPFIX only
	netflow_ignore_long_duration_flow_enable: bool | *false           // FastNetMon will ignore flows which exceed duration specified in configuration
	netflow_long_duration_flow_limit:         >=0 | *1                // FastNetMon will ignore flows which exceed duration specified in this option
	// netflow_v5_per_router_sampling_rate                 string_positive_integer_with_zero_map //    Custom Netflow v5 sampling rate on router basis
	// netflow_v9_per_router_sampling_rate                 string_positive_integer_with_zero_map //    Custom Netflow v9 sampling rate on router basis
	netflow_v9_lite:                    bool | *false // Enable Netflow Lite parser
	netflow_ipfix_inline:               bool | *false // Enables IPFIX inline parser
	ipfix_parse_datalink_frame_section: bool | *false // Enable logic to parse datalink frame section
	// ipfix_per_router_sampling_rate                      string_positive_integer_with_zero_map //    Custom IPFIX sampling rate on router basis
	netflow_sampling_ratio:                                >=0 | *1      // Netflow 9 or IPFIX sampling rate used at agent side. Netflow v9 and IPFIX agents use different and very complex approaches for notifying about sample ratio. Here you could specify a sampling ratio for all this agents. For Netflow v5 we extract sampling ratio from packets directly and this option not used.
	netflow_v5_custom_sampling_ratio_enable:               bool | *false // This option will override netflow v5 sampling rate from packets by specified value
	netflow_v5_sampling_ratio:                             >=0 | *1      // It will be used when netflow_v5_custom_sampling_ratio_enable set to enable
	netflow_templates_cache:                               bool | *true  // Cache Netflow v9 or IPFIX data templates on disk
	netflow_sampling_cache:                                bool | *false // Cache Netflow v9 or IPFIX sampling rates on disk
	netflow_process_only_flows_with_dropped_packets:       bool | *false // We will process only Netflow v9 or IPFIX with forwarding status set to dropped
	netflow_mark_zero_next_hop_and_zero_output_as_dropped: bool | *false // With this option all traffic with zero IPv4 and IPv6 addresses in next hop and zero output interface will be marked as dropped

	// network_management
	networks_list:              [...net.IPCIDR] | *[] // Please specify all IPv4 and IPv6 networks which belong to you
	networks_whitelist:         [...net.IPCIDR] | *[] // All ban actions will be disabled for your hosts in these networks. Use with attention!
	networks_whitelist_remote:  [...net.IPCIDR] | *[] // We will skip traffic to/from these remote networks completely from processing
	monitor_local_ip_addresses: bool | *false         // Add local IP addresses and aliases to networks_list

	// notify_script
	notify_script_hostgroup_enabled: bool | *false                                              // Enable script call in case of blocking for hostgroup total thresholds
	notify_script_hostgroup_path:    string | *"/etc/fastnetmon/scripts/notify_about_attack.sh" // Path to notify script for hostgroup level blocks
	notify_script_enabled:           bool | *false                                              // Enable script call in case of blocking, unban and attack_details actions
	notify_script_path:              string | *"/etc/fastnetmon/scripts/notify_about_attack.sh" // Path to notify script. This script executed for ban, unban and attack detail collection
	notify_script_format:            string | *"text"                                           // Specifies format used for notify script: text or JSON

	// prometheus
	prometheus:      bool | *false         // Enable Prometheus metrics endpoint
	prometheus_host: net.IP | *"127.0.0.1" // Prometheus metrics address
	prometheus_port: >0 & <=65535 | *9209  // Prometheus metrics port

	// redis
	redis_enabled: bool | *false          // Enables attack’s export to Redis
	redis_host:    net.IP | *"127.0.0.1"  // Redis server host
	redis_port:    >0 & <=65535 | *6379   // Redis server port
	redis_prefix:  string | *"fastnetmon" // Prefix for all Redis keys

	// sflow
	sflow:                                   bool | *false           // Enables sFlow capture engine. We support only sFlow v5
	sflow_extract_tunnel_traffic:            bool | *false           // Enables for sFlow code which strips external level for GRE tunnels
	sflow_count_packets_per_device:          bool | *false           // Enable logic to count number of sFlow packets from each device
	sflow_ports:                             [...>0 & <=65535] | *[] // Ports list for sFlow collector. It’s possible to specify multiple ports here
	sflow_host:                              net.IP | *"0.0.0.0"     // sFlow collector default host. Here you can specify the IP address of the listen interface. If default is used, all interfaces will be listen.
	sflow_read_packet_length_from_ip_header: bool | *false           // Some vendors may lie about full packet length in sFlow packet. To avoid this issue we can switch to using IP packet length from parsed header
	sflow_track_sampling_rate:               bool | *false           // Enables tracking for sFlow sampling rate for all exporting entities (devices, line cards)
	sflow_use_new_generation_parser:         bool | *false           // Enable new improved packet parser (experimental)

	// system
	cache_path:                              string | *"/var/cache/fastnetmon"   // Path to folder used for cache
	asn_lookup:                              bool | *true                        // Enable ASN mapping database to execute ASN lookup for IP. You could use it to lookup ASN for particular IP
	country_lookup:                          bool | *false                       // Enable country lookup logic
	force_asn_lookup:                        bool | *false                       // Overwrite ASN received from device by result of lookup by our ASN database
	pid_path:                                string | *"/var/run/fastnetmon.pid" // Path to pid file for checking case if another copy of tool is running, it’s useful when you run multiple instances of tool
	api_host_counters_max_hosts_in_response: >=0 | *100                          // Max number of hosts in show host_counters output
	system_user:                             string | *"fastnetmon"              // Run FastNetMon daemon from particular system user
	system_group:                            string | *"fastnetmon"              // Run FastNetMon daemon from particular system group
	drop_root_permissions:                   bool | *false                       // Try to run from non-root user. Not supported for mirror capture
	license_use_port_443:                    bool | *true                        // Use port 443 instead for license server connections

	// tera_flow
	tera_flow:       bool | *false           // Receive information in Tera Flow format from the network
	tera_flow_ports: [...>0 & <=65535] | *[] // Tera Flow collector port. It’s possible to specify multiple ports here
	tera_flow_host:  string | *"0.0.0.0"     // Tera Flow collector host. To bind to all interfaces for all protocols: not possible yet. To bind to all interfaces for a specific protocol: :: or 0.0.0.0. To bind to localhost for a specific protocol: ::1 or 127.0.0.1.

	// traffic_calculation_management
	keep_traffic_counters_during_restart:            bool | *false // Keep all speed counters during restarts
	process_incoming_traffic:                        bool | *true  // Enables or disables processing for incoming traffic
	process_outgoing_traffic:                        bool | *true  // Enables or disables processing for outgoing traffic
	override_internal_traffic_as_incoming:           bool | *false // Enables logic to process internal traffic as incoming
	override_internal_traffic_as_outgoing:           bool | *false // Enables logic to process internal traffic as outgoing
	process_ipv6_traffic:                            bool | *true  // Enables processing for IPv6 traffic
	enable_connection_tracking:                      bool | *true  // Enable traffic state tracking. If you interested in flow per second rates, please enable it. Be careful, it may increase CPU usage significantly
	remote_host_tracking:                            bool | *false // Completely enable or disable bandwidth calculation for remote hosts
	connection_tracking_skip_ports:                  bool | *false // Disables port processing for connection tracking
	enable_total_hostgroup_counters:                 bool | *false // Enable traffic counters for total per hostgroups traffic
	enable_asn_counters:                             bool | *true  // Enable ASN counters for per ASN traffic
	build_total_hostgroups_from_per_host_hostgroups: bool | *false // Allows using per-host hostgroups for building total hostgroups
	dump_other_traffic:                              bool | *false // Dump all traffic which belongs to other class to log. Only for debugging reasons. It significantly degrades performance
	dump_all_traffic:                                bool | *false // Dump all traffic to log. Only for debugging reasons. It significantly degrades performance
	dump_all_traffic_json:                           bool | *false // Dump all traffic to log in JSON format. Only for debugging reasons. It significantly degrades performance
	speed_calculation_delay:                         >=0 | *1      // This value control how often we run speed recalculation function. Please do not use this unless support suggested this to you
	average_calculation_time:                        >=0 | *5      // We use average values for traffic speed to certain IP and calculates average over this time slice
	ipv6_automatic_data_cleanup:                     bool | *true  // Enables logic which removes old entries from IPv6 data counters
	ipv6_automatic_data_cleanup_threshold:           >=0 | *300    // We will remove all entries which exceed this age in seconds
	ipv6_automatic_data_cleanup_delay:               >=0 | *300    // How often we will run cleanup logic
	ipv4_automatic_data_cleanup:                     bool | *true  // Enables logic which removes old entries from IPv4 data counters
	ipv4_automatic_data_cleanup_threshold:           >=0 | *300    // We will remove all entries which exceed this age in seconds
	ipv4_automatic_data_cleanup_delay:               >=0 | *300    // How often we will run cleanup logic
	ipv4_remote_automatic_data_cleanup:              bool | *true  // Enables logic which removes old entries from IPv4 remote data counters
	ipv4_remote_automatic_data_cleanup_threshold:    >=0 | *300    // We will remove all remove IPv4 entries which exceed this age in seconds
	ipv4_remote_automatic_data_cleanup_delay:        >=0 | *300    // How often we will run cleanup logic for remote IPv4 records
	traffic_buffer:                                  bool | *false // Enables or disables traffic buffer which keeps some amount of previously processed packets
	traffic_buffer_size:                             >=0 | *100000 // Specifies number of elements in traffic_buffer for 1 second of average calculation time
	traffic_buffer_port_mirror:                      bool | *false // Enables or disables traffic buffer for port mirror modes. Do not enable unless sampling is enabled
	generate_attack_traffic_samples:                 bool | *false // Enables logic to populate statistical reports about attacks traffic. Only for vendor integrations
	generate_attack_traffic_samples_delay:           >=0 | *60     // How often we’re going to produce traffic reports about active attacks
	generate_max_talkers_report:                     bool | *false // Enables logic to track max talkers and store them into MongoDB Only for vendor integrations
	generate_max_talkers_report_delay:               >=0 | *300    // How often we’re going to produce reports about max talkers
	generate_hostgroup_traffic_samples:              bool | *false // Enables logic to populate statistical reports about hostgroup traffic. Only for vendor integrations
	generate_hostgroup_traffic_samples_delay:        >=0 | *60     // How often we’re going to produce traffic reports for hostgroup traffic
	generate_hostgroup_traffic_baselines:            bool | *false // Enables logic to populate statistical reports about hostgroup average traffic metrics. Only for vendor integrations
	generate_hostgroup_traffic_baselines_delay:      >=0 | *60     // How often we’re going to produce traffic reports for hostgroup traffic metrics

	// traffic_db
	traffic_db:               bool | *false         // Enable traffic export to persistent traffic database
	traffic_db_host:          net.IP | *"127.0.0.1" // Traffic DB server address
	traffic_db_port:          >0 & <=65535 | *8100  // Traffic DB server port
	traffic_db_sampling_rate: >=0 | *512            // Sampling rate for mirrored traffic for traffic_db export

	// web_api
	web_api_host:                 net.IP | *"127.0.0.1" // Web API host for listening
	web_api_port:                 >0 & <=65535 | *10007 // Web API port for listening
	web_api_login:                string | *"admin"     // Login for web API
	web_api_password:             string | *""          // Password for web API
	web_api_ssl:                  bool | *false         // Web API host for listening for ssl API
	web_api_trace_queries:        bool | *false         // Trace all queries
	web_api_ssl_port:             >0 & <=65535 | *10443 // Web API port for listening
	web_api_ssl_host:             net.IP | *"127.0.0.1" // Web API host for listening
	web_api_ssl_certificate_path: string | *""          // Certificate for SSL API
	web_api_ssl_private_key_path: string | *""          // Private key for SSL API

	// web_callback
	web_callback_enabled: bool | *false                                   // FastNetMon could call external script with http or https protocol and pass attack’s details in JSON format
	web_callback_url:     string | *"http://127.0.0.1:8080/attack/notify" // We could call this script in case of blackhole ban and unban and for partial (flow spec) block action and pass details with JSON inside POST query

	// xdp
	mirror_xdp:                            bool | *false                            // Enable capture from mirror port using AF_XDP capture engine
	xdp_read_packet_length_from_ip_header: bool | *false                            // By default, FastNetMon reads packet length from the wire. But it can use information from IP header when you enable this option
	force_native_mode_xdp:                 bool | *false                            // Requires native XDP support from driver
	zero_copy_xdp:                         bool | *false                            // Enable zero copy mode for XDP. Requires native support from driver (force_native_mode_xdp)
	poll_mode_xdp:                         bool | *false                            // Use poll system call to process incoming packets
	xdp_use_new_generation_parser:         bool | *false                            // Enable new improved packet parser (experimental)
	xdp_set_promisc:                       bool | *false                            // Set promisc flag on interface automatically
	xdp_extract_tunnel_traffic:            bool | *false                            // Enables code which strips external level for GRE tunnels
	interfaces_xdp:                        [...string] | *[]                        // Interfaces list for traffic capture using XDP
	microcode_xdp_path:                    string | *"/etc/fastnetmon/xdp_kernel.o" // You can specify custom path to microcode
}

// Hostgroups configuration
#FastNetMon_Hostgroup_Default: {
	name:                                    string | *"global"                              // Name of host group
	parent_name:                             string | *""                                    // Parent host group name
	description:                             string | *"This is default group for all hosts" // Human-friendly name for this group
	calculation_method:                      string | *"per_host"                            // Traffic calculation method for host group: total or per_host (or empty value)
	networks:                                [...net.IPCIDR] | *[]                           // List of networks which belong to this group
	enable_ban:                              bool | *false                                   // Enable ban actions for hosts in this group
	ban_for_pps:                             bool | *false                                   // Should we block host in this group if it exceeds packet per second threshold?
	ban_for_bandwidth:                       bool | *false                                   // Should we block host in this group if it exceeds bandwidth threshold?
	ban_for_flows:                           bool | *false                                   // Should we block host in this group if it exceeds flows threshold?
	threshold_pps:                           >=0 | *20000                                    // Packet per second traffic to/from this host should exceed this value
	threshold_mbps:                          >=0 | *1000                                     // Bandwidth to/from this host should exceed this value
	threshold_flows:                         >=0 | *3500                                     // Flow per second speed to/from this host should exceed this value
	ban_for_tcp_bandwidth:                   bool | *false                                   // Block hosts in group for TCP bandwidth threshold?
	ban_for_udp_bandwidth:                   bool | *false                                   // Block hosts in group for UDP bandwidth threshold?
	ban_for_icmp_bandwidth:                  bool | *false                                   // Block hosts in group for ICMP bandwidth threshold?
	ban_for_tcp_pps:                         bool | *false                                   // Should we block host in this group if it exceeds packet per second threshold for TCP?
	ban_for_udp_pps:                         bool | *false                                   // Should we block host in this group if it exceeds packet per second threshold for UDP?
	ban_for_icmp_pps:                        bool | *false                                   // Should we block host in this group if it exceeds packet per second threshold for ICMP?
	threshold_tcp_mbps:                      >=0 | *1000                                     // TCP bandwidth to/from this host should exceed this value
	threshold_udp_mbps:                      >=0 | *1000                                     // UDP bandwidth to/from this host should exceed this value
	threshold_icmp_mbps:                     >=0 | *1000                                     // ICMP bandwidth to/from this host should exceed this value
	threshold_tcp_pps:                       >=0 | *100000                                   // TCP packet per second traffic to/from this host should exceed this value
	threshold_udp_pps:                       >=0 | *100000                                   // UDP packet per second traffic to/from this host should exceed this value
	threshold_icmp_pps:                      >=0 | *100000                                   // ICMP packet per second traffic to/from this host should exceed this value
	ban_for_tcp_syn_pps:                     bool | *false                                   // Block hosts in group for TCP SYN packets per second threshold
	threshold_tcp_syn_pps:                   >=0 | *1000                                     // TCP SYN pps to/from this host should exceed this value
	ban_for_tcp_syn_bandwidth:               bool | *false                                   // Block hosts in group for TCP SYN packets per second threshold
	threshold_tcp_syn_mbps:                  >=0 | *1000                                     // TCP SYN bandwidth to/from this host should exceed this value
	ban_for_ip_fragments_pps:                bool | *false                                   // Block hosts in group for fragmented IP packets per second threshold
	threshold_ip_fragments_pps:              >=0 | *1000                                     // Fragmented IP pps to/from this host should exceed this value
	ban_for_ip_fragments_bandwidth:          bool | *false                                   // Block hosts in group for fragmented IP packets per second threshold
	threshold_ip_fragments_mbps:             >=0 | *1000                                     // fragmented IP bandwidth to/from this host should exceed this value
	enable_ban_incoming:                     bool | *false                                   // Enable ban actions for this group for incoming traffic
	enable_ban_outgoing:                     bool | *false                                   // Enable ban actions for this group for incooutgoingming traffic
	ban_for_pps_outgoing:                    bool | *false                                   // Should we block host in this group if it exceeds packet per second threshold?
	ban_for_bandwidth_outgoing:              bool | *false                                   // Should we block host in this group if it exceeds bandwidth threshold?
	ban_for_flows_outgoing:                  bool | *false                                   // Should we block host in this group if it exceeds flows threshold?
	threshold_pps_outgoing:                  >=0 | *20000                                    // Packet per second traffic to/from this host should exceed this value
	threshold_mbps_outgoing:                 >=0 | *1000                                     // Bandwidth to/from this host should exceed this value
	threshold_flows_outgoing:                >=0 | *3500                                     // Flow per second speed to/from this host should exceed this value
	ban_for_tcp_bandwidth_outgoing:          bool | *false                                   // Block hosts in group for TCP bandwidth threshold?
	ban_for_udp_bandwidth_outgoing:          bool | *false                                   // Block hosts in group for UDP bandwidth threshold?
	ban_for_icmp_bandwidth_outgoing:         bool | *false                                   // Block hosts in group for ICMP bandwidth threshold?
	ban_for_tcp_pps_outgoing:                bool | *false                                   // Should we block host in this group if it exceeds packet per second threshold for TCP?
	ban_for_udp_pps_outgoing:                bool | *false                                   // Should we block host in this group if it exceeds packet per second threshold for UDP?
	ban_for_icmp_pps_outgoing:               bool | *false                                   // Should we block host in this group if it exceeds packet per second threshold for ICMP?
	threshold_tcp_mbps_outgoing:             >=0 | *1000                                     // TCP bandwidth to/from this host should exceed this value
	threshold_udp_mbps_outgoing:             >=0 | *1000                                     // UDP bandwidth to/from this host should exceed this value
	threshold_icmp_mbps_outgoing:            >=0 | *1000                                     // ICMP bandwidth to/from this host should exceed this value
	threshold_tcp_pps_outgoing:              >=0 | *100000                                   // TCP packet per second traffic to/from this host should exceed this value
	threshold_udp_pps_outgoing:              >=0 | *100000                                   // UDP packet per second traffic to/from this host should exceed this value
	threshold_icmp_pps_outgoing:             >=0 | *100000                                   // ICMP packet per second traffic to/from this host should exceed this value
	ban_for_tcp_syn_pps_outgoing:            bool | *false                                   // Block hosts in group for TCP SYN packets per second threshold
	threshold_tcp_syn_pps_outgoing:          >=0 | *1000                                     // TCP SYN pps to/from this host should exceed this value
	ban_for_tcp_syn_bandwidth_outgoing:      bool | *false                                   // Block hosts in group for TCP SYN packets per second threshold
	threshold_tcp_syn_mbps_outgoing:         >=0 | *1000                                     // TCP SYN bandwidth to/from this host should exceed this value
	ban_for_ip_fragments_pps_outgoing:       bool | *false                                   // Block hosts in group for fragmented IP packets per second threshold
	threshold_ip_fragments_pps_outgoing:     >=0 | *1000                                     // Fragmented IP pps to/from this host should exceed this value
	ban_for_ip_fragments_bandwidth_outgoing: bool | *false                                   // Block hosts in group for fragmented IP packets per second threshold
	threshold_ip_fragments_mbps_outgoing:    >=0 | *1000                                     // fragmented IP bandwidth to/from this host should exceed this value

	// flexible_thresholds flexible_thresholds "{}" // Flexible thresholds
}

// BGP configuration
#FastNetMon_BGP: {
	name:              string | *"connection_main_router"           // System name for this connection
	description:       string | *"Connection to main Router at NOC" // Human-friendly name for this connection
	local_asn:         >=0                                          // Local ASN number
	local_address:     net.IP                                       // Local address for BGP connection
	remote_asn:        >=0                                          // Remote autonomous system number
	remote_address:    net.IP                                       // Remote IP address of BGP peer
	multihop:          bool | *true                                 // Enable BGP multihop option
	md5_auth:          bool | *false                                // Enable md5 auth for BGP session
	md5_auth_password: string | *""                                 // md5 password for BGP session
	ipv4_unicast:      bool | *true                                 // Enable IPv4 unicast for this peering connection
	ipv6_unicast:      bool | *false                                // Enable IPv6 unicast for this peering connection
	ipv4_flowspec:     bool | *false                                // Enable IPv4 Flow Spec / RFC 5575 for this peering connection
	ipv6_flowspec:     bool | *false                                // Enable IPv6 Flow Spec / RFC 5575 for this peering connection
	active:            bool | *false                                // You could enable or disable this peer with this option
}

// Traffic rules configuration
#FastNetMon_TrafficRule: {
	name:                string | *""      // Name for this rule
	active:              bool | *false     // You could enable or disable rule using this flag
	description:         string | *""      // Human-friendly name for this rule
	source_ports:        [...string] | *[] // Source ports
	destination_ports:   [...string] | *[] // Destination ports
	packet_lengths:      [...string] | *[] // Packet lengths
	protocols:           [...string] | *[] // Protocols list
	fragmentation_flags: [...string] | *[] // Fragmentation flags list
	tcp_flags:           [...string] | *[] // TCP flags list
}
