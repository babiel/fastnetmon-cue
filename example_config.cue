package fastnetmon

config: [string]: main: {
	enable_ban:           true
	enable_ban_hostgroup: true
}

config: [string]: hostgroups: [{
	name:                "global"
	description:         "This is default group for all hosts"
	enable_ban:          true
	enable_ban_incoming: true

	ban_for_bandwidth: true
	threshold_mbps:    337
}]

config: [string]: bgpSessions: [{
	name:              "example session"
	description:       ""
	local_asn:         1337
	local_address:     "1.2.3.4"
	remote_asn:        1338
	remote_address:    "4.3.2.1"
	multihop:          true
	active:            true
}]

config: {
	host_a: main: interfaces: [
		"enp1s0",
	]

	host_b: main: interfaces: [
		"enp1s0",
	]
}
