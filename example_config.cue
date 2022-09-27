package fastnetmon

config: [string]: main: #FastNetMon_Main
config: [string]: main: {
	enable_ban:           true
	enable_ban_hostgroup: true
}

config: [string]: hostgroups: [...#FastNetMon_Hostgroup_Default]
config: [string]: hostgroups: [{
	name:                "global"
	description:         "This is default group for all hosts"
	enable_ban:          true
	enable_ban_incoming: true

	ban_for_bandwidth: true
	threshold_mbps:    337
}]

config: {
	host_a: main: interfaces: [
		"enp1s0",
	]

	host_b: main: interfaces: [
		"enp1s0",
	]
}
