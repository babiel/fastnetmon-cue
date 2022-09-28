package fastnetmon

import (
	"tool/file"
	"tool/exec"
	"encoding/json"
)

command: build: tasks: {
	for host, cfg in config {
		"\(host)": {
			build: {
				mkdir: {
					hostgroup: file.MkdirAll & {
						path: "out/\(host)/hostgroup"
					}

					traffic_rule: file.MkdirAll & {
						path: "out/\(host)/traffic_rule"
					}

					bgp: file.MkdirAll & {
						path: "out/\(host)/bgp"
					}
				}

				"main.json": file.Create & {
					$after: [ for v in mkdir {v}]
					filename: "out/\(host)/main.json"
					contents: json.Marshal(cfg.main)
				}

				for i, group in cfg.hostgroups {
					"hostgroup/\(i).json": file.Create & {
						$after: mkdir.hostgroup
						filename: "out/\(host)/hostgroup/\(i).json"
						contents: json.Marshal(group)
					}
				}

				for i, rule in cfg.trafficRules {
					"traffic_rule/\(i).json": file.Create & {
						$after: mkdir.traffic_rule
						filename: "out/\(host)/traffic_rule/\(i).json"
						contents: json.Marshal(rule)
					}
				}

				for i, session in cfg.bgpSessions {
					"bgp/\(i).json": file.Create & {
						$after: mkdir.bgp
						filename: "out/\(host)/bgp/\(i).json"
						contents: json.Marshal(session)
					}
				}
			}

			"\(host).tar": exec.Run & {
				$after: build
				dir:    "out/\(host)"
				cmd:    ["tar", "-cf", "../\(host).tar", "main.json"] +
					[ for i, _ in cfg.hostgroups {"hostgroup/\(i).json"}] +
					[ for i, _ in cfg.trafficRules {"traffic_rule/\(i).json"}] +
					[ for i, _ in cfg.bgpSessions {"bgp/\(i).json"}]
			}
		}
	}
}
