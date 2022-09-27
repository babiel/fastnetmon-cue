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
				mkdir: file.MkdirAll & {
					path: "out/\(host)/hostgroup"
				}

				"main.json": file.Create & {
					$after:   mkdir
					filename: "out/\(host)/main.json"
					contents: json.Marshal(cfg.main)
				}

				for i, group in cfg.hostgroups {
					"hostgroup/\(i).json": file.Create & {
						$after:   mkdir
						filename: "out/\(host)/hostgroup/\(i).json"
						contents: json.Marshal(group)
					}
				}
			}

			"\(host).tar": exec.Run & {
				$after: build
				dir:    "out/\(host)"
				cmd:    ["tar", "-cf", "../\(host).tar", "main.json"] + [ for i, _ in cfg.hostgroups {"hostgroup/\(i).json"}]
			}
		}
	}
}
