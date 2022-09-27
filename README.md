# FastNetMon CUE Schema

This repository contains the current config schema for the current (`2.0.321 45ec8ef97de0b696c78eed73e4e6d98ae7b7d211`) FastNetMon config.

## Config Import
You can build a tarball with the `cue build` command. More infos to the restore process can be found here: https://fastnetmon.com/docs-fnm-advanced/fastnetmon-backup-restore/

An example deployment would look like this:
```
local$ cue build
local$ scp out/host_a.tar host_a:
local$ ssh host_a
host_a$ fcli create_configuration
host_a$ fcli delete hostgroup global
host_a$ fcli import_configuration backup.tar
```