package config

import (
	_ "embed"
)

var (
	//go:embed client.ini
	ClientConfigTemplate []byte
	//go:embed server.ini
	ServerConfigTemplate []byte
)
