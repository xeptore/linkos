package lanix

import (
	_ "embed"
)

//go:embed lanix.ini
var ConfigFileTemplateContent []byte
