package linkos

import (
	_ "embed"
)

//go:embed linkos.ini
var ConfigFileTemplateContent []byte
