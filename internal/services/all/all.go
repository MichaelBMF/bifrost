// Package all registers every service type of this repository. The agent itself
// imports no service; the binary that runs it imports this package.
package all

import (
	_ "github.com/MichaelBMF/bifrost/internal/services/mqtt"
	_ "github.com/MichaelBMF/bifrost/internal/services/tcp"
)
