//go:build tools

package mobile

// Keeps golang.org/x/mobile in go.mod: gomobile bind needs golang.org/x/mobile/bind
// at build time, but nothing imports it in a normal build.
import _ "golang.org/x/mobile/bind"
