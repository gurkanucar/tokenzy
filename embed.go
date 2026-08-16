package main

import "embed"

// Templates and static assets are compiled into the binary, so a deployment is
// a single file with no external requests at runtime.

//go:embed templates
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS
