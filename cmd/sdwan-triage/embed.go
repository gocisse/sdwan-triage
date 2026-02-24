package main

import "embed"

// Embed the React production build from web/frontend/dist.
// The build step (npm run build in web/frontend) must complete before
// compiling this binary so that the dist/ directory exists.
// During development, if dist/ is empty the binary still compiles —
// the web server will log a warning and serve nothing for static routes.

//go:embed all:dist
var frontendFS embed.FS
