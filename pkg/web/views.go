package web

import (
	"html/template"
	"io"
)

const indexTmplText = `<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Contravider</title>
  </head>
  <body>
    <h1>Contravider v{{ .Version }}</h1>
    <p>
      <h2>Available profiles:</h2>
      <ul>
      {{ range .Profiles }}
      <li><a href="{{ . }}">{{ . }}</a></li>
      {{ end }}
      </ul>
    </p>
  </body>
</html>
`

var indexTmpl = template.Must(template.New("index").Parse(indexTmplText))

// renderProfilesList writes the HTML overview for available profiles.
func renderProfilesList(w io.Writer, version string, profiles []string) error {
	return indexTmpl.Execute(w, struct {
		Version  string
		Profiles []string
	}{
		Version:  version,
		Profiles: profiles,
	})
}
