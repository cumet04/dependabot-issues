package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

func main() {
	alerts, err := getAlerts("cumet04", "dependabot-issues", 10)
	if err != nil {
		panic(err)
	}

	content := ""
	for _, a := range alerts {
		if len(a.UpdateError) == 0 {
			continue
		}
		s, _ := formatAlert(a)
		content += s + "\n"
	}

	if err := genPreview("preview.html", content); err != nil {
		panic(err)
	}
}

type Alert struct {
	CreatedAt    time.Time
	Number       int
	UpdateError  string
	Title        string
	AdvisoryLink string
	Description  string
	Ecosystem    string // NPM, RUBYGEMS, ... refs https://docs.github.com/en/graphql/reference/enums#securityadvisoryecosystem
}

func getAlerts(owner string, name string, count int) ([]Alert, error) {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	httpClient := oauth2.NewClient(context.Background(), src)

	client := githubv4.NewClient(httpClient)

	var query struct {
		Repository struct {
			VulnerabilityAlerts struct {
				Nodes []struct {
					CreatedAt        time.Time
					Number           int
					DependabotUpdate struct {
						Error struct {
							Body string
						}
					}
					SecurityAdvisory struct {
						Summary     string
						Permalink   string
						Description string
					}
					SecurityVulnerability struct {
						Package struct {
							Ecosystem string
						}
					}
				}
			} `graphql:"vulnerabilityAlerts(first: $count, states: OPEN)"`
		} `graphql:"repository(owner: $owner, name: $name)"`
	}

	err := client.Query(context.Background(), &query, map[string]interface{}{
		"owner": githubv4.String(owner),
		"name":  githubv4.String(name),
		"count": githubv4.Int(count),
	})

	if err != nil {
		return nil, err
	}

	var alerts []Alert
	for _, v := range query.Repository.VulnerabilityAlerts.Nodes {
		alerts = append(alerts, Alert{
			CreatedAt:    v.CreatedAt,
			Number:       v.Number,
			UpdateError:  v.DependabotUpdate.Error.Body,
			Title:        v.SecurityAdvisory.Summary,
			AdvisoryLink: v.SecurityAdvisory.Permalink,
			Description:  v.SecurityAdvisory.Description,
			Ecosystem:    v.SecurityVulnerability.Package.Ecosystem,
		})
	}
	return alerts, nil
}

func formatAlert(a Alert) (string, error) {
	result := fmt.Sprintf("# %d. [%s] %s\n", a.Number, a.Ecosystem, a.Title)
	result += a.Description + "\n"
	result += "\n\n---\n\n"
	result += a.UpdateError

	return result, nil
}

func genPreview(filename string, content string) error {
	// Thanks to https://github.com/markedjs/marked and https://github.com/sindresorhus/github-markdown-css
	tmpl := `
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
	<link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.1.0/github-markdown.min.css">
</head>
<body>
  <div class="markdown-body"></div>
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <script>
    document.getElementsByClassName("markdown-body")[0].innerHTML = marked.parse(` + "`{{.Content}}`" + `)
  </script>
</body>
</html>
	`
	t := template.Must(template.New("preview").Parse(tmpl))

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	err = t.Execute(f, map[string]string{
		"Content": strings.ReplaceAll(content, "`", "\\`"),
	})
	if err != nil {
		return err
	}

	return nil
}
