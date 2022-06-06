package main

import (
	"bytes"
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
		if len(a.UpdateErrorBody) == 0 {
			continue
		}
		d, _ := formatAlert(a)
		content += d.Body + "\n"
	}

	if err := genPreview("preview.html", content); err != nil {
		panic(err)
	}
}

type Alert struct {
	CreatedAt        time.Time
	Number           int
	UpdateErrorBody  string
	UpdateErrorTitle string
	UpdateErrorType  string
	Title            string
	AdvisoryLink     string
	Description      string
	Package          string
	Ecosystem        string // NPM, RUBYGEMS, ... refs https://docs.github.com/en/graphql/reference/enums#securityadvisoryecosystem
	AffectedVersions string
	AlertLink        string
}

func getAlerts(owner string, repo string, count int) ([]Alert, error) {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	httpClient := oauth2.NewClient(context.Background(), src)

	client := githubv4.NewClient(httpClient)

	var query struct {
		Repository struct {
			Url                 string
			VulnerabilityAlerts struct {
				Nodes []struct {
					CreatedAt        time.Time
					Number           int
					DependabotUpdate struct {
						Error struct {
							Body      string
							ErrorType string
							Title     string
						}
					}
					SecurityAdvisory struct {
						Summary     string
						Permalink   string
						Description string
					}
					SecurityVulnerability struct {
						VulnerableVersionRange string
						Package                struct {
							Name      string
							Ecosystem string
						}
					}
				}
			} `graphql:"vulnerabilityAlerts(first: $count, states: OPEN)"`
		} `graphql:"repository(owner: $owner, name: $name)"`
	}

	err := client.Query(context.Background(), &query, map[string]interface{}{
		"owner": githubv4.String(owner),
		"name":  githubv4.String(repo),
		"count": githubv4.Int(count),
	})

	if err != nil {
		return nil, err
	}

	var alerts []Alert
	for _, v := range query.Repository.VulnerabilityAlerts.Nodes {
		alerts = append(alerts, Alert{
			CreatedAt:        v.CreatedAt,
			Number:           v.Number,
			UpdateErrorBody:  v.DependabotUpdate.Error.Body,
			UpdateErrorTitle: v.DependabotUpdate.Error.Title,
			UpdateErrorType:  v.DependabotUpdate.Error.ErrorType,
			Title:            v.SecurityAdvisory.Summary,
			AdvisoryLink:     v.SecurityAdvisory.Permalink,
			Description:      v.SecurityAdvisory.Description,
			Package:          v.SecurityVulnerability.Package.Name,
			Ecosystem:        v.SecurityVulnerability.Package.Ecosystem,
			AffectedVersions: v.SecurityVulnerability.VulnerableVersionRange,
			AlertLink:        fmt.Sprintf("%s/security/dependabot/%d", query.Repository.Url, v.Number),
		})
	}
	return alerts, nil
}

func isExistIssue(title string) (bool, error) {
	return false, nil
}

type Draft struct {
	Alert *Alert
	Title string
	Body  string
}

func formatAlert(alert Alert) (*Draft, error) {
	titleTmpl := "[{{.Ecosystem}}] Security Alert: {{.Package}} {{.AffectedVersions}}"
	title, err := tmpl(titleTmpl, alert)
	if err != nil {
		return nil, err
	}

	bodyTmpl := `
Original Alert: [#{{.Number}} {{.Title}}]({{.AlertLink}})

## Description
{{.Description}}

## Dependabot error
⚠️**{{.UpdateErrorTitle}}**

{{.UpdateErrorBody}}
	`
	body, err := tmpl(bodyTmpl, alert)
	if err != nil {
		return nil, err
	}

	return &Draft{
		Alert: &alert,
		Title: title,
		Body:  body,
	}, nil
}

func tmpl(tmpl string, alert Alert) (string, error) {
	t, err := template.New("t").Parse(tmpl)
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	if err := t.Execute(&b, alert); err != nil {
		return "", err
	}

	return b.String(), nil
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
