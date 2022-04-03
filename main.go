package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

func main() {
	alerts, err := getAlerts("cumet04", "dependabot-issues", 10)
	if err != nil {
		panic(err)
	}

	for _, a := range alerts {
		if len(a.UpdateError) == 0 {
			continue
		}
		fmt.Printf("#%d. [%s] %s\n", a.Number, a.Ecosystem, a.Title)
		fmt.Println(a.Description)
		fmt.Println("---")
		fmt.Print(a.UpdateError)
		fmt.Println("-----------------------")
		fmt.Println("")
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
