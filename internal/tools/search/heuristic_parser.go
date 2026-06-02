package search

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	reDateNDays  = regexp.MustCompile(`last\s+(\d+)\s+days?`)
	reDateNHours = regexp.MustCompile(`last\s+(\d+)\s+hours?`)
	reLimitN     = regexp.MustCompile(`\b(?:top|first)\s+(\d+)\b`)
	reAssignee   = regexp.MustCompile(`\b(?:assigned\s+to|assignee|owner(?:ed\s+by)?)\s+(\S+)`)
	reTag        = regexp.MustCompile(`\b(?:tagged?\s+with|tag)\s+["']?([^"'\s]+)["']?`)
	reKeyword    = regexp.MustCompile(`\b(?:title\s+(?:contains?|like)|containing|named?)\s+["']?([^"']+?)["']?(?:\s|$)`)
)

// parseQueryHeuristic builds a FilterResult from natural language using pattern
// matching only — no external AI service is needed. It is used as a fallback when
// no LLM backend (MCP Sampling, OpenAI) is available.
func parseQueryHeuristic(params SearchEntitiesParams) (*FilterResult, error) {
	q := strings.ToLower(params.Query)
	var conditions []interface{}

	// Severity
	if sev := detectSeverity(q); sev > 0 {
		conditions = append(conditions, eqFilter("severity", sev))
	}

	// Status
	conditions = append(conditions, detectStatusFilters(q, params.EntityType)...)

	// Date range
	if since := detectSince(q); !since.IsZero() {
		conditions = append(conditions, gteFilter("_createdAt", since.UTC().Format("2006-01-02T15:04:05")))
	}

	// Assignee
	if m := reAssignee.FindStringSubmatch(q); m != nil {
		conditions = append(conditions, eqFilter("assignee", m[1]))
	}

	// Tag
	if m := reTag.FindStringSubmatch(q); m != nil {
		conditions = append(conditions, likeFilter("tags", "%"+m[1]+"%"))
	}

	// Keyword in title
	if m := reKeyword.FindStringSubmatch(q); m != nil {
		keyword := strings.TrimSpace(m[1])
		if keyword != "" {
			conditions = append(conditions, likeFilter("title", "%"+keyword+"%"))
		}
	}

	// Build raw filter
	var rawFilters map[string]interface{}
	switch len(conditions) {
	case 0:
		rawFilters = map[string]interface{}{}
	case 1:
		rawFilters = conditions[0].(map[string]interface{})
	default:
		rawFilters = map[string]interface{}{"_and": conditions}
	}

	// Sort defaults
	sortBy := "_createdAt"
	sortOrder := "desc"
	if params.SortBy != "" {
		sortBy = params.SortBy
	}
	if params.SortOrder != "" {
		sortOrder = params.SortOrder
	}
	if strings.Contains(q, "oldest") || strings.Contains(q, "earliest") || strings.Contains(q, "first created") {
		sortOrder = "asc"
	}

	// Limit
	numResults := 10
	if params.Limit > 0 {
		numResults = params.Limit
	}
	if m := reLimitN.FindStringSubmatch(q); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
			numResults = n
		}
	}

	return &FilterResult{
		RawFilters:        rawFilters,
		SortBy:            sortBy,
		SortOrder:         sortOrder,
		NumResults:        numResults,
		KeptColumns:       params.ExtraColumns,
		ExtraData:         params.ExtraData,
		AdditionalQueries: params.AdditionalQueries,
	}, nil
}

// detectSeverity maps severity keywords to TheHive numeric values (1-4).
// TheHive: 1=Low, 2=Medium, 3=High, 4=Critical.
func detectSeverity(q string) int {
	switch {
	case contains(q, "critical", "p1"):
		return 4
	case contains(q, "high", "p2"):
		return 3
	case contains(q, "medium", "p3"):
		return 2
	case contains(q, "low", "p4"):
		return 1
	}
	return 0
}

// detectStatusFilters returns status condition(s) matched in the query.
func detectStatusFilters(q, entityType string) []interface{} {
	var conditions []interface{}
	switch entityType {
	case "alert":
		switch {
		case contains(q, "new"):
			conditions = append(conditions, eqFilter("status", "New"))
		case contains(q, "inprogress", "in progress", "in-progress"):
			conditions = append(conditions, eqFilter("status", "InProgress"))
		case contains(q, "ignored"):
			conditions = append(conditions, eqFilter("status", "Ignored"))
		case contains(q, "imported", "promoted"):
			conditions = append(conditions, eqFilter("status", "Imported"))
		}
	case "case":
		switch {
		case contains(q, "open", "active"):
			conditions = append(conditions, eqFilter("status", "Open"))
		case contains(q, "resolved", "closed"):
			conditions = append(conditions, eqFilter("status", "Resolved"))
		case contains(q, "deleted"):
			conditions = append(conditions, eqFilter("status", "Deleted"))
		case contains(q, "duplicated"):
			conditions = append(conditions, eqFilter("status", "Duplicated"))
		}
	case "task":
		switch {
		case contains(q, "waiting"):
			conditions = append(conditions, eqFilter("status", "Waiting"))
		case contains(q, "inprogress", "in progress", "in-progress", "ongoing"):
			conditions = append(conditions, eqFilter("status", "InProgress"))
		case contains(q, "completed", "done"):
			conditions = append(conditions, eqFilter("status", "Completed"))
		case contains(q, "cancelled", "canceled"):
			conditions = append(conditions, eqFilter("status", "Cancel"))
		}
	}
	return conditions
}

// detectSince returns the earliest timestamp implied by the query, or zero.
func detectSince(q string) time.Time {
	now := time.Now()
	switch {
	case contains(q, "today"):
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	case contains(q, "yesterday"):
		d := now.AddDate(0, 0, -1)
		return time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, d.Location())
	case contains(q, "last week", "past week", "this week"):
		return now.AddDate(0, 0, -7)
	case contains(q, "last month", "past month", "this month"):
		return now.AddDate(0, -1, 0)
	case contains(q, "last year", "past year", "this year"):
		return now.AddDate(-1, 0, 0)
	case contains(q, "last 24h", "last 24 h", "last 24 hours"):
		return now.Add(-24 * time.Hour)
	case contains(q, "last 48h", "last 48 h", "last 48 hours"):
		return now.Add(-48 * time.Hour)
	case contains(q, "last 72h", "last 72 h", "last 72 hours"):
		return now.Add(-72 * time.Hour)
	}
	if m := reDateNDays.FindStringSubmatch(q); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return now.AddDate(0, 0, -n)
		}
	}
	if m := reDateNHours.FindStringSubmatch(q); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return now.Add(time.Duration(-n) * time.Hour)
		}
	}
	return time.Time{}
}

// contains reports whether any of the patterns appear as word boundaries in s.
func contains(s string, patterns ...string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func eqFilter(field string, value interface{}) map[string]interface{} {
	return map[string]interface{}{
		"_eq": map[string]interface{}{
			"_field": field,
			"_value": value,
		},
	}
}

func gteFilter(field string, value interface{}) map[string]interface{} {
	return map[string]interface{}{
		"_gte": map[string]interface{}{
			"_field": field,
			"_value": value,
		},
	}
}

func likeFilter(field string, pattern string) map[string]interface{} {
	return map[string]interface{}{
		"_like": map[string]interface{}{
			"_field": field,
			"_value": pattern,
		},
	}
}
