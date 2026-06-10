package search

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// English: "last N days" / Portuguese: "últimos N dias" / "ultimos N dias"
	reDateNDays = regexp.MustCompile(`(?:last|ultimos?|últimos?)\s+(\d+)\s+(?:days?|dias?)`)
	// English: "last N hours" / Portuguese: "últimas N horas" / "ultimas N horas"
	reDateNHours = regexp.MustCompile(`(?:last|ultimas?|últimas?)\s+(\d+)\s+(?:hours?|horas?)`)
	// DD/MM or DD/MM/YYYY  (Brazilian / European format)
	reDateDMY = regexp.MustCompile(`\b(\d{1,2})[/\-](\d{1,2})(?:[/\-](\d{2,4}))?\b`)
	// YYYY-MM-DD
	reDateISO = regexp.MustCompile(`\b(\d{4})-(\d{2})-(\d{2})\b`)
	reLimitN  = regexp.MustCompile(`\b(?:top|first)\s+(\d+)\b`)
	reAssignee = regexp.MustCompile(`\b(?:assigned\s+to|assignee|owner(?:ed\s+by)?)\s+(\S+)`)
	reTag      = regexp.MustCompile(`\b(?:tagged?\s+with|tag)\s+["']?([^"'\s]+)["']?`)
	reKeyword  = regexp.MustCompile(`\b(?:title\s+(?:contains?|like)|containing|named?)\s+["']?([^"']+?)["']?(?:\s|$)`)
)

const dateLayout = "2006-01-02T15:04:05"

// dateRange holds an inclusive time window for a date filter.
// If end is zero, only a _gte filter is emitted (open-ended range).
type dateRange struct {
	start time.Time
	end   time.Time // zero = open-ended
}

// parseQueryHeuristic builds a FilterResult from natural language using pattern
// matching only — no external AI service is needed. It is the automatic fallback
// when no LLM backend (MCP Sampling, OpenAI) is configured.
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
	if dr := detectDateRange(q); !dr.start.IsZero() {
		conditions = append(conditions, gteFilter("_createdAt", dr.start.UTC().Format(dateLayout)))
		if !dr.end.IsZero() {
			conditions = append(conditions, lteFilter("_createdAt", dr.end.UTC().Format(dateLayout)))
		}
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
		if keyword := strings.TrimSpace(m[1]); keyword != "" {
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
	if contains(q, "oldest", "earliest", "first created") {
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

// detectSeverity maps severity keywords to TheHive numeric values (1=Low … 4=Critical).
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

// detectDateRange extracts the date window from the query.
// Returns an open-ended range (end == zero) for relative expressions,
// and a closed range (start + end) for specific calendar days.
func detectDateRange(q string) dateRange {
	now := time.Now()
	loc := now.Location()

	// Relative expressions → open-ended (_gte only)
	switch {
	// "hoje" / "today" / "último dia": from midnight today up to the current moment
	case contains(q, "today", "hoje", "último dia", "ultimo dia", "last day"):
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
		return dateRange{start: start, end: now}

	case contains(q, "yesterday", "ontem"):
		d := now.AddDate(0, 0, -1)
		start := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, loc)
		end := start.Add(24*time.Hour - time.Second)
		return dateRange{start: start, end: end}

	case contains(q, "last week", "past week", "this week", "última semana", "semana passada"):
		return dateRange{start: now.AddDate(0, 0, -7)}

	case contains(q, "last month", "past month", "this month", "último mês", "mês passado"):
		return dateRange{start: now.AddDate(0, -1, 0)}

	case contains(q, "last year", "past year", "this year", "último ano", "ano passado"):
		return dateRange{start: now.AddDate(-1, 0, 0)}

	case contains(q, "last 24h", "last 24 h", "last 24 hours",
		"últimas 24h", "últimas 24 h", "últimas 24 horas",
		"ultimas 24h", "ultimas 24 h", "ultimas 24 horas"):
		return dateRange{start: now.Add(-24 * time.Hour)}

	case contains(q, "last 48h", "last 48 h", "last 48 hours",
		"últimas 48h", "últimas 48 h", "últimas 48 horas",
		"ultimas 48h", "ultimas 48 h", "ultimas 48 horas"):
		return dateRange{start: now.Add(-48 * time.Hour)}

	case contains(q, "last 72h", "last 72 h", "last 72 hours",
		"últimas 72h", "últimas 72 h", "últimas 72 horas",
		"ultimas 72h", "ultimas 72 h", "ultimas 72 horas"):
		return dateRange{start: now.Add(-72 * time.Hour)}
	}

	if m := reDateNDays.FindStringSubmatch(q); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return dateRange{start: now.AddDate(0, 0, -n)}
		}
	}
	if m := reDateNHours.FindStringSubmatch(q); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return dateRange{start: now.Add(time.Duration(-n) * time.Hour)}
		}
	}

	// ISO date YYYY-MM-DD → exact day range
	if m := reDateISO.FindStringSubmatch(q); m != nil {
		y, _ := strconv.Atoi(m[1])
		mo, _ := strconv.Atoi(m[2])
		d, _ := strconv.Atoi(m[3])
		start := time.Date(y, time.Month(mo), d, 0, 0, 0, 0, loc)
		return dateRange{start: start, end: start.Add(24*time.Hour - time.Second)}
	}

	// DD/MM or DD/MM/YYYY → exact day range
	if m := reDateDMY.FindStringSubmatch(q); m != nil {
		day, _ := strconv.Atoi(m[1])
		month, _ := strconv.Atoi(m[2])
		year := now.Year()
		if m[3] != "" {
			y, err := strconv.Atoi(m[3])
			if err == nil {
				if y < 100 {
					y += 2000
				}
				year = y
			}
		}
		if day >= 1 && day <= 31 && month >= 1 && month <= 12 {
			start := time.Date(year, time.Month(month), day, 0, 0, 0, 0, loc)
			return dateRange{start: start, end: start.Add(24*time.Hour - time.Second)}
		}
	}

	return dateRange{}
}

// contains reports whether any of the patterns appear in s.
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
		"_eq": map[string]interface{}{"_field": field, "_value": value},
	}
}

func gteFilter(field string, value interface{}) map[string]interface{} {
	return map[string]interface{}{
		"_gte": map[string]interface{}{"_field": field, "_value": value},
	}
}

func lteFilter(field string, value interface{}) map[string]interface{} {
	return map[string]interface{}{
		"_lte": map[string]interface{}{"_field": field, "_value": value},
	}
}

func likeFilter(field string, pattern string) map[string]interface{} {
	return map[string]interface{}{
		"_like": map[string]interface{}{"_field": field, "_value": pattern},
	}
}
