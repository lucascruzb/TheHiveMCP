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
	reDateISO  = regexp.MustCompile(`\b(\d{4})-(\d{2})-(\d{2})\b`)
	reLimitN   = regexp.MustCompile(`\b(?:top|first)\s+(\d+)\b`)
	reAssignee = regexp.MustCompile(`\b(?:assigned\s+to|assignee|owner(?:ed\s+by)?)\s+(\S+)`)
	reTag      = regexp.MustCompile(`\b(?:tagged?\s+with|tag)\s+["']?([^"'\s]+)["']?`)
	reKeyword  = regexp.MustCompile(`\b(?:title\s+(?:contains?|like)|containing|named?)\s+["']?([^"']+?)["']?(?:\s|$)`)
	// "type wazuh_alert_7" / "tipo wazuh_alert_7" / bare "wazuh_alert_7"
	reType = regexp.MustCompile(`\b(?:type|tipo)\s+(\S+)|\b(wazuh_alert_\d+)\b`)
	// "group by type" / "agrupado por tipo" / "agrupar por tipo"
	reGroupBy = regexp.MustCompile(`\b(?:agrupados?\s+por|agrupar\s+por|resumo\s+por|group\s+by|summary\s+by|grouped\s+by)\s+(\S+)`)
	// maps Portuguese field names to TheHive field names
	groupByFieldMap = map[string]string{
		"tipo":       "type",
		"status":     "status",
		"severidade": "severity",
		"severity":   "severity",
		"assignee":   "assignee",
		"type":       "type",
	}
)

// dateLayout is used only for absolute date expressions (DD/MM/YYYY, YYYY-MM-DD).
// Relative expressions use TheHive's native _between syntax resolved server-side.
const dateLayout = "2006-01-02T15:04:05"

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

	// Date — relative expressions use TheHive's native _between (server-side timezone);
	// absolute dates (DD/MM/YYYY, YYYY-MM-DD) use Unix ms timestamps.
	conditions = append(conditions, detectDateConditions(q)...)

	// Assignee
	if m := reAssignee.FindStringSubmatch(q); m != nil {
		conditions = append(conditions, eqFilter("assignee", m[1]))
	}

	// Tag
	if m := reTag.FindStringSubmatch(q); m != nil {
		conditions = append(conditions, likeFilter("tags", "%"+m[1]+"%"))
	}

	// Alert type ("type wazuh_alert_7", "tipo wazuh_alert_10", or bare "wazuh_alert_7")
	if m := reType.FindStringSubmatch(q); m != nil {
		typeVal := m[1]
		if typeVal == "" {
			typeVal = m[2]
		}
		if typeVal != "" {
			conditions = append(conditions, eqFilter("type", typeVal))
		}
	}

	// Keyword in title
	if m := reKeyword.FindStringSubmatch(q); m != nil {
		if keyword := strings.TrimSpace(m[1]); keyword != "" {
			conditions = append(conditions, likeFilter("title", "%"+keyword+"%"))
		}
	}

	// GroupBy: "agrupado por tipo", "group by type", "resumo por status", etc.
	var groupBy string
	if m := reGroupBy.FindStringSubmatch(q); m != nil {
		raw := strings.ToLower(m[1])
		if mapped, ok := groupByFieldMap[raw]; ok {
			groupBy = mapped
		} else {
			groupBy = raw
		}
	} else if contains(q, "por tipo", "by type", "per type") &&
		contains(q, "resumo", "agrupado", "group", "summary", "total", "breakdown") {
		// "resumo agrupado...por tipo" / "total por tipo" → group by type
		groupBy = "type"
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
		GroupBy:           groupBy,
	}, nil
}

// detectDateConditions returns TheHive filter conditions for date expressions found in q.
// Relative expressions (today, last 24h, etc.) use TheHive's native _between operator
// so the server resolves start/end-of-day in its own configured timezone.
// Absolute dates (DD/MM/YYYY, YYYY-MM-DD) are converted to Unix ms timestamps.
func detectDateConditions(q string) []interface{} {
	now := time.Now()
	loc := now.Location()

	switch {
	// hoje / today / último dia: start of today → now
	case contains(q, "today", "hoje", "último dia", "ultimo dia", "last day"):
		return []interface{}{betweenFilter("date",
			relDate(0, "days", "behind", "startOfDay"),
			relDate(0, "seconds", "ahead", ""),
		)}

	// ontem / yesterday: full previous calendar day
	case contains(q, "yesterday", "ontem"):
		return []interface{}{betweenFilter("date",
			relDate(1, "days", "behind", "startOfDay"),
			relDate(1, "days", "behind", "endOfDay"),
		)}

	// última semana / last week: rolling 7 days
	case contains(q, "last week", "past week", "this week", "última semana", "semana passada"):
		return []interface{}{betweenFilter("date",
			relDate(7, "days", "behind", ""),
			relDate(0, "seconds", "ahead", ""),
		)}

	// último mês / last month: rolling 1 month
	case contains(q, "last month", "past month", "this month", "último mês", "mês passado"):
		return []interface{}{betweenFilter("date",
			relDate(1, "months", "behind", ""),
			relDate(0, "seconds", "ahead", ""),
		)}

	// último ano / last year: rolling 1 year
	case contains(q, "last year", "past year", "this year", "último ano", "ano passado"):
		return []interface{}{betweenFilter("date",
			relDate(1, "years", "behind", ""),
			relDate(0, "seconds", "ahead", ""),
		)}

	// últimas 24 horas / last 24 hours: rolling 24h window
	case contains(q, "last 24h", "last 24 h", "last 24 hours",
		"últimas 24h", "últimas 24 h", "últimas 24 horas",
		"ultimas 24h", "ultimas 24 h", "ultimas 24 horas"):
		return []interface{}{betweenFilter("date",
			relDate(24, "hours", "behind", ""),
			relDate(0, "seconds", "ahead", ""),
		)}

	// últimas 48 horas / last 48 hours
	case contains(q, "last 48h", "last 48 h", "last 48 hours",
		"últimas 48h", "últimas 48 h", "últimas 48 horas",
		"ultimas 48h", "ultimas 48 h", "ultimas 48 horas"):
		return []interface{}{betweenFilter("date",
			relDate(48, "hours", "behind", ""),
			relDate(0, "seconds", "ahead", ""),
		)}

	// últimas 72 horas / last 72 hours
	case contains(q, "last 72h", "last 72 h", "last 72 hours",
		"últimas 72h", "últimas 72 h", "últimas 72 horas",
		"ultimas 72h", "ultimas 72 h", "ultimas 72 horas"):
		return []interface{}{betweenFilter("date",
			relDate(72, "hours", "behind", ""),
			relDate(0, "seconds", "ahead", ""),
		)}
	}

	// Generic "últimas N horas" / "last N hours"
	if m := reDateNHours.FindStringSubmatch(q); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
			return []interface{}{betweenFilter("date",
				relDate(n, "hours", "behind", ""),
				relDate(0, "seconds", "ahead", ""),
			)}
		}
	}

	// Generic "últimos N dias" / "last N days"
	if m := reDateNDays.FindStringSubmatch(q); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
			return []interface{}{betweenFilter("date",
				relDate(n, "days", "behind", ""),
				relDate(0, "seconds", "ahead", ""),
			)}
		}
	}

	// Absolute: ISO date YYYY-MM-DD → exact day range via Unix ms timestamps
	if m := reDateISO.FindStringSubmatch(q); m != nil {
		y, _ := strconv.Atoi(m[1])
		mo, _ := strconv.Atoi(m[2])
		d, _ := strconv.Atoi(m[3])
		start := time.Date(y, time.Month(mo), d, 0, 0, 0, 0, loc)
		end := start.Add(24*time.Hour - time.Second)
		return []interface{}{
			gteFilter("date", start.UTC().Format(dateLayout)),
			lteFilter("date", end.UTC().Format(dateLayout)),
		}
	}

	// Absolute: DD/MM or DD/MM/YYYY → exact day range via Unix ms timestamps
	if m := reDateDMY.FindStringSubmatch(q); m != nil {
		day, _ := strconv.Atoi(m[1])
		month, _ := strconv.Atoi(m[2])
		year := now.Year()
		if m[3] != "" {
			if y, err := strconv.Atoi(m[3]); err == nil {
				if y < 100 {
					y += 2000
				}
				year = y
			}
		}
		if day >= 1 && day <= 31 && month >= 1 && month <= 12 {
			start := time.Date(year, time.Month(month), day, 0, 0, 0, 0, loc)
			end := start.Add(24*time.Hour - time.Second)
			return []interface{}{
				gteFilter("date", start.UTC().Format(dateLayout)),
				lteFilter("date", end.UTC().Format(dateLayout)),
			}
		}
	}

	return nil
}

// betweenFilter builds a TheHive _between filter using relative date descriptors.
// TheHive resolves these server-side (its own configured timezone), which makes
// startOfDay / endOfDay correct regardless of the MCP server's local timezone.
func betweenFilter(field string, from, to map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"_between": map[string]interface{}{
			"_field": field,
			"_from":  from,
			"_to":    to,
		},
	}
}

// relDate builds a relative date descriptor for TheHive's _between operator.
// modifier is optional ("startOfDay", "endOfDay", or "" for none).
func relDate(amount int, unit, look, modifier string) map[string]interface{} {
	m := map[string]interface{}{
		"amount": amount,
		"unit":   unit,
		"look":   look,
	}
	if modifier != "" {
		m["modifier"] = modifier
	}
	return m
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
