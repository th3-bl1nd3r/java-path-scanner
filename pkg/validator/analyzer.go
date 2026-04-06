package validator

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/th3-bl1nd3r/java-path-scanner/pkg/httpclient"
)

// AnalyzeActuatorEnv performs deep analysis of /actuator/env response.
func (v *Validator) AnalyzeActuatorEnv(response *httpclient.Response) map[string]interface{} {
	result := map[string]interface{}{
		"property_sources": []string{},
		"active_profiles":  []string{},
		"secrets":          []map[string]string{},
	}

	var data map[string]interface{}
	if err := json.Unmarshal(response.Body, &data); err != nil {
		return result
	}

	if profiles, ok := data["activeProfiles"].([]interface{}); ok {
		var profileStrs []string
		for _, p := range profiles {
			if s, ok := p.(string); ok {
				profileStrs = append(profileStrs, s)
			}
		}
		result["active_profiles"] = profileStrs
	}

	var secrets []map[string]string
	var sources []string

	if propertySources, ok := data["propertySources"].([]interface{}); ok {
		for _, ps := range propertySources {
			source, ok := ps.(map[string]interface{})
			if !ok {
				continue
			}
			sourceName, _ := source["name"].(string)
			sources = append(sources, sourceName)

			props, ok := source["properties"].(map[string]interface{})
			if !ok {
				continue
			}

			for key, valObj := range props {
				var value string
				if valMap, ok := valObj.(map[string]interface{}); ok {
					if v, ok := valMap["value"].(string); ok {
						value = v
					}
				}

				if value != "" && !isMasked(value) {
					combined := key + "=" + value
					for _, sp := range secretPatterns {
						if sp.Pattern.MatchString(combined) {
							display := value
							if len(display) > 100 {
								display = display[:100]
							}
							secrets = append(secrets, map[string]string{
								"key":    key,
								"value":  display,
								"source": sourceName,
								"type":   sp.Type,
							})
							break
						}
					}
				}
			}
		}
	}

	result["property_sources"] = sources
	result["secrets"] = secrets
	return result
}

// AnalyzeSwagger extracts API endpoints from Swagger/OpenAPI spec.
func (v *Validator) AnalyzeSwagger(response *httpclient.Response) map[string]interface{} {
	result := map[string]interface{}{
		"endpoints":    []map[string]interface{}{},
		"auth_schemes": []map[string]string{},
	}

	var data map[string]interface{}
	if err := json.Unmarshal(response.Body, &data); err != nil {
		return result
	}

	var endpoints []map[string]interface{}

	paths, ok := data["paths"].(map[string]interface{})
	if ok {
		for path, methods := range paths {
			methodMap, ok := methods.(map[string]interface{})
			if !ok {
				continue
			}
			for method, details := range methodMap {
				methodLower := strings.ToLower(method)
				if methodLower == "get" || methodLower == "post" || methodLower == "put" ||
					methodLower == "delete" || methodLower == "patch" {

					endpoint := map[string]interface{}{
						"path":   path,
						"method": strings.ToUpper(method),
					}

					if detailMap, ok := details.(map[string]interface{}); ok {
						if summary, ok := detailMap["summary"].(string); ok {
							endpoint["summary"] = summary
						}
						if tags, ok := detailMap["tags"].([]interface{}); ok {
							var tagStrs []string
							for _, t := range tags {
								if s, ok := t.(string); ok {
									tagStrs = append(tagStrs, s)
								}
							}
							endpoint["tags"] = tagStrs
						}
						_, hasSecurity := detailMap["security"]
						endpoint["auth_required"] = hasSecurity
					}

					endpoints = append(endpoints, endpoint)
				}
			}
		}
	}
	result["endpoints"] = endpoints

	// Security definitions (OAS 2.0 or 3.0)
	var authSchemes []map[string]string
	secDefs := getNestedMap(data, "securityDefinitions")
	if secDefs == nil {
		if components := getNestedMap(data, "components"); components != nil {
			secDefs = getNestedMap(components, "securitySchemes")
		}
	}
	if secDefs != nil {
		for name, scheme := range secDefs {
			schemeMap, ok := scheme.(map[string]interface{})
			if !ok {
				continue
			}
			authSchemes = append(authSchemes, map[string]string{
				"name":   name,
				"type":   getStringVal(schemeMap, "type"),
				"scheme": getStringVal(schemeMap, "scheme"),
			})
		}
	}
	result["auth_schemes"] = authSchemes

	return result
}

// AnalyzeMappings extracts custom endpoints from Spring Boot /actuator/mappings.
func (v *Validator) AnalyzeMappings(response *httpclient.Response) []map[string]string {
	var endpoints []map[string]string

	var data map[string]interface{}
	if err := json.Unmarshal(response.Body, &data); err != nil {
		return endpoints
	}

	// Spring Boot 2.x format
	contexts, ok := data["contexts"].(map[string]interface{})
	if ok {
		for _, ctxData := range contexts {
			ctxMap, ok := ctxData.(map[string]interface{})
			if !ok {
				continue
			}
			mappings, ok := ctxMap["mappings"].(map[string]interface{})
			if !ok {
				continue
			}

			dispatchers := getNestedMap(mappings, "dispatcherServlets")
			if dispatchers == nil {
				dispatchers = getNestedMap(mappings, "dispatcherHandlers")
			}
			if dispatchers == nil {
				continue
			}

			for _, handlerList := range dispatchers {
				handlers, ok := handlerList.([]interface{})
				if !ok {
					continue
				}
				for _, h := range handlers {
					handler, ok := h.(map[string]interface{})
					if !ok {
						continue
					}
					details := getNestedMap(handler, "details")
					if details == nil {
						continue
					}
					conditions := getNestedMap(details, "requestMappingConditions")
					if conditions == nil {
						continue
					}

					patterns := getStringSlice(conditions, "patterns")
					methods := getStringSlice(conditions, "methods")

					for _, pattern := range patterns {
						if strings.HasPrefix(pattern, "/actuator") ||
							strings.HasPrefix(pattern, "/**/favicon.ico") ||
							strings.HasPrefix(pattern, "/error") {
							continue
						}

						methodStr := "ALL"
						if len(methods) > 0 {
							methodStr = strings.Join(methods, ", ")
						}
						handlerStr := getStringVal(handler, "handler")
						endpoints = append(endpoints, map[string]string{
							"path":    pattern,
							"methods": methodStr,
							"handler": handlerStr,
						})
					}
				}
			}
		}
	}

	// Spring Boot 1.x format (flat)
	if !ok {
		for path, details := range data {
			if !strings.HasPrefix(path, "/") {
				continue
			}
			if strings.HasPrefix(path, "/actuator") || strings.HasPrefix(path, "/error") {
				continue
			}
			methodStr := "ALL"
			if detailMap, ok := details.(map[string]interface{}); ok {
				if m, ok := detailMap["method"].(string); ok {
					methodStr = m
				}
			}
			endpoints = append(endpoints, map[string]string{
				"path":    path,
				"methods": methodStr,
				"handler": truncateStr(toString(details), 100),
			})
		}
	}

	return endpoints
}

// AnalyzeHeapdump checks if a heapdump is actually downloadable.
func (v *Validator) AnalyzeHeapdump(response *httpclient.Response) bool {
	// Check for Java heap dump magic bytes (HPROF)
	if len(response.Body) > 4 {
		header := string(response.Body[:18])
		return strings.HasPrefix(header, "JAVA PROFILE") || strings.Contains(header, "hprof")
	}
	return response.ContentLength > 1024*1024 // > 1MB likely a real heapdump
}

func getNestedMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key]; ok {
		if nested, ok := v.(map[string]interface{}); ok {
			return nested
		}
	}
	return nil
}

func getStringVal(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getStringSlice(m map[string]interface{}, key string) []string {
	var result []string
	if v, ok := m[key].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
	}
	return result
}

func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// Compile-time check
var _ = regexp.Compile
