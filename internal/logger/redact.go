package logger

import (
	"regexp"
	"strings"
)

var secretRe = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b[\w-]{24,26}\.[\w-]{6,7}\.[\w-]{27,}\b`),
	regexp.MustCompile(`(?i)\bmfa\.[\w-]{84,}\b`),
	regexp.MustCompile(`(?i)steamAuthTicket["\s:=']+[A-Za-z0-9+/=]{40,}`),
	regexp.MustCompile(`(?i)\beyA[\w+/=]{40,}\b`),
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}`),
	regexp.MustCompile(`(?i)(token|passwd|password|secret|apikey|api_key|client_secret|session)\s*[=:]\s*["']?[A-Za-z0-9._~+/=-]{12,}["']?`),
	regexp.MustCompile(`(?i)-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{40,}`),
	regexp.MustCompile(`(?i)base64[,:= ]+[A-Za-z0-9+/=]{40,}`),
}

const redacted = "[REDACTED]"

func Redact(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, re := range secretRe {
		out = re.ReplaceAllString(out, redacted)
	}
	return out
}

func RedactAll(fields map[string]any) map[string]any {
	for k, v := range fields {
		if s, ok := v.(string); ok {
			fields[k] = Redact(s)
			continue
		}
		if sl, ok := v.([]string); ok {
			for i := range sl {
				sl[i] = Redact(sl[i])
			}
		}
	}
	return fields
}

func LooksSecret(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "token") || strings.Contains(l, "password") ||
		strings.Contains(l, "secret") || strings.Contains(l, "bearer") ||
		strings.Contains(l, "-enc") || strings.Contains(l, "base64") ||
		strings.Contains(l, "mfa") || strings.Contains(l, "steamauthticket") ||
		strings.Contains(l, "eyA")
}
