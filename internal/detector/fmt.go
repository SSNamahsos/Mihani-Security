package detector

import "strconv"

func formatInt(v int) string   { return strconv.Itoa(v) }
func formatHex(v int64) string { return strconv.FormatInt(v, 16) }
