package sl

import (
	"log/slog"
	"strings"
)

func MaskEmail(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 1 {
		return "***"
	}

	local := email[:at]
	domain := email[at+1:]

	return local[:1] + "***@" + domain
}

func Err(err error) slog.Attr {
	return slog.Attr{
		Key:   "error",
		Value: slog.StringValue(err.Error()),
	}
}
