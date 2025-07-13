package validator

import (
	"regexp"
)

const emailRegex = "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])"

func ValidateEmail(s string) bool {
	ss := []byte(s)
	a, _ := regexp.Match(emailRegex, ss)
	return a
}

// ValidatePassword checks the password for length. The password must be in between 8 and 72 characters long.
func ValidatePassword(s string) bool {
	if len(s) < 8 || len(s) > 72 {
		return false
	}
	hasUpper := regexp.MustCompile("[A-Z]").MatchString(s)
	hasLower := regexp.MustCompile("[a-z]").MatchString(s)
	hasNumber := regexp.MustCompile("[0-9]").MatchString(s)
	hasSpecial := regexp.MustCompile(`[!@#\$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(s)

	return hasUpper && hasLower && hasNumber && hasSpecial
}
