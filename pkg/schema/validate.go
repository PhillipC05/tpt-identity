package schema

import (
	"fmt"
	"strconv"
	"time"
)

// Validate checks that claims satisfy the required fields defined by schemaID.
// claims is a map of claim name → string value (as serialised in a VC).
func Validate(schemaID string, claims map[string]string) error {
	s, err := GetSchema(schemaID)
	if err != nil {
		return err
	}
	for _, def := range s.Claims {
		val, ok := claims[def.Name]
		if def.Required && !ok {
			return fmt.Errorf("schema %s: missing required claim %q", schemaID, def.Name)
		}
		if !ok {
			continue
		}
		if err := validateType(def.Name, def.Type, val); err != nil {
			return fmt.Errorf("schema %s: %w", schemaID, err)
		}
	}
	return nil
}

func validateType(name, typ, val string) error {
	switch typ {
	case "string":
		if val == "" {
			return fmt.Errorf("claim %q must not be empty", name)
		}
	case "date":
		if _, err := time.Parse("2006-01-02", val); err != nil {
			return fmt.Errorf("claim %q must be a date (YYYY-MM-DD): %w", name, err)
		}
	case "number":
		if _, err := strconv.ParseFloat(val, 64); err != nil {
			return fmt.Errorf("claim %q must be a number: %w", name, err)
		}
	case "boolean":
		if val != "true" && val != "false" {
			return fmt.Errorf("claim %q must be 'true' or 'false'", name)
		}
	}
	return nil
}
