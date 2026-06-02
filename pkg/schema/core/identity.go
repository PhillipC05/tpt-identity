package core

import "github.com/PhillipC05/tpt-identity/pkg/schema"

func init() {
	schema.RegisterCategory(schema.Category{
		ID:          "identity",
		Name:        "Identity",
		Description: "Core personal identity documents and government identifiers",
		Icon:        "id-card",
	})

	for _, s := range []schema.Schema{
		{ID: "identity.legal-name", CategoryID: "identity", Name: "Legal Name", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "givenNames", Type: "string", Required: true},
				{Name: "familyName", Type: "string", Required: true},
				{Name: "preferredName", Type: "string"},
			}},
		{ID: "identity.dob", CategoryID: "identity", Name: "Date of Birth", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "dateOfBirth", Type: "date", Required: true},
			}},
		{ID: "identity.address", CategoryID: "identity", Name: "Address", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "streetAddress", Type: "string", Required: true},
				{Name: "suburb", Type: "string"},
				{Name: "city", Type: "string", Required: true},
				{Name: "postcode", Type: "string"},
				{Name: "country", Type: "string", Required: true},
			}},
		{ID: "identity.passport", CategoryID: "identity", Name: "Passport", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "passportNumber", Type: "string", Required: true},
				{Name: "issuingCountry", Type: "string", Required: true},
				{Name: "expiryDate", Type: "date", Required: true},
			}},
		{ID: "identity.drivers-licence", CategoryID: "identity", Name: "Driver's Licence", Source: schema.SourceCore,
			Claims: []schema.ClaimDefinition{
				{Name: "licenceNumber", Type: "string", Required: true},
				{Name: "issuingAuthority", Type: "string", Required: true},
				{Name: "licenceClass", Type: "string"},
				{Name: "expiryDate", Type: "date", Required: true},
			}},
		{ID: "identity.nhi", CategoryID: "identity", Name: "NHI Number (NZ)", Source: schema.SourceCore,
			Description: "New Zealand National Health Index number",
			Claims: []schema.ClaimDefinition{
				{Name: "nhiNumber", Type: "string", Required: true},
			}},
		{ID: "identity.ird-number", CategoryID: "identity", Name: "IRD Number (NZ)", Source: schema.SourceCore,
			Description: "New Zealand Inland Revenue Department tax number",
			Claims: []schema.ClaimDefinition{
				{Name: "irdNumber", Type: "string", Required: true},
			}},
	} {
		schema.RegisterSchema(s)
	}
}
