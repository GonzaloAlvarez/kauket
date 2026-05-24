package bundle

import (
	"filippo.io/age"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
)

type combinedRecipientProvider struct {
	a agebox.RecipientProvider
	b agebox.RecipientProvider
}

func (c combinedRecipientProvider) Recipients() ([]age.Recipient, error) {
	aRecips, err := c.a.Recipients()
	if err != nil {
		return nil, err
	}
	bRecips, err := c.b.Recipients()
	if err != nil {
		return nil, err
	}
	out := make([]age.Recipient, 0, len(aRecips)+len(bRecips))
	out = append(out, aRecips...)
	out = append(out, bRecips...)
	return out, nil
}
