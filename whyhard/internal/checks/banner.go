package checks

import (
	"fmt"
	"os"
	"time"

	"whyhard/internal/core"
)

// legalBanner — стандартный текст предупреждения о мониторинге доступа.
// Юридическая ценность зависит от юрисдикции — это базовый текст,
// администратор может (и должен) адаптировать под свою организацию.
const legalBanner = `*****************************************************************
* Доступ к этой системе только для авторизованных пользователей. *
* Все действия могут отслеживаться и протоколироваться.           *
* Несанкционированный доступ запрещён и преследуется по закону.   *
*****************************************************************
`

var bannerFiles = []string{"/etc/issue", "/etc/issue.net"}

type BannerModule struct{}

func NewBanner() *BannerModule { return &BannerModule{} }

func (m *BannerModule) Name() string { return "banner" }

func (m *BannerModule) Run(mode core.Mode) []core.Finding {
	var findings []core.Finding

	for _, path := range bannerFiles {
		data, err := os.ReadFile(path)
		exists := err == nil

		if exists && string(data) == legalBanner {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: path, Severity: core.SeverityLow, Risk: core.RiskSafe,
				Status: core.StatusOK, Detail: fmt.Sprintf("%s уже содержит legal-баннер whyhard", path),
			})
			continue
		}

		if mode == core.ModeAudit {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: path, Severity: core.SeverityLow, Risk: core.RiskSafe,
				Status: core.StatusWarn,
				Detail: fmt.Sprintf("%s не содержит предупреждения о мониторинге доступа (или отличается)", path),
			})
			continue
		}

		if exists {
			backupPath := fmt.Sprintf("%s.whyhard.bak.%d", path, time.Now().Unix())
			_ = os.WriteFile(backupPath, data, 0644) // best-effort backup, не критично для текстового баннера
		}

		if err := os.WriteFile(path, []byte(legalBanner), 0644); err != nil {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: path, Severity: core.SeverityLow, Risk: core.RiskSafe,
				Status: core.StatusError, Detail: err.Error(),
			})
			continue
		}
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: path, Severity: core.SeverityLow, Risk: core.RiskSafe,
			Status: core.StatusFixed, Detail: fmt.Sprintf("%s обновлён (legal-баннер)", path),
		})
	}

	return findings
}
