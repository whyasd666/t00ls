// Package core содержит Core Engine — минимальный диспетчер, который
// запускает и останавливает независимые модули WhySentry (Audit, Monitor,
// Response, и любые будущие модули) по единому контракту.
package core

import "context"

// Module — единый контракт для всех модулей агента.
// Start должен блокироваться до отмены ctx (для долгоживущих модулей,
// например Monitor/Response) либо завершиться сразу после выполнения
// разовой задачи (например, Audit при старте).
type Module interface {
	Name() string
	Start(ctx context.Context) error
}
