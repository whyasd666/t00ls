package core

import (
	"context"
	"sync"

	"whysentry/internal/logger"
)

// Engine — диспетчер модулей. Хранит список зарегистрированных модулей
// и управляет их жизненным циклом через общий context.
type Engine struct {
	modules []Module
	wg      sync.WaitGroup
}

// NewEngine создаёт пустой Core Engine.
func NewEngine() *Engine {
	return &Engine{}
}

// Register добавляет модуль в список управляемых Engine'ом.
// Порядок регистрации определяет порядок запуска (не порядок остановки —
// все модули останавливаются параллельно по отмене ctx).
func (e *Engine) Register(m Module) {
	e.modules = append(e.modules, m)
}

// Run запускает все зарегистрированные модули в отдельных горутинах.
// Не блокируется — для ожидания завершения используйте Wait.
func (e *Engine) Run(ctx context.Context) {
	for _, m := range e.modules {
		e.wg.Add(1)
		go func(mod Module) {
			defer e.wg.Done()
			logger.Info("[core] starting module: %s", mod.Name())
			if err := mod.Start(ctx); err != nil {
				logger.Error("[core] module %q exited with error: %v", mod.Name(), err)
				return
			}
			logger.Info("[core] module %q stopped", mod.Name())
		}(m)
	}
}

// Wait блокируется до завершения всех модулей (например, после отмены ctx
// в результате сигнала SIGINT/SIGTERM).
func (e *Engine) Wait() {
	e.wg.Wait()
}
