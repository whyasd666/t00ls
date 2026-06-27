package core

import "whyhard/internal/logger"

// Engine — диспетчер модулей whyhard. В отличие от WhySentry, модули
// запускаются последовательно (не в горутинах): порядок важен (например,
// backup конфигов должен происходить до их правки внутри модуля), и
// каждый прогон — однократный, а не бесконечный цикл.
type Engine struct {
	modules []Module
}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Register(m Module) {
	e.modules = append(e.modules, m)
}

// Run выполняет все модули по очереди и возвращает объединённый список находок.
func (e *Engine) Run(mode Mode) []Finding {
	var all []Finding
	for _, m := range e.modules {
		logger.Info("[core] running module: %s", m.Name())
		findings := m.Run(mode)
		logger.Info("[core] module %q: %d checks", m.Name(), len(findings))
		all = append(all, findings...)
	}
	return all
}
