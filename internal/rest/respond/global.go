package respond

var (
	globalResponder = &Responder{}
)

func ReplaceGlobal(responder *Responder) func() {
	prev := responder
	globalResponder = responder
	return func() {
		ReplaceGlobal(prev)
	}

}

func NewResponse() *Responder { return globalResponder }
