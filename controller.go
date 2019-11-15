package pweb

import (
	"context"
	"net/http"

	"github.com/justinas/alice"
)

//Controller Phil controller
type Controller struct {
	ctx    context.Context
	chain  alice.Chain
	router *PhilRouter
}

//Get returns GET handler function
func (c Controller) Get(path string, f func(http.ResponseWriter, *http.Request) Response) {
	c.router.Get(path, c.chain.ThenFunc(ResponseHandler(f)))
}

//Post returns POST handler function
func (c Controller) Post(path string, body interface{}, f func(http.ResponseWriter, *http.Request) Response) {
	if body == nil {
		c.router.Post(path, c.chain.ThenFunc(ResponseHandler(f)))
	} else {
		c.router.Post(path, c.chain.Append(JSONBodyHandler(c.ctx, body)).ThenFunc(ResponseHandler(f)))
	}
}

//Put returns PUT handler function
func (c Controller) Put(path string, body interface{}, f func(http.ResponseWriter, *http.Request) Response) {
	if body == nil {
		c.router.Put(path, c.chain.ThenFunc(ResponseHandler(f)))
	} else {
		c.router.Put(path, c.chain.Append(JSONBodyHandler(c.ctx, body)).ThenFunc(ResponseHandler(f)))
	}
}

//Delete returns DELETE handler function
func (c Controller) Delete(path string, body interface{}, f func(http.ResponseWriter, *http.Request) Response) {
	if body == nil {
		c.router.Delete(path, c.chain.ThenFunc(ResponseHandler(f)))
	} else {
		c.router.Delete(path, c.chain.Append(JSONBodyHandler(c.ctx, body)).ThenFunc(ResponseHandler(f)))
	}
}

//Append append any middleware of type func(http.Handler) http.Handler at the controller level. This can be used by
//controllers to attach middleware specific to controllers
func (c Controller) Append(constructor alice.Constructor) {
	c.chain = c.chain.Append(constructor)
}

//NewController new controller object
func NewController(ctx context.Context, c alice.Chain, r *PhilRouter) Controller {
	return Controller{ctx: ctx, chain: c, router: r}
}
