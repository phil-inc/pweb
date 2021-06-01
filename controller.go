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

//Head returns HEAD handler function
func (c Controller) Head(path string, body interface{}, f func(http.ResponseWriter, *http.Request) Response) {
	if body == nil {
		c.router.Head(path, c.chain.ThenFunc(ResponseHandler(f)))
	} else {
		c.router.Head(path, c.chain.Append(JSONBodyHandler(c.ctx, body)).ThenFunc(ResponseHandler(f)))
	}
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

//NewController new controller object
func NewController(ctx context.Context, c alice.Chain, r *PhilRouter) Controller {
	return Controller{ctx: ctx, chain: c, router: r}
}
