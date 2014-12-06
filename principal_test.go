package principal

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thrisp/flotilla"
)

var (
	n1 string      = "role:a"
	n2 string      = "role:b"
	n3 string      = "role:c"
	n4 string      = "item:key:gold"
	p0 *Permission = NewPermission(1, 2, 3, "four")
	p1 *Permission = NewPermission(n1, n2)
	p2 *Permission = NewPermission(n3)
	p3 *Permission = NewPermission("role:a", n4)
)

func PerformRequest(r http.Handler, method, path string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func testapp(name string, p *Principal) *flotilla.App {
	f := flotilla.New(name)
	p.Init(f)
	f.Configure(f.Configuration...)
	return f
}

func testextension() *Principal {
	return New(UseSession())
}

func testidentity(p ...interface{}) *Identity {
	return NewIdentity("test", p...)
}

func TestExtension(t *testing.T) {
	exists := false
	f := testapp("test-extension", testextension())
	f.GET("/test", func(c *flotilla.Ctx) {
		p, _ := c.Call("principal")
		if _, ok := p.(*Principal); ok {
			exists = true
		}
		c.ServeData(200, []byte("success"))
	})
	PerformRequest(f, "GET", "/test")
	if !exists {
		t.Errorf("principal extension does not exist")
	}
}

func TestIdentity(t *testing.T) {
	identity := ""
	f := testapp("test-identity", testextension())
	f.GET("/identity", func(c *flotilla.Ctx) {
		p, _ := c.Call("principal")
		principal := p.(*Principal)
		i := testidentity()
		principal.IdentityChange(i)
		c.ServeData(200, []byte("success"))
		identity = c.Session.Get("identity_id").(string)
	})
	PerformRequest(f, "GET", "/identity")
	if identity != "test" {
		t.Errorf(fmt.Sprintf("test identity should be 'test', got %s", identity))
	}
}

func TestPermission(t *testing.T) {
	f := testapp("test-identity", testextension())
	f.GET("/permission", func(c *flotilla.Ctx) {
		p, _ := c.Call("principal")
		principal := p.(*Principal)
		i := testidentity(n1, n2)
		principal.IdentityChange(i)
		fmt.Printf("%+v %+v %t\n", p0, i, p0.Allows(i))
		fmt.Printf("%+v %+v %t\n", p1, i, p1.Allows(i))
		fmt.Printf("%+v %+v %t\n", p2, i, p2.Allows(i))
		fmt.Printf("%+v %+v %t\n", p3, i, p3.Allows(i))
		ii := testidentity(n4)
		principal.IdentityChange(ii)
		fmt.Printf("%+v %+v %t\n", p0, ii, p0.Allows(ii))
		fmt.Printf("%+v %+v %t\n", p1, ii, p1.Allows(ii))
		fmt.Printf("%+v %+v %t\n", p2, ii, p2.Allows(ii))
		fmt.Printf("%+v %+v %t\n", p3, ii, p3.Allows(ii))
		c.ServeData(200, []byte("success"))
	})
	PerformRequest(f, "GET", "/permission")
}
