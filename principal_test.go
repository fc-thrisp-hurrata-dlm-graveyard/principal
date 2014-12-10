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
	p0 *Permission = NewPermission(1, 2, 3, "four", "anonymous")
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

func testapp(name string, p *Manager) *flotilla.App {
	f := flotilla.New(name)
	p.Init(f)
	f.Configure(f.Configuration...)
	return f
}

func testextension(version string) *Manager {
	switch version {
	default:
		return New(UseSession())
	}
}

func testidentity(p ...interface{}) *Identity {
	return NewIdentity("test", p...)
}

func TestExtension(t *testing.T) {
	exists := false
	f := testapp("test-extension", testextension(""))
	f.GET("/test", func(c *flotilla.Ctx) {
		p, _ := c.Call("principal")
		if _, ok := p.(*Manager); ok {
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
	f := testapp("test-identity", testextension(""))
	f.GET("/identity", func(c *flotilla.Ctx) {
		manager(c).Change(testidentity())
		c.ServeData(200, []byte("success"))
		identity = c.Session.Get("identity_id").(string)
	})
	PerformRequest(f, "GET", "/identity")
	if identity != "test" {
		t.Errorf(fmt.Sprintf("test identity should be 'test', got %s", identity))
	}
}

/*
func permissionhandler(c *flotilla.Ctx) {
	p := principal(c)
	i := testidentity(n1, n2)
	p.Change(i)
	fmt.Printf("%+v %+v %t\n", p0, i, p0.Allows(i))
	fmt.Printf("%+v %+v %t\n", p1, i, p1.Allows(i))
	fmt.Printf("%+v %+v %t\n", p2, i, p2.Allows(i))
	fmt.Printf("%+v %+v %t\n", p3, i, p3.Allows(i))
	ii := testidentity(n4)
	p.Change(ii)
	fmt.Printf("%+v %+v %t\n", p0, ii, p0.Allows(ii))
	fmt.Printf("%+v %+v %t\n", p1, ii, p1.Allows(ii))
	fmt.Printf("%+v %+v %t\n", p2, ii, p2.Allows(ii))
	fmt.Printf("%+v %+v %t\n", p3, ii, p3.Allows(ii))
	c.ServeData(200, []byte("success"))
	fmt.Printf("permission handler, %+v\n", c.Data["identity"])
}

func TestPermission(t *testing.T) {
	extension := testextension()
	f := testapp("test-identity", extension)
	f.GET("/permission0", SufficientAuthorization(permissionhandler, p0))
	f.GET("/permission1", SufficientAuthorization(permissionhandler, p1))
	f.GET("/permission2", NecessaryAuthorization(permissionhandler, p2))
	f.GET("/permission3", NecessaryAuthorization(permissionhandler, p3))
	PerformRequest(f, "GET", "/permission0")
	PerformRequest(f, "GET", "/permission1")
	PerformRequest(f, "GET", "/permission2")
	PerformRequest(f, "GET", "/permission3")
}
*/
