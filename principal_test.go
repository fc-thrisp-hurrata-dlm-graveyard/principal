package principal

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thrisp/flotilla"
)

var (
	n1 string     = "role:a"
	n2 string     = "role:b"
	n3 string     = "role:c"
	n4 string     = "item:key:gold"
	e1 string     = "garlic"
	e2 string     = "onion"
	p0 Permission = NewPermission("p0", 1, 2, 3, "four", "anonymous")
	p1 Permission = NewPermission("p1", n1, n2)
	p2 Permission = NewPermission("p2", n3)
	p3 Permission = NewPermission("p3", "role:a", n4)
	p4 Permission = NewPermission("p4")
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

func testidentity(p ...interface{}) Identity {
	return NewIdentity("test", p...)
}

func TestExtension(t *testing.T) {
	exists := false
	f := testapp("test-extension", testextension(""))
	f.GET("/test", func(c flotilla.Ctx) {
		p, _ := c.Call("principal")
		if _, ok := p.(*Manager); ok {
			exists = true
		}
		c.Call("serveplain", 200, []byte("success"))
	})
	PerformRequest(f, "GET", "/test")
	if !exists {
		t.Errorf("principal extension does not exist")
	}
}

func TestIdentity(t *testing.T) {
	identity := ""
	f := testapp("test-identity", testextension(""))
	f.GET("/identity", func(c flotilla.Ctx) {
		manager(c).Change(testidentity())
		c.Call("serveplain", 200, []byte("success"))
		idty, _ := c.Call("getsession", "identity_id")
		identity = idty.(string)
	})
	PerformRequest(f, "GET", "/identity")
	if identity != "test" {
		t.Errorf(fmt.Sprintf("test identity should be 'test', got %s", identity))
	}
}

func testallow(t *testing.T, test string, i Identity, expected bool, permissions ...Permission) {
	for _, permission := range permissions {
		result := permission.Allows(i)
		if result != expected {
			t.Errorf(fmt.Sprintf("%s: identity %+v not allowed for permission %+v; result was %t, expected %t", test, i, permission, result, expected))
		}
	}
}

func testrequire(t *testing.T, test string, i Identity, expected bool, permissions ...Permission) {
	for _, permission := range permissions {
		result := permission.Requires(i)
		if result != expected {
			t.Errorf(fmt.Sprintf("%s: identity %+v not required for permission %+v; result was %t, expected %t", test, i, permission, result, expected))
		}
	}
}

func needhandler(t *testing.T, test string, kind string, i Identity, expected bool, permissions ...Permission) flotilla.Manage {
	return func(c flotilla.Ctx) {
		p := manager(c)
		p.Change(i)
		switch kind {
		case "allow":
			testallow(t, test, i, expected, permissions...)
		case "require":
			testrequire(t, test, i, expected, permissions...)
		}
		c.Call("serveplain", 200, []byte("success"))
	}
}

func TestPermission(t *testing.T) {
	extension := testextension("")
	f := testapp("test-identity", extension)
	f.GET("/permission_allow", needhandler(t, "TestPermission :: allow", "allow", testidentity(n1, n2), true, p0))
	f.GET("/permission_allow_no", needhandler(t, "TestPermission :: allow_no", "allow", testidentity(n1, n2), false, p2))
	f.GET("/permission_require", needhandler(t, "TestPermission :: require", "require", testidentity(n1, n2), true, p1))
	f.GET("/permission_require_no", needhandler(t, "TestPermission :: require_no", "require", testidentity(n1, n2), false, p2))
	PerformRequest(f, "GET", "/permission_allow")
	PerformRequest(f, "GET", "/permission_allow_no")
	PerformRequest(f, "GET", "/permission_require")
	PerformRequest(f, "GET", "/permission_require_no")
}

func TestSufficient(t *testing.T) {
	//identity := testidentity(n1, n2)
	//extension := testextension("")
	//f := testapp("test-identity", extension)
	//f.GET("/nil", func(c *flotilla.Ctx) { p := manager(c); p.Change(identity); fmt.Printf("%+v\n", c.Session) })
	//f.GET("/sufficient_permission", func(c *flotilla.Ctx) {
	//	fmt.Printf("before: %+v\n", c.Session)
	//	p := manager(c)
	//	p.Change(identity)
	//	fmt.Printf("after: %+v\n", c.Session)
	//})
	//w := httptest.NewRecorder()
	//req, _ := http.NewRequest("GET", "/nil", nil)
	//f.ServeHTTP(w, req)
	//f.ServeHTTP(w, req)
	//f.ServeHTTP(w, req)
	//f.ServeHTTP(w, req)
	//req, _ := http.NewRequest("GET", "/sufficient_permission", nil)
	//f.ServeHTTP(w, req)
	//f.ServeHTTP(w, req)
	//f.ServeHTTP(w, req)
	//fmt.Printf("%+v\n", w)
}

func TestNecessary(t *testing.T) {
	//f.GET("/permission2", Necessary(permissionhandler(testidentity(n1, n2)), p2))
	//f.GET("/permission3", Necessary(permissionhandler(testidentity(n1, n2)), p3))
}
