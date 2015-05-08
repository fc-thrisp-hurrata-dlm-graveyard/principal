package principal

import "errors"

type DataStore interface {
	Get(string) Permission
	Put(string, ...interface{}) error
	Delete(string) error
}

var NotImplemented = errors.New("[Security-Principal] Not Implemented")

func DefaultDataStore() *defaultDataStore {
	return &defaultDataStore{}
}

type defaultDataStore struct{}

func (d *defaultDataStore) Get(string) Permission {
	return nil
}

func (d *defaultDataStore) Put(string, ...interface{}) error {
	return NotImplemented
}

func (d *defaultDataStore) Delete(string) error {
	return NotImplemented
}
