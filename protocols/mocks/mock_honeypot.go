// Code generated by mockery v2.44.1. DO NOT EDIT.

package mocks

import (
	context "context"

	connection "github.com/mushorg/glutton/connection"

	mock "github.com/stretchr/testify/mock"

	net "net"
)

// MockHoneypot is an autogenerated mock type for the Honeypot type
type MockHoneypot struct {
	mock.Mock
}

type MockHoneypot_Expecter struct {
	mock *mock.Mock
}

func (_m *MockHoneypot) EXPECT() *MockHoneypot_Expecter {
	return &MockHoneypot_Expecter{mock: &_m.Mock}
}

// ConnectionByFlow provides a mock function with given fields: _a0
func (_m *MockHoneypot) ConnectionByFlow(_a0 [2]uint64) connection.Metadata {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for ConnectionByFlow")
	}

	var r0 connection.Metadata
	if rf, ok := ret.Get(0).(func([2]uint64) connection.Metadata); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(connection.Metadata)
	}

	return r0
}

// MockHoneypot_ConnectionByFlow_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ConnectionByFlow'
type MockHoneypot_ConnectionByFlow_Call struct {
	*mock.Call
}

// ConnectionByFlow is a helper method to define mock.On call
//   - _a0 [2]uint64
func (_e *MockHoneypot_Expecter) ConnectionByFlow(_a0 interface{}) *MockHoneypot_ConnectionByFlow_Call {
	return &MockHoneypot_ConnectionByFlow_Call{Call: _e.mock.On("ConnectionByFlow", _a0)}
}

func (_c *MockHoneypot_ConnectionByFlow_Call) Run(run func(_a0 [2]uint64)) *MockHoneypot_ConnectionByFlow_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([2]uint64))
	})
	return _c
}

func (_c *MockHoneypot_ConnectionByFlow_Call) Return(_a0 connection.Metadata) *MockHoneypot_ConnectionByFlow_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockHoneypot_ConnectionByFlow_Call) RunAndReturn(run func([2]uint64) connection.Metadata) *MockHoneypot_ConnectionByFlow_Call {
	_c.Call.Return(run)
	return _c
}

// MetadataByConnection provides a mock function with given fields: _a0
func (_m *MockHoneypot) MetadataByConnection(_a0 net.Conn) (connection.Metadata, error) {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for MetadataByConnection")
	}

	var r0 connection.Metadata
	var r1 error
	if rf, ok := ret.Get(0).(func(net.Conn) (connection.Metadata, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func(net.Conn) connection.Metadata); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(connection.Metadata)
	}

	if rf, ok := ret.Get(1).(func(net.Conn) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockHoneypot_MetadataByConnection_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MetadataByConnection'
type MockHoneypot_MetadataByConnection_Call struct {
	*mock.Call
}

// MetadataByConnection is a helper method to define mock.On call
//   - _a0 net.Conn
func (_e *MockHoneypot_Expecter) MetadataByConnection(_a0 interface{}) *MockHoneypot_MetadataByConnection_Call {
	return &MockHoneypot_MetadataByConnection_Call{Call: _e.mock.On("MetadataByConnection", _a0)}
}

func (_c *MockHoneypot_MetadataByConnection_Call) Run(run func(_a0 net.Conn)) *MockHoneypot_MetadataByConnection_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(net.Conn))
	})
	return _c
}

func (_c *MockHoneypot_MetadataByConnection_Call) Return(_a0 connection.Metadata, _a1 error) *MockHoneypot_MetadataByConnection_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockHoneypot_MetadataByConnection_Call) RunAndReturn(run func(net.Conn) (connection.Metadata, error)) *MockHoneypot_MetadataByConnection_Call {
	_c.Call.Return(run)
	return _c
}

// ProduceTCP provides a mock function with given fields: protocol, conn, md, payload, decoded
func (_m *MockHoneypot) ProduceTCP(protocol string, conn net.Conn, md connection.Metadata, payload []byte, decoded interface{}) error {
	ret := _m.Called(protocol, conn, md, payload, decoded)

	if len(ret) == 0 {
		panic("no return value specified for ProduceTCP")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, net.Conn, connection.Metadata, []byte, interface{}) error); ok {
		r0 = rf(protocol, conn, md, payload, decoded)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockHoneypot_ProduceTCP_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ProduceTCP'
type MockHoneypot_ProduceTCP_Call struct {
	*mock.Call
}

// ProduceTCP is a helper method to define mock.On call
//   - protocol string
//   - conn net.Conn
//   - md connection.Metadata
//   - payload []byte
//   - decoded interface{}
func (_e *MockHoneypot_Expecter) ProduceTCP(protocol interface{}, conn interface{}, md interface{}, payload interface{}, decoded interface{}) *MockHoneypot_ProduceTCP_Call {
	return &MockHoneypot_ProduceTCP_Call{Call: _e.mock.On("ProduceTCP", protocol, conn, md, payload, decoded)}
}

func (_c *MockHoneypot_ProduceTCP_Call) Run(run func(protocol string, conn net.Conn, md connection.Metadata, payload []byte, decoded interface{})) *MockHoneypot_ProduceTCP_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(net.Conn), args[2].(connection.Metadata), args[3].([]byte), args[4].(interface{}))
	})
	return _c
}

func (_c *MockHoneypot_ProduceTCP_Call) Return(_a0 error) *MockHoneypot_ProduceTCP_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockHoneypot_ProduceTCP_Call) RunAndReturn(run func(string, net.Conn, connection.Metadata, []byte, interface{}) error) *MockHoneypot_ProduceTCP_Call {
	_c.Call.Return(run)
	return _c
}

// ProduceUDP provides a mock function with given fields: handler, srcAddr, dstAddr, md, payload, decoded
func (_m *MockHoneypot) ProduceUDP(handler string, srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, md connection.Metadata, payload []byte, decoded interface{}) error {
	ret := _m.Called(handler, srcAddr, dstAddr, md, payload, decoded)

	if len(ret) == 0 {
		panic("no return value specified for ProduceUDP")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, *net.UDPAddr, *net.UDPAddr, connection.Metadata, []byte, interface{}) error); ok {
		r0 = rf(handler, srcAddr, dstAddr, md, payload, decoded)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockHoneypot_ProduceUDP_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ProduceUDP'
type MockHoneypot_ProduceUDP_Call struct {
	*mock.Call
}

// ProduceUDP is a helper method to define mock.On call
//   - handler string
//   - srcAddr *net.UDPAddr
//   - dstAddr *net.UDPAddr
//   - md connection.Metadata
//   - payload []byte
//   - decoded interface{}
func (_e *MockHoneypot_Expecter) ProduceUDP(handler interface{}, srcAddr interface{}, dstAddr interface{}, md interface{}, payload interface{}, decoded interface{}) *MockHoneypot_ProduceUDP_Call {
	return &MockHoneypot_ProduceUDP_Call{Call: _e.mock.On("ProduceUDP", handler, srcAddr, dstAddr, md, payload, decoded)}
}

func (_c *MockHoneypot_ProduceUDP_Call) Run(run func(handler string, srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, md connection.Metadata, payload []byte, decoded interface{})) *MockHoneypot_ProduceUDP_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(*net.UDPAddr), args[2].(*net.UDPAddr), args[3].(connection.Metadata), args[4].([]byte), args[5].(interface{}))
	})
	return _c
}

func (_c *MockHoneypot_ProduceUDP_Call) Return(_a0 error) *MockHoneypot_ProduceUDP_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockHoneypot_ProduceUDP_Call) RunAndReturn(run func(string, *net.UDPAddr, *net.UDPAddr, connection.Metadata, []byte, interface{}) error) *MockHoneypot_ProduceUDP_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateConnectionTimeout provides a mock function with given fields: ctx, conn
func (_m *MockHoneypot) UpdateConnectionTimeout(ctx context.Context, conn net.Conn) error {
	ret := _m.Called(ctx, conn)

	if len(ret) == 0 {
		panic("no return value specified for UpdateConnectionTimeout")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, net.Conn) error); ok {
		r0 = rf(ctx, conn)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockHoneypot_UpdateConnectionTimeout_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateConnectionTimeout'
type MockHoneypot_UpdateConnectionTimeout_Call struct {
	*mock.Call
}

// UpdateConnectionTimeout is a helper method to define mock.On call
//   - ctx context.Context
//   - conn net.Conn
func (_e *MockHoneypot_Expecter) UpdateConnectionTimeout(ctx interface{}, conn interface{}) *MockHoneypot_UpdateConnectionTimeout_Call {
	return &MockHoneypot_UpdateConnectionTimeout_Call{Call: _e.mock.On("UpdateConnectionTimeout", ctx, conn)}
}

func (_c *MockHoneypot_UpdateConnectionTimeout_Call) Run(run func(ctx context.Context, conn net.Conn)) *MockHoneypot_UpdateConnectionTimeout_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(net.Conn))
	})
	return _c
}

func (_c *MockHoneypot_UpdateConnectionTimeout_Call) Return(_a0 error) *MockHoneypot_UpdateConnectionTimeout_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockHoneypot_UpdateConnectionTimeout_Call) RunAndReturn(run func(context.Context, net.Conn) error) *MockHoneypot_UpdateConnectionTimeout_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockHoneypot creates a new instance of MockHoneypot. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockHoneypot(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockHoneypot {
	mock := &MockHoneypot{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
