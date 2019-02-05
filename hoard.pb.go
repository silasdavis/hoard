// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: hoard.proto

package hoard // import "github.com/monax/hoard"

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/gogoproto"
import grant "github.com/monax/hoard/grant"
import reference "github.com/monax/hoard/reference"
import storage "github.com/monax/hoard/storage"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type GrantAndGrantSpec struct {
	Grant *grant.Grant `protobuf:"bytes,1,opt,name=Grant" json:"Grant,omitempty"`
	// The type of grant to output
	GrantSpec            *grant.Spec `protobuf:"bytes,2,opt,name=GrantSpec" json:"GrantSpec,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *GrantAndGrantSpec) Reset()         { *m = GrantAndGrantSpec{} }
func (m *GrantAndGrantSpec) String() string { return proto.CompactTextString(m) }
func (*GrantAndGrantSpec) ProtoMessage()    {}
func (*GrantAndGrantSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_hoard_108c501ca1351cb2, []int{0}
}
func (m *GrantAndGrantSpec) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GrantAndGrantSpec.Unmarshal(m, b)
}
func (m *GrantAndGrantSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GrantAndGrantSpec.Marshal(b, m, deterministic)
}
func (dst *GrantAndGrantSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GrantAndGrantSpec.Merge(dst, src)
}
func (m *GrantAndGrantSpec) XXX_Size() int {
	return xxx_messageInfo_GrantAndGrantSpec.Size(m)
}
func (m *GrantAndGrantSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_GrantAndGrantSpec.DiscardUnknown(m)
}

var xxx_messageInfo_GrantAndGrantSpec proto.InternalMessageInfo

func (m *GrantAndGrantSpec) GetGrant() *grant.Grant {
	if m != nil {
		return m.Grant
	}
	return nil
}

func (m *GrantAndGrantSpec) GetGrantSpec() *grant.Spec {
	if m != nil {
		return m.GrantSpec
	}
	return nil
}

type PlaintextAndGrantSpec struct {
	Plaintext *Plaintext `protobuf:"bytes,1,opt,name=Plaintext" json:"Plaintext,omitempty"`
	// The type of grant to output
	GrantSpec            *grant.Spec `protobuf:"bytes,2,opt,name=GrantSpec" json:"GrantSpec,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *PlaintextAndGrantSpec) Reset()         { *m = PlaintextAndGrantSpec{} }
func (m *PlaintextAndGrantSpec) String() string { return proto.CompactTextString(m) }
func (*PlaintextAndGrantSpec) ProtoMessage()    {}
func (*PlaintextAndGrantSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_hoard_108c501ca1351cb2, []int{1}
}
func (m *PlaintextAndGrantSpec) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PlaintextAndGrantSpec.Unmarshal(m, b)
}
func (m *PlaintextAndGrantSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PlaintextAndGrantSpec.Marshal(b, m, deterministic)
}
func (dst *PlaintextAndGrantSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PlaintextAndGrantSpec.Merge(dst, src)
}
func (m *PlaintextAndGrantSpec) XXX_Size() int {
	return xxx_messageInfo_PlaintextAndGrantSpec.Size(m)
}
func (m *PlaintextAndGrantSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_PlaintextAndGrantSpec.DiscardUnknown(m)
}

var xxx_messageInfo_PlaintextAndGrantSpec proto.InternalMessageInfo

func (m *PlaintextAndGrantSpec) GetPlaintext() *Plaintext {
	if m != nil {
		return m.Plaintext
	}
	return nil
}

func (m *PlaintextAndGrantSpec) GetGrantSpec() *grant.Spec {
	if m != nil {
		return m.GrantSpec
	}
	return nil
}

type ReferenceAndGrantSpec struct {
	Reference *reference.Ref `protobuf:"bytes,1,opt,name=Reference" json:"Reference,omitempty"`
	// The type of grant to output
	GrantSpec            *grant.Spec `protobuf:"bytes,2,opt,name=GrantSpec" json:"GrantSpec,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *ReferenceAndGrantSpec) Reset()         { *m = ReferenceAndGrantSpec{} }
func (m *ReferenceAndGrantSpec) String() string { return proto.CompactTextString(m) }
func (*ReferenceAndGrantSpec) ProtoMessage()    {}
func (*ReferenceAndGrantSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_hoard_108c501ca1351cb2, []int{2}
}
func (m *ReferenceAndGrantSpec) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ReferenceAndGrantSpec.Unmarshal(m, b)
}
func (m *ReferenceAndGrantSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ReferenceAndGrantSpec.Marshal(b, m, deterministic)
}
func (dst *ReferenceAndGrantSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReferenceAndGrantSpec.Merge(dst, src)
}
func (m *ReferenceAndGrantSpec) XXX_Size() int {
	return xxx_messageInfo_ReferenceAndGrantSpec.Size(m)
}
func (m *ReferenceAndGrantSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_ReferenceAndGrantSpec.DiscardUnknown(m)
}

var xxx_messageInfo_ReferenceAndGrantSpec proto.InternalMessageInfo

func (m *ReferenceAndGrantSpec) GetReference() *reference.Ref {
	if m != nil {
		return m.Reference
	}
	return nil
}

func (m *ReferenceAndGrantSpec) GetGrantSpec() *grant.Spec {
	if m != nil {
		return m.GrantSpec
	}
	return nil
}

type Plaintext struct {
	Data                 []byte   `protobuf:"bytes,1,opt,name=Data,proto3" json:"Data,omitempty"`
	Salt                 []byte   `protobuf:"bytes,2,opt,name=Salt,proto3" json:"Salt,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Plaintext) Reset()         { *m = Plaintext{} }
func (m *Plaintext) String() string { return proto.CompactTextString(m) }
func (*Plaintext) ProtoMessage()    {}
func (*Plaintext) Descriptor() ([]byte, []int) {
	return fileDescriptor_hoard_108c501ca1351cb2, []int{3}
}
func (m *Plaintext) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Plaintext.Unmarshal(m, b)
}
func (m *Plaintext) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Plaintext.Marshal(b, m, deterministic)
}
func (dst *Plaintext) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Plaintext.Merge(dst, src)
}
func (m *Plaintext) XXX_Size() int {
	return xxx_messageInfo_Plaintext.Size(m)
}
func (m *Plaintext) XXX_DiscardUnknown() {
	xxx_messageInfo_Plaintext.DiscardUnknown(m)
}

var xxx_messageInfo_Plaintext proto.InternalMessageInfo

func (m *Plaintext) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *Plaintext) GetSalt() []byte {
	if m != nil {
		return m.Salt
	}
	return nil
}

type Ciphertext struct {
	EncryptedData        []byte   `protobuf:"bytes,1,opt,name=EncryptedData,proto3" json:"EncryptedData,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Ciphertext) Reset()         { *m = Ciphertext{} }
func (m *Ciphertext) String() string { return proto.CompactTextString(m) }
func (*Ciphertext) ProtoMessage()    {}
func (*Ciphertext) Descriptor() ([]byte, []int) {
	return fileDescriptor_hoard_108c501ca1351cb2, []int{4}
}
func (m *Ciphertext) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Ciphertext.Unmarshal(m, b)
}
func (m *Ciphertext) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Ciphertext.Marshal(b, m, deterministic)
}
func (dst *Ciphertext) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Ciphertext.Merge(dst, src)
}
func (m *Ciphertext) XXX_Size() int {
	return xxx_messageInfo_Ciphertext.Size(m)
}
func (m *Ciphertext) XXX_DiscardUnknown() {
	xxx_messageInfo_Ciphertext.DiscardUnknown(m)
}

var xxx_messageInfo_Ciphertext proto.InternalMessageInfo

func (m *Ciphertext) GetEncryptedData() []byte {
	if m != nil {
		return m.EncryptedData
	}
	return nil
}

type ReferenceAndCiphertext struct {
	Reference            *reference.Ref `protobuf:"bytes,1,opt,name=Reference" json:"Reference,omitempty"`
	Ciphertext           *Ciphertext    `protobuf:"bytes,2,opt,name=Ciphertext" json:"Ciphertext,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *ReferenceAndCiphertext) Reset()         { *m = ReferenceAndCiphertext{} }
func (m *ReferenceAndCiphertext) String() string { return proto.CompactTextString(m) }
func (*ReferenceAndCiphertext) ProtoMessage()    {}
func (*ReferenceAndCiphertext) Descriptor() ([]byte, []int) {
	return fileDescriptor_hoard_108c501ca1351cb2, []int{5}
}
func (m *ReferenceAndCiphertext) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ReferenceAndCiphertext.Unmarshal(m, b)
}
func (m *ReferenceAndCiphertext) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ReferenceAndCiphertext.Marshal(b, m, deterministic)
}
func (dst *ReferenceAndCiphertext) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReferenceAndCiphertext.Merge(dst, src)
}
func (m *ReferenceAndCiphertext) XXX_Size() int {
	return xxx_messageInfo_ReferenceAndCiphertext.Size(m)
}
func (m *ReferenceAndCiphertext) XXX_DiscardUnknown() {
	xxx_messageInfo_ReferenceAndCiphertext.DiscardUnknown(m)
}

var xxx_messageInfo_ReferenceAndCiphertext proto.InternalMessageInfo

func (m *ReferenceAndCiphertext) GetReference() *reference.Ref {
	if m != nil {
		return m.Reference
	}
	return nil
}

func (m *ReferenceAndCiphertext) GetCiphertext() *Ciphertext {
	if m != nil {
		return m.Ciphertext
	}
	return nil
}

type Address struct {
	Address              []byte   `protobuf:"bytes,1,opt,name=Address,proto3" json:"Address,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Address) Reset()         { *m = Address{} }
func (m *Address) String() string { return proto.CompactTextString(m) }
func (*Address) ProtoMessage()    {}
func (*Address) Descriptor() ([]byte, []int) {
	return fileDescriptor_hoard_108c501ca1351cb2, []int{6}
}
func (m *Address) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Address.Unmarshal(m, b)
}
func (m *Address) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Address.Marshal(b, m, deterministic)
}
func (dst *Address) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Address.Merge(dst, src)
}
func (m *Address) XXX_Size() int {
	return xxx_messageInfo_Address.Size(m)
}
func (m *Address) XXX_DiscardUnknown() {
	xxx_messageInfo_Address.DiscardUnknown(m)
}

var xxx_messageInfo_Address proto.InternalMessageInfo

func (m *Address) GetAddress() []byte {
	if m != nil {
		return m.Address
	}
	return nil
}

func init() {
	proto.RegisterType((*GrantAndGrantSpec)(nil), "hoard.GrantAndGrantSpec")
	proto.RegisterType((*PlaintextAndGrantSpec)(nil), "hoard.PlaintextAndGrantSpec")
	proto.RegisterType((*ReferenceAndGrantSpec)(nil), "hoard.ReferenceAndGrantSpec")
	proto.RegisterType((*Plaintext)(nil), "hoard.Plaintext")
	proto.RegisterType((*Ciphertext)(nil), "hoard.Ciphertext")
	proto.RegisterType((*ReferenceAndCiphertext)(nil), "hoard.ReferenceAndCiphertext")
	proto.RegisterType((*Address)(nil), "hoard.Address")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// GrantClient is the client API for Grant service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type GrantClient interface {
	// Seal a Reference to create a Grant
	Seal(ctx context.Context, in *ReferenceAndGrantSpec, opts ...grpc.CallOption) (*grant.Grant, error)
	// Unseal a Grant to recover the Reference
	Unseal(ctx context.Context, in *grant.Grant, opts ...grpc.CallOption) (*reference.Ref, error)
	// Convert one grant to another grant to re-share with another party or just
	// to change grant type
	Reseal(ctx context.Context, in *GrantAndGrantSpec, opts ...grpc.CallOption) (*grant.Grant, error)
	// Put a Plaintext and returned the sealed Reference as a Grant
	PutSeal(ctx context.Context, in *PlaintextAndGrantSpec, opts ...grpc.CallOption) (*grant.Grant, error)
	// Unseal a Grant and follow the Reference to return a Plaintext
	UnsealGet(ctx context.Context, in *grant.Grant, opts ...grpc.CallOption) (*Plaintext, error)
}

type grantClient struct {
	cc *grpc.ClientConn
}

func NewGrantClient(cc *grpc.ClientConn) GrantClient {
	return &grantClient{cc}
}

func (c *grantClient) Seal(ctx context.Context, in *ReferenceAndGrantSpec, opts ...grpc.CallOption) (*grant.Grant, error) {
	out := new(grant.Grant)
	err := c.cc.Invoke(ctx, "/hoard.Grant/Seal", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *grantClient) Unseal(ctx context.Context, in *grant.Grant, opts ...grpc.CallOption) (*reference.Ref, error) {
	out := new(reference.Ref)
	err := c.cc.Invoke(ctx, "/hoard.Grant/Unseal", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *grantClient) Reseal(ctx context.Context, in *GrantAndGrantSpec, opts ...grpc.CallOption) (*grant.Grant, error) {
	out := new(grant.Grant)
	err := c.cc.Invoke(ctx, "/hoard.Grant/Reseal", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *grantClient) PutSeal(ctx context.Context, in *PlaintextAndGrantSpec, opts ...grpc.CallOption) (*grant.Grant, error) {
	out := new(grant.Grant)
	err := c.cc.Invoke(ctx, "/hoard.Grant/PutSeal", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *grantClient) UnsealGet(ctx context.Context, in *grant.Grant, opts ...grpc.CallOption) (*Plaintext, error) {
	out := new(Plaintext)
	err := c.cc.Invoke(ctx, "/hoard.Grant/UnsealGet", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GrantServer is the server API for Grant service.
type GrantServer interface {
	// Seal a Reference to create a Grant
	Seal(context.Context, *ReferenceAndGrantSpec) (*grant.Grant, error)
	// Unseal a Grant to recover the Reference
	Unseal(context.Context, *grant.Grant) (*reference.Ref, error)
	// Convert one grant to another grant to re-share with another party or just
	// to change grant type
	Reseal(context.Context, *GrantAndGrantSpec) (*grant.Grant, error)
	// Put a Plaintext and returned the sealed Reference as a Grant
	PutSeal(context.Context, *PlaintextAndGrantSpec) (*grant.Grant, error)
	// Unseal a Grant and follow the Reference to return a Plaintext
	UnsealGet(context.Context, *grant.Grant) (*Plaintext, error)
}

func RegisterGrantServer(s *grpc.Server, srv GrantServer) {
	s.RegisterService(&_Grant_serviceDesc, srv)
}

func _Grant_Seal_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReferenceAndGrantSpec)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GrantServer).Seal(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hoard.Grant/Seal",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GrantServer).Seal(ctx, req.(*ReferenceAndGrantSpec))
	}
	return interceptor(ctx, in, info, handler)
}

func _Grant_Unseal_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(grant.Grant)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GrantServer).Unseal(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hoard.Grant/Unseal",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GrantServer).Unseal(ctx, req.(*grant.Grant))
	}
	return interceptor(ctx, in, info, handler)
}

func _Grant_Reseal_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GrantAndGrantSpec)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GrantServer).Reseal(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hoard.Grant/Reseal",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GrantServer).Reseal(ctx, req.(*GrantAndGrantSpec))
	}
	return interceptor(ctx, in, info, handler)
}

func _Grant_PutSeal_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PlaintextAndGrantSpec)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GrantServer).PutSeal(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hoard.Grant/PutSeal",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GrantServer).PutSeal(ctx, req.(*PlaintextAndGrantSpec))
	}
	return interceptor(ctx, in, info, handler)
}

func _Grant_UnsealGet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(grant.Grant)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GrantServer).UnsealGet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hoard.Grant/UnsealGet",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GrantServer).UnsealGet(ctx, req.(*grant.Grant))
	}
	return interceptor(ctx, in, info, handler)
}

var _Grant_serviceDesc = grpc.ServiceDesc{
	ServiceName: "hoard.Grant",
	HandlerType: (*GrantServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Seal",
			Handler:    _Grant_Seal_Handler,
		},
		{
			MethodName: "Unseal",
			Handler:    _Grant_Unseal_Handler,
		},
		{
			MethodName: "Reseal",
			Handler:    _Grant_Reseal_Handler,
		},
		{
			MethodName: "PutSeal",
			Handler:    _Grant_PutSeal_Handler,
		},
		{
			MethodName: "UnsealGet",
			Handler:    _Grant_UnsealGet_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "hoard.proto",
}

// CleartextClient is the client API for Cleartext service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type CleartextClient interface {
	// Push some plaintext data into storage and get its deterministically
	// generated secret reference.
	Put(ctx context.Context, in *Plaintext, opts ...grpc.CallOption) (*reference.Ref, error)
	// Provide a secret reference to an encrypted blob and get the plaintext
	// data back.
	Get(ctx context.Context, in *reference.Ref, opts ...grpc.CallOption) (*Plaintext, error)
}

type cleartextClient struct {
	cc *grpc.ClientConn
}

func NewCleartextClient(cc *grpc.ClientConn) CleartextClient {
	return &cleartextClient{cc}
}

func (c *cleartextClient) Put(ctx context.Context, in *Plaintext, opts ...grpc.CallOption) (*reference.Ref, error) {
	out := new(reference.Ref)
	err := c.cc.Invoke(ctx, "/hoard.Cleartext/Put", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cleartextClient) Get(ctx context.Context, in *reference.Ref, opts ...grpc.CallOption) (*Plaintext, error) {
	out := new(Plaintext)
	err := c.cc.Invoke(ctx, "/hoard.Cleartext/Get", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CleartextServer is the server API for Cleartext service.
type CleartextServer interface {
	// Push some plaintext data into storage and get its deterministically
	// generated secret reference.
	Put(context.Context, *Plaintext) (*reference.Ref, error)
	// Provide a secret reference to an encrypted blob and get the plaintext
	// data back.
	Get(context.Context, *reference.Ref) (*Plaintext, error)
}

func RegisterCleartextServer(s *grpc.Server, srv CleartextServer) {
	s.RegisterService(&_Cleartext_serviceDesc, srv)
}

func _Cleartext_Put_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Plaintext)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CleartextServer).Put(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hoard.Cleartext/Put",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CleartextServer).Put(ctx, req.(*Plaintext))
	}
	return interceptor(ctx, in, info, handler)
}

func _Cleartext_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(reference.Ref)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CleartextServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hoard.Cleartext/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CleartextServer).Get(ctx, req.(*reference.Ref))
	}
	return interceptor(ctx, in, info, handler)
}

var _Cleartext_serviceDesc = grpc.ServiceDesc{
	ServiceName: "hoard.Cleartext",
	HandlerType: (*CleartextServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Put",
			Handler:    _Cleartext_Put_Handler,
		},
		{
			MethodName: "Get",
			Handler:    _Cleartext_Get_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "hoard.proto",
}

// EncryptionClient is the client API for Encryption service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type EncryptionClient interface {
	// Encrypt some data and get its deterministically generated
	// secret reference including its address without storing the data.
	Encrypt(ctx context.Context, in *Plaintext, opts ...grpc.CallOption) (*ReferenceAndCiphertext, error)
	// Decrypt the provided data by supplying it alongside its secret
	// reference. The address is not used for decryption and may be omitted.
	Decrypt(ctx context.Context, in *ReferenceAndCiphertext, opts ...grpc.CallOption) (*Plaintext, error)
}

type encryptionClient struct {
	cc *grpc.ClientConn
}

func NewEncryptionClient(cc *grpc.ClientConn) EncryptionClient {
	return &encryptionClient{cc}
}

func (c *encryptionClient) Encrypt(ctx context.Context, in *Plaintext, opts ...grpc.CallOption) (*ReferenceAndCiphertext, error) {
	out := new(ReferenceAndCiphertext)
	err := c.cc.Invoke(ctx, "/hoard.Encryption/Encrypt", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *encryptionClient) Decrypt(ctx context.Context, in *ReferenceAndCiphertext, opts ...grpc.CallOption) (*Plaintext, error) {
	out := new(Plaintext)
	err := c.cc.Invoke(ctx, "/hoard.Encryption/Decrypt", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EncryptionServer is the server API for Encryption service.
type EncryptionServer interface {
	// Encrypt some data and get its deterministically generated
	// secret reference including its address without storing the data.
	Encrypt(context.Context, *Plaintext) (*ReferenceAndCiphertext, error)
	// Decrypt the provided data by supplying it alongside its secret
	// reference. The address is not used for decryption and may be omitted.
	Decrypt(context.Context, *ReferenceAndCiphertext) (*Plaintext, error)
}

func RegisterEncryptionServer(s *grpc.Server, srv EncryptionServer) {
	s.RegisterService(&_Encryption_serviceDesc, srv)
}

func _Encryption_Encrypt_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Plaintext)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).Encrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hoard.Encryption/Encrypt",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).Encrypt(ctx, req.(*Plaintext))
	}
	return interceptor(ctx, in, info, handler)
}

func _Encryption_Decrypt_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReferenceAndCiphertext)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EncryptionServer).Decrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hoard.Encryption/Decrypt",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EncryptionServer).Decrypt(ctx, req.(*ReferenceAndCiphertext))
	}
	return interceptor(ctx, in, info, handler)
}

var _Encryption_serviceDesc = grpc.ServiceDesc{
	ServiceName: "hoard.Encryption",
	HandlerType: (*EncryptionServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Encrypt",
			Handler:    _Encryption_Encrypt_Handler,
		},
		{
			MethodName: "Decrypt",
			Handler:    _Encryption_Decrypt_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "hoard.proto",
}

// StorageClient is the client API for Storage service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type StorageClient interface {
	// Insert the (presumably) encrypted data provided and get the its address.
	Push(ctx context.Context, in *Ciphertext, opts ...grpc.CallOption) (*Address, error)
	// Retrieve the (presumably) encrypted data stored at address.
	Pull(ctx context.Context, in *Address, opts ...grpc.CallOption) (*Ciphertext, error)
	// Get some information about the encrypted blob stored at an address,
	// including whether it exists.
	Stat(ctx context.Context, in *Address, opts ...grpc.CallOption) (*storage.StatInfo, error)
}

type storageClient struct {
	cc *grpc.ClientConn
}

func NewStorageClient(cc *grpc.ClientConn) StorageClient {
	return &storageClient{cc}
}

func (c *storageClient) Push(ctx context.Context, in *Ciphertext, opts ...grpc.CallOption) (*Address, error) {
	out := new(Address)
	err := c.cc.Invoke(ctx, "/hoard.Storage/Push", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageClient) Pull(ctx context.Context, in *Address, opts ...grpc.CallOption) (*Ciphertext, error) {
	out := new(Ciphertext)
	err := c.cc.Invoke(ctx, "/hoard.Storage/Pull", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageClient) Stat(ctx context.Context, in *Address, opts ...grpc.CallOption) (*storage.StatInfo, error) {
	out := new(storage.StatInfo)
	err := c.cc.Invoke(ctx, "/hoard.Storage/Stat", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// StorageServer is the server API for Storage service.
type StorageServer interface {
	// Insert the (presumably) encrypted data provided and get the its address.
	Push(context.Context, *Ciphertext) (*Address, error)
	// Retrieve the (presumably) encrypted data stored at address.
	Pull(context.Context, *Address) (*Ciphertext, error)
	// Get some information about the encrypted blob stored at an address,
	// including whether it exists.
	Stat(context.Context, *Address) (*storage.StatInfo, error)
}

func RegisterStorageServer(s *grpc.Server, srv StorageServer) {
	s.RegisterService(&_Storage_serviceDesc, srv)
}

func _Storage_Push_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Ciphertext)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServer).Push(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hoard.Storage/Push",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServer).Push(ctx, req.(*Ciphertext))
	}
	return interceptor(ctx, in, info, handler)
}

func _Storage_Pull_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Address)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServer).Pull(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hoard.Storage/Pull",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServer).Pull(ctx, req.(*Address))
	}
	return interceptor(ctx, in, info, handler)
}

func _Storage_Stat_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Address)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServer).Stat(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/hoard.Storage/Stat",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServer).Stat(ctx, req.(*Address))
	}
	return interceptor(ctx, in, info, handler)
}

var _Storage_serviceDesc = grpc.ServiceDesc{
	ServiceName: "hoard.Storage",
	HandlerType: (*StorageServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Push",
			Handler:    _Storage_Push_Handler,
		},
		{
			MethodName: "Pull",
			Handler:    _Storage_Pull_Handler,
		},
		{
			MethodName: "Stat",
			Handler:    _Storage_Stat_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "hoard.proto",
}

func (m *GrantAndGrantSpec) ProtoSize() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Grant != nil {
		l = m.Grant.ProtoSize()
		n += 1 + l + sovHoard(uint64(l))
	}
	if m.GrantSpec != nil {
		l = m.GrantSpec.ProtoSize()
		n += 1 + l + sovHoard(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *PlaintextAndGrantSpec) ProtoSize() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Plaintext != nil {
		l = m.Plaintext.ProtoSize()
		n += 1 + l + sovHoard(uint64(l))
	}
	if m.GrantSpec != nil {
		l = m.GrantSpec.ProtoSize()
		n += 1 + l + sovHoard(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *ReferenceAndGrantSpec) ProtoSize() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Reference != nil {
		l = m.Reference.ProtoSize()
		n += 1 + l + sovHoard(uint64(l))
	}
	if m.GrantSpec != nil {
		l = m.GrantSpec.ProtoSize()
		n += 1 + l + sovHoard(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *Plaintext) ProtoSize() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Data)
	if l > 0 {
		n += 1 + l + sovHoard(uint64(l))
	}
	l = len(m.Salt)
	if l > 0 {
		n += 1 + l + sovHoard(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *Ciphertext) ProtoSize() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.EncryptedData)
	if l > 0 {
		n += 1 + l + sovHoard(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *ReferenceAndCiphertext) ProtoSize() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Reference != nil {
		l = m.Reference.ProtoSize()
		n += 1 + l + sovHoard(uint64(l))
	}
	if m.Ciphertext != nil {
		l = m.Ciphertext.ProtoSize()
		n += 1 + l + sovHoard(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *Address) ProtoSize() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Address)
	if l > 0 {
		n += 1 + l + sovHoard(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovHoard(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozHoard(x uint64) (n int) {
	return sovHoard(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}

func init() { proto.RegisterFile("hoard.proto", fileDescriptor_hoard_108c501ca1351cb2) }

var fileDescriptor_hoard_108c501ca1351cb2 = []byte{
	// 511 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x54, 0x4d, 0x6f, 0xd3, 0x40,
	0x10, 0x95, 0x69, 0x9a, 0xc8, 0x93, 0xb4, 0xd0, 0x95, 0x5a, 0x45, 0x56, 0x41, 0xc8, 0x20, 0x4a,
	0x05, 0x38, 0xe0, 0x8a, 0x4b, 0x6f, 0xa5, 0x45, 0x15, 0xb7, 0x68, 0x2d, 0x2e, 0x48, 0x1c, 0x36,
	0xf1, 0xc6, 0x89, 0xe4, 0xee, 0x5a, 0xeb, 0xb5, 0xd4, 0xde, 0x39, 0xf1, 0x2b, 0xf8, 0x6f, 0xfc,
	0x0a, 0x6e, 0xc8, 0xe3, 0x8d, 0xbf, 0x55, 0x29, 0x27, 0xef, 0xbc, 0x79, 0x6f, 0x66, 0x67, 0xfc,
	0xb4, 0x30, 0x5e, 0x4b, 0xa6, 0x42, 0x2f, 0x51, 0x52, 0x4b, 0xb2, 0x8f, 0x81, 0xf3, 0x21, 0xda,
	0xe8, 0x75, 0xb6, 0xf0, 0x96, 0xf2, 0x6e, 0x16, 0xc9, 0x48, 0xce, 0x30, 0xbb, 0xc8, 0x56, 0x18,
	0x61, 0x80, 0xa7, 0x42, 0xe5, 0x3c, 0x55, 0x7c, 0xc5, 0x15, 0x17, 0x4b, 0x6e, 0x80, 0x71, 0xa4,
	0x98, 0xd0, 0x26, 0x38, 0x48, 0xb5, 0x54, 0x2c, 0x32, 0x39, 0x77, 0x01, 0x47, 0xb7, 0x79, 0xf6,
	0x4a, 0x84, 0xf8, 0x0d, 0x12, 0xbe, 0x24, 0x2e, 0xec, 0x63, 0x30, 0xb5, 0x5e, 0x5a, 0x6f, 0xc7,
	0xfe, 0xc4, 0x2b, 0x0a, 0x20, 0x46, 0x8b, 0x14, 0x39, 0x07, 0xbb, 0x14, 0x4c, 0x9f, 0x20, 0x6f,
	0x6c, 0x78, 0x39, 0x44, 0xab, 0xac, 0xab, 0xe0, 0x78, 0x1e, 0xb3, 0x8d, 0xd0, 0xfc, 0xbe, 0xd9,
	0xc7, 0x03, 0xbb, 0x4c, 0x98, 0x5e, 0xcf, 0xbc, 0x62, 0x01, 0x25, 0x4e, 0x2b, 0xca, 0x2e, 0x3d,
	0x13, 0x38, 0xa6, 0xdb, 0x35, 0x34, 0x7a, 0xbe, 0x07, 0xbb, 0x4c, 0x98, 0x9e, 0x87, 0x5e, 0xb5,
	0x31, 0xca, 0x57, 0xb4, 0x22, 0xec, 0xd2, 0xf1, 0xa2, 0x36, 0x0c, 0x21, 0x30, 0xb8, 0x61, 0x9a,
	0x61, 0x83, 0x09, 0xc5, 0x73, 0x8e, 0x05, 0x2c, 0xd6, 0x58, 0x66, 0x42, 0xf1, 0xec, 0xfa, 0x00,
	0xd7, 0x9b, 0x64, 0xcd, 0x15, 0xaa, 0x5e, 0xc3, 0xc1, 0x57, 0xb1, 0x54, 0x0f, 0x89, 0xe6, 0x61,
	0x4d, 0xde, 0x04, 0xdd, 0x07, 0x38, 0xa9, 0x8f, 0x56, 0xd3, 0xef, 0x36, 0xdb, 0xa7, 0x7a, 0x6f,
	0x33, 0xdc, 0x91, 0x59, 0x7f, 0x95, 0xa0, 0x35, 0x92, 0xfb, 0x0a, 0x46, 0x57, 0x61, 0xa8, 0x78,
	0x9a, 0x92, 0x69, 0x79, 0x34, 0xb7, 0xdc, 0x86, 0xfe, 0x3f, 0xcb, 0xd8, 0x87, 0xf8, 0x30, 0x08,
	0x38, 0x8b, 0xc9, 0xa9, 0xa9, 0xda, 0xfb, 0x47, 0x9c, 0x86, 0xbd, 0xc8, 0x1b, 0x18, 0x7e, 0x17,
	0x69, 0xae, 0x6a, 0xe0, 0x4e, 0x6b, 0x10, 0xf2, 0x11, 0x86, 0x94, 0x23, 0x6f, 0x6a, 0xaa, 0x77,
	0x7c, 0xdc, 0xaa, 0xfc, 0x19, 0x46, 0xf3, 0x4c, 0x37, 0x2e, 0xd4, 0x6b, 0xcb, 0x96, 0xec, 0x1d,
	0xd8, 0xc5, 0x85, 0x6e, 0xb9, 0x6e, 0xdd, 0xa9, 0x63, 0x56, 0xff, 0x27, 0xd8, 0xd7, 0x31, 0x67,
	0xc5, 0xef, 0x38, 0x83, 0xbd, 0x79, 0xa6, 0x49, 0x87, 0xd5, 0x99, 0xe5, 0x0c, 0xf6, 0xf2, 0xe2,
	0x2d, 0xb8, 0xa7, 0xfc, 0x2f, 0x0b, 0xc0, 0x98, 0x61, 0x23, 0x05, 0xb9, 0x84, 0x91, 0x89, 0x7a,
	0x9a, 0x3c, 0xef, 0x59, 0x7a, 0xcd, 0x2b, 0x97, 0x30, 0xba, 0xe1, 0x85, 0xf6, 0x71, 0x66, 0xcf,
	0x35, 0x7e, 0x5b, 0x30, 0x0a, 0x8a, 0x67, 0x84, 0x9c, 0xc3, 0x60, 0x9e, 0xa5, 0x6b, 0xd2, 0x75,
	0x8e, 0x73, 0x68, 0xa0, 0xad, 0x65, 0x90, 0x1a, 0xc7, 0xa4, 0x85, 0x3b, 0x5d, 0x69, 0x4e, 0x0d,
	0x34, 0xd3, 0x3d, 0xd4, 0xed, 0xf3, 0x95, 0xa7, 0xbf, 0x89, 0x95, 0xfc, 0x72, 0xfa, 0xe7, 0xef,
	0x0b, 0xeb, 0xc7, 0x49, 0xed, 0x8d, 0xbc, 0x93, 0x82, 0xdd, 0xcf, 0x50, 0xb8, 0x18, 0xe2, 0x33,
	0x77, 0xf1, 0x3f, 0x00, 0x00, 0xff, 0xff, 0x3f, 0xed, 0x18, 0xd8, 0x58, 0x05, 0x00, 0x00,
}
