// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: reference.proto

package reference

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	math "math"
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

type Ref struct {
	Address              []byte   `protobuf:"bytes,1,opt,name=Address,proto3" json:"Address,omitempty"`
	SecretKey            []byte   `protobuf:"bytes,2,opt,name=SecretKey,proto3" json:"SecretKey,omitempty"`
	Salt                 []byte   `protobuf:"bytes,3,opt,name=Salt,proto3" json:"Salt,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Ref) Reset()         { *m = Ref{} }
func (m *Ref) String() string { return proto.CompactTextString(m) }
func (*Ref) ProtoMessage()    {}
func (*Ref) Descriptor() ([]byte, []int) {
	return fileDescriptor_6b165e33ad62994c, []int{0}
}
func (m *Ref) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Ref.Unmarshal(m, b)
}
func (m *Ref) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Ref.Marshal(b, m, deterministic)
}
func (m *Ref) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Ref.Merge(m, src)
}
func (m *Ref) XXX_Size() int {
	return xxx_messageInfo_Ref.Size(m)
}
func (m *Ref) XXX_DiscardUnknown() {
	xxx_messageInfo_Ref.DiscardUnknown(m)
}

var xxx_messageInfo_Ref proto.InternalMessageInfo

func (m *Ref) GetAddress() []byte {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *Ref) GetSecretKey() []byte {
	if m != nil {
		return m.SecretKey
	}
	return nil
}

func (m *Ref) GetSalt() []byte {
	if m != nil {
		return m.Salt
	}
	return nil
}

func init() {
	proto.RegisterType((*Ref)(nil), "reference.Ref")
}

func init() { proto.RegisterFile("reference.proto", fileDescriptor_6b165e33ad62994c) }

var fileDescriptor_6b165e33ad62994c = []byte{
	// 141 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2f, 0x4a, 0x4d, 0x4b,
	0x2d, 0x4a, 0xcd, 0x4b, 0x4e, 0xd5, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x84, 0x0b, 0x28,
	0x05, 0x72, 0x31, 0x07, 0xa5, 0xa6, 0x09, 0x49, 0x70, 0xb1, 0x3b, 0xa6, 0xa4, 0x14, 0xa5, 0x16,
	0x17, 0x4b, 0x30, 0x2a, 0x30, 0x6a, 0xf0, 0x04, 0xc1, 0xb8, 0x42, 0x32, 0x5c, 0x9c, 0xc1, 0xa9,
	0xc9, 0x45, 0xa9, 0x25, 0xde, 0xa9, 0x95, 0x12, 0x4c, 0x60, 0x39, 0x84, 0x80, 0x90, 0x10, 0x17,
	0x4b, 0x70, 0x62, 0x4e, 0x89, 0x04, 0x33, 0x58, 0x02, 0xcc, 0x76, 0x52, 0x8d, 0x52, 0x4e, 0xcf,
	0x2c, 0xc9, 0x28, 0x4d, 0xd2, 0x4b, 0xce, 0xcf, 0xd5, 0xcf, 0xcd, 0xcf, 0x4b, 0xac, 0xd0, 0xcf,
	0xc8, 0x4f, 0x2c, 0x4a, 0xd1, 0x2f, 0x33, 0xd3, 0x87, 0xdb, 0x9c, 0xc4, 0x06, 0x76, 0x8b, 0x31,
	0x20, 0x00, 0x00, 0xff, 0xff, 0xfc, 0xab, 0x93, 0x0c, 0x9e, 0x00, 0x00, 0x00,
}
