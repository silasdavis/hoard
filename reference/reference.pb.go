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
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type Ref_RefType int32

const (
	// Default raw reference containing a body chunk
	Ref_BODY Ref_RefType = 0
	// Ref to a header chunk
	Ref_HEADER Ref_RefType = 1
	// A ref to a Plaintext of refs
	Ref_LINK Ref_RefType = 2
)

var Ref_RefType_name = map[int32]string{
	0: "BODY",
	1: "HEADER",
	2: "LINK",
}

var Ref_RefType_value = map[string]int32{
	"BODY":   0,
	"HEADER": 1,
	"LINK":   2,
}

func (x Ref_RefType) String() string {
	return proto.EnumName(Ref_RefType_name, int32(x))
}

func (Ref_RefType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_6b165e33ad62994c, []int{0, 0}
}

type Ref struct {
	Address   []byte `protobuf:"bytes,1,opt,name=Address,proto3" json:"Address,omitempty"`
	SecretKey []byte `protobuf:"bytes,2,opt,name=SecretKey,proto3" json:"SecretKey,omitempty"`
	Salt      []byte `protobuf:"bytes,3,opt,name=Salt,proto3" json:"Salt,omitempty"`
	// Type indicates whether to undergo further decoding
	Type Ref_RefType `protobuf:"varint,4,opt,name=Type,proto3,enum=reference.Ref_RefType" json:"Type,omitempty"`
	// The size in bytes of the plaintext data
	Size_                int64    `protobuf:"varint,5,opt,name=Size,proto3" json:"Size,omitempty"`
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

func (m *Ref) GetType() Ref_RefType {
	if m != nil {
		return m.Type
	}
	return Ref_BODY
}

func (m *Ref) GetSize_() int64 {
	if m != nil {
		return m.Size_
	}
	return 0
}

func init() {
	proto.RegisterEnum("reference.Ref_RefType", Ref_RefType_name, Ref_RefType_value)
	proto.RegisterType((*Ref)(nil), "reference.Ref")
}

func init() { proto.RegisterFile("reference.proto", fileDescriptor_6b165e33ad62994c) }

var fileDescriptor_6b165e33ad62994c = []byte{
	// 221 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2f, 0x4a, 0x4d, 0x4b,
	0x2d, 0x4a, 0xcd, 0x4b, 0x4e, 0xd5, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x84, 0x0b, 0x28,
	0xed, 0x61, 0xe4, 0x62, 0x0e, 0x4a, 0x4d, 0x13, 0x92, 0xe0, 0x62, 0x77, 0x4c, 0x49, 0x29, 0x4a,
	0x2d, 0x2e, 0x96, 0x60, 0x54, 0x60, 0xd4, 0xe0, 0x09, 0x82, 0x71, 0x85, 0x64, 0xb8, 0x38, 0x83,
	0x53, 0x93, 0x8b, 0x52, 0x4b, 0xbc, 0x53, 0x2b, 0x25, 0x98, 0xc0, 0x72, 0x08, 0x01, 0x21, 0x21,
	0x2e, 0x96, 0xe0, 0xc4, 0x9c, 0x12, 0x09, 0x66, 0xb0, 0x04, 0x98, 0x2d, 0xa4, 0xc5, 0xc5, 0x12,
	0x52, 0x59, 0x90, 0x2a, 0xc1, 0xa2, 0xc0, 0xa8, 0xc1, 0x67, 0x24, 0xa6, 0x87, 0xb0, 0x3e, 0x28,
	0x35, 0x0d, 0x84, 0x41, 0xb2, 0x41, 0x60, 0x35, 0x60, 0xfd, 0x99, 0x55, 0xa9, 0x12, 0xac, 0x0a,
	0x8c, 0x1a, 0xcc, 0x41, 0x60, 0xb6, 0x92, 0x26, 0x17, 0x3b, 0x54, 0x91, 0x10, 0x07, 0x17, 0x8b,
	0x93, 0xbf, 0x4b, 0xa4, 0x00, 0x83, 0x10, 0x17, 0x17, 0x9b, 0x87, 0xab, 0xa3, 0x8b, 0x6b, 0x90,
	0x00, 0x23, 0x48, 0xd4, 0xc7, 0xd3, 0xcf, 0x5b, 0x80, 0xc9, 0x49, 0x35, 0x4a, 0x39, 0x3d, 0xb3,
	0x24, 0xa3, 0x34, 0x49, 0x2f, 0x39, 0x3f, 0x57, 0x3f, 0x37, 0x3f, 0x2f, 0xb1, 0x42, 0x3f, 0x23,
	0x3f, 0xb1, 0x28, 0x45, 0xbf, 0xcc, 0x42, 0x1f, 0x6e, 0x6f, 0x12, 0x1b, 0xd8, 0xdf, 0xc6, 0x80,
	0x00, 0x00, 0x00, 0xff, 0xff, 0xba, 0x35, 0x90, 0x07, 0x0a, 0x01, 0x00, 0x00,
}
