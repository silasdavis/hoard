// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: grant.proto

package grant

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

type Grant struct {
	// The grantSpec provides sufficient information to decrypt the reference
	// if hoard has access to the requisite secret
	Spec                 *Spec    `protobuf:"bytes,1,opt,name=Spec,proto3" json:"Spec,omitempty"`
	EncryptedReference   []byte   `protobuf:"bytes,2,opt,name=EncryptedReference,proto3" json:"EncryptedReference,omitempty"`
	Version              int32    `protobuf:"varint,3,opt,name=Version,proto3" json:"Version,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Grant) Reset()         { *m = Grant{} }
func (m *Grant) String() string { return proto.CompactTextString(m) }
func (*Grant) ProtoMessage()    {}
func (*Grant) Descriptor() ([]byte, []int) {
	return fileDescriptor_d8d80872b3060482, []int{0}
}
func (m *Grant) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Grant.Unmarshal(m, b)
}
func (m *Grant) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Grant.Marshal(b, m, deterministic)
}
func (m *Grant) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Grant.Merge(m, src)
}
func (m *Grant) XXX_Size() int {
	return xxx_messageInfo_Grant.Size(m)
}
func (m *Grant) XXX_DiscardUnknown() {
	xxx_messageInfo_Grant.DiscardUnknown(m)
}

var xxx_messageInfo_Grant proto.InternalMessageInfo

func (m *Grant) GetSpec() *Spec {
	if m != nil {
		return m.Spec
	}
	return nil
}

func (m *Grant) GetEncryptedReference() []byte {
	if m != nil {
		return m.EncryptedReference
	}
	return nil
}

func (m *Grant) GetVersion() int32 {
	if m != nil {
		return m.Version
	}
	return 0
}

type Spec struct {
	Plaintext            *PlaintextSpec `protobuf:"bytes,1,opt,name=Plaintext,proto3" json:"Plaintext,omitempty"`
	Symmetric            *SymmetricSpec `protobuf:"bytes,2,opt,name=Symmetric,proto3" json:"Symmetric,omitempty"`
	OpenPGP              *OpenPGPSpec   `protobuf:"bytes,3,opt,name=OpenPGP,proto3" json:"OpenPGP,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *Spec) Reset()         { *m = Spec{} }
func (m *Spec) String() string { return proto.CompactTextString(m) }
func (*Spec) ProtoMessage()    {}
func (*Spec) Descriptor() ([]byte, []int) {
	return fileDescriptor_d8d80872b3060482, []int{1}
}
func (m *Spec) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Spec.Unmarshal(m, b)
}
func (m *Spec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Spec.Marshal(b, m, deterministic)
}
func (m *Spec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Spec.Merge(m, src)
}
func (m *Spec) XXX_Size() int {
	return xxx_messageInfo_Spec.Size(m)
}
func (m *Spec) XXX_DiscardUnknown() {
	xxx_messageInfo_Spec.DiscardUnknown(m)
}

var xxx_messageInfo_Spec proto.InternalMessageInfo

func (m *Spec) GetPlaintext() *PlaintextSpec {
	if m != nil {
		return m.Plaintext
	}
	return nil
}

func (m *Spec) GetSymmetric() *SymmetricSpec {
	if m != nil {
		return m.Symmetric
	}
	return nil
}

func (m *Spec) GetOpenPGP() *OpenPGPSpec {
	if m != nil {
		return m.OpenPGP
	}
	return nil
}

type PlaintextSpec struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PlaintextSpec) Reset()         { *m = PlaintextSpec{} }
func (m *PlaintextSpec) String() string { return proto.CompactTextString(m) }
func (*PlaintextSpec) ProtoMessage()    {}
func (*PlaintextSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_d8d80872b3060482, []int{2}
}
func (m *PlaintextSpec) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PlaintextSpec.Unmarshal(m, b)
}
func (m *PlaintextSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PlaintextSpec.Marshal(b, m, deterministic)
}
func (m *PlaintextSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PlaintextSpec.Merge(m, src)
}
func (m *PlaintextSpec) XXX_Size() int {
	return xxx_messageInfo_PlaintextSpec.Size(m)
}
func (m *PlaintextSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_PlaintextSpec.DiscardUnknown(m)
}

var xxx_messageInfo_PlaintextSpec proto.InternalMessageInfo

type SymmetricSpec struct {
	// A non-secret identifier for a secret that is 'known' to Hoard (accessible via store or config)
	PublicID             string   `protobuf:"bytes,1,opt,name=PublicID,proto3" json:"PublicID,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SymmetricSpec) Reset()         { *m = SymmetricSpec{} }
func (m *SymmetricSpec) String() string { return proto.CompactTextString(m) }
func (*SymmetricSpec) ProtoMessage()    {}
func (*SymmetricSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_d8d80872b3060482, []int{3}
}
func (m *SymmetricSpec) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SymmetricSpec.Unmarshal(m, b)
}
func (m *SymmetricSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SymmetricSpec.Marshal(b, m, deterministic)
}
func (m *SymmetricSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SymmetricSpec.Merge(m, src)
}
func (m *SymmetricSpec) XXX_Size() int {
	return xxx_messageInfo_SymmetricSpec.Size(m)
}
func (m *SymmetricSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_SymmetricSpec.DiscardUnknown(m)
}

var xxx_messageInfo_SymmetricSpec proto.InternalMessageInfo

func (m *SymmetricSpec) GetPublicID() string {
	if m != nil {
		return m.PublicID
	}
	return ""
}

type OpenPGPSpec struct {
	PublicKey            string   `protobuf:"bytes,1,opt,name=PublicKey,proto3" json:"PublicKey,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *OpenPGPSpec) Reset()         { *m = OpenPGPSpec{} }
func (m *OpenPGPSpec) String() string { return proto.CompactTextString(m) }
func (*OpenPGPSpec) ProtoMessage()    {}
func (*OpenPGPSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_d8d80872b3060482, []int{4}
}
func (m *OpenPGPSpec) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_OpenPGPSpec.Unmarshal(m, b)
}
func (m *OpenPGPSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_OpenPGPSpec.Marshal(b, m, deterministic)
}
func (m *OpenPGPSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OpenPGPSpec.Merge(m, src)
}
func (m *OpenPGPSpec) XXX_Size() int {
	return xxx_messageInfo_OpenPGPSpec.Size(m)
}
func (m *OpenPGPSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_OpenPGPSpec.DiscardUnknown(m)
}

var xxx_messageInfo_OpenPGPSpec proto.InternalMessageInfo

func (m *OpenPGPSpec) GetPublicKey() string {
	if m != nil {
		return m.PublicKey
	}
	return ""
}

func init() {
	proto.RegisterType((*Grant)(nil), "grant.Grant")
	proto.RegisterType((*Spec)(nil), "grant.Spec")
	proto.RegisterType((*PlaintextSpec)(nil), "grant.PlaintextSpec")
	proto.RegisterType((*SymmetricSpec)(nil), "grant.SymmetricSpec")
	proto.RegisterType((*OpenPGPSpec)(nil), "grant.OpenPGPSpec")
}

func init() { proto.RegisterFile("grant.proto", fileDescriptor_d8d80872b3060482) }

var fileDescriptor_d8d80872b3060482 = []byte{
	// 277 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x51, 0xcd, 0x4a, 0xf3, 0x40,
	0x14, 0x25, 0xdf, 0x67, 0xac, 0xb9, 0xb1, 0x08, 0x17, 0x17, 0x41, 0x84, 0xc6, 0xac, 0x02, 0x95,
	0x04, 0x22, 0xf8, 0x00, 0xa2, 0x14, 0x71, 0x61, 0x48, 0xc1, 0x85, 0xbb, 0x64, 0x7a, 0x6d, 0x07,
	0x9a, 0x99, 0x30, 0x4e, 0xa5, 0x79, 0x17, 0x1f, 0x56, 0x32, 0x99, 0x26, 0x16, 0xdc, 0xcd, 0xf9,
	0xbb, 0xe7, 0xc0, 0x80, 0xbf, 0x56, 0xa5, 0xd0, 0x49, 0xa3, 0xa4, 0x96, 0xe8, 0x1a, 0x10, 0x29,
	0x70, 0x17, 0xdd, 0x03, 0x67, 0x70, 0xb2, 0x6c, 0x88, 0x05, 0x4e, 0xe8, 0xc4, 0x7e, 0xe6, 0x27,
	0xbd, 0xb7, 0xa3, 0x0a, 0x23, 0x60, 0x02, 0xf8, 0x24, 0x98, 0x6a, 0x1b, 0x4d, 0xab, 0x82, 0x3e,
	0x48, 0x91, 0x60, 0x14, 0xfc, 0x0b, 0x9d, 0xf8, 0xbc, 0xf8, 0x43, 0xc1, 0x00, 0x26, 0x6f, 0xa4,
	0x3e, 0xb9, 0x14, 0xc1, 0xff, 0xd0, 0x89, 0xdd, 0xe2, 0x00, 0xa3, 0x6f, 0xa7, 0xef, 0xc2, 0x0c,
	0xbc, 0x7c, 0x5b, 0x72, 0xa1, 0x69, 0xaf, 0x6d, 0xf1, 0xa5, 0x2d, 0x1e, 0x78, 0xb3, 0x60, 0xb4,
	0x75, 0x99, 0x65, 0x5b, 0xd7, 0xa4, 0x15, 0x67, 0xa6, 0x7d, 0xcc, 0x0c, 0x7c, 0x9f, 0x19, 0x20,
	0xde, 0xc2, 0xe4, 0xb5, 0x21, 0x91, 0x2f, 0x72, 0x33, 0xc5, 0xcf, 0xd0, 0x26, 0x2c, 0x6b, 0xfc,
	0x07, 0x4b, 0x74, 0x01, 0xd3, 0xa3, 0xf6, 0x68, 0x0e, 0xd3, 0xa3, 0xd3, 0x78, 0x05, 0x67, 0xf9,
	0xae, 0xda, 0x72, 0xf6, 0xfc, 0x68, 0x66, 0x7b, 0xc5, 0x80, 0xa3, 0x39, 0xf8, 0xbf, 0xae, 0xe2,
	0x35, 0x78, 0xbd, 0xf4, 0x42, 0xad, 0xf5, 0x8e, 0xc4, 0xc3, 0xcd, 0xfb, 0x6c, 0xcd, 0xf5, 0x66,
	0x57, 0x25, 0x4c, 0xd6, 0x69, 0x2d, 0x45, 0xb9, 0x4f, 0x37, 0xb2, 0x54, 0xab, 0xf4, 0xeb, 0x3e,
	0x35, 0x13, 0xab, 0x53, 0xf3, 0x5d, 0x77, 0x3f, 0x01, 0x00, 0x00, 0xff, 0xff, 0x77, 0xd0, 0xe7,
	0x45, 0xbd, 0x01, 0x00, 0x00,
}
