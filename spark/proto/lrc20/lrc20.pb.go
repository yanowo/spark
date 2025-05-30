// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.3
// source: lrc20.proto

package lrc20

import (
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	spark "github.com/lightsparkdev/spark/proto/spark"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SendSparkSignatureRequest struct {
	state                      protoimpl.MessageState                  `protogen:"open.v1"`
	FinalTokenTransaction      *spark.TokenTransaction                 `protobuf:"bytes,1,opt,name=final_token_transaction,json=finalTokenTransaction,proto3" json:"final_token_transaction,omitempty"`
	OperatorSpecificSignatures []*spark.OperatorSpecificOwnerSignature `protobuf:"bytes,2,rep,name=operator_specific_signatures,json=operatorSpecificSignatures,proto3" json:"operator_specific_signatures,omitempty"`
	OperatorSignatureData      *SparkOperatorSignatureData             `protobuf:"bytes,3,opt,name=operator_signature_data,json=operatorSignatureData,proto3" json:"operator_signature_data,omitempty"`
	RevocationSecrets          []*spark.RevocationSecretWithIndex      `protobuf:"bytes,4,rep,name=revocation_secrets,json=revocationSecrets,proto3" json:"revocation_secrets,omitempty"`
	unknownFields              protoimpl.UnknownFields
	sizeCache                  protoimpl.SizeCache
}

func (x *SendSparkSignatureRequest) Reset() {
	*x = SendSparkSignatureRequest{}
	mi := &file_lrc20_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SendSparkSignatureRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SendSparkSignatureRequest) ProtoMessage() {}

func (x *SendSparkSignatureRequest) ProtoReflect() protoreflect.Message {
	mi := &file_lrc20_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SendSparkSignatureRequest.ProtoReflect.Descriptor instead.
func (*SendSparkSignatureRequest) Descriptor() ([]byte, []int) {
	return file_lrc20_proto_rawDescGZIP(), []int{0}
}

func (x *SendSparkSignatureRequest) GetFinalTokenTransaction() *spark.TokenTransaction {
	if x != nil {
		return x.FinalTokenTransaction
	}
	return nil
}

func (x *SendSparkSignatureRequest) GetOperatorSpecificSignatures() []*spark.OperatorSpecificOwnerSignature {
	if x != nil {
		return x.OperatorSpecificSignatures
	}
	return nil
}

func (x *SendSparkSignatureRequest) GetOperatorSignatureData() *SparkOperatorSignatureData {
	if x != nil {
		return x.OperatorSignatureData
	}
	return nil
}

func (x *SendSparkSignatureRequest) GetRevocationSecrets() []*spark.RevocationSecretWithIndex {
	if x != nil {
		return x.RevocationSecrets
	}
	return nil
}

type SparkOperatorSignatureData struct {
	state                     protoimpl.MessageState `protogen:"open.v1"`
	SparkOperatorSignature    []byte                 `protobuf:"bytes,1,opt,name=spark_operator_signature,json=sparkOperatorSignature,proto3" json:"spark_operator_signature,omitempty"`
	OperatorIdentityPublicKey []byte                 `protobuf:"bytes,2,opt,name=operator_identity_public_key,json=operatorIdentityPublicKey,proto3" json:"operator_identity_public_key,omitempty"`
	unknownFields             protoimpl.UnknownFields
	sizeCache                 protoimpl.SizeCache
}

func (x *SparkOperatorSignatureData) Reset() {
	*x = SparkOperatorSignatureData{}
	mi := &file_lrc20_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SparkOperatorSignatureData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SparkOperatorSignatureData) ProtoMessage() {}

func (x *SparkOperatorSignatureData) ProtoReflect() protoreflect.Message {
	mi := &file_lrc20_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SparkOperatorSignatureData.ProtoReflect.Descriptor instead.
func (*SparkOperatorSignatureData) Descriptor() ([]byte, []int) {
	return file_lrc20_proto_rawDescGZIP(), []int{1}
}

func (x *SparkOperatorSignatureData) GetSparkOperatorSignature() []byte {
	if x != nil {
		return x.SparkOperatorSignature
	}
	return nil
}

func (x *SparkOperatorSignatureData) GetOperatorIdentityPublicKey() []byte {
	if x != nil {
		return x.OperatorIdentityPublicKey
	}
	return nil
}

type SparkSignatureOutputData struct {
	state                protoimpl.MessageState `protogen:"open.v1"`
	SpentOutputIndex     uint32                 `protobuf:"varint,1,opt,name=spent_output_index,json=spentOutputIndex,proto3" json:"spent_output_index,omitempty"`
	RevocationPrivateKey []byte                 `protobuf:"bytes,2,opt,name=revocation_private_key,json=revocationPrivateKey,proto3,oneof" json:"revocation_private_key,omitempty"`
	unknownFields        protoimpl.UnknownFields
	sizeCache            protoimpl.SizeCache
}

func (x *SparkSignatureOutputData) Reset() {
	*x = SparkSignatureOutputData{}
	mi := &file_lrc20_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SparkSignatureOutputData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SparkSignatureOutputData) ProtoMessage() {}

func (x *SparkSignatureOutputData) ProtoReflect() protoreflect.Message {
	mi := &file_lrc20_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SparkSignatureOutputData.ProtoReflect.Descriptor instead.
func (*SparkSignatureOutputData) Descriptor() ([]byte, []int) {
	return file_lrc20_proto_rawDescGZIP(), []int{2}
}

func (x *SparkSignatureOutputData) GetSpentOutputIndex() uint32 {
	if x != nil {
		return x.SpentOutputIndex
	}
	return 0
}

func (x *SparkSignatureOutputData) GetRevocationPrivateKey() []byte {
	if x != nil {
		return x.RevocationPrivateKey
	}
	return nil
}

type GetSparkTxRequest struct {
	state                     protoimpl.MessageState `protogen:"open.v1"`
	FinalTokenTransactionHash []byte                 `protobuf:"bytes,1,opt,name=final_token_transaction_hash,json=finalTokenTransactionHash,proto3" json:"final_token_transaction_hash,omitempty"`
	unknownFields             protoimpl.UnknownFields
	sizeCache                 protoimpl.SizeCache
}

func (x *GetSparkTxRequest) Reset() {
	*x = GetSparkTxRequest{}
	mi := &file_lrc20_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetSparkTxRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSparkTxRequest) ProtoMessage() {}

func (x *GetSparkTxRequest) ProtoReflect() protoreflect.Message {
	mi := &file_lrc20_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSparkTxRequest.ProtoReflect.Descriptor instead.
func (*GetSparkTxRequest) Descriptor() ([]byte, []int) {
	return file_lrc20_proto_rawDescGZIP(), []int{3}
}

func (x *GetSparkTxRequest) GetFinalTokenTransactionHash() []byte {
	if x != nil {
		return x.FinalTokenTransactionHash
	}
	return nil
}

type VerifySparkTxRequest struct {
	state                 protoimpl.MessageState  `protogen:"open.v1"`
	FinalTokenTransaction *spark.TokenTransaction `protobuf:"bytes,1,opt,name=final_token_transaction,json=finalTokenTransaction,proto3" json:"final_token_transaction,omitempty"`
	unknownFields         protoimpl.UnknownFields
	sizeCache             protoimpl.SizeCache
}

func (x *VerifySparkTxRequest) Reset() {
	*x = VerifySparkTxRequest{}
	mi := &file_lrc20_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VerifySparkTxRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VerifySparkTxRequest) ProtoMessage() {}

func (x *VerifySparkTxRequest) ProtoReflect() protoreflect.Message {
	mi := &file_lrc20_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VerifySparkTxRequest.ProtoReflect.Descriptor instead.
func (*VerifySparkTxRequest) Descriptor() ([]byte, []int) {
	return file_lrc20_proto_rawDescGZIP(), []int{4}
}

func (x *VerifySparkTxRequest) GetFinalTokenTransaction() *spark.TokenTransaction {
	if x != nil {
		return x.FinalTokenTransaction
	}
	return nil
}

type ListSparkTxsRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	PageToken     []byte                 `protobuf:"bytes,1,opt,name=page_token,json=pageToken,proto3,oneof" json:"page_token,omitempty"`
	PageSize      *uint32                `protobuf:"varint,2,opt,name=page_size,json=pageSize,proto3,oneof" json:"page_size,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListSparkTxsRequest) Reset() {
	*x = ListSparkTxsRequest{}
	mi := &file_lrc20_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListSparkTxsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListSparkTxsRequest) ProtoMessage() {}

func (x *ListSparkTxsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_lrc20_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListSparkTxsRequest.ProtoReflect.Descriptor instead.
func (*ListSparkTxsRequest) Descriptor() ([]byte, []int) {
	return file_lrc20_proto_rawDescGZIP(), []int{5}
}

func (x *ListSparkTxsRequest) GetPageToken() []byte {
	if x != nil {
		return x.PageToken
	}
	return nil
}

func (x *ListSparkTxsRequest) GetPageSize() uint32 {
	if x != nil && x.PageSize != nil {
		return *x.PageSize
	}
	return 0
}

type ListSparkTxsResponse struct {
	state             protoimpl.MessageState      `protogen:"open.v1"`
	TokenTransactions []*TokenTransactionResponse `protobuf:"bytes,1,rep,name=token_transactions,json=tokenTransactions,proto3" json:"token_transactions,omitempty"`
	NextPageToken     []byte                      `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3,oneof" json:"next_page_token,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *ListSparkTxsResponse) Reset() {
	*x = ListSparkTxsResponse{}
	mi := &file_lrc20_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListSparkTxsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListSparkTxsResponse) ProtoMessage() {}

func (x *ListSparkTxsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_lrc20_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListSparkTxsResponse.ProtoReflect.Descriptor instead.
func (*ListSparkTxsResponse) Descriptor() ([]byte, []int) {
	return file_lrc20_proto_rawDescGZIP(), []int{6}
}

func (x *ListSparkTxsResponse) GetTokenTransactions() []*TokenTransactionResponse {
	if x != nil {
		return x.TokenTransactions
	}
	return nil
}

func (x *ListSparkTxsResponse) GetNextPageToken() []byte {
	if x != nil {
		return x.NextPageToken
	}
	return nil
}

type GetSparkTxResponse struct {
	state                 protoimpl.MessageState  `protogen:"open.v1"`
	FinalTokenTransaction *spark.TokenTransaction `protobuf:"bytes,1,opt,name=final_token_transaction,json=finalTokenTransaction,proto3" json:"final_token_transaction,omitempty"`
	unknownFields         protoimpl.UnknownFields
	sizeCache             protoimpl.SizeCache
}

func (x *GetSparkTxResponse) Reset() {
	*x = GetSparkTxResponse{}
	mi := &file_lrc20_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetSparkTxResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSparkTxResponse) ProtoMessage() {}

func (x *GetSparkTxResponse) ProtoReflect() protoreflect.Message {
	mi := &file_lrc20_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSparkTxResponse.ProtoReflect.Descriptor instead.
func (*GetSparkTxResponse) Descriptor() ([]byte, []int) {
	return file_lrc20_proto_rawDescGZIP(), []int{7}
}

func (x *GetSparkTxResponse) GetFinalTokenTransaction() *spark.TokenTransaction {
	if x != nil {
		return x.FinalTokenTransaction
	}
	return nil
}

type TokenTransactionResponse struct {
	state                 protoimpl.MessageState  `protogen:"open.v1"`
	Finalized             bool                    `protobuf:"varint,1,opt,name=finalized,proto3" json:"finalized,omitempty"`
	FinalTokenTransaction *spark.TokenTransaction `protobuf:"bytes,2,opt,name=final_token_transaction,json=finalTokenTransaction,proto3" json:"final_token_transaction,omitempty"`
	unknownFields         protoimpl.UnknownFields
	sizeCache             protoimpl.SizeCache
}

func (x *TokenTransactionResponse) Reset() {
	*x = TokenTransactionResponse{}
	mi := &file_lrc20_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TokenTransactionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TokenTransactionResponse) ProtoMessage() {}

func (x *TokenTransactionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_lrc20_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TokenTransactionResponse.ProtoReflect.Descriptor instead.
func (*TokenTransactionResponse) Descriptor() ([]byte, []int) {
	return file_lrc20_proto_rawDescGZIP(), []int{8}
}

func (x *TokenTransactionResponse) GetFinalized() bool {
	if x != nil {
		return x.Finalized
	}
	return false
}

func (x *TokenTransactionResponse) GetFinalTokenTransaction() *spark.TokenTransaction {
	if x != nil {
		return x.FinalTokenTransaction
	}
	return nil
}

type ListWithdrawnOutputsRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Blockhash     []byte                 `protobuf:"bytes,1,opt,name=blockhash,proto3,oneof" json:"blockhash,omitempty"`
	PageToken     *string                `protobuf:"bytes,2,opt,name=page_token,json=pageToken,proto3,oneof" json:"page_token,omitempty"`
	PageSize      *uint32                `protobuf:"varint,3,opt,name=page_size,json=pageSize,proto3,oneof" json:"page_size,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListWithdrawnOutputsRequest) Reset() {
	*x = ListWithdrawnOutputsRequest{}
	mi := &file_lrc20_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListWithdrawnOutputsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListWithdrawnOutputsRequest) ProtoMessage() {}

func (x *ListWithdrawnOutputsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_lrc20_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListWithdrawnOutputsRequest.ProtoReflect.Descriptor instead.
func (*ListWithdrawnOutputsRequest) Descriptor() ([]byte, []int) {
	return file_lrc20_proto_rawDescGZIP(), []int{9}
}

func (x *ListWithdrawnOutputsRequest) GetBlockhash() []byte {
	if x != nil {
		return x.Blockhash
	}
	return nil
}

func (x *ListWithdrawnOutputsRequest) GetPageToken() string {
	if x != nil && x.PageToken != nil {
		return *x.PageToken
	}
	return ""
}

func (x *ListWithdrawnOutputsRequest) GetPageSize() uint32 {
	if x != nil && x.PageSize != nil {
		return *x.PageSize
	}
	return 0
}

type ListWithdrawnOutputsResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Outputs       []*spark.TokenOutput   `protobuf:"bytes,1,rep,name=outputs,proto3" json:"outputs,omitempty"`
	NextPageToken *string                `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3,oneof" json:"next_page_token,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ListWithdrawnOutputsResponse) Reset() {
	*x = ListWithdrawnOutputsResponse{}
	mi := &file_lrc20_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ListWithdrawnOutputsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListWithdrawnOutputsResponse) ProtoMessage() {}

func (x *ListWithdrawnOutputsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_lrc20_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListWithdrawnOutputsResponse.ProtoReflect.Descriptor instead.
func (*ListWithdrawnOutputsResponse) Descriptor() ([]byte, []int) {
	return file_lrc20_proto_rawDescGZIP(), []int{10}
}

func (x *ListWithdrawnOutputsResponse) GetOutputs() []*spark.TokenOutput {
	if x != nil {
		return x.Outputs
	}
	return nil
}

func (x *ListWithdrawnOutputsResponse) GetNextPageToken() string {
	if x != nil && x.NextPageToken != nil {
		return *x.NextPageToken
	}
	return ""
}

var File_lrc20_proto protoreflect.FileDescriptor

const file_lrc20_proto_rawDesc = "" +
	"\n" +
	"\vlrc20.proto\x12\x06rpc.v1\x1a\x1bgoogle/protobuf/empty.proto\x1a\x17validate/validate.proto\x1a\vspark.proto\"\x82\x03\n" +
	"\x19SendSparkSignatureRequest\x12O\n" +
	"\x17final_token_transaction\x18\x01 \x01(\v2\x17.spark.TokenTransactionR\x15finalTokenTransaction\x12g\n" +
	"\x1coperator_specific_signatures\x18\x02 \x03(\v2%.spark.OperatorSpecificOwnerSignatureR\x1aoperatorSpecificSignatures\x12Z\n" +
	"\x17operator_signature_data\x18\x03 \x01(\v2\".rpc.v1.SparkOperatorSignatureDataR\x15operatorSignatureData\x12O\n" +
	"\x12revocation_secrets\x18\x04 \x03(\v2 .spark.RevocationSecretWithIndexR\x11revocationSecrets\"\xab\x01\n" +
	"\x1aSparkOperatorSignatureData\x12C\n" +
	"\x18spark_operator_signature\x18\x01 \x01(\fB\t\xfaB\x06z\x04\x10@\x18IR\x16sparkOperatorSignature\x12H\n" +
	"\x1coperator_identity_public_key\x18\x02 \x01(\fB\a\xfaB\x04z\x02h!R\x19operatorIdentityPublicKey\"\x9e\x01\n" +
	"\x18SparkSignatureOutputData\x12,\n" +
	"\x12spent_output_index\x18\x01 \x01(\rR\x10spentOutputIndex\x129\n" +
	"\x16revocation_private_key\x18\x02 \x01(\fH\x00R\x14revocationPrivateKey\x88\x01\x01B\x19\n" +
	"\x17_revocation_private_key\"T\n" +
	"\x11GetSparkTxRequest\x12?\n" +
	"\x1cfinal_token_transaction_hash\x18\x01 \x01(\fR\x19finalTokenTransactionHash\"g\n" +
	"\x14VerifySparkTxRequest\x12O\n" +
	"\x17final_token_transaction\x18\x01 \x01(\v2\x17.spark.TokenTransactionR\x15finalTokenTransaction\"x\n" +
	"\x13ListSparkTxsRequest\x12\"\n" +
	"\n" +
	"page_token\x18\x01 \x01(\fH\x00R\tpageToken\x88\x01\x01\x12 \n" +
	"\tpage_size\x18\x02 \x01(\rH\x01R\bpageSize\x88\x01\x01B\r\n" +
	"\v_page_tokenB\f\n" +
	"\n" +
	"_page_size\"\xa8\x01\n" +
	"\x14ListSparkTxsResponse\x12O\n" +
	"\x12token_transactions\x18\x01 \x03(\v2 .rpc.v1.TokenTransactionResponseR\x11tokenTransactions\x12+\n" +
	"\x0fnext_page_token\x18\x02 \x01(\fH\x00R\rnextPageToken\x88\x01\x01B\x12\n" +
	"\x10_next_page_token\"e\n" +
	"\x12GetSparkTxResponse\x12O\n" +
	"\x17final_token_transaction\x18\x01 \x01(\v2\x17.spark.TokenTransactionR\x15finalTokenTransaction\"\x89\x01\n" +
	"\x18TokenTransactionResponse\x12\x1c\n" +
	"\tfinalized\x18\x01 \x01(\bR\tfinalized\x12O\n" +
	"\x17final_token_transaction\x18\x02 \x01(\v2\x17.spark.TokenTransactionR\x15finalTokenTransaction\"\xb1\x01\n" +
	"\x1bListWithdrawnOutputsRequest\x12!\n" +
	"\tblockhash\x18\x01 \x01(\fH\x00R\tblockhash\x88\x01\x01\x12\"\n" +
	"\n" +
	"page_token\x18\x02 \x01(\tH\x01R\tpageToken\x88\x01\x01\x12 \n" +
	"\tpage_size\x18\x03 \x01(\rH\x02R\bpageSize\x88\x01\x01B\f\n" +
	"\n" +
	"_blockhashB\r\n" +
	"\v_page_tokenB\f\n" +
	"\n" +
	"_page_size\"\x8d\x01\n" +
	"\x1cListWithdrawnOutputsResponse\x12,\n" +
	"\aoutputs\x18\x01 \x03(\v2\x12.spark.TokenOutputR\aoutputs\x12+\n" +
	"\x0fnext_page_token\x18\x02 \x01(\tH\x00R\rnextPageToken\x88\x01\x01B\x12\n" +
	"\x10_next_page_token2\xe2\x03\n" +
	"\fSparkService\x12O\n" +
	"\x12SendSparkSignature\x12!.rpc.v1.SendSparkSignatureRequest\x1a\x16.google.protobuf.Empty\x12I\n" +
	"\fListSparkTxs\x12\x1b.rpc.v1.ListSparkTxsRequest\x1a\x1c.rpc.v1.ListSparkTxsResponse\x12C\n" +
	"\n" +
	"GetSparkTx\x12\x19.rpc.v1.GetSparkTxRequest\x1a\x1a.rpc.v1.GetSparkTxResponse\x12E\n" +
	"\rVerifySparkTx\x12\x1c.rpc.v1.VerifySparkTxRequest\x1a\x16.google.protobuf.Empty\x12G\n" +
	"\fFreezeTokens\x12\x1a.spark.FreezeTokensRequest\x1a\x1b.spark.FreezeTokensResponse\x12a\n" +
	"\x14ListWithdrawnOutputs\x12#.rpc.v1.ListWithdrawnOutputsRequest\x1a$.rpc.v1.ListWithdrawnOutputsResponseB,Z*github.com/lightsparkdev/spark/proto/lrc20b\x06proto3"

var (
	file_lrc20_proto_rawDescOnce sync.Once
	file_lrc20_proto_rawDescData []byte
)

func file_lrc20_proto_rawDescGZIP() []byte {
	file_lrc20_proto_rawDescOnce.Do(func() {
		file_lrc20_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_lrc20_proto_rawDesc), len(file_lrc20_proto_rawDesc)))
	})
	return file_lrc20_proto_rawDescData
}

var file_lrc20_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_lrc20_proto_goTypes = []any{
	(*SendSparkSignatureRequest)(nil),            // 0: rpc.v1.SendSparkSignatureRequest
	(*SparkOperatorSignatureData)(nil),           // 1: rpc.v1.SparkOperatorSignatureData
	(*SparkSignatureOutputData)(nil),             // 2: rpc.v1.SparkSignatureOutputData
	(*GetSparkTxRequest)(nil),                    // 3: rpc.v1.GetSparkTxRequest
	(*VerifySparkTxRequest)(nil),                 // 4: rpc.v1.VerifySparkTxRequest
	(*ListSparkTxsRequest)(nil),                  // 5: rpc.v1.ListSparkTxsRequest
	(*ListSparkTxsResponse)(nil),                 // 6: rpc.v1.ListSparkTxsResponse
	(*GetSparkTxResponse)(nil),                   // 7: rpc.v1.GetSparkTxResponse
	(*TokenTransactionResponse)(nil),             // 8: rpc.v1.TokenTransactionResponse
	(*ListWithdrawnOutputsRequest)(nil),          // 9: rpc.v1.ListWithdrawnOutputsRequest
	(*ListWithdrawnOutputsResponse)(nil),         // 10: rpc.v1.ListWithdrawnOutputsResponse
	(*spark.TokenTransaction)(nil),               // 11: spark.TokenTransaction
	(*spark.OperatorSpecificOwnerSignature)(nil), // 12: spark.OperatorSpecificOwnerSignature
	(*spark.RevocationSecretWithIndex)(nil),      // 13: spark.RevocationSecretWithIndex
	(*spark.TokenOutput)(nil),                    // 14: spark.TokenOutput
	(*spark.FreezeTokensRequest)(nil),            // 15: spark.FreezeTokensRequest
	(*emptypb.Empty)(nil),                        // 16: google.protobuf.Empty
	(*spark.FreezeTokensResponse)(nil),           // 17: spark.FreezeTokensResponse
}
var file_lrc20_proto_depIdxs = []int32{
	11, // 0: rpc.v1.SendSparkSignatureRequest.final_token_transaction:type_name -> spark.TokenTransaction
	12, // 1: rpc.v1.SendSparkSignatureRequest.operator_specific_signatures:type_name -> spark.OperatorSpecificOwnerSignature
	1,  // 2: rpc.v1.SendSparkSignatureRequest.operator_signature_data:type_name -> rpc.v1.SparkOperatorSignatureData
	13, // 3: rpc.v1.SendSparkSignatureRequest.revocation_secrets:type_name -> spark.RevocationSecretWithIndex
	11, // 4: rpc.v1.VerifySparkTxRequest.final_token_transaction:type_name -> spark.TokenTransaction
	8,  // 5: rpc.v1.ListSparkTxsResponse.token_transactions:type_name -> rpc.v1.TokenTransactionResponse
	11, // 6: rpc.v1.GetSparkTxResponse.final_token_transaction:type_name -> spark.TokenTransaction
	11, // 7: rpc.v1.TokenTransactionResponse.final_token_transaction:type_name -> spark.TokenTransaction
	14, // 8: rpc.v1.ListWithdrawnOutputsResponse.outputs:type_name -> spark.TokenOutput
	0,  // 9: rpc.v1.SparkService.SendSparkSignature:input_type -> rpc.v1.SendSparkSignatureRequest
	5,  // 10: rpc.v1.SparkService.ListSparkTxs:input_type -> rpc.v1.ListSparkTxsRequest
	3,  // 11: rpc.v1.SparkService.GetSparkTx:input_type -> rpc.v1.GetSparkTxRequest
	4,  // 12: rpc.v1.SparkService.VerifySparkTx:input_type -> rpc.v1.VerifySparkTxRequest
	15, // 13: rpc.v1.SparkService.FreezeTokens:input_type -> spark.FreezeTokensRequest
	9,  // 14: rpc.v1.SparkService.ListWithdrawnOutputs:input_type -> rpc.v1.ListWithdrawnOutputsRequest
	16, // 15: rpc.v1.SparkService.SendSparkSignature:output_type -> google.protobuf.Empty
	6,  // 16: rpc.v1.SparkService.ListSparkTxs:output_type -> rpc.v1.ListSparkTxsResponse
	7,  // 17: rpc.v1.SparkService.GetSparkTx:output_type -> rpc.v1.GetSparkTxResponse
	16, // 18: rpc.v1.SparkService.VerifySparkTx:output_type -> google.protobuf.Empty
	17, // 19: rpc.v1.SparkService.FreezeTokens:output_type -> spark.FreezeTokensResponse
	10, // 20: rpc.v1.SparkService.ListWithdrawnOutputs:output_type -> rpc.v1.ListWithdrawnOutputsResponse
	15, // [15:21] is the sub-list for method output_type
	9,  // [9:15] is the sub-list for method input_type
	9,  // [9:9] is the sub-list for extension type_name
	9,  // [9:9] is the sub-list for extension extendee
	0,  // [0:9] is the sub-list for field type_name
}

func init() { file_lrc20_proto_init() }
func file_lrc20_proto_init() {
	if File_lrc20_proto != nil {
		return
	}
	file_lrc20_proto_msgTypes[2].OneofWrappers = []any{}
	file_lrc20_proto_msgTypes[5].OneofWrappers = []any{}
	file_lrc20_proto_msgTypes[6].OneofWrappers = []any{}
	file_lrc20_proto_msgTypes[9].OneofWrappers = []any{}
	file_lrc20_proto_msgTypes[10].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_lrc20_proto_rawDesc), len(file_lrc20_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_lrc20_proto_goTypes,
		DependencyIndexes: file_lrc20_proto_depIdxs,
		MessageInfos:      file_lrc20_proto_msgTypes,
	}.Build()
	File_lrc20_proto = out.File
	file_lrc20_proto_goTypes = nil
	file_lrc20_proto_depIdxs = nil
}
