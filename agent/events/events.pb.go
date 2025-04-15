// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.0
// source: agent/events/events.proto

package events

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
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

type AgentEvent struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	EventType     string                 `protobuf:"bytes,1,opt,name=event_type,json=eventType,proto3" json:"event_type,omitempty"`
	Timestamp     *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	ComputationId string                 `protobuf:"bytes,3,opt,name=computation_id,json=computationId,proto3" json:"computation_id,omitempty"`
	Details       []byte                 `protobuf:"bytes,4,opt,name=details,proto3" json:"details,omitempty"`
	Originator    string                 `protobuf:"bytes,5,opt,name=originator,proto3" json:"originator,omitempty"`
	Status        string                 `protobuf:"bytes,6,opt,name=status,proto3" json:"status,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AgentEvent) Reset() {
	*x = AgentEvent{}
	mi := &file_agent_events_events_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AgentEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AgentEvent) ProtoMessage() {}

func (x *AgentEvent) ProtoReflect() protoreflect.Message {
	mi := &file_agent_events_events_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AgentEvent.ProtoReflect.Descriptor instead.
func (*AgentEvent) Descriptor() ([]byte, []int) {
	return file_agent_events_events_proto_rawDescGZIP(), []int{0}
}

func (x *AgentEvent) GetEventType() string {
	if x != nil {
		return x.EventType
	}
	return ""
}

func (x *AgentEvent) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *AgentEvent) GetComputationId() string {
	if x != nil {
		return x.ComputationId
	}
	return ""
}

func (x *AgentEvent) GetDetails() []byte {
	if x != nil {
		return x.Details
	}
	return nil
}

func (x *AgentEvent) GetOriginator() string {
	if x != nil {
		return x.Originator
	}
	return ""
}

func (x *AgentEvent) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

type AgentLog struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Message       string                 `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	ComputationId string                 `protobuf:"bytes,2,opt,name=computation_id,json=computationId,proto3" json:"computation_id,omitempty"`
	Level         string                 `protobuf:"bytes,3,opt,name=level,proto3" json:"level,omitempty"`
	Timestamp     *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AgentLog) Reset() {
	*x = AgentLog{}
	mi := &file_agent_events_events_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AgentLog) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AgentLog) ProtoMessage() {}

func (x *AgentLog) ProtoReflect() protoreflect.Message {
	mi := &file_agent_events_events_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AgentLog.ProtoReflect.Descriptor instead.
func (*AgentLog) Descriptor() ([]byte, []int) {
	return file_agent_events_events_proto_rawDescGZIP(), []int{1}
}

func (x *AgentLog) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *AgentLog) GetComputationId() string {
	if x != nil {
		return x.ComputationId
	}
	return ""
}

func (x *AgentLog) GetLevel() string {
	if x != nil {
		return x.Level
	}
	return ""
}

func (x *AgentLog) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

type EventsLogs struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Message:
	//
	//	*EventsLogs_AgentLog
	//	*EventsLogs_AgentEvent
	Message       isEventsLogs_Message `protobuf_oneof:"message"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *EventsLogs) Reset() {
	*x = EventsLogs{}
	mi := &file_agent_events_events_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EventsLogs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EventsLogs) ProtoMessage() {}

func (x *EventsLogs) ProtoReflect() protoreflect.Message {
	mi := &file_agent_events_events_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EventsLogs.ProtoReflect.Descriptor instead.
func (*EventsLogs) Descriptor() ([]byte, []int) {
	return file_agent_events_events_proto_rawDescGZIP(), []int{2}
}

func (x *EventsLogs) GetMessage() isEventsLogs_Message {
	if x != nil {
		return x.Message
	}
	return nil
}

func (x *EventsLogs) GetAgentLog() *AgentLog {
	if x != nil {
		if x, ok := x.Message.(*EventsLogs_AgentLog); ok {
			return x.AgentLog
		}
	}
	return nil
}

func (x *EventsLogs) GetAgentEvent() *AgentEvent {
	if x != nil {
		if x, ok := x.Message.(*EventsLogs_AgentEvent); ok {
			return x.AgentEvent
		}
	}
	return nil
}

type isEventsLogs_Message interface {
	isEventsLogs_Message()
}

type EventsLogs_AgentLog struct {
	AgentLog *AgentLog `protobuf:"bytes,1,opt,name=agent_log,json=agentLog,proto3,oneof"`
}

type EventsLogs_AgentEvent struct {
	AgentEvent *AgentEvent `protobuf:"bytes,2,opt,name=agent_event,json=agentEvent,proto3,oneof"`
}

func (*EventsLogs_AgentLog) isEventsLogs_Message() {}

func (*EventsLogs_AgentEvent) isEventsLogs_Message() {}

var File_agent_events_events_proto protoreflect.FileDescriptor

const file_agent_events_events_proto_rawDesc = "" +
	"\n" +
	"\x19agent/events/events.proto\x12\x06events\x1a\x1fgoogle/protobuf/timestamp.proto\"\xde\x01\n" +
	"\n" +
	"AgentEvent\x12\x1d\n" +
	"\n" +
	"event_type\x18\x01 \x01(\tR\teventType\x128\n" +
	"\ttimestamp\x18\x02 \x01(\v2\x1a.google.protobuf.TimestampR\ttimestamp\x12%\n" +
	"\x0ecomputation_id\x18\x03 \x01(\tR\rcomputationId\x12\x18\n" +
	"\adetails\x18\x04 \x01(\fR\adetails\x12\x1e\n" +
	"\n" +
	"originator\x18\x05 \x01(\tR\n" +
	"originator\x12\x16\n" +
	"\x06status\x18\x06 \x01(\tR\x06status\"\x9b\x01\n" +
	"\bAgentLog\x12\x18\n" +
	"\amessage\x18\x01 \x01(\tR\amessage\x12%\n" +
	"\x0ecomputation_id\x18\x02 \x01(\tR\rcomputationId\x12\x14\n" +
	"\x05level\x18\x03 \x01(\tR\x05level\x128\n" +
	"\ttimestamp\x18\x04 \x01(\v2\x1a.google.protobuf.TimestampR\ttimestamp\"\x7f\n" +
	"\n" +
	"EventsLogs\x12/\n" +
	"\tagent_log\x18\x01 \x01(\v2\x10.events.AgentLogH\x00R\bagentLog\x125\n" +
	"\vagent_event\x18\x02 \x01(\v2\x12.events.AgentEventH\x00R\n" +
	"agentEventB\t\n" +
	"\amessageB\n" +
	"Z\b./eventsb\x06proto3"

var (
	file_agent_events_events_proto_rawDescOnce sync.Once
	file_agent_events_events_proto_rawDescData []byte
)

func file_agent_events_events_proto_rawDescGZIP() []byte {
	file_agent_events_events_proto_rawDescOnce.Do(func() {
		file_agent_events_events_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_agent_events_events_proto_rawDesc), len(file_agent_events_events_proto_rawDesc)))
	})
	return file_agent_events_events_proto_rawDescData
}

var file_agent_events_events_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_agent_events_events_proto_goTypes = []any{
	(*AgentEvent)(nil),            // 0: events.AgentEvent
	(*AgentLog)(nil),              // 1: events.AgentLog
	(*EventsLogs)(nil),            // 2: events.EventsLogs
	(*timestamppb.Timestamp)(nil), // 3: google.protobuf.Timestamp
}
var file_agent_events_events_proto_depIdxs = []int32{
	3, // 0: events.AgentEvent.timestamp:type_name -> google.protobuf.Timestamp
	3, // 1: events.AgentLog.timestamp:type_name -> google.protobuf.Timestamp
	1, // 2: events.EventsLogs.agent_log:type_name -> events.AgentLog
	0, // 3: events.EventsLogs.agent_event:type_name -> events.AgentEvent
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_agent_events_events_proto_init() }
func file_agent_events_events_proto_init() {
	if File_agent_events_events_proto != nil {
		return
	}
	file_agent_events_events_proto_msgTypes[2].OneofWrappers = []any{
		(*EventsLogs_AgentLog)(nil),
		(*EventsLogs_AgentEvent)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_agent_events_events_proto_rawDesc), len(file_agent_events_events_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_agent_events_events_proto_goTypes,
		DependencyIndexes: file_agent_events_events_proto_depIdxs,
		MessageInfos:      file_agent_events_events_proto_msgTypes,
	}.Build()
	File_agent_events_events_proto = out.File
	file_agent_events_events_proto_goTypes = nil
	file_agent_events_events_proto_depIdxs = nil
}
