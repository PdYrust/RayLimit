package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

type xrayUUIDRoutingContextQueryResult struct {
	Contexts []UUIDRoutingContext
	Issues   []SessionEvidenceIssue
}

type xrayUUIDRoutingTransportDialer func(ctx context.Context, endpoint APIEndpoint) (*grpc.ClientConn, func(), error)

const (
	xrayRoutingServiceSubscribeMethod = "/xray.app.router.command.RoutingService/SubscribeRoutingStats"
	xrayRoutingTransportTimeout       = 3 * time.Second
)

var xrayRoutingFieldSelectors = []string{
	"user",
	"inbound",
	"network",
	"ip_source",
	"ip_target",
	"ip_local",
	"port_source",
	"port_target",
	"port_local",
	"domain",
	"protocol",
	"outbound",
}

var (
	xrayRoutingDescriptorOnce sync.Once
	xrayRoutingDescriptorSet  xrayRoutingDescriptors
)

type xrayRoutingDescriptors struct {
	subscribeRequest protoreflect.MessageDescriptor
	routingContext   protoreflect.MessageDescriptor
	fields           xrayRoutingDescriptorFields
}

type xrayRoutingDescriptorFields struct {
	subscribeSelectors protoreflect.FieldDescriptor
	inboundTag         protoreflect.FieldDescriptor
	network            protoreflect.FieldDescriptor
	sourceIPs          protoreflect.FieldDescriptor
	targetIPs          protoreflect.FieldDescriptor
	sourcePort         protoreflect.FieldDescriptor
	targetPort         protoreflect.FieldDescriptor
	targetDomain       protoreflect.FieldDescriptor
	protocol           protoreflect.FieldDescriptor
	user               protoreflect.FieldDescriptor
	outboundTag        protoreflect.FieldDescriptor
	localIPs           protoreflect.FieldDescriptor
	localPort          protoreflect.FieldDescriptor
}

func defaultXrayUUIDRoutingContextQuery(dial xrayUUIDRoutingTransportDialer) xrayUUIDRoutingContextQuery {
	if dial == nil {
		dial = dialXrayRoutingEndpoint
	}

	return func(ctx context.Context, runtime SessionRuntime, target RuntimeTarget, endpoint APIEndpoint, uuid string) (xrayUUIDRoutingContextQueryResult, error) {
		return queryXrayUUIDRoutingContexts(ctx, runtime, endpoint, uuid, dial)
	}
}

func queryXrayUUIDRoutingContexts(ctx context.Context, runtime SessionRuntime, endpoint APIEndpoint, uuid string, dial xrayUUIDRoutingTransportDialer) (xrayUUIDRoutingContextQueryResult, error) {
	if err := runtime.Validate(); err != nil {
		return xrayUUIDRoutingContextQueryResult{}, err
	}

	uuid = normalizeUUIDRoutingEvidenceKey(uuid)
	if uuid == "" {
		return xrayUUIDRoutingContextQueryResult{}, newXraySessionQueryError(
			SessionEvidenceIssueInsufficient,
			"Xray RoutingService querying requires a non-empty uuid",
		)
	}

	conn, closeConn, err := dial(ctx, endpoint)
	if err != nil {
		return xrayUUIDRoutingContextQueryResult{}, err
	}
	defer closeConn()

	stream, err := subscribeXrayRoutingStats(ctx, conn)
	if err != nil {
		return xrayUUIDRoutingContextQueryResult{}, newXraySessionQueryError(
			SessionEvidenceIssueUnavailable,
			"Xray RoutingService subscribe failed against %s: %v",
			describeAPIEndpoint(endpoint),
			err,
		)
	}

	result := xrayUUIDRoutingContextQueryResult{}
	for {
		message := dynamicpb.NewMessage(xrayRoutingDescriptorsForQuery().routingContext)
		err := stream.RecvMsg(message)
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			if len(result.Contexts) != 0 {
				result.Issues = append(result.Issues, SessionEvidenceIssue{
					Code:    SessionEvidenceIssueInsufficient,
					Message: fmt.Sprintf("Xray RoutingService stream ended after partial uuid routing evidence from %s: %v", describeAPIEndpoint(endpoint), err),
				})
				return result, nil
			}
			return xrayUUIDRoutingContextQueryResult{}, newXraySessionQueryError(
				SessionEvidenceIssueUnavailable,
				"Xray RoutingService stream failed for %s: %v",
				describeAPIEndpoint(endpoint),
				err,
			)
		}

		context, issue, ok := uuidRoutingContextFromDynamicMessage(runtime, uuid, endpoint, message)
		if issue != nil {
			result.Issues = append(result.Issues, *issue)
		}
		if ok {
			result.Contexts = append(result.Contexts, context)
		}
	}
}

func dialXrayRoutingEndpoint(ctx context.Context, endpoint APIEndpoint) (*grpc.ClientConn, func(), error) {
	if endpoint.TLS {
		return nil, nil, newXraySessionQueryError(
			SessionEvidenceIssueInsufficient,
			"Xray live uuid routing querying currently supports only insecure API endpoints; %s is not queryable",
			describeAPIEndpoint(endpoint),
		)
	}

	dialCtx, cancel := context.WithTimeout(ctx, xrayRoutingTransportTimeout)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}

	var target string
	switch endpoint.Network {
	case EndpointNetworkTCP:
		server, err := xrayGRPCServerAddress(endpoint)
		if err != nil {
			cancel()
			return nil, nil, err
		}
		target = server
	case EndpointNetworkUnix:
		socketPath := strings.TrimSpace(endpoint.Path)
		if socketPath == "" {
			cancel()
			return nil, nil, newXraySessionQueryError(
				SessionEvidenceIssueInsufficient,
				"Xray live uuid routing querying requires a concrete unix socket path; %s is incomplete",
				describeAPIEndpoint(endpoint),
			)
		}
		target = "unix:" + socketPath
		opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		}))
	default:
		cancel()
		return nil, nil, newXraySessionQueryError(
			SessionEvidenceIssueInsufficient,
			"Xray live uuid routing querying currently supports only TCP and unix API endpoints; %s is not queryable",
			describeAPIEndpoint(endpoint),
		)
	}

	conn, err := grpc.DialContext(dialCtx, target, opts...)
	if err != nil {
		cancel()
		code := SessionEvidenceIssueUnavailable
		if isPermissionError(err) {
			code = SessionEvidenceIssuePermissionDenied
		}
		return nil, nil, newXraySessionQueryError(
			code,
			"Xray RoutingService transport could not dial %s: %v",
			describeAPIEndpoint(endpoint),
			err,
		)
	}

	return conn, func() {
		cancel()
		_ = conn.Close()
	}, nil
}

func subscribeXrayRoutingStats(ctx context.Context, conn *grpc.ClientConn) (grpc.ClientStream, error) {
	descriptors := xrayRoutingDescriptorsForQuery()
	request := dynamicpb.NewMessage(descriptors.subscribeRequest)
	selectors := request.Mutable(descriptors.fields.subscribeSelectors).List()
	for _, selector := range xrayRoutingFieldSelectors {
		selectors.Append(protoreflect.ValueOfString(selector))
	}

	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, xrayRoutingServiceSubscribeMethod)
	if err != nil {
		return nil, err
	}
	if err := stream.SendMsg(request); err != nil {
		return nil, err
	}
	if err := stream.CloseSend(); err != nil {
		return nil, err
	}

	return stream, nil
}

func xrayRoutingDescriptorsForQuery() xrayRoutingDescriptors {
	xrayRoutingDescriptorOnce.Do(func() {
		file := buildXrayRoutingDescriptorFile()
		xrayRoutingDescriptorSet = xrayRoutingDescriptors{
			subscribeRequest: file.Messages().ByName("SubscribeRoutingStatsRequest"),
			routingContext:   file.Messages().ByName("RoutingContext"),
		}
		xrayRoutingDescriptorSet.fields = xrayRoutingDescriptorFields{
			subscribeSelectors: xrayRoutingDescriptorSet.subscribeRequest.Fields().ByNumber(1),
			inboundTag:         xrayRoutingDescriptorSet.routingContext.Fields().ByNumber(1),
			network:            xrayRoutingDescriptorSet.routingContext.Fields().ByNumber(2),
			sourceIPs:          xrayRoutingDescriptorSet.routingContext.Fields().ByNumber(3),
			targetIPs:          xrayRoutingDescriptorSet.routingContext.Fields().ByNumber(4),
			sourcePort:         xrayRoutingDescriptorSet.routingContext.Fields().ByNumber(5),
			targetPort:         xrayRoutingDescriptorSet.routingContext.Fields().ByNumber(6),
			targetDomain:       xrayRoutingDescriptorSet.routingContext.Fields().ByNumber(7),
			protocol:           xrayRoutingDescriptorSet.routingContext.Fields().ByNumber(8),
			user:               xrayRoutingDescriptorSet.routingContext.Fields().ByNumber(9),
			outboundTag:        xrayRoutingDescriptorSet.routingContext.Fields().ByNumber(12),
			localIPs:           xrayRoutingDescriptorSet.routingContext.Fields().ByNumber(13),
			localPort:          xrayRoutingDescriptorSet.routingContext.Fields().ByNumber(14),
		}
	})

	return xrayRoutingDescriptorSet
}

func buildXrayRoutingDescriptorFile() protoreflect.FileDescriptor {
	fileProto := &descriptorpb.FileDescriptorProto{
		Syntax:  stringPtr("proto3"),
		Name:    stringPtr("internal/discovery/xray_uuid_routing_transport.proto"),
		Package: stringPtr("raylimit.discovery"),
		EnumType: []*descriptorpb.EnumDescriptorProto{
			{
				Name: stringPtr("Network"),
				Value: []*descriptorpb.EnumValueDescriptorProto{
					{Name: stringPtr("Unknown"), Number: int32Ptr(0)},
					{Name: stringPtr("TCP"), Number: int32Ptr(2)},
					{Name: stringPtr("UDP"), Number: int32Ptr(3)},
					{Name: stringPtr("UNIX"), Number: int32Ptr(4)},
				},
			},
		},
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: stringPtr("SubscribeRoutingStatsRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   stringPtr("FieldSelectors"),
						Number: int32Ptr(1),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
					},
				},
			},
			{
				Name: stringPtr("RoutingContext"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: stringPtr("InboundTag"), Number: int32Ptr(1), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
					{Name: stringPtr("Network"), Number: int32Ptr(2), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_ENUM.Enum(), TypeName: stringPtr(".raylimit.discovery.Network")},
					{Name: stringPtr("SourceIPs"), Number: int32Ptr(3), Label: descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum()},
					{Name: stringPtr("TargetIPs"), Number: int32Ptr(4), Label: descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum()},
					{Name: stringPtr("SourcePort"), Number: int32Ptr(5), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_UINT32.Enum()},
					{Name: stringPtr("TargetPort"), Number: int32Ptr(6), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_UINT32.Enum()},
					{Name: stringPtr("TargetDomain"), Number: int32Ptr(7), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
					{Name: stringPtr("Protocol"), Number: int32Ptr(8), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
					{Name: stringPtr("User"), Number: int32Ptr(9), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
					{Name: stringPtr("OutboundTag"), Number: int32Ptr(12), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
					{Name: stringPtr("LocalIPs"), Number: int32Ptr(13), Label: descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum()},
					{Name: stringPtr("LocalPort"), Number: int32Ptr(14), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_UINT32.Enum()},
				},
			},
		},
	}

	file, err := protodesc.NewFile(fileProto, nil)
	if err != nil {
		panic(err)
	}

	return file
}

func uuidRoutingContextFromDynamicMessage(runtime SessionRuntime, uuid string, endpoint APIEndpoint, message *dynamicpb.Message) (UUIDRoutingContext, *SessionEvidenceIssue, bool) {
	descriptors := xrayRoutingDescriptorsForQuery()
	user := normalizeUUIDRoutingEvidenceKey(message.Get(descriptors.fields.user).String())
	if user == "" {
		issue := SessionEvidenceIssue{
			Code:    SessionEvidenceIssueInsufficient,
			Message: fmt.Sprintf("Xray RoutingService returned a routing context without user identity through API endpoint %s", describeAPIEndpoint(endpoint)),
		}
		return UUIDRoutingContext{}, &issue, false
	}
	if user != uuid {
		issue := SessionEvidenceIssue{
			Code:    SessionEvidenceIssueInsufficient,
			Message: fmt.Sprintf("Xray RoutingService returned routing evidence for user %q while UUID %q was requested through API endpoint %s", user, uuid, describeAPIEndpoint(endpoint)),
		}
		return UUIDRoutingContext{}, &issue, false
	}

	sourceIPs, err := bytesListToNormalizedRoutingIPs(message.Get(descriptors.fields.sourceIPs).List())
	if err != nil {
		issue := SessionEvidenceIssue{
			Code:    SessionEvidenceIssueInsufficient,
			Message: fmt.Sprintf("Xray RoutingService returned invalid source ip data for UUID %q through API endpoint %s: %v", uuid, describeAPIEndpoint(endpoint), err),
		}
		return UUIDRoutingContext{}, &issue, false
	}
	targetIPs, err := bytesListToNormalizedRoutingIPs(message.Get(descriptors.fields.targetIPs).List())
	if err != nil {
		issue := SessionEvidenceIssue{
			Code:    SessionEvidenceIssueInsufficient,
			Message: fmt.Sprintf("Xray RoutingService returned invalid target ip data for UUID %q through API endpoint %s: %v", uuid, describeAPIEndpoint(endpoint), err),
		}
		return UUIDRoutingContext{}, &issue, false
	}
	localIPs, err := bytesListToNormalizedRoutingIPs(message.Get(descriptors.fields.localIPs).List())
	if err != nil {
		issue := SessionEvidenceIssue{
			Code:    SessionEvidenceIssueInsufficient,
			Message: fmt.Sprintf("Xray RoutingService returned invalid local ip data for UUID %q through API endpoint %s: %v", uuid, describeAPIEndpoint(endpoint), err),
		}
		return UUIDRoutingContext{}, &issue, false
	}

	context := UUIDRoutingContext{
		Runtime:      runtime,
		UUID:         uuid,
		Network:      xrayRoutingNetworkLabel(message.Get(descriptors.fields.network).Enum()),
		InboundTag:   strings.TrimSpace(message.Get(descriptors.fields.inboundTag).String()),
		OutboundTag:  strings.TrimSpace(message.Get(descriptors.fields.outboundTag).String()),
		Protocol:     strings.ToLower(strings.TrimSpace(message.Get(descriptors.fields.protocol).String())),
		TargetDomain: strings.TrimSpace(message.Get(descriptors.fields.targetDomain).String()),
		SourceIPs:    sourceIPs,
		LocalIPs:     localIPs,
		TargetIPs:    targetIPs,
		SourcePort:   int(message.Get(descriptors.fields.sourcePort).Uint()),
		LocalPort:    int(message.Get(descriptors.fields.localPort).Uint()),
		TargetPort:   int(message.Get(descriptors.fields.targetPort).Uint()),
		Confidence:   SessionEvidenceConfidenceHigh,
		Note:         fmt.Sprintf("observed via Xray RoutingService subscription through API endpoint %s", describeAPIEndpoint(endpoint)),
	}
	if err := context.Validate(); err != nil {
		issue := SessionEvidenceIssue{
			Code:    SessionEvidenceIssueInsufficient,
			Message: fmt.Sprintf("Xray RoutingService returned invalid routing evidence for UUID %q through API endpoint %s: %v", uuid, describeAPIEndpoint(endpoint), err),
		}
		return UUIDRoutingContext{}, &issue, false
	}

	return context, nil, true
}

func xrayRoutingNetworkLabel(value protoreflect.EnumNumber) string {
	switch value {
	case 2:
		return "tcp"
	case 3:
		return "udp"
	case 4:
		return "unix"
	default:
		return ""
	}
}

func bytesListToNormalizedRoutingIPs(list protoreflect.List) ([]string, error) {
	if list.Len() == 0 {
		return nil, nil
	}

	ips := make([]string, 0, list.Len())
	for index := 0; index < list.Len(); index++ {
		raw := list.Get(index).Bytes()
		addr, ok := netip.AddrFromSlice(raw)
		if !ok {
			return nil, fmt.Errorf("field entry %d did not contain a valid ip address", index)
		}
		ips = append(ips, addr.Unmap().String())
	}

	return normalizeUUIDRoutingIPs(ips)
}

func xrayGRPCServerAddress(endpoint APIEndpoint) (string, error) {
	if endpoint.Network != EndpointNetworkTCP {
		return "", newXraySessionQueryError(
			SessionEvidenceIssueInsufficient,
			"Xray live uuid routing querying currently supports TCP API server addressing only for non-unix endpoints; %s is not queryable",
			describeAPIEndpoint(endpoint),
		)
	}
	if endpoint.Port <= 0 {
		return "", newXraySessionQueryError(
			SessionEvidenceIssueInsufficient,
			"Xray live uuid routing querying requires a concrete TCP port; %s is incomplete",
			describeAPIEndpoint(endpoint),
		)
	}

	host := strings.TrimSpace(endpoint.Address)
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}

	return net.JoinHostPort(host, fmt.Sprintf("%d", endpoint.Port)), nil
}

func stringPtr(value string) *string {
	return &value
}

func int32Ptr(value int32) *int32 {
	return &value
}
