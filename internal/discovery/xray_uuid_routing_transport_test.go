package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

type testRoutingStatsService interface{}

type testRoutingStatsServer struct {
	subscribe func(request *dynamicpb.Message, stream grpc.ServerStream) error
}

func (s *testRoutingStatsServer) handleSubscribe(stream grpc.ServerStream) error {
	request := dynamicpb.NewMessage(xrayRoutingDescriptorsForQuery().subscribeRequest)
	if err := stream.RecvMsg(request); err != nil {
		return err
	}

	return s.subscribe(request, stream)
}

func startTestRoutingStatsServer(t *testing.T, subscribe func(request *dynamicpb.Message, stream grpc.ServerStream) error) (xrayUUIDRoutingTransportDialer, func()) {
	t.Helper()

	listener := bufconn.Listen(1 << 20)

	server := grpc.NewServer()
	handler := &testRoutingStatsServer{subscribe: subscribe}
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "xray.app.router.command.RoutingService",
		HandlerType: (*testRoutingStatsService)(nil),
		Streams: []grpc.StreamDesc{{
			StreamName:    "SubscribeRoutingStats",
			ServerStreams: true,
			Handler: func(srv any, stream grpc.ServerStream) error {
				return srv.(*testRoutingStatsServer).handleSubscribe(stream)
			},
		}},
	}, handler)

	go func() {
		_ = server.Serve(listener)
	}()

	dialer := func(ctx context.Context, _ APIEndpoint) (*grpc.ClientConn, func(), error) {
		conn, err := grpc.DialContext(ctx, "bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		if err != nil {
			return nil, nil, err
		}

		return conn, func() {
			_ = conn.Close()
		}, nil
	}

	return dialer, func() {
		server.Stop()
		_ = listener.Close()
	}
}

func writeUUIDRoutingAPIConfig(t *testing.T, port int) string {
	t.Helper()

	return writeXrayAPIConfig(t, fmt.Sprintf(`{
  "api": {"tag":"api","services":["RoutingService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":%d}],
  "routing": {
    "rules": [
      {"type":"field","user":["user-a"],"outboundTag":"proxy-out"}
    ]
  }
}`, port))
}

func testRoutingSelectors(request *dynamicpb.Message) []string {
	fields := xrayRoutingDescriptorsForQuery().fields
	values := request.Get(fields.subscribeSelectors).List()
	selectors := make([]string, 0, values.Len())
	for index := 0; index < values.Len(); index++ {
		selectors = append(selectors, values.Get(index).String())
	}

	return selectors
}

func newTestRoutingContextMessage(t *testing.T, uuid string, network protoreflect.EnumNumber, sourceIPs []string, localIPs []string) *dynamicpb.Message {
	t.Helper()

	fields := xrayRoutingDescriptorsForQuery().fields
	message := dynamicpb.NewMessage(xrayRoutingDescriptorsForQuery().routingContext)
	message.Set(fields.user, protoreflect.ValueOfString(uuid))
	message.Set(fields.network, protoreflect.ValueOfEnum(network))
	message.Set(fields.inboundTag, protoreflect.ValueOfString("socks-in"))
	message.Set(fields.outboundTag, protoreflect.ValueOfString("proxy-out"))
	message.Set(fields.protocol, protoreflect.ValueOfString("tls"))
	message.Set(fields.targetDomain, protoreflect.ValueOfString("example.net"))
	message.Set(fields.sourcePort, protoreflect.ValueOfUint32(43120))
	message.Set(fields.localPort, protoreflect.ValueOfUint32(8443))
	message.Set(fields.targetPort, protoreflect.ValueOfUint32(443))

	sourceList := message.Mutable(fields.sourceIPs).List()
	for _, value := range sourceIPs {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			t.Fatalf("parse source ip %q: %v", value, err)
		}
		sourceList.Append(protoreflect.ValueOfBytes(addr.AsSlice()))
	}

	localList := message.Mutable(fields.localIPs).List()
	for _, value := range localIPs {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			t.Fatalf("parse local ip %q: %v", value, err)
		}
		localList.Append(protoreflect.ValueOfBytes(addr.AsSlice()))
	}

	return message
}

func TestXrayUUIDRoutingEvidenceProviderBuiltInTransportIngestsLiveRoutingStats(t *testing.T) {
	dialer, cleanup := startTestRoutingStatsServer(t, func(request *dynamicpb.Message, stream grpc.ServerStream) error {
		selectors := strings.Join(testRoutingSelectors(request), ",")
		if !strings.Contains(selectors, "user") || !strings.Contains(selectors, "port_local") || !strings.Contains(selectors, "ip_local") {
			t.Fatalf("expected uuid routing selectors to include user and local flow fields, got %q", selectors)
		}

		message := newTestRoutingContextMessage(t, "user-a", 2, []string{"2001:db8::10", "::ffff:203.0.113.10"}, []string{"2001:db8::20"})
		return stream.SendMsg(message)
	})
	defer cleanup()

	configPath := writeUUIDRoutingAPIConfig(t, 10085)
	provider := NewXrayUUIDRoutingEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.DialRoutingTransport = dialer
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }

	result, err := provider.ObserveUUIDRoutingEvidence(context.Background(), testXrayEvidenceRuntime(), "user-a")
	if err != nil {
		t.Fatalf("expected live uuid routing evidence observation to succeed, got %v", err)
	}

	if result.State() != UUIDRoutingEvidenceStateLive {
		t.Fatalf("expected live routing evidence state, got %#v", result)
	}
	if result.Candidate == nil || result.Candidate.Status != UUIDNonIPBackendStatusCandidate {
		t.Fatalf("expected routing candidate metadata to be preserved, got %#v", result.Candidate)
	}
	if len(result.Contexts) != 1 {
		t.Fatalf("expected one live routing context, got %#v", result.Contexts)
	}
	context := result.Contexts[0]
	if context.Network != "tcp" || context.Protocol != "tls" {
		t.Fatalf("expected normalized network/protocol fields, got %#v", context)
	}
	if len(context.SourceIPs) != 2 || context.SourceIPs[0] != "2001:db8::10" || context.SourceIPs[1] != "203.0.113.10" {
		t.Fatalf("expected ipv6-aware source ip preservation, got %#v", context.SourceIPs)
	}
	if len(context.LocalIPs) != 1 || context.LocalIPs[0] != "2001:db8::20" {
		t.Fatalf("expected ipv6 local ip preservation, got %#v", context.LocalIPs)
	}
	if context.SourcePort != 43120 || context.LocalPort != 8443 || context.TargetPort != 443 {
		t.Fatalf("expected port evidence to be preserved, got %#v", context)
	}
}

func TestXrayUUIDRoutingEvidenceProviderBuiltInTransportReportsUnavailableWhenDialFails(t *testing.T) {
	configPath := writeUUIDRoutingAPIConfig(t, 10085)
	provider := NewXrayUUIDRoutingEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.DialRoutingTransport = func(context.Context, APIEndpoint) (*grpc.ClientConn, func(), error) {
		return nil, nil, newXraySessionQueryError(SessionEvidenceIssueUnavailable, "Xray RoutingService transport could not dial %s: %v", "tcp://127.0.0.1:10085", errors.New("buf transport unavailable"))
	}

	result, err := provider.ObserveUUIDRoutingEvidence(context.Background(), testXrayEvidenceRuntime(), "user-a")
	if err != nil {
		t.Fatalf("expected unavailable uuid routing evidence observation to succeed, got %v", err)
	}

	if result.State() != UUIDRoutingEvidenceStateUnavailable {
		t.Fatalf("expected unavailable routing evidence state, got %#v", result)
	}
	if len(result.Issues) != 1 || !strings.Contains(result.Issues[0].Message, "transport could not dial") {
		t.Fatalf("expected transport dial failure issue, got %#v", result.Issues)
	}
}

func TestXrayUUIDRoutingEvidenceProviderBuiltInTransportMarksPartialOnExactUserMismatch(t *testing.T) {
	dialer, cleanup := startTestRoutingStatsServer(t, func(request *dynamicpb.Message, stream grpc.ServerStream) error {
		_ = request
		if err := stream.SendMsg(newTestRoutingContextMessage(t, "user-a", 2, []string{"203.0.113.10"}, []string{"2001:db8::20"})); err != nil {
			return err
		}
		return stream.SendMsg(newTestRoutingContextMessage(t, "other-user", 2, []string{"203.0.113.11"}, []string{"2001:db8::21"}))
	})
	defer cleanup()

	configPath := writeUUIDRoutingAPIConfig(t, 10085)
	provider := NewXrayUUIDRoutingEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.DialRoutingTransport = dialer
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }

	result, err := provider.ObserveUUIDRoutingEvidence(context.Background(), testXrayEvidenceRuntime(), "user-a")
	if err != nil {
		t.Fatalf("expected partial uuid routing evidence observation to succeed, got %v", err)
	}

	if result.State() != UUIDRoutingEvidenceStatePartial {
		t.Fatalf("expected partial routing evidence state, got %#v", result)
	}
	if len(result.Contexts) != 1 {
		t.Fatalf("expected only the exact-user routing context to survive, got %#v", result.Contexts)
	}
	if len(result.Issues) != 1 || !strings.Contains(result.Issues[0].Message, "other-user") {
		t.Fatalf("expected exact-user mismatch issue, got %#v", result.Issues)
	}
}
