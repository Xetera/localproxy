package discovery

import "sort"

type PortProtocol string

const (
	ProtocolHTTP PortProtocol = "http"
	ProtocolTCP  PortProtocol = "tcp"
)

type WellKnownPort struct {
	Port      int
	Subdomain string
	Protocol  PortProtocol
	TCPPort   int
}

func GetAllWellKnownPorts() []WellKnownPort {
	var result []WellKnownPort
	for port, info := range WellKnownPorts {
		result = append(result, WellKnownPort{
			Port:      port,
			Subdomain: info.Subdomain,
			Protocol:  info.Protocol,
			TCPPort:   info.TCPPort,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Subdomain < result[j].Subdomain
	})
	return result
}

type WellKnownPortInfo struct {
	Subdomain string
	Protocol  PortProtocol
	TCPPort   int
}

var WellKnownPorts = map[int]WellKnownPortInfo{
	8384:  {"syncthing", ProtocolHTTP, 0},
	5432:  {"postgres", ProtocolTCP, 15432},
	6379:  {"redis", ProtocolTCP, 16379},
	9200:  {"elasticsearch", ProtocolHTTP, 0},
	27017: {"mongodb", ProtocolTCP, 17017},
	15672: {"rabbitmq", ProtocolHTTP, 0},
	8161:  {"activemq", ProtocolHTTP, 0},
	11211: {"memcached", ProtocolTCP, 21211},
	7474:  {"neo4j", ProtocolHTTP, 0},
	5601:  {"kibana", ProtocolHTTP, 0},
	3306:  {"mysql", ProtocolTCP, 13306},
	1433:  {"mssql", ProtocolTCP, 11433},
	4369:  {"epmd", ProtocolTCP, 14369},
	9042:  {"cassandra", ProtocolTCP, 19042},
	2181:  {"zookeeper", ProtocolTCP, 12181},
	9092:  {"kafka", ProtocolTCP, 19092},
	8983:  {"solr", ProtocolHTTP, 0},
	5672:  {"amqp", ProtocolTCP, 15672},
	1883:  {"mqtt", ProtocolTCP, 11883},
	8086:  {"influxdb", ProtocolHTTP, 0},
	3100:  {"loki", ProtocolHTTP, 0},
	3200:  {"tempo", ProtocolHTTP, 0},
	16686: {"jaeger", ProtocolHTTP, 0},
	9411:  {"zipkin", ProtocolHTTP, 0},
	4317:  {"otel", ProtocolTCP, 14317},
	8300:  {"consul", ProtocolTCP, 18300},
	8500:  {"consulhttp", ProtocolHTTP, 0},
	8200:  {"vault", ProtocolHTTP, 0},
}
