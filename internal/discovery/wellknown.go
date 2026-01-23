package discovery

import "sort"

type WellKnownPort struct {
	Port      int
	Subdomain string
}

func GetAllWellKnownPorts() []WellKnownPort {
	var result []WellKnownPort
	for port, subdomain := range WellKnownPorts {
		result = append(result, WellKnownPort{Port: port, Subdomain: subdomain})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Subdomain < result[j].Subdomain
	})
	return result
}

var WellKnownPorts = map[int]string{
	8384:  "syncthing",
	5432:  "postgres",
	6379:  "redis",
	9200:  "elasticsearch",
	27017: "mongodb",
	15672: "rabbitmq",
	8161:  "activemq",
	11211: "memcached",
	7474:  "neo4j",
	5601:  "kibana",
	3306:  "mysql",
	1433:  "mssql",
	4369:  "epmd",
	9042:  "cassandra",
	2181:  "zookeeper",
	9092:  "kafka",
	8983:  "solr",
	5672:  "amqp",
	1883:  "mqtt",
	8086:  "influxdb",
	3100:  "loki",
	3200:  "tempo",
	16686: "jaeger",
	9411:  "zipkin",
	4317:  "otel",
	8300:  "consul",
	8500:  "consulhttp",
	8200:  "vault",
}
