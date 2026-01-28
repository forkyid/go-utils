package sd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery/types"
	"github.com/forkyid/go-utils/v1/logger"
)

var Instance *Registrar
var defaultInterval = 60
var ErrNamespaceNameNotExists = errors.New("NamespaceName doesn't exist")
var ErrNoBackendEntry = errors.New("No backend entry in the service registry")

type Registrar struct {
	mapExist map[string]bool

	SRegistry map[string]*ServiceRegistry
}

// A Config provides service configuration for service discovery.
type Config struct {
	// The HttpName name of the namespace.
	NamespaceName *string

	// Interval is a variable that determines how frequently the app service updates the stored addresses
	// by comparing them to the service registry. Seconds are the units of Interval use.
	Interval *int

	Registrar *Registrar
}

// ServiceDiscovery Type
type ServiceDiscovery struct {
	Config *Config
}

type Backend struct {
	Addr       string `json:"address"`
	InstanceID string `json:"instance_id"`
}

type ServiceRegistry struct {
	BackendsStore atomic.Value
}

type DiscoverInstancesOutput map[string][]Backend

// Update the addresses obtained from the service registry.
func DiscoverInstances(r *Registrar, namespaceName string) (DiscoverInstancesOutput, error) {
	cfg, _ := config.LoadDefaultConfig(context.TODO(), config.WithRegion(os.Getenv("AWS_REGION")))
	svcDiscovery := servicediscovery.NewFromConfig(cfg)
	resp := DiscoverInstancesOutput{}
	for svcName := range r.SRegistry {
		input := &servicediscovery.DiscoverInstancesInput{
			HealthStatus:  types.HealthStatusFilterHealthy,
			NamespaceName: &namespaceName,
			ServiceName:   &svcName,
		}
		result, err := svcDiscovery.DiscoverInstances(context.TODO(), input)
		if err != nil {
			logger.Errorf(nil, err.Error(), nil)
		} else {
			var backends []Backend

			for _, instance := range result.Instances {
				backends = append(backends, Backend{
					Addr: fmt.Sprintf("http://%s:%s",
						instance.Attributes["AWS_INSTANCE_IPV4"],
						instance.Attributes["AWS_INSTANCE_PORT"],
					),
					InstanceID: *instance.InstanceId,
				})
			}
			r.SRegistry[svcName].BackendsStore.Store(backends)
			resp[svcName] = backends
		}
	}
	return resp, nil
}

// Call the service registry periodically.
func callServerEvery(sd *ServiceDiscovery) {
	for {
		<-time.After(time.Duration(*sd.Config.Interval) * time.Second)
		go DiscoverInstances(sd.Config.Registrar, *sd.Config.NamespaceName)
	}
}

func NewRegistry() *ServiceRegistry {
	sr := ServiceRegistry{}
	sr.BackendsStore.Store([]Backend{})

	return &sr
}

// Initialize Service Discovery.
func NewServiceDiscovery(cfgs ...*Config) (*ServiceDiscovery, error) {
	cfg := &Config{}
	for _, attr := range cfgs {
		if attr.NamespaceName != nil {
			cfg.NamespaceName = attr.NamespaceName
		}

		if attr.Interval != nil {
			cfg.Interval = attr.Interval
		} else {
			cfg.Interval = &defaultInterval
		}

		if attr.Registrar != nil {
			cfg.Registrar = attr.Registrar
		}
	}

	if *cfg.NamespaceName == "" {
		return nil, ErrNamespaceNameNotExists
	}

	DiscoverInstances(cfg.Registrar, *cfg.NamespaceName)

	return &ServiceDiscovery{
		Config: cfg,
	}, nil
}

func InitRegistrar(serviceNames ...string) *Registrar {
	if Instance == nil {
		Instance = &Registrar{
			mapExist:  make(map[string]bool, 0),
			SRegistry: make(map[string]*ServiceRegistry, 0),
		}
	}

	Instance.AddServices(append(serviceNames, os.Getenv("GET_ACCOUNT_STATUS_SERVICE_NAME"), os.Getenv("CHECK_AUTH_TOKEN_SERVICE_NAME"))...)
	return Instance
}

func (r *Registrar) AddServices(serviceNames ...string) {
	for _, serviceName := range serviceNames {
		if !r.mapExist[serviceName] {
			r.SRegistry[serviceName] = NewRegistry()
			r.mapExist[serviceName] = true
		}
	}
}

func (r *Registrar) GetService(serviceName string) *ServiceRegistry {
	return r.SRegistry[serviceName]
}

// Run Service Discovery
func (sd *ServiceDiscovery) Run() {
	go callServerEvery(sd)
}

func (sr *ServiceRegistry) Len() int {
	return len(sr.GetBackends())
}

func (sr *ServiceRegistry) GetBackends() []Backend {
	return sr.BackendsStore.Load().([]Backend)
}

func (sr *ServiceRegistry) GetHostByIndex(index int) string {
	return sr.GetBackends()[index].Addr
}

func (sr *ServiceRegistry) GetHost(reqCount *uint64, fallbackHost string) string {
	if sr.Len() == 0 {
		logger.Errorf(nil, ErrNoBackendEntry.Error(), nil)
		return fallbackHost
	}
	atomic.AddUint64(reqCount, 1)
	return sr.GetHostByIndex(int(atomic.LoadUint64(reqCount) % uint64(sr.Len())))
}
