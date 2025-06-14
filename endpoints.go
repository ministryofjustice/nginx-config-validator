package main

import (
	"fmt"
)

// getEndpointsFromSlices returns a list of Endpoint structs for a given service/target port combination.
func getEndpointsFromSlices(s *corev1.Service, port *corev1.ServicePort, proto corev1.Protocol, zoneForHints string,
	getServiceEndpointsSlices func(string) ([]*discoveryv1.EndpointSlice, error),
) []Endpoint {
	upsServers := []Endpoint{}

	if s == nil || port == nil {
		return upsServers
	}

	// we need to check if there is at least one endpoint with controller zone
	// if we use traffic distribution
	useTrafficDistribution := s.Spec.TrafficDistribution != nil && *s.Spec.TrafficDistribution == corev1.ServiceTrafficDistributionPreferClose

	// using a map avoids duplicated upstream servers when the service
	// contains multiple port definitions sharing the same targetport
	processedUpstreamServers := make(map[string]struct{})

	svcKey := k8s.MetaNamespaceKey(s)
	var useTopologyHints bool

	// ExternalName services
	if s.Spec.Type == corev1.ServiceTypeExternalName {
		if ip := net.ParseIP(s.Spec.ExternalName); s.Spec.ExternalName == "localhost" ||
			(ip != nil && ip.IsLoopback()) {
			klog.Errorf("Invalid attempt to use localhost name %s in %q", s.Spec.ExternalName, svcKey)
			return upsServers
		}

		klog.V(3).Infof("Ingress using Service %q of type ExternalName.", svcKey)
		targetPort := port.TargetPort.IntValue()
		// if the externalName is not an IP address we need to validate is a valid FQDN
		if net.ParseIP(s.Spec.ExternalName) == nil {
			externalName := strings.TrimSuffix(s.Spec.ExternalName, ".")
			if errs := validation.IsDNS1123Subdomain(externalName); len(errs) > 0 {
				klog.Errorf("Invalid DNS name %s: %v", s.Spec.ExternalName, errs)
				return upsServers
			}
		}

		return append(upsServers, Endpoint{
			Address: s.Spec.ExternalName,
			Port:    fmt.Sprintf("%v", targetPort),
		})
	}

	klog.V(3).Infof("Getting Endpoints from endpointSlices for Service %q and port %v", svcKey, port.String())
	epss, err := getServiceEndpointsSlices(svcKey)
	if err != nil {
		klog.Warningf("Error obtaining Endpoints for Service %q: %v", svcKey, err)
		return upsServers
	}
	// loop over all endpointSlices generated for service
	for _, eps := range epss {
		var ports []int32
		if len(eps.Ports) == 0 && port.TargetPort.Type == intstr.Int {
			// When ports is empty, it indicates that there are no defined ports, using svc targePort if it's a number
			klog.V(3).Infof("No ports found on endpointSlice, using service TargetPort %v for Service %q", port.String(), svcKey)
			ports = append(ports, port.TargetPort.IntVal)
		} else {
			for _, epPort := range eps.Ports {
				if !reflect.DeepEqual(*epPort.Protocol, proto) {
					continue
				}
				var targetPort int32
				if port.Name == "" {
					// port.Name is optional if there is only one port
					targetPort = *epPort.Port
				} else if port.Name == *epPort.Name {
					targetPort = *epPort.Port
				}
				if targetPort == 0 && port.TargetPort.Type == intstr.Int {
					// use service target port if it's a number and no port name matched
					// https://github.com/kubernetes/ingress-nginx/issues/7390
					targetPort = port.TargetPort.IntVal
				}
				if targetPort == 0 {
					continue
				}
				ports = append(ports, targetPort)
			}
		}
		useTopologyHints = false
		if zoneForHints != emptyZone {
			useTopologyHints = true

			// check if endpointslices have zone hints with controller zone
			if useTrafficDistribution {
				foundEndpointsForZone := false
				for _, ep := range eps.Endpoints {
					if ep.Hints == nil {
						continue
					}
					for _, epzone := range ep.Hints.ForZones {
						if epzone.Name == zoneForHints {
							foundEndpointsForZone = true
							break
						}
					}
				}
				if !foundEndpointsForZone {
					klog.V(3).Infof("No endpoints found for zone %q in Service %q", zoneForHints, svcKey)
					useTopologyHints = false
				}
			}

			// check if all endpointslices have zone hints
			for _, ep := range eps.Endpoints {
				if ep.Hints == nil || len(ep.Hints.ForZones) == 0 {
					useTopologyHints = false
					break
				}
			}
			if useTopologyHints {
				klog.V(3).Infof("All endpoint slices has zone hint, using zone %q for Service %q", zoneForHints, svcKey)
			}
		}

		for _, ep := range eps.Endpoints {
			if (ep.Conditions.Ready != nil) && !(*ep.Conditions.Ready) {
				continue
			}
			epHasZone := false
			if useTopologyHints {
				for _, epzone := range ep.Hints.ForZones {
					if epzone.Name == zoneForHints {
						epHasZone = true
						break
					}
				}
			}

			if useTopologyHints && !epHasZone {
				continue
			}

			for _, epPort := range ports {
				for _, epAddress := range ep.Addresses {
					hostPort := net.JoinHostPort(epAddress, strconv.Itoa(int(epPort)))
					if _, exists := processedUpstreamServers[hostPort]; exists {
						continue
					}
					ups := Endpoint{
						Address: epAddress,
						Port:    fmt.Sprintf("%v", epPort),
						Target:  ep.TargetRef,
					}
					upsServers = append(upsServers, ups)
					processedUpstreamServers[hostPort] = struct{}{}
				}
			}
		}
	}

	klog.V(3).Infof("Endpoints found for Service %q: %v", svcKey, upsServers)
	return upsServers
}
