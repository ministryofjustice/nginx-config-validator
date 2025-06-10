package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	apiv1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	rootLocation = "/"
)

var (
	pathTypeExact  = networking.PathTypeExact
	pathTypePrefix = networking.PathTypePrefix
)

// getConfiguration returns the configuration matching the standard kubernetes ingress
func (n *controller.NGINXController) getConfiguration(ingresses []*Ingress) (sets.Set[string], []*Server, *Configuration) {
	upstreams, servers := n.getBackendServers(ingresses)
	var passUpstreams []*SSLPassthroughBackend

	hosts := sets.New[string]()

	for _, server := range servers {
		// If a location is defined by a prefix string that ends with the slash character, and requests are processed by one of
		// proxy_pass, fastcgi_pass, uwsgi_pass, scgi_pass, memcached_pass, or grpc_pass, then the special processing is performed.
		// In response to a request with URI equal to // this string, but without the trailing slash, a permanent redirect with the
		// code 301 will be returned to the requested URI with the slash appended. If this is not desired, an exact match of the
		// URIand location could be defined like this:
		//
		// location /user/ {
		//     proxy_pass http://user.example.com;
		// }
		// location = /user {
		//     proxy_pass http://login.example.com;
		// }
		server.Locations = updateServerLocations(server.Locations)

		if !hosts.Has(server.Hostname) {
			hosts.Insert(server.Hostname)
		}

		for _, alias := range server.Aliases {
			if !hosts.Has(alias) {
				hosts.Insert(alias)
			}
		}

		if !server.SSLPassthrough {
			continue
		}

		for _, loc := range server.Locations {
			if loc.Path != rootLocation {
				log.Println("Ignoring SSL Passthrough for location %q in server %q", loc.Path, server.Hostname)
				continue
			}
			passUpstreams = append(passUpstreams, &SSLPassthroughBackend{
				Backend:  loc.Backend,
				Hostname: server.Hostname,
				Service:  loc.Service,
				Port:     loc.Port,
			})
			break
		}
	}

	return hosts, servers, &Configuration{
		Backends:              upstreams,
		Servers:               servers,
		TCPEndpoints:          n.getStreamServices(n.cfg.TCPConfigMapName, apiv1.ProtocolTCP),
		UDPEndpoints:          n.getStreamServices(n.cfg.UDPConfigMapName, apiv1.ProtocolUDP),
		PassthroughBackends:   passUpstreams,
		BackendConfigChecksum: n.store.GetBackendConfiguration().Checksum,
		DefaultSSLCertificate: n.getDefaultSSLCertificate(),
		StreamSnippets:        n.getStreamSnippets(ingresses),
	}
}

// updateServerLocations inspects the generated locations configuration for a server
// normalizing the path and adding an additional exact location when is possible
func updateServerLocations(locations []*Location) []*Location {
	newLocations := []*Location{}

	// get Exact locations to check if one already exists
	exactLocations := map[string]*Location{}
	for _, location := range locations {
		if *location.PathType == pathTypeExact {
			exactLocations[location.Path] = location
		}
	}

	for _, location := range locations {
		// location / does not require any update
		if location.Path == rootLocation {
			newLocations = append(newLocations, location)
			continue
		}

		location.IngressPath = location.Path

		// only Prefix locations could require an additional location block
		if *location.PathType != pathTypePrefix {
			newLocations = append(newLocations, location)
			continue
		}

		// locations with rewrite or using regular expressions are not modified
		if needsRewrite(location) || location.Rewrite.UseRegex {
			newLocations = append(newLocations, location)
			continue
		}

		// If exists an Exact location is not possible to create a new one.
		if _, alreadyExists := exactLocations[location.Path]; alreadyExists {
			// normalize path. Must end in /
			location.Path = normalizePrefixPath(location.Path)
			newLocations = append(newLocations, location)
			continue
		}

		var el Location = *location

		// normalize path. Must end in /
		location.Path = normalizePrefixPath(location.Path)
		newLocations = append(newLocations, location)

		// add exact location
		exactLocation := &el
		exactLocation.PathType = &pathTypeExact

		newLocations = append(newLocations, exactLocation)
	}

	return newLocations
}

func normalizePrefixPath(path string) string {
	if path == rootLocation {
		return rootLocation
	}

	if !strings.HasSuffix(path, "/") {
		return fmt.Sprintf("%v/", path)
	}

	return path
}

func needsRewrite(location *Location) bool {
	if location.Rewrite.Target != "" && location.Rewrite.Target != location.Path {
		return true
	}

	return false
}

// Test checks if config file is a syntax valid nginx configuration
func Test(cfg string) ([]byte, error) {
	//nolint:gosec // Ignore G204 error
	return exec.Command("nc.Binary", "-c", cfg, "-t").CombinedOutput() // TODO: use right binary location
}
