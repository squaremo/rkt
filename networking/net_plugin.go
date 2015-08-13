// Copyright 2015 The rkt Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package networking

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/appc/cni/pkg/invoke"
	"github.com/appc/cni/pkg/types"

	"github.com/coreos/rkt/common"
)

// TODO(eyakubovich): make this configurable in rkt.conf
const UserNetPluginsPath = "/usr/lib/rkt/plugins/net"
const BuiltinNetPluginsPath = "usr/lib/rkt/plugins/net"

func (e *podEnv) netPluginAdd(n *activeNet, netns string) (ip, hostIP net.IP, err error) {
	result, err := e.execNetPlugin("ADD", n, netns)
	if err != nil {
		return nil, nil, err
	}

	if result.IP4 == nil {
		return nil, nil, fmt.Errorf("net-plugin returned no IPv4 configuration")
	}

	return result.IP4.IP.IP, result.IP4.Gateway, nil
}

func (e *podEnv) netPluginDel(n *activeNet, netns string) error {
	_, err := e.execNetPlugin("DEL", n, netns)
	return err
}

func (e *podEnv) pluginPaths() []string {
	// try 3rd-party path first
	return []string{
		UserNetPluginsPath,
		filepath.Join(common.Stage1RootfsPath(e.podRoot), BuiltinNetPluginsPath),
	}
}

func (e *podEnv) findNetPlugin(plugin string) string {
	return invoke.FindInPath(plugin, e.pluginPaths())
}

func envVars(vars [][2]string) []string {
	env := os.Environ()

	for _, kv := range vars {
		env = append(env, strings.Join(kv[:], "="))
	}

	return env
}

func (e *podEnv) execNetPlugin(cmd string, n *activeNet, netns string) (*types.Result, error) {
	pluginPath := e.findNetPlugin(n.conf.Type)
	if pluginPath == "" {
		return nil, fmt.Errorf("Could not find plugin %q", n.conf.Type)
	}

	vars := [][2]string{
		{"CNI_COMMAND", cmd},
		{"CNI_CONTAINERID", e.podID.String()},
		{"CNI_NETNS", netns},
		{"CNI_ARGS", n.runtime.Args},
		{"CNI_IFNAME", n.runtime.IfName},
		{"CNI_PATH", strings.Join(e.pluginPaths(), ":")},
	}
	return invoke.ExecPlugin(pluginPath, n.confBytes, envVars(vars))
}
