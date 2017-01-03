// Copyright © 2016 Porthole authors & AB Kvällstidningen Expressen <infra@expressen.se>
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

package cmd

import (
	"fmt"
	"time"

	"github.com/cldmnky/vault-jwt-go"
	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/cobra"
)

var (
	containerId string
	command     string
)

// get-tokenCmd represents the get-token command
var getTokenCmd = &cobra.Command{
	Use:   "get-token",
	Short: "get-token generates valid jwt tokens/headers",
	Long: `use get token to generate a valid "Authorization: bearer <string>
for use with porthole serve.
	Example:
		porthole get-token -t <containerid> <command>
	and that's all I have to say about that.`,
	Run: func(cmd *cobra.Command, args []string) {
		claims := PortholeClaims{
			containerId,
			[]string{command},
			true,
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(1500).Unix(),
				Issuer:    "test",
				Subject:   "username",
			},
		}
		vaultConfig.Address = vaultAddr
		config := vault_jwt.Config{
			vaultConfig,
			vaultPath,
			vaultToken,
			false,
		}
		token := jwt.NewWithClaims(jwt.GetSigningMethod("Vault"), claims)
		ss, _ := token.SignedString(config)
		fmt.Printf("Authorization: bearer %s", ss)
	},
}

func init() {
	RootCmd.AddCommand(getTokenCmd)
	getTokenCmd.PersistentFlags().StringVar(&containerId, "containerid", "mycontainer", "Container ID")
	getTokenCmd.PersistentFlags().StringVar(&command, "command", "/bin/sh", "Command")

}
