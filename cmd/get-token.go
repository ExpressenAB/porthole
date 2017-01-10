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
	"log"
	"strings"
	"time"

	"github.com/cldmnky/vault-jwt-go"
	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	pskFile string
	ss      string
)

// get-tokenCmd represents the get-token command
var getTokenCmd = &cobra.Command{
	Use:   "get-token",
	Short: "get-token generates valid jwt tokens/headers",
	Long: `use get token to generate a valid "Authorization: bearer <string>
for use with porthole serve.
	Example:
		porthole get-token --containerid <containerid> -command <command>
	and that's all I have to say about that.`,
	Run: func(cmd *cobra.Command, args []string) {
		claims := PortholeClaims{
			viper.GetString("containerid"),
			[]string{viper.GetString("command")},
			true,
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(1500).Unix(),
				Issuer:    "porthole-get-token",
				Subject:   viper.GetString("user"),
			},
		}
		log.Printf("Config using %v", viper.AllSettings())
		if strings.ToLower(viper.GetString("algo")) == "vault" {
			vaultConfig.Address = viper.GetString("vault-addr")
			config := vault_jwt.Config{
				vaultConfig,
				viper.GetString("vault-path"),
				viper.GetString("vault-token"),
				false,
			}
			token := jwt.NewWithClaims(jwt.GetSigningMethod("Vault"), claims)
			ss, _ = token.SignedString(config)
		} else {
			token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
			ss, _ = token.SignedString([]byte(pskList.GetString(viper.GetString("user"))))
		}
		fmt.Printf("Authorization: bearer %s", ss)
	},
}

func init() {
	RootCmd.AddCommand(getTokenCmd)
	getTokenCmd.PersistentFlags().String("algo", "hs256", "jwt auth provider, must be one of (hs256/vault)")
	getTokenCmd.PersistentFlags().String("user", "porthole", "User id for jwt Subject")
	getTokenCmd.PersistentFlags().String("containerid", "mycontainer", "Container ID")
	getTokenCmd.PersistentFlags().String("command", "/bin/bash", "Command")
	getTokenCmd.PersistentFlags().StringVar(&pskFile, "psk-file", "", "yaml file of psk: [<username>:<secretkey>] (default $HOME/.porthole-psk.yml)")
	getTokenCmd.PersistentFlags().String("vault-addr", "http://127.0.0.1:8200", "vault address")
	getTokenCmd.PersistentFlags().String("vault-token", "myroot", "vault token")
	getTokenCmd.PersistentFlags().String("vault-path", "porthole", "vault path, will be appended to /transit/hmac/")
	bindGetTokenFlags()
	bindGetTokenEnvs()
	if strings.ToLower(viper.GetString("algo")) == "hs256" {
		if pskFile != "" {
			pskList.SetConfigFile(pskFile)
		}
		pskList.SetConfigName(".porthole-psk")
		pskList.AddConfigPath("$HOME")
		pskList.AddConfigPath(".")
		err := pskList.ReadInConfig()
		if err != nil {
			log.Fatalf("Error reading psk-file: %s", err.Error())
		}
	}
}

func bindGetTokenFlags() {
	getTokenCmd.PersistentFlags().VisitAll(func(f *flag.Flag) {
		err := viper.BindPFlag(f.Name, f)
		if err != nil {
			log.Fatalf("Error setting up flags: %s", err.Error())
		}
	})
}

func bindGetTokenEnvs() {
	viper.SetEnvPrefix("porthole")
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	getTokenCmd.PersistentFlags().VisitAll(func(f *flag.Flag) {
		err := viper.BindEnv(f.Name)
		if err != nil {
			log.Fatalf("Error setting up environment variables: %s", err.Error())
		}
	})
}
