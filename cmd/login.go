package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"

	"github.com/Masterminds/semver/v3"
	"github.com/fi-ts/cloudctl/cmd/helper"
	"github.com/fi-ts/cloudctl/pkg/api"
	"github.com/metal-stack/metal-lib/auth"
	"github.com/metal-stack/v"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"golang.org/x/term"
)

type OIDCToken struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

func newLoginCmd(c *config) *cobra.Command {
	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "login user and receive token",
		Long:  "login and receive token that will be used to authenticate commands.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				console io.Writer
				handler auth.TokenHandlerFunc
			)

			if viper.GetBool("print-only") {
				// do not store, only print to console
				handler = printTokenHandler
			} else if viper.GetBool("direct") {
				// get token from open id connect flow
				username := viper.GetString("username")
				if username == "" {
					fmt.Print("Enter Username: ")
					_, err := fmt.Scanln(&username)
					if err != nil {
						return err
					}
				}

				fmt.Print("Enter Password: ")
				bytePassword, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return err
				}
				fmt.Println()
				password := string(bytePassword)

				cs, err := api.GetContexts()
				if err != nil {
					return err
				}
				ctx := api.MustDefaultContext()
				oidcToken, err := getOIDCToken(os.Getenv("CLOUDCTL_USER"), password, ctx)
				if err != nil {
					return err
				}
				_, err = auth.UpdateKubeConfigContext(viper.GetString("kubeconfig"), auth.TokenInfo{
					IDToken:      oidcToken.AccessToken,
					RefreshToken: oidcToken.RefreshToken,
					TokenClaims: auth.Claims{
						Issuer: ctx.IssuerURL,
						Name:   username,
					},
					IssuerConfig: auth.IssuerConfig{
						ClientID:     ctx.ClientID,
						ClientSecret: ctx.ClientSecret,
						IssuerURL:    ctx.IssuerURL,
					},
				}, auth.ExtractName, api.FormatContextName(api.CloudContext, cs.CurrentContext))
				if err != nil {
					return err
				}
				return nil

			} else {
				cs, err := api.GetContexts()
				if err != nil {
					return err
				}
				console = os.Stdout
				handler = auth.NewUpdateKubeConfigHandler(viper.GetString("kubeconfig"), console, auth.WithContextName(api.FormatContextName(api.CloudContext, cs.CurrentContext)))
			}

			scopes := auth.DexScopes
			ctx := api.MustDefaultContext()
			if ctx.IssuerType == "generic" {
				scopes = auth.GenericScopes
			} else if ctx.CustomScopes != "" {
				cs := strings.Split(ctx.CustomScopes, ",")
				for i := range cs {
					cs[i] = strings.TrimSpace(cs[i])
				}
				scopes = cs
			}

			config := auth.Config{
				ClientID:     ctx.ClientID,
				ClientSecret: ctx.ClientSecret,
				IssuerURL:    ctx.IssuerURL,
				Scopes:       scopes,
				TokenHandler: handler,
				Console:      console,
				Debug:        viper.GetBool("debug"),
				Log:          c.log,
			}

			if ctx.IssuerType == "generic" {
				config.SuccessMessage = fmt.Sprintf(`Please close this page and return to your terminal. Manage your session on: <a href=%q>%s</a>`, ctx.IssuerURL+"/account", ctx.IssuerURL+"/account")
			}

			err := auth.OIDCFlow(config)
			if err != nil {
				return err
			}

			resp, err := c.cloud.Version.Info(nil, helper.ClientNoAuth())
			if err != nil {
				return err
			}
			if resp.Payload != nil && resp.Payload.MinClientVersion != nil {
				minVersion := *resp.Payload.MinClientVersion
				parsedMinVersion, err := semver.NewVersion(minVersion)
				if err != nil {
					return fmt.Errorf("required cloudctl minimum version:%q is not semver parsable:%w", minVersion, err)
				}

				// This is a developer build
				if !strings.HasPrefix(v.Version, "v") {
					return nil
				}

				thisVersion, err := semver.NewVersion(v.Version)
				if err != nil {
					return fmt.Errorf("cloudctl version:%q is not semver parsable:%w", v.Version, err)
				}

				if thisVersion.LessThan(parsedMinVersion) {
					return fmt.Errorf("your cloudctl version:%s is smaller than the required minimum version:%s, please run `cloudctl update do` to update to the supported version", thisVersion, minVersion)
				}

				if !thisVersion.Equal(parsedMinVersion) {
					fmt.Println()
					fmt.Printf("WARNING: Your cloudctl version %q might not compatible with the cloud-api (supported version is %q). Please run `cloudctl update do` to update to the supported version.", thisVersion, minVersion)
					fmt.Println()
				}
			}

			return nil
		},
		PreRun: bindPFlags,
	}
	loginCmd.Flags().Bool("print-only", false, "If true, the token is printed to stdout")
	loginCmd.Flags().Bool("direct", false, "If true, login directly to the cloud-api without using the browser")
	loginCmd.Flags().String("username", "", "username for direct login")
	return loginCmd
}

func printTokenHandler(tokenInfo auth.TokenInfo) error {
	fmt.Println(tokenInfo.IDToken)
	return nil
}

func getOIDCToken(username, password string, ctx api.Context) (OIDCToken, error) {
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", ctx.ClientID)
	data.Set("client_secret", ctx.ClientSecret)
	data.Set("username", username)
	data.Set("password", password)
	resp, err := http.PostForm(ctx.IssuerURL+"/protocol/openid-connect/token", data)
	if err != nil {
		return OIDCToken{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return OIDCToken{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return OIDCToken{}, err
	}

	var oidcToken OIDCToken
	err = json.Unmarshal(body, &oidcToken)
	if err != nil {
		return OIDCToken{}, err
	}
	return oidcToken, nil
}
