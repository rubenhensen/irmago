package cmd

import (
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/go-errors/errors"
	"github.com/mitchellh/mapstructure"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/requestorserver"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"

	"github.com/spf13/viper"
)

// var logger = server.NewLogger(0, false, false)
var conf *requestorserver.Configuration

var MetadataCommand = &cobra.Command{
	Use:   "metadata",
	Short: "Starts a server to return metadata needed in VC sessions",
	Long:  `Starts a server to return metadata needed in VC sessions`,
	Run: func(command *cobra.Command, args []string) {
		if err := configure(command); err != nil {
			die("Failed to read configuration from file, args, or env vars", err)
		}

		// Hack: temporarily disable scheme updating to prevent verifyConfiguration() from immediately updating schemes
		enabled := conf.DisableSchemesUpdate
		conf.DisableSchemesUpdate = true

		if _, err := requestorserver.New(conf); err != nil {
			die("Invalid configuration", err)
		}

		conf.DisableSchemesUpdate = enabled // restore previous value before printing configuration

		serv, err := requestorserver.New(conf)
		if err != nil {
			die("Failed to configure server", err)
		}

		stopped := make(chan struct{})
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

		go func() {
			if err := serv.Start(conf, true); err != nil {
				die("Failed to start server", err)
			}
			conf.Logger.Debug("Server stopped")
			stopped <- struct{}{}
		}()

		for {
			select {
			case <-interrupt:
				conf.Logger.Debug("Caught interrupt")
				serv.Stop() // causes serv.Start() above to return
				conf.Logger.Debug("Sent stop signal to server")
			case <-stopped:
				conf.Logger.Info("Exiting")
				close(stopped)
				close(interrupt)
				return
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(MetadataCommand)

	if err := setFlags(MetadataCommand, productionMode()); err != nil {
		die("Failed to attach flags to "+MetadataCommand.Name()+" command", err)
	}
}

func configure(cmd *cobra.Command) error {
	dashReplacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(dashReplacer)
	// viper.SetFileKeyReplacer(dashReplacer)
	viper.SetEnvPrefix("IRMASERVER")
	viper.AutomaticEnv()
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}

	// Locate and read configuration file
	confpath := viper.GetString("config")
	if confpath != "" {
		dir, file := filepath.Dir(confpath), filepath.Base(confpath)
		viper.SetConfigName(strings.TrimSuffix(file, filepath.Ext(file)))
		viper.AddConfigPath(dir)
	} else {
		viper.SetConfigName("irmaserver")
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/irmaserver/")
		viper.AddConfigPath("$HOME/.irmaserver")
	}
	err := viper.ReadInConfig() // Hold error checking until we know how much of it to log

	// Create our logger instance
	logger = server.NewLogger(viper.GetInt("verbose"), viper.GetBool("quiet"), viper.GetBool("log-json"))

	// First log output: hello, development or production mode, log level
	mode := "development"
	if viper.GetBool("production") {
		mode = "production"
	}
	logger.WithFields(logrus.Fields{
		"version":   irma.Version,
		"mode":      mode,
		"verbosity": server.Verbosity(viper.GetInt("verbose")),
	}).Info("irma server running")

	// Now we finally examine and log any error from viper.ReadInConfig()
	if err != nil {
		if _, notfound := err.(viper.ConfigFileNotFoundError); notfound {
			logger.Info("No configuration file found")
		} else {
			die("Failed to unmarshal configuration file at "+viper.ConfigFileUsed(), err)
		}
	} else {
		logger.Info("Config file: ", viper.ConfigFileUsed())
	}

	// Read configuration from flags and/or environmental variables
	conf = &requestorserver.Configuration{
		Configuration: &server.Configuration{
			SchemesPath:           viper.GetString("schemes-path"),
			SchemesAssetsPath:     viper.GetString("schemes-assets-path"),
			SchemesUpdateInterval: viper.GetInt("schemes-update"),
			DisableSchemesUpdate:  viper.GetInt("schemes-update") == 0,
			IssuerPrivateKeysPath: viper.GetString("privkeys"),
			URL:                   viper.GetString("url"),
			DisableTLS:            viper.GetBool("no-tls"),
			Email:                 viper.GetString("email"),
			EnableSSE:             viper.GetBool("sse"),
			Verbose:               viper.GetInt("verbose"),
			Quiet:                 viper.GetBool("quiet"),
			LogJSON:               viper.GetBool("log-json"),
			Logger:                logger,
			Production:            viper.GetBool("production"),
		},
		Permissions: requestorserver.Permissions{
			Disclosing: handlePermission("disclose-perms"),
			Signing:    handlePermission("sign-perms"),
			Issuing:    handlePermission("issue-perms"),
		},
		ListenAddress:                  viper.GetString("listen-addr"),
		Port:                           viper.GetInt("port"),
		MetadataPort:                   viper.GetInt("metadataport"),
		ClientListenAddress:            viper.GetString("client-listen-addr"),
		ClientPort:                     viper.GetInt("client-port"),
		DisableRequestorAuthentication: viper.GetBool("no-auth"),
		Requestors:                     make(map[string]requestorserver.Requestor),
		MaxRequestAge:                  viper.GetInt("max-request-age"),
		StaticPath:                     viper.GetString("static-path"),
		StaticPrefix:                   viper.GetString("static-prefix"),

		TlsCertificate:           viper.GetString("tls-cert"),
		TlsCertificateFile:       viper.GetString("tls-cert-file"),
		TlsPrivateKey:            viper.GetString("tls-privkey"),
		TlsPrivateKeyFile:        viper.GetString("tls-privkey-file"),
		ClientTlsCertificate:     viper.GetString("client-tls-cert"),
		ClientTlsCertificateFile: viper.GetString("client-tls-cert-file"),
		ClientTlsPrivateKey:      viper.GetString("client-tls-privkey"),
		ClientTlsPrivateKeyFile:  viper.GetString("client-tls-privkey-file"),
	}

	if conf.Production {
		if !viper.GetBool("no-email") && conf.Email == "" {
			return errors.New("In production mode it is required to specify either an email address with the --email flag, or explicitly opting out with --no-email. See help or README for more info.")
		}
		if viper.GetBool("no-email") && conf.Email != "" {
			return errors.New("--no-email cannot be combined with --email")
		}
	}

	// Handle requestors
	var requestors map[string]interface{}
	if val, flagOrEnv := viper.Get("requestors").(string); !flagOrEnv || val != "" {
		if requestors, err = cast.ToStringMapE(viper.Get("requestors")); err != nil {
			return errors.WrapPrefix(err, "Failed to unmarshal requestors from flag or env var", 0)
		}
	}
	if len(requestors) > 0 {
		if err := mapstructure.Decode(requestors, &conf.Requestors); err != nil {
			return errors.WrapPrefix(err, "Failed to unmarshal requestors from config file", 0)
		}
	}

	logger.Debug("Done configuring")

	return nil
}
