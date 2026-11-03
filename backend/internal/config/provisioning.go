package config

// ProvisioningConfig 配置主服务到当前平台的内部同步接口。
// APIKey 必须通过外部配置注入，不能写入仓库或默认值。
type ProvisioningConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	APIKey  string `mapstructure:"api_key"`
}
