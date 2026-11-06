package config

// CoworkPortalConfig 模型门户使用独立开关及最少32字符的服务密钥。
type CoworkPortalConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	APIKey  string `mapstructure:"api_key"`
}
