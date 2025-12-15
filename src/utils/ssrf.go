package utils

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	// 内网IP地址范围
	privateIPBlocks []*net.IPNet
)

func init() {
	// 定义内网IP范围
	privateRanges := []string{
		"10.0.0.0/8",       // RFC1918 私有地址
		"172.16.0.0/12",    // RFC1918 私有地址
		"192.168.0.0/16",   // RFC1918 私有地址
		"127.0.0.0/8",      // Loopback
		"169.254.0.0/16",   // Link-local
		"::1/128",          // IPv6 loopback
		"fc00::/7",         // IPv6 私有地址
		"fe80::/10",        // IPv6 link-local
		"0.0.0.0/8",        // 当前网络
		"100.64.0.0/10",    // Shared Address Space (CGNAT)
		"192.0.0.0/24",     // IETF Protocol Assignments
		"192.0.2.0/24",     // TEST-NET-1
		"198.51.100.0/24",  // TEST-NET-2
		"203.0.113.0/24",   // TEST-NET-3
		"224.0.0.0/4",      // 组播地址
		"240.0.0.0/4",      // 保留地址
		"255.255.255.255/32", // 广播地址
	}

	for _, cidr := range privateRanges {
		_, block, err := net.ParseCIDR(cidr)
		if err == nil {
			privateIPBlocks = append(privateIPBlocks, block)
		}
	}
}

// IsPrivateIP 检查IP是否为内网地址
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true // 无效IP视为内网
	}

	// 检查是否为未指定地址
	if ip.IsUnspecified() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckURLSafety 检查URL是否安全（非内网地址）
func CheckURLSafety(urlStr string) (bool, string) {
	// 解析URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false, fmt.Sprintf("无效的URL: %v", err)
	}

	host := parsedURL.Hostname()
	if host == "" {
		return false, "URL缺少主机名"
	}

	// 检查是否为IP地址
	if ip := net.ParseIP(host); ip != nil {
		if IsPrivateIP(ip) {
			return false, "禁止访问内网地址"
		}
		return true, ""
	}

	// 检查是否为localhost变体
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") {
		return false, "禁止访问localhost"
	}

	// DNS解析域名
	ips, err := net.LookupIP(host)
	if err != nil {
		return false, fmt.Sprintf("DNS解析失败: %v", err)
	}

	// 检查所有解析到的IP
	for _, ip := range ips {
		if IsPrivateIP(ip) {
			return false, fmt.Sprintf("域名 %s 解析到内网地址，禁止访问", host)
		}
	}

	return true, ""
}

// ExtractDomain 从URL中提取域名
func ExtractDomain(urlStr string) (string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	return parsedURL.Hostname(), nil
}
