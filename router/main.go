package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	appCode          = "4ca99fa6b56cc2ba"
	userAgent        = "Mozilla/5.0 (Linux; Android 12; SM-A5560 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Safari/537.36; SKLand/1.52.1"
	deviceInfoURL    = "https://fp-it.portal101.cn/deviceprofile/v4"
	grantCodeURL     = "https://as.hypergryph.com/user/oauth2/v2/grant"
	credCodeURL      = "https://zonai.skland.com/web/v1/user/auth/generate_cred_by_code"
	bindingURL       = "https://zonai.skland.com/api/v1/game/player/binding"
	arknightsURL     = "https://zonai.skland.com/api/v1/game/attendance"
	endfieldURL      = "https://zonai.skland.com/web/v1/game/endfield/attendance"
	feishuTokenURL   = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
	feishuMessageURL = "https://open.feishu.cn/open-apis/im/v1/messages"
	requestTimeout   = 30 * time.Second
	maxResponseSize  = 2 << 20
	maxAttempts      = 3
	errorSnippetSize = 200

	devicePublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmxMNr7n8ZeT0tE1R9j/mPixoinPkeM+k4VGIn/s0k7N5rJAfnZ0eMER+QhwFvshzo0LNmeUkpR8uIlU/GEVr8mN28sKmwd2gpygqj0ePnBmOW4v0ZVwbSYK+izkhVFk2V/doLoMbWy6b+UnA8mkjvg0iYWRByfRsK2gdl7llqCwIDAQAB"
)

// retryBackoff 是两次网络尝试之间的等待时间，测试中会临时缩短。
var retryBackoff = 2 * time.Second

// 森空岛服务与推送受众都按中国标准时间，时间戳固定用 UTC+8 输出，
// 避免路由器时区未设置（常见为 UTC）时告警时间偏移 8 小时。
var chinaTime = time.FixedZone("CST", 8*60*60)

type desRule struct {
	name string
	key  string
}

var desRules = map[string]desRule{
	"appId":        {name: "xx", key: "uy7mzc4h"},
	"canvas":       {name: "yk", key: "snrn887t"},
	"clientSize":   {name: "zx", key: "cpmjjgsu"},
	"organization": {name: "dp", key: "78moqjfc"},
	"os":           {name: "pj", key: "je6vk6t4"},
	"platform":     {name: "gm", key: "pakxhcd2"},
	"plugins":      {name: "kq", key: "v51m3pzl"},
	"pmf":          {name: "vw", key: "2mdeslu3"},
	"referer":      {name: "ab", key: "y7bmrjlc"},
	"res":          {name: "hf", key: "whxqm2a7"},
	"rtype":        {name: "lo", key: "x8o2h2bl"},
	"sdkver":       {name: "sc", key: "9q3dcxp2"},
	"status":       {name: "an", key: "2jbrxxw4"},
	"subVersion":   {name: "ns", key: "eo3i2puh"},
	"svm":          {name: "qr", key: "fzj3kaeh"},
	"time":         {name: "nb", key: "q2t3odsk"},
	"timezone":     {name: "as", key: "1uv05lj5"},
	"tn":           {name: "py", key: "x9nzj1bp"},
	"trees":        {name: "pi", key: "acfs0xo4"},
	"ua":           {name: "bj", key: "k92crp1t"},
	"url":          {name: "cf", key: "y95hjkoo"},
	"vpw":          {name: "ca", key: "r9924ab5"},
}

var plainNames = map[string]string{
	"box":      "jf",
	"protocol": "protocol",
	"version":  "version",
}

type credentials struct {
	Cred  string `json:"cred"`
	Token string `json:"token"`
}

type endfieldRole struct {
	ServerID string `json:"serverId"`
	RoleID   string `json:"roleId"`
	Nickname string `json:"nickname"`
}

type binding struct {
	UID         string         `json:"uid"`
	ChannelName string         `json:"channelName"`
	Nickname    string         `json:"nickName"`
	GameName    string         `json:"gameName"`
	GameID      int64          `json:"gameId"`
	Roles       []endfieldRole `json:"roles"`
	AppCode     string         `json:"-"`
}

type bindingGroup struct {
	AppCode     string    `json:"appCode"`
	BindingList []binding `json:"bindingList"`
}

type signer struct {
	client *http.Client
	did    string
	cred   string
	token  string
}

type feishuConfig struct {
	AppID     string `json:"app_id"`
	AppSecret string `json:"app_secret"`
	ReceiveID string `json:"receive_id"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(1)
	}
}

// timestamp 是推送和提示信息里使用的人类可读时间。
func timestamp() string {
	return time.Now().In(chinaTime).Format("2006-01-02 15:04:05")
}

func run() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("定位可执行文件: %w", err)
	}
	configDir := filepath.Dir(executable)
	checkOnly := flag.Bool("check", false, "只验证令牌和角色绑定，不执行签到")
	testFeishu := flag.Bool("test-feishu", false, "只发送飞书测试消息，不执行签到")
	tokenFile := flag.String("token-file", filepath.Join(configDir, "TOKEN.txt"), "每行一个鹰角网络通行证")
	feishuConfigFile := flag.String("feishu-config", filepath.Join(configDir, "FEISHU_APP.json"), "飞书应用机器人配置文件")
	flag.Parse()

	client := &http.Client{Timeout: requestTimeout}
	var feishu *feishuConfig
	failed := false
	if !*checkOnly || *testFeishu {
		var err error
		feishu, err = readFeishuConfig(*feishuConfigFile)
		if err != nil {
			if *testFeishu {
				return fmt.Errorf("飞书配置: %w", err)
			}
			fmt.Fprintln(os.Stderr, "飞书配置错误：", err)
			failed = true
		}
	}
	if *testFeishu {
		if feishu == nil {
			return errors.New("没有配置飞书应用机器人")
		}
		message := fmt.Sprintf("森空岛签到推送测试\n时间：%s\n✅ 应用机器人个人消息通道已连通", timestamp())
		if err := pushFeishu(context.Background(), client, *feishu, message); err != nil {
			return fmt.Errorf("飞书测试推送失败: %w", err)
		}
		fmt.Println("飞书测试推送成功")
		return nil
	}

	tokens, err := readTokens(*tokenFile)
	if err != nil {
		return failWithFeishu(context.Background(), client, feishu, err)
	}

	did, err := getDeviceID(context.Background(), client)
	if err != nil {
		return failWithFeishu(context.Background(), client, feishu, fmt.Errorf("生成设备标识失败: %w", err))
	}

	var report []string
	for i, token := range tokens {
		before := len(report)
		if err := runAccount(context.Background(), client, did, token, i+1, *checkOnly, &report); err != nil {
			fmt.Fprintf(os.Stderr, "账号 %d：%v\n", i+1, err)
			if len(report) == before {
				report = append(report, fmt.Sprintf("❌ 账号 %d：%v", i+1, err))
			}
			failed = true
		}
	}

	if !*checkOnly && feishu != nil {
		if len(report) == 0 {
			report = append(report, "ℹ️ 没有找到支持签到的角色")
		}
		title := "森空岛签到完成"
		if failed {
			title = "森空岛签到存在失败"
		}
		message := fmt.Sprintf("%s\n时间：%s\n%s", title, timestamp(), strings.Join(report, "\n"))
		if err := pushFeishu(context.Background(), client, *feishu, message); err != nil {
			fmt.Fprintln(os.Stderr, "飞书推送失败：", err)
			failed = true
		} else {
			fmt.Println("飞书推送成功")
		}
	}
	if failed {
		return errors.New("签到或通知至少一项失败")
	}
	return nil
}

func failWithFeishu(ctx context.Context, client *http.Client, feishu *feishuConfig, cause error) error {
	if feishu == nil {
		return cause
	}
	message := fmt.Sprintf("森空岛签到失败\n时间：%s\n❌ %v", timestamp(), cause)
	if err := pushFeishu(ctx, client, *feishu, message); err != nil {
		return fmt.Errorf("%w；飞书推送失败: %v", cause, err)
	}
	return cause
}

func readTokens(path string) ([]string, error) {
	raw := os.Getenv("TOKEN")
	if raw == "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("读取令牌文件 %s: %w", path, err)
		}
		raw = string(data)
	}

	tokens := parseTokens(raw)
	if len(tokens) == 0 {
		return nil, errors.New("没有找到有效令牌")
	}
	return tokens, nil
}

// parseTokens 接受逗号或换行分隔的裸通行证，也接受从森空岛网页整段复制的 JSON。
func parseTokens(raw string) []string {
	if content, ok := tokenFromJSON(raw); ok {
		raw = content
	}
	seen := make(map[string]bool)
	var tokens []string
	for _, token := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	}) {
		token = strings.TrimSpace(token)
		if content, ok := tokenFromJSON(token); ok {
			token = content
		}
		if token != "" && !seen[token] {
			seen[token] = true
			tokens = append(tokens, token)
		}
	}
	return tokens
}

// tokenFromJSON 解析森空岛网页上的 {"data":{"content":"通行证"}} 结构。
func tokenFromJSON(raw string) (string, bool) {
	var payload struct {
		Data struct {
			Content string `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &payload); err != nil {
		return "", false
	}
	content := strings.TrimSpace(payload.Data.Content)
	return content, content != ""
}

// tokenExpiredHint 在通行证失效时补一句可操作的提示，而不只是抛出服务端原始报文。
func tokenExpiredHint(err error) error {
	message := err.Error()
	expired := strings.Contains(message, "未登录") || strings.Contains(message, "失效") ||
		(strings.Contains(message, "无效") && strings.Contains(strings.ToLower(message), "token"))
	if !expired {
		return err
	}
	return fmt.Errorf("%w；通行证可能已失效，请在电脑上重新登录森空岛，把新的 TOKEN 写入 TOKEN.txt", err)
}

func runAccount(ctx context.Context, client *http.Client, did, token string, account int, checkOnly bool, report *[]string) error {
	cred, err := getCredentials(ctx, client, did, token)
	if err != nil {
		return err
	}
	s := &signer{client: client, did: did, cred: cred.Cred, token: cred.Token}
	bindings, err := s.getBindings(ctx)
	if err != nil {
		return err
	}

	if checkOnly {
		var arknights, endfield int
		for _, item := range bindings {
			switch item.AppCode {
			case "arknights":
				arknights++
			case "endfield":
				endfield++
			}
		}
		fmt.Printf("账号 %d：凭证有效，明日方舟绑定 %d，终末地绑定 %d\n", account, arknights, endfield)
		return nil
	}

	failed := false
	for _, item := range bindings {
		switch item.AppCode {
		case "arknights":
			message, err := s.signArknights(ctx, item)
			if err != nil {
				message := fmt.Sprintf("[%s] 角色 %s 签到失败：%v", item.GameName, item.Nickname, err)
				fmt.Fprintln(os.Stderr, message)
				*report = append(*report, "❌ "+message)
				failed = true
				continue
			}
			fmt.Println(message)
			*report = append(*report, "✅ "+message)
		case "endfield":
			for _, role := range item.Roles {
				message, err := s.signEndfield(ctx, item, role)
				if err != nil {
					message := fmt.Sprintf("[%s] 角色 %s 签到失败：%v", item.GameName, role.Nickname, err)
					fmt.Fprintln(os.Stderr, message)
					*report = append(*report, "❌ "+message)
					failed = true
					continue
				}
				fmt.Println(message)
				*report = append(*report, "✅ "+message)
			}
		}
	}
	if failed {
		return errors.New("存在签到失败的角色")
	}
	return nil
}

func readFeishuConfig(path string) (*feishuConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取 %s: %w", path, err)
	}
	var config feishuConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", path, err)
	}
	config.AppID = strings.TrimSpace(config.AppID)
	config.AppSecret = strings.TrimSpace(config.AppSecret)
	config.ReceiveID = strings.TrimSpace(config.ReceiveID)
	if config.AppID == "" || config.AppSecret == "" || config.ReceiveID == "" {
		return nil, errors.New("飞书配置缺少 app_id、app_secret 或 receive_id")
	}
	return &config, nil
}

func pushFeishu(ctx context.Context, client *http.Client, config feishuConfig, text string) error {
	return pushFeishuTo(ctx, client, config, text, feishuTokenURL, feishuMessageURL)
}

func pushFeishuTo(ctx context.Context, client *http.Client, config feishuConfig, text, tokenURL, messageURL string) error {
	tokenBody, err := json.Marshal(struct {
		AppID     string `json:"app_id"`
		AppSecret string `json:"app_secret"`
	}{AppID: config.AppID, AppSecret: config.AppSecret})
	if err != nil {
		return err
	}
	var tokenResponse struct {
		Code              int    `json:"code"`
		Message           string `json:"msg"`
		TenantAccessToken string `json:"tenant_access_token"`
	}
	if err := requestJSON(ctx, client, http.MethodPost, tokenURL, tokenBody, nil, &tokenResponse); err != nil {
		return fmt.Errorf("获取 tenant_access_token: %w", err)
	}
	if tokenResponse.Code != 0 || tokenResponse.TenantAccessToken == "" {
		return fmt.Errorf("获取 tenant_access_token 失败: %s", tokenResponse.Message)
	}

	content, err := json.Marshal(struct {
		Text string `json:"text"`
	}{Text: text})
	if err != nil {
		return err
	}
	messageBody, err := json.Marshal(struct {
		ReceiveID   string `json:"receive_id"`
		MessageType string `json:"msg_type"`
		Content     string `json:"content"`
	}{ReceiveID: config.ReceiveID, MessageType: "text", Content: string(content)})
	if err != nil {
		return err
	}
	var messageResponse struct {
		Code    int    `json:"code"`
		Message string `json:"msg"`
		Data    struct {
			MessageID string `json:"message_id"`
		} `json:"data"`
	}
	headers := map[string]string{"Authorization": "Bearer " + tokenResponse.TenantAccessToken}
	endpoint := messageURL + "?receive_id_type=open_id"
	if err := requestJSON(ctx, client, http.MethodPost, endpoint, messageBody, headers, &messageResponse); err != nil {
		return fmt.Errorf("发送个人消息: %w", err)
	}
	if messageResponse.Code != 0 || messageResponse.Data.MessageID == "" {
		return fmt.Errorf("发送个人消息失败: %s", messageResponse.Message)
	}
	return nil
}

func getCredentials(ctx context.Context, client *http.Client, did, token string) (credentials, error) {
	grantBody, err := json.Marshal(struct {
		AppCode string `json:"appCode"`
		Token   string `json:"token"`
		Type    int    `json:"type"`
	}{AppCode: appCode, Token: token, Type: 0})
	if err != nil {
		return credentials{}, err
	}
	var grantResponse struct {
		Status int    `json:"status"`
		Msg    string `json:"msg"`
		Data   struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	if err := requestJSON(ctx, client, http.MethodPost, grantCodeURL, grantBody, loginHeaders(did), &grantResponse); err != nil {
		return credentials{}, fmt.Errorf("获取认证代码: %w", err)
	}
	if grantResponse.Status != 0 || grantResponse.Data.Code == "" {
		return credentials{}, tokenExpiredHint(fmt.Errorf("获取认证代码失败: %s", grantResponse.Msg))
	}

	credBody, err := json.Marshal(struct {
		Code string `json:"code"`
		Kind int    `json:"kind"`
	}{Code: grantResponse.Data.Code, Kind: 1})
	if err != nil {
		return credentials{}, err
	}
	var credResponse struct {
		Code    int         `json:"code"`
		Message string      `json:"message"`
		Data    credentials `json:"data"`
	}
	if err := requestJSON(ctx, client, http.MethodPost, credCodeURL, credBody, loginHeaders(did), &credResponse); err != nil {
		return credentials{}, fmt.Errorf("获取凭证: %w", err)
	}
	if credResponse.Code != 0 || credResponse.Data.Cred == "" || credResponse.Data.Token == "" {
		return credentials{}, tokenExpiredHint(fmt.Errorf("获取凭证失败: %s", credResponse.Message))
	}
	return credResponse.Data, nil
}

func loginHeaders(did string) map[string]string {
	return map[string]string{
		"User-Agent":       userAgent,
		"dId":              did,
		"X-Requested-With": "com.hypergryph.skland",
	}
}

func (s *signer) getBindings(ctx context.Context) ([]binding, error) {
	var response struct {
		Code    *int   `json:"code"`
		Message string `json:"message"`
		Data    struct {
			List []bindingGroup `json:"list"`
		} `json:"data"`
	}
	if err := s.signedJSON(ctx, http.MethodGet, bindingURL, nil, nil, &response); err != nil {
		return nil, fmt.Errorf("读取角色绑定: %w", err)
	}
	if response.Code == nil {
		return nil, errors.New("角色绑定响应缺少 code")
	}
	if *response.Code != 0 {
		return nil, tokenExpiredHint(fmt.Errorf("读取角色绑定失败: %s", response.Message))
	}

	if response.Data.List == nil {
		return nil, errors.New("角色绑定响应缺少 data.list")
	}
	var result []binding
	for _, group := range response.Data.List {
		if group.AppCode != "arknights" && group.AppCode != "endfield" {
			continue
		}
		if group.BindingList == nil {
			return nil, fmt.Errorf("%s 绑定响应缺少 bindingList", group.AppCode)
		}
		for _, item := range group.BindingList {
			if group.AppCode == "endfield" && item.Roles == nil {
				return nil, errors.New("终末地绑定响应缺少 roles")
			}
			item.AppCode = group.AppCode
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *signer) signArknights(ctx context.Context, item binding) (string, error) {
	uid, err := json.Marshal(item.UID)
	if err != nil {
		return "", err
	}
	body := []byte(fmt.Sprintf(`{"gameId": %d, "uid": %s}`, item.GameID, uid))
	var response struct {
		Code    *int   `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Awards []struct {
				Resource struct {
					Name string `json:"name"`
				} `json:"resource"`
				Count *int `json:"count"`
			} `json:"awards"`
		} `json:"data"`
	}
	if err := s.signedJSON(ctx, http.MethodPost, arknightsURL, body, nil, &response); err != nil {
		return "", err
	}
	if response.Code == nil {
		return "", errors.New("签到响应缺少 code")
	}
	if *response.Code != 0 {
		return "", errors.New(response.Message)
	}
	if response.Data.Awards == nil {
		return "", errors.New("签到响应缺少 data.awards")
	}
	var awards []string
	for _, award := range response.Data.Awards {
		count := 1
		if award.Count != nil && *award.Count > 0 {
			count = *award.Count
		}
		awards = append(awards, fmt.Sprintf("%s×%d", award.Resource.Name, count))
	}
	return fmt.Sprintf("[%s] 角色 %s（%s）签到成功，获得 %s", item.GameName, item.Nickname, item.ChannelName, strings.Join(awards, "、")), nil
}

func (s *signer) signEndfield(ctx context.Context, item binding, role endfieldRole) (string, error) {
	extra := map[string]string{
		"Content-Type": "application/json",
		"sk-game-role": fmt.Sprintf("3_%s_%s", role.RoleID, role.ServerID),
		"Referer":      "https://game.skland.com/",
		"Origin":       "https://game.skland.com/",
	}
	var response struct {
		Code    *int   `json:"code"`
		Message string `json:"message"`
		Data    struct {
			AwardIDs []struct {
				ID string `json:"id"`
			} `json:"awardIds"`
			ResourceInfo map[string]struct {
				Name  string `json:"name"`
				Count int    `json:"count"`
			} `json:"resourceInfoMap"`
		} `json:"data"`
	}
	if err := s.signedJSON(ctx, http.MethodPost, endfieldURL, nil, extra, &response); err != nil {
		return "", err
	}
	if response.Code == nil {
		return "", errors.New("签到响应缺少 code")
	}
	if *response.Code != 0 {
		return "", errors.New(response.Message)
	}
	if response.Data.AwardIDs == nil || response.Data.ResourceInfo == nil {
		return "", errors.New("签到响应缺少奖励数据")
	}
	var awards []string
	for _, award := range response.Data.AwardIDs {
		resource, ok := response.Data.ResourceInfo[award.ID]
		if !ok {
			return "", fmt.Errorf("签到响应缺少奖励 %s 的详情", award.ID)
		}
		awards = append(awards, fmt.Sprintf("%s×%d", resource.Name, resource.Count))
	}
	return fmt.Sprintf("[%s] 角色 %s（%s）签到成功，获得 %s", item.GameName, role.Nickname, item.ChannelName, strings.Join(awards, "、")), nil
}

func (s *signer) signedJSON(ctx context.Context, method, rawURL string, body []byte, extraHeaders map[string]string, out any) error {
	headers, err := signedHeaders(s.token, s.did, rawURL, method, string(body), time.Now())
	if err != nil {
		return err
	}
	headers["cred"] = s.cred
	headers["User-Agent"] = userAgent
	headers["X-Requested-With"] = "com.hypergryph.skland"
	for key, value := range extraHeaders {
		headers[key] = value
	}
	return requestJSON(ctx, s.client, method, rawURL, body, headers, out)
}

func signedHeaders(token, did, rawURL, method, body string, now time.Time) (map[string]string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	signBody := body
	if method == http.MethodGet {
		signBody = parsed.RawQuery
	}
	headerJSON := fmt.Sprintf(`{"platform":"3","timestamp":"%s","dId":"%s","vName":"1.0.0"}`, timestamp, did)
	source := parsed.Path + signBody + timestamp + headerJSON
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte(source))
	hmacHex := hex.EncodeToString(mac.Sum(nil))
	md5Sum := md5.Sum([]byte(hmacHex))

	return map[string]string{
		"sign":      hex.EncodeToString(md5Sum[:]),
		"platform":  "3",
		"timestamp": timestamp,
		"dId":       did,
		"vName":     "1.0.0",
	}, nil
}

func requestJSON(ctx context.Context, client *http.Client, method, rawURL string, body []byte, headers map[string]string, out any) error {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryBackoff):
			}
		}
		// 每次尝试都重建请求，保证重试时请求体可以重放。
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
		if err != nil {
			return err
		}
		req.Close = true
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		if body != nil && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = httpError(resp.StatusCode, data)
			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
				continue
			}
			return lastErr
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("解析响应 JSON: %w", err)
		}
		return nil
	}
	return lastErr
}

func httpError(status int, body []byte) error {
	if snippet := bodySnippet(body); snippet != "" {
		return fmt.Errorf("HTTP %d：%s", status, snippet)
	}
	return fmt.Errorf("HTTP %d", status)
}

// bodySnippet 截取响应体的开头用于排障，并遮掉其中可能出现的凭证字段。
func bodySnippet(body []byte) string {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		maskSecrets(payload)
		if encoded, err := marshalJSON(payload); err == nil {
			body = encoded
		}
	}
	runes := []rune(strings.TrimSpace(string(body)))
	if len(runes) > errorSnippetSize {
		return string(runes[:errorSnippetSize]) + "…"
	}
	return string(runes)
}

func maskSecrets(payload map[string]any) {
	for _, key := range []string{"cred", "token"} {
		if _, ok := payload[key]; ok {
			payload[key] = "*****"
		}
	}
	data, ok := payload["data"].(map[string]any)
	if !ok {
		return
	}
	for _, key := range []string{"code", "cred", "token"} {
		if _, ok := data[key]; ok {
			data[key] = "*****"
		}
	}
}

func getDeviceID(ctx context.Context, client *http.Client) (string, error) {
	uid, err := randomUUID()
	if err != nil {
		return "", err
	}
	vpw, err := randomUUID()
	if err != nil {
		return "", err
	}
	trees, err := randomUUID()
	if err != nil {
		return "", err
	}
	smid, err := makeSMID()
	if err != nil {
		return "", err
	}
	data, err := deviceIdentifier(uid, vpw, trees, smid, time.Now().UnixMilli())
	if err != nil {
		return "", err
	}
	uidCipher, err := encryptUID(uid)
	if err != nil {
		return "", err
	}

	body, err := json.Marshal(struct {
		AppID        string `json:"appId"`
		Compress     int    `json:"compress"`
		Data         string `json:"data"`
		Encode       int    `json:"encode"`
		EP           string `json:"ep"`
		Organization string `json:"organization"`
		OS           string `json:"os"`
	}{
		AppID:        "default",
		Compress:     2,
		Data:         data,
		Encode:       5,
		EP:           uidCipher,
		Organization: "UWXspnCCJN4sfYlNfqps",
		OS:           "web",
	})
	if err != nil {
		return "", err
	}
	var response struct {
		Code   int `json:"code"`
		Detail struct {
			DeviceID string `json:"deviceId"`
		} `json:"detail"`
	}
	if err := requestJSON(ctx, client, http.MethodPost, deviceInfoURL, body, nil, &response); err != nil {
		return "", err
	}
	if response.Code != 1100 || response.Detail.DeviceID == "" {
		return "", fmt.Errorf("设备服务返回代码 %d", response.Code)
	}
	return "B" + response.Detail.DeviceID, nil
}

// deviceIdentifier 生成设备标识请求中的 data 字段，随机值与时间由参数传入，便于用固定输入验证。
func deviceIdentifier(uid, vpw, trees, smid string, nowMillis int64) (string, error) {
	device := map[string]any{
		"plugins":      "MicrosoftEdgePDFPluginPortableDocumentFormatinternal-pdf-viewer1,MicrosoftEdgePDFViewermhjfbmdgcfjbbpaeojofohoefgiehjai1",
		"ua":           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
		"canvas":       "259ffe69",
		"timezone":     -480,
		"platform":     "Win32",
		"url":          "https://www.skland.com/",
		"referer":      "",
		"res":          "1920_1080_24_1.25",
		"clientSize":   "0_0_1080_1920_1920_1080_1920_1080",
		"status":       "0011",
		"vpw":          vpw,
		"svm":          nowMillis,
		"trees":        trees,
		"pmf":          nowMillis,
		"protocol":     102,
		"organization": "UWXspnCCJN4sfYlNfqps",
		"appId":        "default",
		"os":           "web",
		"version":      "3.0.0",
		"sdkver":       "3.0.0",
		"box":          "",
		"rtype":        "all",
		"smid":         smid,
		"subVersion":   "1.0.0",
		"time":         0,
	}
	tn, err := makeTN(device)
	if err != nil {
		return "", err
	}
	tnHash := md5.Sum([]byte(tn))
	device["tn"] = hex.EncodeToString(tnHash[:])

	encryptedDevice, err := encryptDeviceFields(device)
	if err != nil {
		return "", err
	}
	deviceJSON, err := marshalJSON(encryptedDevice)
	if err != nil {
		return "", err
	}
	compressed, err := gzipLevel2(deviceJSON)
	if err != nil {
		return "", err
	}
	uidHash := md5.Sum([]byte(uid))
	privateID := hex.EncodeToString(uidHash[:])[:16]
	payload, err := encryptAES([]byte(base64.StdEncoding.EncodeToString(compressed)), []byte(privateID))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(payload), nil
}

// encryptUID 生成设备标识请求中的 ep 字段。
func encryptUID(uid string) (string, error) {
	publicKeyDER, err := base64.StdEncoding.DecodeString(devicePublicKey)
	if err != nil {
		return "", err
	}
	parsedKey, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return "", err
	}
	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("设备公钥不是 RSA 公钥")
	}
	encryptedUID, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(uid))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedUID), nil
}

func encryptDeviceFields(input map[string]any) (map[string]any, error) {
	result := make(map[string]any, len(input))
	for key, value := range input {
		if rule, ok := desRules[key]; ok {
			encrypted, err := encryptTripleDES([]byte(pythonString(value)), []byte(rule.key))
			if err != nil {
				return nil, err
			}
			result[rule.name] = base64.StdEncoding.EncodeToString(encrypted)
			continue
		}
		if name, ok := plainNames[key]; ok {
			result[name] = value
			continue
		}
		result[key] = value
	}
	return result, nil
}

func encryptTripleDES(value, shortKey []byte) ([]byte, error) {
	if len(shortKey) != 8 {
		return nil, errors.New("3DES 密钥长度必须为 8")
	}
	key := append(append(append([]byte{}, shortKey...), shortKey...), shortKey...)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	padded := append(append([]byte{}, value...), make([]byte, block.BlockSize())...)
	padded = padded[:len(padded)/block.BlockSize()*block.BlockSize()]
	result := make([]byte, len(padded))
	for offset := 0; offset < len(padded); offset += block.BlockSize() {
		block.Encrypt(result[offset:offset+block.BlockSize()], padded[offset:offset+block.BlockSize()])
	}
	return result, nil
}

func encryptAES(value, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := append(append([]byte{}, value...), 0)
	for len(padded)%aes.BlockSize != 0 {
		padded = append(padded, 0)
	}
	result := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, []byte("0102030405060708")).CryptBlocks(result, padded)
	return result, nil
}

func gzipLevel2(value []byte) ([]byte, error) {
	var result bytes.Buffer
	writer, err := gzip.NewWriterLevel(&result, 2)
	if err != nil {
		return nil, err
	}
	writer.Header.ModTime = time.Unix(0, 0)
	if _, err := writer.Write(value); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

func makeTN(input map[string]any) (string, error) {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result strings.Builder
	for _, key := range keys {
		switch value := input[key].(type) {
		case int:
			result.WriteString(strconv.Itoa(value * 10000))
		case int64:
			result.WriteString(strconv.FormatInt(value*10000, 10))
		case float64:
			result.WriteString(strconv.FormatFloat(value*10000, 'f', -1, 64))
		case string:
			result.WriteString(value)
		case map[string]any:
			nested, err := makeTN(value)
			if err != nil {
				return "", err
			}
			result.WriteString(nested)
		default:
			return "", fmt.Errorf("tn 不支持值类型 %T", value)
		}
	}
	return result.String(), nil
}

func pythonString(value any) string {
	switch value := value.(type) {
	case int:
		return strconv.Itoa(value)
	case int64:
		return strconv.FormatInt(value, 10)
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	default:
		return fmt.Sprint(value)
	}
}

func marshalJSON(value any) ([]byte, error) {
	var result bytes.Buffer
	encoder := json.NewEncoder(&result)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(result.Bytes(), []byte{'\n'}), nil
}

func randomUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func makeSMID() (string, error) {
	uuid, err := randomUUID()
	if err != nil {
		return "", err
	}
	uuidHash := md5.Sum([]byte(uuid))
	value := time.Now().Format("20060102150405") + hex.EncodeToString(uuidHash[:]) + "00"
	smskHash := md5.Sum([]byte("smsk_web_" + value))
	return value + hex.EncodeToString(smskHash[:])[:14] + "0", nil
}
