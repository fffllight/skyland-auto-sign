package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedHeaders(t *testing.T) {
	now := time.Unix(1695184599, 0)
	headers, err := signedHeaders(
		"11173b53e138d291c440e347107cc5b4",
		"device-id",
		"https://zonai.skland.com/api/v1/game/player/binding",
		http.MethodGet,
		"",
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if headers["sign"] != "80310db538d9a9797b98d7c330434cb3" {
		t.Fatalf("unexpected signature: %s", headers["sign"])
	}
	if headers["timestamp"] != "1695184599" {
		t.Fatalf("unexpected timestamp: %s", headers["timestamp"])
	}
}

func TestSignedPostHeaders(t *testing.T) {
	headers, err := signedHeaders(
		"11173b53e138d291c440e347107cc5b4",
		"device-id",
		"https://zonai.skland.com/api/v1/game/attendance",
		http.MethodPost,
		`{"gameId": 1, "uid": "123"}`,
		time.Unix(1695184599, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if headers["sign"] != "347e9a834e1ab768b5007c731c0328cc" {
		t.Fatalf("unexpected signature: %s", headers["sign"])
	}
}

func TestReadTokens(t *testing.T) {
	t.Setenv("TOKEN", " first,second\nfirst ")
	tokens, err := readTokens("unused")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || tokens[0] != "first" || tokens[1] != "second" {
		t.Fatalf("unexpected tokens: %#v", tokens)
	}
}

func TestPushFeishu(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/token" {
			_, _ = writer.Write([]byte(`{"code":0,"msg":"success","tenant_access_token":"tenant-token","expire":7200}`))
			return
		}
		if request.URL.Query().Get("receive_id_type") != "open_id" || request.Header.Get("Authorization") != "Bearer tenant-token" {
			t.Errorf("unexpected request metadata: %s %#v", request.URL.String(), request.Header)
		}
		var message struct {
			ReceiveID   string `json:"receive_id"`
			MessageType string `json:"msg_type"`
			Content     string `json:"content"`
		}
		if err := json.NewDecoder(request.Body).Decode(&message); err != nil {
			t.Error(err)
		}
		if message.ReceiveID != "open-id" || message.MessageType != "text" || message.Content != `{"text":"签到结果"}` {
			t.Errorf("unexpected message: %#v", message)
		}
		_, _ = writer.Write([]byte(`{"code":0,"msg":"success","data":{"message_id":"message-id"}}`))
	}))
	defer server.Close()

	config := feishuConfig{AppID: "app-id", AppSecret: "app-secret", ReceiveID: "open-id"}
	if err := pushFeishuTo(context.Background(), server.Client(), config, "签到结果", server.URL+"/token", server.URL+"/messages"); err != nil {
		t.Fatal(err)
	}
}

func TestResponseValidation(t *testing.T) {
	tests := []struct {
		name  string
		call  func(*signer) error
		valid string
	}{
		{"bindings", func(s *signer) error {
			_, err := s.getBindings(context.Background())
			return err
		}, `{"code":0,"data":{"list":[]}}`},
		{"arknights", func(s *signer) error {
			_, err := s.signArknights(context.Background(), binding{GameID: 1, UID: "123"})
			return err
		}, `{"code":0,"data":{"awards":[{"resource":{"name":"合成玉"},"count":100}]}}`},
		{"endfield", func(s *signer) error {
			_, err := s.signEndfield(context.Background(), binding{}, endfieldRole{RoleID: "123", ServerID: "1"})
			return err
		}, `{"code":0,"data":{"awardIds":[{"id":"reward"}],"resourceInfoMap":{"reward":{"name":"奖励","count":1}}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, payload := range []string{`{}`, `null`, `{"code":null}`, `{"code":0}`, `{"code":0,"data":{}}`, `{"code":1,"message":"rejected"}`, tt.valid} {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(payload))
				}))
				client := &http.Client{Transport: redirectTestTransport{target: server.URL}}
				err := tt.call(&signer{client: client, token: "test", did: "test", cred: "test"})
				server.Close()
				if (err == nil) != (payload == tt.valid) {
					t.Errorf("payload %s: unexpected error %v", payload, err)
				}
			}
		})
	}
}

func TestEndfieldRolesValidation(t *testing.T) {
	for _, roles := range []string{"", `,"roles":null`, `,"roles":[]`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"code":0,"data":{"list":[{"appCode":"endfield","bindingList":[{"uid":"123"`+roles+`}]}]}}`)
		}))
		client := &http.Client{Transport: redirectTestTransport{target: server.URL}}
		_, err := (&signer{client: client, token: "test", did: "test", cred: "test"}).getBindings(context.Background())
		server.Close()
		if roles == `,"roles":[]` {
			if err != nil {
				t.Fatalf("explicit empty roles rejected: %v", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "roles") {
			t.Fatalf("missing/null roles %q: expected roles error, got %v", roles, err)
		}
	}
}

func TestBindingListValidation(t *testing.T) {
	for _, appCode := range []string{"arknights", "endfield"} {
		t.Run(appCode, func(t *testing.T) {
			for _, list := range []string{"", `,"bindingList":null`, `,"bindingList":[]`} {
				client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					payload := `{"code":0,"data":{"list":[{"appCode":"` + appCode + `"` + list + `}]}}`
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(payload)), Header: make(http.Header)}, nil
				})}
				bindings, err := (&signer{client: client, token: "test", did: "test", cred: "test"}).getBindings(context.Background())
				if list == `,"bindingList":[]` {
					if err != nil || len(bindings) != 0 {
						t.Fatalf("explicit empty bindingList: bindings=%v, error=%v", bindings, err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "bindingList") {
					t.Fatalf("missing/null bindingList %q: expected bindingList error, got %v", list, err)
				}
			}
		})
	}
}

func TestBadFeishuConfigStillSigns(t *testing.T) {
	oldArgs, oldFlags, oldTransport := os.Args, flag.CommandLine, http.DefaultTransport
	t.Cleanup(func() {
		os.Args, flag.CommandLine, http.DefaultTransport = oldArgs, oldFlags, oldTransport
	})
	t.Setenv("TOKEN", "test-token")
	path := filepath.Join(t.TempDir(), "feishu.json")
	attendanceCalls := 0
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var payload string
		switch r.URL.String() {
		case deviceInfoURL:
			payload = `{"code":1100,"detail":{"deviceId":"test-device"}}`
		case grantCodeURL:
			payload = `{"status":0,"data":{"code":"test-code"}}`
		case credCodeURL:
			payload = `{"code":0,"data":{"cred":"test-cred","token":"test-token"}}`
		case bindingURL:
			payload = `{"code":0,"data":{"list":[{"appCode":"arknights","bindingList":[{"gameId":1,"uid":"123"}]}]}}`
		case arknightsURL:
			attendanceCalls++
			payload = `{"code":0,"data":{"awards":[]}}`
		default:
			t.Fatalf("unexpected network request: %s", r.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(payload)), Header: make(http.Header)}, nil
	})
	for _, config := range []string{`{`, `{"app_id":"test"}`} {
		if err := os.WriteFile(path, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"", "--check", "--test-feishu"} {
			attendanceCalls = 0
			os.Args = []string{"test", "--feishu-config", path}
			if mode != "" {
				os.Args = append(os.Args, mode)
			}
			flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
			err := run()
			wantCalls := 0
			if mode == "" {
				wantCalls = 1
			}
			if attendanceCalls != wantCalls || (err == nil) != (mode == "--check") {
				t.Fatalf("config=%q mode=%q: attendance calls=%d, error=%v", config, mode, attendanceCalls, err)
			}
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

const (
	referenceUID   = "11111111-2222-4333-8444-555555555555"
	referenceVPW   = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	referenceTrees = "99999999-8888-4777-8666-555555555555"
	referenceSMID  = "2023111422000000000000000000000000000000000000000123456789abcd0"
	referenceTime  = int64(1700000000000)
	// referenceDeviceData 是与 Python 参考实现（src/SecuritySm.py）逐字节交叉验证过的设备标识载荷。
	referenceDeviceData = "0f8872ba5ab4f212bea05d87725fb1e0fe55e85f560cf747fbb1c0ecf7e37c165bdd2384099614b19fe3c023d6ea9e1ab1c2362c0a2c90b56f5c6615cece25060450d744ad7627b6f901316021eb3f6bd5a23c5e89cfef0024400df8184ac013023701508979b2fd8d4eec7b67787f66c7f47d7c9b856c8421e074736ffd56d29d3bcae4460f782bd88fc31d549bc392f4dd4d37e19980fe5417fc671b098dec0781d48e75da6c82691820f0cdb32ebf7916c87a946a05663c4935d7be131e10bfc8cf77aa2d893f061a042fb953e812c2b139f11b3efefb4e1fefeb63de87ae4d5acaa01da0296f7fb8bcb79605a4fa1355bb8a249802792b66adb8df2fbefd515aa73ef511039ac53f5029b17b2511d540abab551ced92dccf2cee8a241832d4b81f2936cfb09ee3176f9d7eda08115ac8edafc683dcdc826ad6dd0db438d14416e25dd176a632e5777eed459452888b8fcf700a0873d79a2b43dba2ba06fcf8273d284a9b676290d0152004b3a3aae02aa1049faddeeaa0267d5a68d0b0f65b490424aee5e3e94414799ea4e887dc6995961f058dfab2dfa38529550cf3f63e4990b2ed029134731ff862e1bd80bc8cbffc418b719471b3cbfa620740bbe3130cbb4536d7567f5ec02e5428dcbce0305ee13e09219e7da99b4a22371e320935082f92820ad002cce6de07947e43216639730504d157d6af39853e9b2adb74557bad94125f879e3ddc600633d26985935bec7133424dbeb044ddce64d8d7c66121c763c8b81691af1c5b8ad758f13ace0fd16e51ab9d080883214773bdf0a00b1d17e7b052a9e19f951f331dcde29e39865443f356fc453d5f2560ed52a7609c0919c61a798767a2d05abf34b525d700ebe8e277820340f04847f02f147336042647cb05e920012ea8244dc84952a88a7b5f4cca8ef3dab4b0d067a4bc508a0fef05980d8f7af265f9c822082082d1512cf3be2fbcc3aa470796f8603d0be4b5fe870183ae587fc94f749da82d2f82e533e924ef126e0d01bc1c0f3f8d505400c16020b53e0e7547586dedd5d542acf115ab21f6760d290a77e4fceb2ed7c18d4f9e3ef065c6f2df5841be45608f6866e5a671f6711eca501ea6eab6203d6c2387a10d1f7053c696e732968f7ca2fb4eced6ee03c4581ad94d832395dabad2edc3837d861fad3167f12f3ee8e99e7b5c1069bd1a8dfbd1189d1f4186a0d65e45aba37698ffda8f2578d32a92eaa035b28c00f4014728d78b6c0a6275814ca98a2bacbc5d42e1b1e27f0ae9ac881a11c6e12c450ec6b7c986ca345138fad905689339103b2e417ba3631803e6b76964fad932faccee1e51e92d77c9dd990470c80dd8877c1b078b6f54fb1af44ec01a8eb7960a00b19f0f4d51ad0a8df9c83c2e4efc2ad3a2a08325231a1100e39c8c0b72ae12f86c488661b0ed85e125d803531fef354c1a1857f2c0389fbce2381915fefcad9ae5221f452265356d32fa56a13a033e81596b1de1c2608b7005dece2df0bc313b45c94e4f42e5f49e21482b42f2f64657ba0fbc4a8d4b6b7e06fecfa3759b666f069294d794d71000c4e0c041a7692cc9adbd6ac080a526c792edf6eac141ebde3d52ec4030f6a331812376f7ef55180b84369d4487b2d93cd1ed6c"
)

func TestParseTokens(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"裸令牌", " first,second\nfirst ", []string{"first", "second"}},
		{"网页 JSON", `{"code":0,"data":{"content":"from-web"}}`, []string{"from-web"}},
		{"逐行 JSON", "{\"data\":{\"content\":\"a\"}}\n{\"data\":{\"content\":\"b\"}}", []string{"a", "b"}},
		{"空内容", " \n ", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTokens(tt.raw)
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Fatalf("parseTokens(%q) = %#v, 期望 %#v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestTokenExpiredHint(t *testing.T) {
	for _, message := range []string{"获取认证代码失败: 用户未登录", "获取凭证失败: token 无效", "读取角色绑定失败: 登录已失效"} {
		got := tokenExpiredHint(errors.New(message)).Error()
		if !strings.Contains(got, "TOKEN.txt") {
			t.Errorf("%q: 缺少重新获取通行证的提示：%s", message, got)
		}
	}
	if got := tokenExpiredHint(errors.New("获取凭证失败: 服务开小差了")).Error(); got != "获取凭证失败: 服务开小差了" {
		t.Errorf("无关错误不应追加提示：%s", got)
	}
}

func TestBodySnippetMasksSecrets(t *testing.T) {
	snippet := bodySnippet([]byte(`{"code":1,"message":"拒绝","data":{"cred":"secret-cred","token":"secret-token"}}`))
	if strings.Contains(snippet, "secret") {
		t.Fatalf("响应体摘要泄漏了凭证：%s", snippet)
	}
	if !strings.Contains(snippet, "*****") || !strings.Contains(snippet, "拒绝") {
		t.Fatalf("响应体摘要缺少关键内容：%s", snippet)
	}

	long := bodySnippet([]byte(strings.Repeat("啊", errorSnippetSize+50)))
	if len([]rune(long)) != errorSnippetSize+1 || !strings.HasSuffix(long, "…") {
		t.Fatalf("超长响应体未按字符截断：%d", len([]rune(long)))
	}
}

func TestRequestRetry(t *testing.T) {
	oldBackoff := retryBackoff
	retryBackoff = 0
	t.Cleanup(func() { retryBackoff = oldBackoff })

	var out struct {
		Code int `json:"code"`
	}
	var attempts int
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		if attempts < maxAttempts {
			return nil, errors.New("connection refused")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"code":0}`)), Header: make(http.Header)}, nil
	})}
	if err := requestJSON(context.Background(), client, http.MethodGet, "https://zonai.skland.com/", nil, nil, &out); err != nil {
		t.Fatalf("重试后仍然失败：%v", err)
	}
	if attempts != maxAttempts {
		t.Fatalf("连接错误尝试次数 = %d，期望 %d", attempts, maxAttempts)
	}

	attempts = 0
	client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader(`{"message":"上游错误"}`)), Header: make(http.Header)}, nil
	})
	if err := requestJSON(context.Background(), client, http.MethodGet, "https://zonai.skland.com/", nil, nil, &out); err == nil {
		t.Fatal("持续 5xx 时应当失败")
	}
	if attempts != maxAttempts {
		t.Fatalf("5xx 尝试次数 = %d，期望 %d", attempts, maxAttempts)
	}

	attempts = 0
	client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(`{"message":"参数错误"}`)), Header: make(http.Header)}, nil
	})
	err := requestJSON(context.Background(), client, http.MethodGet, "https://zonai.skland.com/", nil, nil, &out)
	if attempts != 1 {
		t.Fatalf("4xx 尝试次数 = %d，期望 1", attempts)
	}
	if err == nil || !strings.Contains(err.Error(), "参数错误") {
		t.Fatalf("错误信息未包含响应体摘要：%v", err)
	}
}

func TestDeviceIdentifierMatchesReference(t *testing.T) {
	data, err := deviceIdentifier(referenceUID, referenceVPW, referenceTrees, referenceSMID, referenceTime)
	if err != nil {
		t.Fatal(err)
	}
	if data != referenceDeviceData {
		t.Fatalf("设备标识与参考实现不一致：\n实际 %s\n期望 %s", data, referenceDeviceData)
	}

	fields := decodeDeviceData(t, data, referenceUID)
	if len(fields) != 26 {
		t.Fatalf("字段数量 = %d，期望 26：%v", len(fields), fields)
	}
	for key, want := range map[string]any{
		"xx":       "Xoz/PL65pzA=",                                             // appId
		"jf":       "",                                                         // box
		"protocol": float64(102),                                               // 明文
		"smid":     referenceSMID,                                              // 不参与混淆
		"py":       "W8w34S/qeaQ6sY1I9BXI5f5eUKMyDBl71JbY52RJEnlqOqJ+tZsXQQ==", // tn
	} {
		if fields[key] != want {
			t.Errorf("字段 %s = %v，期望 %v", key, fields[key], want)
		}
	}
	// 规则表里参与混淆的字段都不应保留原名字（version/protocol 按规则本就是明文）。
	for key := range desRules {
		if _, ok := fields[key]; ok {
			t.Errorf("出现了未混淆的字段 %s", key)
		}
	}
	if _, ok := fields["box"]; ok {
		t.Error("出现了未混淆的字段 box")
	}
}

// decodeDeviceData 逆向还原设备标识载荷，用于断言混淆后的字段内容。
func decodeDeviceData(t *testing.T, data, uid string) map[string]any {
	t.Helper()
	payload, err := hex.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload)%aes.BlockSize != 0 {
		t.Fatalf("载荷长度 %d 不是块大小的整数倍", len(payload))
	}
	uidHash := md5.Sum([]byte(uid))
	block, err := aes.NewCipher([]byte(hex.EncodeToString(uidHash[:])[:16]))
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(payload))
	cipher.NewCBCDecrypter(block, []byte("0102030405060708")).CryptBlocks(plain, payload)

	// 明文尾部是补零，压缩数据长度未知，这里依次尝试去掉 0~16 个补零字节。
	for trim := 0; trim <= aes.BlockSize; trim++ {
		compressed, err := base64.StdEncoding.DecodeString(string(plain[:len(plain)-trim]))
		if err != nil {
			continue
		}
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			continue
		}
		decoded, err := io.ReadAll(reader)
		if err != nil {
			continue
		}
		var fields map[string]any
		if err := json.Unmarshal(decoded, &fields); err != nil {
			continue
		}
		return fields
	}
	t.Fatal("无法还原设备标识载荷")
	return nil
}

type redirectTestTransport struct {
	target string
}

func (transport redirectTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	target, err := url.Parse(transport.target)
	if err != nil {
		return nil, err
	}
	cloned.URL.Scheme = target.Scheme
	cloned.URL.Host = target.Host
	return http.DefaultTransport.RoundTrip(cloned)
}
