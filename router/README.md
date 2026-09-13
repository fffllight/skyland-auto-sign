# AX6000 精简版

此目录提供不依赖 Python、pip、OpenSSL 或第三方 Go 模块的单文件可执行程序，适用于当前检查到的 ARM64 AX6000。它保留：

- 从 `TOKEN.txt` 或 `TOKEN` 环境变量读取一个或多个鹰角网络通行证；
- 生成森空岛请求所需的设备标识；
- 获取明日方舟和终末地角色；
- 两款游戏的签到；
- 可选的飞书应用机器人个人签到结果推送；
- `--check` 只读检查模式和失败时的非零退出码。

为减少路由器占用，它不包含密码/验证码登录、其他推送渠道和文件日志。登录仍在可信电脑上完成，只把 `TOKEN.txt` 复制到路由器。

## 构建

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -trimpath -tags nethttpomithttp2 -ldflags='-s -w -buildid=' -o skyland-sign-arm64 .
```

`nethttpomithttp2` 去掉标准库内置的 HTTP/2 实现，程序只走 HTTP/1.1（与 Python 参考实现一致），体积少约 390 KB，功能不受影响。产物是静态链接的，不依赖 libc，可直接丢到 BusyBox / musl 的路由器上运行；部署前用 `uname -m` 确认目标机器是 `aarch64`，还可用 `go version -m skyland-sign-arm64` 核对构建信息。

### 闪存紧张时再压一层

体积实测（本目录构建，Go 1.23.1 + UPX 5.2.1，arm64）：

| 构建方式 | 体积 |
| --- | --- |
| `-trimpath -ldflags='-s -w'` | 5,374,104 |
| 上面加上 `-tags nethttpomithttp2 -buildid=` | 4,980,871 |
| 再 `upx --best`（NRV 算法，启动最快） | 1,812,408 |
| 再 `upx --lzma`（本目录附带的 `.upx` 版本） | **1,483,072** |

```sh
upx --lzma skyland-sign-arm64   # 追求最小，本目录的 skyland-sign-arm64.upx 就是这一档
upx --best skyland-sign-arm64   # 稍大但解压更快
upx -t skyland-sign-arm64       # 打包后校验
```

代价：启动时在内存中解压，峰值多占约 5 MB 内存、多花几十毫秒；section header 被移除，`go version -m` 不再能读取构建信息。解压只在内存中进行、不改写文件，`os.Executable()` 定位 `TOKEN.txt` 的行为不变。压缩版和未压缩版行为完全一致，可以先跑 `--check` 确认能连通再决定用哪个。

## 使用

把 `skyland-sign-arm64`（或压缩版 `skyland-sign-arm64.upx`）和 `TOKEN.txt` 放在同一目录，然后执行：

```sh
chmod 700 skyland-sign-arm64
chmod 600 TOKEN.txt
./skyland-sign-arm64 --check
./skyland-sign-arm64 --test-feishu
./skyland-sign-arm64
```

`--check` 只验证设备标识、令牌、凭证和角色绑定，不会调用签到接口。`--test-feishu` 只发送一条飞书测试消息，也不会签到。建议第一次部署时先跑通 `--check` 再放到定时任务里。

`TOKEN.txt` 每行一个鹰角网络通行证，也支持直接粘贴森空岛网页上的整段 JSON（会自动取出其中的通行证）。也可以用 `TOKEN` 环境变量代替文件，多个通行证用逗号分隔；环境变量存在时优先于文件。

## 飞书推送

默认从可执行文件所在目录读取 `TOKEN.txt` 和 `FEISHU_APP.json`，可从任意工作目录启动。使用 `--token-file` 或 `--feishu-config` 显式指定相对路径时，路径相对于当前工作目录。

把飞书应用凭证和接收人的 `open_id` 单独保存：

```sh
cat > FEISHU_APP.json <<'EOF'
{
  "app_id": "应用 App ID",
  "app_secret": "应用 App Secret",
  "receive_id": "接收人的 open_id"
}
EOF
chmod 600 FEISHU_APP.json
```

程序会在每次推送前获取短期 `tenant_access_token`，该临时凭证不会落盘。正常签到会汇总全部账号和角色后向指定个人推送一次；未配置 `FEISHU_APP.json` 时不会推送，`--check` 模式也不会推送。

## 部署到路由器（Xiaomi AX6000 实测）

小米/OpenWrt 的根分区是只读镜像（`touch /x` 报 `Read-only file system`），`/etc` 只是内存
overlay（重启即丢），只有 `/data` 这类 ubi 卷可写且重启保留。所以二进制和配置都放
`/data/skyland-sign/`，并用一个脚本包住 cron 调用：

```sh
#!/bin/sh
# 由 cron 每天调用：签到并把输出写入日志，日志只保留最近 200 行。
# 传 check 参数时只做只读校验（--check），不签到也不推送，用于演练这条路径。
umask 077
DIR=/data/skyland-sign
MODE=""
[ "$1" = "check" ] && MODE="--check"
echo "===== $(date '+%Y-%m-%d %H:%M:%S') 开始 =====" >> "$DIR/run.log"
"$DIR/skyland-sign-arm64" $MODE --token-file "$DIR/TOKEN.txt" --feishu-config "$DIR/FEISHU_APP.json" >> "$DIR/run.log" 2>&1
tail -n 200 "$DIR/run.log" > "$DIR/run.log.tmp" && mv "$DIR/run.log.tmp" "$DIR/run.log"
```

crontab 里只留一行（BusyBox crond 每分钟自动重读 `/etc/crontabs/root`，改完不用重启服务）：

```sh
0 3 * * * /data/skyland-sign/run.sh >/dev/null 2>&1
```

日志用 `tail -n 200` 自己封顶，不依赖 logrotate——`/etc/logrotate.d` 在只读根上、内存
overlay 里加的配置重启就没了，不值得依赖。

上线前演练一次，不消耗当天签到机会（`--check` 只认证不签到）：

```sh
sh /data/skyland-sign/run.sh check
/data/skyland-sign/skyland-sign-arm64 --test-feishu --feishu-config /data/skyland-sign/FEISHU_APP.json
```

更新版本时用「先传临时名、比对 md5、再原子替换」，避免传输出错或路径短暂缺失：

```sh
ssh ax6000 'cat > /data/skyland-sign/skyland-sign-arm64.new && chmod 700 /data/skyland-sign/skyland-sign-arm64.new' < skyland-sign-arm64.upx
ssh ax6000 'md5sum /data/skyland-sign/skyland-sign-arm64.new'   # 与本机 md5sum 比对
ssh ax6000 'mv /data/skyland-sign/skyland-sign-arm64.new /data/skyland-sign/skyland-sign-arm64'
```

`/data` 一共 23 MB 上下，部署后记得删掉备份出来的旧二进制，删之前先确认新版本跑通过一次。

## 排障

- 网络请求遇到连接错误、429 或 5xx 会自动重试，共 3 次尝试、间隔 2 秒，路由器刚开机时 WAN 未就绪也能自愈。
- 报错信息里会带上服务端响应体的开头（凭证字段已遮挡），时间戳固定按 UTC+8 输出，因此路由器时区没设置也不会出现时间偏移。
- 提示"通行证可能已失效"时，在电脑上重新登录森空岛取一份新的通行证即可；程序不会删除或改写 `TOKEN.txt`。
- 若出现"解析响应 JSON"，通常是服务端返回了与预期类型不同的字段，请连同完整报错一起反馈。
