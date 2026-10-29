[English](guest.md) | 简体中文

# Guest 文件

Go 实现的文档见 [pkg.go.dev](https://pkg.go.dev/github.com/verirelay/protocol/guest)。

来宾启动声明和引导文件都按严格规则解码：

- 各自恰好是一个 JSON 对象。
- 任何层级出现未知字段或重复键都无效。
- 每个键都必须与字段名完全一致（包括大小写）。

base64url 值均为 canonical 且无 padding 的形式。

## 来宾启动声明（Guest Manifest）

initrd 中的 `/etc/verirelay/manifest.json` 记录 Guest 的构建来源和启动参数：

```json
{
  "version": "verirelay-guest-manifest/1",
  "source": {
    "verirelay": { "repository": "https://github.com/verirelay/verirelay", "commit": "<40-hex sha>" },
    "veriforge": { "repository": "https://github.com/verirelay/veriforge", "commit": "<40-hex sha>" }
  },
  "launch_profile": {
    "version": "verirelay-launch-profile/1",
    "measurement_profile": "sev-snp-qemu-direct-boot/1",
    "vcpu_type": "EPYC-v4",
    "guest_features": "0x1",
    "kernel_hashes": true,
    "kernel_append": "<kernel cmdline>"
  }
}
```

| 字段 | 规则 |
| --- | --- |
| `version` | `"verirelay-guest-manifest/1"` |
| `source.verirelay.repository`, `source.veriforge.repository` | canonical 形式的 HTTPS 仓库 URL，见下文 |
| `source.verirelay.commit`, `source.veriforge.commit` | 小写 40 位 hex commit SHA |
| `launch_profile.version` | `"verirelay-launch-profile/1"` |
| `launch_profile.measurement_profile` | `"sev-snp-qemu-direct-boot/1"` |
| `launch_profile.vcpu_type` | `"EPYC-v4"` |
| `launch_profile.guest_features` | `"0x1"` |
| `launch_profile.kernel_hashes` | `true` |
| `launch_profile.kernel_append` | 非空的内核 cmdline，不含 NUL、换行或其他控制字符 |

仓库 URL：

- 是带 host 和 path 的 `https` URL；
- 不含 user info、query、fragment 或末尾斜杠；
- 不以 `.git` 结尾；
- 必须是 canonical 形式：scheme 和 host 为小写，URL 语法要求百分号编码的字符都已编码。

来宾启动声明不含 vCPU 数量：启动度量已覆盖它，同一套启动产物集可以用任意 vCPU 数量启动。

`source` 和 `launch_profile` 是重算启动度量的复现提示。它们由 VeriRelay 的证明接口公开，不进入 `REPORT_DATA`、密钥绑定和收据。

`launch_profile.kernel_append` 是权威的内核 cmdline 提示。

## 引导文件（Bootstrap）

```json
{"version":"veriprov-bootstrap/1","protocol":"veriprov/1","url":"https://veriprov.example.com","identity_public_key":"<unpadded base64url, 32 bytes>","profile":"<optional>"}
```

| 字段 | 规则 |
| --- | --- |
| `version` | `"veriprov-bootstrap/1"` |
| `protocol` | `"veriprov/1"` |
| `url` | VeriProv 的 HTTPS origin，不含 user info、path（`/` 也不行）、query 或 fragment，可以带显式端口 |
| `identity_public_key` | VeriProv 身份密钥的 32 字节 Ed25519 公钥，base64url 编码，该密钥为 envelope 签名；见 [`veriprov/1` 配置下发](veriprov1.zh-CN.md)的「Envelope 签名」一节 |
| `profile` | 可选，1 到 64 个 `[A-Za-z0-9._-]` 字符，出现时不能为空 |

引导文件最多 4096 字节，不含 NUL 字节。`HOST_DATA` 覆盖它的原始字节，因此对文件的任何改动（包括空白）都会改变 `HOST_DATA`。

### 配置盘

宿主机通过配置盘交付引导文件，配置盘是一个只读的 raw virtio 块设备：

- 设备内容是引导文件字节，其后是直到设备末尾的零 padding。
- CVM 中恰好有一个 virtio 块设备。
- Guest 把第一个 NUL 之前的字节作为引导文件。设备在引导文件之后必须有 NUL，引导文件不能为空。

### `HOST_DATA` 绑定

```text
HOST_DATA = SHA-256(引导文件字节)
```

宿主机在启动时用 QEMU `-object sev-snp-guest,...,host-data=<32 字节 digest 的 base64>` 设置 `HOST_DATA`。

Guest 把读到的引导文件的 SHA-256 与自身证明报告中的 `HOST_DATA` 比较，不一致时不进行配置下发。

VeriRelay 在证明响应中以 `bootstrap` 公开引导文件字节（[`avr/1` 收据](avr1.zh-CN.md)的「证明响应」一节），验证方据此做同样的比较。
