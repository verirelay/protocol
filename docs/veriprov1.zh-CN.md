[English](veriprov1.md) | 简体中文

# `veriprov/1` 配置下发

`veriprov/1` 是 VeriProv（服务端）与 VeriRelay Guest（客户端）之间的配置下发契约。

[`schemas/veriprov1/`](../schemas/veriprov1/) 存放消息和运行配置的 JSON Schema。Go 实现的文档见 [pkg.go.dev](https://pkg.go.dev/github.com/verirelay/protocol/veriprov1)。

每条消息和运行配置都恰好是一个 JSON 对象，按宽松规则解码：

- 任何层级的未知字段都被忽略。
- 任何层级出现重复键都无效，每个键都必须与字段名完全一致（包括大小写）。
- 必填字段仍然必填。

所有 base64url 值均为 canonical 且无 padding 的形式。时间戳为整秒、以 `Z` 结尾的 RFC 3339 UTC，例如 `2026-07-11T07:00:00Z`。

## Challenge

challenge 请求是空 JSON 对象 `{}`。

challenge 响应包含以下字段，均为必填：

| 字段 | 类型 | 规则 |
| --- | --- | --- |
| `challenge_id` | string | 不透明 token：至少 16 字节，base64url 编码 |
| `nonce` | string | 恰好 32 字节，base64url 编码 |
| `issued_at` | string | 时间戳 |
| `expires_at` | string | 晚于 `issued_at` 的时间戳 |
| `ttl_seconds` | integer | 正数 |

客户端原样回传 `challenge_id`。challenge 是否有效或过期只由 VeriProv 判断。客户端不按自己的时钟拒绝 challenge。

## 配置下发

provision 请求包含以下字段，均为必填：

| 字段 | 类型 | 规则 |
| --- | --- | --- |
| `challenge_id` | string | challenge 响应中的 `challenge_id` |
| `provisioning_public_key` | string | 32 字节 X25519 原始公钥，base64url 编码，运行配置加密给它 |
| `attestation_report` | string | AMD SEV-SNP 证明报告的原始字节（1184 字节），base64url 编码，其 `REPORT_DATA` 是下文的密钥绑定 |

provision 响应是 `{"envelope": {...}}`，envelope 包含以下字段，均为必填：

| 字段 | 类型 | 规则 |
| --- | --- | --- |
| `version` | string | `"veriprov/1"` |
| `challenge_id` | string | 请求中的 `challenge_id` |
| `enc` | string | 32 字节 HPKE 封装密钥，base64url 编码 |
| `ciphertext` | string | HPKE 密文，base64url 编码 |
| `aad.protocol` | string | `"veriprov/1"` |
| `aad.challenge_id` | string | 与 envelope 的 `challenge_id` 一致 |
| `signature` | string | 64 字节 Ed25519 签名，base64url 编码 |

## 密钥绑定

```text
REPORT_DATA = SHA-512( "veriprov/1" || 0x00 || nonce || provisioning_public_key )
```

`nonce` 是 32 字节的 challenge nonce，`provisioning_public_key` 是 32 字节 X25519 原始公钥。

## 加密封装

```text
HPKE (RFC 9180), base mode, single-shot
suite = DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305
info  = "veriprov/1\x00runtime-config"
aad   = {"protocol":"veriprov/1","challenge_id":"<id>"}
```

AAD 字节就是这段紧凑 JSON：恰好这两个成员，按此顺序，不含空白。`<id>` 是 envelope 的 `challenge_id`。明文是运行配置 JSON。

## Envelope 签名

```text
message   = "veriprov/1\x00envelope\x00" || challenge_id || 0x00 || enc || ciphertext
signature = Ed25519(VeriProv 身份私钥, message)
```

`challenge_id` 是 envelope 中按原样发送的 `challenge_id` 字符串（UTF-8）。`enc` 和 `ciphertext` 是解码后的字节。

Guest 在打开 envelope 之前用引导文件的 `identity_public_key`（[Guest 文件](guest.zh-CN.md)的「引导文件（Bootstrap）」一节）验证 `signature`，验证失败时拒绝该 envelope。

## 错误

错误响应 body 是 `{"error": {...}}`：

| 字段 | 类型 | 规则 |
| --- | --- | --- |
| `error.code` | string | 下表中的错误码之一 |
| `error.message` | string | 人类可读的说明 |
| `error.request_id` | string，可选 | request id |

每个错误码对应固定的 HTTP 状态码：

| 错误码 | HTTP 状态码 |
| --- | ---: |
| `invalid_request.malformed_json` | 400 |
| `invalid_request.invalid_field` | 400 |
| `invalid_request.body_too_large` | 413 |
| `challenge.not_found` | 404 |
| `challenge.expired` | 409 |
| `attestation.report_data_mismatch` | 409 |
| `policy.denied` | 409 |
| `envelope.hpke_failed` | 503 |
| `service.unavailable` | 503 |
| `internal.error` | 500 |

服务路由与各错误码的触发条件见 [VeriProv 服务 API](https://github.com/verirelay/veriprov/blob/main/docs/api.zh-CN.md)。

## 运行配置

```json
{
  "version": "verirelay-runtime-config/1",
  "admin_token": "<token>",
  "receipt_store": { "type": "redis", "addr": "redis.internal:6379", "tls": true, "key_prefix": "verirelay:", "ttl_seconds": 3600 },
  "raw_store": { "type": "memory", "max_ttl_seconds": 86400, "max_bytes": 268435456 }
}
```

| 字段 | 类型 | 规则 |
| --- | --- | --- |
| `version` | string | 必填，`"verirelay-runtime-config/1"` |
| `admin_token` | string | 必填且非空，首尾不含空白 |
| `receipt_store` | object | 可选，收据存储 |
| `raw_store` | object | 可选，原文留存存储 |

`receipt_store` 和 `raw_store` 包含以下字段：

| 字段 | 适用于 | 类型 | 规则 |
| --- | --- | --- | --- |
| `type` | 所有存储 | string | 必填，`"redis"` 或 `"memory"` |
| `addr` | Redis | string | 必填，不能为空白 |
| `tls` | Redis | boolean | 可选 |
| `username` | Redis | string | 可选 |
| `password` | Redis | string | 可选 |
| `db` | Redis | integer | 可选，不能为负数 |
| `key_prefix` | Redis | string | 可选，非空，默认 `"verirelay:"` |
| `ttl_seconds` | `receipt_store` | integer | 可选，正数，默认 `3600` |
| `max_entries` | memory `receipt_store` | integer | 可选，正数，默认 `10000` |
| `max_ttl_seconds` | `raw_store` | integer | 可选，不能为负数，为 `0` 或不填表示不设上限 |
| `max_bytes` | memory `raw_store` | integer | 可选，正数，默认 `268435456`（256 MiB） |

不填的字段取默认值，填写的字段必须符合规则。不适用于该存储 `type` 的字段会被忽略。

存储不填时：

- 不填 `receipt_store` 时，收据存储是使用默认值的 memory 存储。
- 不填 `raw_store` 时，若 `receipt_store` 是 Redis，原文留存存储使用它的 Redis 连接和 `key_prefix`，否则是使用默认值的 memory 存储。

`key_prefix` 是所有 Redis key 的命名空间根：

| Key | 内容 |
| --- | --- |
| `<key_prefix>receipt:<request_id>` | 一张收据 |
| `<key_prefix>attestation:<key_id>` | 某个收据签名密钥归档的证明响应 |
| `<key_prefix>raw:<store_id>` | 一份原文留存 |

各字段的作用见 VeriRelay 的 [configuration.zh-CN.md](https://github.com/verirelay/verirelay/blob/main/docs/configuration.zh-CN.md) 中「VeriProv 下发的运行配置」一节。

## 测试向量

| 文件 | 内容 |
| --- | --- |
| [`veriprov1/testdata/binding_golden.json`](../veriprov1/testdata/binding_golden.json) | 一个 nonce、一个 X25519 公钥、绑定输入以及得到的 `REPORT_DATA` |
| [`veriprov1/testdata/hpke_golden.json`](../veriprov1/testdata/hpke_golden.json) | 一对测试专用接收方密钥、一个 AAD 上下文、`enc`、`ciphertext` 以及它们解密得到的明文 |
| [`veriprov1/testdata/envelope_signature_golden.json`](../veriprov1/testdata/envelope_signature_golden.json) | 一个测试专用 VeriProv 身份密钥种子及其公钥、一个已签名的 envelope 以及它的签名消息 |
| [`veriprov1/testdata/verirelay_runtime_config_valid.json`](../veriprov1/testdata/verirelay_runtime_config_valid.json) | 一份合法的运行配置 |
