[English](avr1.md) | 简体中文

# `avr/1` 收据

`avr/1` 是 VeriRelay 每次完整转发到上游后签发的收据格式：一份 canonical 形式、用 Ed25519 签名的交换记录，签名密钥绑定到证明报告。Go 实现的文档见 [pkg.go.dev](https://pkg.go.dev/github.com/verirelay/protocol/avr1)。

所有 base64url 值均为 canonical 且无 padding 的形式，所有 hex 值均为小写。

## 解码

| 格式 | 解码 |
| --- | --- |
| 收据 | 严格：任何层级出现未知字段都无效 |
| 证明响应 | 宽松：任何层级的未知字段都被忽略 |
| 收据证据包 | 宽松，但其中的 `receipt` 严格 |
| 原文留存 envelope 和明文 | 宽松 |

每个值都恰好是一个 JSON 对象。所有格式中：

- 任何层级出现重复键都无效。
- 每个键都必须与字段名完全一致（包括大小写）。
- 必填字段仍然必填。

## 收据字段

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `version` | string | 固定为 `"avr/1"` |
| `canonicalization` | string | 固定为 `"jcs-rfc8785"`（RFC 8785） |
| `signature_algorithm` | string | 固定为 `"ed25519"` |
| `hash_algorithm` | string | 固定为 `"sha256"` |
| `request_id` | string | VeriRelay 分配的 request id（`X-VeriRelay-Request-Id`） |
| `timestamp` | string | RFC 3339 UTC，以 `Z` 结尾 |
| `method` | string | 被代理请求的方法 |
| `upstream_authority` | string | 上游 host[:port] |
| `upstream_path` | string | 转发时的 path 与 query |
| `request_body_sha256` | string | 请求 body 的 hex SHA-256 |
| `response_body_sha256` | string | 响应 body 的 hex SHA-256 |
| `response_status` | integer | 上游 HTTP 状态码，100 到 599 |
| `upstream_tls.sni` | string | 连向上游时使用的 TLS SNI |
| `upstream_tls.spki_sha256` | string | 上游证书 SPKI 的 hex SHA-256 |
| `service_public_key` | string | base64url 编码的收据签名密钥 Ed25519 原始公钥（32 字节） |
| `key_id` | string | SHA-256(原始公钥) 前 8 字节的 hex |
| `signature.payload_sha256` | string | 被签名 payload 的 hex SHA-256 |
| `signature.value` | string | 对 payload 的 64 字节 Ed25519 签名，base64url 编码 |

所有字段均为必填，必填字符串不能为空。

## 签名

签名方按以下步骤生成 payload 并签名：

1. 从收据对象中去掉 `signature`。
2. 用 JCS（RFC 8785）把其余部分转为 canonical 形式。结果即 payload。
3. `signature.payload_sha256` 设为 payload 的 hex SHA-256，`signature.value` 设为对 payload 字节的 Ed25519 签名。

验证方只在以下条件全部满足时接受收据：

- 能按严格规则解码：不含上表以外的字段（包括 `upstream_tls` 和 `signature` 内部），也没有重复键。
- 所有字段齐全，四个算法标识与上表的值完全一致。
- `request_body_sha256`、`response_body_sha256` 和 `upstream_tls.spki_sha256` 都是 64 位 hex。
- `response_status` 是 100 到 599 的整数。
- `service_public_key` 解码后为 32 字节，`key_id` 与之匹配。
- `timestamp` 能按 RFC 3339 解析，并以 `Z` 结尾。
- `signature.payload_sha256` 与重新计算的 payload 一致，`signature.value` 能用 `service_public_key` 验证通过。

## 密钥绑定

```text
REPORT_DATA = SHA-512(
    "VeriRelay-AVR-REPORT-DATA/1\x00"
    || u32be(len("avr/1"))   || "avr/1"
    || u32be(len("ed25519")) || "ed25519"
    || u32be(32) || receipt_signing_public_key
    || u32be(32) || nonce
)
```

- `u32be(n)` 是 4 字节大端整数 `n`。
- `receipt_signing_public_key` 是 32 字节 Ed25519 原始公钥。
- `nonce` 是 32 字节的 Attestation Nonce。

## 证明响应

`GET /v1/avr/attestation?nonce=<base64url>` 的响应 body 是一个 JSON 对象。nonce 为 32 字节。

这些字段只是声明：标识值、编码、证书信任、签名、新鲜性、策略和披露声明均由验证方自行检查。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `version` | string | `"avr/1"` |
| `tee_type` | string | `"sev-snp"` |
| `evidence` | object | 证明报告原文 |
| `endorsements` | object | AMD 证书链 |
| `nonce` | string | base64url 编码的 Attestation Nonce |
| `receipt_signing_public_key` | string | base64url 编码的收据签名密钥 Ed25519 原始公钥（32 字节） |
| `key_id` | string | 该公钥的 `key_id`，计算方式与收据相同 |
| `key_binding` | object | 密钥绑定参数 |
| `source` | object | `verirelay` 和 `veriforge`，均为含 `repository`、`commit` 字符串的对象 |
| `launch_profile` | object | 字符串 `version`、`measurement_profile`、`vcpu_type`、`guest_features`、`kernel_append`；布尔值 `kernel_hashes` |
| `bootstrap` | string，可选 | 引导文件原始字节的 base64url，开发模式下不存在 |

`evidence`：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `format` | string | `"amd-sev-snp-report/1"` |
| `report` | string | AMD SEV-SNP 证明报告的原始字节（1184 字节），base64url 编码 |
| `report_data` | string | hex `REPORT_DATA` |

`endorsements` 中的证书均为 DER 字节的 base64url：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `format` | string | `"amd-sev-snp-cert-chain/1"` |
| `encoding` | string | `"base64url-der"` |
| `vcek` | string，可选 | VCEK 证书，为空时省略 |
| `vlek` | string，可选 | VLEK 证书，为空时省略 |
| `ask` | string | ASK 证书 |
| `ark` | string | ARK 证书 |

`key_binding`：

| 字段 | 值 |
| --- | --- |
| `rule` | `"verirelay-avr-report-data/1"`，即上文的密钥绑定 |
| `protocol_version` | `"avr/1"` |
| `signature_algorithm` | `"ed25519"` |
| `report_data_sha512` | 由 `receipt_signing_public_key` 和 `nonce` 计算出的 hex `REPORT_DATA` |
| `report_data_encoding` | `"raw-64-bytes"` |
| `public_key_encoding` | `"base64url-unpadded-ed25519-raw-32-bytes"` |
| `nonce_encoding` | `"base64url-unpadded-raw-32-bytes"` |

`source` 和 `launch_profile` 披露来自[来宾启动声明](guest.zh-CN.md)，但不是完整的来宾启动声明。仅凭这些字段存在不能认证源码身份或发布策略。

验证方用证明报告核对 `bootstrap`：解码后的 `bootstrap` 的 SHA-256 必须等于报告中的 `HOST_DATA`（[Guest 文件](guest.zh-CN.md)的「引导文件（Bootstrap）」一节）。

## 收据证据包

收据证据包是 `GET /v1/avr/evidence/<request_id>` 的响应 body，包含一张收据，以及为其收据签名密钥归档的证明响应。

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `version` | string | `"avr/1"` |
| `receipt` | object | 收据，按严格规则解码 |
| `attestation` | object 或 null | 归档的证明响应，没有归档时为 `null` |

## 原文留存

原文留存保存一次交换的请求 body 和响应 body 原文，用每次留存独立的密钥加密。密钥是客户端通过 `X-VeriRelay-Store-Key` 收到的 32 字节 AES-256 密钥（无 padding 的 base64url）。`store_id` 是 `X-VeriRelay-Store-Id` 的值。

见 VeriRelay 的 [api.zh-CN.md](https://github.com/verirelay/verirelay/blob/main/docs/api.zh-CN.md) 中「原文留存」一节。

envelope：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `version` | string | `"verirelay-raw-capture/1"` |
| `algorithm` | string | `"AES-256-GCM"` |
| `nonce` | string | 12 字节 GCM nonce，base64url 编码 |
| `ciphertext` | string | 明文的 AES-256-GCM 密文及 tag，base64url 编码 |

AAD 是 UTF-8 字符串 `version + ":" + store_id`，例如 `verirelay-raw-capture/1:<store_id>`。

明文是一个 JSON 对象：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `version` | string | `"verirelay-raw-capture-plaintext/1"` |
| `request_body` | string | 请求 body 原始字节的 base64url |
| `response_body` | string | 响应 body 原始字节的 base64url |

## 测试向量

| 文件 | 内容 |
| --- | --- |
| [`avr1/testdata/avr1_signed_receipt_golden.json`](../avr1/testdata/avr1_signed_receipt_golden.json) | 一张已签名收据、字段顺序打乱的同一张收据、它的 canonical payload、payload 哈希和签名，以及反例 |
| [`avr1/testdata/avr1_attestation_with_bootstrap.json`](../avr1/testdata/avr1_attestation_with_bootstrap.json) | 带 `bootstrap` 的证明响应 |
| [`avr1/testdata/avr1_attestation_without_bootstrap.json`](../avr1/testdata/avr1_attestation_without_bootstrap.json) | 不带 `bootstrap` 的同一响应 |
| [`avr1/testdata/raw_capture_golden.json`](../avr1/testdata/raw_capture_golden.json) | 一个测试专用密钥、`store_id`、请求 body 和响应 body、明文、AAD 以及由它们得到的原文留存 envelope |

这些证明响应中的证明报告原文是合成测试数据，不是可信的证明报告。见 [testdata README](../avr1/testdata/README.md)。
