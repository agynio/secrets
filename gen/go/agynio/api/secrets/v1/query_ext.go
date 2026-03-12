package secretsv1

import "google.golang.org/protobuf/encoding/protowire"

const (
	listSecretProvidersQueryField = 3
	listSecretsQueryField         = 4
)

func (x *ListSecretProvidersRequest) GetQuery() string {
	if x == nil {
		return ""
	}
	return queryFromUnknownFields(x.unknownFields, listSecretProvidersQueryField)
}

func (x *ListSecretsRequest) GetQuery() string {
	if x == nil {
		return ""
	}
	return queryFromUnknownFields(x.unknownFields, listSecretsQueryField)
}

func queryFromUnknownFields(raw []byte, fieldNumber protowire.Number) string {
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return ""
		}
		raw = raw[n:]
		if num == fieldNumber && typ == protowire.BytesType {
			value, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return ""
			}
			return string(value)
		}
		m := protowire.ConsumeFieldValue(num, typ, raw)
		if m < 0 {
			return ""
		}
		raw = raw[m:]
	}
	return ""
}
