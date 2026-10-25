package mcprecon

import "testing"

func FuzzParseRPC(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`),
		[]byte(`{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"missing"}}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"result":null,"error":{"code":1,"message":"bad"}}`),
		[]byte(`not json`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseRPC(data, 1)
	})
}
