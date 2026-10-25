# Auditoria do MCPEnum — 25 de outubro de 2026

## Objetivo e evidência

Esta revisão compara o comportamento do MCPEnum com as práticas de descoberta de serviços do Nmap e de identificação HTTP do OWASP WSTG. O teste local usou `127.0.0.1:13000/mcp`; não é uma medição de desempenho em rede externa.

- `go test -race ./...` e `go vet ./...` passaram durante a revisão.
- O MCPEnum confirmou MCP e listou 12 ferramentas, 3 recursos e 2 prompts no alvo local. O Nmap 7.99 com `-sV`, `mcp-info` e `mcp-enum` listou as mesmas contagens.
- O perfil HTTP estendido do MCPEnum observou `HEAD /` com 404, `OPTIONS /` com 204 e `GET /` com 404. O título HTML do último foi `Error`. Estes dados são distintos da prova de MCP.
- `-sV` identificou o serviço como `mcp vulnerable-mcp-server 1.0.0`. Essa identificação foi produzida pelo mecanismo de versão e pelos scripts do Nmap; o MCPEnum não afirma ter replicado a base de assinaturas de serviços do Nmap.

## Práticas aplicadas

| Prática | Implementação / interpretação |
|---|---|
| Evidência antes de conclusão | Respostas HTTP e cabeçalhos não confirmam MCP; o detector exige uma resposta válida do protocolo. `PortInfo` fica separado do inventário MCP. |
| Custos limitados | Perfis HTTP `off`, `basic` e `extended`; uma sondagem por origem, timeout por requisição, limite de cabeçalho e até 4 KiB de corpo lido para título HTML. |
| Redirecionamentos controlados | As sondas de porta não seguem redirecionamentos; a saída remove consulta e fragmento de `Location`. |
| Dados sensíveis | O token Bearer não é enviado nas sondas da origem. Saídas usam categorias de erro e limitam os valores de cabeçalho. |
| Resultado legível e automatizável | Terminal apresenta dados da porta uma vez por origem; JSON preserva os dados por candidato. Banner, progresso e verbose vão para `stderr`. |
| Estados honestos | `open`, `closed` e `unknown` dependem de resposta HTTP ou recusa de conexão observada; cabeçalhos e identidade de servidor são autodeclarados. |

## Próximos aprimoramentos recomendados

1. **Identificação de HTTP/HTTPS em portas não padrão.** `--target` assume HTTP, exceto na porta 443. Adicionar fallback TLS controlado, com limite de uma tentativa por origem, reduziria resultados negativos por esquema incorreto. `--url` já permite selecionar o esquema exato.
2. **Fingerprint com procedência explícita.** Se forem adicionadas assinaturas de produto ou versão, guardar o padrão, resposta e nível de confiança. Um cabeçalho `Server` isolado deve permanecer identificado como autodeclarado. O Nmap diferencia nomes obtidos por tabela de porta e por sondagem e registra confiança no XML.
3. **Cobertura de outros protocolos.** Uma porta TCP aberta sem HTTP deve ser descrita como serviço desconhecido. Identificação de banners genéricos exigiria um módulo próprio e limites de escopo, não inferências a partir de uma falha HTTP.
4. **Teste contínuo de interoperabilidade.** Manter fixtures de implementações MCP modernas e legadas, autenticação, paginação, SSE, caminhos personalizados, redirecionamentos e servidores HTTP sem MCP. Comparar itens e estados, não apenas contagens.
5. **Métricas completas por origem.** Registrar separadamente contagem e duração das sondas HTTP, mantendo a métrica MCP atual comparável a versões anteriores. Para estudos de desempenho, registrar também configuração, versão da ferramenta e latência do laboratório.

## Referências

- [Nmap: service and version detection](https://nmap.org/book/man-version-detection.html)
- [Nmap: service probes and their purpose](https://nmap.org/book/nmap-service-probes.html)
- [Nmap: XML service `method` and `conf`](https://nmap.org/book/output-formats-xml-output.html)
- [OWASP WSTG: fingerprint web server](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server/)
