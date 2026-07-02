# Apêndice do Artefato VulnForge AI

Este apêndice complementa o `README.md` com informações adicionais para a avaliação pelo Comitê Técnico de Artefatos (CTA) do SBRC 2026.

## Recursos específicos ou restrições

Não são necessários recursos adicionais (infraestrutura de nuvem, chaves SSH, etc.) para a execução dos testes e experimentos descritos no `README.md`.

A única exceção opcional é a **chave de API de LLM** caso o revisor deseje testar a análise/síntese via modelo em nuvem (OpenRouter). Sem chave, o sistema faz fallback automático para o analisador baseado em regras e mutadores offline.

### Para executar com LLM real (opcional)

```bash
export OPENROUTER_API_KEY="sua-chave"
export VULNFORGE_LLM_PROVIDER="openrouter"
export VULNFORGE_LLM_MODEL="anthropic/claude-sonnet-4"
protoforge analyze --text "..."
```

## Informações de contato

- Autores: VulnForge AI Team
- Repositório: <URL_DO_REPOSITORIO>
- E-mail de contato: <EMAIL_DE_CONTATO>

## Notas para revisores

- O modo padrão de todos os comandos de ataque é **dry-run**; nenhum tráfego é enviado sem confirmação explícita.
- A execução de ataques reais requer alvos em redes de laboratório permitidas pelo safety guard.
- O Dockerfile utiliza apenas CPU (sem GPU/CUDA) e inclui `tcpdump` para capturas opcionais.
