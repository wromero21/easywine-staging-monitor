# Monitor operacional do EasyWine Staging — piloto de sete dias

**Pacote preparado para revisão. Nenhum repositório, publicação, agendamento ou aviso foi criado por este pacote.** Destino proposto: repositório público separado `wromero21/easywine-staging-monitor`. Publicar somente os sete arquivos abaixo, mediante aprovação explícita do responsável. O repositório do aplicativo não recebe alterações.

| Publicação permitida | Finalidade |
| --- | --- |
| `README.md` | Procedimento e limites |
| `host-once.mjs` | Adaptador operacional |
| `pilot-policy.public.json` | Política pública fixa |
| `.github/workflows/staging-monitor.yml` | Workflow e permissões delimitadas |
| `components/monitor-collector/passive-collector.mjs` | Coletor existente, bytes preservados |
| `components/operations-readiness-20261017/alerts/alert-engine.mjs` | Motor existente, bytes preservados |
| `components/operations-readiness-20261018/alerts-durable/run-once.mjs` | Runner durável existente, bytes preservados |

**Excluir testes, estado sintético, relatórios locais e qualquer arquivo não listado.** A divulgação pública compreende código operacional, URL pública do Staging e histórico sanitizado de disponibilidade. Não inclui código do aplicativo, credenciais, e-mails pessoais ou dados de usuários.

## Funcionamento delimitado

O workflow usa runner Linux padrão e Node 24.14.0, sem instalar pacotes npm, cache ou artifacts. Apenas o token automático `GITHUB_TOKEN`, com `contents:write` e `actions:read`, permite gravar a branch `monitor-state` e conferir a conclusão dos jobs de aviso. Não há PAT, segredo adicional, domínio ou transporte SMTP.

O cron configura uma rodada a cada cinco minutos. Cada rodada reserva duas tentativas GET e consulta somente a raiz e `/api/health` de `https://easywine-staging.pages.dev`, com dez segundos por alvo, sem cookies, autenticação, redirect ou retry. Não testa Auth, banco, Gemini ou pagamentos. Três falhas abrem um incidente; dois sucessos o recuperam, conforme o motor original.

O bootstrap fixa uma única época de sete dias. São permitidas até 2.016 rodadas e 4.032 reservas GET, sem reinício automático. A reserva é persistida por commit CAS antes da coleta; checkpoint e intenções de aviso são persistidos por outro CAS. Conflito, corrupção ou reserva incompleta interrompem novas sondas. Não usar cache/artifact como estado nem resetar a branch. Mudanças do driver/workflow/política ou componentes durante a época são recusadas.

O job falha uma vez por nova abertura persistida, solicitando o aviso nativo do Actions. Incidente ainda aberto aparece no resumo com amostras e contagem ativa; não gera outra falha artificial. Recuperação produz job bem-sucedido e resumo, sem simular falha para enviar e-mail. O motor conserva sua fila pendente; não chamamos `recordDelivery`.

Conclusão de job, intenção de aviso e recibo humano são registros separados. A preferência do proprietário já foi conferida: avisos no GitHub e por e-mail, somente para workflows com falha. **Entrega real ainda não foi comprovada.** O destinatário depende do ator do cron: a primeira publicação deve usar a sessão do proprietário ou autenticação Git vinculada a ele. Assinar o commit com seu nome não prova esse ator.

## Procedimento posterior à aprovação

1. Criar o repositório público isolado e publicar somente a lista acima com identidade do proprietário. Conferir divulgação, permissões e uso exclusivo do runner padrão público, com gasto adicional autorizado de US$0. Não usar runner pago, cache/artifact pago ou outro recurso. O nome estava disponível no préflight; nada foi criado.
2. Definir a variável do repositório `MONITOR_PILOT_APPROVED` como `bootstrap-only`. No workflow, escolher operação `bootstrap` e confirmação exata `BEGIN_7_DAY_PUBLIC_STAGING_PILOT`. Isso cria a época/branch somente se ausentes e faz zero GETs ao Staging. Conferir o resumo e o estado antes de prosseguir. Não repetir bootstrap nem apagar histórico para contornar falha.
3. Depois do bootstrap aprovado e conferido, definir a mesma variável como `true`. Uma execução manual `sample` faz somente uma rodada; o cron passa a usar o mesmo estado. O agendamento é best-effort e pode atrasar ou perder execuções; não é SLA de cinco minutos.
4. **Recibo único de abertura:** somente após o proprietário receber de fato o e-mail correspondente, executar operação `receipt`, preencher o ID exato mostrado no resumo, selecionar `opening-email` e confirmar `HUMAN_RECEIPT_CONFIRMED`. Isso registra a declaração humana e não faz sondas nem marca a fila original como entregue. Recibo repetido é recusado.
5. **Recibo de recuperação:** após ler a recuperação real no resumo bem-sucedido, usar a mesma operação com o ID `:recovered`, tipo `recovery-summary` e a mesma confirmação. Isso comprova leitura do resumo; não afirma entrega de e-mail de recuperação.
6. Ao encerrar os sete dias, o responsável deve **desabilitar manualmente este workflow/agendamento**, como parte da aprovação do piloto. O limite interno já impede novos GETs, mas o cron continua iniciando jobs terminais até essa ação. Não conceder `actions:write` para encerramento automático nem iniciar nova época.

Falhas de infraestrutura/estado permanecem `BLOCKED` e job com falha; avisos nativos podem se repetir. Se o problema surgir depois da coleta, até duas tentativas já podem ter ocorrido e a reserva permanece consumida. Não assumir zero requests, repetir a rodada ou recuperar automaticamente a reserva.

Foram concluídas 13 provas locais novas, inteiramente simuladas, do adaptador. Não existe modo de drill sintético remoto no driver nem teste real de e-mail executado. Recebimento efetivo e uma rodada hospedada/agendada com esta estação desligada ainda precisam de evidência. Um verificador independente da ausência do monitor permanece pendente; outro cron no mesmo GitHub não o substitui. Este piloto não deve ser apresentado como monitoramento permanente completo.
