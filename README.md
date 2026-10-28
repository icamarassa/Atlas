# Atlas TI — documentação de TI

Aplicação web e API ASP.NET Core 10 para manuais e POPs de TI. A implantação usa três serviços: MariaDB 11.8 com InnoDB, API e site estático Nginx. 

## Limpeza dos documentos de exemplo

A base SQL não insere documentos fictícios; ela cria apenas a estrutura, categorias e permissões iniciais. Os 12 documentos de demonstração estavam no armazenamento local do navegador. A interface agora inicia vazia e, ao abrir/recarregar a Biblioteca, remove esses títulos de demonstração do navegador, junto com seus favoritos, alertas e anexos locais. Documentos próprios com outros títulos são mantidos. A limpeza ocorre no navegador em que os dados estavam; como eram dados locais, não eram compartilhados com outros usuários.

## Implantar no servidor que já tem Docker Compose

O `docker-compose.yml` desta pasta já contém os três serviços. A forma mais simples é colocar o AtlasTI em uma pasta própria no servidor, com este Compose e o `.env`, separado do Compose dos outros sistemas. Se preferir incorporar no Compose existente, copie os serviços `mariadb`, `api` e `web`, além dos volumes ao fim do arquivo. Nesse caso, ajuste os caminhos relativos: `build.context` deve apontar para a pasta do AtlasTI (por exemplo `./manual-ti`) e os volumes dos certificados também devem começar com `./manual-ti/certs/`. Copie as variáveis do `.env.example` para o `.env` que fica ao lado do Compose existente (sem sobrescrever variáveis dos outros sistemas). Mantenha nomes de serviços, portas, variáveis e volumes únicos; o `api` precisa alcançar o serviço MariaDB pelo nome `mariadb` na rede interna do Compose. Não publique a porta da API.

Copie a pasta `manual-ti` completa para o servidor Linux, preservando `api/`, `web/`, os arquivos do site, `docker-compose.yml` e `.env.example`. Entre nessa pasta e prepare os segredos:

```bash
cp .env.example .env
openssl rand -hex 32
openssl rand -hex 32
openssl rand -base64 48
openssl rand -hex 32
nano .env
chmod 600 .env
mkdir -p certs/ldap-ca
```

Use valores diferentes para `MARIADB_ROOT_PASSWORD`, `MARIADB_PASSWORD`, `JWT_SIGNING_KEY` e `DATA_PROTECTION_CERT_PASSWORD`. Edite também os campos LDAP e o e-mail inicial do administrador. `LDAP_USER_ID_FORMAT` deve permanecer `{0}` se o diretório aceitar o login informado diretamente. Não compartilhe o `.env` nem a saída expandida de configurações do Compose.

A API em Linux precisa de um certificado local para criptografar as chaves de proteção de dados persistidas. Gere um certificado autoassinado para esse uso, usando a senha de exportação definida em `DATA_PROTECTION_CERT_PASSWORD`:

```bash
openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
  -keyout certs/atlas-ti-dp.key -out certs/atlas-ti-dp.crt \
  -subj "/CN=AtlasTI Data Protection"
openssl pkcs12 -export -out certs/atlas-ti-dp.pfx \
  -inkey certs/atlas-ti-dp.key -in certs/atlas-ti-dp.crt
chmod 600 certs/atlas-ti-dp.pfx certs/atlas-ti-dp.key
```

O comando solicitará a senha de exportação; informe exatamente a mesma do `.env`. O certificado acima serve para proteger chaves da aplicação, não é o certificado do site HTTPS. Copie para `certs/ldap-ca/` o certificado da autoridade certificadora que emitiu o certificado do LDAPS `192.168.20.14` (e do servidor secundário, se houver), em formato PEM e com extensão `.crt`. Se o arquivo recebido tiver extensão `.cer`, converta-o para PEM conforme as instruções abaixo. Confirme que o certificado é da CA emissora e que o certificado do LDAP foi emitido por ela. A API exige uma cadeia LDAPS confiável; não desativa a validação do certificado.

Para converter o arquivo `.cer` fornecido pelo administrador do diretório, execute no servidor. O comando detecta se o arquivo de origem está em PEM ou DER e grava o resultado no local montado pelo Compose:

```bash
if sudo openssl x509 -in /etc/cert/gacc-HERA-CA-1.cer -noout >/dev/null 2>&1; then
  sudo openssl x509 -in /etc/cert/gacc-HERA-CA-1.cer \
    -out /opt/atlas-ti/certs/ldap-ca/gacc-HERA-CA-1.crt
else
  sudo openssl x509 -inform DER -in /etc/cert/gacc-HERA-CA-1.cer \
    -out /opt/atlas-ti/certs/ldap-ca/gacc-HERA-CA-1.crt
fi
sudo chmod 644 /opt/atlas-ti/certs/ldap-ca/gacc-HERA-CA-1.crt
sudo openssl x509 -in /opt/atlas-ti/certs/ldap-ca/gacc-HERA-CA-1.crt \
  -noout -subject -issuer
```

Confira o `subject` e o `issuer` exibidos com a equipe de diretório para garantir que é a CA que assina o certificado LDAPS. O início do contêiner instala essas CAs no repositório confiável e, em seguida, inicia a API com usuário sem privilégios.

Valide a sintaxe e inicie os serviços:

```bash
docker compose config -q
docker compose up -d --build
docker compose ps
docker compose logs -f mariadb api web
```

Abra `http://192.168.20.29:5225`. O Nginx serve o site e encaminha chamadas `/api/` para a API dentro da rede Docker. A API aguarda a base ficar saudável, inicializa as tabelas e configurações iniciais, e os dados são guardados em volumes nomeados: `atlas-ti-mariadb-data`, `atlas-ti-documents` e `atlas-ti-dataprotection`. Faça backup desses volumes e do certificado PFX. Nunca use `docker compose down -v` para uma parada normal, porque o `-v` remove os volumes e os dados.

O mapeamento atual publica o banco em `192.168.20.29:8060`. No firewall do servidor, restrinja TCP/8060 aos computadores ou serviços administrativos que realmente precisarem conectar ao banco. O site usa TCP/5225. Se o endereço `192.168.20.29` não estiver configurado em uma interface do host Docker, substitua o IP à esquerda dos mapeamentos de portas pelo IP real do servidor.

> Se mesclar os serviços no Compose de outro sistema, execute os comandos dentro da pasta que contém esse arquivo e mantenha os caminhos relativos apontando para a pasta AtlasTI (por exemplo `./manual-ti/certs/...`). O Compose pode usar uma rede existente ou criar a própria; os três serviços do AtlasTI precisam compartilhar a mesma rede.

## Configuração manual (API no Windows)

Para uso temporário fora do Docker, mantenha o banco no servidor e execute a API no Windows. Requisitos: .NET 10 SDK, conectividade até `192.168.20.29:8060` e acesso ao LDAPS `192.168.20.14:636` com certificado confiável. Configure a senha de `atlas_ti` quando o inicializador solicitar. Não coloque senhas no comando nem em `appsettings.json`.

```powershell
.\Initialize-AtlasTi.ps1 -DatabaseHost "192.168.20.29" -DatabasePort 8060 -LdapHost "192.168.20.14" -LdapSecondaryHost "" -AdminLogin "icaro.admin"
```

O login ocorre pelo LDAP com credenciais individuais; senhas pessoais não são armazenadas. Até dois servidores LDAPS podem ser configurados em Administração → Active Directory. A conta de consulta LDAP, Base DN e atributo de login são configurados nessa tela. A credencial de consulta é criptografada pela API antes de ser gravada no banco. A conta administradora inicial é `icaro.admin`; ela precisa existir no diretório para autenticar.

## Iniciar a API no Windows

Requisitos: .NET 10 SDK, acesso ao NuGet.org (ou feed interno), conectividade até `192.168.20.29:8060` e acesso ao LDAP `192.168.20.14:636` com certificado LDAPS confiável.

Na pasta do projeto, execute:

```powershell
.\Initialize-AtlasTi.ps1
```

O script solicita a senha do usuário `atlas_ti` configurada no `.env` do servidor. Não coloque senhas no comando nem em `appsettings.json`. O script restaura dependências, conecta ao MariaDB, cria as tabelas/categorias/papéis/permissões se a base estiver vazia, provisiona `icaro.admin` como administrador inicial e executa a API em `http://localhost:5225`.

Se preferir, altere os parâmetros ao iniciar:

```powershell
.\Initialize-AtlasTi.ps1 -DatabaseHost "192.168.20.29" -DatabasePort 8060 -LdapHost "192.168.20.14" -LdapSecondaryHost "" -AdminLogin "icaro.admin"
```

O login ocorre pelo LDAP com credenciais individuais; senhas pessoais não são armazenadas. Até dois servidores LDAPS podem ser configurados na tela Administração → Active Directory. Para JIT, associe grupos do AD aos papéis Administrador, Aprovador, Editor e Leitor. Configure Base DN, atributo de login e uma conta de consulta sem privilégio administrativo, com leitura/pesquisa na árvore do diretório; sua credencial é criptografada pela API antes de ser gravada. As páginas do portal exigem sessão LDAP válida e os endpoints de dados validam o JWT e as permissões.

## API

- `POST /api/auth/login`, `GET /api/me`
- `GET/POST /api/documents`, `PUT /api/documents/{id}`
- `POST /api/documents/{id}/versions`, `POST /api/documents/{id}/submit`
- `GET /api/approvals/pending`, `POST /api/approvals/{approvalId}/decision`
- `PATCH /api/documents/{id}/state`
- `GET/PUT /api/admin/users`, `GET /api/admin/roles`, `PUT /api/admin/roles/{roleName}/permissions`
- Swagger em `/swagger` no modo de desenvolvimento; saúde em `/health/live` e `/health/ready`.

Os papéis iniciais são Administrador, Editor, Aprovador e Leitor. Os estados do documento incluem Publicado, Obsoleto, Inativo e Revisão. O banco mantém versões, solicitações de aprovação e trilha de auditoria.

## Configuração e migração

`api/appsettings.json` contém valores não secretos de referência. Segredos e ajustes de implantação são fornecidos por variáveis de ambiente, por exemplo `ConnectionStrings__AtlasTi`, `Jwt__SigningKey`, `DataProtection__KeyEncryptionCertificatePath`, `DataProtection__KeyEncryptionCertificatePassword` e `Ldap__*`. A tela `/admin-settings.html` permite gerenciar os servidores e parâmetros LDAP; os parâmetros de banco são configurados no ambiente da API. As chaves de ASP.NET Data Protection ficam em `api/App_Data/DataProtectionKeys`; preserve essa pasta em reinícios e implantações e restrinja seu acesso. No Windows, as chaves são protegidas pelo DPAPI. Em Linux/produção, a API exige um certificado PFX para proteger as chaves. Preserve também esse certificado e o volume de chaves, pois a credencial LDAP criptografada depende deles para ser lida.

O MariaDB pode ser movido para outro host Linux com dump/restore e atualização da connection string. A API e o schema usam MariaDB/MySQL. Migrar para SQL Server exigiria adaptar o dialeto SQL.

## Documentos, conteúdo e anexos

O cadastro permite escrever o manual ou POP no editor integrado e, opcionalmente, anexar um PDF, DOC ou DOCX à versão. O conteúdo do editor é apresentado em modo somente leitura ao consultar o documento. Para corrigir ou atualizar uma publicação, cria-se uma nova versão; as versões anteriores permanecem no histórico. PDF pode ser visualizado no navegador. DOC/DOCX são disponibilizados para download, mantendo o arquivo original.

Os endpoints da API aceitam conteúdo e anexo multipart. Os arquivos são armazenados fora da pasta pública do site, com nome interno aleatório, limite de 25 MB, validação de tipo e hash SHA-256. Configure `DocumentFiles:RootPath` (ou `DocumentFiles__RootPath` no ambiente) para apontar a pasta persistente do servidor; faça backup dessa pasta junto com o banco.

Enquanto o banco/API ainda não forem implantados, a interface principal opera como demonstração local: registros ficam no `localStorage` do navegador e anexos ficam no IndexedDB do mesmo navegador. Essa persistência não sincroniza entre usuários ou computadores. A API e o schema estão preparados para a persistência compartilhada quando o banco estiver disponível.

## Administração e ajuda

A engrenagem do topo oferece atalhos para Active Directory, alertas do sistema, configurações gerais e gerenciamento de usuários. O sino abre o pop-up de alertas novos; para registrar leitura, a pessoa precisa confirmar que leu, e também pode ignorar o aviso. `alert-settings.html` concentra as preferências e `notifications.html` mostra o histórico de leitura, ignorados, pendentes e resolvidos. No modo de demonstração, esse histórico fica no navegador. No perfil, usuários podem escolher uma foto local e alterar a senha do diretório; a foto permanece neste navegador e a troca de senha exige que o LDAP, a conta de pesquisa e o Base DN estejam configurados. O menu do espaço de trabalho seleciona o módulo Biblioteca de TI e deixa pontos de entrada para futuros módulos. O manual de uso está em `guide.html`, também acessível pelos atalhos de ajuda do sistema.

## LDAPS

A API usa bind simples apenas dentro de uma sessão LDAPS com validação normal de certificado; não desativa a validação. Instale a CA do diretório nos hosts da API e confirme que o certificado do LDAP corresponde ao nome usado na configuração.

## Perfis de acesso

| Perfil | O que pode |
|---|---|
| **Master** | Administrador do sistema: tudo. Vê usuários e perfis, altera grupos de cada conta, exclui e restaura usuários, edita grupos e limites de visualização e configura o Active Directory. É o único que concede ou retira o papel Master. |
| **Administrador** | Nível privilegiado de documentos: aprova, altera estado, oculta, corrige autoria, **exclui documentos** e **cria/edita categorias e sistemas**. Não vê usuários nem configura integrações. |
| Editor / Aprovador / Leitor | Criam e enviam, aprovam, ou apenas leem documentos publicados. |

Permissões novas: `document.manage` (ocultar/autoria), `document.delete`, `catalog.manage`, `user.view`, `user.delete`.
Na primeira inicialização depois da atualização, quem tinha o papel Administrador atribuído manualmente passa a ser Master (para ninguém perder acesso) e o administrador inicial (`DatabaseBootstrap__AdminExternalId`) é sempre Master.
Grupos do AD mapeados para "Administrador" continuam nesse nível; para dar acesso total a um grupo do AD, mapeie-o para "Master" em Active Directory → Mapeamento de grupos.
Excluir um usuário é reversível: a conta perde acesso e grupos, mas documentos e histórico continuam com o nome da pessoa. Há sempre ao menos um Master ativo.
