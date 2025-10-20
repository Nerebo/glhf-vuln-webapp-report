---

---
# GLHF - Good Luck Have Fun
por André Fonseca

### Cesar School  
### Ciência da Computação  
### Segurança Cibernética
### Professor: Henrique Arcoverde


Recife – PE  
16 de Outubro de 2025





![Images/Capa_GLHF.png]

---

## Resumo

### Objetivos
Avaliação de segurança da aplicação web GLHF, com foco na identificação de fraquezas e vulnerabilidades que possam ser exploradas por usuários ou malfeitores
### Metodologia
A análise foi realizada manualmente por meio da exploração direta da aplicação, combinando técnicas de mapeamento de superfície de ataque, manipulação de requisições, análise de fluxos e verificação de comportamentos inesperados em funcionalidades críticas.
### Ferramentas
Firefox Devtools, Burp Suite Community, Scripts Python, Vscode e ambiente virtualizado Docker.
### Escopo
A avaliação foi conduzida em ambiente local com base nas instruções do repositório. Foram examinadas páginas públicas, fluxos de login e recuperação de conta, gerenciamento de pedidos e funcionalidades administrativas.
### Período da avaliação
- Início: 10/10/2025
- Finalização 16/10/2025
### Vulnerabilidades Identificadas
Foram identificadas 9 vulnerabilidades de segurança, classificadas conforme o OWASP Top 10:2021 e suas respectivas CWE. As falhas abrangem desde falhas de enumeração de usuários até falhas graves de autenticação e controle de acesso a paineis de administrador.
### Principais Impactos
- Falha na autenticação de sessão pelo backend
- Cookies de sessão fácilmente forjáveis
- Exposição de estrutura interna do banco de dados através de injeção de SQL
- Execução de código malicioso no cliente
- Armazenamento inseguro de dados
- Acesso completo a interfaces de administrador

---

| #   | Título                                                            | Endpoin(s)               | Parâmetro(s)             | Componente Afetado                                                              | Abrangência                            | OWASP    | CWE                                |
| --- | ----------------------------------------------------------------- | ------------------------ | ------------------------ | ------------------------------------------------------------------------------- | -------------------------------------- | -------- | ---------------------------------- |
| 1   | Enumeração de Usuários                                            | /login, /direct          | username, toUser         | backend (verificação de identidade)                                             | usuários não autenticados              | A07:2021 | CWE-204                            |
| 2   | Sistema vulnerável a brute-force                                  | /login, /mfa             | username, password, code | Backend(ausencia de Rate Limiter), Backend (Mecanismo de autenticação)          | Usuários não autenticados              | A07:2021 | CWE-307                            |
| 3   | Token de Sessão previsíveis (Informações do Usuario e Time Based) | -                        | session_id (Cookie)      | Backend (Geração de Tokens)                                                     | Usuários autenticados                  | A02:2021 | CWE-330, CWE-311, CWE-326, CWE-340 |
| 4   | Escalação Horizontal                                              | /profile                 | bio, user_id             | Backend (Mecanismo de validação)                                                | Usuários autenticados                  | A01:2021 | CWE-284, CWE-639                   |
| 5   | Cross-Site Scripting                                              | /profile, /direct, /root | bio, message, toUser     | Frontend (Renderização de informações), Backend (Armazenamento sem codificação) | Usuários autenticados                  | A03:2021 | CWE-79, CWE-80                     |
| 6   | SQL Injection                                                     | /board                   | search                   | Backend (Queries do banco)                                                      | Usuários autenticados                  | A03:2021 | CWE-89                             |
| 7   | Insecure Direct Object References                                 | /static/avatars/{id}     | -                        | -                                                                               | Usuários autenticados/não autenticados | A01:2021 | CWE-284, CWE-639, CWE-200          |
| 8   | Armazenamento inseguro de dados críticos                          | -                        | -                        | Backend (Armazenamento de senha no banco), FrontEnd (Exposição dos dados)       | Usuarios Autenticados                  | A02:2021 | CWE-326, CWE-759                   |
| 9   | Falha de autenticação na interface administrativa                 | /root                    | token                    | Sistema inteiro                                                                 | Root                                   | A05:2021 | CWE-656                            |

---
## Enumeração de Usuário
### Ponto Afetado: 
Endpoint(s): `/login, /direct`
Parametro(s): `username, toUser`
Componente Afetado: `backend (verificação de identidade)`
Abrangência: `Usuários não autenticados`

### Descrição
Na exploração incial foi possível se identificar uma falha de enumeração de usuários no mecânismo de Login, uma falha que permite ao atacante saber quais usuários estão cadastrados no sistema por meio diferenças na resposta da aplicação. Essa falha se dá pois a resposta da requisição possui algumas diferenças sutis. Já mais a frente também foi encontrada uma falha de enumeração na página de `direct` onde o sistema indicava a existência de um usuário

**Enumeração na página de login**
Durante os testes foi possível se identificar algumas diferenças em requisições que apontavam para uma enumeração de usuários
- Tempo de resposta: Para requisições que continham como `username` usuários existentes no banco, foi possível se identificar um aumento significativo no tempo de resposta, com as requisições corretas tendo um tempo de espera de 100ms+. Como observado na imagem abaixo tentativas de login para contas existentes possuem um tempo de espera e número de caracteres elevado
	![[Images/Enumeracao_Tempo_Resposta.png]]

- Diferença no HTML: Ao se inserir credênciais válidas o código HTML da página apresentava sutís diferenças, com a div de classe `login-error` tendo seu valor modificado
	- Resposta para usuário incorreto: `<div class="login-error">Invalid credentials.<!-- id:0 --></div>`
	 ![[Images/Enumeracao_Invalid_Credentials_0.png]]
	- Resposta para usuários corretos: `<div class="login-error">Invalid credentials.<!-- id:1 padding -------------- --></div>`
	 ![[Images/Enumeracao_Invalid_Credentials_1.png]]

**Enumeração na página de direct**
O fluxo de envio de mensagens para novos usuários possui uma falha de enumeração, visto que, caso um nome incorreto seja inserido o sistema retornará uma mensagem de erro dizendo "`usuario x não encontrado`"
![[Images/Enumeracao_Usuario_Inexistente.png]]
### Classificação
**OWASP Top-10**: [AO7:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
**CWE** [CWE-204](https://cwe.mitre.org/data/definitions/204.html)

### Impacto
A capacidade de realizar a distinção entre usuários existentes e inexistentes no sistema com base na diferença no número de caracteres e no tempo de resposta. Isso pode ocasionar na criação de uma lista de usuários válidos o que viabiliza ataques de força bruta, Password spraying ou se aproveitar de falhas de autenticação.

### Recomendações
- Implementar mecânismos de proteção contra automação, como um captcha, rate limiting ou prova de trabalho (PoW)
- Evitar o envio de respostas explicitamente diferentes
- Geração de alertas em caso de múltiplas requisições, ou requisições de endereços de IP suspeitos

---
## Ataques de Força Bruta
### Ponto Afetado: 
Endpoint(s): `/login, /2fa`
Parametro(s): `username, password, code`
Componente Afetado: `backend (mecanismo de autenticação), backend(ausencia de rate limiter)`
Abrangência: `Usuários não autenticados`

### Descrição
Após a exploração inicial com o ataque de enumeração de usuário, foi possível se montar uma lista de usuários existentes no sistema, essa lista viria a ser utilizada como componente de um ataque de força bruta, que consiste na realização de repetitivas requisições ao sistema em busca de mudanças na resposta (No caso da página de login a resposta esperada era um 302 redirecionando o usuário ao endpoint de `/2fa`) contra o endpoint `/login`, com o objetivo de encontrar uma lista de usuários e senhas válidas. Após encontrar um usuário válido, com as credenciais `usuario: windows96, senha: iloveyou2`.
![[Images/Bruteforce_User_Pass.png]]
Com o acesso parcial ao sistema foi necessário contornar o mecanismo de autenticação de segundo fator (2FA). Observou-se que a aplicação invalidava o token de sessão ao detectar **três tentativas falhas** de 2FA (logout/desautenticação), o que deveria mitigar ataques por repetição. Para contornar essa proteção, um script automatizado foi desenvolvido para repetir o fluxo de login a cada tentativa: o atacante efetua o login primário para obter um novo _cookie_ de **pré-autenticação** e em seguida testa códigos 2FA de 4 dígitos no intervalo lógico `0000`–`9999`. Esse loop de _re-login → testar 2FA → novo re-login_ permitiu à prova de conceito realizar muitas tentativas de código sem permanecer dependente do mesmo token original, viabilizando a enumeração massiva de códigos 2FA apesar do logout após três falhas.
![[Images/Bruteforce_Algoritmo.png]]
![[Images/Bruteforce_MFA.png]]
![[Images/Session_Code_Decode_Estrutura.png]]
Através da execução do algoritmo foi possível se obter um código de sessão valido e que seguia a seguinte estrutura: 
`session_id = {u:nome de usuario, id:id do usuario, r: funcao do usuario no sistema, exp: tempo de expiracao do cookie (1hr), v: 1`
Sabendo disso foi possível se forjar esse cookie de sessão e por meio da função de match and replace do burpsuite ganhar acesso ao sistema
![[Images/Bruteforce_Match_and_Replace.png]]
### Classificação
**OWASP TOP 10:** [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
**CWE**: [CWE-307](https://cwe.mitre.org/data/definitions/307.html)

### Impacto
Um ataque de força bruta pode comprometer contas (especialmente com senhas fracas), permitindo acesso a dados sensíveis, movimentação lateral e escalonamento de privilégios — mesmo 2FA pode ser contornado se o fluxo for vulnerável.

### Recomendações
- Implementar mecânismos de proteção contra automação, como um captcha, rate limiting ou prova de trabalho (PoW)
- Geração de alertas em caso de múltiplas requisições, ou requisições de endereços de IP suspeitos
- Aumento da entropia do Token, adicionando caracteres extra ou permitindo que ele abranja o alfabeto

---
## Token de Sessão feito com base em dados previsíveis e do usuário

### Ponto Afetado:
Endpoint(s): `Todas sessões autenticadas`
Parametro(s): `session_id (Cookie)`
Componente Afetado: `Backend (Geração de Tokens)`
Abrangência: `Usuários não autenticados`
### Descrição
Após a realização de ataques de força bruta foi identificado que o algoritmo utilizado pelo sistema para a geração de cookies de sessão possuia dados previsíveis e dados do usuário, que então eram codificados seguindo o seguinte algoritmo
![[Images/Session_Algoritmo_Sistema.png]]

Após a identificação da estrutura do cookie de sessão um objeto previsível contendo `u`, `id`, `role`, `exp` e `v` que é apenas codificado em Base64, o próximo passo lógico será a tentativa de forjar os cookies. Para isso foi criado um algoritmo que permite a inserção de dados que serão então codificados em base 64 de forma a gerar um cookie de sessão válido que permita o acesso ao sistema

![[Images/Session_Algoritmo.png]]

Após a criação de um cookie de sessão válido, foi possível se obter acesso ao sistema, através da função de match and replace do BurpSuite Comunity, que artificialmente insere o cookie de sessão em todas as requisições que passam pelo proxy.

![[Images/Bruteforce_Match_and_Replace.png]]
![[Images/Session_Acessando_Perfil.png]]
### Classificação

**OWASP Top-10**: [AO2:2021 Identification and Authentication Failures](https://owasp.org/Top10/pt-BR/A02_2021-Cryptographic_Failures/)
**CWE** [CWE-330](https://cwe.mitre.org/data/definitions/330.html), [CWE-311](https://cwe.mitre.org/data/definitions/311.html), [CWE-326](https://cwe.mitre.org/data/definitions/326.html), [CWE-340](https://cwe.mitre.org/data/definitions/340.html)
### Impacto
Permitir que tokens de sessão previsíveis, ou fácilmente forjáveis, sejam aceitos sem a verificação de integridade ou vínculo com estado server-size, acaba por expor a apicação a ataques. Um atacante capaz de manipular um session_id pode realizar a invasão e o acesso a recursos de forma indevida, de modo a realizar uma escalação de privilégios horizontal ou vertical.
### Recomendações
- Evitar a utilização de dados do usuário para a criação de tokens de sessão
- Evitar a utilização de variáveis previsíveis, no caso do token o tempo
- Realizar a autenticação da sessão pelo back-end

---
## Escalação de privilégios horizontal
Ponto Afetado: 
Endpoint(s): `/profile`
Parametro(s): `bio, user_id`
Componente Afetado: `backend(mecanismo de validação)`
Abrangência: `Usuários autenticados`

### Descrição
Na página de perfil do usuário foi possível se identificar uma escalação de privilégios horizontais, onde um usuário realiza ações que não deveriam ser permitidas a si porém não recebe mais privilégios. Na página de perfil do usuário, mais especificamente no campo de modificação de descrição é possível se verificar que o campo escondido do tipo user_id é enviado em requisições, e é com base nele que o sistema verifica e modifica a descrição.

Na funcionalidade de edição de perfil, foi identificado um fraco controle de autorização, o formulário envia um campo oculto `user_id` que o backend utiliza para identificar de qual perfil a nova descrição será.
![[Images/Escalação_Horizontal_Perfil.png]]

Isso permite que usuários autenticados modifiquem o user_id na requisição e alterem o campo de bio de outros usuários sem necessitar de elevação de privilégios, configurando-se como uma escalação horizontal de privilégios
![[Images/XSS_Perfil_Pre_Modificacao.png]] 

Requisição de modificação da descrição do usuário 7000 (Neo) 

![[Images/XSS_Requisição_Mudança_Perfil.png]]

Perfil de Neo pós ataque

![[Images/XSS_Perfil_Desc_Mudada.png]]

### Classificação
- **OWASP TOP 10:** [A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)  
- **CWE:** [CWE-284 — Improper Access Control](https://cwe.mitre.org/data/definitions/284.html), [CWE-639 — Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

### Impacto 
Um atacante autenticado pode alterar o conteúdo de perfis alheios, inserindo links maliciosos, scripts ou desinformação, afetando a confidencialidade e integridade dos perfis de outros usuários. Dependendo do conteúdo (ex.: injeção de HTML/JS), isso pode também levar a ataques XSS contra visitantes dos perfis e posterior comprometimento de contas. Há também impacto reputacional e risco regulatório se perfis oficiais forem adulterados.

### Recomendações
- Ignorar o id enviado pelo usuário em requisições
- Adoção do princípio de menor privilégio
- Realizar a validação de requisições pelo backend baseado na sessão

--- 
### Cross-Site-Scripting
### Ponto Afetado: 
Endpoint(s): `/profile, /direct, /root`
Parametro(s): `bio, message, toUser`
Componente Afetado: Frontend (Renderização de informações), Backend (Armazenamento sem codificação)
Abrangência: `Usuários autenticados`

### Descrição
Foi identificado um XSS persistente: entrada maliciosa em campos textuais (por exemplo `bio`, `message`, `toUser`) é armazenada no banco e posteriormente renderizada pelo frontend sem codificação/escape adequados, fazendo com que o código HTML/JavaScript injetado seja executado no navegador de outros usuários ao acessar as páginas afetadas.

No GLHF essa injeção maliciosa de código, adicionado com a escalação horizontal de privilégios, permite a injeção de código malicioso na descrição de outros usuários do sistema, impedindo-os de acessar seu próprio perfil, ou até mesmo travando seu navegador inteiramente. Um caso parecido ocorreu na rede MySpace em 2006 onde um usuário criou um Worm que se propagava através de injeção de XSS na descrição de seu perfil.
![[Images/Injecao_XSS_Perfil.png]]

Essa injeção de código malicioso não se limita apenas a página de perfil de usuários, estando presente também na função de mensageria da aplicação onde as mensagens são processadas e enviadas sem a sanitização adequada. Isso possibilita a invasores o envio indiscriminado de código malicioso a usuários, que será executado em seu navegador, travando a aplicação, realizando requisições indevidas ou levando-os a domínios externos, maliciosos, que possam roubar suas informações
![[Images/Injecao_XSS_Chat_Botao.png]]
![[Images/Injecao_XSS_Chat_Redirecionamento.png]]

Outro ponto onde ocorre a injeção de XSS, é na página de root, onde ao realizar a querry `SELECT * FROM CHAT` é possível ser vítima Cross-Site Scripting, visto que o sistema armazena em seu banco de dados as mensagens de forma não-segura

![[Images/XSS_Terminal.png]]
### Classificação
- **OWASP TOP 10:** [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/)  
- **CWE:** [CWE-79 — Cross-Site Scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html), [CWE-80 — Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)
### Impacto
Um ataque de XSS pode ter impactos significativos tanto para usuários quanto para a aplicação. Esse tipo de vulnerabilidade possibilita que invasores executem código HTML ou JavaScript diretamente no navegador de vítimas comprometendo a integridade do sistema. Entre os principais riscos ao sistema estão o redirecionamento de vítimas a domínios maliciosos, o travamento de seu navegador ou a realização de ações de forma ilicita.
### Recomendações
- Sanitização adequada das requisições enviadas pelos usuários 
- Utilização do HTML encoding 
- Encoding das mensagens pre-armazenamento no banco

---
## SQL Injection
### Ponto Afetado: 
Endpoint(s): `/board`
Parametro(s): `search`
Componente Afetado: `backend (querries no banco)`
Abrangência: `Usuários autenticados`

### Descrição
O campo de busca do _board_ é vulnerável a injeção de SQL: entradas do usuário são incorporadas diretamente em consultas ao banco sem tratamento adequado, permitindo alterar a lógica da query e recuperar dados arbitrários do banco (schema, tabelas e conteúdo). Durante os testes foi possível enumerar o número de colunas, identificar tipos de retorno e listar tabelas e registros do banco, demonstrando exposição completa do conteúdo armazenado.

Para devidamente explorar essa vulnerabilidade primeiros precisamos descobrir como é o retorno da querry original, para isso foi utilizada a querry `' OR 1=1 UNION SELECT NULL, NULL, NULL, NULL, NULL, NULL --`  que possuia como retorno
![[Images/SQL_Injection_Union.png]]

Testando com uma coluna a mais na querry de união, foi possível se encontrar a seguinte página de erro, indicando que o número correto de colunas que deveriam ser adicionadas depois da UNION eram seis.![[Images/SQL_Injection_Union_Num_Colunas_Certo.png]]

agora para verificar o tipo de dados que é retornado foi feita a consulta `' OR 1=1 UNION SELECT 'A', 'A', 'A', 'A', 'A', 'A', 'A' --`![[Images/SQL_Injection_As.png]]

Sabendo disso, agora nós podemos alterar levemente a consulta anterior afim de obter o schema (Tabela que armazena as estruturas de outras tabelas) do banco de dados, para isso foi executada a injeção `' OR 1=1 UNION SELECT 'A', 'A', 'A', 'A', 'A', name, from sqlite_schema` de forma que o retorno foram o nome de todas as tabelas presentes no banco
![[Images/SQL_Injection_Tabelas_3.png]]
![[Images/SQL_Injection_Tabelas_4.png]]

Sabendo disso, agora temos acesso total ao banco de dados e suas tabelas, podendo verificar informações de usuários, mensagens, board e comentários. Para exemplificar iremos rodar a consulta `' OR 1=1 UNION SELECT * FROM USERS`
![[Images/SQL_Injection_Info_Usuarios.png]]
### Classificação
- **OWASP TOP 10:** [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/)  
- **CWE:** [CWE-89 — SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
### Impacto
A injeção de código SQL no GLHF, pode levar ao exfiltration de todo o banco de dados, comprometimento de credenciais. Seus impactos incluem a perda de confidencialidade, integridade e disponilidade dos dados. 

### Recomendações
- Fazer uso de prepared statements (Consultas parametrizadas)
- Não anexar os dados enviados por usuários diretamente as requisições
- utilização de Encoding quando necessário

---

## Insecure Direct Object References

Endpoint(s): ` /static/avatars/{id}`  
Parametro(s): `id`  
Componente Afetado: `-`  
Abrangência: `Usuários não autenticados`

### Descrição
Em uma exploração da página de perfil foi identificado que arquivos de avatare de usuários podem ser acessíveis diretamente através de arquivos estáticos da aplicação, sem verificação de autorização ou atenticação. Permitindo que atores não autenticados acessem, enumerem e recuperem imagens de perfil dos usuários através do ID em sua URL
acessando o diretório `minhaapp:1337/static/img/avatar/{id}.png`
![[Images/IDOR_Acesso_Imagem_Perfil.png]]
### Classificação
- **OWASP TOP 10:** [A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)  
- **CWE:** [CWE-284 — Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) [CWE-639 — Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

### Impacto
A exposição direta de avatares possiblita atacantes não autorizados a obeterem dados indevidos sobre a aplicação, conseguindo acessar a foto de perfil de usuários e o seu número identificador no banco (utilizado na construção do cookie de sessão)
### Recomendações
- Realizar a verificação de autorização em acessos
- Servir arquivos por meio de endpoints controlados
- Minimizar metadados expostos
- Adoção do princípio de menor privilégio

---
## Armazenamento Inseguro de Dados

### Ponto Afetado: 
Endpoint(s): `-`
Parametro(s): `-`
Componente Afetado: `backend (armazenamento no banco), Frontend (exposição dos dados)`
Abrangência: `Usuários não autenticados`
### Descrição
A forma como dados críticos, senha de usuários, estão sendo armazenadas no sistema é insegura e vunerável a ataques de rainbow table (ataques de tabelas de hash pre-computado). Isso expõe os usuários a vazamentos de credenciais, comprometendo a confidencialidade e integridade das contas. Além disso informações sensíveis também são expostas, como o identificador único de usuários no banco sendo exposto no caminho da imagem. A chave privada do Flask também é exposta no repositório da aplicação.
![[Images/Rainbow_Table.png]]
![[Images/Escalação_Horizontal_Perfil.png]]

### Categoria
- **OWASP TOP 10:** [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)  
- **CWE:** [CWE-326 — Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)  [CWE-729 — Use of a One-Way Hash Without a Salt](https://cwe.mitre.org/data/definitions/729.html)
### Impacto
O armazenamento inseguro de senhas e a exposição de informações críticas pode levar a comprometimento de contas de usuários, permitindo que atacantes obtenham credenciais válidas e acessem perfis e dados privados. Caso essas credenciais sejam reutilizadas em outros sistemas, o risco se estende a serviços externos, gerando **perda de confidencialidade, exposição de dados sensíveis, fraude, e danos à reputação da aplicação**.
### Recomendações
- Utilização de algoritmos de hash com salt para armzenamento de senhas
- Utilização de algoritmos de hash mais forte
- Notificação a todos os usuários atualmente cadastrados no sistema para que atualizem sua senha urgentemente

---

## Falha no controle de acesso ao painel de admin

### Ponto Afetado: 
Endpoint(s): `/root`
Parametro(s): `token`
Componente Afetado: `backend(validacao de acesso inadequada)`
Abrangência: `Root`

### Descricao
O endpoint administrativo `/root` permite acesso a funcionalidades críticas sem exigir autenticação adequada, pedindo apenas um token de sessão que pode fácilmente ser forjado como já foi visto anteriormente. Qualquer usuário que descubra o endpoint ou um token estático pode obter acesso completo à interface administrativa. Nesta interface estão disponíveis ferramentas de alto risco, como um **console shell** e um **console SQLite**, expondo toda a infraestrutura e os dados do sistema. A ausência de autenticação efetiva transforma um recurso crítico em um vetor de comprometimento total do sistema.

![[Images/Interface_Administracao.png]]

### Categoria
- **OWASP TOP 10:** [A05:2021 — Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
- **CWE:** [CWE-656 — Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

### Impacto
A falha permite que atacantes realizem **ações administrativas completas**, incluindo execução de comandos no shell, manipulação direta do banco de dados SQLite, alteração ou exclusão de dados sensíveis, e configuração de contas de usuários. Isso resulta em **comprometimento total do sistema, perda de confidencialidade, integridade e disponibilidade**, além de sérios riscos legais, reputacionais e de conformidade.
### Recomendações
- Não confiar apenas em segurança por obscuridade
- Aprimorar os mecanismos de autenticação
- Geração pseudo aleatória de tokens através de um csprng