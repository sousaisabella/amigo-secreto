# 🎄 Amigo Secreto

Mural de amigo secreto: cada pessoa entra pelo convite, deixa dicas e links de presente, vota no dia, no local e na comida, e vê quem tirou no próprio celular, sem que ninguém mais veja (nem o organizador).

## Publicar (GitHub Pages)

O app é publicado pelo GitHub Pages direto deste repositório. Basta que as mudanças cheguem ao branch configurado em **Settings → Pages** (normalmente `main`, pasta raiz).

Todos estes arquivos precisam ficar juntos na raiz: `index.html`, `app.js`, `vendor/firebase-auth.js`, `privacidade.html`, `sw.js`, `manifest.webmanifest`, `icon.svg`, `icon-192.png`, `icon-512.png` e a pasta `fonts/`.

Funciona no endereço `https://<usuário>.github.io/amigo-secreto/` (os caminhos são relativos). No celular, dá para usar "Adicionar à tela inicial".

## Regras de segurança do Firebase (obrigatório)

O banco em "modo de teste" deixa qualquer pessoa ler e apagar todas as festas, e **para de funcionar sozinho depois de 30 dias**. Para trocar pelas regras do app:

1. Abra o [console do Firebase](https://console.firebase.google.com) → projeto `amigo-secreto-64e8b`.
2. Vá em **Realtime Database → Regras**.
3. Apague o conteúdo, cole o arquivo `database.rules.json` inteiro e clique em **Publicar**.

Com essas regras:
- ninguém consegue listar ou baixar todas as festas: só lê uma festa quem tem o convite dela;
- não é possível apagar uma festa inteira de uma vez;
- cada campo tem tipo e tamanho validados, e dados estranhos são recusados;
- as regras não expiram.

## Como funciona o sigilo

- Ao entrar, cada pessoa recebe um **código de recuperação** e um par de chaves criado no próprio aparelho.
- No sorteio, o resultado de cada pessoa é cifrado com a chave pública dela. O banco só guarda texto cifrado.
- O código de recuperação permite entrar como você em outro aparelho. O **código do organizador** recupera o painel do organizador.

Limitação conhecida: sem login (Firebase Auth), o banco não tem como saber quem está escrevendo. Quem tiver o convite consegue, mexendo no banco por fora do app, alterar dados da festa. O resultado do sorteio, porém, continua secreto.

## Privacidade e segurança no navegador

- **Política de privacidade** em `privacidade.html`. É um rascunho: vale uma revisão jurídica.
- **"Apagar meus dados"**, no rodapé da festa: remove na hora nome, dica, links, votos, chaves e perguntas da pessoa (direito de exclusão, art. 18 da LGPD).
- **Sem pedidos a terceiros:** as fontes (Fredoka e Nunito, licença SIL OFL, em `fonts/`) são servidas pelo próprio site, então o IP de quem visita não vai para o Google Fonts.
- **Content-Security-Policy** via `<meta>`: só roda script do próprio site (`app.js`) e só conecta ao Firebase. Isso bloqueia scripts injetados.

## Login e regras (fase 1)

- **Convidados** entram sem login: o app cria uma conta anônima do Firebase, sem nenhum dado pessoal.
- **Quem cria uma festa** precisa entrar com o Google, o que dificulta abuso. Qualquer pessoa pode "Entrar com Google" para usar o app em outros aparelhos, e a conta anônima é ligada à conta Google sem perder nada.
- As regras em `database.rules.json` usam `auth.uid`: só você edita seus dados, só o dono da festa sorteia e mexe nas configurações, e ninguém lê a área privada `users/<uid>` de outra pessoa.
- Festas da versão anterior: o organizador toca em "Entrar com Google e reativar", os participantes são migrados automaticamente ao abrir o convite, e depois o organizador remove os perfis antigos.

### Configuração no console do Firebase

1. **Authentication → Método de login:** ative **Anônimo** e **Google**.
2. **Authentication → Configurações → Domínios autorizados:** adicione `sousaisabella.github.io`.
3. **Realtime Database → Regras:** cole `database.rules.json` e publique **antes** de publicar esta versão do site.
4. **Login com Google (Google Identity Services):** no [Google Cloud Console → Credenciais](https://console.cloud.google.com/apis/credentials?project=amigo-secreto-64e8b), abra o cliente OAuth **"Web client (auto created by Google Service)"** e adicione `https://sousaisabella.github.io` em **Origens JavaScript autorizadas**. Sem isso, a janela do Google mostra `origin_mismatch`. O app usa esse cliente em vez da página do `firebaseapp.com`, que falha no Chrome do iPhone.
5. Recomendado: no [Google Cloud Console → Credenciais](https://console.cloud.google.com/apis/credentials?project=amigo-secreto-64e8b), restrinja a chave de API "Browser key" a referenciadores HTTP `https://sousaisabella.github.io/*`.

A `apiKey` em `build/auth-entry.js` **não é segredo**: ela só identifica o projeto. A proteção vem das regras.

### Gerar o módulo de login

`vendor/firebase-auth.js` é o SDK oficial do Firebase (login), empacotado. Só é preciso gerar de novo ao mudar `build/auth-entry.js` ou atualizar o SDK:

```sh
npm install
npm run build
```

### Testes com o emulador

Com o [Firebase Emulator Suite](https://firebase.google.com/docs/emulator-suite) rodando (banco na porta 9000, login na 9099), abra `http://localhost:PORTA/?emu=1`: o app usa os emuladores em vez do projeto real.
