# 🎄 Amigo Secreto

Mural de amigo secreto: cada pessoa entra pelo convite, deixa dicas e links de presente, vota no dia, no local e na comida, e vê quem tirou no próprio celular, sem que ninguém mais veja (nem o organizador).

## Publicar (GitHub Pages)

O app é publicado pelo GitHub Pages direto deste repositório. Basta que as mudanças cheguem ao branch configurado em **Settings → Pages** (normalmente `main`, pasta raiz).

Todos estes arquivos precisam ficar juntos na raiz: `index.html`, `app.js`, `privacidade.html`, `sw.js`, `manifest.webmanifest`, `icon.svg`, `icon-192.png`, `icon-512.png` e a pasta `fonts/`.

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
