# 🎄 Amigo Secreto

Mural de amigo secreto: cada pessoa entra pelo convite, deixa dicas e links de presente, vota no dia, no local e na comida, e vê quem tirou no próprio celular, sem que ninguém mais veja (nem o organizador).

## Publicar

1. Arraste **a pasta inteira** (não só o `index.html`) para o [Netlify Drop](https://app.netlify.com/drop).
   Arquivos: `index.html`, `sw.js`, `manifest.webmanifest`, `icon.svg`, `icon-192.png`, `icon-512.png`.
2. Abra o endereço que o Netlify gerar. No celular, dá para usar "Adicionar à tela inicial".

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
