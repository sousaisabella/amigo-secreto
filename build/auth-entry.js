/* Login do Firebase (anônimo + Google). Empacotado em vendor/firebase-auth.js pelo `npm run build`.
   Exposto como window.FBAuth para o app.js, que continua sem dependências. */
import { initializeApp } from "firebase/app";
import {
  getAuth, connectAuthEmulator, onIdTokenChanged, signInAnonymously, signOut,
  GoogleAuthProvider, signInWithPopup, linkWithPopup, signInWithCredential, linkWithCredential
} from "firebase/auth";

/* configuração pública do app web (não é segredo: identifica o projeto; a proteção vem das regras) */
const config = {
  apiKey: "AIzaSyBVkzFjS3wDDd8QAuLJsyn7DBdBbSCge8o",
  authDomain: "amigo-secreto-64e8b.firebaseapp.com",
  databaseURL: "https://amigo-secreto-64e8b-default-rtdb.firebaseio.com",
  projectId: "amigo-secreto-64e8b",
  storageBucket: "amigo-secreto-64e8b.firebasestorage.app",
  messagingSenderId: "938460990493",
  appId: "1:938460990493:web:dd2b2685a1e4efba544af4"
};

let auth = null;
const listeners = [];
let beforeSwitch = null;   /* o app tira a pessoa anônima das festas antes da troca de conta */
const fromProvider = (u, k) => ((u.providerData || []).find(p => p && p[k]) || {})[k] || "";
const info = u => u && { uid: u.uid, anon: u.isAnonymous, name: u.displayName || fromProvider(u, "displayName"), email: u.email || fromProvider(u, "email") };
const emit = (u, err) => listeners.forEach(fn => { try { fn(info(u), err); } catch (e) {} });

/* entra com o Google mantendo a mesma conta quando a pessoa já estava como anônima */
async function withGoogle(viaPopup, credential) {
  const u = auth.currentUser;
  try {
    if (u && u.isAnonymous) {
      const r = credential ? await linkWithCredential(u, credential) : await linkWithPopup(u, viaPopup);
      /* depois de ligar, entra de novo com a mesma credencial do Google: a conta é a mesma, mas o token
         passa a dizer "entrou com Google" (as regras do banco exigem isso para criar festa) */
      const again = credential || GoogleAuthProvider.credentialFromResult(r);
      if (again) { try { return (await signInWithCredential(auth, again)).user; } catch (e) {} }
      await r.user.getIdToken(true);
      return r.user;
    }
    return (credential ? await signInWithCredential(auth, credential) : await signInWithPopup(auth, viaPopup)).user;
  } catch (e) {
    /* essa conta Google já tem cadastro: entra nela (os dados anônimos deste aparelho ficam para trás) */
    if (e && (e.code === "auth/credential-already-in-use" || e.code === "auth/email-already-in-use")) {
      const c = GoogleAuthProvider.credentialFromError(e) || credential;
      if (c && beforeSwitch) { try { await beforeSwitch(); } catch (x) {} }
      if (c) return (await signInWithCredential(auth, c)).user;
    }
    throw e;
  }
}

window.FBAuth = {
  config,
  start(emulator) {
    auth = getAuth(initializeApp(config));
    auth.languageCode = "pt-BR";
    if (emulator) connectAuthEmulator(auth, "http://127.0.0.1:9099", { disableWarnings: true });
    onIdTokenChanged(auth, u => {
      if (!u) { signInAnonymously(auth).catch(e => emit(null, e)); return; }
      emit(u);
    });
  },
  onChange(fn) { listeners.push(fn); },
  beforeSwitch(fn) { beforeSwitch = fn; },
  user() { return info(auth && auth.currentUser); },
  token(force) { return auth && auth.currentUser ? auth.currentUser.getIdToken(!!force) : Promise.resolve(""); },
  async google() {
    const p = new GoogleAuthProvider();
    p.setCustomParameters({ prompt: "select_account" });
    const u = await withGoogle(p);
    emit(u); return info(u);
  },
  /* só no emulador local, para os testes automáticos */
  async googleForTests(sub, email, name) {
    if (!auth || !auth.emulatorConfig) throw new Error("apenas no emulador");
    const c = GoogleAuthProvider.credential(JSON.stringify({ sub, email, name, email_verified: true }));
    const u = await withGoogle(null, c);
    emit(u); return info(u);
  },
  signOut() { return signOut(auth); }
};
