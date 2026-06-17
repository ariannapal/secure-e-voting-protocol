"""
entities.py
-----------
Definisce le entita' principali del sistema di voto elettronico
universitario descritto nel WP2:

    - AutoritaElettorale (AE)
    - Urna (Urna Elettronica, UE)
    - AuthServer  (Sistema di Autenticazione, AS)
    - Client      (applicazione/User Agent dell'elettore)

In questa prima implementazione vengono coperte:
    * Fase 1 - Setup iniziale e PKI (generazione reale di chiavi RSA,
      certificazione tramite la CertificationAuthority)
    * Fase 2 - Autenticazione e rilascio del token (OIDC/FIDO2 simulati,
      registro degli aventi diritto, generazione e firma del token
      pseudonimo tramite RSA-PSS)

Le fasi successive (cifratura/sottomissione del voto, Merkle Tree,
scrutinio) sono lasciate come estensioni future e non sono trattate
in questo modulo, in linea con la richiesta di implementare la
struttura di base.
"""

from __future__ import annotations

import time
import json
from dataclasses import dataclass, field
from typing import Dict, Optional

from cryptography.hazmat.primitives.asymmetric import rsa

import crypto_utils as cu
from pki import CertificationAuthority, Certificato, verifica_certificato_offline


# ---------------------------------------------------------------------------
# Strutture dati di supporto
# ---------------------------------------------------------------------------

@dataclass
class TokenVoto:
    """
    Token pseudonimo di voto T, rilasciato dall'AS allo studente che ha
    superato con successo l'autenticazione e il controllo degli aventi
    diritto. Il token e' firmato dall'AS in modo che l'Urna possa
    verificarne l'autenticita' senza dover risalire all'identita' reale
    dello studente (pseudo-anonimato).
    """
    valore: str            # T: identificativo pseudonimo casuale (hex)
    hash_token: bytes       # h_T = SHA256(T)
    firma_as: bytes         # Sig_AS(T) = Sig(SK_AS, h_T)  (RSA-PSS)
    timestamp: float = field(default_factory=time.time)

    def __repr__(self) -> str:
        return f"TokenVoto(T={self.valore[:12]}..., firmato_da_AS=True)"


@dataclass
class RegistroElettoreEntry:
    """
    Singola riga del Registro_Elettori:
        { student_ID, avente_diritto, token_rilasciato }
    """
    student_id: str
    avente_diritto: bool
    token_rilasciato: bool = False


# ---------------------------------------------------------------------------
# Autorita' Elettorale (AE)
# ---------------------------------------------------------------------------

class AutoritaElettorale:
    """
    Autorita' Elettorale (AE).

    In Fase 1 genera due distinte coppie di chiavi RSA a 4096 bit, in
    conformita' al principio di separazione delle chiavi descritto nel
    WP2:
        - coppia di Cifratura/Decifratura  (PK_AE_enc, SK_AE_enc)
        - coppia di Firma/Verifica          (PK_AE_sig, SK_AE_sig)

    La chiave privata di decifratura (SK_AE_enc) viene mantenuta offline
    e sara' utilizzata soltanto in Fase 5 (scrutinio, non implementata
    in questa versione di base).
    """

    BIT_SIZE_AE = 4096

    def __init__(self):
        self.id = "AE-UNIVERSITA"

        # Coppia di cifratura/decifratura: PK_AE^enc, SK_AE^enc
        self._sk_enc: rsa.RSAPrivateKey = cu.genera_coppia_rsa(self.BIT_SIZE_AE)
        self.pk_enc: rsa.RSAPublicKey = self._sk_enc.public_key()

        # Coppia di firma/verifica: PK_AE^sig, SK_AE^sig
        self._sk_sig: rsa.RSAPrivateKey = cu.genera_coppia_rsa(self.BIT_SIZE_AE)
        self.pk_sig: rsa.RSAPublicKey = self._sk_sig.public_key()

        # Certificati X.509, popolati dopo la certificazione (Fase 1)
        self.cert_enc: Optional[Certificato] = None
        self.cert_sig: Optional[Certificato] = None

    def richiedi_certificazione(self, ca: CertificationAuthority) -> None:
        """
        Predispone le due CSR (per la chiave di cifratura e per quella
        di firma) e le sottopone alla Certification Authority, ottenendo
        i due certificati X.509 distinti:

            Cert_AE^enc = {ID_AE, PK_AE^enc, Uso: Cifratura, ...}
            Cert_AE^sig = {ID_AE, PK_AE^sig, Uso: Firma Digitale, ...}
        """
        self.cert_enc = ca.emetti_certificato(
            id_soggetto=self.id,
            chiave_pubblica=self.pk_enc,
            uso="Cifratura",
        )
        self.cert_sig = ca.emetti_certificato(
            id_soggetto=self.id,
            chiave_pubblica=self.pk_sig,
            uso="Firma Digitale",
        )

    def __repr__(self) -> str:
        certificata = self.cert_enc is not None and self.cert_sig is not None
        return f"AutoritaElettorale(id={self.id}, certificata={certificata})"


# ---------------------------------------------------------------------------
# Urna Elettronica (UE)
# ---------------------------------------------------------------------------

class Urna:
    """
    Urna Elettronica (UE).

    Riceve esclusivamente voti cifrati (non implementato in questa
    versione di base) e, in conformita' al proprio ruolo architetturale
    (che non prevede la decifratura di dati riservati), genera in Fase 1
    soltanto una coppia di chiavi dedicata alla firma digitale (RSA-PSS),
    utilizzata per firmare ricevute e Merkle Root.

    Mantiene inoltre uno stato persistente dei token pseudonimi
    presentati dagli elettori, per poter rifiutare eventuali duplicati
    (anti-double-voting) nelle fasi successive.
    """

    BIT_SIZE_UE = 2048

    def __init__(self):
        self.id = "UE-URNA"

        self._sk_sig: rsa.RSAPrivateKey = cu.genera_coppia_rsa(self.BIT_SIZE_UE)
        self.pk_sig: rsa.RSAPublicKey = self._sk_sig.public_key()

        self.cert_sig: Optional[Certificato] = None

        # Stato dell'urna: token pseudonimi gia' utilizzati per votare.
        # Chiave: valore del token (T) -> True se gia' utilizzato.
        self._token_utilizzati: Dict[str, bool] = {}

        # Stato dell'urna: token registrati/ricevuti ma non ancora "spesi".
        # Utile per ispezionare lo stato della componente dalla CLI.
        self._token_ricevuti: Dict[str, TokenVoto] = {}

    def richiedi_certificazione(self, ca: CertificationAuthority) -> None:
        """Ottiene il certificato X.509 per la propria chiave di firma."""
        self.cert_sig = ca.emetti_certificato(
            id_soggetto=self.id,
            chiave_pubblica=self.pk_sig,
            uso="Firma Digitale",
        )

    def registra_token(self, token: TokenVoto, pk_as: rsa.RSAPublicKey) -> bool:
        """
        Riceve un token pseudonimo di voto dal Client e ne verifica
        l'autenticita' tramite la chiave pubblica dell'AS (PK_AS),
        prima di registrarlo come "presentato" nello stato dell'Urna.

        Verifica eseguita:
            Verify(PK_AS, h_T, Sig_AS(T)) = true

        Ritorna True se il token e' valido e non era gia' stato
        utilizzato, False altrimenti.
        """
        if token.valore in self._token_utilizzati:
            return False

        firma_valida = cu.rsa_pss_verify(pk_as, token.hash_token, token.firma_as)
        if not firma_valida:
            return False

        self._token_ricevuti[token.valore] = token
        self._token_utilizzati[token.valore] = True
        return True

    def token_gia_utilizzato(self, valore_token: str) -> bool:
        """Verifica se un dato token e' gia' stato impiegato per votare."""
        return self._token_utilizzati.get(valore_token, False)

    def stato(self) -> str:
        """Riassunto leggibile dello stato corrente dell'Urna."""
        return (
            f"Urna(id={self.id}, certificata={self.cert_sig is not None}, "
            f"token_registrati={len(self._token_ricevuti)})"
        )

    def __repr__(self) -> str:
        return self.stato()


# ---------------------------------------------------------------------------
# Sistema di Autenticazione (AS)
# ---------------------------------------------------------------------------

class AuthServer:
    """
    Sistema di Autenticazione (AS).

    Compiti principali (Fase 2):
        1. Delegare l'autenticazione dello studente a un Identity
           Provider tramite OpenID Connect (qui SIMULATO: non viene
           effettuata alcuna chiamata di rete reale, ma il flusso e'
           riprodotto fedelmente a livello logico).
        2. Consultare il Registro_Elettori per verificare che lo
           studente sia un avente diritto e non abbia gia' ricevuto
           un token.
        3. Generare un token pseudonimo di voto T e firmarlo con la
           propria chiave privata (RSA-PSS), in modo che l'Urna possa
           verificarne l'autenticita' senza apprendere l'identita'
           reale dello studente.

    In conformita' al proprio ruolo architetturale, l'AS genera
    esclusivamente una coppia di chiavi dedicata alla firma digitale.
    """

    BIT_SIZE_AS = 2048

    def __init__(self, path_registro: str = "studenti.json"):
        self.id = "AS-AUTENTICAZIONE"
        self._sk_sig = cu.genera_coppia_rsa(self.BIT_SIZE_AS)
        self.pk_sig = self._sk_sig.public_key()
        self.cert_sig = None
        self._registro_elettori: Dict[str, RegistroElettoreEntry] = {}
        
        # Caricamento del JSON nel server
        self._carica_registro(path_registro)

    def _carica_registro(self, path: str):
        try:
            with open(path, 'r') as f:
                dati = json.load(f)
                for s in dati["studenti"]:
                    self._registro_elettori[s["student_id"]] = RegistroElettoreEntry(
                        student_id=s["student_id"],
                        avente_diritto=s["avente_diritto"],
                        token_rilasciato=s["token_rilasciato"]
                    )
        except FileNotFoundError:
            print(f"[Avviso] File {path} non trovato.")

    def salva_registro(self, path: str = "studenti.json"):
        """Salva lo stato attuale del registro nel file JSON."""
        dati = {"studenti": []}
        for entry in self._registro_elettori.values():
            dati["studenti"].append({
                "student_id": entry.student_id,
                "avente_diritto": entry.avente_diritto,
                "token_rilasciato": entry.token_rilasciato
            })
        with open(path, 'w') as f:
            json.dump(dati, f, indent=4)

    def richiedi_certificazione(self, ca: CertificationAuthority) -> None:
        """Ottiene il certificato X.509 per la propria chiave di firma."""
        self.cert_sig = ca.emetti_certificato(
            id_soggetto=self.id,
            chiave_pubblica=self.pk_sig,
            uso="Firma Digitale",
        )

    # -- Gestione del registro degli aventi diritto --------------------------------

    def iscrivi_studente(self, student_id: str, avente_diritto: bool = True) -> None:
        """
        Inserisce (o aggiorna) una riga nel Registro_Elettori per lo
        studente indicato. Operazione tipicamente eseguita "a monte"
        dall'amministrazione universitaria, qui esposta per comodita'
        di test/demo nella CLI.
        """
        self._registro_elettori[student_id] = RegistroElettoreEntry(
            student_id=student_id,
            avente_diritto=avente_diritto,
            token_rilasciato=False,
        )

    def _controllo_aventi_diritto(self, student_id: str) -> Optional[str]:
        """
        Verifica le due condizioni descritte nel WP2:
            1) lo studente e' presente nel registro ed e' avente diritto;
            2) non gli e' gia' stato rilasciato un token.

        Ritorna None se entrambi i controlli sono superati, altrimenti
        una stringa che descrive il motivo del rifiuto.
        """
        entry = self._registro_elettori.get(student_id)
        if entry is None:
            return "Studente non presente nel Registro_Elettori."
        if not entry.avente_diritto:
            return "Studente non avente diritto al voto."
        if entry.token_rilasciato:
            return "Token di voto gia' rilasciato per questo studente."
        return None

    # -- Fase 2: OIDC simulato + FIDO2 simulato -------------------------------------

    def simula_richiesta_oidc(self, client_id: str, redirect_uri: str) -> dict:
        """
        Costruisce (senza effettuare alcuna chiamata di rete) la
        richiesta OpenID Connect che l'AS invierebbe all'Identity
        Provider:

            OIDC_Request = { client_id, redirect_uri, response_type, scope }
        """
        return {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid",
        }

    def autentica_studente_simulato(self, student_id: str) -> TokenVoto:
        """
        Punto di ingresso principale della Fase 2, esposto al Client/CLI.

        Riproduce in modo simulato l'intero flusso:
            1) costruzione della OIDC_Request verso l'IdP;
            2) simulazione del login FIDO2 (challenge/response) tra
               l'Identity Provider e l'authenticator dello studente;
            3) verifica dell'ID Token restituito dall'IdP;
            4) controllo degli aventi diritto sul Registro_Elettori;
            5) generazione del token pseudonimo T e firma RSA-PSS
               (Sig_AS(T) = Sig(SK_AS, SHA256(T))).

        Nessuna chiamata di rete reale viene effettuata: l'Identity
        Provider e l'authenticator FIDO2 sono simulati internamente a
        questo metodo, ma la sequenza logica dei passaggi e dei dati
        scambiati rispetta fedelmente il protocollo descritto nel WP2.

        Solleva PermissionError se l'autenticazione o il controllo
        degli aventi diritto falliscono.
        """

        # --- Passo 1: OIDC_Request verso l'Identity Provider --------------------
        oidc_request = self.simula_richiesta_oidc(
            client_id=self.id,
            redirect_uri="https://voto.universita.it/callback",
        )

        # --- Passo 2: simulazione del login FIDO2 --------------------------------
        # In un sistema reale la coppia (PK_studente, SK_studente) risiede
        # nel dispositivo dello studente. Qui generiamo una coppia "ad-hoc"
        # esclusivamente per dimostrare la sequenza challenge/response,
        # dato che non e' disponibile un vero authenticator hardware.
        sk_studente_simulata = cu.genera_coppia_rsa(2048)
        pk_studente_simulata = sk_studente_simulata.public_key()

        challenge = cu.genera_valore_casuale(32)          # CSPRNG
        firma_authenticator = cu.rsa_pss_sign(sk_studente_simulata, challenge)
        fido2_ok = cu.rsa_pss_verify(pk_studente_simulata, challenge, firma_authenticator)

        if not fido2_ok:
            raise PermissionError("Verifica FIDO2 fallita: autenticazione rifiutata.")

        # --- Passo 3: verifica dell'ID Token (qui assunto valido se FIDO2 ok) ----
        # In una implementazione completa l'IdP firmerebbe un ID Token JWT;
        # qui il superamento della verifica FIDO2 e' considerato equivalente
        # al ricevimento di un ID Token valido e verificato dall'AS.
        id_token_verificato = fido2_ok

        if not id_token_verificato:
            raise PermissionError("ID Token non valido: identita' non attendibile.")

        # --- Passo 4: controllo degli aventi diritto -----------------------------
        motivo_rifiuto = self._controllo_aventi_diritto(student_id)
        if motivo_rifiuto is not None:
            raise PermissionError(motivo_rifiuto)

        # --- Passo 5: generazione e firma del token pseudonimo -------------------
        valore_token = cu.genera_id_esadecimale(32)
        hash_token = cu.sha256(valore_token.encode())
        firma_as = cu.rsa_pss_sign(self._sk_sig, hash_token)

        token = TokenVoto(
            valore=valore_token,
            hash_token=hash_token,
            firma_as=firma_as,
        )

        # Aggiornamento dello stato: il token e' stato rilasciato.
        self._registro_elettori[student_id].token_rilasciato = True

        # Salva immediatamente su disco per rendere persistente il cambiamento
        self.salva_registro()

        return token

    def __repr__(self) -> str:
        n_iscritti = len(self._registro_elettori)
        n_token = sum(1 for e in self._registro_elettori.values() if e.token_rilasciato)
        return (
            f"AuthServer(id={self.id}, certificato={self.cert_sig is not None}, "
            f"iscritti={n_iscritti}, token_rilasciati={n_token})"
        )


# ---------------------------------------------------------------------------
# Client (User Agent dell'elettore)
# ---------------------------------------------------------------------------

class Client:
    """
    Applicazione/User Agent dell'elettore.

    In Fase 1 esegue il bootstrapping della fiducia: scarica/riceve i
    certificati di AE, Urna e AS e ne verifica offline l'autenticita'
    tramite la chiave pubblica della CA (PK_CA), preventivamente
    cablata nell'applicazione.

    In Fase 2 avvia, tramite l'AS, la procedura di autenticazione
    simulata e ottiene il proprio token pseudonimo di voto, che
    mantiene nel proprio stato locale (memoria volatile) per l'uso
    nelle fasi successive (sottomissione del voto, non implementata
    in questa versione di base).
    """

    def __init__(self, student_id: str, pk_ca: rsa.RSAPublicKey):
        self.student_id = student_id
        self._pk_ca = pk_ca

        # Chiavi pubbliche autenticate degli attori, popolate dopo la
        # verifica dei certificati (None finche' non verificate).
        self.pk_ae_enc: Optional[rsa.RSAPublicKey] = None
        self.pk_ae_sig: Optional[rsa.RSAPublicKey] = None
        self.pk_ue_sig: Optional[rsa.RSAPublicKey] = None
        self.pk_as_sig: Optional[rsa.RSAPublicKey] = None

        # Token di voto ottenuto in Fase 2 (None finche' non richiesto).
        self.token: Optional[TokenVoto] = None

    # -- Fase 1: bootstrapping della fiducia ----------------------------------------

    def verifica_e_carica_certificato_ae(self, cert_enc: Certificato, cert_sig: Certificato) -> bool:
        """
        Verifica offline i due certificati dell'Autorita' Elettorale
        (cifratura e firma) tramite PK_CA e, se validi, ne estrae e
        memorizza le chiavi pubbliche.
        """
        ok_enc = verifica_certificato_offline(self._pk_ca, cert_enc)
        ok_sig = verifica_certificato_offline(self._pk_ca, cert_sig)

        if ok_enc and ok_sig:
            self.pk_ae_enc = cert_enc.chiave_pubblica
            self.pk_ae_sig = cert_sig.chiave_pubblica
            return True
        return False

    def verifica_e_carica_certificato_ue(self, cert_sig: Certificato) -> bool:
        """Verifica offline il certificato dell'Urna e ne carica la chiave pubblica."""
        if verifica_certificato_offline(self._pk_ca, cert_sig):
            self.pk_ue_sig = cert_sig.chiave_pubblica
            return True
        return False

    def verifica_e_carica_certificato_as(self, cert_sig: Certificato) -> bool:
        """Verifica offline il certificato dell'AS e ne carica la chiave pubblica."""
        if verifica_certificato_offline(self._pk_ca, cert_sig):
            self.pk_as_sig = cert_sig.chiave_pubblica
            return True
        return False

    @property
    def fiducia_inizializzata(self) -> bool:
        """True se tutte le chiavi pubbliche necessarie sono state caricate e verificate."""
        return all(
            pk is not None
            for pk in (self.pk_ae_enc, self.pk_ae_sig, self.pk_ue_sig, self.pk_as_sig)
        )

    # -- Fase 2: autenticazione e ottenimento del token -----------------------------

    def autenticati(self, auth_server: AuthServer) -> TokenVoto:
        """
        Avvia, tramite l'AS, la procedura di autenticazione simulata
        (OIDC + FIDO2) e, in caso di successo, salva localmente il
        token pseudonimo di voto ottenuto.

        Solleva PermissionError se l'autenticazione fallisce (rilanciata
        dall'AuthServer).
        """
        token = auth_server.autentica_studente_simulato(self.student_id)
        self.token = token
        return token

    def verifica_token_locale(self) -> bool:
        """
        Verifica, lato Client, l'autenticita' del proprio token usando
        la chiave pubblica dell'AS (PK_AS) gia' caricata e verificata
        in Fase 1. Utile come controllo di integrita' prima di usare
        il token nelle fasi successive.
        """
        if self.token is None or self.pk_as_sig is None:
            return False
        return cu.rsa_pss_verify(self.pk_as_sig, self.token.hash_token, self.token.firma_as)

    def __repr__(self) -> str:
        return (
            f"Client(student_id={self.student_id}, "
            f"fiducia_inizializzata={self.fiducia_inizializzata}, "
            f"token_ottenuto={self.token is not None})"
        )