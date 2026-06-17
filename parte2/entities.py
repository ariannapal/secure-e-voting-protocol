"""
entities.py
-----------
Definisce le entita' principali del sistema di voto elettronico
universitario descritto nel WP2:

    - AutoritaElettorale (AE)
    - Urna (Urna Elettronica, UE)
    - AuthServer  (Sistema di Autenticazione, AS)
    - Client      (applicazione/User Agent dell'elettore)

In questa implementazione vengono coperte:
    * Fase 1 - Setup iniziale e PKI (generazione reale di chiavi RSA,
      certificazione tramite la CertificationAuthority)
    * Fase 2 - Autenticazione e rilascio del token (OIDC/FIDO2 simulati,
      registro degli aventi diritto, generazione e firma del token
      pseudonimo tramite RSA-PSS)
    * Fase 3 - Preparazione e invio del voto cifrato (validazione
      semantica Lista+Preferenza, cifratura RSA-OAEP, composizione e
      invio del Payload di voto)
    * Fase 4 - Ricezione, registrazione e verificabilita' del voto
      (verifica del token, controllo di unicita' tramite
      ElencoTokenUsati, calcolo del ReceiptID, rilascio della ricevuta
      firmata dall'Urna e verifica locale lato client)

Le fasi successive (Merkle Tree/Bulletin Board e scrutinio) sono
lasciate come estensioni future.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import rsa

import crypto_utils as cu
from pki import CertificationAuthority, Certificato, verifica_certificato_offline
from ballot import MessaggioVoto, PayloadVoto, Ricevuta, calcola_receipt_id
from election_config import ConfigurazioneElettorale


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

        # ElencoTokenUsati = {h_T1, h_T2, ...}: impronte SHA-256 dei token
        # gia' impiegati per votare. Implementato come dizionario per
        # ottenere una ricerca media O(1), come descritto nel WP2.
        self._elenco_token_usati: Dict[str, bool] = {}

        # Stato dell'urna: token registrati/ricevuti ma non ancora "spesi".
        # Utile per ispezionare lo stato della componente dalla CLI.
        self._token_ricevuti: Dict[str, TokenVoto] = {}

        # Coda interna persistente e append-only dei voti cifrati accettati,
        # non ancora pubblicati a batch sul Bulletin Board (Fase 4).
        self._coda_interna: list = []

        # Ricevute emesse, indicizzate per ReceiptID (hex), per eventuali
        # consultazioni successive (es. dalla CLI).
        self._ricevute_emesse: Dict[str, "Ricevuta"] = {}

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

        Nota: questo metodo e' mantenuto per compatibilita' e per
        scenari in cui si vuole registrare un token senza ancora
        sottomettere un voto. La sottomissione effettiva del voto
        (Fase 4) avviene tramite 'ricevi_voto', che esegue gli stessi
        controlli sul token nel contesto della ricezione del payload.
        """
        h_t_hex = token.hash_token.hex()
        if h_t_hex in self._elenco_token_usati:
            return False

        firma_valida = cu.rsa_pss_verify(pk_as, token.hash_token, token.firma_as)
        if not firma_valida:
            return False

        self._token_ricevuti[token.valore] = token
        self._elenco_token_usati[h_t_hex] = True
        return True

    def token_gia_utilizzato(self, token: TokenVoto) -> bool:
        """
        Verifica se un dato token e' gia' stato impiegato per votare,
        controllando la presenza della sua impronta h_T = SHA256(T)
        nell'ElencoTokenUsati (struttura a Hash Table, ricerca O(1)).
        """
        return token.hash_token.hex() in self._elenco_token_usati

    # -- Fase 4: ricezione, registrazione e rilascio della ricevuta -----------------

    def ricevi_voto(self, payload: PayloadVoto, pk_as: rsa.RSAPublicKey) -> Ricevuta:
        """
        Riceve dal Client il payload di voto Payload = {C, T, Sig_AS(T)}
        ed esegue, nell'ordine, i controlli descritti in Fase 4:

            1) verifica dell'autenticita' del token tramite
               Verify(PK_AS, h_T, Sig_AS(T));
            2) controllo di unicita' del token tramite l'ElencoTokenUsati
               (hash table, ricerca O(1)), per impedire il riutilizzo;
            3) registrazione del voto cifrato nella coda interna
               persistente e append-only;
            4) calcolo del ReceiptID = SHA256(T || C) e generazione
               della ricevuta crittografica firmata dall'Urna con
               RSA-PSS: Sig_UE(ReceiptID || Timestamp).

        Solleva ValueError se il payload viene rifiutato (token non
        autentico oppure gia' utilizzato), riportando il motivo.
        Ritorna la Ricevuta in caso di accettazione del voto.
        """
        h_t = cu.sha256(bytes.fromhex(payload.token_hex))
        h_t_hex = h_t.hex()

        # --- Passo 1: verifica autenticita' del token --------------------------
        firma_as_bytes = bytes.fromhex(payload.firma_as_hex)
        firma_valida = cu.rsa_pss_verify(pk_as, h_t, firma_as_bytes)
        if not firma_valida:
            raise ValueError("Token non autentico: verifica Sig_AS(T) fallita.")

        # --- Passo 2: controllo di unicita' (ElencoTokenUsati, O(1)) ------------
        if h_t_hex in self._elenco_token_usati:
            raise ValueError("Token gia' utilizzato: voto respinto (anti double-voting).")

        # Token autentico e non ancora usato: lo marchiamo immediatamente
        # come utilizzato, prima di proseguire con la registrazione.
        self._elenco_token_usati[h_t_hex] = True

        # --- Passo 3: registrazione nella coda interna persistente --------------
        receipt_id_hex = calcola_receipt_id(payload.token_hex, payload.ciphertext_hex)
        timestamp = time.time()

        voto_registrato = {
            "token_hex": payload.token_hex,
            "ciphertext_hex": payload.ciphertext_hex,
            "receipt_id_hex": receipt_id_hex,
            "timestamp": timestamp,
        }
        self._coda_interna.append(voto_registrato)

        # --- Passo 4: generazione della ricevuta crittografica firmata ----------
        messaggio_da_firmare = receipt_id_hex.encode() + str(timestamp).encode()
        firma_ue = cu.rsa_pss_sign(self._sk_sig, messaggio_da_firmare)

        ricevuta = Ricevuta(
            token_hex=payload.token_hex,
            ciphertext_hex=payload.ciphertext_hex,
            receipt_id_hex=receipt_id_hex,
            timestamp=timestamp,
            firma_ue=firma_ue,
        )
        self._ricevute_emesse[receipt_id_hex] = ricevuta
        return ricevuta

    def numero_voti_in_coda(self) -> int:
        """Numero di voti attualmente registrati nella coda interna (non ancora pubblicati a batch)."""
        return len(self._coda_interna)

    def stato(self) -> str:
        """Riassunto leggibile dello stato corrente dell'Urna."""
        return (
            f"Urna(id={self.id}, certificata={self.cert_sig is not None}, "
            f"token_registrati={len(self._token_ricevuti)}, "
            f"voti_in_coda={len(self._coda_interna)}, "
            f"ricevute_emesse={len(self._ricevute_emesse)})"
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

    def __init__(self):
        self.id = "AS-AUTENTICAZIONE"

        self._sk_sig: rsa.RSAPrivateKey = cu.genera_coppia_rsa(self.BIT_SIZE_AS)
        self.pk_sig: rsa.RSAPublicKey = self._sk_sig.public_key()

        self.cert_sig: Optional[Certificato] = None

        # Registro_Elettori = { student_ID -> RegistroElettoreEntry }
        self._registro_elettori: Dict[str, RegistroElettoreEntry] = {}

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

        # Stato relativo alla Fase 3/4 (voto espresso e ricevuta ottenuta).
        self.ultimo_messaggio: Optional[MessaggioVoto] = None   # M in chiaro
        self.ultimo_ciphertext_hex: Optional[str] = None        # C = RSA-OAEP(PK_AE, M), in hex
        self.ultimo_payload: Optional[PayloadVoto] = None
        self.ultima_ricevuta: Optional[Ricevuta] = None

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

    # -- Fase 3: preparazione, cifratura e invio del voto ----------------------------

    def vota(
        self,
        lista: str,
        candidato: Optional[str],
        urna: "Urna",
        configurazione: ConfigurazioneElettorale,
    ) -> Ricevuta:
        """
        Implementa per intero la Fase 3 e la consegna del voto descritta
        nel WP2:

            1) Validazione semantica della combinazione (lista, candidato):
               il candidato, se presente, deve appartenere alla lista
               selezionata. Non e' ammesso scegliere un candidato di una
               lista diversa.
            2) Costruzione del messaggio in chiaro
               M = (lista, candidato, nonce) e relativa serializzazione
               JSON -> byte.
            3) Cifratura RSA-OAEP del messaggio con la chiave pubblica
               di cifratura dell'Autorita' Elettorale (PK_AE^enc),
               precedentemente verificata e caricata in Fase 1/3:
                   C = RSA-OAEP_Encrypt(PK_AE_enc, M)
            4) Composizione del Payload di voto:
                   Payload = { C, T, Sig_AS(T) }
            5) Invio del payload all'Urna Elettronica tramite il
               metodo 'ricevi_voto' (che modella il canale HTTPS/TLS
               Client -> UE), ottenendo la Ricevuta crittografica.

        Precondizioni: il Client deve avere completato il bootstrap
        della fiducia (fiducia_inizializzata) ed avere ottenuto un
        token di voto valido (token non None).

        Solleva:
            RuntimeError se la fiducia non e' stata inizializzata o se
                non si possiede ancora un token di voto;
            ValueError se la combinazione (lista, candidato) non e'
                semanticamente valida, oppure se l'Urna rifiuta il voto
                (token non autentico o gia' utilizzato).
        """
        if not self.fiducia_inizializzata:
            raise RuntimeError(
                "Bootstrap della fiducia non completato: impossibile cifrare il "
                "voto senza aver prima verificato i certificati di AE e UE."
            )
        if self.token is None:
            raise RuntimeError(
                "Nessun token di voto disponibile: e' necessario autenticarsi "
                "(Fase 2) prima di poter votare."
            )

        # --- Passo 1: validazione semantica Lista + Preferenza vincolata --------
        if not configurazione.lista_esiste(lista):
            raise ValueError(f"La lista '{lista}' non esiste nella configurazione elettorale.")

        if candidato is not None:
            if not configurazione.candidato_appartiene_a_lista(lista, candidato):
                raise ValueError(
                    f"Il candidato '{candidato}' non appartiene alla lista '{lista}': "
                    "selezione non ammessa (preferenza vincolata)."
                )

        # --- Passo 2: costruzione del messaggio in chiaro M ----------------------
        messaggio = MessaggioVoto.crea(lista=lista, candidato=candidato)
        if not messaggio.valida_dimensioni():
            raise ValueError(
                "I campi 'lista' o 'candidato' superano la dimensione massima "
                "consentita (64 byte UTF-8)."
            )
        m_bytes = messaggio.to_json_bytes()

        # --- Passo 3: cifratura RSA-OAEP con PK_AE^enc ----------------------------
        ciphertext = cu.rsa_oaep_encrypt(self.pk_ae_enc, m_bytes)
        ciphertext_hex = ciphertext.hex()

        # --- Passo 4: composizione del Payload di voto ----------------------------
        payload = PayloadVoto(
            ciphertext_hex=ciphertext_hex,
            token_hex=self._token_hex(),
            firma_as_hex=self.token.firma_as.hex(),
        )

        # --- Passo 5: invio del payload all'Urna (canale HTTPS/TLS modellato) ----
        ricevuta = urna.ricevi_voto(payload, pk_as=self.pk_as_sig)

        # Aggiornamento dello stato locale del Client.
        self.ultimo_messaggio = messaggio
        self.ultimo_ciphertext_hex = ciphertext_hex
        self.ultimo_payload = payload
        self.ultima_ricevuta = ricevuta

        return ricevuta

    def _token_hex(self) -> str:
        """
        Restituisce la rappresentazione esadecimale del token pseudonimo
        T, cosi' come memorizzata e trasmessa nel Payload di voto
        (campo 'token' della Tabella del WP2, codifica esadecimale).
        """
        return self.token.valore.encode("utf-8").hex()

    # -- Fase 4 (lato client): verifica locale della ricevuta -----------------------

    def verifica_ricevuta(self) -> bool:
        """
        Esegue il doppio controllo locale descritto in Fase 4:

            1) ricalcola ReceiptID' = SHA256(T || C) usando il token e
               il ciphertext effettivamente inviati, e lo confronta con
               il ReceiptID riportato nella ricevuta (questo rileva
               qualsiasi alterazione di C avvenuta dopo l'invio);
            2) verifica la firma dell'Urna Sig_UE(ReceiptID || Timestamp)
               con la chiave pubblica PK_UE_sig, caricata e verificata
               in Fase 1, per accertarsi che la ricevuta sia stata
               effettivamente prodotta dall'Urna Elettronica.

        Ritorna True solo se entrambi i controlli hanno esito positivo.
        """
        if self.ultima_ricevuta is None or self.ultimo_payload is None:
            return False
        if self.pk_ue_sig is None:
            return False

        ricevuta = self.ultima_ricevuta

        # --- Controllo 1: ricalcolo locale del ReceiptID --------------------------
        receipt_id_ricalcolato = calcola_receipt_id(
            token_hex=self.ultimo_payload.token_hex,
            ciphertext_hex=self.ultimo_payload.ciphertext_hex,
        )
        if receipt_id_ricalcolato != ricevuta.receipt_id_hex:
            return False

        # --- Controllo 2: verifica della firma dell'Urna ---------------------------
        messaggio_firmato = ricevuta.messaggio_firmato()
        firma_valida = cu.rsa_pss_verify(self.pk_ue_sig, messaggio_firmato, ricevuta.firma_ue)

        return firma_valida

    def __repr__(self) -> str:
        return (
            f"Client(student_id={self.student_id}, "
            f"fiducia_inizializzata={self.fiducia_inizializzata}, "
            f"token_ottenuto={self.token is not None})"
        )