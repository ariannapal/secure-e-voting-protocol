"""
CLI per il sistema di voto elettronico universitario.

Realizza DUE sportelli distinti, ciascuno con il proprio loop
interattivo, che riflettono i ruoli del protocollo WP2:

  [A] Sportello Amministrativo
        Fase 1  – Inizializza CA, chiavi RSA, certificati X.509,
                  caricamento Registro_Elettori
        Fase 5  – Chiusura urna, scrutinio, pubblicazione verbale finale

  [E] Sportello Elettore  (User Agent dello studente)
        Autenticati    – passo unico per l'elettore: internamente esegue
                         in automatico il Bootstrap della fiducia (Fase 1b,
                         verifica offline dei certificati) e poi la Fase 2
                         (OIDC + FIDO2, rilascio token pseudonimo). L'esito
                         del bootstrap viene comunicato chiaramente prima
                         di procedere con l'autenticazione vera e propria.
        Fase 3/4      – Preparazione voto (RSA-OAEP), invio all'Urna, ricevuta
        Verifica      – Controllo locale token e ricevuta crittografica

Separazione identita' / voto (WP2, Pseudo-anonimato):
    - Lo student_id viene inserito UNA SOLA VOLTA allo sportello elettore,
      esclusivamente per il controllo nel Registro_Elettori (Fase 2).
    - Dalla Fase 3 in poi l'elettore opera attraverso il token pseudonimo T:
      l'Urna non conosce e non ha bisogno di conoscere chi sta votando.
    - Lo sportello amministrativo non interagisce mai con identita' reali
      degli elettori: gestisce solo strutture aggregate (urna, BB, verbale).

"""

import sys

from system_setup import inizializza_sistema, bootstrap_client, esegui_fase5, SistemaVoto
from entities import Client


# ============================================================================
# Stato condiviso della sessione (in memoria, unica istanza per processo)
# ============================================================================

class StatoSistema:
    """
    Contenitore dello stato globale condiviso tra i due sportelli.
    In un sistema reale le componenti server-side (ae, urna, auth_server, bb)
    sarebbero processi separati raggiungibili via rete; qui condividono la
    stessa memoria di processo perche' l'intera simulazione e' locale.
    """
    def __init__(self):
        self.sistema: SistemaVoto | None = None

    @property
    def pronto(self) -> bool:
        return self.sistema is not None

    @property
    def elezione_aperta(self) -> bool:
        return self.pronto and not self.sistema.elezione_chiusa

    @property
    def elezione_chiusa(self) -> bool:
        return self.pronto and self.sistema.elezione_chiusa


# ============================================================================
# Utilita' di stampa
# ============================================================================

LARGHEZZA = 64

def linea(char: str = "─") -> str:
    return char * LARGHEZZA

def intestazione(titolo: str) -> None:
    print("\n" + linea("═"))
    padding = (LARGHEZZA - len(titolo) - 2) // 2
    print("║" + " " * padding + titolo + " " * (LARGHEZZA - len(titolo) - 2 - padding) + "║")
    print(linea("═"))

def sezione(titolo: str) -> None:
    print("\n" + linea("─"))
    print(f"  {titolo}")
    print(linea("─"))

def ok(msg: str) -> None:
    print(f"  ✓  {msg}")

def info(msg: str) -> None:
    print(f"  ·  {msg}")

def errore(msg: str) -> None:
    print(f"\n  ✗  ERRORE: {msg}")

def avviso(msg: str) -> None:
    print(f"  ⚠  {msg}")

def campo(etichetta: str, valore: str) -> None:
    print(f"  {etichetta:<28} {valore}")


# ============================================================================
# SPORTELLO AMMINISTRATIVO  (Autorita' Elettorale)
# ============================================================================

def sportello_amministrativo(stato: StatoSistema) -> None:
    intestazione("SPORTELLO AMMINISTRATIVO")
    print()
    print("  Questo sportello e' riservato al Sistema.")
    print("  Consente di inizializzare il sistema (Fase 1) e, al termine")
    print("  della finestra di voto, di chiudere l'urna ed eseguire")
    print("  lo scrutinio (Fase 5).")
    print()
    print("  Gli elettori devono attendere l'inizializzazione del sistema per poter votare.")

    while True:
        print()
        print(linea())
        print("  MENU AMMINISTRATIVO")
        print(linea())

        # Voci disponibili in base allo stato
        if not stato.pronto:
            print("  1  Inizializza sistema (Fase 1: CA, chiavi, certificati)")
        else:
            n_pubblicati = len(stato.sistema.bb.tutte_le_tuple())
            n_in_coda = stato.sistema.urna.numero_voti_in_coda()
            print(f"  ·  Sistema gia' inizializzato  "
                  f"(voti totali: {n_pubblicati + n_in_coda}, "
                  f"in batch corrente non pubblicato: {n_in_coda})")

        if stato.elezione_aperta:
            print("  5  Chiudi urna ed esegui lo scrutinio (Fase 5)")

        if stato.elezione_chiusa:
            print("  ·  Elezione chiusa — scrutinio completato")

        print("  0  Torna al menu principale")
        print()

        scelta = input("  Scelta: ").strip()

        if scelta == "0":
            break

        elif scelta == "1" and not stato.pronto:
            _amm_inizializza(stato)

        elif scelta == "5" and stato.elezione_aperta:
            _amm_scrutinio(stato)

        else:
            avviso("Opzione non disponibile in questo stato del sistema.")


def _amm_inizializza(stato: StatoSistema) -> None:
    sezione("FASE 1 — Setup iniziale e PKI")
    print()
    print("  Il sistema avvia la Fase 1 del protocollo:")
    print("   1) La CA d'Ateneo genera la propria coppia di chiavi")
    print("   2) AE, Urna e AS generano AUTONOMAMENTE le proprie chiavi RSA")
    print("      (AE: 4096 bit × 2 coppie; Urna e AS: 2048 bit, sola firma)")
    print("   3) Ciascuna componente richiede ed ottiene il proprio")
    print("      certificato X.509 dalla CA d'Ateneo")
    print("   4) L'AS carica il Registro_Elettori da 'registro_elettori.json'")
    print()
    print("  Generazione chiavi RSA in corso (alcuni secondi)...")

    try:
        stato.sistema = inizializza_sistema()
    except FileNotFoundError as e:
        errore(str(e))
        return
    except ValueError as e:
        errore(f"Registro_Elettori non valido: {e}")
        return

    s = stato.sistema
    print()
    sezione("Componenti inizializzate")
    campo("Certification Authority:", s.ca.nome)
    campo("Autorita' Elettorale:", s.ae.id)
    campo("  cert_enc emesso:", "si'" if s.ae.cert_enc else "no")
    campo("  cert_sig emesso:", "si'" if s.ae.cert_sig else "no")
    campo("Urna Elettronica:", s.urna.id)
    campo("  cert_sig emesso:", "si'" if s.urna.cert_sig else "no")
    campo("Auth Server:", s.auth_server.id)
    campo("  cert_sig emesso:", "si'" if s.auth_server.cert_sig else "no")
    campo("Elezione ID:", s.election_id)

    n_iscritti = len(s.auth_server._registro_elettori)
    n_aventi_diritto = sum(
        1 for e in s.auth_server._registro_elettori.values() if e.avente_diritto
    )
    campo("Registro_Elettori:", f"{n_iscritti} iscritti, {n_aventi_diritto} aventi diritto")

    print()
    ok("Fase 1 completata. Il sistema e' pronto ad accettare votanti.")
    print()
    info("Gli elettori possono ora usare lo Sportello Elettore.")


def _amm_scrutinio(stato: StatoSistema) -> None:
    sezione("FASE 5 — Chiusura urna e scrutinio")
    print()
    print("  L'AE avvia la Fase 5 del protocollo:")
    print("   1) L'Urna chiude la sessione: pubblica l'eventuale ultimo")
    print("      batch residuo (con padding se sotto soglia B_min) e la")
    print("      Merkle Root finale firmata. I batch precedenti sono gia'")
    print("      stati pubblicati durante la finestra di voto al")
    print("      raggiungimento della soglia o del timeout (Fase 4)")
    print("   2) L'AS pubblica l'attestazione firmata su n_token emessi")
    print("   3) L'AE scarica tutto dal Bulletin Board ")
    print("   4) L'AE verifica integrita': firme sui batch, Merkle Root,")
    print("      Sig_UE sulla chiusura, Sig_AS sull'attestazione")
    print("   5) L'AE verifica coerenza quantitativa: |foglie reali| <= n_token")
    print("      (il padding dichiarato dall'Urna e' escluso dal conteggio)")
    print("   6) L'AE decifra con SK_AE e valida le schede")
    print("   7) L'AE conta le preferenze e firma il verbale finale")
    print()

    n_voti_batch_corrente = stato.sistema.urna.numero_voti_in_coda()
    n_voti_gia_pubblicati = len(stato.sistema.bb.tutte_le_tuple())
    n_voti_totali = n_voti_batch_corrente + n_voti_gia_pubblicati
    n_batch_gia_pubblicati = len(stato.sistema.bb.batch_pubblicati)

    if n_voti_totali == 0:
        avviso("L'urna e' vuota: nessun voto da scrutinare.")
        scelta = input("  Continuare comunque? (s/N): ").strip().lower()
        if scelta != "s":
            return

    campo("Batch gia' pubblicati in Fase 4:", str(n_batch_gia_pubblicati))
    campo("Voti reali nel batch corrente (non ancora pubblicato):", str(n_voti_batch_corrente))
    campo("Voti reali totali raccolti:", str(n_voti_totali))
    print()

    try:
        verbale = esegui_fase5(stato.sistema)
    except ValueError as e:
        errore(f"Scrutinio interrotto: {e}")
        return

    n_dummy_totali = stato.sistema.bb.totale_dummy_pubblicati()

    sezione("VERBALE FINALE — pubblicato sul Bulletin Board")
    campo("Election ID:", verbale.election_id)
    campo("Merkle Root finale:", verbale.radice_finale_hex[:32] + "...")
    campo("ReceiptID pubblicati (incl. padding):", str(verbale.numero_receipt_pubblicati))
    campo("  di cui schede fittizie (padding):", str(n_dummy_totali))
    campo("Voti cifrati scrutinati:", str(verbale.voti_cifrati_scrutinati))
    campo("Voti decifrati:", str(verbale.voti_decifrati))
    campo("Voti validi:", str(verbale.voti_validi))
    campo("Voti non validi (incl. padding scartato):", str(verbale.voti_non_validi))
    print()
    print("  Risultati per lista:")
    for lista, voti in verbale.risultati_per_lista.items():
        print(f"    {lista:<40} {voti} voti")
    if verbale.preferenze_per_candidato:
        print()
        print("  Preferenze per candidato:")
        for cand, pref in verbale.preferenze_per_candidato.items():
            print(f"    {cand:<40} {pref} preferenze")
    print()
    campo("Timestamp scrutinio:", str(verbale.timestamp_scrutinio))
    campo("Sig_AE(Verbale):",
          verbale.firma_ae.hex()[:32] + f"... ({len(verbale.firma_ae)} byte)")
    print()
    ok("Verbale firmato e pubblicato sul Bulletin Board.")
    ok("Fase 5 completata. L'elezione e' ufficialmente chiusa.")


# ============================================================================
# SPORTELLO ELETTORE  (User Agent dello studente)
# ============================================================================

def sportello_elettore(stato: StatoSistema) -> None:
    intestazione("SPORTELLO ELETTORE — Sessione di voto")
    print()
    print("  Questo sportello rappresenta l'applicazione client")
    print("  dell'elettore (User Agent). Ogni avvio e' una sessione")
    print("  indipendente per un singolo studente.")
    print()

    if not stato.pronto:
        errore("Il sistema non e' ancora inizializzato.")
        print("  Il sistema deve prima completare la Fase 1.")
        input("  [Invio per tornare al menu principale] ")
        return

    if stato.elezione_chiusa:
        avviso("L'elezione e' gia' stata chiusa. Non e' piu' possibile votare.")
        input("  [Invio per tornare al menu principale] ")
        return

    # Ogni sessione elettore e' un Client fresco (memoria volatile).
    client: Client | None = None

    while True:
        print()
        print(linea())
        print("  MENU ELETTORE")
        print(linea())

        # Stato corrente della sessione. Il bootstrap della fiducia (Fase 1b)
        # non e' piu' un passo separato per l'utente: avviene in modo
        # automatico e trasparente all'interno dell'autenticazione (vedi
        # '_el_autentica_elettore'), che lo combina con la Fase 2.
        fase_autenticata = client is not None and client.token is not None
        fase_votato = fase_autenticata and client.ultima_ricevuta is not None

        if not fase_autenticata:
            print("  1  Autenticati  (verifica certificati + login → diritto di voto)")
        else:
            print("  ·  Autenticato  — identita' verificata, token pseudonimo in memoria")

        if fase_autenticata and not fase_votato:
            if stato.elezione_aperta:
                print("  2  Vota  (cifra la scheda → invia all'Urna → ricevuta)")
            else:
                avviso("L'elezione e' stata chiusa: non e' piu' possibile votare.")

        if fase_votato:
            print("  ·  Voto espresso — ricevuta crittografica ottenuta")
            print("  3  Verifica token pseudonimo  (controllo Sig_AS locale)")
            print("  4  Verifica ricevuta di voto  (ReceiptID + Sig_UE locale)")

        print("  0  Esci dallo sportello elettore")
        print()

        scelta = input("  Scelta: ").strip()

        if scelta == "0":
            break

        elif scelta == "1" and not fase_autenticata:
            client, _ = _el_autentica_elettore(stato)

        elif scelta == "2" and fase_autenticata and not fase_votato and stato.elezione_aperta:
            _el_vota(stato, client)

        elif scelta == "3" and fase_votato:
            _el_verifica_token(client)

        elif scelta == "4" and fase_votato:
            _el_verifica_ricevuta(client)

        else:
            avviso("Opzione non disponibile in questa fase della sessione.")


def _el_autentica_elettore(stato: StatoSistema) -> tuple[Client | None, str | None]:
    """
    Procedura unica di accesso dell'elettore: dal suo punto di vista e'
    UN SOLO passo ("Autenticati"), anche se internamente combina due
    fasi del protocollo WP2:

      Passo 1/2 (Fase 1b, automatico) — Bootstrap della fiducia: il
        client verifica offline, tramite PK_CA cablata, i certificati
        X.509 di AE, Urna e AS. Non e' piu' un'azione separata da
        scegliere a menu: avviene da sola, e l'esito viene comunicato
        chiaramente prima di proseguire.

      Passo 2/2 (Fase 2) — Autenticazione vera e propria: OIDC + FIDO2
        simulati, controllo del Registro_Elettori e rilascio del token
        pseudonimo di voto T, firmato dall'AS.

    Lo student_ID viene chiesto una sola volta, qui, e serve solo per
    il controllo nel Registro_Elettori: da questo punto in poi tutte
    le operazioni (voto, ricevuta) avvengono tramite il token
    pseudonimo T, senza alcun legame con l'identita' reale.

    Ritorna (client, student_id) se l'intera procedura ha successo,
    altrimenti (None, None): in caso di errore (in un punto qualsiasi)
    l'elettore puo' semplicemente riprovare da capo con "Autenticati".
    """
    sezione("Autenticati — accesso allo sportello")
    print()
    print("  Per poter votare devi prima identificarti. Ti verra' chiesto")
    print("  lo student_ID una sola volta: serve solo per il controllo nel")
    print("  Registro_Elettori. Da qui in avanti opererai in forma anonima,")
    print("  tramite un token pseudonimo: l'Urna non sapra' mai chi sei.")
    print()

    student_id = input("  student_ID: ").strip()
    if not student_id:
        errore("student_ID non può essere vuoto.")
        return None, None

    # ------------------------------------------------------------------
    # Passo 1/2 — Bootstrap della fiducia (Fase 1b), automatico
    # ------------------------------------------------------------------
    print()
    print("  Passo 1/2  Verifica dei certificati dell'infrastruttura...")
    info("Il tuo dispositivo controlla offline, con PK_CA gia' cablata,")
    info("che le chiavi pubbliche di AE, Urna e AS siano autentiche")
    info("(nessuna interrogazione di rete necessaria).")

    try:
        client = bootstrap_client(stato.sistema, student_id)
    except RuntimeError as e:
        print()
        errore(str(e))
        return None, None

    if not client.fiducia_inizializzata:
        print()
        errore("Verifica dei certificati non riuscita: impossibile continuare.")
        return None, None

    print()
    ok("Bootstrap riuscito: certificati di AE, Urna e AS verificati con successo.")
    info(f"PK_AE_enc, PK_AE_sig, PK_UE_sig, PK_AS_sig caricate e autenticate.")

    # ------------------------------------------------------------------
    # Passo 2/2 — Autenticazione OIDC + FIDO2 e rilascio del token (Fase 2)
    # ------------------------------------------------------------------
    print()
    print("  Passo 2/2  Autenticazione e rilascio del token di voto...")
    print()
    info("OIDC_Request → Identity Provider universitario")
    info("Login FIDO2 (challenge/response) con l'authenticator dello studente")
    info("ID Token verificato dall'AS: Verify(PK_IdP, ID_Token)")
    info("Controllo Registro_Elettori: avente diritto e non gia' votato")

    try:
        token = client.autenticati(stato.sistema.auth_server)
    except PermissionError as e:
        print()
        errore(str(e))
        print()
        info("Puoi riprovare scegliendo di nuovo 'Autenticati'.")
        return None, None

    info("Token pseudonimo T generato (CSPRNG) e firmato dall'AS: Sig_AS(T)")

    print()
    sezione("Token pseudonimo ottenuto")
    campo("T (prime 32 car.):",   token.valore[:32] + "...")
    campo("Sig_AS(T) (prime 32):", token.firma_as.hex()[:32] + "...")
    print()
    ok("Autenticazione completata: hai ottenuto il diritto di voto.")
    print()
    print("  Da questo momento la tua identita' reale non e' piu' necessaria:")
    print("  il voto avverra' tramite il token T, in forma anonima.")

    return client, student_id


def _el_vota(stato: StatoSistema, client: Client) -> None:
    """
    Fase 3 + Fase 4 — Preparazione, cifratura, invio e ricevuta.

    Fase 3 (lato Client):
      1) Validazione semantica della scelta (lista, candidato vincolato)
      2) Costruzione M = { lista, candidato, nonce }  [JSON → bytes]
      3) C = RSA-OAEP_Encrypt(PK_AE_enc, M)
      4) Payload = { C, T, Sig_AS(T) }  inviato all'Urna via HTTPS/TLS

    Fase 4 (lato Urna → Client):
      5) Urna: Verify(PK_AS, h_T, Sig_AS(T))
      6) Urna: controllo unicita' token (ElencoTokenUsati, O(1))
      7) Urna: ReceiptID = SHA256(T || C)
      8) Urna: Sig_UE(ReceiptID || Timestamp)  → Ricevuta al Client
      9) Urna: se scatta il trigger di soglia (B_min) o di timeout
         (Delta_max), pubblica automaticamente il batch corrente sul
         Bulletin Board (con padding se sotto soglia per timeout)

    L'Urna non conosce lo student_id: riceve solo { C, T, Sig_AS(T) }.
    """
    sezione("FASE 3 — Preparazione e cifratura del voto")
    print()
    print("  Il voto viene preparato SUL TUO DISPOSITIVO:")
    print("  M = { lista, candidato, nonce }  poi cifrato con PK_AE.")
    print("  L'Urna ricevera' solo il ciphertext: mai la preferenza in chiaro.")
    print()

    liste = stato.sistema.configurazione.elenco_liste()
    if not liste:
        errore("Nessuna lista configurata nel sistema.")
        return

    print("  Liste disponibili:")
    for i, nome in enumerate(liste, 1):
        print(f"    {i}.  {nome}")
    print()

    try:
        idx_lista = int(input("  Numero lista: ").strip()) - 1
        if not (0 <= idx_lista < len(liste)):
            raise ValueError
    except ValueError:
        errore("Selezione lista non valida.")
        return

    lista_scelta = liste[idx_lista]
    candidati = stato.sistema.configurazione.candidati_di(lista_scelta)
    candidato_scelto = None

    if candidati:
        print()
        print(f"  Candidati della lista «{lista_scelta}»:")
        print("    0.  (nessuna preferenza interna)")
        for i, nome in enumerate(candidati, 1):
            print(f"    {i}.  {nome}")
        print()
        try:
            idx_cand = int(input("  Numero candidato (0 = nessuno): ").strip())
            if not (0 <= idx_cand <= len(candidati)):
                raise ValueError
        except ValueError:
            errore("Selezione candidato non valida.")
            return
        if idx_cand > 0:
            candidato_scelto = candidati[idx_cand - 1]
    else:
        print()
        info(f"La lista «{lista_scelta}» non prevede preferenza interna.")

    # Riepilogo prima della cifratura
    print()
    print("  Riepilogo scheda:")
    campo("  Lista selezionata:", lista_scelta)
    campo("  Preferenza interna:", candidato_scelto if candidato_scelto else "(nessuna)")
    print()

    print()
    print("  Cifratura in corso...")
    info("nonce   ← CSPRNG(32 byte)  [rende M non deterministico]")
    info("M       = JSON{ lista, candidato, nonce }  → bytes")
    info("C       = RSA-OAEP_Encrypt(PK_AE_enc, M)")
    info("Payload = { C, T, Sig_AS(T) }  → Urna Elettronica (HTTPS/TLS)")

    try:
        ricevuta = client.vota(
            lista=lista_scelta,
            candidato=candidato_scelto,
            urna=stato.sistema.urna,
            configurazione=stato.sistema.configurazione,
            bb=stato.sistema.bb,
        )
    except (ValueError, RuntimeError) as e:
        errore(str(e))
        return

    payload = client.ultimo_payload

    sezione("FASE 4 — Risposta dell'Urna Elettronica")
    print()
    print("  L'Urna ha eseguito:")
    info("Verify(PK_AS, h_T, Sig_AS(T))  → firma valida")
    info("Controllo ElencoTokenUsati      → token non ancora usato")
    info("ReceiptID = SHA256(T ‖ C)      → calcolato e registrato")
    info("Sig_UE(ReceiptID ‖ Timestamp)  → ricevuta firmata e consegnata")
    print()

    sezione("Ricevuta crittografica")
    campo("Token T (prime 32 car.):",
          payload.token_hex[:32] + f"... ({len(payload.token_hex)//2} B)")
    campo("Ciphertext C (prime 32 car.):",
          payload.ciphertext_hex[:32] + f"... ({len(payload.ciphertext_hex)//2} B)")
    campo("ReceiptID:", ricevuta.receipt_id_hex)
    campo("Timestamp:", str(ricevuta.timestamp))
    campo("Sig_UE (prime 32 car.):",
          ricevuta.firma_ue.hex()[:32] + f"... ({len(ricevuta.firma_ue)} B)")

    # Verifica locale immediata
    esito = client.verifica_ricevuta()
    print()
    if esito:
        ok("Verifica locale ricevuta: ReceiptID ricalcolato = ReceiptID ricevuto")
        ok("Sig_UE verificata con PK_UE_sig → ricevuta autentica")
    else:
        errore("Verifica locale ricevuta FALLITA.")

    print()
    print("  ┌─────────────────────────────────────────────────────┐")
    print("  │  Salva il ReceiptID: ti consente di verificare che  │")
    print("  │  il tuo voto sia incluso nel Merkle Tree pubblicato  │")
    print("  │  sul Bulletin Board dopo la chiusura dell'urna.     │")
    print("  └─────────────────────────────────────────────────────┘")


def _el_verifica_token(client: Client) -> None:
    sezione("Verifica locale del token pseudonimo")
    print()
    print("  Il client ricalcola h_T = SHA256(T) e verifica:")
    print("  Verify(PK_AS, h_T, Sig_AS(T))")
    print()
    esito = client.verifica_token_locale()
    if esito:
        ok("Firma Sig_AS(T) valida — il token e' autentico.")
        info("Il token e' stato rilasciato dall'AS autorizzato.")
    else:
        errore("Verifica firma fallita — token non autentico o chiave errata.")


def _el_verifica_ricevuta(client: Client) -> None:
    sezione("Verifica locale della ricevuta di voto")
    print()
    print("  Il client esegue due controlli indipendenti:")
    print("   1) Ricalcola ReceiptID' = SHA256(T ‖ C) e confronta")
    print("      con il ReceiptID nella ricevuta → garantisce che C")
    print("      non sia stato alterato dopo l'invio.")
    print("   2) Verifica Sig_UE(ReceiptID ‖ Timestamp) con PK_UE_sig")
    print("      → garantisce che la ricevuta sia dell'Urna autentica.")
    print()
    ricevuta = client.ultima_ricevuta
    campo("ReceiptID atteso:", ricevuta.receipt_id_hex)

    esito = client.verifica_ricevuta()
    print()
    if esito:
        ok("ReceiptID ricalcolato coincide con quello ricevuto.")
        ok("Sig_UE verificata con PK_UE_sig — ricevuta autentica.")
    else:
        errore("Verifica fallita.")


# ============================================================================
# MENU PRINCIPALE — scelta dello sportello
# ============================================================================

def menu_principale(stato: StatoSistema) -> None:
    while True:
        intestazione("SISTEMA DI VOTO ELETTRONICO UNIVERSITARIO")
        
        if not stato.pronto:
            print("\n  Sistema non inizializzato.")
            print("  Accesso consentito solo allo Sportello Amministrativo.")
            print("\n  [A] Sportello Amministrativo (Fase 1: Inizializzazione)")
            print("  [0] Esci")
            print()
            
            scelta = input("  Accesso: ").strip().upper()
            
            if scelta == "A":
                sportello_amministrativo(stato)
            elif scelta == "0":
                sys.exit(0)
            else:
                avviso("Scelta non valida.")
        
        else:
            # Menu completo (mostrato solo dopo l'inizializzazione)
            print()
            ok("Sistema inizializzato e pronto.")
            print("\n  [A] Sportello Amministrativo (Gestione)")
            print("  [E] Sportello Elettore       (Voto)")
            print("  [0] Esci")
            print()
            
            scelta = input("  Accesso: ").strip().upper()
            
            if scelta == "A":
                sportello_amministrativo(stato)
            elif scelta == "E":
                sportello_elettore(stato)
            elif scelta == "0":
                sys.exit(0)
            else:
                avviso("Scelta non valida.")


# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    stato = StatoSistema()
    menu_principale(stato)