"""
main.py
-------
CLI interattiva per il sistema di voto elettronico universitario.

Permette di:
    1. Inizializzare il sistema (Fase 1: CA + generazione/certificazione
       chiavi di AE, Urna, AS).
    2. Registrare uno studente come avente diritto (Registro_Elettori).
    3. Avviare il bootstrap della fiducia per un nuovo Client.
    4. Autenticarsi (avvia la simulazione OIDC + FIDO2) e generare/
       ottenere il proprio token pseudonimo di voto firmato dall'AS.
    5. Votare: selezionare lista e (opzionalmente) candidato, cifrare
       la scheda con RSA-OAEP, inviarla all'Urna e ricevere la ricevuta
       crittografica con il ReceiptID (Fase 3 e 4).
    6. Ispezionare lo stato delle entita' (AE, Urna, AS, Client).
    7. Verificare localmente il proprio token (lato Client).
    8. Verificare localmente la propria ricevuta di voto (lato Client).

Esegui con:
    python3 main.py
"""

import sys

from system_setup import inizializza_sistema, bootstrap_client, SistemaVoto
from entities import Client


class ContestoCLI:
    """Mantiene lo stato in memoria condiviso dalla sessione CLI corrente."""

    def __init__(self):
        self.sistema: SistemaVoto | None = None
        # Mappa student_id -> Client, per gestire piu' elettori nella stessa sessione.
        self.clients: dict[str, Client] = {}


def stampa_intestazione(testo: str) -> None:
    print("\n" + "=" * 60)
    print(testo)
    print("=" * 60)


def stampa_menu() -> None:
    print("\nMenu principale - Sistema di Voto Elettronico Universitario")
    print("-" * 60)
    print("1. Inizializza sistema (Fase 1: CA, chiavi, certificati)")
    print("2. Iscrivi studente come avente diritto al voto")
    print("3. Bootstrap fiducia Client (scarica/verifica certificati)")
    print("4. Autenticati (simulazione OIDC + FIDO2) e ottieni token")
    print("5. Vota (cifra la scheda e invia il voto all'Urna)")
    print("6. Mostra stato del sistema")
    print("7. Verifica localmente il proprio token (lato Client)")
    print("8. Verifica localmente la propria ricevuta di voto (lato Client)")
    print("0. Esci")


def azione_inizializza_sistema(ctx: ContestoCLI) -> None:
    stampa_intestazione("FASE 1 - Setup iniziale e PKI")
    print("Generazione delle chiavi RSA in corso (potrebbe richiedere alcuni secondi)...")
    ctx.sistema = inizializza_sistema()
    print("\nSistema inizializzato correttamente:")
    print(f"  - CA:         {ctx.sistema.ca.nome}")
    print(f"  - {ctx.sistema.ae!r}")
    print(f"  - {ctx.sistema.urna!r}")
    print(f"  - {ctx.sistema.auth_server!r}")


def azione_iscrivi_studente(ctx: ContestoCLI) -> None:
    if ctx.sistema is None:
        print("\n[Errore] Devi prima inizializzare il sistema (opzione 1).")
        return

    student_id = input("Inserisci lo student_ID da iscrivere: ").strip()
    if not student_id:
        print("[Errore] student_ID non valido.")
        return

    risposta = input("E' avente diritto al voto? [s/n] (default: s): ").strip().lower()
    avente_diritto = risposta != "n"

    ctx.sistema.auth_server.iscrivi_studente(student_id, avente_diritto=avente_diritto)
    stato = "avente diritto" if avente_diritto else "NON avente diritto"
    print(f"\nStudente '{student_id}' iscritto nel Registro_Elettori come {stato}.")


def azione_bootstrap_client(ctx: ContestoCLI) -> None:
    if ctx.sistema is None:
        print("\n[Errore] Devi prima inizializzare il sistema (opzione 1).")
        return

    student_id = input("Inserisci lo student_ID per cui creare il Client: ").strip()
    if not student_id:
        print("[Errore] student_ID non valido.")
        return

    stampa_intestazione("Bootstrap della Fiducia (Client)")
    try:
        client = bootstrap_client(ctx.sistema, student_id)
    except RuntimeError as e:
        print(f"[Errore] {e}")
        return

    ctx.clients[student_id] = client
    print(f"Client creato per '{student_id}'.")
    print("Verifica offline dei certificati (PK_CA hardcoded) completata:")
    print(f"  - PK_AE_enc verificata: {client.pk_ae_enc is not None}")
    print(f"  - PK_AE_sig verificata: {client.pk_ae_sig is not None}")
    print(f"  - PK_UE_sig verificata: {client.pk_ue_sig is not None}")
    print(f"  - PK_AS_sig verificata: {client.pk_as_sig is not None}")
    print(f"  - Fiducia inizializzata: {client.fiducia_inizializzata}")


def azione_autenticati(ctx: ContestoCLI) -> None:
    if ctx.sistema is None:
        print("\n[Errore] Devi prima inizializzare il sistema (opzione 1).")
        return

    student_id = input("Inserisci lo student_ID con cui autenticarti: ").strip()
    if not student_id:
        print("[Errore] student_ID non valido.")
        return

    client = ctx.clients.get(student_id)
    if client is None:
        print(
            f"[Errore] Nessun Client trovato per '{student_id}'. "
            "Esegui prima il bootstrap della fiducia (opzione 3)."
        )
        return

    stampa_intestazione("FASE 2 - Autenticazione e rilascio del token")
    print("Costruzione della OIDC_Request verso l'Identity Provider...")
    oidc_request = ctx.sistema.auth_server.simula_richiesta_oidc(
        client_id=ctx.sistema.auth_server.id,
        redirect_uri="https://voto.universita.it/callback",
    )
    print(f"  OIDC_Request = {oidc_request}")

    print("\nSimulazione autenticazione FIDO2 (challenge/response) in corso...")
    try:
        token = client.autenticati(ctx.sistema.auth_server)
    except PermissionError as e:
        print(f"\n[Autenticazione rifiutata] {e}")
        return

    print("\nAutenticazione completata con successo.")
    print(f"Token pseudonimo di voto ottenuto: {token!r}")
    print("Il token e' stato firmato dall'AS con RSA-PSS e salvato localmente nel Client.")


def azione_vota(ctx: ContestoCLI) -> None:
    if ctx.sistema is None:
        print("\n[Errore] Devi prima inizializzare il sistema (opzione 1).")
        return

    student_id = input("Inserisci lo student_ID con cui votare: ").strip()
    if not student_id:
        print("[Errore] student_ID non valido.")
        return

    client = ctx.clients.get(student_id)
    if client is None:
        print(
            f"[Errore] Nessun Client trovato per '{student_id}'. "
            "Esegui prima il bootstrap della fiducia (opzione 3)."
        )
        return
    if client.token is None:
        print(
            f"[Errore] Il Client di '{student_id}' non possiede ancora un token. "
            "Autenticati prima (opzione 4)."
        )
        return

    stampa_intestazione("FASE 3 - Preparazione e invio del voto cifrato")

    liste = ctx.sistema.configurazione.elenco_liste()
    if not liste:
        print("[Errore] Nessuna lista configurata nel sistema.")
        return

    print("Liste disponibili:")
    for i, nome_lista in enumerate(liste, start=1):
        print(f"  {i}. {nome_lista}")

    scelta_lista = input("\nSeleziona il numero della lista da votare: ").strip()
    try:
        indice_lista = int(scelta_lista) - 1
        if indice_lista < 0 or indice_lista >= len(liste):
            raise ValueError
    except ValueError:
        print("[Errore] Selezione della lista non valida.")
        return

    lista_scelta = liste[indice_lista]
    candidati = ctx.sistema.configurazione.candidati_di(lista_scelta)

    candidato_scelto = None
    if candidati:
        print(f"\nCandidati della lista '{lista_scelta}':")
        print("  0. (nessuna preferenza interna)")
        for i, nome_candidato in enumerate(candidati, start=1):
            print(f"  {i}. {nome_candidato}")

        scelta_candidato = input("\nSeleziona il numero del candidato (o 0 per nessuna preferenza): ").strip()
        try:
            indice_candidato = int(scelta_candidato)
            if indice_candidato < 0 or indice_candidato > len(candidati):
                raise ValueError
        except ValueError:
            print("[Errore] Selezione del candidato non valida.")
            return

        if indice_candidato > 0:
            candidato_scelto = candidati[indice_candidato - 1]
    else:
        print(f"\nLa lista '{lista_scelta}' non prevede preferenza interna.")

    print("\nPreparazione della scheda di voto sul client...")
    print(f"  Lista selezionata:     {lista_scelta}")
    print(f"  Candidato selezionato: {candidato_scelto if candidato_scelto else '(nessuno)'}")
    print("\nCifratura RSA-OAEP del messaggio M = (lista, candidato, nonce) con PK_AE_enc...")

    try:
        ricevuta = client.vota(
            lista=lista_scelta,
            candidato=candidato_scelto,
            urna=ctx.sistema.urna,
            configurazione=ctx.sistema.configurazione,
        )
    except (ValueError, RuntimeError) as e:
        print(f"\n[Voto respinto] {e}")
        return

    print("\nVoto cifrato inviato all'Urna Elettronica (canale HTTPS/TLS simulato).")
    print("Payload = { ciphertext, token, Sig_AS(T) } accettato.")

    stampa_intestazione("Ricevuta crittografica rilasciata dall'Urna")
    print(f"  Token (T):        {client.ultimo_payload.token_hex}")
    print(f"  Ciphertext (C):   {client.ultimo_payload.ciphertext_hex[:64]}... "
          f"({len(client.ultimo_payload.ciphertext_hex) // 2} byte)")
    print(f"  ReceiptID:        {ricevuta.receipt_id_hex}")
    print(f"  Timestamp:        {ricevuta.timestamp}")
    print(f"  Sig_UE(...):      {ricevuta.firma_ue.hex()[:64]}... "
          f"({len(ricevuta.firma_ue)} byte)")

    esito_verifica = client.verifica_ricevuta()
    print(
        f"\nVerifica locale della ricevuta (ricalcolo ReceiptID + verifica Sig_UE): "
        f"{'VALIDA' if esito_verifica else 'NON VALIDA'}"
    )


def azione_mostra_stato(ctx: ContestoCLI) -> None:
    stampa_intestazione("Stato del sistema")
    if ctx.sistema is None:
        print("Il sistema non e' ancora stato inizializzato.")
        return

    print(f"CA:           {ctx.sistema.ca.nome}")
    print(f"{ctx.sistema.ae!r}")
    print(f"{ctx.sistema.urna!r}")
    print(f"{ctx.sistema.auth_server!r}")

    if not ctx.clients:
        print("\nNessun Client ancora creato in questa sessione.")
    else:
        print("\nClient attivi in questa sessione:")
        for student_id, client in ctx.clients.items():
            print(f"  - {client!r}")


def azione_verifica_token_locale(ctx: ContestoCLI) -> None:
    student_id = input("Inserisci lo student_ID di cui verificare il token: ").strip()
    client = ctx.clients.get(student_id)
    if client is None:
        print(f"[Errore] Nessun Client trovato per '{student_id}'.")
        return

    if client.token is None:
        print(f"[Errore] Il Client di '{student_id}' non possiede ancora un token.")
        return

    esito = client.verifica_token_locale()
    print(f"\nVerifica locale del token con PK_AS: {'VALIDA' if esito else 'NON VALIDA'}")


def azione_verifica_ricevuta(ctx: ContestoCLI) -> None:
    student_id = input("Inserisci lo student_ID di cui verificare la ricevuta: ").strip()
    client = ctx.clients.get(student_id)
    if client is None:
        print(f"[Errore] Nessun Client trovato per '{student_id}'.")
        return

    if client.ultima_ricevuta is None:
        print(f"[Errore] Il Client di '{student_id}' non ha ancora votato.")
        return

    esito = client.verifica_ricevuta()
    print(
        f"\nVerifica locale della ricevuta (ReceiptID + Sig_UE): "
        f"{'VALIDA' if esito else 'NON VALIDA'}"
    )


def main() -> None:
    ctx = ContestoCLI()

    print("Sistema di Voto Elettronico Universitario - CLI di base")
    print("(Fase 1: Setup/PKI - Fase 2: Autenticazione - Fase 3/4: Voto cifrato e ricevuta)")

    while True:
        stampa_menu()
        scelta = input("\nScegli un'opzione: ").strip()

        if scelta == "1":
            azione_inizializza_sistema(ctx)
        elif scelta == "2":
            azione_iscrivi_studente(ctx)
        elif scelta == "3":
            azione_bootstrap_client(ctx)
        elif scelta == "4":
            azione_autenticati(ctx)
        elif scelta == "5":
            azione_vota(ctx)
        elif scelta == "6":
            azione_mostra_stato(ctx)
        elif scelta == "7":
            azione_verifica_token_locale(ctx)
        elif scelta == "8":
            azione_verifica_ricevuta(ctx)
        elif scelta == "0":
            print("Uscita dal sistema. Arrivederci.")
            sys.exit(0)
        else:
            print("[Errore] Opzione non valida, riprova.")


if __name__ == "__main__":
    main()