import os
import json
import time
import secrets
from collections import Counter
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# =====================================================================
# DATI DI TEST E CONFIGURAZIONE DELLE LISTE ELETTORALI (WP1 & WP2)
# =====================================================================
LISTE_ELETTORALI = {
    "studenti ingegneria": ["Mario Rossi", "Luigi Bianchi", "Elena Verdi"],
    "studentiunisa": ["Anna Russo", "Paolo Gallo", "Sofia Ferrari"],
    "agora": ["Diego Esposito", "Chiara Fontana", "Federico Rizzo"]
}

# =====================================================================
# FUNZIONI UTILITARIE CRITTOGRAFICHE (PROTOCOLLI DEL WP2)
# =====================================================================

def genera_coppia_chiavi_rsa(key_size=2048):
    """Genera una coppia di chiavi RSA."""
    chiave_privata = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    return chiave_privata, chiave_privata.public_key()

def sha256(data: bytes) -> bytes:
    """Esegue l'hashing SHA-256 dei dati in input."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def firma_rsa_pss(chiave_privata, data: bytes) -> bytes:
    """Applica lo schema di firma digitale RSA-PSS come richiesto dal WP2."""
    return chiave_privata.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verifica_rsa_pss(chiave_pubblica, firma: bytes, data: bytes) -> bool:
    """Verifica una firma digitale RSA-PSS."""
    try:
        chiave_pubblica.verify(
            firma,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def cifra_rsa_oaep(chiave_pubblica, data: bytes) -> bytes:
    """Cifra i dati tramite RSA-OAEP per ottenere una cifratura probabilistica."""
    return chiave_pubblica.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decifra_rsa_oaep(chiave_privata, ciphertext: bytes) -> bytes:
    """Decifra i dati cifrati in RSA-OAEP."""
    return chiave_privata.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# =====================================================================
# STRUTTURE DATI COMPLESSE: CERTIFICATI E MERKLE TREE
# =====================================================================

class Certificate:
    """Simulazione di un certificato digitale X.509 emesso dalla CA."""
    def __init__(self, entity_id, public_key, signature=None):
        self.entity_id = entity_id
        self.public_key = public_key
        self.signature = signature

    def to_bytes(self) -> bytes:
        """Serializza le informazioni core del certificato per la firma/verifica."""
        pk_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return self.entity_id.encode() + pk_bytes


class MerkleTree:
    """Implementazione completa e ricorsiva del Merkle Tree per la gestione dei batch."""
    def __init__(self, leaves_input):
        self.leaves = [bytes.fromhex(l) if isinstance(l, str) else l for l in leaves_input]
        self.levels = []
        if self.leaves:
            self.build_tree(self.leaves)

    def build_tree(self, current_level):
        """Costruisce l'albero calcolando ricorsivamente gli hash delle coppie di nodi."""
        self.levels.append(current_level)
        if len(current_level) == 1:
            return
        
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1] if (i + 1 < len(current_level)) else left
            combined_hash = sha256(left + right)
            next_level.append(combined_hash)
            
        self.build_tree(next_level)

    @property
    def root(self) -> bytes:
        """Restituisce la Merkle Root dell'albero."""
        if not self.levels or not self.levels[-1]:
            return b""
        return self.levels[-1][0]

    def get_proof(self, leaf_index):
        """Genera la Merkle Proof per una determinata foglia."""
        proof = []
        idx = leaf_index
        for level in self.levels[:-1]:
            if idx % 2 == 0:
                sibling = level[idx + 1] if (idx + 1 < len(level)) else level[idx]
                proof.append((sibling, 'right'))
            else:
                sibling = level[idx - 1]
                proof.append((sibling, 'left'))
            idx //= 2
        return proof

    @staticmethod
    def verify_proof(leaf, proof, root) -> bool:
        """L'elettore ricalcola la radice partendo dalla foglia e dalla proof."""
        current = bytes.fromhex(leaf) if isinstance(leaf, str) else leaf
        for sibling, direction in proof:
            if direction == 'right':
                current = sha256(current + sibling)
            else:
                current = sha256(sibling + current)
        return current == root


# =====================================================================
# COMPONENTI E ATTORI DEL SISTEMA (STRUTTURA A CLASSI)
# =====================================================================

class CertificationAuthority:
    """Entità fiduciaria radice che firma i certificati delle componenti di sistema."""
    def __init__(self):
        self.private_key, self.public_key = genera_coppia_chiavi_rsa(2048)

    def issue_certificate(self, entity_id, entity_public_key) -> Certificate:
        """Crea e firma digitalmente un certificato per un'entità di rete."""
        cert = Certificate(entity_id, entity_public_key)
        cert.signature = firma_rsa_pss(self.private_key, cert.to_bytes())
        return cert

    def verify_certificate(self, cert: Certificate) -> bool:
        """Valida la firma apposta dalla CA sul certificato."""
        return verifica_rsa_pss(self.public_key, cert.signature, cert.to_bytes())


class BulletinBoard:
    """Registro pubblico e immutabile accessibile a tutti gli attori in modalità Read-Only."""
    def __init__(self):
        self.batches = []
        self.final_publication = None
        self.verbale = None

    def publish_batch(self, batch_data):
        """Riceve e memorizza le informazioni di un batch pubblicato dall'Urna."""
        self.batches.append(batch_data)
        print(f"[Bulletin Board] Pubblicato BATCH #{batch_data['batch_id']} | "
              f"Nuove ricevute: {len(batch_data['receipt_ids_batch'])} | "
              f"Ricevute totali: {batch_data['receipt_count_totale']} | "
              f"Merkle Root globale: {batch_data['RMerkle_globale'].hex()[:16]}...")

    def publish_final_closure(self, final_data):
        """Pubblica i dati aggregati alla chiusura delle urne."""
        self.final_publication = final_data
        print(f"[Bulletin Board] PUBBLICAZIONE DI CHIUSURA EFFETTUATA. Merkle Root Finale: {final_data['R_finale'].hex()[:16]}...")

    def publish_verbale(self, verbale_data):
        """Rende pubblico il verbale finale redatto dall'Autorità Elettorale."""
        self.verbale = verbale_data
        print("[Bulletin Board] VERBALE FINALE DELLO SCRUTINIO PUBBLICATO CON SUCCESSO!")


class AuthenticationSystem:
    """Responsabile del controllo dei diritti di voto e del rilascio del token pseudonimo."""
    def __init__(self, ca: CertificationAuthority):
        self.private_key, self.public_key = genera_coppia_chiavi_rsa(2048)
        self.cert = ca.issue_certificate("Sistema di Autenticazione", self.public_key)
        self.registro_elettori = {}
        self.tokens_emessi = 0

    def inserisci_avente_diritto(self, student_id, ha_diritto=True):
        """Configura lo stato iniziale dello studente nel database."""
        self.registro_elettori[student_id] = {
            "avente_diritto": ha_diritto,
            "token_rilasciato": False  # [CORRETTO] uniformato in italiano
        }

    def verifica_e_rilascia_token(self, student_id):
        """Simula la verifica post-autenticazione IdP e genera il token crittografico."""
        elettore = self.registro_elettori.get(student_id)
        if not elettore:
            print(f"[AS] Accesso Negato: Lo studente {student_id} non è presente nei registri.")
            return None

        if not elettore["avente_diritto"]:
            print(f"[AS] Accesso Negato: Lo studente {student_id} non possiede il diritto di voto.")
            return None

        if elettore["token_rilasciato"]:  # [CORRETTO] uniformato con l'inizializzazione
            print(f"[AS] Tentativo di Double Voting Rilevato! Token già emesso per lo studente {student_id}.")
            return None

        T = secrets.token_hex(32)
        sig_as = firma_rsa_pss(self.private_key, T.encode())

        elettore["token_rilasciato"] = True  # [CORRETTO] uniformato con l'inizializzazione
        self.tokens_emessi += 1

        print(f"[AS] Identità confermata per lo studente {student_id}. Rilasciato Token Pseudonimo T.")
        return T, sig_as


class ElectronicUrn:
    """Registro digitale anonimo incaricato di raccogliere i voti in modo strutturato."""
    def __init__(self, ca: CertificationAuthority, election_id="Elezioni_Unisa_2026"):
        self.private_key, self.public_key = genera_coppia_chiavi_rsa(2048)
        self.cert = ca.issue_certificate("Urna Elettronica", self.public_key)
        self.election_id = election_id
        
        self.token_usati = set()
        self.voti_registrati = []
        self.receipt_ids_correnti = []
        self.batch_counter = 0
        self.batch_size = 3                  # soglia dimostrativa B_min per il prototipo
        self.max_batch_wait_seconds = 900     # Delta_max: 15 minuti nel modello teorico
        self.batch_opened_at = None
        self.albero_globale = MerkleTree([])
        self.root_corrente = b""

    def ricevi_voto(self, payload, pk_as, bb: BulletinBoard):
        """Valida l'autorizzazione di voto del payload, calcola il ReceiptID e gestisce i batch."""
        C = payload["C"]
        T = payload["T"]
        sig_as = payload["SigAS(T)"]

        if not verifica_rsa_pss(pk_as, sig_as, T.encode()):
            print("[Urna] Errore: Firma dell'autorizzazione di voto non valida. Voto scartato.")
            return None

        h_t = sha256(T.encode()).hex()
        if h_t in self.token_usati:
            print("[Urna] Errore: Questo token di voto è già stato utilizzato. Voto respinto.")
            return None

        self.token_usati.add(h_t)

        receipt_id = sha256(T.encode() + C)

        timestamp = int(time.time())
        data_to_sign = receipt_id + str(timestamp).encode()
        sig_ue = firma_rsa_pss(self.private_key, data_to_sign)

        ricevuta = {
            "T": T,
            "C": C,
            "ReceiptID": receipt_id,
            "Timestamp": timestamp,
            "SigUE": sig_ue
        }

        self.voti_registrati.append({"receipt_id": receipt_id, "C": C, "T": T})
        self.receipt_ids_correnti.append(receipt_id)

        if self.batch_opened_at is None:
            self.batch_opened_at = timestamp

        print(f"[Urna] Voto accettato e registrato con successo. ReceiptID emesso: {receipt_id.hex()[:12]}...")

        if self._deve_pubblicare_batch(timestamp):
            self._pubblica_batch_su_bb(bb)

        return ricevuta

    def _deve_pubblicare_batch(self, timestamp_corrente):
        """Implementa il batching ibrido: soglia minima di voti oppure tempo massimo."""
        if len(self.receipt_ids_correnti) >= self.batch_size:
            return True
        if self.batch_opened_at is not None:
            tempo_trascorso = timestamp_corrente - self.batch_opened_at
            return tempo_trascorso >= self.max_batch_wait_seconds
        return False

    def _receipt_ids_globali(self):
        """Restituisce tutti i ReceiptID registrati fino a questo momento, nell'ordine di accettazione."""
        return [v["receipt_id"] for v in self.voti_registrati]

    def _voti_cifrati_globali(self):
        """Restituisce tutti i ciphertext registrati, senza shuffle e nello stesso ordine dei ReceiptID."""
        return [v["C"] for v in self.voti_registrati]

    def _hash_lista_ciphertext(self, ciphertexts):
        """Calcola un digest dell'elenco dei ciphertext, così la firma finale copre anche i voti cifrati."""
        return sha256(b"".join(sha256(c) for c in ciphertexts))

    def _pubblica_batch_su_bb(self, bb: BulletinBoard):
        """
        Pubblica il batch corrente e ricalcola la Merkle Root globale dell'urna.

        Il batch serve solo come soglia di pubblicazione.
        La Merkle Root pubblicata rappresenta sempre l'albero complessivo
        formato da tutti i ReceiptID registrati fino a quel momento.
        """
        self.batch_counter += 1

        receipt_ids_batch_hex = [r.hex() for r in self.receipt_ids_correnti]
        receipt_ids_globali = self._receipt_ids_globali()
        receipt_ids_globali_hex = [r.hex() for r in receipt_ids_globali]

        self.albero_globale = MerkleTree(receipt_ids_globali)
        self.root_corrente = self.albero_globale.root

        timestamp_batch = int(time.time())
        data_to_sign = (
            self.election_id.encode()
            + str(self.batch_counter).encode()
            + "".join(receipt_ids_batch_hex).encode()
            + "".join(receipt_ids_globali_hex).encode()
            + self.root_corrente
            + str(timestamp_batch).encode()
        )
        sig_ue_batch = firma_rsa_pss(self.private_key, sha256(data_to_sign))

        batch_pub = {
            "batch_id": self.batch_counter,
            "receipt_ids_batch": receipt_ids_batch_hex,
            "receipt_ids_globali": receipt_ids_globali_hex,
            "receipt_count_totale": len(receipt_ids_globali_hex),
            "RMerkle_globale": self.root_corrente,
            "TimestampBatch": timestamp_batch,
            "SigUE": sig_ue_batch
        }

        bb.publish_batch(batch_pub)
        self.receipt_ids_correnti = []
        self.batch_opened_at = None

    def chiudi_urna_e_pubblica_risultati(self, bb: BulletinBoard):
        """Chiude ufficialmente le votazioni e pubblica i dati finali sul Bulletin Board."""
        if self.receipt_ids_correnti:
            print("[Urna] Svuotamento buffer: Pubblicazione del batch residuo prima della chiusura...")
            self._pubblica_batch_su_bb(bb)

        tutti_i_receipt_ids = self._receipt_ids_globali()
        tutti_i_receipt_ids_hex = [r.hex() for r in tutti_i_receipt_ids]

        albero_complessivo = MerkleTree(tutti_i_receipt_ids)
        r_finale = albero_complessivo.root

        voti_cifrati = self._voti_cifrati_globali()
        hash_voti_cifrati = self._hash_lista_ciphertext(voti_cifrati)

        timestamp_chiusura = int(time.time())
        data_to_sign = (
            self.election_id.encode()
            + r_finale
            + hash_voti_cifrati
            + str(timestamp_chiusura).encode()
        )
        sig_ue = firma_rsa_pss(self.private_key, sha256(data_to_sign))

        final_pub = {
            "election_id": self.election_id,
            "receipt_ids": tutti_i_receipt_ids_hex,
            "R_finale": r_finale,
            "hash_voti_cifrati": hash_voti_cifrati,
            "timestamp_chiusura": timestamp_chiusura,
            "SigUE": sig_ue,
            "voti_cifrati": voti_cifrati
        }

        bb.publish_final_closure(final_pub)
        return albero_complessivo


class ElectoralAuthority:
    """Entità incaricata dello scrutinio, della decifratura e della validazione delle schede."""
    def __init__(self, ca: CertificationAuthority):
        self.private_key, self.public_key = genera_coppia_chiavi_rsa(4096)
        self.cert = ca.issue_certificate("Autorità Elettorale", self.public_key)

    def esegui_scrutinio(self, bb: BulletinBoard, total_as_tokens_issued, pk_urn):
        """Scarica i dati dal BB, effettua i ricalcoli di integrità e compie il conteggio."""
        print("\n--- [AE] AVVIO DELLA FASE 5: SCRUTINIO DEI RISULTATI ---")
        
        final_pub = bb.final_publication
        if not final_pub:
            print("[AE] Errore Critico: Nessun dato di chiusura presente sul registro pubblico.")
            return None

        election_id = final_pub['election_id']
        r_finale_bb = final_pub['R_finale']
        timestamp_chiusura = final_pub['timestamp_chiusura']
        sig_ue = final_pub['SigUE']
        hash_voti_cifrati = final_pub['hash_voti_cifrati']
        receipt_ids_pubblicati = final_pub['receipt_ids']
        voti_cifrati_da_scrutinare = final_pub['voti_cifrati']

        hash_voti_cifrati_ricalcolato = sha256(b"".join(sha256(c) for c in voti_cifrati_da_scrutinare))
        if hash_voti_cifrati_ricalcolato != hash_voti_cifrati:
            print("[AE] Errore di Integrità: L'elenco dei voti cifrati è stato alterato.")
            return None
        print("[AE] Sotto-fase 1/4: Integrità dell'elenco dei voti cifrati confermata.")

        data_to_verify = election_id.encode() + r_finale_bb + hash_voti_cifrati + str(timestamp_chiusura).encode()
        if not verifica_rsa_pss(pk_urn, sig_ue, sha256(data_to_verify)):
            print("[AE] Errore di Autenticità: La firma dell'Urna Elettronica non è valida.")
            return None
        print("[AE] Sotto-fase 2/4: Autenticità della firma dell'Urna verificata con successo.")

        albero_ricalcolato = MerkleTree(receipt_ids_pubblicati)
        if albero_ricalcolato.root != r_finale_bb:
            print("[AE] Errore di Integrità: La radice Merkle ricalcolata differisce da quella pubblicata!")
            return None
        print("[AE] Sotto-fase 3/4: Integrità della struttura dati Merkle Root confermata.")

        num_receipts = len(receipt_ids_pubblicati)
        num_ciphertexts = len(voti_cifrati_da_scrutinare)
        print(f"[AE] Log quantitativi -> Ricevute: {num_receipts} | Voti cifrati: {num_ciphertexts} | Token AS: {total_as_tokens_issued}")
        if not (num_receipts == num_ciphertexts == total_as_tokens_issued):
            print("[AE] Errore di Flusso: Rilevata un'incoerenza quantitativa tra i moduli di controllo!")
            return None
        print("[AE] Sotto-fase 4/4: Coerenza quantitativa approvata.")

        conteggio_liste = Counter()
        conteggio_candidati = Counter()
        voti_validi = 0
        voti_non_validi = 0

        for idx, ciphertext in enumerate(voti_cifrati_da_scrutinare):
            try:
                decrypted_bytes = decifra_rsa_oaep(self.private_key, ciphertext)
                voto_json = json.loads(decrypted_bytes.decode())
                
                lista_scelta = voto_json.get("lista")
                candidato_scelto = voto_json.get("candidato")

                if lista_scelta in LISTE_ELETTORALI:
                    if candidato_scelto is None or candidato_scelto in LISTE_ELETTORALI[lista_scelta]:
                        voti_validi += 1
                        conteggio_liste[lista_scelta] += 1
                        if candidato_scelto:
                            conteggio_candidati[candidato_scelto] += 1
                    else:
                        print(f"[AE] Scheda #{idx} Non Valida: Candidato '{candidato_scelto}' non appartiene a '{lista_scelta}'.")
                        voti_non_validi += 1
                else:
                    print(f"[AE] Scheda #{idx} Non Valida: La lista '{lista_scelta}' non esiste.")
                    voti_non_validi += 1
                    
            except Exception as e:
                print(f"[AE] Scheda #{idx} Non Valida: Errore strutturale di decifratura o parsing: {e}")
                voti_non_validi += 1

        verbale = {
            "election_id": election_id,
            "R_finale": r_finale_bb.hex(),
            "m": num_receipts,
            "voti_cifrati_scrutinati": num_ciphertexts,
            "voti_decifrati": voti_validi + voti_non_validi,
            "voti_validi": voti_validi,
            "voti_non_validi": voti_non_validi,
            "risultati_liste": dict(conteggio_liste),
            "risultati_candidati": dict(conteggio_candidati)
        }

        verbale_bytes = json.dumps(verbale, sort_keys=True).encode()
        sig_ae = firma_rsa_pss(self.private_key, verbale_bytes)

        pubblicazione_verbale = {
            "verbale": verbale,
            "SigAE": sig_ae
        }

        bb.publish_verbale(pubblicazione_verbale)
        return pubblicazione_verbale


class Elector:
    """Rappresentazione del client lato studente dell'elettore."""
    def __init__(self, student_id, nome):
        self.student_id = student_id
        self.nome = nome
        self.token_voto = None
        self.sig_as_token = None
        self.ricevuta = None

    def esegui_autenticazione_e_ottieni_token(self, as_system: AuthenticationSystem):
        """Simulazione crittografica della Fase 1."""
        risultato = as_system.verifica_e_rilascia_token(self.student_id)
        if risultato:
            self.token_voto, self.sig_as_token = risultato
            return True
        return False

    def esprimi_preferenza(self, lista, candidato, cert_ae: Certificate, ca: CertificationAuthority, urn: ElectronicUrn, bb: BulletinBoard, pk_as):
        """Fase 2 & Fase 3: Cifratura lato client e invio all'Urna."""
        if not self.token_voto:
            print(f"[Elettore {self.nome}] Errore: Non possiedi un'autorizzazione valida per votare.")
            return False

        if not ca.verify_certificate(cert_ae):
            print(f"[Elettore {self.nome}] Errore Critico: Il certificato dell'Autorità Elettorale è contraffatto!")
            return False

        salt_crittografico = secrets.token_hex(32)
        scheda_voto = {
            "lista": lista,
            "candidato": candidato,
            "salt": salt_crittografico
        }
        scheda_bytes = json.dumps(scheda_voto, sort_keys=True).encode()

        C = cifra_rsa_oaep(cert_ae.public_key, scheda_bytes)

        payload = {
            "C": C,
            "T": self.token_voto,
            "SigAS(T)": self.sig_as_token
        }

        self.ricevuta = urn.ricevi_voto(payload, pk_as, bb)
        
        if self.ricevuta:
            receipt_id_locale = sha256(self.token_voto.encode() + C)
            if receipt_id_locale == self.ricevuta["ReceiptID"]:
                print(f"[Elettore {self.nome}] Ricevuta crittografica verificata localmente con successo.")
                return True
        return False

    def verifica_inclusione_individuale(self, bb: BulletinBoard):
        """Fase 4: consente all'elettore di controllare l'inclusione usando i dati pubblici del BB."""
        if not self.ricevuta:
            print(f"[Elettore {self.nome}] Nessuna ricevuta memorizzata. Verifica non eseguibile.")
            return False

        my_receipt_id_hex = self.ricevuta["ReceiptID"].hex()

        final_pub = bb.final_publication
        if not final_pub:
            print(f"[Elettore {self.nome}] Errore: L'urna non ha ancora chiuso la sessione pubblica sul Bulletin Board.")
            return False

        r_finale_bb = final_pub["R_finale"]
        receipt_ids_pubblicati = final_pub["receipt_ids"]

        if my_receipt_id_hex not in receipt_ids_pubblicati:
            print(f"[Elettore {self.nome}] ALLARME FRODE: Il mio ReceiptID non figura sul Bulletin Board pubblico!")
            return False

        albero_pubblico = MerkleTree(receipt_ids_pubblicati)
        indice_foglia = receipt_ids_pubblicati.index(my_receipt_id_hex)
        proof = albero_pubblico.get_proof(indice_foglia)

        is_valid = MerkleTree.verify_proof(self.ricevuta["ReceiptID"], proof, r_finale_bb)

        if is_valid:
            print(f"[Elettore {self.nome}] VERIFICA INDIVIDUALE SUPERATA: Il voto è incluso matematicamente nel Bulletin Board!")
            return True
        else:
            print(f"[Elettore {self.nome}] ERRORE DI VERIFICA: La Merkle Proof ha prodotto una radice incoerente.")
            return False


# =====================================================================
# BLOCCO DI SIMULAZIONE OPERATIVA COMPLETA
# =====================================================================

if __name__ == "__main__":
    print("=====================================================================")
    print("INIZIO SIMULAZIONE ARCHITETTURA DEL PROTOCOLLO CRITTOGRAFICO (WP2)")
    print("=====================================================================\n")

    # 1. SETUP DELL'INFRASTRUTTURA CRITTOGRAFICA (Fase 1)
    ca = CertificationAuthority()
    bb = BulletinBoard()
    as_system = AuthenticationSystem(ca)
    urna = ElectronicUrn(ca)
    autorita_elettorale = ElectoralAuthority(ca)

    as_system.inserisci_avente_diritto("S101", ha_diritto=True)
    as_system.inserisci_avente_diritto("S102", ha_diritto=True)
    as_system.inserisci_avente_diritto("S103", ha_diritto=True)
    as_system.inserisci_avente_diritto("S104", ha_diritto=True)
    as_system.inserisci_avente_diritto("S105", ha_diritto=True)

    elettori = [
        Elector("S101", "Alice"),
        Elector("S102", "Bob"),
        Elector("S103", "Charlie"),
        Elector("S104", "David"),
        Elector("S105", "Eve")
    ]

    voti_da_esprimere = [
        ("studenti ingegneria", "Mario Rossi"),  # Alice
        ("studentiunisa", "Anna Russo"),         # Bob
        ("agora", "Diego Esposito"),             # Charlie -> Completa il Batch 1 (dimensione 3)
        ("studenti ingegneria", "Elena Verdi"),  # David
        ("agora", "Claudio Bisio")               # Eve (MALFORMATO: Candidato non appartenente alla lista)
    ]

    print("--- FASE 1, 2 & 3: AUTENTICAZIONE, RILASCIO TOKEN ED INVIO DELLE SCHEDE ---")
    for elettore, (lista, candidato) in zip(elettori, voti_da_esprimere):
        if elettore.esegui_autenticazione_e_ottieni_token(as_system):
            # [CORRETTO] Sistemato nome metodo coerente con la classe Elector
            elettore.esprimi_preferenza(
                lista=lista,
                candidato=candidato,
                cert_ae=autorita_elettorale.cert,
                ca=ca,
                urn=urna,
                bb=bb,
                pk_as=as_system.public_key
            )

    # 2. CHIUSURA DELLA SESSIONE ELETTORALE (Fase 4)
    albero_complessivo_elezione = urna.chiudi_urna_e_pubblica_risultati(bb)

    # 3. VERIFICA INDIVIDUALE DEGLI ELETTORI (Fase 4 - Trasparenza)
    print("\n--- FASE 4: VERIFICA INDIVIDUALE DELLE MERKLE PROOF DA PARTE DEGLI ELETTORI ---")
    for elettore in elettori:
        # [CORRETTO] Sistemato nome metodo coerente con la classe Elector
        elettore.verifica_inclusione_individuale(bb)

    # 4. SCRUTINIO FINALE E RENDICONTAZIONE (Fase 5)
    pubblicazione_finale = autorita_elettorale.esegui_scrutinio(
        bb=bb,
        total_as_tokens_issued=as_system.tokens_emessi,
        pk_urn=urna.public_key
    )

    if pubblicazione_finale:
        verbale = pubblicazione_finale["verbale"]
        print("\n=====================================================================")
        print("RISULTATI UFFICIALI DELLO SCRUTINIO ELETTORALE")
        print("=====================================================================")
        print(f"Identificativo Elezione : {verbale['election_id']}")
        print(f"Ricevute Totali sul BB  : {verbale['m']}")
        print(f"Voti Decifrati          : {verbale['voti_decifrati']}")
        print(f"Voti Validi             : {verbale['voti_validi']}")
        print(f"Voti Annullati/Non Val. : {verbale['voti_non_validi']} (Es. Candidato incoerente con la lista)")
        print("---------------------------------------------------------------------")
        print("CONTEGGIO VOTI DI LISTA:")
        for lista, voti in verbale["risultati_liste"].items():
            print(f" - {lista.upper()}: {voti} voti")
        print("---------------------------------------------------------------------")
        print("PREFERENZE DETTAGLIATE CANDIDATI:")
        for cand, pref in verbale["risultati_candidati"].items():
            print(f" - {cand}: {pref} preferenze")
        print("=====================================================================")