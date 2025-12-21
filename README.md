# ARP Responder

## Uvod

ARP (Address Resolution Protocol) je protokol koji povezuje logičko adresiranje na mrežnom sloju (IPv4 adrese) sa fizičkim adresiranjem na podatkovnom sloju (MAC adrese) u lokalnoj mreži. U tipičnoj Ethernet LAN mreži, Ethernet okvir se isporučuje na osnovu MAC adrese odredišta, dok aplikacije i protokoli viših slojeva (npr. TCP/UDP) komuniciraju korištenjem IP adresa.

Kada čvor želi poslati IP paket ka određenoj IPv4 adresi u istoj lokalnoj mreži, on mora znati kojoj MAC adresi ta IP adresa pripada. Ako tražena IP adresa nije prisutna u lokalnoj ARP tabeli (ARP cache), čvor inicira ARP postupak razrješenja adrese (engl. address resolution):

1. Generiše se ARP Request – broadcast Ethernet okvir u kojem se navodi:
   - IP adresa čvora čija se MAC adresa traži,
   - IP i MAC adresa pošiljaoca zahtjeva.
2. Svi uređaji u lokalnoj mreži primaju ARP Request, ali **odgovara samo onaj čija IP adresa odgovara traženoj adresi**.
3. Taj uređaj šalje ARP Reply – unicast Ethernet okvir koji sadrži:
   - svoju MAC adresu,
   - svoju IP adresu (kao potvrdu),
   - IP/MAC adrese pošiljaoca zahtjeva u odgovarajućim poljima.
4. Pošiljalac ažurira svoju ARP tabelu, upisuje par (IP, MAC) i omogućava slanje IP paketa ka tom odredištu koristeći dobijenu MAC adresu.

Na narednoj slici prikazan je proces ARP komunikacije, uključujući ARP request i ARP reply:
<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/bd80100d-f5b2-4fc2-bf94-2921d3f7d430" />

## ARP protokol

ARP paket se sastoji od Ethernet frame headera i ARP headera. Dužina Ethernet frame headera je 14 bajtova, dok je dužina ARP headera 28 bajtova. Informacije vezane za Address Resolution Protocol nalaze se upravo u ovom dijelu.
U ARP paketu, EtherType u Ethernet zaglavlju ima vrijednost 0x0806. Ostali dijelovi Ethernet headera isti su kao i kod drugih Ethernet paketa.
ARP header sadrži više različitih polja. Ispod se nalaze navedeni dijelovi ARP headera, jedan po jedan.
<img width="900" height="500" alt="image" src="https://github.com/user-attachments/assets/bc90bd7e-3b97-43aa-a1e2-2c374282ac84" />

Kao što se može vidjeti u formatu ARP paketa, ARP header se sastoji od više različitih polja. Njihovi nazivi su:


- **Hardware type (HTYPE)** – tip fizičkog interfejsa; za Ethernet je najčešće vrijednost `1`.
- **Protocol type (PTYPE)** – identifikator protokola višeg sloja; za IPv4 se koristi vrijednost `0x0800`.
- **Hardware address length (HLEN)** – dužina hardverske (MAC) adrese u oktetima; za Ethernet je `6`.
- **Protocol address length (PLEN)** – dužina IP adrese u oktetima; za IPv4 je `4`.
- **Opcode** – tip ARP poruke:
  - `1` – ARP Request,
  - `2` – ARP Reply.
- **Sender hardware address (SHA)** – MAC adresa pošiljaoca ARP poruke.
- **Sender protocol address (SPA)** – IP adresa pošiljaoca ARP poruke.
- **Target hardware address (THA)** – MAC adresa odredišta (kod ARP Requesta se često stavlja nula, jer još nije poznata).
- **Target protocol address (TPA)** – IP adresa odredišta čija se MAC adresa traži.

Kombinacijom ovih polja, ARP omogućava da čvor jednoznačno identifikuje ko traži adresu (sender) i za koju IP adresu (target) želi da dobije MAC adresu.

## Opis projekta i popis signala

U ovom projektu implementira se VHDL modul ARP Responder, čija je uloga da odgovori na ARP upite za rezoluciju MAC adrese lokalnog čvora. Modul prima Ethernet/ARP okvire putem Avalon-ST interfejsa i generiše odgovarajući ARP reply kada je ciljna IP adresa jednaka adresi konfigurisanog čvora.
IP adresa i MAC adresa uređaja definišu se kao generički parametri prilikom instanciranja modula, što omogućava jednostavnu integraciju u različite mrežne konfiguracije. Komunikacija preko ulaznih i izlaznih portova odvija se korištenjem ready/valid rukovanja, koje obezbjeđuje pouzdan prijenos podataka kroz tok.
U nastavku je prikazan popis svih signala korištenih u ARP Responder modulu: 
- `clock`: Takt signal
- `reset`: Reset signal (aktivna visoka vrednost)
- `in_data[7:0]`: Ulazni podaci (bajt po bajt)
- `in_valid`: Validnost ulaznih podataka
- `in_sop`: Start of Packet za ulaz
- `in_eop`: End of Packet za ulaz
- `in_ready`: Ready signal za ulaz (modul spreman za prijem)
- `out_data[7:0]`: Izlazni podaci (bajt po bajt)
- `out_valid`: Validnost izlaznih podataka
- `out_sop`: Start of Packet za izlaz
- `out_eop`: End of Packet za izlaz
- `out_ready`: Ready signal za izlaz (primalac spreman).

## Scenariji za testiranje

Validacija ARP Responder modula izvršena je kroz tri ključna scenarija koji pokrivaju ispravno procesiranje, filtriranje saobraćaja i ignorisanje nepodržanih protokola.

### **1. Validna ARP rezolucija (Target IP Match)**
Ovo je osnovni scenarij u kojem modul prima ARP zahtjev koji je namijenjen upravo njemu.

*   **Ulaz:** Testbench šalje broadcast **ARP Request** u kojem je `Target IP` jednak IP adresi modula (npr. `192.168.1.1`).
*   **Proces:** Modul detektuje ispravan `EtherType (0x0806)` i poklapanje IP adrese.
*   **Rezultat:** Modul generiše **ARP Reply** (unicast) sa svojom MAC adresom. Izlazni signal `out_valid` postaje aktivan.

### **2. Filtriranje tuđih zahtjeva (Target IP Mismatch)**
Provjera da li modul ispravno ignoriše ARP zahtjeve koji su namijenjeni drugim uređajima u mreži.

*   **Ulaz:** Testbench šalje **ARP Request** u kojem je `Target IP` neka druga adresa (npr. `192.168.1.50`), različita od adrese modula.
*   **Proces:** Modul parsira paket, ali utvrđuje da se tražena IP adresa **ne poklapa** sa njegovom.
*   **Rezultat:** Modul odbacuje paket i **ne šalje odgovor**. Linija `out_valid` ostaje neaktivna ('0').

### **3. Ignorisanje nevažećeg saobraćaja (Non-ARP i Non-Request ARP)**
Testiranje robusnosti dizajna na okvire koji nisu relevantni za ARP rezoluciju.

* **Ulaz:** Testbench šalje Ethernet okvir koji nije ARP (npr. IPv4 paket gdje je `EtherType = 0x0800`), ili ARP okvir koji nije zahtjev za rezoluciju (npr. `EtherType = 0x0806`, ali `Opcode ≠ 0x0001`), ili ARP okvir sa neispravnim formatom za Ethernet/IPv4 (npr. `HTYPE ≠ 0x0001`, `PTYPE ≠ 0x0800`, `HLEN ≠ 6`, `PLEN ≠ 4`).
* **Proces:** Modul prvo provjerava EtherType polje u Ethernet zaglavlju. Ako je okvir ARP, dodatno provjerava validnost ARP hedera (`HTYPE/PTYPE/HLEN/PLEN`) i `Opcode` polje unutar ARP zaglavlja.
* **Rezultat:** Pošto okvir nije relevantan za ARP Request obradu (`EtherType ≠ 0x0806` ili ARP nije validan ili `Opcode ≠ 0x0001`), modul momentalno prestaje sa obradom i ignoriše ostatak paketa. Nema reakcije na izlazu (ne šalje se ARP Reply, out_valid ostaje neaktivan '0').

## WaveDrom dijagram
Wavedrom dijagram je kreiran pomoću WaveDrom alata i prikazan je u fajlu `waveform.json`. Dijagrami pokrivaju sljedeće scenarije:

## FSM (Finite State Machine) dizajn
FSM dijagram je kreiran pomoću draw.io alata i sačuvan u fajlu `fsm_diagram.drawio`.

### Opis stanja FSM-a


## VHDL implementacija

VHDL kod je implementiran u fajlu `arp_responder.vhd`. Modul implementira:

## Verifikacija pomoću simulacijskog alata ModelSim

## Zaključak

## Literatura

1. **Intel**. *Avalon Interface Specification, Intel Quartus Prime Design Suite 20.1*, v2022.01.24.  
   
2. **Spurgeon, Charles E.**, **Zimmerman, Joann**. *Ethernet: The Definitive Guide: Designing and Managing Local Area Networks*. 2nd ed. O'Reilly, 2025.

3. **Medhi, Deepankar**, **Ramasamy, Karthikeyan**. *Network Routing: Algorithms, Protocols, and Architectures*. Morgan Kaufmann, 2007. (Includes CD-ROM).
4. [ResearchGate: ARP Spoofing Solutions](https://www.researchgate.net/publication/276282183_Various_Solutions_for_Address_Resolution_Protocol_Spoofing_Attacks)
5. [Fortinet: What is ARP?](https://www.fortinet.com/resources/cyberglossary/what-is-arp)







